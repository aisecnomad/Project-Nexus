"""Dataclass attributes are independent values, never positional CLI arguments."""

import pytest

from shadowscan.models import Evidence, Finding, Kind, Risk, RiskFactor, Surface
from shadowscan.utils.redaction import REDACTED


@pytest.mark.parametrize("field", ["signal", "description", "location", "snippet", "signature"])
def test_evidence_flag_shaped_attribute_does_not_redact_its_neighbor(field):
    values = {
        "signal": "observation", "description": "Observed an agent",
        "location": "agent.py:1", "snippet": "ordinary source",
        "weight": 0.5, "signature": "framework.example", "attributes": {"label": "ordinary"},
    }
    values[field] = "--token"
    evidence = Evidence(**values)
    for name, expected in values.items():
        assert getattr(evidence, name) == expected
    evidence.sanitize()
    assert evidence.weight == 0.5


def test_finding_flag_shaped_title_preserves_resource_identity_and_serialization():
    finding = Finding(surface=Surface.CODE, connector="code.filesystem", kind=Kind.AGENT,
                      title="--token", resource="repository/agent", resource_type="repository")
    identity = finding.id
    finding.evidence.append(Evidence("signal", "description", snippet="--token", weight=0.5))
    finding.risk = Risk(factors=[RiskFactor("--token", "Independent description", 5)])
    finding.sanitize()
    finding.recompute_confidence()
    assert finding.resource == "repository/agent"
    assert finding.id == identity == finding.compute_id()
    assert finding.confidence == 0.5
    assert finding.risk.factors[0].description == "Independent description"
    assert finding.to_dict()["evidence"][0]["weight"] == 0.5


def test_singleton_wrappers_preserve_real_nested_argv_and_cross_field_redaction():
    secret = "opaque-argument-credential-value"
    evidence = Evidence("observation", f"Failure echoed {secret}",
                        attributes={"argv": ["--token", secret]})
    assert evidence.description == f"Failure echoed {REDACTED}"
    assert evidence.attributes["argv"] == ["--token", REDACTED]
    finding = Finding(surface=Surface.CODE, connector="code.filesystem", kind=Kind.AGENT,
                      title=f"Echoed {secret}", resource="repository/agent", resource_type="repository",
                      metadata={"argv": ["--token", secret]})
    assert finding.title == f"Echoed {REDACTED}"
    assert finding.metadata["argv"] == ["--token", REDACTED]


def _finding(**overrides) -> Finding:
    values = dict(surface=Surface.CODE, connector="code.filesystem", kind=Kind.AGENT, title="Agent",
                  resource="github:acme/app", resource_type="repository")
    values.update(overrides)
    return Finding(**values)


def test_sanitize_verifies_unchanged_state_by_digest_and_redacts_every_later_mutation(monkeypatch):
    from shadowscan import models

    calls = []
    original = models.sanitize

    def counting(value, **kwargs):
        calls.append(1)
        return original(value, **kwargs)

    monkeypatch.setattr(models, "sanitize", counting)
    finding = _finding()
    assert len(calls) == 1, "construction performs one full pass"
    finding.sanitize()
    finding.to_dict()
    assert len(calls) == 1, "an unchanged finding is not re-scanned"
    finding.title = "uses sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN"
    assert finding.to_dict()["title"] == f"uses {REDACTED}" and len(calls) == 2
    finding.metadata["nested"] = {"api_key": "opaque-configured-value"}
    assert finding.to_dict()["metadata"]["nested"]["api_key"] == REDACTED and len(calls) == 3
    # Evidence construction runs its own pass (one call); the finding then needs one more.
    finding.evidence.append(Evidence(signal="x", description="Authorization: Bearer abcdef0123456789"))
    assert "abcdef0123456789" not in finding.to_dict()["evidence"][0]["description"] and len(calls) == 5
    finding.risk = Risk(score=10, factors=[RiskFactor("f", "password=hunter2-value", 1)])
    assert finding.to_dict()["risk"]["factors"][0]["description"] == f"password={REDACTED}" and len(calls) == 6
    finding.to_dict()
    assert len(calls) == 6


def test_sanitization_bookkeeping_never_enters_reports_and_cannot_be_imported():
    finding = _finding()
    exported = finding.to_dict()
    assert "_sanitized_state" not in exported
    forged = Finding.from_dict({**exported, "_sanitized_state": "0" * 64,
                                "title": "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN"})
    assert forged.title == REDACTED
    assert forged == Finding.from_dict(forged.to_dict()), "cache state is excluded from equality"


def test_failed_sanitization_pass_records_no_verified_state():
    from shadowscan.utils.redaction import SanitizationLimitError

    finding = _finding()
    finding.connector = "code.filesystem sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN"
    with pytest.raises(SanitizationLimitError):
        finding.sanitize()
    assert finding._sanitized_state != finding._state_digest(), "a failed pass never marks the state verified"
    assert REDACTED in finding.connector, "the rejected identity field is withheld even though the finding is omitted"


def test_state_digest_rejects_an_aliased_dag_before_expanding_it():
    from shadowscan.utils.redaction import SanitizationLimitError

    node: list = ["x"]
    for _ in range(40):
        node = [node, node]  # 2**40 leaves if expanded by repr
    finding = _finding()
    finding.metadata["dag"] = node
    with pytest.raises(SanitizationLimitError):
        finding.sanitize()
    with pytest.raises(SanitizationLimitError):
        finding._state_digest()
