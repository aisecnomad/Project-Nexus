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
