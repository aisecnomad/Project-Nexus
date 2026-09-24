"""Finding import must ignore unknown reporter fields and keep identity stable."""

from __future__ import annotations

import pytest

from shadowscan.models import Evidence, Finding, Kind, Risk, RiskFactor, Surface


def _finding() -> Finding:
    return Finding(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.AGENT,
        title="t",
        resource="r",
        resource_type="repository",
        evidence=[Evidence(signal="dependency:pypi:langchain", description="langchain present", weight=0.4)],
        risk=Risk(score=10, factors=[RiskFactor(id="kind.agent", description="declared agent", weight=10)]),
    )


def test_finding_from_dict_ignores_unknown_keys():
    finding = _finding()
    payload = finding.to_dict()
    payload["future_reporter_field"] = {"not": "a finding attribute"}
    payload["evidence"][0]["future_evidence_field"] = "drop-me"
    payload["risk"]["factors"][0]["future_factor_field"] = "drop-me"
    restored = Finding.from_dict(payload)
    assert restored.resource == "r"
    assert restored.title == "t"
    assert restored.identity_schema == finding.identity_schema
    assert restored.id == finding.id
    assert restored.evidence[0].signal == "dependency:pypi:langchain"
    assert restored.risk.factors[0].id == "kind.agent"


def test_finding_from_dict_defaults_missing_identity_to_legacy():
    payload = _finding().to_dict()
    payload.pop("identity_schema")
    payload.pop("identity_discriminator", None)
    restored = Finding.from_dict(payload)
    assert restored.identity_schema == "shadowscan.finding-identity/v1"
    assert restored.id == payload["id"]


def test_finding_from_dict_rejects_missing_required_fields():
    payload = _finding().to_dict()
    payload["resource"] = ""
    with pytest.raises(ValueError, match="resource"):
        Finding.from_dict(payload)


def test_finding_from_dict_rejects_non_object_payload():
    with pytest.raises(TypeError, match="object"):
        Finding.from_dict(["not", "a", "finding"])  # type: ignore[arg-type]


def test_finding_from_dict_rejects_malformed_nested_objects():
    payload = _finding().to_dict()
    payload["evidence"] = ["not-an-object"]
    with pytest.raises(ValueError, match="evidence"):
        Finding.from_dict(payload)
    payload = _finding().to_dict()
    payload["risk"]["factors"] = ["not-an-object"]
    with pytest.raises(ValueError, match="risk factor"):
        Finding.from_dict(payload)
