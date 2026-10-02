"""Finding import must ignore unknown reporter fields and keep identity stable."""

from __future__ import annotations

import json

import pytest

from shadowscan.models import Evidence, Finding, Kind, Likelihood, Risk, RiskFactor, ScanResult, Surface


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


def _sample_finding():
    return Finding(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.AGENT,
        title="sample",
        resource="repo:sample",
        resource_type="repository",
    )


@pytest.mark.parametrize("field", ["score", "factor", "evidence", "confidence"])
@pytest.mark.parametrize(
    "value", [True, False, None, "opaque-secret-value", [], {}, float("nan"), float("inf")]
)
def test_finding_import_rejects_malformed_numeric_fields_without_echoing_them(field, value):
    payload = _sample_finding().to_dict()
    if field == "score":
        payload["risk"]["score"] = value
    elif field == "factor":
        payload["risk"]["factors"] = [{"id": "test", "description": "test", "weight": value}]
    elif field == "evidence":
        payload["evidence"] = [{"signal": "test", "description": "test", "weight": value}]
    else:
        payload["confidence"] = value
    with pytest.raises(ValueError) as failure:
        Finding.from_dict(payload)
    assert "opaque-secret-value" not in str(failure.value)


@pytest.mark.parametrize("risk", [False, 0, [], ""])
def test_empty_malformed_risk_cannot_masquerade_as_missing(risk):
    payload = _sample_finding().to_dict()
    payload["risk"] = risk
    with pytest.raises(ValueError, match="risk must be an object"):
        Finding.from_dict(payload)


@pytest.mark.parametrize(
    "field,value",
    [
        ("score", -1),
        ("score", 101),
        ("confidence", -0.1),
        ("confidence", 1.1),
        ("evidence", -0.1),
        ("evidence", 1.1),
    ],
)
def test_finding_import_rejects_out_of_range_scores(field, value):
    payload = _sample_finding().to_dict()
    if field == "score":
        payload["risk"]["score"] = value
    elif field == "evidence":
        payload["evidence"] = [{"signal": "test", "description": "test", "weight": value}]
    else:
        payload["confidence"] = value
    with pytest.raises(ValueError, match="range"):
        Finding.from_dict(payload)


def _bedrock_finding(**kwargs) -> Finding:
    base = dict(
        surface=Surface.CLOUD,
        connector="cloud.aws",
        kind=Kind.AGENT,
        title="Bedrock Agent: ops",
        resource="arn:aws:bedrock:us-east-1:123456789012:agent/A1",
        resource_type="bedrock-agent",
    )
    base.update(kwargs)
    return Finding(**base)


def test_report_serialization_hides_private_state_and_tolerates_newer_fields():
    finding = _bedrock_finding(evidence=[Evidence("signal", "clean")])
    data = finding.to_dict()
    assert "_clean_digest" not in json.dumps(ScanResult(findings=[finding]).to_dict())
    data["future_field"] = {"anything": 1}
    data["_clean_digest"] = "untrusted"
    data["evidence"][0]["future_attribute"] = 2
    data["risk"]["factors"] = [{"id": "x", "description": "y", "weight": 1, "novel": True}]
    restored = Finding.from_dict(data)
    assert restored.id == finding.id and restored.risk.factors[0].id == "x"
    with pytest.raises(TypeError):
        Finding.from_dict("not an object")  # type: ignore[arg-type]


# ---------------------------------------------------------- likelihood label
def test_likelihood_is_a_confidence_bucket_named_strong():
    assert [member.value for member in Likelihood] == ["strong", "likely", "possible", "weak"]
    assert not hasattr(Likelihood, "CONFIRMED")
    for confidence, expected in [
        (1.0, Likelihood.STRONG),
        (0.85, Likelihood.STRONG),
        (0.849, Likelihood.LIKELY),
        (0.6, Likelihood.LIKELY),
        (0.599, Likelihood.POSSIBLE),
        (0.3, Likelihood.POSSIBLE),
        (0.299, Likelihood.WEAK),
        (0.0, Likelihood.WEAK),
    ]:
        assert Likelihood.from_confidence(confidence) is expected
    for member in Likelihood:
        assert Likelihood(member.value) is member


def test_the_legacy_confirmed_spelling_reads_as_strong_and_nothing_else_does():
    assert Likelihood("confirmed") is Likelihood.STRONG
    for value in ["CONFIRMED", "Confirmed", " confirmed", "certain", "", None, 1]:
        with pytest.raises(ValueError):
            Likelihood(value)


def test_finding_import_reads_reports_written_before_the_rename():
    finding = _finding()
    finding.evidence[0].weight = 0.9
    finding.recompute_confidence()
    payload = finding.to_dict()
    assert payload["likelihood"] == "strong" and finding.likelihood is Likelihood.STRONG
    payload["likelihood"] = "confirmed"
    restored = Finding.from_dict(payload)
    assert restored.likelihood is Likelihood.STRONG and restored.to_dict()["likelihood"] == "strong"
    assert restored.id == finding.id  # the label is not part of a finding's identity
    # The label is derived from confidence; a stored label never overrides it.
    payload["confidence"] = 0.2
    assert Finding.from_dict(payload).likelihood is Likelihood.WEAK
    payload["likelihood"] = "certain"
    with pytest.raises(ValueError):
        Finding.from_dict(payload)


def test_json_report_uses_the_new_label_only():
    finding = _finding()
    finding.evidence[0].weight = 0.95
    finding.recompute_confidence()
    report = ScanResult(findings=[finding]).to_json()
    assert '"likelihood": "strong"' in report and "confirmed" not in report
