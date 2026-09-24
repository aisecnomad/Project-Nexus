"""Core regressions retained from the additional production hardening review."""

from __future__ import annotations

import json

import pytest

from shadowscan.connectors import ConnectorContext
from shadowscan.models import Evidence, Finding, Kind, ScanResult, Surface
from shadowscan.registry import Inventory
from shadowscan.utils import redaction
from shadowscan.utils.http import HttpClient


def _finding(**kwargs) -> Finding:
    base = dict(surface=Surface.CLOUD, connector="cloud.aws", kind=Kind.AGENT,
                title="Bedrock Agent: ops", resource="arn:aws:bedrock:us-east-1:123456789012:agent/A1",
                resource_type="bedrock-agent")
    base.update(kwargs)
    return Finding(**base)


def test_sanitize_catches_every_later_mutation():
    finding = _finding(evidence=[Evidence("signal", "clean", snippet="nothing here", weight=0.5)])
    finding.sanitize()
    finding.title = "leaked sk-proj-" + "a" * 40
    finding.evidence[0].snippet = "AKIA" + "A" * 16
    finding.metadata["note"] = "Authorization: Bearer abcdefghijklmnop"
    finding.sanitize()
    assert "sk-proj" not in finding.title and redaction.REDACTED in finding.title
    assert "AKIA" not in (finding.evidence[0].snippet or "")
    assert "abcdefghijklmnop" not in finding.metadata["note"]


def test_report_serialization_hides_private_state_and_tolerates_newer_fields():
    finding = _finding(evidence=[Evidence("signal", "clean")])
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


def test_ssws_scheme_and_repr_escaped_values_are_redacted():
    assert "00abcdefghijklmnop" not in redaction.sanitize_text("Authorization: SSWS 00abcdefghijklmnop")
    secret = "00SuperSecretOktaApiToken123456\n"
    ctx = ConnectorContext(config={"token": secret})
    message = ctx.sanitize_message(f"InvalidHeader: Invalid leading whitespace in header value: {secret!r}")
    assert "SuperSecretOktaApiToken" not in message


@pytest.mark.parametrize("secret", [
    "pplx-" + "a" * 45, "gsk_" + "A" * 45, "xai-" + "b" * 64, "nvapi-" + "c" * 64, "r8_" + "d" * 32,
    "csk-" + "e" * 32, "tgp_v1_" + "f" * 32, "e2b_" + "0" * 40, "lsv2_pt_" + "a" * 32 + "_" + "b" * 10,
    "tvly-dev-" + "g" * 24, "pcsk_" + "h" * 24, "fc-" + "1" * 32, "app-" + "A" * 24, "sk-lf-" + "0" * 36,
])
def test_every_detectable_credential_format_is_redacted_by_the_text_sanitizer(secret):
    assert secret not in redaction.sanitize_text(f"value {secret} trailing")


def test_http_client_rejects_control_characters_in_headers_without_echoing_them():
    with pytest.raises(ValueError) as failure:
        HttpClient("https://example.com", headers={"Authorization": "SSWS 00SuperSecret\n"})
    assert "SuperSecret" not in str(failure.value)


def test_inventory_name_patterns_are_reused(tmp_path):
    (tmp_path / "agents.yaml").write_text("agents:\n  - id: reviewer\n    names: [coderabbitai]\n    resources: ['x:*']\n")
    inventory = Inventory.load([str(tmp_path)])
    for _ in range(3):
        assert inventory.suggest(_finding(title="Slack app: CodeRabbitAI", resource="slack:app:1"))
    assert set(inventory._name_patterns) == {"reviewer", "coderabbitai"}
