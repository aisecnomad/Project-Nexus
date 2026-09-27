"""Finding.sanitize: later mutations, redaction policy changes and alias budgets."""

from __future__ import annotations

import pytest

from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.utils import redaction


def _finding():
    return Finding(surface=Surface.CODE, connector="code.filesystem", kind=Kind.AGENT,
                   title="sample", resource="repo:sample", resource_type="repository")


def _bedrock_finding(**kwargs) -> Finding:
    base = dict(surface=Surface.CLOUD, connector="cloud.aws", kind=Kind.AGENT,
                title="Bedrock Agent: ops", resource="arn:aws:bedrock:us-east-1:123456789012:agent/A1",
                resource_type="bedrock-agent")
    base.update(kwargs)
    return Finding(**base)


def test_finding_sanitization_does_not_serialize_alias_dags_before_budget_check():
    finding = _finding()
    value = {"label": "ordinary"}
    for _ in range(12):
        value = {"children": [value] * 10}
    finding.metadata = value
    with pytest.raises(redaction.SanitizationLimitError, match="expanded output"):
        finding.sanitize()


def test_repeated_finding_sanitization_observes_new_redaction_policy(monkeypatch):
    finding = _finding()
    finding.metadata["new_secret_format"] = "opaque-secret-value"
    finding.evidence.append(Evidence("test", "opaque-secret-value"))
    finding.sanitize()
    monkeypatch.setattr(redaction, "_SENSITIVE_NAMES", redaction._SENSITIVE_NAMES | {"newsecretformat"})
    finding.sanitize()
    assert finding.metadata["new_secret_format"] == redaction.REDACTED
    assert finding.evidence[0].description == redaction.REDACTED


def test_sanitize_catches_every_later_mutation():
    finding = _bedrock_finding(evidence=[Evidence("signal", "clean", snippet="nothing here", weight=0.5)])
    finding.sanitize()
    finding.title = "leaked sk-proj-" + "a" * 40
    finding.evidence[0].snippet = "AKIA" + "A" * 16
    finding.metadata["note"] = "Authorization: Bearer abcdefghijklmnop"
    finding.sanitize()
    assert "sk-proj" not in finding.title and redaction.REDACTED in finding.title
    assert "AKIA" not in (finding.evidence[0].snippet or "")
    assert "abcdefghijklmnop" not in finding.metadata["note"]
