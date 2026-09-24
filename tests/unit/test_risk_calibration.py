from __future__ import annotations

from shadowscan.models import Finding, Kind, RiskLevel, Surface
from shadowscan.risk import assess


def test_risk_bands_stay_calibrated(index):
    shadow_agent = Finding(
        surface=Surface.CLOUD, connector="cloud.aws", kind=Kind.AGENT,
        title="Bedrock Agent", resource="arn:aws:bedrock:us-east-1:1:agent/A1",
        resource_type="bedrock-agent", confidence=0.9,
        capabilities=["code-exec", "autonomous"],
        tags=["policy.privileged-scopes", "plaintext-credential"],
        shadow=True,
    )
    registered_usage = Finding(
        surface=Surface.CODE, connector="code.filesystem", kind=Kind.FRAMEWORK_USAGE,
        title="langchain usage", resource="github:acme/svc", resource_type="project",
        confidence=0.3, owner="platform", shadow=False, registry_match="svc",
    )
    secret = Finding(
        surface=Surface.CODE, connector="code.filesystem", kind=Kind.SECRET,
        title="provider key", resource="github:acme/svc/config.py", resource_type="secret",
        confidence=0.8, tags=["hardcoded-credential"], shadow=True,
    )
    assert assess(shadow_agent, index, inventory_present=True).level == RiskLevel.CRITICAL
    quiet = assess(registered_usage, index, inventory_present=True)
    assert quiet.level in {RiskLevel.LOW, RiskLevel.INFO}
    assert assess(secret, index, inventory_present=True).score >= 50
