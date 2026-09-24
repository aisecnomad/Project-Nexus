"""Control-grade evidence tiers and risk-score conservatism."""

from __future__ import annotations

from shadowscan.evidence import annotate_finding, is_gate_eligible
from shadowscan.models import Evidence, EvidenceTier, ExecutionStatus, Finding, Kind, RiskLevel, Surface
from shadowscan.risk import assess


def _finding(**kwargs) -> Finding:
    values = dict(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.FRAMEWORK_USAGE,
        title="LangChain import",
        resource="repo:acme/demo",
        resource_type="repository",
        confidence=0.7,
        evidence=[Evidence(signal="dependency:pypi:langchain", description="langchain in requirements", weight=0.6)],
    )
    values.update(kwargs)
    return Finding(**values)


def test_code_framework_usage_is_static_and_not_established() -> None:
    finding = annotate_finding(_finding())
    assert finding.evidence_tier is EvidenceTier.STATIC_CANDIDATE
    assert finding.execution_status is ExecutionStatus.NOT_ESTABLISHED
    assert is_gate_eligible(finding) is False


def test_cloud_agent_is_configured_not_running() -> None:
    finding = annotate_finding(_finding(
        surface=Surface.CLOUD,
        connector="cloud.aws",
        kind=Kind.AGENT,
        title="Bedrock Agent",
        resource="arn:aws:bedrock:us-east-1:123456789012:agent/ABC",
        resource_type="bedrock-agent",
        provider="aws",
        account="123456789012",
        evidence=[Evidence(signal="aws:bedrock-agent", description="listed agent", weight=0.95)],
        confidence=0.95,
    ))
    assert finding.evidence_tier is EvidenceTier.CONFIGURED_RESOURCE
    assert finding.execution_status is ExecutionStatus.CONFIGURED
    assert is_gate_eligible(finding) is True


def test_gateway_caller_is_runtime_observed() -> None:
    finding = annotate_finding(_finding(
        surface=Surface.GATEWAY,
        connector="gateway.logs",
        kind=Kind.GATEWAY_CALLER,
        title="svc-bot: 12 requests",
        resource="gateway:svc-bot",
        resource_type="caller",
        metadata={"events": 12},
        evidence=[Evidence(signal="gateway:service", description="12 LLM request(s)", weight=0.8)],
    ))
    assert finding.evidence_tier is EvidenceTier.RUNTIME_OBSERVED
    assert finding.execution_status is ExecutionStatus.OBSERVED


def test_runtime_plus_configured_is_corroborated() -> None:
    finding = annotate_finding(_finding(
        surface=Surface.CLOUD,
        connector="cloud.aws",
        kind=Kind.AGENT,
        title="Bedrock Agent with invocations",
        resource="arn:aws:bedrock:us-east-1:123456789012:agent/ABC",
        resource_type="bedrock-agent",
        metadata={"runtime_activity": {"events": 4}},
        evidence=[
            Evidence(signal="aws:bedrock-agent", description="listed agent", weight=0.9),
            Evidence(signal="runtime:invocations", description="invocation log", weight=0.7),
        ],
    ))
    assert finding.evidence_tier is EvidenceTier.CORROBORATED
    assert finding.execution_status is ExecutionStatus.CORROBORATED


def test_shadow_framework_usage_cannot_reach_high() -> None:
    finding = _finding(shadow=True, owner=None)
    finding.risk = assess(finding, inventory_present=True)
    assert finding.evidence_tier is EvidenceTier.STATIC_CANDIDATE
    assert finding.risk.score < 50
    assert finding.risk.level in {RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.INFO}
    assert any(factor.id == "static-cap" for factor in finding.risk.factors)


def test_unmatched_configured_agent_keeps_shadow_weight_but_not_critical_from_shadow_alone() -> None:
    finding = _finding(
        surface=Surface.CLOUD,
        connector="cloud.aws",
        kind=Kind.AGENT,
        title="Bedrock Agent",
        resource="arn:aws:bedrock:us-east-1:123456789012:agent/ABC",
        resource_type="bedrock-agent",
        shadow=True,
        owner=None,
        confidence=1.0,
        evidence=[Evidence(signal="aws:bedrock-agent", description="listed agent", weight=0.97)],
    )
    finding.risk = assess(finding, inventory_present=True)
    assert finding.evidence_tier is EvidenceTier.CONFIGURED_RESOURCE
    shadow = next(factor for factor in finding.risk.factors if factor.id == "shadow")
    assert shadow.weight == 15
    assert finding.risk.score < 75


def test_hardcoded_secret_remains_gate_eligible_and_can_be_critical() -> None:
    finding = _finding(
        kind=Kind.SECRET,
        title="LLM provider credential",
        resource="services/research-agent/app/config.py",
        resource_type="file",
        tags=["hardcoded-credential"],
        confidence=0.9,
        evidence=[Evidence(signal="secret:provider.openai", description="redacted key", weight=0.9)],
    )
    finding.risk = assess(finding, inventory_present=True)
    assert is_gate_eligible(finding) is True
    assert finding.risk.level in {RiskLevel.HIGH, RiskLevel.CRITICAL}


def test_registered_configured_resource_gets_negative_shadow_factor() -> None:
    finding = _finding(
        surface=Surface.CLOUD,
        connector="cloud.aws",
        kind=Kind.AGENT,
        title="Bedrock Agent",
        resource="arn:aws:bedrock:us-east-1:123456789012:agent/ABC",
        resource_type="bedrock-agent",
        shadow=False,
        registry_match="ops-provisioning-04",
        owner="Platform-Engineering",
        confidence=1.0,
        evidence=[Evidence(signal="aws:bedrock-agent", description="listed agent", weight=0.97)],
    )
    finding.risk = assess(finding, inventory_present=True)
    assert any(factor.id == "registered" and factor.weight < 0 for factor in finding.risk.factors)


def test_static_gates_opt_in() -> None:
    finding = annotate_finding(_finding())
    assert is_gate_eligible(finding, allow_static_gates=False) is False
    assert is_gate_eligible(finding, allow_static_gates=True) is True
