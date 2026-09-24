"""Control-mode gates: static candidates must not fail a production scan."""

from __future__ import annotations

from shadowscan.cli import _exit_code
from shadowscan.control import apply_control_mode, is_gate_eligible, scan_exit_code
from shadowscan.models import (
    EvidenceTier,
    ExecutionStatus,
    Finding,
    Kind,
    Risk,
    RiskLevel,
    ScanResult,
    ScanStats,
    Surface,
)
from shadowscan.risk import assess


def _finding(**kwargs) -> Finding:
    values = dict(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.FRAMEWORK_USAGE,
        title="LangChain import",
        resource="repo",
        resource_type="project",
        confidence=0.9,
        shadow=True,
        evidence_tier=EvidenceTier.STATIC_CANDIDATE,
        execution_status=ExecutionStatus.NOT_ESTABLISHED,
        risk=Risk(score=80, level=RiskLevel.CRITICAL),
    )
    values.update(kwargs)
    return Finding(**values)


def _complete(findings) -> ScanResult:
    return ScanResult(
        findings=list(findings),
        stats=[ScanStats(connector="code.filesystem", started_at="2026-01-01T00:00:00Z", finished_at="2026-01-01T00:00:01Z")],
    )


def test_static_framework_usage_does_not_trip_default_gate():
    result = _complete([_finding()])
    assert result.complete
    assert _exit_code(result, "high") == 0
    assert scan_exit_code(result, "critical") == 0
    assert is_gate_eligible(result.findings[0]) is False


def test_allow_static_gates_trips_on_static_critical():
    result = _complete([_finding()])
    assert _exit_code(result, "high", allow_static_gates=True) == 2


def test_secret_is_always_gate_eligible():
    secret = _finding(kind=Kind.SECRET, title="OpenAI key", evidence_tier=EvidenceTier.STATIC_CANDIDATE)
    assert is_gate_eligible(secret) is True
    result = _complete([secret])
    assert _exit_code(result, "high") == 2


def test_configured_cloud_agent_trips_gate():
    agent = _finding(
        surface=Surface.CLOUD,
        connector="cloud.aws",
        kind=Kind.AGENT,
        title="Bedrock Agent",
        evidence_tier=EvidenceTier.CONFIGURED_RESOURCE,
        execution_status=ExecutionStatus.CONFIGURED,
    )
    assert is_gate_eligible(agent) is True
    assert _exit_code(_complete([agent]), "high") == 2


def test_incomplete_scan_beats_fail_on():
    result = ScanResult(
        findings=[_finding(kind=Kind.SECRET)],
        stats=[ScanStats(connector="cloud.aws", started_at="2026-01-01T00:00:00Z", errors=["denied"], incomplete=True)],
    )
    assert _exit_code(result, "high") == 3
    assert _exit_code(result, None) == 3


def test_control_mode_defaults():
    confidence, fail_on, allow_static = apply_control_mode(0.0, None)
    assert confidence == 0.6
    assert fail_on == "high"
    assert allow_static is False


def test_static_shadow_cannot_reach_high_without_secrets():
    finding = _finding(risk=Risk(), tags=[], frameworks=["framework.langchain"])
    finding.risk = assess(finding, inventory_present=True)
    assert finding.risk.score < 50
    assert finding.risk.level in {RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.INFO}
