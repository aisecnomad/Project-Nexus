"""Production-control gate: which findings may fail a scan.

ShadowScan reports evidence of AI agents and integrations. A static import is a
candidate, not proof of execution. Default `--fail-on` therefore ignores
static-only candidates unless the operator opts in with `--allow-static-gates`.

Hard-coded provider credentials remain gate-eligible even when the evidence is
static: that is a real secret-exposure control, not an agent-runtime claim.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from shadowscan.models import Finding, Kind, ScanResult

STATIC_CANDIDATE = "static_candidate"
CONFIGURED_RESOURCE = "configured_resource"
RUNTIME_OBSERVED = "runtime_observed"
CORROBORATED = "corroborated"

NOT_ESTABLISHED = "not_established"
UNKNOWN = "unknown"
CONFIGURED = "configured"
OBSERVED = "observed"

GATE_TIERS = frozenset({CONFIGURED_RESOURCE, RUNTIME_OBSERVED, CORROBORATED})
RUNTIME_STATUSES = frozenset({OBSERVED, CORROBORATED})
ALWAYS_GATE_KINDS = frozenset({Kind.SECRET})
LEVELS = ["critical", "high", "medium", "low", "info"]

_SURFACE_CONFIGURED = frozenset({"identity", "saas", "lowcode", "cloud"})


def _enum_value(value: Any, default: str) -> str:
    if value is None:
        return default
    return value.value if hasattr(value, "value") else str(value)


def infer_evidence_tier(finding: Finding) -> str:
    """Best-effort tier when the engine has not yet stamped evidence_tier."""
    activity = finding.metadata.get("runtime_activity") if finding.metadata else None
    if isinstance(activity, dict) and activity.get("status") == "observed":
        related = finding.metadata.get("related") if finding.metadata else None
        if related:
            return CORROBORATED
        return RUNTIME_OBSERVED
    if finding.kind == Kind.GATEWAY_CALLER:
        return RUNTIME_OBSERVED
    if finding.kind == Kind.SECRET:
        return STATIC_CANDIDATE
    if finding.surface.value in _SURFACE_CONFIGURED and finding.kind != Kind.FRAMEWORK_USAGE:
        return CONFIGURED_RESOURCE
    if finding.kind in {Kind.INFRA, Kind.MCP_SERVER, Kind.AGENT_CONFIG}:
        return STATIC_CANDIDATE
    return STATIC_CANDIDATE


def infer_execution_status(finding: Finding) -> str:
    activity = finding.metadata.get("runtime_activity") if finding.metadata else None
    if isinstance(activity, dict) and activity.get("status") == "observed":
        related = finding.metadata.get("related") if finding.metadata else None
        return CORROBORATED if related else OBSERVED
    if finding.kind == Kind.GATEWAY_CALLER:
        return OBSERVED
    if finding.surface.value in _SURFACE_CONFIGURED and finding.kind not in {Kind.FRAMEWORK_USAGE, Kind.SECRET}:
        return CONFIGURED
    return NOT_ESTABLISHED


def evidence_tier(finding: Finding) -> str:
    stamped = getattr(finding, "evidence_tier", None)
    if stamped is not None:
        return _enum_value(stamped, STATIC_CANDIDATE)
    return infer_evidence_tier(finding)


def execution_status(finding: Finding) -> str:
    stamped = getattr(finding, "execution_status", None)
    if stamped is not None:
        return _enum_value(stamped, NOT_ESTABLISHED)
    return infer_execution_status(finding)


def is_gate_eligible(finding: Finding, *, allow_static_gates: bool = False) -> bool:
    """Return whether a finding may trip `--fail-on`.

    Secrets always count. Runtime-observed and configured cloud/SaaS/identity
    resources count. Static framework-usage and inventory-miss-only code hits
    do not, unless ``allow_static_gates`` is set.
    """
    if allow_static_gates:
        return True
    if finding.kind in ALWAYS_GATE_KINDS:
        return True
    if execution_status(finding) in RUNTIME_STATUSES:
        return True
    return evidence_tier(finding) in GATE_TIERS


def gate_findings(findings: Iterable[Finding], *, allow_static_gates: bool = False) -> list[Finding]:
    return [finding for finding in findings if is_gate_eligible(finding, allow_static_gates=allow_static_gates)]


def scan_exit_code(result: ScanResult, fail_on: str | None, allow_static_gates: bool = False) -> int:
    """Exit 3 for incomplete coverage, 2 for a tripped control gate, else 0."""
    if not result.complete:
        return 3
    if not fail_on:
        return 0
    if fail_on not in LEVELS:
        return 3
    threshold = LEVELS.index(fail_on)
    gated = gate_findings(result.findings, allow_static_gates=allow_static_gates)
    worst = min((LEVELS.index(f.risk.level.value) for f in gated), default=len(LEVELS))
    return 2 if worst <= threshold else 0


def apply_control_mode(min_confidence: float, fail_on: str | None) -> tuple[float, str, bool]:
    """Conservative production-control defaults.

    ``fail_on=high`` so a configured unregistered Bedrock agent still fails the
    gate. Static-only candidates stay excluded. Confidence floor 0.6 drops
    weak lexical hits.
    """
    return (max(min_confidence, 0.6), fail_on or "high", False)


def gate_summary(result: ScanResult, *, allow_static_gates: bool = False) -> dict[str, int]:
    eligible = gate_findings(result.findings, allow_static_gates=allow_static_gates)
    excluded = len(result.findings) - len(eligible)
    by_tier: dict[str, int] = {}
    for finding in result.findings:
        tier = evidence_tier(finding)
        by_tier[tier] = by_tier.get(tier, 0) + 1
    return {
        "gate_eligible": len(eligible),
        "gate_excluded_static": excluded,
        "by_evidence_tier": by_tier,
    }
