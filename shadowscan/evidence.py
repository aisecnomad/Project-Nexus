"""Evidence tier and execution-status classification.

ShadowScan findings are *observations*. They do not, by themselves, prove that
an agent is executing. Classification is deterministic from surface, kind,
evidence signals and metadata already on the finding.
"""

from __future__ import annotations

from shadowscan.models import EvidenceTier, ExecutionStatus, Finding, Kind, Surface

CREDENTIAL_TAGS = frozenset({
    "hardcoded-credential",
    "plaintext-credential",
    "inline-secrets",
})

_RUNTIME_SIGNAL_PREFIXES = ("gateway:", "runtime:", "log:", "invocation:")
_RUNTIME_METADATA_KEYS = (
    "runtime_activity",
    "runtime_observations",
    "runtime_sources",
    "events",
    "invocation_count",
)
_CONFIGURED_KINDS = frozenset({
    Kind.CLOUD_RESOURCE,
    Kind.BOT_APP,
    Kind.OAUTH_GRANT,
    Kind.SERVICE_IDENTITY,
    Kind.WORKFLOW,
    Kind.IAM_GRANT,
    Kind.TOKEN,
})
_LIVE_SURFACES = frozenset({
    Surface.IDENTITY,
    Surface.SAAS,
    Surface.LOWCODE,
    Surface.CLOUD,
})


def _has_runtime_evidence(finding: Finding) -> bool:
    if finding.surface == Surface.GATEWAY or finding.kind == Kind.GATEWAY_CALLER:
        return True
    for ev in finding.evidence:
        signal = ev.signal or ""
        if signal.startswith(_RUNTIME_SIGNAL_PREFIXES):
            return True
    metadata = finding.metadata or {}
    if metadata.get("runtime_activity"):
        return True
    for key in _RUNTIME_METADATA_KEYS:
        value = metadata.get(key)
        if isinstance(value, list) and value:
            return True
        if isinstance(value, dict) and value:
            return True
        if isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0:
            return True
    return False


def _has_configured_evidence(finding: Finding) -> bool:
    if finding.kind in _CONFIGURED_KINDS:
        return True
    if finding.surface in _LIVE_SURFACES and finding.kind != Kind.FRAMEWORK_USAGE:
        return True
    if finding.kind == Kind.AGENT and finding.surface != Surface.CODE:
        return True
    return False


def classify_evidence(finding: Finding) -> tuple[EvidenceTier, ExecutionStatus]:
    """Return (tier, execution_status) for a finding. Does not mutate."""
    runtime = _has_runtime_evidence(finding)
    configured = _has_configured_evidence(finding)
    if runtime and configured:
        return EvidenceTier.CORROBORATED, ExecutionStatus.CORROBORATED
    if runtime:
        return EvidenceTier.RUNTIME_OBSERVED, ExecutionStatus.OBSERVED
    if configured:
        return EvidenceTier.CONFIGURED_RESOURCE, ExecutionStatus.CONFIGURED
    return EvidenceTier.STATIC_CANDIDATE, ExecutionStatus.NOT_ESTABLISHED


def annotate_finding(finding: Finding) -> Finding:
    """Set evidence_tier and execution_status in place. Idempotent."""
    tier, status = classify_evidence(finding)
    finding.evidence_tier = tier
    finding.execution_status = status
    return finding


def is_static_only(finding: Finding) -> bool:
    tier = finding.evidence_tier
    value = tier.value if isinstance(tier, EvidenceTier) else str(tier or "")
    return value == EvidenceTier.STATIC_CANDIDATE.value


def has_credential_exposure(finding: Finding) -> bool:
    if finding.kind == Kind.SECRET:
        return True
    return any(tag in CREDENTIAL_TAGS for tag in finding.tags)


def is_gate_eligible(finding: Finding, *, allow_static_gates: bool = False) -> bool:
    """Whether a finding may fail a production ``--fail-on`` gate.

    Secrets and explicit credential-exposure tags remain eligible even when the
    observation is static. Other static candidates require ``allow_static_gates``.
    """
    if allow_static_gates:
        return True
    if has_credential_exposure(finding):
        return True
    tier = finding.evidence_tier
    value = tier.value if isinstance(tier, EvidenceTier) else str(tier or "")
    return value in {
        EvidenceTier.CONFIGURED_RESOURCE.value,
        EvidenceTier.RUNTIME_OBSERVED.value,
        EvidenceTier.CORROBORATED.value,
    }
