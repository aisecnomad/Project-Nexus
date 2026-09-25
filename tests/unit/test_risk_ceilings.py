"""Risk is bounded: breadth of vendor mentions never outranks a confirmed agent."""

from __future__ import annotations

from shadowscan.models import Evidence, Finding, Kind, RiskLevel, Surface
from shadowscan.risk import FRAMEWORK_USAGE_CEILING, MAX_CAPABILITY_WEIGHT, MAX_PROVIDER_WEIGHT, assess


def broad_finding(kind: Kind) -> Finding:
    f = Finding(surface=Surface.CODE, connector="code.filesystem", kind=kind, title="t", resource="repo", resource_type="project")
    for cap in ("code-exec", "autonomous", "saas-actions", "browsing", "memory", "multi-agent", "tool-use", "rag"):
        f.add_capability(cap)
    for provider in ("provider.openrouter", "provider.deepseek", "provider.perplexity", "provider.google-gemini", "provider.openai-compatible"):
        f.add_model_provider(provider)
    f.add_evidence(Evidence(signal="dependency:x", description="d", weight=0.95))
    f.add_evidence(Evidence(signal="dependency:y", description="d", weight=0.95))
    return f


def test_framework_usage_never_reaches_critical_and_ceilings_are_explained():
    risk = assess(broad_finding(Kind.FRAMEWORK_USAGE), inventory_present=True)
    assert risk.score <= FRAMEWORK_USAGE_CEILING
    assert risk.level != RiskLevel.CRITICAL
    ids = {factor.id for factor in risk.factors}
    assert {"capability-ceiling", "provider-ceiling"} <= ids
    capability_total = sum(factor.weight for factor in risk.factors if factor.id.startswith("capability"))
    provider_total = sum(factor.weight for factor in risk.factors if factor.id.startswith("provider"))
    assert capability_total == MAX_CAPABILITY_WEIGHT
    assert provider_total == MAX_PROVIDER_WEIGHT


def test_confirmed_agent_with_the_same_evidence_outranks_framework_usage():
    agent = assess(broad_finding(Kind.AGENT), inventory_present=True)
    usage = assess(broad_finding(Kind.FRAMEWORK_USAGE), inventory_present=True)
    assert agent.score > usage.score


def test_factors_still_sum_to_the_score_after_ceilings():
    risk = assess(broad_finding(Kind.FRAMEWORK_USAGE), inventory_present=True)
    assert sum(factor.weight for factor in risk.factors) == risk.score
