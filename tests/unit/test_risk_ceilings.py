"""Risk is bounded: breadth of vendor mentions never outranks a confirmed agent."""

from __future__ import annotations

import pytest

from shadowscan.models import Evidence, Finding, Kind, RiskLevel, Surface
from shadowscan.risk import FRAMEWORK_USAGE_CEILING, MAX_CAPABILITY_WEIGHT, MAX_PROVIDER_WEIGHT, assess


def broad_finding(kind: Kind, *tags: str) -> Finding:
    """An unregistered, ownerless finding that names every vendor it can."""
    f = Finding(surface=Surface.CODE, connector="code.filesystem", kind=kind, title="t", resource="repo", resource_type="project")
    for cap in ("code-exec", "autonomous", "saas-actions", "browsing", "memory", "multi-agent", "tool-use", "rag"):
        f.add_capability(cap)
    for provider in ("provider.openrouter", "provider.deepseek", "provider.perplexity", "provider.google-gemini", "provider.openai-compatible"):
        f.add_model_provider(provider)
    for tag in tags:
        f.add_tag(tag)
    f.add_evidence(Evidence(signal="dependency:x", description="d", weight=0.95))
    f.add_evidence(Evidence(signal="dependency:y", description="d", weight=0.95))
    f.recompute_confidence()
    f.shadow = True
    return f


def factor_ids(risk) -> set[str]:
    return {factor.id for factor in risk.factors}


def test_framework_usage_is_held_at_its_ceiling_and_the_ceilings_are_explained():
    finding = broad_finding(Kind.FRAMEWORK_USAGE)
    assert finding.confidence > 0.99
    risk = assess(finding, inventory_present=True)
    assert risk.score == FRAMEWORK_USAGE_CEILING
    assert risk.level != RiskLevel.CRITICAL
    assert {"capability-ceiling", "provider-ceiling", "kind-ceiling"} <= factor_ids(risk)
    capability_total = sum(factor.weight for factor in risk.factors if factor.id.startswith("capability"))
    provider_total = sum(factor.weight for factor in risk.factors if factor.id.startswith("provider"))
    assert capability_total == MAX_CAPABILITY_WEIGHT
    assert provider_total == MAX_PROVIDER_WEIGHT
    assert sum(factor.weight for factor in risk.factors) == risk.score


def test_confirmed_agent_with_the_same_evidence_outranks_framework_usage():
    agent = assess(broad_finding(Kind.AGENT), inventory_present=True)
    usage = assess(broad_finding(Kind.FRAMEWORK_USAGE), inventory_present=True)
    assert usage.score == FRAMEWORK_USAGE_CEILING
    assert agent.score > usage.score
    assert agent.level == RiskLevel.CRITICAL


@pytest.mark.parametrize("kind", [Kind.FRAMEWORK_USAGE, Kind.AGENT, Kind.SECRET])
def test_factors_sum_to_the_score_when_the_raw_total_exceeds_the_scale(kind):
    finding = broad_finding(kind, "hardcoded-credential", "policy.privileged-scopes")
    risk = assess(finding, inventory_present=True)
    assert "score-bounds" in factor_ids(risk)
    assert sum(factor.weight for factor in risk.factors) == risk.score
    expected = FRAMEWORK_USAGE_CEILING if kind == Kind.FRAMEWORK_USAGE else 100
    assert risk.score == expected


def test_factors_sum_to_the_score_under_confidence_scaling():
    finding = broad_finding(Kind.AGENT)
    finding.evidence.clear()
    finding.add_evidence(Evidence(signal="dependency:x", description="d", weight=0.35))
    finding.recompute_confidence()
    risk = assess(finding, inventory_present=True)
    assert "confidence-scaling" in factor_ids(risk)
    assert sum(factor.weight for factor in risk.factors) == risk.score


@pytest.mark.parametrize("value", ["many", float("inf"), float("nan"), [3], {"n": 1}, True, None])
def test_malformed_connector_counts_do_not_break_scoring(value):
    for kind, key in ((Kind.SECRET, "count"), (Kind.GATEWAY_CALLER, "events"), (Kind.BOT_APP, "user_count")):
        finding = Finding(surface=Surface.CODE, connector="c", kind=kind, title="t", resource="r", resource_type="x")
        finding.metadata[key] = value
        risk = assess(finding)
        assert 0 <= risk.score <= 100
        assert not {"multiple-secrets", "volume", "blast-radius"} & factor_ids(risk)
