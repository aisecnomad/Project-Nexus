"""Risk scoring must be total: malformed metadata degrades to a neutral score, never a crash.

Metadata reaches ``assess()`` from loaded reports, incremental cache entries and
third-party plugins. None of those may abort the whole scan, and well-formed
input must keep scoring exactly as before the hardening.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import random
import re
from decimal import ROUND_HALF_EVEN, Decimal
from pathlib import Path

import pytest
from click.testing import CliRunner

import shadowscan.risk as risk_module
from shadowscan.cli import main
from shadowscan.config import ConfigValidationError, ConnectorSpec, ScanConfig
from shadowscan.connectors import ConnectorContext, get_connector_class
from shadowscan.engine import Engine
from shadowscan.models import (
    Evidence,
    Finding,
    Kind,
    Risk,
    RiskFactor,
    RiskLevel,
    ScanStats,
    Surface,
    now_iso,
)
from shadowscan.risk import (
    CAPABILITY_WEIGHTS,
    GOVERNANCE_WEIGHTS,
    KIND_BASE,
    PROVIDER_WEIGHTS,
    TAG_WEIGHTS,
    RiskPolicy,
    _confidence_scale,
    assess,
    provider_ids,
)
from shadowscan.signatures.schema import CAPABILITIES

GARBAGE = ["many", "", None, [3], {"n": 3}, True, float("nan"), float("inf"), "3.5", object()]


def _finding(**overrides) -> Finding:
    base = dict(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.AGENT,
        title="agent",
        resource="repo/agent.py",
        resource_type="agent",
        confidence=0.9,
    )
    base.update(overrides)
    return Finding(**base)


def _ids(risk: Risk) -> set[str]:
    return {factor.id for factor in risk.factors}


# ------------------------------------------------------------------ metadata


@pytest.mark.parametrize("count", GARBAGE)
def test_non_numeric_secret_count_scores_without_the_multiple_secrets_factor(count):
    risk = assess(_finding(kind=Kind.SECRET, metadata={"count": count}))
    assert risk.score >= 0 and "multiple-secrets" not in _ids(risk)


@pytest.mark.parametrize("count, shown", [(3, "3"), ("3", "3"), (3.9, "3"), (2, "2")])
def test_numeric_secret_counts_still_score_the_multiple_secrets_factor(count, shown):
    risk = assess(_finding(kind=Kind.SECRET, metadata={"count": count}))
    factor = next(factor for factor in risk.factors if factor.id == "multiple-secrets")
    assert factor.weight == 5 and factor.description == f"{shown} credentials in one place"


@pytest.mark.parametrize("count", [1, 0, -4, "1", "0"])
def test_single_or_no_secrets_do_not_score_the_multiple_secrets_factor(count):
    assert "multiple-secrets" not in _ids(assess(_finding(kind=Kind.SECRET, metadata={"count": count})))


def test_mcp_server_entries_of_any_shape_are_tolerated():
    servers = [
        "stdio",
        None,
        ["transport", "stdio"],
        5,
        2.5,
        True,
        {"transport": "stdio"},
        {"auto_approve": ["*"]},
        {"url": "http://internal.example/mcp"},
    ]
    risk = assess(_finding(kind=Kind.MCP_SERVER, metadata={"servers": servers}))
    assert {"mcp-stdio", "mcp-auto-approve", "mcp-plain-http"} <= _ids(risk)
    for servers in ("stdio", {"transport": "stdio"}, 7, None, [], ["stdio"], [None], [["stdio"]]):
        risk = assess(_finding(kind=Kind.MCP_SERVER, metadata={"servers": servers}))
        assert risk.score >= 0
        assert not {"mcp-stdio", "mcp-auto-approve", "mcp-plain-http"} & _ids(risk)


@pytest.mark.parametrize("definitions", ["not a list", 5, {"a": {"file": "a.md"}}, None, True, 2.0])
def test_agent_definitions_count_only_when_they_are_a_list(definitions):
    risk = assess(_finding(kind=Kind.AGENT_CONFIG, metadata={"agent_definitions": definitions}))
    assert risk.score >= 0 and "sub-agents" not in _ids(risk)


@pytest.mark.parametrize(
    "definitions, weight",
    [
        ([{"file": "a.md"}], 3),
        ([{"file": "a.md"}, {"file": "b.md"}], 6),
        (({"file": "a.md"},) * 5, 10),
        ([], 0),
    ],
)
def test_agent_definition_lists_still_score_sub_agents(definitions, weight):
    risk = assess(_finding(kind=Kind.AGENT_CONFIG, metadata={"agent_definitions": definitions}))
    factor = next((factor for factor in risk.factors if factor.id == "sub-agents"), None)
    assert (factor.weight if factor else 0) == weight


@pytest.mark.parametrize("events", GARBAGE + [-5, "-12000"])
def test_gateway_event_garbage_scores_without_the_volume_factor(events):
    risk = assess(_finding(kind=Kind.GATEWAY_CALLER, metadata={"events": events}))
    assert risk.score >= 0 and "volume" not in _ids(risk)


@pytest.mark.parametrize("events, weight", [(12_000, 10), ("12000", 10), (1500.5, 5), (1000, 5), (999, 0)])
def test_gateway_event_counts_still_score_volume(events, weight):
    risk = assess(_finding(kind=Kind.GATEWAY_CALLER, metadata={"events": events}))
    factor = next((factor for factor in risk.factors if factor.id == "volume"), None)
    assert (factor.weight if factor else 0) == weight


@pytest.mark.parametrize("kind", [Kind.OAUTH_GRANT, Kind.BOT_APP])
@pytest.mark.parametrize("users", GARBAGE)
def test_user_count_garbage_scores_without_the_blast_radius_factor(kind, users):
    for key in ("user_count", "consenting_users", "users", "install_count"):
        risk = assess(_finding(kind=kind, metadata={key: users}))
        assert risk.score >= 0 and "blast-radius" not in _ids(risk)


@pytest.mark.parametrize(
    "metadata, weight",
    [
        ({"user_count": 250}, 10),
        ({"consenting_users": "42"}, 5),
        ({"users": 12.9}, 5),
        ({"install_count": 9}, 0),
        ({"user_count": "garbage", "consenting_users": 500}, 0),  # first present key wins, as before
    ],
)
def test_user_counts_still_score_blast_radius(metadata, weight):
    risk = assess(_finding(kind=Kind.OAUTH_GRANT, metadata=metadata))
    factor = next((factor for factor in risk.factors if factor.id == "blast-radius"), None)
    assert (factor.weight if factor else 0) == weight


@pytest.mark.parametrize("kind", list(Kind))
def test_non_dict_metadata_and_malformed_list_fields_never_abort_scoring(index, kind):
    finding = _finding(kind=kind, tags=["policy.privileged-scopes"], capabilities=["code-exec"])
    finding.metadata = "garbage"
    finding.tags = [{"policy": "x"}, None, 3, "policy.privileged-scopes"]
    finding.capabilities = "code-exec"
    finding.frameworks = None
    finding.model_providers = ({"provider": "openai"}, "provider.openrouter")
    risk = assess(finding, index, inventory_present=True)
    assert risk.score >= 0 and risk.factors[0].id == "kind"
    assert {"tag:policy.privileged-scopes", "provider:provider.openrouter"} <= _ids(risk)
    assert "capability:code-exec" not in _ids(risk)


# ------------------------------------------------------------------ confidence scaling


def test_confidence_scaling_never_adds_risk_to_a_negative_subtotal():
    expired = _finding(
        kind=Kind.TOKEN, tags=["expired"], owner="alice", shadow=False, registry_match="svc", confidence=0.05
    )
    risk = assess(expired, inventory_present=True)
    assert (
        sum(factor.weight for factor in risk.factors if factor.id not in {"confidence-scaling", "bounds"})
        == -10
    )
    scaling = next(factor for factor in risk.factors if factor.id == "confidence-scaling")
    assert scaling.weight == 0
    assert "multiplied by 0.62" in scaling.description and "confidence is 0.05" in scaling.description
    # The floor is an explicit factor, so the listed factors still sum to the score.
    assert next(factor for factor in risk.factors if factor.id == "bounds").weight == 10
    assert sum(factor.weight for factor in risk.factors) == risk.score
    assert risk.score == 0 and risk.level == RiskLevel.INFO


def test_confidence_scaling_of_a_zero_subtotal_is_neutral():
    risk = assess(_finding(kind=Kind.TOKEN, tags=["expired"], owner="alice", confidence=0.2))
    scaling = next(factor for factor in risk.factors if factor.id == "confidence-scaling")
    assert scaling.weight == 0 and risk.score == 0


def test_confidence_scaling_of_a_positive_subtotal_is_unchanged():
    risk = assess(_finding(confidence=0.5))
    assert sum(factor.weight for factor in risk.factors if factor.id != "confidence-scaling") == 25
    scaling = next(factor for factor in risk.factors if factor.id == "confidence-scaling")
    assert scaling.weight == -5 and "multiplied by 0.80" in scaling.description
    assert risk.score == 20 and risk.level == RiskLevel.LOW
    assert sum(factor.weight for factor in risk.factors) == risk.score


def test_full_confidence_adds_no_scaling_factor():
    assert "confidence-scaling" not in _ids(assess(_finding(confidence=1.0)))


def _documented_score(total: int, confidence: float) -> int:
    """docs/concepts/risk.md: min(100, max(0, round(raw * (0.6 + 0.4 * confidence)))), halves to even."""
    scale = Decimal("0.6") + Decimal("0.4") * Decimal(repr(confidence))
    return max(0, min(100, int((Decimal(total) * scale).quantize(Decimal(1), rounding=ROUND_HALF_EVEN))))


def _assess_raw(total: int, confidence: float) -> Risk:
    """Assess a finding whose factors add up to exactly ``total`` before scaling."""
    kind = min(total, 100)
    extra = total - kind
    policy = RiskPolicy.from_options({"kinds": {"agent": kind}, "capabilities": {"code-exec": extra}})
    finding = _finding(confidence=confidence, owner="team", capabilities=["code-exec"] if extra else [])
    return assess(finding, policy=policy)


@pytest.mark.parametrize(
    "total, confidence, score, level",
    [
        (75, 0.15, 50, RiskLevel.HIGH),  # 75 * 0.66 = 49.5: half to even is 50 (floats said 49, medium)
        (45, 0.25, 32, RiskLevel.MEDIUM),  # 45 * 0.7 = 31.5
        (85, 0.25, 60, RiskLevel.HIGH),  # 85 * 0.7 = 59.5
        (125, 0.17, 84, RiskLevel.CRITICAL),  # 125 * 0.668 = 83.5
        (125, 0.21, 86, RiskLevel.CRITICAL),  # 125 * 0.684 = 85.5
    ],
)
def test_score_rounds_half_to_even_where_binary_floats_drifted(total, confidence, score, level):
    risk = _assess_raw(total, confidence)
    assert (risk.score, risk.level) == (score, level) == (_documented_score(total, confidence), level)
    assert sum(factor.weight for factor in risk.factors) == risk.score
    scaling = next(factor for factor in risk.factors if factor.id == "confidence-scaling")
    assert scaling.weight == score - total  # none of these is clamped, so no bounds factor either
    assert "bounds" not in _ids(risk)


def test_the_scaling_factor_names_the_exact_multiplier():
    risk = _assess_raw(75, 0.15)
    scaling = next(factor for factor in risk.factors if factor.id == "confidence-scaling")
    assert scaling.weight == -25
    assert "multiplied by 0.66 because confidence is 0.15" in scaling.description


def test_scale_equals_the_decimal_formula_over_the_whole_grid():
    # Every raw total from 0 to 130 (above 100 the score is clamped) at every confidence from
    # 0.000 to 1.000 in steps of 0.001. The float formula disagreed at five of these points.
    for total in range(131):
        for thousandths in range(1001):
            confidence = thousandths / 1000
            exact = max(0, min(100, round(total * _confidence_scale(confidence))))
            assert exact == _documented_score(total, confidence), (total, confidence)


def test_assess_follows_the_decimal_formula_and_its_factors_sum_to_the_score():
    rng = random.Random(20260315)
    for _ in range(400):
        total, confidence = rng.randint(0, 130), rng.randint(0, 1000) / 1000
        risk = _assess_raw(total, confidence)
        assert risk.score == _documented_score(total, confidence), (total, confidence)
        assert sum(factor.weight for factor in risk.factors) == risk.score, (total, confidence)


def test_danger_score_uses_the_same_exact_scaling():
    # Governance (shadow, 25) is excluded from the danger subtotal: 75 * 0.66 = 49.5 -> 50.
    policy = RiskPolicy.from_options({"kinds": {"agent": 75}, "governance": {"no-owner": 0}})
    finding = _finding(confidence=0.15, owner="team")
    finding.shadow = True
    risk = assess(finding, inventory_present=True, policy=policy)
    assert risk.danger_score == 50 and risk.score == _documented_score(100, 0.15) == 66


class _OddRepr(float):
    def __repr__(self) -> str:
        return "OddRepr(0.5)"


@pytest.mark.parametrize(
    "confidence", [1e-05, 5e-324, 0.1 + 0.2, 1 - 1e-16, _OddRepr(0.5), float("nan"), float("inf"), -3.0, 7.5]
)
def test_unusual_confidences_scale_without_error_and_keep_the_factors_exact(confidence):
    risk = _assess_raw(75, confidence)
    clamped = 1.0 if confidence != confidence else max(0.0, min(1.0, float(confidence)))
    assert risk.score == _documented_score(75, clamped)
    assert sum(factor.weight for factor in risk.factors) == risk.score


def test_danger_basis_omits_zero_weight_governance_factors():
    # Under "danger", governance factors are scaled to zero and never move
    # the score; they should not appear at all, matching how tag factors
    # already skip a zero-weight contribution (risk.py's `if w:` guard).
    danger = RiskPolicy(basis="danger")
    risk_no_owner = assess(_finding(owner=None), inventory_present=True, policy=danger)
    assert _ids(risk_no_owner).isdisjoint({"shadow", "registered", "no-owner"})
    for finding_shadow in (True, False):
        target = _finding(owner="alice")
        target.shadow = finding_shadow
        risk = assess(target, inventory_present=True, policy=danger)
        assert _ids(risk).isdisjoint({"shadow", "registered", "no-owner"})

    # Sanity check: the same findings under the default ("combined") basis do
    # score these factors, so the assertions above are testing the "danger"
    # scale-to-zero path and not an unrelated absence.
    combined = RiskPolicy()
    risk = assess(_finding(owner=None), inventory_present=True, policy=combined)
    assert "no-owner" in _ids(risk)


# ------------------------------------------------------------------ parity on well-formed input


def _reference_assess(finding: Finding, index, inventory_present: bool) -> Risk:
    """The scorer as shipped before hardening; only valid for well-formed input."""
    factors: list[RiskFactor] = []
    factors.append(RiskFactor("kind", f"{finding.kind.value} finding", KIND_BASE.get(finding.kind, 5)))
    if inventory_present:
        if finding.shadow:
            factors.append(RiskFactor("shadow", "not present in the sanctioned agent inventory", 25))
        elif finding.shadow is False:
            factors.append(RiskFactor("registered", f"registered as {finding.registry_match}", -10))
    if not finding.owner:
        factors.append(RiskFactor("no-owner", "no identifiable owner", 10))
    seen_caps = set()
    for cap in finding.capabilities:
        if cap in CAPABILITY_WEIGHTS and cap not in seen_caps:
            seen_caps.add(cap)
            w, d = CAPABILITY_WEIGHTS[cap]
            factors.append(RiskFactor(f"capability:{cap}", d, w))
    for tag in finding.tags:
        if tag in TAG_WEIGHTS:
            w, d = TAG_WEIGHTS[tag]
            if w:
                factors.append(RiskFactor(f"tag:{tag}", d, w))
    for pid in finding.model_providers:
        if pid in PROVIDER_WEIGHTS:
            w, d = PROVIDER_WEIGHTS[pid]
            factors.append(RiskFactor(f"provider:{pid}", d, w))
    if index is not None:
        notes = []
        for sid in finding.frameworks + finding.model_providers:
            sig = index.get(sid)
            if sig and sig.risk_notes:
                notes.extend(sig.risk_notes)
        if notes:
            factors.append(RiskFactor("vendor-notes", "; ".join(dict.fromkeys(notes))[:300], 5))
    if (
        finding.kind == Kind.SECRET
        and finding.metadata.get("count", 1)
        and int(finding.metadata.get("count", 1)) > 1
    ):
        factors.append(
            RiskFactor("multiple-secrets", f"{finding.metadata['count']} credentials in one place", 5)
        )
    if finding.kind == Kind.MCP_SERVER:
        servers = finding.metadata.get("servers") or []
        if any(s.get("transport") == "stdio" for s in servers):
            factors.append(
                RiskFactor("mcp-stdio", "local stdio MCP servers run with the user's full privileges", 5)
            )
        if any(s.get("auto_approve") for s in servers):
            factors.append(RiskFactor("mcp-auto-approve", "MCP tools auto-approved without confirmation", 10))
        if any(s.get("url") and str(s.get("url")).startswith("http://") for s in servers):
            factors.append(RiskFactor("mcp-plain-http", "remote MCP server over plain HTTP", 10))
    if finding.kind == Kind.AGENT_CONFIG and finding.metadata.get("agent_definitions"):
        n = len(finding.metadata["agent_definitions"])
        factors.append(RiskFactor("sub-agents", f"{n} sub-agent definition(s)", min(10, 3 * n)))
    if finding.kind == Kind.GATEWAY_CALLER:
        events = int(finding.metadata.get("events") or 0)
        if events >= 10_000:
            factors.append(RiskFactor("volume", f"very high call volume ({events})", 10))
        elif events >= 1_000:
            factors.append(RiskFactor("volume", f"high call volume ({events})", 5))
    if finding.kind in {Kind.OAUTH_GRANT, Kind.BOT_APP}:
        users = (
            finding.metadata.get("user_count")
            or finding.metadata.get("consenting_users")
            or finding.metadata.get("users")
            or finding.metadata.get("install_count")
            or 0
        )
        try:
            users = int(users)
        except (TypeError, ValueError):
            users = 0
        if users >= 100:
            factors.append(RiskFactor("blast-radius", f"{users} users / installations", 10))
        elif users >= 10:
            factors.append(RiskFactor("blast-radius", f"{users} users / installations", 5))
    total = sum(f.weight for f in factors)
    scale = 0.6 + 0.4 * max(0.0, min(1.0, finding.confidence))
    score = int(round(max(0, min(100, total * scale))))
    if scale < 1.0:
        # Round the scaled score first so the adjustment is exactly the
        # difference the reported score shows, ties included.
        factors.append(
            RiskFactor("confidence-scaling", "scaled by confidence", int(round(total * scale)) - total)
        )
    return Risk(score=score, level=RiskLevel.from_score(score), factors=factors)


def _fixture_connectors(fixtures: Path) -> list[tuple[str, dict]]:
    return [
        ("code.filesystem", {"path": str(fixtures / "sample_repo"), "label": "fixture"}),
        ("cloud.aws", {"input": str(fixtures / "cloud" / "aws_records.jsonl")}),
        ("cloud.azure", {"input": str(fixtures / "cloud" / "azure_records.jsonl")}),
        ("cloud.gcp", {"input": str(fixtures / "cloud" / "gcp_records.jsonl")}),
        ("cloud.oci", {"input": str(fixtures / "cloud" / "oci_records.jsonl")}),
        ("gateway.logs", {"input": str(fixtures / "gateway" / "azure_openai_diag.json")}),
        ("gateway.logs", {"input": str(fixtures / "gateway" / "bedrock_invocations.jsonl")}),
        ("gateway.logs", {"input": str(fixtures / "gateway" / "egress_proxy.log")}),
        ("gateway.logs", {"input": str(fixtures / "gateway" / "litellm_spend.jsonl")}),
        (
            "identity.auth0",
            {"input": str(fixtures / "identity" / "auth0_clients.json"), "domain": "acme.eu.auth0.com"},
        ),
        ("identity.entra", {"input": str(fixtures / "identity" / "entra_graph.json"), "tenant_id": "t"}),
        ("identity.google-workspace", {"input": str(fixtures / "identity" / "google_tokens.json")}),
        ("identity.jwt", {"input": str(fixtures / "identity" / "tokens.txt")}),
        (
            "identity.okta",
            {"input": str(fixtures / "identity" / "okta_apps.json"), "org_url": "https://acme.okta.com"},
        ),
        ("lowcode.make", {"input": str(fixtures / "lowcode" / "make_scenarios.json")}),
        ("lowcode.n8n", {"input": str(fixtures / "lowcode" / "n8n_workflows.json")}),
        ("lowcode.power-platform", {"input": str(fixtures / "lowcode" / "power_platform.json")}),
        (
            "lowcode.salesforce",
            {
                "input": str(fixtures / "lowcode" / "salesforce.json"),
                "instance_url": "https://acme.my.salesforce.com",
            },
        ),
        (
            "lowcode.servicenow",
            {"input": str(fixtures / "lowcode" / "servicenow.json"), "instance": "acme.service-now.com"},
        ),
        ("lowcode.workato", {"input": str(fixtures / "lowcode" / "workato_recipes.json")}),
        ("lowcode.zapier", {"input": str(fixtures / "lowcode" / "zapier_zaps.csv")}),
        (
            "saas.atlassian",
            {
                "input": str(fixtures / "saas" / "atlassian_plugins.json"),
                "site": "https://acme.atlassian.net",
            },
        ),
        (
            "saas.generic",
            {
                "input": str(fixtures / "saas" / "generic_apps.csv"),
                "platform": "google-marketplace",
                "fields": {
                    "name": "App Name",
                    "scopes": "Permissions",
                    "users": "Users",
                    "owner": "Installed By",
                    "url": "Domain",
                },
            },
        ),
        ("saas.github-apps", {"input": str(fixtures / "saas" / "github_installations.json"), "org": "acme"}),
        ("saas.microsoft-teams", {"input": str(fixtures / "saas" / "teams_apps.json"), "tenant_id": "t"}),
        ("saas.notion", {"input": str(fixtures / "saas" / "notion_users.json")}),
        ("saas.slack", {"input": str(fixtures / "saas" / "slack.json")}),
        ("saas.zoom", {"input": str(fixtures / "saas" / "zoom_apps.json")}),
    ]


@pytest.fixture(scope="module")
def fixture_findings(index, fixtures) -> list[Finding]:
    findings: list[Finding] = []
    for name, config in _fixture_connectors(fixtures):
        connector = get_connector_class(name)(ConnectorContext(config=config, index=index))
        findings.extend(connector.run())
    return findings


def test_bundled_fixture_findings_score_identically_to_the_reference(index, fixture_findings):
    assert len(fixture_findings) >= 50 and {finding.kind for finding in fixture_findings} >= {
        Kind.SECRET,
        Kind.MCP_SERVER,
        Kind.AGENT_CONFIG,
        Kind.GATEWAY_CALLER,
        Kind.OAUTH_GRANT,
        Kind.BOT_APP,
    }
    for finding in fixture_findings:
        for inventory_present, shadow, match in (
            (False, None, None),
            (True, True, None),
            (True, False, "registered"),
        ):
            candidate = copy.deepcopy(finding)
            candidate.shadow, candidate.registry_match = shadow, match
            actual = assess(candidate, index, inventory_present=inventory_present)
            expected = _reference_assess(candidate, index, inventory_present)
            assert (actual.score, actual.level) == (expected.score, expected.level)
            # The bounds factor keeps the listed factors summing to a floored or
            # capped score; the reference model has no such factor.
            actual_factors = [factor for factor in actual.factors if factor.id != "bounds"]
            assert [factor.id for factor in actual_factors] == [factor.id for factor in expected.factors]
            for got, want in zip(actual_factors, expected.factors, strict=True):
                if got.id == "confidence-scaling":
                    # The only intended difference: scaling never reads as added risk.
                    assert got.weight == min(0, want.weight)
                else:
                    assert (got.description, got.weight) == (want.description, want.weight)


# ------------------------------------------------------------------ imported findings


def _record(**overrides) -> dict:
    record = _finding().to_dict()
    # A report's id and discriminator describe the record's own identity, so a
    # record for another resource must have them recomputed rather than copied.
    del record["id"], record["identity_discriminator"]
    record.update(overrides)
    return record


@pytest.mark.parametrize(
    "name, value",
    [
        ("metadata", "garbage"),
        ("metadata", None),
        ("metadata", ["count", 3]),
        ("tags", "policy.privileged-scopes"),
        ("tags", ["ok", 1]),
        ("tags", None),
        ("capabilities", {"code-exec": True}),
        ("frameworks", "framework.langchain"),
        ("model_providers", [None]),
        ("models", 3),
        ("permissions", [["admin"]]),
        ("shadow", "false"),
        ("shadow", 0),
        ("owner", 5),
        ("first_seen", 1700000000),
        ("last_seen", ["2026"]),
        ("id", 12345),
        ("provider", ["aws"]),
        ("registry_match", {"id": "x"}),
        ("identity_discriminator", 1),
    ],
)
def test_from_dict_rejects_field_shapes_the_pipeline_cannot_process(name, value):
    with pytest.raises(ValueError, match=name):
        Finding.from_dict(_record(**{name: value}))


def test_from_dict_rejects_risk_factors_and_evidence_without_text_fields():
    for factor in (
        {"weight": 1},
        {"id": "kind", "weight": 1},
        {"id": None, "description": "x", "weight": 1},
        {"id": "kind", "description": 5, "weight": 1},
    ):
        record = _record()
        record["risk"]["factors"] = [factor]
        with pytest.raises(ValueError, match="risk factor"):
            Finding.from_dict(record)
    for item in (
        {"description": "x"},
        {"signal": 1, "description": "x"},
        {"signal": "s", "description": None},
    ):
        with pytest.raises(ValueError, match="evidence"):
            Finding.from_dict(_record(evidence=[item]))


@pytest.mark.parametrize(
    "name, value",
    [
        ("location", ["agent.py:1"]),
        ("location", 5),
        ("snippet", {"source": "agent.run()"}),
        ("signature", ["framework.example"]),
        ("attributes", None),
        ("attributes", []),
        ("attributes", "invalid"),
    ],
)
def test_from_dict_rejects_evidence_shapes_before_postprocessing(name, value):
    item = {"signal": "dependency", "description": "Agent package", name: value}
    with pytest.raises(ValueError, match=f"evidence {name}"):
        Finding.from_dict(_record(evidence=[item]))


def test_from_dict_accepts_optional_evidence_text_and_object_attributes():
    finding = Finding.from_dict(
        _record(
            evidence=[
                {
                    "signal": "dependency",
                    "description": "Agent package",
                    "location": None,
                    "snippet": None,
                    "signature": None,
                    "attributes": {"confidence_group": "dependency", "optional": None},
                }
            ]
        )
    )
    finding.recompute_confidence()
    assert finding.confidence == 0.5
    assert finding.evidence[0].location is None
    assert finding.evidence[0].attributes["optional"] is None


def test_from_dict_keeps_optional_text_fields_null_and_accepts_garbage_inside_metadata():
    metadata = {
        "count": "many",
        "servers": "stdio",
        "agent_definitions": 3,
        "events": [1],
        "user_count": None,
    }
    finding = Finding.from_dict(_record(owner=None, first_seen=None, shadow=None, metadata=metadata))
    assert finding.owner is None and finding.shadow is None and finding.metadata == metadata
    for kind in (Kind.SECRET, Kind.MCP_SERVER, Kind.AGENT_CONFIG, Kind.GATEWAY_CALLER, Kind.OAUTH_GRANT):
        finding.kind = kind
        assert assess(finding, inventory_present=True).score >= 0


def test_engine_completes_when_report_derived_findings_carry_garbage_metadata(monkeypatch, index):
    records = [
        _record(kind="secret", resource="repo/.env", resource_type="secret", metadata={"count": "many"}),
        _record(
            kind="mcp-server",
            resource="repo/.mcp.json",
            resource_type="mcp-config",
            metadata={
                "servers": ["stdio", None, ["x"], 5, {"transport": "stdio", "url": "http://localhost:3000"}]
            },
        ),
        _record(
            kind="agent-config",
            resource="repo/.claude",
            resource_type="agent-config",
            metadata={"agent_definitions": "not a list"},
        ),
        _record(
            surface="gateway",
            connector="gateway.logs",
            kind="gateway-caller",
            resource="gateway:user:bob",
            resource_type="gateway-caller",
            metadata={"events": "lots", "runtime_observations": "none"},
        ),
        _record(
            surface="identity",
            connector="identity.okta",
            kind="oauth-grant",
            resource="okta:app:1",
            resource_type="oauth-app",
            metadata={"user_count": [1, 2], "users": {"n": 1}},
        ),
    ]

    class ReportConnector:
        def __init__(self, ctx):
            self.ctx = ctx

        def run(self):
            self.ctx.stats = ScanStats(connector="report", started_at=now_iso(), finished_at=now_iso())
            return [Finding.from_dict(record) for record in records]

    monkeypatch.setattr("shadowscan.engine.get_connector_class", lambda name: ReportConnector)
    cfg = ScanConfig(
        connectors=[ConnectorSpec("code.filesystem")],
        inventory=[str(Path(__file__).parents[1] / "fixtures" / "inventory" / "ops-provisioning-04.yaml")],
    )
    result = Engine(cfg, index).run()
    assert result.complete, [stats.errors for stats in result.stats]
    assert len(result.findings) == len(records)
    assert all(
        finding.risk.factors and finding.risk.score >= 0 and finding.shadow is True
        for finding in result.findings
    )
    mcp = next(finding for finding in result.findings if finding.kind == Kind.MCP_SERVER)
    assert {"mcp-stdio", "mcp-plain-http"} <= _ids(mcp.risk) and "mcp-auto-approve" not in _ids(mcp.risk)
    secret = next(finding for finding in result.findings if finding.kind == Kind.SECRET)
    assert "multiple-secrets" not in _ids(secret.risk)
    assert result.findings == sorted(
        result.findings, key=lambda f: (-f.risk.score, -f.confidence, f.surface.value, f.title)
    )


# ------------------------------------------------------------------ risk_weights typos


@pytest.mark.parametrize("key", ["code-execution", "codeexec", "tool_use", "multi-agents", "network"])
def test_unknown_capability_key_is_rejected_by_key_not_value(key):
    # A capability typo used to exit 0 and change nothing.
    with pytest.raises(ValueError) as failure:
        RiskPolicy.from_options({"capabilities": {key: 99}})
    message = str(failure.value)
    assert f"risk_weights.capabilities.{key} is not a capability" in message
    assert "99" not in message and "code-exec" in message  # the value is not echoed; the choices are listed
    with pytest.raises(ConfigValidationError, match=f"options.risk_weights.capabilities.{key}"):
        ScanConfig(risk_weights={"capabilities": {key: 99}})


def test_capability_typo_suggests_the_closest_name():
    with pytest.raises(ValueError, match=r"did you mean code-exec\?"):
        RiskPolicy.from_options({"capabilities": {"code-execution": 99}})


def test_every_capability_in_the_vocabulary_is_accepted_and_applies():
    assert set(CAPABILITIES) == set(CAPABILITY_WEIGHTS)
    policy = RiskPolicy.from_options({"capabilities": dict.fromkeys(CAPABILITIES, 7)})
    assert {weight for weight, _ in policy.capabilities.values()} == {7}
    risk = assess(_finding(capabilities=["code-exec"], owner="team"), policy=policy)
    assert next(f for f in risk.factors if f.id == "capability:code-exec").weight == 7


def test_provider_ids_are_checked_against_the_loaded_signatures(index):
    known = provider_ids(index)
    assert set(PROVIDER_WEIGHTS) <= known  # every built-in provider weight names a real signature
    policy = RiskPolicy.from_options({"providers": {"provider.deepseek": 20}}, known_providers=known)
    assert policy.providers["provider.deepseek"][0] == 20
    with pytest.raises(ValueError) as failure:
        RiskPolicy.from_options({"providers": {"provider.opneai": 88}}, known_providers=known)
    message = str(failure.value)
    assert "risk_weights.providers.provider.opneai is not a model provider signature id" in message
    assert "did you mean provider.openai?" in message and "88" not in message
    # Without the loaded signatures there is nothing to check against: the key is only validated for shape.
    assert (
        RiskPolicy.from_options({"providers": {"provider.opneai": 88}}).providers["provider.opneai"][0] == 88
    )


def test_engine_rejects_an_unknown_provider_id_before_any_connector_runs(index, monkeypatch):
    constructed = []

    def forbidden(name):
        constructed.append(name)
        raise AssertionError("no connector may be constructed")

    monkeypatch.setattr("shadowscan.engine.get_connector_class", forbidden)
    cfg = ScanConfig(
        connectors=[ConnectorSpec("code.filesystem")], risk_weights={"providers": {"provider.opneai": 5}}
    )
    with pytest.raises(ConfigValidationError, match=r"options\.risk_weights\.providers\.provider\.opneai"):
        Engine(cfg, index)
    # A configuration changed after construction is caught before the run, like the other options.
    cfg = ScanConfig(connectors=[ConnectorSpec("code.filesystem")])
    engine = Engine(cfg, index)
    cfg.risk_weights = {"providers": {"provider.opneai": 5}}
    with pytest.raises(ConfigValidationError, match=r"risk_weights\.providers\.provider\.opneai"):
        engine.run()
    assert constructed == []


def test_engine_accepts_the_readme_risk_policy_and_custom_provider_signatures(tmp_path, index):
    readme = {
        "capabilities": {"code-exec": 25},
        "tags": {"meeting-bot": 20},
        "providers": {"provider.deepseek": 20},
        "kinds": {"agent": 20},
        "governance": {"shadow": 15, "no-owner": 5, "registered": -10},
    }
    Engine(ScanConfig(connectors=[ConnectorSpec("code.filesystem")], risk_weights=readme), index)
    # A provider defined by the organisation's own signature pack is a valid id once that pack is loaded.
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "acme.yaml").write_text(
        "- id: custom.acme-llm\n  name: Acme LLM\n  category: provider\n  signals:\n"
        "    - type: domain\n      values: [api.acme-llm.example]\n      weight: 0.9\n"
    )
    weights = {"providers": {"custom.acme-llm": 12}}
    cfg = ScanConfig(
        connectors=[ConnectorSpec("code.filesystem")], signature_dirs=[str(pack)], risk_weights=weights
    )
    assert "custom.acme-llm" in provider_ids(Engine(cfg).index)
    with pytest.raises(ConfigValidationError, match="custom.acme-llm"):
        Engine(ScanConfig(connectors=[ConnectorSpec("code.filesystem")], risk_weights=weights), index)


def test_cli_scan_fails_on_a_capability_typo_without_echoing_the_value(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("openai\n")
    cfg = tmp_path / "scan.yaml"
    cfg.write_text(
        f"connectors:\n  - name: code.filesystem\n    path: {repo}\n"
        "options:\n  risk_weights:\n    capabilities: {code-execution: 97}\n"
    )
    res = CliRunner().invoke(main, ["scan", "-c", str(cfg), "--format", "json"])
    assert res.exit_code != 0 and "risk_weights.capabilities.code-execution" in res.output
    assert "97" not in res.output
    cfg.write_text(cfg.read_text().replace("code-execution", "code-exec"))
    res = CliRunner().invoke(main, ["scan", "-c", str(cfg), "--format", "json"])
    assert res.exit_code == 0, res.output
    assert json.loads(res.output)["findings"]


def test_unknown_tag_key_warns_once_and_is_still_accepted(caplog, monkeypatch):
    # Tags are open-ended (signature packs, plugins and identity types add their own), so a
    # tag that is not one of the built-in weighted tags can be valid: warn, never reject.
    monkeypatch.setattr(risk_module, "_WARNED_TAGS", set())
    with caplog.at_level(logging.WARNING, logger="shadowscan.risk"):
        policy = RiskPolicy.from_options({"tags": {"plaintext-credentail": 31, "plaintext-credential": 30}})
        RiskPolicy.from_options({"tags": {"plaintext-credentail": 31}})
        ScanConfig(risk_weights={"tags": {"plaintext-credentail": 31}})
    messages = [record.getMessage() for record in caplog.records if record.name == "shadowscan.risk"]
    assert len(messages) == 1
    assert "risk_weights.tags.plaintext-credentail is not a built-in tag" in messages[0]
    assert "did you mean plaintext-credential?" in messages[0] and "31" not in messages[0]
    assert policy.tags["plaintext-credentail"][0] == 31 and policy.tags["plaintext-credential"][0] == 30
    # The typo scores nothing for a finding that carries the real tag; the real one still scores.
    risk = assess(_finding(tags=["plaintext-credential"], owner="team"), policy=policy)
    assert next(f for f in risk.factors if f.id == "tag:plaintext-credential").weight == 30


def test_builtin_tag_keys_do_not_warn(caplog, monkeypatch):
    monkeypatch.setattr(risk_module, "_WARNED_TAGS", set())
    with caplog.at_level(logging.WARNING, logger="shadowscan.risk"):
        RiskPolicy.from_options({"tags": dict.fromkeys(TAG_WEIGHTS, 1)})
    assert not [record for record in caplog.records if record.name == "shadowscan.risk"]


# ------------------------------------------------- default weights, levels, evidence groups

# The default weights are policy: a change moves every score, so it has to be deliberate. When this
# fails, update docs/concepts/risk.md, the changelog and the migration notes, then this digest.
_DEFAULT_WEIGHTS_DIGEST = "55661f8d723089881dc2a4f46c5f2ad578856ba380453299b8a092a685fd59f4"


def test_default_risk_weights_change_only_deliberately():
    tables = {
        "kinds": {kind.value: weight for kind, weight in KIND_BASE.items()},
        "capabilities": CAPABILITY_WEIGHTS,
        "tags": TAG_WEIGHTS,
        "providers": PROVIDER_WEIGHTS,
        "governance": GOVERNANCE_WEIGHTS,
    }
    digest = hashlib.sha256(json.dumps(tables, sort_keys=True).encode()).hexdigest()
    assert digest == _DEFAULT_WEIGHTS_DIGEST, f"the default risk weights changed (new digest {digest})"


def test_documented_default_weights_match_the_code():
    doc = Path(__file__).resolve().parents[2] / "docs" / "concepts" / "risk.md"
    rows = re.findall(
        r"^\| (`[^|]+`) \| [^|]* \| ([\u2212+-]?\d+) \|$", doc.read_text(encoding="utf-8"), re.M
    )
    checked = 0
    for names, cell in rows:
        weight = int(cell.replace("\u2212", "-"))
        for name in (part.strip().strip("`") for part in names.split(" / ")):
            if name in GOVERNANCE_WEIGHTS:
                assert GOVERNANCE_WEIGHTS[name] == weight, name
            elif name.startswith("tag:"):
                assert TAG_WEIGHTS[name[4:]][0] == weight, name
            elif name.startswith("capability:"):
                assert CAPABILITY_WEIGHTS[name[11:]][0] == weight, name
            else:
                continue
            checked += 1
    assert checked >= 10, "the documented weight table was not found"


@pytest.mark.parametrize(
    "score,level",
    [
        (100, "critical"),
        (75, "critical"),
        (74, "high"),
        (50, "high"),
        (49, "medium"),
        (25, "medium"),
        (24, "low"),
        (1, "low"),
        (0, "info"),
        (-3, "info"),
    ],
)
def test_risk_level_boundaries_match_the_documented_ranges(score, level):
    assert RiskLevel.from_score(score) is RiskLevel(level)


def _confidence(*weights: float, groups: tuple[str | None, ...] | None = None) -> float:
    groups = groups or (None,) * len(weights)
    finding = _finding(
        evidence=[
            Evidence(
                signal=f"test:{number}",
                description=f"observation {number}",
                weight=weight,
                attributes={"confidence_group": group} if group else {},
            )
            for number, (weight, group) in enumerate(zip(weights, groups, strict=True))
        ]
    )
    finding.recompute_confidence()
    return finding.confidence


def test_independent_evidence_combines_by_noisy_or():
    assert _confidence(0.4, 0.5) == 0.7  # 1 - 0.6 * 0.5
    assert _confidence(0.4, 0.5, 0.5) == 0.85


def test_evidence_in_one_confidence_group_counts_once_at_its_strongest():
    # Repeated observations of one thing (the same idiom in several files) are correlated:
    # adding them up would turn a pile of weak signals into certainty.
    assert _confidence(0.4, 0.5, groups=("g", "g")) == 0.5
    assert _confidence(0.2, 0.2, 0.2, 0.2, groups=("g", "g", "g", "g")) == 0.2
    # Different groups, and grouped plus ungrouped evidence, are independent of each other.
    assert _confidence(0.4, 0.5, groups=("one", "two")) == 0.7
    assert _confidence(0.4, 0.5, 0.4, groups=("g", "g", None)) == 0.7
