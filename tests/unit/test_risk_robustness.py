"""Risk scoring must be total: malformed metadata degrades to a neutral score, never a crash.

Metadata reaches ``assess()`` from loaded reports, incremental cache entries and
third-party plugins. None of those may abort the whole scan, and well-formed
input must keep scoring exactly as before the hardening.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors import ConnectorContext, get_connector_class
from shadowscan.engine import Engine
from shadowscan.models import Finding, Kind, Risk, RiskFactor, RiskLevel, ScanStats, Surface, now_iso
from shadowscan.risk import CAPABILITY_WEIGHTS, KIND_BASE, PROVIDER_WEIGHTS, TAG_WEIGHTS, assess

GARBAGE = ["many", "", None, [3], {"n": 3}, True, float("nan"), float("inf"), "3.5", object()]


def _finding(**overrides) -> Finding:
    base = dict(surface=Surface.CODE, connector="code.filesystem", kind=Kind.AGENT, title="agent",
                resource="repo/agent.py", resource_type="agent", confidence=0.9)
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
    servers = ["stdio", None, ["transport", "stdio"], 5, 2.5, True,
               {"transport": "stdio"}, {"auto_approve": ["*"]}, {"url": "http://internal.example/mcp"}]
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


@pytest.mark.parametrize("definitions, weight", [
    ([{"file": "a.md"}], 3), ([{"file": "a.md"}, {"file": "b.md"}], 6), (({"file": "a.md"},) * 5, 10), ([], 0),
])
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


@pytest.mark.parametrize("metadata, weight", [
    ({"user_count": 250}, 10), ({"consenting_users": "42"}, 5), ({"users": 12.9}, 5), ({"install_count": 9}, 0),
    ({"user_count": "garbage", "consenting_users": 500}, 0),  # first present key wins, as before
])
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
    expired = _finding(kind=Kind.TOKEN, tags=["expired"], owner="alice", shadow=False, registry_match="svc",
                       confidence=0.05)
    risk = assess(expired, inventory_present=True)
    assert sum(factor.weight for factor in risk.factors if factor.id not in {"confidence-scaling", "bounds"}) == -10
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
    if finding.kind == Kind.SECRET and finding.metadata.get("count", 1) and int(finding.metadata.get("count", 1)) > 1:
        factors.append(RiskFactor("multiple-secrets", f"{finding.metadata['count']} credentials in one place", 5))
    if finding.kind == Kind.MCP_SERVER:
        servers = finding.metadata.get("servers") or []
        if any(s.get("transport") == "stdio" for s in servers):
            factors.append(RiskFactor("mcp-stdio", "local stdio MCP servers run with the user's full privileges", 5))
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
        users = (finding.metadata.get("user_count") or finding.metadata.get("consenting_users")
                 or finding.metadata.get("users") or finding.metadata.get("install_count") or 0)
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
        factors.append(RiskFactor("confidence-scaling", "scaled by confidence", int(round(total * scale)) - total))
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
        ("identity.auth0", {"input": str(fixtures / "identity" / "auth0_clients.json"), "domain": "acme.eu.auth0.com"}),
        ("identity.entra", {"input": str(fixtures / "identity" / "entra_graph.json"), "tenant_id": "t"}),
        ("identity.google-workspace", {"input": str(fixtures / "identity" / "google_tokens.json")}),
        ("identity.jwt", {"input": str(fixtures / "identity" / "tokens.txt")}),
        ("identity.okta", {"input": str(fixtures / "identity" / "okta_apps.json"), "org_url": "https://acme.okta.com"}),
        ("lowcode.make", {"input": str(fixtures / "lowcode" / "make_scenarios.json")}),
        ("lowcode.n8n", {"input": str(fixtures / "lowcode" / "n8n_workflows.json")}),
        ("lowcode.power-platform", {"input": str(fixtures / "lowcode" / "power_platform.json")}),
        ("lowcode.salesforce", {"input": str(fixtures / "lowcode" / "salesforce.json"),
                                "instance_url": "https://acme.my.salesforce.com"}),
        ("lowcode.servicenow", {"input": str(fixtures / "lowcode" / "servicenow.json"), "instance": "acme.service-now.com"}),
        ("lowcode.workato", {"input": str(fixtures / "lowcode" / "workato_recipes.json")}),
        ("lowcode.zapier", {"input": str(fixtures / "lowcode" / "zapier_zaps.csv")}),
        ("saas.atlassian", {"input": str(fixtures / "saas" / "atlassian_plugins.json"), "site": "https://acme.atlassian.net"}),
        ("saas.generic", {"input": str(fixtures / "saas" / "generic_apps.csv"), "platform": "google-marketplace",
                          "fields": {"name": "App Name", "scopes": "Permissions", "users": "Users",
                                     "owner": "Installed By", "url": "Domain"}}),
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
        Kind.SECRET, Kind.MCP_SERVER, Kind.AGENT_CONFIG, Kind.GATEWAY_CALLER, Kind.OAUTH_GRANT, Kind.BOT_APP,
    }
    for finding in fixture_findings:
        for inventory_present, shadow, match in ((False, None, None), (True, True, None), (True, False, "registered")):
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


@pytest.mark.parametrize("name, value", [
    ("metadata", "garbage"), ("metadata", None), ("metadata", ["count", 3]),
    ("tags", "policy.privileged-scopes"), ("tags", ["ok", 1]), ("tags", None),
    ("capabilities", {"code-exec": True}), ("frameworks", "framework.langchain"), ("model_providers", [None]),
    ("models", 3), ("permissions", [["admin"]]),
    ("shadow", "false"), ("shadow", 0),
    ("owner", 5), ("first_seen", 1700000000), ("last_seen", ["2026"]), ("id", 12345),
    ("provider", ["aws"]), ("registry_match", {"id": "x"}), ("identity_discriminator", 1),
])
def test_from_dict_rejects_field_shapes_the_pipeline_cannot_process(name, value):
    with pytest.raises(ValueError, match=name):
        Finding.from_dict(_record(**{name: value}))


def test_from_dict_rejects_risk_factors_and_evidence_without_text_fields():
    for factor in ({"weight": 1}, {"id": "kind", "weight": 1}, {"id": None, "description": "x", "weight": 1},
                   {"id": "kind", "description": 5, "weight": 1}):
        record = _record()
        record["risk"]["factors"] = [factor]
        with pytest.raises(ValueError, match="risk factor"):
            Finding.from_dict(record)
    for item in ({"description": "x"}, {"signal": 1, "description": "x"}, {"signal": "s", "description": None}):
        with pytest.raises(ValueError, match="evidence"):
            Finding.from_dict(_record(evidence=[item]))


def test_from_dict_keeps_optional_text_fields_null_and_accepts_garbage_inside_metadata():
    metadata = {"count": "many", "servers": "stdio", "agent_definitions": 3, "events": [1], "user_count": None}
    finding = Finding.from_dict(_record(owner=None, first_seen=None, shadow=None, metadata=metadata))
    assert finding.owner is None and finding.shadow is None and finding.metadata == metadata
    for kind in (Kind.SECRET, Kind.MCP_SERVER, Kind.AGENT_CONFIG, Kind.GATEWAY_CALLER, Kind.OAUTH_GRANT):
        finding.kind = kind
        assert assess(finding, inventory_present=True).score >= 0


def test_engine_completes_when_report_derived_findings_carry_garbage_metadata(monkeypatch, index):
    records = [
        _record(kind="secret", resource="repo/.env", resource_type="secret", metadata={"count": "many"}),
        _record(kind="mcp-server", resource="repo/.mcp.json", resource_type="mcp-config",
                metadata={"servers": ["stdio", None, ["x"], 5, {"transport": "stdio", "url": "http://localhost:3000"}]}),
        _record(kind="agent-config", resource="repo/.claude", resource_type="agent-config",
                metadata={"agent_definitions": "not a list"}),
        _record(surface="gateway", connector="gateway.logs", kind="gateway-caller", resource="gateway:user:bob",
                resource_type="gateway-caller", metadata={"events": "lots", "runtime_observations": "none"}),
        _record(surface="identity", connector="identity.okta", kind="oauth-grant", resource="okta:app:1",
                resource_type="oauth-app", metadata={"user_count": [1, 2], "users": {"n": 1}}),
    ]

    class ReportConnector:
        def __init__(self, ctx):
            self.ctx = ctx

        def run(self):
            self.ctx.stats = ScanStats(connector="report", started_at=now_iso(), finished_at=now_iso())
            return [Finding.from_dict(record) for record in records]

    monkeypatch.setattr("shadowscan.engine.get_connector_class", lambda name: ReportConnector)
    cfg = ScanConfig(connectors=[ConnectorSpec("code.filesystem")],
                     inventory=[str(Path(__file__).parents[2] / "agent-card.yaml")])
    result = Engine(cfg, index).run()
    assert result.complete, [stats.errors for stats in result.stats]
    assert len(result.findings) == len(records)
    assert all(finding.risk.factors and finding.risk.score >= 0 and finding.shadow is True for finding in result.findings)
    mcp = next(finding for finding in result.findings if finding.kind == Kind.MCP_SERVER)
    assert {"mcp-stdio", "mcp-plain-http"} <= _ids(mcp.risk) and "mcp-auto-approve" not in _ids(mcp.risk)
    secret = next(finding for finding in result.findings if finding.kind == Kind.SECRET)
    assert "multiple-secrets" not in _ids(secret.risk)
    assert result.findings == sorted(result.findings, key=lambda f: (-f.risk.score, -f.confidence, f.surface.value, f.title))
