from __future__ import annotations

import json
from pathlib import Path
from threading import Event

import pytest

from shadowscan.config import ConnectorSpec, ScanConfig, parse_set_options
from shadowscan.connectors.common import unique_records
from shadowscan.correlation import correlate
from shadowscan.engine import Engine, _prune_runtime_links
from shadowscan.merge import merge
from shadowscan.models import Evidence, Finding, Kind, RiskLevel, ScanStats, Surface, now_iso
from shadowscan.registry import Inventory, card_stub_for
from shadowscan.risk import assess
from shadowscan.signatures import SignatureIndex


def _f(**kw) -> Finding:
    base = dict(
        surface=Surface.CLOUD,
        connector="cloud.aws",
        kind=Kind.AGENT,
        title="Bedrock Agent: ops-provisioning-04",
        resource="arn:aws:bedrock:us-east-1:1:agent/A1",
        resource_type="bedrock-agent",
        confidence=0.9,
    )
    base.update(kw)
    return Finding(**base)


def test_inventory_loads_capability_card_and_matches(tmp_path: Path):
    card = Path(__file__).parents[1] / "fixtures" / "inventory" / "ops-provisioning-04.yaml"
    inv = Inventory.load([str(card)])
    assert (
        len(inv) == 1
        and inv.entries[0].agent_id == "ops-provisioning-04"
        and inv.entries[0].owner == "Platform-Engineering"
    )
    f = _f(
        resource="arn:aws:bedrock:us-east-1:123456789012:agent/AGENT1",
        metadata={"agent_name": "ops-provisioning-04"},
    )
    assert inv.match(f).agent_id == "ops-provisioning-04"
    assert (
        inv.match(
            _f(title="Bedrock Agent: other", resource="arn:aws:bedrock:us-east-1:1:agent/B2", metadata={})
        )
        is None
    )
    # resource glob patterns and aliases in simple format
    (tmp_path / "agents.yaml").write_text(
        "agents:\n  - id: reviewer\n    name: Code Reviewer\n    owner: dev-prod\n    resources: ['github:installation:*']\n    names: [coderabbitai]\n"
    )
    inv = Inventory.load([str(tmp_path)])
    assert (
        inv.match(_f(resource="github:installation:101", title="GitHub App installed: coderabbitai")).agent_id
        == "reviewer"
    )
    assert inv.match(_f(resource="slack:app:1", title="Slack app: CodeRabbitAI")) is None
    assert inv.suggest(_f(resource="slack:app:1", title="Slack app: CodeRabbitAI"))[0].agent_id == "reviewer"
    # CSV
    (tmp_path / "agents.yaml").unlink()
    (tmp_path / "inv.csv").write_text(
        "agent_id,name,owner,resources\nhr-helper,HR Helper,erin,power-platform:bot:bot-1|okta:app:x\n"
    )
    inv = Inventory.load([str(tmp_path / "inv.csv")])
    assert inv.match(_f(resource="power-platform:bot:bot-1")).owner == "erin"


def test_risk_scoring_is_explainable(index):
    f = _f(
        capabilities=["code-exec", "autonomous"],
        tags=["policy.privileged-scopes", "plaintext-credential"],
        shadow=True,
    )
    risk = assess(f, index, inventory_present=True)
    ids = {x.id for x in risk.factors}
    assert {
        "shadow",
        "no-owner",
        "capability:code-exec",
        "tag:policy.privileged-scopes",
        "tag:plaintext-credential",
    } <= ids
    assert risk.level == RiskLevel.CRITICAL
    quiet = _f(kind=Kind.FRAMEWORK_USAGE, confidence=0.3, owner="team", shadow=False, registry_match="x")
    r2 = assess(quiet, index, inventory_present=True)
    assert r2.level in {RiskLevel.LOW, RiskLevel.INFO} and any(x.id == "registered" for x in r2.factors)


def test_merge_and_correlate():
    a = _f(evidence=[Evidence("x", "one", weight=0.5)], frameworks=["framework.langchain"])
    b = _f(evidence=[Evidence("y", "two", weight=0.5)], frameworks=["protocol.mcp"], owner="bob")
    merged = merge([a, b])
    assert (
        len(merged) == 1
        and set(merged[0].frameworks) == {"framework.langchain", "protocol.mcp"}
        and merged[0].owner == "bob"
        and len(merged[0].evidence) == 2
    )
    cloud = _f(metadata={"agent_name": "ops-provisioning-04"})
    iac = _f(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.INFRA,
        resource="github:acme/infra/bedrock.tf",
        resource_type="iac",
        metadata={"names": ["ops-provisioning-04"], "name": "ops-provisioning-04"},
    )
    correlate([cloud, iac])
    assert cloud.metadata["related"] == [iac.id] and iac.metadata["related"] == [cloud.id]


def test_confidence_threshold_prunes_links_to_omitted_findings(monkeypatch):
    agent = "ops-provisioning-04"
    findings = {
        "cloud": _f(metadata={"agent_name": agent}, confidence=0.95),
        "identity": _f(
            surface=Surface.IDENTITY,
            connector="identity.entra",
            kind=Kind.SERVICE_IDENTITY,
            title=f"Entra service principal: {agent}",
            resource="entra:sp:ops",
            resource_type="service-principal",
            metadata={"display_name": agent},
            confidence=0.9,
        ),
        "iac": _f(
            surface=Surface.CODE,
            connector="code.filesystem",
            kind=Kind.INFRA,
            title="Terraform: bedrock.tf",
            resource="github:acme/infra/bedrock.tf",
            resource_type="iac",
            metadata={"name": agent},
            confidence=0.3,
        ),
        "bot": _f(
            surface=Surface.SAAS,
            connector="saas.slack",
            kind=Kind.BOT_APP,
            title="Slack app: invoice-assistant",
            resource="slack:app:A1",
            resource_type="slack-app",
            metadata={"name": "invoice-assistant"},
            confidence=0.8,
        ),
        "flow": _f(
            surface=Surface.LOWCODE,
            connector="lowcode.zapier",
            kind=Kind.WORKFLOW,
            title="Zapier workflow: invoice-assistant",
            resource="zapier:zap:1",
            resource_type="zap",
            metadata={"name": "invoice-assistant"},
            confidence=0.2,
        ),
    }

    class Connector:
        def __init__(self, ctx):
            self.ctx = ctx

        def run(self):
            self.ctx.stats = ScanStats(connector="test", started_at=now_iso(), finished_at=now_iso())
            return [findings[self.ctx.config["label"]]]

    monkeypatch.setattr("shadowscan.engine.get_connector_class", lambda name: Connector)
    specs = [ConnectorSpec(f"platform.{label}", label=label) for label in findings]
    result = Engine(ScanConfig(connectors=specs, min_confidence=0.5), SignatureIndex([])).run()
    assert result.complete
    by_id = {f.id: f for f in result.findings}
    assert set(by_id) == {findings[label].id for label in ("cloud", "identity", "bot")}
    # Links among retained findings survive on both sides; none names an omitted finding.
    assert by_id[findings["cloud"].id].metadata["related"] == [findings["identity"].id]
    assert by_id[findings["identity"].id].metadata["related"] == [findings["cloud"].id]
    assert "related" not in by_id[findings["bot"].id].metadata


def test_confidence_threshold_prunes_runtime_links_to_omitted_gateway_findings():
    def caller(name: str, confidence: float) -> Finding:
        return _f(
            surface=Surface.GATEWAY,
            connector="gateway.logs",
            kind=Kind.GATEWAY_CALLER,
            title=f"Agentic caller '{name}'",
            resource=f"principal:{name}",
            resource_type="gateway-caller",
            confidence=confidence,
        )

    kept, omitted = caller("svc-ops", 0.9), caller("svc-batch", 0.2)
    code = _f(
        surface=Surface.CODE,
        connector="code.filesystem",
        title="Agent in ops: LangChain",
        resource="github:acme/ops-agent",
        resource_type="project",
    )
    code.metadata["runtime_activity"] = {
        "status": "observed",
        "events": 3,
        "sources": [
            {"gateway_finding_id": kept.id, "events": 1},
            {"gateway_finding_id": omitted.id, "events": 2},
        ],
    }
    code.add_evidence(
        Evidence(
            signal="runtime:gateway-observed",
            description="Linked gateway recorded 3 timestamped request(s)",
            weight=0.0,
            attributes={"gateway_finding_ids": sorted([kept.id, omitted.id])},
        )
    )
    # The threshold removed the second caller; its observation remains evidence.
    _prune_runtime_links([code, kept])
    sources = code.metadata["runtime_activity"]["sources"]
    assert [source["gateway_finding_id"] for source in sources] == [kept.id, None]
    assert [source["events"] for source in sources] == [1, 2]
    observed = next(ev for ev in code.evidence if ev.signal == "runtime:gateway-observed")
    assert observed.attributes["gateway_finding_ids"] == [kept.id]


def test_parallel_connector_completion_cannot_change_merge_attribution(monkeypatch):
    second_finished = Event()

    class Connector:
        def __init__(self, ctx):
            self.ctx = ctx

        def run(self):
            label = self.ctx.config["label"]
            if label == "first":
                assert second_finished.wait(2)
            else:
                second_finished.set()
            self.ctx.stats = ScanStats(
                connector="code.filesystem", started_at=now_iso(), finished_at=now_iso()
            )
            return [
                _f(
                    surface=Surface.CODE,
                    connector="code.filesystem",
                    kind=Kind.FRAMEWORK_USAGE,
                    title="Same resource",
                    resource="repo",
                    resource_type="project",
                    owner=label,
                    metadata={"first_source": label},
                )
            ]

    # Make the second connector complete before the first.
    monkeypatch.setattr("shadowscan.engine.get_connector_class", lambda name: Connector)
    cfg = ScanConfig(
        connectors=[
            ConnectorSpec("code.filesystem", label="first"),
            ConnectorSpec("code.filesystem", label="second"),
        ],
        parallel=2,
    )
    result = Engine(cfg, SignatureIndex([])).run()
    assert result.complete and len(result.findings) == 1
    assert result.findings[0].owner == "first"
    assert result.findings[0].metadata["first_source"] == "first"


def test_merge_deduplicates_all_evidence_and_nested_gateway_observations():
    def evidence():
        return Evidence("signal", "same observation", location="source")

    first = _f(evidence=[evidence()])
    repeated = _f(evidence=[evidence(), evidence()])
    assert len(merge([first, repeated])[0].evidence) == 1

    first_observation = {"code_resources": ["repo"], "scope": {"tenant": "one", "project": "two"}}
    reordered_observation = {"scope": {"project": "two", "tenant": "one"}, "code_resources": ["repo"]}
    common = dict(
        surface=Surface.GATEWAY,
        connector="gateway.logs",
        kind=Kind.GATEWAY_CALLER,
        resource="caller:one",
        resource_type="caller/service",
    )
    gateway = _f(
        **common,
        metadata={
            "runtime_source": {"input": "one.jsonl"},
            "runtime_observations": [first_observation],
            "events": 1,
        },
    )
    duplicate = _f(
        **common,
        metadata={
            "runtime_source": {"input": "one.jsonl"},
            "runtime_observations": [reordered_observation],
            "events": 1,
        },
    )
    combined = merge([gateway, duplicate])[0]
    assert len(combined.metadata["runtime_observations"]) == 1
    assert len(combined.metadata["runtime_sources"]) == 1
    assert combined.metadata["events"] == 1


def test_nested_observations_preserve_boolean_and_numeric_values():
    assert unique_records([{"trusted": True}, {"trusted": 1}, {"trusted": False}, {"trusted": 0}]) == [
        {"trusted": True},
        {"trusted": 1},
        {"trusted": False},
        {"trusted": 0},
    ]


def test_merge_preserves_runtime_observations_and_variable_names():
    observed = {
        "code_resources": ["github:acme/agent"],
        "frameworks": ["framework.langchain"],
        "identity_basis": "configured-exact-caller-and-scope",
        "timestamped_events": 1,
        "first_seen": "2026-09-22T10:00:00Z",
        "last_seen": "2026-09-22T10:00:00Z",
    }
    gateway = _f(
        surface=Surface.GATEWAY,
        connector="gateway.logs",
        kind=Kind.GATEWAY_CALLER,
        resource="caller:abc",
        metadata={"runtime_source": {"input": "a.jsonl"}, "runtime_observations": [observed]},
    )
    again = _f(
        surface=Surface.GATEWAY,
        connector="gateway.logs",
        kind=Kind.GATEWAY_CALLER,
        resource="caller:abc",
        metadata={"runtime_source": {"input": "b.jsonl"}, "runtime_observations": [observed]},
    )
    same = _f(
        surface=Surface.GATEWAY,
        connector="gateway.logs",
        kind=Kind.GATEWAY_CALLER,
        resource="caller:abc",
        metadata={"runtime_source": {"input": "a.jsonl"}, "runtime_observations": [observed]},
    )
    first = _f(kind=Kind.SECRET, metadata={"variable_names": ["OPENAI_API_KEY"]})
    second = _f(kind=Kind.SECRET, metadata={"variable_names": ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"]})
    result = merge([gateway, again, same, first, second])
    merged_gateway = next(f for f in result if f.surface == Surface.GATEWAY)
    assert {entry["source"]["input"] for entry in merged_gateway.metadata["runtime_observations"]} == {
        "a.jsonl",
        "b.jsonl",
    }
    assert len(merged_gateway.metadata["runtime_observations"]) == 2
    assert next(f for f in result if f.kind == Kind.SECRET).metadata["variable_names"] == [
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
    ]


def test_gateway_caller_keeps_export_metrics_separate_and_correlates_both(tmp_path: Path, index):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("langchain\n")
    binding = {
        "code_resource": "github:acme/ops-agent",
        "caller": "principal:svc-ops",
        "scope": {"tenant": "tenant-a"},
    }
    gateway_specs = []
    for name, timestamp, tokens, cost, environment in (
        ("a.jsonl", "2026-09-22T10:00:00Z", 100, 0.1, "production"),
        ("b.jsonl", "2026-09-23T11:00:00Z", 200, 0.2, "staging"),
    ):
        export = tmp_path / name
        export.write_text(
            json.dumps(
                {
                    "service": "svc-ops",
                    "tenant_id": "tenant-a",
                    "model": "gpt-4o",
                    "user_agent": "langchain/0.3",
                    "timestamp": timestamp,
                    "prompt_tokens": tokens,
                    "completion_tokens": 10,
                    "cost": cost,
                    "environment": environment,
                }
            )
            + "\n"
        )
        gateway_specs.append(
            ConnectorSpec(
                "gateway.logs",
                {
                    "input": str(export),
                    "correlation_bindings": [binding],
                },
                label="shared-gateway",
            )
        )
    result = Engine(
        ScanConfig(
            connectors=[
                ConnectorSpec("code.filesystem", {"path": str(repo)}, label="github:acme/ops-agent"),
                *gateway_specs,
            ],
            parallel=1,
        ),
        index,
    ).run()
    assert result.complete
    gateways = [f for f in result.findings if f.surface == Surface.GATEWAY]
    assert len(gateways) == 2
    assert len({gateway.id for gateway in gateways}) == 2
    assert {Path(gateway.metadata["runtime_source"]["input"]).name for gateway in gateways} == {
        "a.jsonl",
        "b.jsonl",
    }
    assert all(gateway.metadata["events"] == gateway.metadata["records"] == 1 for gateway in gateways)
    assert all(
        gateway.metadata["aggregate_records"] == 0 and gateway.metadata["models"] == {"gpt-4o": 1}
        for gateway in gateways
    )
    assert {gateway.metadata["tokens_in"] for gateway in gateways} == {100, 200}
    assert all(gateway.metadata["tokens_out"] == 10 for gateway in gateways)
    assert {gateway.metadata["cost"] for gateway in gateways} == {0.1, 0.2}
    activity = next(f for f in result.findings if f.surface == Surface.CODE).metadata["runtime_activity"]
    assert activity["status"] == "observed" and activity["events"] == 2
    assert {Path(source["source"]["input"]).name for source in activity["sources"]} == {"a.jsonl", "b.jsonl"}
    assert {source["gateway_finding_id"] for source in activity["sources"]} == {
        gateway.id for gateway in gateways
    }


def test_engine_end_to_end_with_config(tmp_path: Path, fixtures, index):
    cfg = ScanConfig(
        connectors=[
            ConnectorSpec(
                name="code.filesystem", config={"path": str(fixtures / "sample_repo"), "label": "repo"}
            ),
            ConnectorSpec(name="cloud.aws", config={"input": str(fixtures / "cloud" / "aws_records.jsonl")}),
            ConnectorSpec(name="nope.missing", config={}),
        ],
        inventory=[str(Path(__file__).parents[1] / "fixtures" / "inventory" / "ops-provisioning-04.yaml")],
        min_confidence=0.2,
        parallel=2,
    )
    result = Engine(cfg, index).run()
    assert result.inventory_size == 1
    registered = [f for f in result.findings if f.shadow is False]
    assert {f.registry_match for f in registered} == {"ops-provisioning-04"} and len(registered) >= 2
    assert all(f.owner for f in registered)  # owner inherited from the card
    assert all(f.risk.score >= 0 for f in result.findings)
    assert result.findings == sorted(
        result.findings, key=lambda f: (-f.risk.score, -f.confidence, f.surface.value, f.title)
    )
    skipped = [s for s in result.stats if s.skipped]
    assert skipped and "unknown connector" in (skipped[0].skip_reason or "")
    stub = card_stub_for(result.findings[0])
    assert stub["metadata"]["agent_id"] and stub["discovery"]["resources"] == [result.findings[0].resource]


def test_config_yaml_paths_and_env(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("GH_ORG_TEST", "acme")
    cfg_file = tmp_path / "shadowscan.yaml"
    (tmp_path / "exports").mkdir()
    (tmp_path / "exports" / "x.jsonl").write_text("{}\n")
    cfg_file.write_text(
        "inventory: [./inventory]\nconnectors:\n  - name: gateway.logs\n    input: ./exports/x.jsonl\n  - name: code.github\n    org: ${GH_ORG_TEST}\n    token: ${MISSING_TOKEN:-none}\n    enabled: false\noptions:\n  fail_on: high\n  parallel: 1\n"
    )
    cfg = ScanConfig.from_yaml(cfg_file)
    assert cfg.connectors[0].config["input"] == str(tmp_path / "exports" / "x.jsonl")
    assert cfg.connectors[1].config == {"org": "acme", "token": "none"} and not cfg.connectors[1].enabled
    assert cfg.inventory == [str(tmp_path / "inventory")] and cfg.fail_on == "high"
    assert parse_set_options(
        ["regions=us-east-1,eu-west-1", "cloudtrail_days=3", "verbose=true", "org=acme"]
    ) == {"regions": ["us-east-1", "eu-west-1"], "cloudtrail_days": 3, "verbose": True, "org": "acme"}


@pytest.mark.parametrize("threshold", ["nan", "inf", "-inf", "1.1", "-0.01", "not-a-number", None, True])
def test_invalid_confidence_threshold_never_clears_scan(threshold):
    with pytest.raises(ValueError, match="min_confidence must be a finite number between 0 and 1"):
        ScanConfig.from_dict({"options": {"min_confidence": threshold}})
    cfg = ScanConfig(min_confidence=threshold)
    with pytest.raises(ValueError, match="min_confidence must be a finite number between 0 and 1"):
        Engine(cfg, SignatureIndex([])).run()


def test_env_connector_enabled_flag_parsed_explicitly(monkeypatch):
    monkeypatch.setenv("RUN_CLOUD", "false")
    cfg = ScanConfig.from_dict({"connectors": [{"name": "cloud.aws", "enabled": "${RUN_CLOUD}"}]})
    assert not cfg.connectors[0].enabled
    monkeypatch.setenv("RUN_CLOUD", "true")
    assert (
        ScanConfig.from_dict({"connectors": [{"name": "cloud.aws", "enabled": "${RUN_CLOUD}"}]})
        .connectors[0]
        .enabled
    )
    with pytest.raises(ValueError, match="connector enabled"):
        ScanConfig.from_dict({"connectors": [{"name": "cloud.aws", "enabled": "perhaps"}]})


# An inventory that the scanned content controls can approve that content.
NARROW_CARD = "agents:\n  - id: reviewer\n    owner: x\n    resources: ['github:org/unrelated']\n"
WILDCARD_CARD = "agents: [{agent_id: approved-everything, owner: x, resources: ['*']}]\n"


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "agent.py").write_text("from crewai import Agent\nAgent(role='r')\n")
    return repo


def _inventory_warnings(result) -> list[str]:
    stats = [s for s in result.stats if s.connector == "engine.inventory"]
    assert all(not (s.incomplete or s.skipped or s.errors) for s in stats)
    return [warning for s in stats for warning in s.warnings]


@pytest.mark.parametrize("layout", ["directory", "file"])
def test_inventory_inside_scanned_path_is_a_warning_not_a_failure(tmp_path, index, layout):
    repo = _repo(tmp_path)
    (repo / "inventory").mkdir()
    (repo / "inventory" / "agents.yaml").write_text(NARROW_CARD)
    inventory = str(repo / "inventory") if layout == "directory" else str(repo / "inventory" / "agents.yaml")
    config = ScanConfig(
        connectors=[ConnectorSpec("code.filesystem", {"paths": [str(repo)]})], inventory=[inventory]
    )
    result = Engine(config, index).run()
    assert _inventory_warnings(result) == [
        f"inventory {inventory} is inside scanned path {repo}; scanned content could alter approvals"
    ]
    assert result.complete and result.findings


@pytest.mark.parametrize("connector", ["code.github", "code.gitlab"])
def test_inventory_inside_offline_provider_clones_is_reported(tmp_path, index, connector):
    # Offline clones are scanned content like a code.filesystem path; a pull
    # request in one of them could approve its own findings.
    clones = tmp_path / "clones"
    repo = clones / "acme__agent"
    repo.mkdir(parents=True)
    (repo / "agent.py").write_text("from crewai import Agent\nAgent(role='r')\n")
    (repo / "agents.yaml").write_text(NARROW_CARD)
    inventory = str(repo / "agents.yaml")
    config = ScanConfig(
        connectors=[ConnectorSpec(connector, {"input": str(clones), "use_git": False})], inventory=[inventory]
    )
    result = Engine(config, index).run()
    assert _inventory_warnings(result) == [
        f"inventory {inventory} is inside scanned path {clones}; scanned content could alter approvals"
    ]
    assert result.complete and result.findings


def test_inventory_outside_scanned_paths_is_not_reported(tmp_path, index):
    repo = _repo(tmp_path)
    (tmp_path / "agents.yaml").write_text(NARROW_CARD)
    config = ScanConfig(
        connectors=[ConnectorSpec("code.filesystem", {"path": str(repo)})],
        inventory=[str(tmp_path / "agents.yaml")],
    )
    result = Engine(config, index).run()
    assert _inventory_warnings(result) == []
    assert [s.connector for s in result.stats] == ["code.filesystem"]


def test_inventory_directory_that_loads_files_from_a_scanned_tree_names_them(tmp_path, index):
    repo = _repo(tmp_path)
    (repo / "approvals.yaml").write_text(NARROW_CARD)
    config = ScanConfig(
        connectors=[ConnectorSpec("code.filesystem", {"path": str(repo)})], inventory=[str(tmp_path)]
    )
    warnings = _inventory_warnings(Engine(config, index).run())
    assert warnings == [
        f"inventory {repo / 'approvals.yaml'} is inside scanned path {repo}; scanned content could alter approvals"
    ]


def test_wildcard_inventory_resource_is_reported_once_per_entry(tmp_path, index):
    repo = _repo(tmp_path)
    card = tmp_path / "agents.yaml"
    card.write_text(
        "agents:\n"
        "  - {agent_id: approved-everything, owner: x, resources: ['*']}\n"
        "  - {agent_id: every-code-finding, owner: x, resources: ['**'], surfaces: [code]}\n"
    )
    config = ScanConfig(
        connectors=[ConnectorSpec("code.filesystem", {"path": str(repo)})], inventory=[str(card)]
    )
    result = Engine(config, index).run()
    assert _inventory_warnings(result) == [
        f"inventory entry approved-everything in {card} has resource pattern '*', which approves every finding",
        f"inventory entry every-code-finding in {card} has resource pattern '*', which approves every finding"
        " its scope constraints allow",
    ]
    assert result.findings and result.complete


@pytest.mark.parametrize("pattern,approves_everything", [("?*", True), ("*?", True), ("github:*", False)])
def test_any_pattern_that_matches_every_resource_is_reported(tmp_path, index, pattern, approves_everything):
    repo = _repo(tmp_path)
    card = tmp_path / "agents.yaml"
    card.write_text(f"agents:\n  - {{agent_id: broad, owner: x, resources: ['{pattern}']}}\n")
    config = ScanConfig(
        connectors=[ConnectorSpec("code.filesystem", {"path": str(repo)})], inventory=[str(card)]
    )
    expected = (
        f"inventory entry broad in {card} has resource pattern '{pattern}', which approves every finding"
    )
    assert _inventory_warnings(Engine(config, index).run()) == ([expected] if approves_everything else [])


def test_cli_shows_in_tree_inventory_warning_without_changing_the_gate(tmp_path):
    from click.testing import CliRunner

    from shadowscan.cli import main

    repo = _repo(tmp_path)
    (repo / "inventory").mkdir()
    (repo / "inventory" / "agents.yaml").write_text(WILDCARD_CARD)
    args = ["code", str(repo), "--inventory", str(repo / "inventory"), "--fail-on", "high"]
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 0, result.output
    output = " ".join(result.output.split())
    assert "is inside scanned path" in output and "approves every finding" in output
    report = json.loads(CliRunner().invoke(main, [*args, "-f", "json"]).stdout)
    assert report["summary"]["complete"] is True
    [stats] = [s for s in report["stats"] if s["connector"] == "engine.inventory"]
    assert len(stats["warnings"]) == 2 and not stats["errors"]
