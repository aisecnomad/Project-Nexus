from __future__ import annotations

import json
from pathlib import Path
from threading import Event

import pytest

from shadowscan.config import ConnectorSpec, ScanConfig, parse_set_options
from shadowscan.engine import Engine, _unique_records, correlate, merge
from shadowscan.models import Evidence, Finding, Kind, RiskLevel, ScanStats, Surface, now_iso
from shadowscan.registry import Inventory, card_stub_for
from shadowscan.risk import assess
from shadowscan.signatures import SignatureIndex


def _f(**kw) -> Finding:
    base = dict(surface=Surface.CLOUD, connector="cloud.aws", kind=Kind.AGENT, title="Bedrock Agent: ops-provisioning-04", resource="arn:aws:bedrock:us-east-1:1:agent/A1", resource_type="bedrock-agent", confidence=0.9)
    base.update(kw)
    return Finding(**base)


def test_inventory_loads_capability_card_and_matches(tmp_path: Path):
    card = Path(__file__).parents[1] / "fixtures" / "inventory" / "ops-provisioning-04.yaml"
    inv = Inventory.load([str(card)])
    assert len(inv) == 1 and inv.entries[0].agent_id == "ops-provisioning-04" and inv.entries[0].owner == "Platform-Engineering"
    f = _f(resource="arn:aws:bedrock:us-east-1:123456789012:agent/AGENT1", metadata={"agent_name": "ops-provisioning-04"})
    assert inv.match(f).agent_id == "ops-provisioning-04"
    assert inv.match(_f(title="Bedrock Agent: other", resource="arn:aws:bedrock:us-east-1:1:agent/B2", metadata={})) is None
    # resource glob patterns and aliases in simple format
    (tmp_path / "agents.yaml").write_text("agents:\n  - id: reviewer\n    name: Code Reviewer\n    owner: dev-prod\n    resources: ['github:installation:*']\n    names: [coderabbitai]\n")
    inv = Inventory.load([str(tmp_path)])
    assert inv.match(_f(resource="github:installation:101", title="GitHub App installed: coderabbitai")).agent_id == "reviewer"
    assert inv.match(_f(resource="slack:app:1", title="Slack app: CodeRabbitAI")) is None
    assert inv.suggest(_f(resource="slack:app:1", title="Slack app: CodeRabbitAI"))[0].agent_id == "reviewer"
    # CSV
    (tmp_path / "agents.yaml").unlink()
    (tmp_path / "inv.csv").write_text("agent_id,name,owner,resources\nhr-helper,HR Helper,erin,power-platform:bot:bot-1|okta:app:x\n")
    inv = Inventory.load([str(tmp_path / "inv.csv")])
    assert inv.match(_f(resource="power-platform:bot:bot-1")).owner == "erin"


def test_risk_scoring_is_explainable(index):
    f = _f(capabilities=["code-exec", "autonomous"], tags=["policy.privileged-scopes", "plaintext-credential"], shadow=True)
    risk = assess(f, index, inventory_present=True)
    ids = {x.id for x in risk.factors}
    assert {"shadow", "no-owner", "capability:code-exec", "tag:policy.privileged-scopes", "tag:plaintext-credential"} <= ids
    assert risk.level == RiskLevel.CRITICAL
    quiet = _f(kind=Kind.FRAMEWORK_USAGE, confidence=0.3, owner="team", shadow=False, registry_match="x")
    r2 = assess(quiet, index, inventory_present=True)
    assert r2.level in {RiskLevel.LOW, RiskLevel.INFO} and any(x.id == "registered" for x in r2.factors)


def test_merge_and_correlate():
    a = _f(evidence=[Evidence("x", "one", weight=0.5)], frameworks=["framework.langchain"])
    b = _f(evidence=[Evidence("y", "two", weight=0.5)], frameworks=["protocol.mcp"], owner="bob")
    merged = merge([a, b])
    assert len(merged) == 1 and set(merged[0].frameworks) == {"framework.langchain", "protocol.mcp"} and merged[0].owner == "bob" and len(merged[0].evidence) == 2
    cloud = _f(metadata={"agent_name": "ops-provisioning-04"})
    iac = _f(surface=Surface.CODE, connector="code.filesystem", kind=Kind.INFRA, resource="github:acme/infra/bedrock.tf", resource_type="iac", metadata={"names": ["ops-provisioning-04"], "name": "ops-provisioning-04"})
    correlate([cloud, iac])
    assert cloud.metadata["related"] == [iac.id] and iac.metadata["related"] == [cloud.id]


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
            self.ctx.stats = ScanStats(connector="code.filesystem", started_at=now_iso(), finished_at=now_iso())
            return [_f(surface=Surface.CODE, connector="code.filesystem", kind=Kind.FRAMEWORK_USAGE,
                       title="Same resource", resource="repo", resource_type="project",
                       owner=label, metadata={"first_source": label})]

    # Make the second connector complete before the first.
    monkeypatch.setattr("shadowscan.engine.get_connector_class", lambda name: Connector)
    cfg = ScanConfig(connectors=[
        ConnectorSpec("code.filesystem", label="first"),
        ConnectorSpec("code.filesystem", label="second"),
    ], parallel=2)
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
    common = dict(surface=Surface.GATEWAY, connector="gateway.logs", kind=Kind.GATEWAY_CALLER,
                  resource="caller:one", resource_type="caller/service")
    gateway = _f(**common, metadata={"runtime_source": {"input": "one.jsonl"},
                                    "runtime_observations": [first_observation], "events": 1})
    duplicate = _f(**common, metadata={"runtime_source": {"input": "one.jsonl"},
                                      "runtime_observations": [reordered_observation], "events": 1})
    combined = merge([gateway, duplicate])[0]
    assert len(combined.metadata["runtime_observations"]) == 1
    assert len(combined.metadata["runtime_sources"]) == 1
    assert combined.metadata["events"] == 1


def test_nested_observations_preserve_boolean_and_numeric_values():
    assert _unique_records([{"trusted": True}, {"trusted": 1}, {"trusted": False}, {"trusted": 0}]) == [
        {"trusted": True}, {"trusted": 1}, {"trusted": False}, {"trusted": 0},
    ]


def test_merge_preserves_runtime_observations_and_variable_names():
    observed = {
        "code_resources": ["github:acme/agent"], "frameworks": ["framework.langchain"],
        "identity_basis": "configured-exact-caller-and-scope", "timestamped_events": 1,
        "first_seen": "2026-09-22T10:00:00Z", "last_seen": "2026-09-22T10:00:00Z",
    }
    gateway = _f(surface=Surface.GATEWAY, connector="gateway.logs", kind=Kind.GATEWAY_CALLER,
                 resource="caller:abc", metadata={"runtime_source": {"input": "a.jsonl"}, "runtime_observations": [observed]})
    again = _f(surface=Surface.GATEWAY, connector="gateway.logs", kind=Kind.GATEWAY_CALLER,
               resource="caller:abc", metadata={"runtime_source": {"input": "b.jsonl"}, "runtime_observations": [observed]})
    same = _f(surface=Surface.GATEWAY, connector="gateway.logs", kind=Kind.GATEWAY_CALLER,
              resource="caller:abc", metadata={"runtime_source": {"input": "a.jsonl"}, "runtime_observations": [observed]})
    first = _f(kind=Kind.SECRET, metadata={"variable_names": ["OPENAI_API_KEY"]})
    second = _f(kind=Kind.SECRET, metadata={"variable_names": ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"]})
    result = merge([gateway, again, same, first, second])
    merged_gateway = next(f for f in result if f.surface == Surface.GATEWAY)
    assert {entry["source"]["input"] for entry in merged_gateway.metadata["runtime_observations"]} == {"a.jsonl", "b.jsonl"}
    assert len(merged_gateway.metadata["runtime_observations"]) == 2
    assert next(f for f in result if f.kind == Kind.SECRET).metadata["variable_names"] == ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"]


def test_gateway_caller_keeps_export_metrics_separate_and_correlates_both(tmp_path: Path, index):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("langchain\n")
    binding = {"code_resource": "github:acme/ops-agent", "caller": "principal:svc-ops", "scope": {"tenant": "tenant-a"}}
    gateway_specs = []
    for name, timestamp, tokens, cost, environment in (
        ("a.jsonl", "2026-09-22T10:00:00Z", 100, 0.1, "production"),
        ("b.jsonl", "2026-09-23T11:00:00Z", 200, 0.2, "staging"),
    ):
        export = tmp_path / name
        export.write_text(json.dumps({
            "service": "svc-ops", "tenant_id": "tenant-a", "model": "gpt-4o",
            "user_agent": "langchain/0.3", "timestamp": timestamp,
            "prompt_tokens": tokens, "completion_tokens": 10, "cost": cost,
            "environment": environment,
        }) + "\n")
        gateway_specs.append(ConnectorSpec("gateway.logs", {
            "input": str(export), "correlation_bindings": [binding],
        }, label="shared-gateway"))
    result = Engine(ScanConfig(connectors=[
        ConnectorSpec("code.filesystem", {"path": str(repo)}, label="github:acme/ops-agent"),
        *gateway_specs,
    ], parallel=1), index).run()
    assert result.complete
    gateways = [f for f in result.findings if f.surface == Surface.GATEWAY]
    assert len(gateways) == 2
    assert len({gateway.id for gateway in gateways}) == 2
    assert {Path(gateway.metadata["runtime_source"]["input"]).name for gateway in gateways} == {"a.jsonl", "b.jsonl"}
    assert all(gateway.metadata["events"] == gateway.metadata["records"] == 1 for gateway in gateways)
    assert all(gateway.metadata["aggregate_records"] == 0 and gateway.metadata["models"] == {"gpt-4o": 1} for gateway in gateways)
    assert {gateway.metadata["tokens_in"] for gateway in gateways} == {100, 200}
    assert all(gateway.metadata["tokens_out"] == 10 for gateway in gateways)
    assert {gateway.metadata["cost"] for gateway in gateways} == {0.1, 0.2}
    activity = next(f for f in result.findings if f.surface == Surface.CODE).metadata["runtime_activity"]
    assert activity["status"] == "observed" and activity["events"] == 2
    assert {Path(source["source"]["input"]).name for source in activity["sources"]} == {"a.jsonl", "b.jsonl"}
    assert {source["gateway_finding_id"] for source in activity["sources"]} == {gateway.id for gateway in gateways}


def test_engine_end_to_end_with_config(tmp_path: Path, fixtures, index):
    cfg = ScanConfig(
        connectors=[
            ConnectorSpec(name="code.filesystem", config={"path": str(fixtures / "sample_repo"), "label": "repo"}),
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
    assert result.findings == sorted(result.findings, key=lambda f: (-f.risk.score, -f.confidence, f.surface.value, f.title))
    skipped = [s for s in result.stats if s.skipped]
    assert skipped and "unknown connector" in (skipped[0].skip_reason or "")
    stub = card_stub_for(result.findings[0])
    assert stub["metadata"]["agent_id"] and stub["discovery"]["resources"] == [result.findings[0].resource]


def test_config_yaml_paths_and_env(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("GH_ORG_TEST", "acme")
    cfg_file = tmp_path / "shadowscan.yaml"
    (tmp_path / "exports").mkdir()
    (tmp_path / "exports" / "x.jsonl").write_text("{}\n")
    cfg_file.write_text("inventory: [./inventory]\nconnectors:\n  - name: gateway.logs\n    input: ./exports/x.jsonl\n  - name: code.github\n    org: ${GH_ORG_TEST}\n    token: ${MISSING_TOKEN:-none}\n    enabled: false\noptions:\n  fail_on: high\n  parallel: 1\n")
    cfg = ScanConfig.from_yaml(cfg_file)
    assert cfg.connectors[0].config["input"] == str(tmp_path / "exports" / "x.jsonl")
    assert cfg.connectors[1].config == {"org": "acme", "token": "none"} and not cfg.connectors[1].enabled
    assert cfg.inventory == [str(tmp_path / "inventory")] and cfg.fail_on == "high"
    assert parse_set_options(["regions=us-east-1,eu-west-1", "cloudtrail_days=3", "verbose=true", "org=acme"]) == {"regions": ["us-east-1", "eu-west-1"], "cloudtrail_days": 3, "verbose": True, "org": "acme"}


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
    assert ScanConfig.from_dict({"connectors": [{"name": "cloud.aws", "enabled": "${RUN_CLOUD}"}]}).connectors[0].enabled
    with pytest.raises(ValueError, match="connector enabled"):
        ScanConfig.from_dict({"connectors": [{"name": "cloud.aws", "enabled": "perhaps"}]})
