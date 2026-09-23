from __future__ import annotations

from pathlib import Path

from shadowscan.config import ConnectorSpec, ScanConfig, parse_set_options
from shadowscan.engine import Engine, correlate, merge
from shadowscan.models import Evidence, Finding, Kind, RiskLevel, Surface
from shadowscan.registry import Inventory, card_stub_for
from shadowscan.risk import assess


def _f(**kw) -> Finding:
    base = dict(surface=Surface.CLOUD, connector="cloud.aws", kind=Kind.AGENT, title="Bedrock Agent: ops-provisioning-04", resource="arn:aws:bedrock:us-east-1:1:agent/A1", resource_type="bedrock-agent", confidence=0.9)
    base.update(kw)
    return Finding(**base)


def test_inventory_loads_capability_card_and_matches(tmp_path: Path):
    card = Path(__file__).parents[2] / "agent-card.yaml"
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


def test_engine_end_to_end_with_config(tmp_path: Path, fixtures):
    cfg = ScanConfig(
        connectors=[
            ConnectorSpec(name="code.filesystem", config={"path": str(fixtures / "sample_repo"), "label": "repo"}),
            ConnectorSpec(name="cloud.aws", config={"input": str(fixtures / "cloud" / "aws_records.jsonl")}),
            ConnectorSpec(name="nope.missing", config={}),
        ],
        inventory=[str(Path(__file__).parents[2] / "agent-card.yaml")],
        min_confidence=0.2,
        parallel=2,
    )
    result = Engine(cfg).run()
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
