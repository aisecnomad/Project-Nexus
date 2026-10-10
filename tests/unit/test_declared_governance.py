"""Declared governance facts: the Capability Card ``governance`` block, its findings and mappings.

The block is operator-declared and never inferred. These tests pin its strict
validation, that only the card approving a finding in the current run can
declare its facts, the declared control rules and how reports label the facts.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine
from shadowscan.fleet import merge_reports
from shadowscan.governance import (
    DECLARED_GOVERNANCE_KEY,
    EU_AI_ACT_RISK_CLASSES,
    GovernanceError,
    apply_declared_governance,
    declared_facts,
    declared_risk_class,
    parse_governance,
    valid_declared_governance,
)
from shadowscan.mappings import control_references
from shadowscan.models import Kind, ScanResult, ScanStats
from shadowscan.registry import Inventory, InventoryEntry, InventoryValidationError, card_stub_for
from shadowscan.reporters import render

AGENT_ARN = "arn:aws:bedrock:us-east-1:111111111111:agent/AGENTX"
EU = "eu-ai-act-2024:"
SECRET_SHAPED = "opaque-secret-value-9f8e7d"
GOVERNANCE = {
    "eu_ai_act_risk_class": "high",
    "intended_purpose": "Issue refunds for disputed card payments.",
    "oversight_measures": ["Refunds above 500 EUR need a second approver", "Weekly sample review"],
    "aiuc1_certificate": "AIUC-1 certificate 2026-Q2-0042",
    "iso42001_scope": True,
}


def card(**extra: Any) -> dict[str, Any]:
    return {
        "schema_version": 2,
        "metadata": {"agent_id": "refunds-agent", "owner_team": "payments"},
        "discovery": {"resources": [AGENT_ARN]},
        **extra,
    }


def write(tmp_path: Path, payload: Any, name: str = "card.yaml") -> Path:
    path = tmp_path / name
    path.write_text(yaml.safe_dump(payload, sort_keys=False))
    return path


def bedrock_export(tmp_path: Path) -> Path:
    source = tmp_path / "aws.jsonl"
    record = {
        "_kind": "bedrock-agent",
        "_region": "us-east-1",
        "agentId": "AGENTX",
        "agentArn": AGENT_ARN,
        "agentName": "refunds",
        "agentStatus": "PREPARED",
        "_action_groups": [],
        "_knowledge_bases": [],
        "_aliases": [],
    }
    source.write_text(json.dumps(record) + "\n")
    return source


def scan(tmp_path: Path, index, inventory: list[Path] | None = None) -> tuple[ScanResult, Any]:
    config = ScanConfig(
        connectors=[ConnectorSpec(name="cloud.aws", config={"input": str(bedrock_export(tmp_path))})],
        inventory=[str(path) for path in inventory or []],
    )
    result = Engine(config, index=index).run()
    assert result.complete
    [agent] = result.findings
    return result, agent


# ------------------------------------------------------------- card parsing


def test_schema_version_2_card_declares_governance(tmp_path):
    [entry] = Inventory.load([write(tmp_path, card(governance=GOVERNANCE))]).entries
    assert entry.governance == GOVERNANCE


def test_governance_values_are_stripped_and_null_keys_are_undeclared(tmp_path):
    block = {"eu_ai_act_risk_class": None, "intended_purpose": "  Triage  ", "iso42001_scope": False}
    [entry] = Inventory.load([write(tmp_path, card(governance=block))]).entries
    assert entry.governance == {"intended_purpose": "Triage", "iso42001_scope": False}


@pytest.mark.parametrize("block", [None, {}, {"eu_ai_act_risk_class": None}])
def test_a_block_that_declares_nothing_is_absent(tmp_path, block):
    [entry] = Inventory.load([write(tmp_path, card(governance=block))]).entries
    assert entry.governance is None


@pytest.mark.parametrize("risk_class", EU_AI_ACT_RISK_CLASSES)
def test_every_risk_class_is_accepted(risk_class):
    assert parse_governance({"eu_ai_act_risk_class": risk_class}) == {"eu_ai_act_risk_class": risk_class}


@pytest.mark.parametrize(
    ("block", "location", "reason"),
    [
        ("high", "governance", "expected a mapping"),
        (["high"], "governance", "expected a mapping"),
        ({"risk_class": "high"}, "governance", "unsupported field"),
        ({SECRET_SHAPED: "x"}, "governance", "unsupported field"),
        ({"eu_ai_act_risk_class": "High"}, "governance.eu_ai_act_risk_class", "expected one of"),
        ({"eu_ai_act_risk_class": "medium"}, "governance.eu_ai_act_risk_class", "expected one of"),
        ({"eu_ai_act_risk_class": 3}, "governance.eu_ai_act_risk_class", "expected one of"),
        ({"intended_purpose": ""}, "governance.intended_purpose", "nonempty string"),
        ({"intended_purpose": "   "}, "governance.intended_purpose", "nonempty string"),
        ({"intended_purpose": 5}, "governance.intended_purpose", "nonempty string"),
        ({"intended_purpose": "x" * 501}, "governance.intended_purpose", "at most 500"),
        ({"oversight_measures": "review"}, "governance.oversight_measures", "list of nonempty strings"),
        ({"oversight_measures": ["ok", ""]}, "governance.oversight_measures", "nonempty string"),
        ({"oversight_measures": ["ok", 7]}, "governance.oversight_measures", "nonempty string"),
        ({"oversight_measures": ["x" * 201]}, "governance.oversight_measures", "at most 200"),
        ({"oversight_measures": ["m"] * 21}, "governance.oversight_measures", "at most 20 measures"),
        ({"aiuc1_certificate": "x" * 201}, "governance.aiuc1_certificate", "at most 200"),
        ({"aiuc1_certificate": ["c"]}, "governance.aiuc1_certificate", "nonempty string"),
        ({"iso42001_scope": "yes"}, "governance.iso42001_scope", "expected true or false"),
        ({"iso42001_scope": 1}, "governance.iso42001_scope", "expected true or false"),
    ],
)
def test_malformed_governance_fails_inventory_validation(tmp_path, block, location, reason):
    path = write(tmp_path, card(governance=block))
    with pytest.raises(InventoryValidationError) as info:
        Inventory.load([path])
    message = str(info.value)
    assert f"document 1.entry 1.{location}: " in message and reason in message
    # Values are never echoed: a misplaced value can be a credential.
    assert SECRET_SHAPED not in message and "x" * 30 not in message


def test_upper_limits_are_inclusive():
    block = {
        "intended_purpose": "p" * 500,
        "oversight_measures": ["m" * 200] * 20,
        "aiuc1_certificate": "c" * 200,
    }
    assert parse_governance(block) == block


@pytest.mark.parametrize("version", [None, 1])
def test_governance_requires_schema_version_2(tmp_path, version):
    payload = card(governance={"eu_ai_act_risk_class": "high"})
    if version is None:
        del payload["schema_version"]
    else:
        payload["schema_version"] = version
    with pytest.raises(InventoryValidationError, match=r"entry 1\.governance: requires schema_version 2"):
        Inventory.load([write(tmp_path, payload)])


def test_an_earlier_card_may_carry_a_null_governance_block(tmp_path):
    payload = card(governance=None)
    del payload["schema_version"]
    [entry] = Inventory.load([write(tmp_path, payload)]).entries
    assert entry.governance is None


def test_simple_entries_and_csv_rows_have_no_governance_fields(tmp_path):
    simple = {"agents": [{"id": "a", "resources": ["r"], "governance": {"eu_ai_act_risk_class": "high"}}]}
    with pytest.raises(InventoryValidationError, match="unsupported field"):
        Inventory.load([write(tmp_path, simple, "agents.yaml")])
    rows = tmp_path / "agents.csv"
    rows.write_text("agent_id,resources,eu_ai_act_risk_class\na,r,high\n")
    with pytest.raises(InventoryValidationError, match="unsupported field"):
        Inventory.load([rows])


@pytest.mark.parametrize("governance", ["high", {"eu_ai_act_risk_class": "critical"}])
def test_inventory_entry_validates_direct_construction(governance):
    with pytest.raises(InventoryValidationError, match="governance"):
        InventoryEntry(agent_id="a", governance=governance)


def test_inventory_entry_keeps_a_parsed_block():
    assert InventoryEntry(agent_id="a", governance=dict(GOVERNANCE)).governance == GOVERNANCE
    assert InventoryEntry(agent_id="a", governance={}).governance is None


def test_governance_error_names_the_field_and_never_the_value():
    with pytest.raises(GovernanceError) as info:
        parse_governance({"eu_ai_act_risk_class": SECRET_SHAPED})
    assert info.value.field == "governance.eu_ai_act_risk_class"
    assert SECRET_SHAPED not in str(info.value)


# ------------------------------------------------------------------- stubs


def test_stub_declares_an_unknown_risk_class_placeholder_and_round_trips(tmp_path, index):
    _, agent = scan(tmp_path, index)
    stub = card_stub_for(agent)
    assert stub["governance"] == {"eu_ai_act_risk_class": "unknown"}
    assert list(stub).index("governance") == list(stub).index("autonomy_profile") + 1
    [entry] = Inventory.load([write(tmp_path, stub, "stub.yaml")]).entries
    assert entry.governance == {"eu_ai_act_risk_class": "unknown"}


def test_cli_stubs_write_the_governance_placeholder(tmp_path, index):
    result, _ = scan(tmp_path, index)
    report = tmp_path / "report.json"
    report.write_text(result.to_json())
    out = tmp_path / "pending"
    invocation = CliRunner().invoke(main, ["inventory", "stubs", str(report), "-o", str(out)])
    assert invocation.exit_code == 0, invocation.output
    [path] = sorted(out.iterdir())
    assert yaml.safe_load(path.read_text())["governance"] == {"eu_ai_act_risk_class": "unknown"}


# ------------------------------------------------------------- inventory check


def test_inventory_check_lists_the_declared_class(tmp_path):
    path = write(tmp_path, card(governance=GOVERNANCE))
    invocation = CliRunner().invoke(main, ["inventory", "check", str(path)])
    assert invocation.exit_code == 0, invocation.output
    assert "EU AI Act class (declared)" in invocation.output
    assert "refunds-agent" in invocation.output and "high" in invocation.output


def test_inventory_check_rejects_a_malformed_block_without_echoing_it(tmp_path):
    path = write(tmp_path, card(governance={"eu_ai_act_risk_class": SECRET_SHAPED}))
    invocation = CliRunner().invoke(main, ["inventory", "check", str(path)])
    assert invocation.exit_code == 1
    assert "governance.eu_ai_act_risk_class" in invocation.output
    assert SECRET_SHAPED not in invocation.output


# ------------------------------------------------------------------ findings


def test_a_matched_finding_records_the_declared_block_and_its_card(tmp_path, index):
    _, agent = scan(tmp_path, index, [write(tmp_path, card(governance=GOVERNANCE))])
    assert agent.shadow is False and agent.registry_match == "refunds-agent"
    assert agent.metadata[DECLARED_GOVERNANCE_KEY] == {**GOVERNANCE, "source": "refunds-agent"}
    exported = agent.to_dict()
    assert exported["metadata"][DECLARED_GOVERNANCE_KEY]["source"] == "refunds-agent"
    assert {f"{EU}Art.12", f"{EU}Art.14", f"{EU}Art.26"} <= set(exported["metadata"]["controls"])


def test_an_unmatched_finding_has_no_declared_block(tmp_path, index):
    other = card(governance=GOVERNANCE, discovery={"resources": [AGENT_ARN + "-other"]})
    _, agent = scan(tmp_path, index, [write(tmp_path, other)])
    assert agent.shadow is True and DECLARED_GOVERNANCE_KEY not in agent.metadata
    assert f"{EU}Art.26" not in control_references(agent)


def test_a_card_without_governance_declares_nothing(tmp_path, index):
    _, agent = scan(tmp_path, index, [write(tmp_path, card())])
    assert agent.shadow is False and DECLARED_GOVERNANCE_KEY not in agent.metadata


def test_a_planted_block_is_replaced_on_every_pass(make_finding):
    # A connector, plugin or cache entry cannot declare facts for a finding.
    finding = make_finding(shadow=False, metadata={DECLARED_GOVERNANCE_KEY: {"eu_ai_act_risk_class": "high"}})
    apply_declared_governance(finding, None)
    assert DECLARED_GOVERNANCE_KEY not in finding.metadata
    entry = InventoryEntry(agent_id="card-a", governance={"eu_ai_act_risk_class": "limited"})
    apply_declared_governance(finding, entry)
    apply_declared_governance(finding, entry)
    assert finding.metadata[DECLARED_GOVERNANCE_KEY] == {
        "eu_ai_act_risk_class": "limited",
        "source": "card-a",
    }
    apply_declared_governance(finding, InventoryEntry(agent_id="card-b"))
    assert DECLARED_GOVERNANCE_KEY not in finding.metadata


def test_a_revoked_declaration_disappears_on_the_next_run(tmp_path, index):
    path = write(tmp_path, card(governance=GOVERNANCE))
    config = ScanConfig(
        connectors=[ConnectorSpec(name="cloud.aws", config={"input": str(bedrock_export(tmp_path))})],
        inventory=[str(path)],
    )
    engine = Engine(config, index=index)
    [agent] = engine.run().findings
    assert DECLARED_GOVERNANCE_KEY in agent.metadata
    write(tmp_path, card())
    [agent] = engine.run().findings
    assert agent.shadow is False and DECLARED_GOVERNANCE_KEY not in agent.metadata


# ------------------------------------------------------------- declared rules


def _declared(make_finding, risk_class: str, **overrides: Any):
    block = {"eu_ai_act_risk_class": risk_class, "source": "card"}
    fields = {"shadow": False, "owner": "team", "metadata": {DECLARED_GOVERNANCE_KEY: block}}
    fields.update(overrides)
    return make_finding(**fields)


def test_declared_high_risk_references_record_keeping_oversight_and_deployer_articles(make_finding):
    refs = control_references(_declared(make_finding, "high", kind=Kind.NETWORK_CONTACT))
    assert refs == [f"{EU}Art.12", f"{EU}Art.14", f"{EU}Art.26"]


@pytest.mark.parametrize("risk_class", ["limited", "gpai", "gpai-systemic"])
@pytest.mark.parametrize("kind", [Kind.AGENT, Kind.BOT_APP, Kind.AI_APP])
def test_declared_transparency_classes_reference_art_50_for_user_facing_kinds(make_finding, risk_class, kind):
    assert f"{EU}Art.50" in control_references(_declared(make_finding, risk_class, kind=kind))


@pytest.mark.parametrize("risk_class", ["limited", "gpai"])
def test_declared_transparency_needs_a_user_facing_kind(make_finding, risk_class):
    assert control_references(_declared(make_finding, risk_class, kind=Kind.NETWORK_CONTACT)) == []


@pytest.mark.parametrize("risk_class", ["prohibited", "minimal", "unknown"])
def test_other_declared_classes_add_no_reference(make_finding, risk_class):
    assert control_references(_declared(make_finding, risk_class, kind=Kind.NETWORK_CONTACT)) == []


@pytest.mark.parametrize("shadow", [True, None])
def test_declared_facts_apply_only_to_registered_findings(make_finding, shadow):
    finding = _declared(make_finding, "high", kind=Kind.NETWORK_CONTACT, shadow=shadow)
    assert declared_risk_class(finding) is None and declared_facts(finding) is None
    assert f"{EU}Art.26" not in control_references(finding)


@pytest.mark.parametrize(
    "block",
    [
        {"eu_ai_act_risk_class": "high", "source": "card"},
        {"iso42001_scope": False, "source": "card"},
        {**GOVERNANCE, "source": "card"},
    ],
)
def test_valid_declared_blocks(block):
    assert valid_declared_governance(block)


@pytest.mark.parametrize(
    "block",
    [
        None,
        [],
        {"source": "card"},
        {"eu_ai_act_risk_class": "high"},
        {"eu_ai_act_risk_class": "high", "source": 3},
        {"eu_ai_act_risk_class": "high", "source": "card", "verified": True},
        {"eu_ai_act_risk_class": "critical", "source": "card"},
    ],
)
def test_malformed_declared_blocks(block):
    assert not valid_declared_governance(block)


# --------------------------------------------------------------------- fleet


def _report(tmp_path: Path, index, inventory: list[Path] | None = None) -> dict[str, Any]:
    result, _ = scan(tmp_path, index, inventory)
    return json.loads(result.to_json())


def test_fleet_merge_keeps_declared_facts_only_for_registered_findings(tmp_path, index):
    registered = _report(tmp_path, index, [write(tmp_path, card(governance=GOVERNANCE))])
    [agent] = merge_reports([("a.json", registered), ("b.json", registered)]).findings
    assert agent.shadow is False and agent.metadata[DECLARED_GOVERNANCE_KEY]["source"] == "refunds-agent"
    unregistered = _report(tmp_path, index, [write(tmp_path, card(discovery={"resources": ["other"]}))])
    [agent] = merge_reports([("a.json", registered), ("b.json", unregistered)]).findings
    assert agent.shadow is True and DECLARED_GOVERNANCE_KEY not in agent.metadata


@pytest.mark.parametrize(
    "damage",
    [
        lambda block: block.update(eu_ai_act_risk_class="critical"),
        lambda block: block.pop("source"),
        lambda block: block.update(oversight_measures="review"),
    ],
)
def test_fleet_merge_rejects_malformed_declared_governance(tmp_path, index, damage):
    report = _report(tmp_path, index, [write(tmp_path, card(governance=GOVERNANCE))])
    damage(report["findings"][0]["metadata"][DECLARED_GOVERNANCE_KEY])
    with pytest.raises(ValueError, match="malformed declared governance"):
        merge_reports([("broken.json", report)])


# ------------------------------------------------------------------- reports


def _registered(**metadata: Any) -> ScanResult:
    from shadowscan.models import Finding, Surface

    finding = Finding(
        surface=Surface.CLOUD,
        connector="cloud.aws",
        kind=Kind.AGENT,
        title="Refunds agent",
        resource=AGENT_ARN,
        resource_type="bedrock-agent",
        shadow=False,
        registry_match="refunds-agent",
        metadata=metadata,
    )
    return ScanResult(findings=[finding], stats=[ScanStats(connector="cloud.aws", started_at="2026-01-01")])


def test_markdown_and_html_label_declared_facts():
    hostile = {
        **GOVERNANCE,
        "intended_purpose": "<u>purpose</u> @team https://x.test",
        "source": "<u>card</u>",
    }
    result = _registered(**{DECLARED_GOVERNANCE_KEY: hostile})
    markdown = render(result, "markdown")
    assert "**Declared governance** (card `<u>card</u>`, not verified):" in markdown
    assert "EU AI Act risk class: high" in markdown and "ISO/IEC 42001 scope: yes" in markdown
    assert "&lt;u&gt;purpose&lt;/u&gt; \\[@\\]team hxxps://x.test" in markdown
    page = render(result, "html")
    assert "<b>Declared governance</b> (card <code>&lt;u&gt;card&lt;/u&gt;</code>, not verified)" in page
    assert "<li>intended purpose: &lt;u&gt;purpose&lt;/u&gt;" in page and "<u>" not in page
    # Shown once, as declared facts, not again in the raw metadata dump.
    assert page.count("Weekly sample review") == 1


def test_reports_omit_a_malformed_declared_block():
    result = _registered(**{DECLARED_GOVERNANCE_KEY: {"eu_ai_act_risk_class": "critical", "source": "c"}})
    assert "Declared governance" not in render(result, "markdown")
    assert "Declared governance" not in render(result, "html")
