"""Declared autonomy levels: Capability Card schema 2, simple inventories, stubs, scoring and merges."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from click.testing import CliRunner

from shadowscan.autonomy import SCHEMA, UNDERSTATED_TAG, classify, merge_autonomy, valid_autonomy
from shadowscan.cli import main
from shadowscan.config import ConfigValidationError, ConnectorSpec, ScanConfig
from shadowscan.engine import Engine
from shadowscan.fleet import merge_reports
from shadowscan.models import Finding, Kind, Surface
from shadowscan.registry import (
    IGNORED_AUTONOMY_LEVEL,
    Inventory,
    InventoryEntry,
    InventoryValidationError,
    card_stub_for,
)
from shadowscan.risk import AUTONOMY_WEIGHTS, RiskPolicy, assess

AGENT_ARN = "arn:aws:bedrock:us-east-1:111111111111:agent/AGENTX"


def card(**extra: Any) -> dict[str, Any]:
    return {
        "metadata": {"agent_id": "refunds-agent", "owner_team": "payments"},
        "discovery": {"resources": [AGENT_ARN]},
        **extra,
    }


def write(tmp_path: Path, payload: Any, name: str = "card.yaml") -> Path:
    path = tmp_path / name
    path.write_text(yaml.safe_dump(payload, sort_keys=False))
    return path


def bedrock_export(tmp_path: Path, confirmation: str = "DISABLED") -> Path:
    source = tmp_path / "aws.jsonl"
    record = {
        "_kind": "bedrock-agent",
        "_region": "us-east-1",
        "agentId": "AGENTX",
        "agentArn": AGENT_ARN,
        "agentName": "refunds",
        "agentStatus": "PREPARED",
        "_action_groups": [
            {
                "actionGroupName": "refund",
                "actionGroupState": "ENABLED",
                "actionGroupExecutor": {"lambda": "arn:aws:lambda:us-east-1:111111111111:function:refund"},
                "functionSchema": {
                    "functions": [
                        {"name": "issue_refund", "requireConfirmation": confirmation},
                        {"name": "close_case", "requireConfirmation": confirmation},
                    ]
                },
                "agentVersion": "DRAFT",
            }
        ],
        "_knowledge_bases": [],
        "_aliases": [],
    }
    source.write_text(json.dumps(record) + "\n")
    return source


def scan(tmp_path: Path, index, inventory: list[Path] | None = None, **options: Any):
    config = ScanConfig(
        connectors=[ConnectorSpec(name="cloud.aws", config={"input": str(bedrock_export(tmp_path))})],
        inventory=[str(path) for path in inventory or []],
        **options,
    )
    result = Engine(config, index=index).run()
    assert result.complete
    [agent] = result.findings
    return result, agent


# ------------------------------------------------------------- card parsing


def test_schema_version_2_card_declares_a_level(tmp_path):
    [entry] = Inventory.load([write(tmp_path, card(schema_version=2, autonomy_profile={"level": 3}))]).entries
    assert entry.autonomy_level == 3 and not entry.ignored_autonomy_level


@pytest.mark.parametrize("profile", [None, {}, {"level": None, "memory_persistence": True}])
def test_schema_version_2_card_may_leave_the_level_undeclared(tmp_path, profile):
    payload = card(schema_version=2) if profile is None else card(schema_version=2, autonomy_profile=profile)
    inventory = Inventory.load([write(tmp_path, payload)])
    assert inventory.entries[0].autonomy_level is None and inventory.autonomy_warnings() == []


@pytest.mark.parametrize("level", [6, -1, "3", True, 2.0, [3]])
def test_schema_version_2_rejects_a_level_outside_the_scale(tmp_path, level):
    with pytest.raises(
        InventoryValidationError, match="autonomy_profile.level: expected an integer from 0 to 5"
    ):
        Inventory.load([write(tmp_path, card(schema_version=2, autonomy_profile={"level": level}))])


@pytest.mark.parametrize("profile", ["L3", [3], 3])
def test_schema_version_2_requires_an_autonomy_profile_mapping(tmp_path, profile):
    with pytest.raises(InventoryValidationError, match="autonomy_profile: expected a mapping"):
        Inventory.load([write(tmp_path, card(schema_version=2, autonomy_profile=profile))])


@pytest.mark.parametrize("version", [0, 3, "2", True, 2.0, None])
def test_unknown_card_schema_version_is_invalid(tmp_path, version):
    with pytest.raises(InventoryValidationError, match="unsupported card schema version"):
        Inventory.load([write(tmp_path, card(schema_version=version))])


@pytest.mark.parametrize("version", [None, 1])
def test_earlier_card_level_is_ignored_with_a_warning(tmp_path, version):
    payload = card(autonomy_profile={"level": 4})
    if version is not None:
        payload["schema_version"] = version
    path = write(tmp_path, payload)
    inventory = Inventory.load([path])
    [entry] = inventory.entries
    assert entry.autonomy_level is None and entry.ignored_autonomy_level
    assert inventory.autonomy_warnings() == [
        f"inventory entry refunds-agent in {path}: {IGNORED_AUTONOMY_LEVEL}"
    ]
    assert IGNORED_AUTONOMY_LEVEL == "autonomy_profile.level ignored: card has no schema_version 2"


@pytest.mark.parametrize("profile", [None, {"memory_persistence": True}, "free text"])
def test_earlier_card_without_a_level_is_silent(tmp_path, profile):
    payload = card() if profile is None else card(autonomy_profile=profile)
    assert Inventory.load([write(tmp_path, payload)]).autonomy_warnings() == []


def test_inventory_check_prints_the_ignored_level_warning(tmp_path):
    path = write(tmp_path, card(autonomy_profile={"level": 4}))
    result = CliRunner().invoke(main, ["inventory", "check", str(path)])
    assert result.exit_code == 0, result.output
    assert IGNORED_AUTONOMY_LEVEL in " ".join(result.output.split())
    current = write(tmp_path, card(schema_version=2, autonomy_profile={"level": 4}), "v2.yaml")
    result = CliRunner().invoke(main, ["inventory", "check", str(current)])
    assert result.exit_code == 0 and IGNORED_AUTONOMY_LEVEL not in result.output


def test_engine_reports_the_ignored_level_as_an_advisory_inventory_warning(tmp_path, index):
    result, agent = scan(tmp_path, index, [write(tmp_path, card(autonomy_profile={"level": 0}))])
    [stats] = [s for s in result.stats if s.connector == "engine.inventory"]
    assert not (stats.incomplete or stats.errors or stats.skipped)
    assert any(IGNORED_AUTONOMY_LEVEL in warning for warning in stats.warnings)
    # The ignored level is undeclared: no comparison, no understated tag.
    assert agent.registry_match == "refunds-agent" and "declared" not in agent.metadata["autonomy"]
    assert UNDERSTATED_TAG not in agent.tags


# ----------------------------------------------------------- simple formats


def test_simple_entries_and_csv_columns_declare_a_level(tmp_path):
    listing = write(tmp_path, {"agents": [{"id": "a", "resources": ["x"], "autonomy_level": 0}]}, "a.yaml")
    assert Inventory.load([listing]).entries[0].autonomy_level == 0
    csv_path = tmp_path / "agents.csv"
    csv_path.write_text("agent_id,resources,autonomy_level\nb,x,4\nc,y,\n")
    assert [e.autonomy_level for e in Inventory.load([csv_path]).entries] == [4, None]


@pytest.mark.parametrize("level", [7, "high", True, 1.5])
def test_simple_entries_reject_a_level_outside_the_scale(tmp_path, level):
    path = write(tmp_path, [{"id": "a", "resources": ["x"], "autonomy_level": level}], "a.yaml")
    with pytest.raises(InventoryValidationError, match="autonomy_level: expected an integer from 0 to 5"):
        Inventory.load([path])


@pytest.mark.parametrize("cell", ["6", "x", "3.0", "-1", "03"])
def test_csv_rejects_a_level_outside_the_scale(tmp_path, cell):
    path = tmp_path / "agents.csv"
    path.write_text(f"agent_id,resources,autonomy_level\nb,x,{cell}\n")
    with pytest.raises(InventoryValidationError, match="autonomy_level"):
        Inventory.load([path])


@pytest.mark.parametrize(("level", "ignored"), [(6, False), (True, False), (None, 1)])
def test_inventory_entry_validates_its_autonomy_fields(level, ignored):
    with pytest.raises(InventoryValidationError):
        InventoryEntry(agent_id="a", autonomy_level=level, ignored_autonomy_level=ignored)


def test_bundled_examples_declare_levels_on_the_current_scale():
    root = Path(__file__).parents[2]
    [example] = Inventory.load([root / "agent-card.yaml"]).entries
    assert example.autonomy_level == 3 and not example.ignored_autonomy_level
    levels = {e.agent_id: e.autonomy_level for e in Inventory.load([root / "examples" / "inventory"]).entries}
    assert levels == {"claims-assistant": 3, "coderabbit-reviewer": 3, "sanctioned-copilot": 2}


# ------------------------------------------------------------ engine compare


def test_declared_level_below_the_observed_floor_is_flagged_and_scored(tmp_path, index):
    path = write(tmp_path, card(schema_version=2, autonomy_profile={"level": 1}))
    _, agent = scan(tmp_path, index, [path])
    autonomy = agent.metadata["autonomy"]
    assert agent.registry_match == "refunds-agent" and valid_autonomy(autonomy)
    assert (autonomy["floor"], autonomy["declared"], autonomy["declared_source"]) == (3, 1, "refunds-agent")
    assert UNDERSTATED_TAG in agent.tags
    factor = next(f for f in agent.risk.factors if f.id == f"tag:{UNDERSTATED_TAG}")
    assert (factor.weight, factor.description) == (10, "declared autonomy level is below the observed floor")


def test_declared_level_at_the_floor_is_not_flagged(tmp_path, index):
    path = write(tmp_path, card(schema_version=2, autonomy_profile={"level": 3}))
    _, agent = scan(tmp_path, index, [path])
    assert agent.metadata["autonomy"]["declared"] == 3 and UNDERSTATED_TAG not in agent.tags
    assert not [f for f in agent.risk.factors if f.id == f"tag:{UNDERSTATED_TAG}"]


def test_scan_without_inventory_still_classifies(tmp_path, index):
    _, agent = scan(tmp_path, index)
    assert agent.metadata["autonomy"]["floor"] == 3 and "declared" not in agent.metadata["autonomy"]
    assert agent.metadata["autonomy"]["schema"] == SCHEMA


def test_risk_autonomy_group_scores_only_with_a_nonzero_weight(tmp_path, index):
    _, default = scan(tmp_path, index)
    assert not [f for f in default.risk.factors if f.id.startswith("autonomy:")]
    _, weighted = scan(tmp_path, index, risk_weights={"autonomy": {"L3": 7, "L5": 20}})
    [factor] = [f for f in weighted.risk.factors if f.id.startswith("autonomy:")]
    assert (factor.id, factor.weight) == ("autonomy:L3", 7)
    assert factor.description == "observed autonomy floor L3 Semi-Autonomous / Agentic Workflow"
    assert weighted.risk.danger_score > default.risk.danger_score
    _, zero = scan(tmp_path, index, risk_weights={"autonomy": {"L3": 0}})
    assert not [f for f in zero.risk.factors if f.id.startswith("autonomy:")]


def test_autonomy_risk_reads_the_finding_not_a_forged_block():
    policy = RiskPolicy.from_options({"autonomy": {"L5": 50}})
    f = Finding(
        surface=Surface.CLOUD,
        connector="test",
        kind=Kind.CLOUD_RESOURCE,
        title="t",
        resource="r",
        resource_type="x",
        metadata={"autonomy": {"schema": SCHEMA, "floor": 5}},
    )
    assert not [factor for factor in assess(f, policy=policy).factors if factor.id.startswith("autonomy:")]
    secret = Finding(
        surface=Surface.CODE, connector="t", kind=Kind.SECRET, title="t", resource="r", resource_type="x"
    )
    policy = RiskPolicy.from_options({"autonomy": dict.fromkeys(AUTONOMY_WEIGHTS, 9)})
    assert not [
        factor for factor in assess(secret, policy=policy).factors if factor.id.startswith("autonomy:")
    ]


@pytest.mark.parametrize(
    ("weights", "message"),
    [
        ({"autonomy": {"L6": 1}}, "risk_weights.autonomy has an invalid key"),
        ({"autonomy": {"l3": 1}}, "risk_weights.autonomy.l3 must be one of L0, L1, L2, L3, L4, L5"),
        ({"autonomy": {"high": 1}}, "must be one of L0, L1, L2, L3, L4, L5"),
        ({"autonomy": {3: 1}}, "risk_weights.autonomy has an invalid key"),
        ({"autonomy": {"L3": True}}, "risk_weights.autonomy.L3 must be an integer between -100 and 100"),
        ({"autonomy": {"L3": 101}}, "must be an integer between -100 and 100"),
        ({"autonomy": ["L3"]}, "risk_weights.autonomy must be a mapping"),
    ],
)
def test_risk_weights_reject_unknown_autonomy_keys(weights, message):
    with pytest.raises(ValueError, match=message):
        RiskPolicy.from_options(weights)
    with pytest.raises(ConfigValidationError):
        ScanConfig.from_dict({"options": {"risk_weights": weights}, "connectors": []})


def test_autonomy_defaults_are_zero_for_every_level():
    assert AUTONOMY_WEIGHTS == {"L0": 0, "L1": 0, "L2": 0, "L3": 0, "L4": 0, "L5": 0}
    assert dict(RiskPolicy().autonomy) == AUTONOMY_WEIGHTS


def test_cached_findings_are_classified_after_collection(tmp_path, index):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("langchain\n")
    config = ScanConfig(
        connectors=[ConnectorSpec("code.filesystem", {"path": str(repo), "use_git": False})],
        incremental=True,
        state_dir=str(tmp_path / "state"),
        parallel=1,
    )
    first = Engine(config, index).run()
    second = Engine(config, index).run()
    assert second.stats[0].cached and first.findings
    assert all(valid_autonomy(f.metadata["autonomy"]) for f in second.findings)
    assert [f.metadata["autonomy"] for f in first.findings] == [
        f.metadata["autonomy"] for f in second.findings
    ]


# ------------------------------------------------------------------- stubs


def _finding(**overrides: Any) -> Finding:
    values: dict[str, Any] = {
        "surface": Surface.CLOUD,
        "connector": "cloud.aws",
        "kind": Kind.AGENT,
        "title": "Bedrock Agent: refunds",
        "resource": AGENT_ARN,
        "resource_type": "bedrock-agent",
        "provider": "aws",
        "account": "111111111111",
        "region": "us-east-1",
        "capabilities": ["tool-use", "code-exec"],
    }
    values.update(overrides)
    return Finding(**values)


def test_stub_writes_schema_version_2_and_the_observed_floor():
    stub = card_stub_for(_finding())
    assert next(iter(stub)) == "schema_version" and stub["schema_version"] == 2
    assert stub["autonomy_profile"]["level"] == 3


def test_stub_uses_a_well_formed_report_block_and_recomputes_a_malformed_one():
    reported = _finding(capabilities=["tool-use"])
    autonomy = classify(_finding(capabilities=["code-exec"], kind=Kind.AGENT_CONFIG))
    assert autonomy is not None and autonomy["floor"] == 2
    reported.metadata["autonomy"] = autonomy
    assert card_stub_for(reported)["autonomy_profile"]["level"] == 2
    reported.metadata["autonomy"] = {"schema": SCHEMA, "floor": 0}
    assert card_stub_for(reported)["autonomy_profile"]["level"] == 3


def test_stub_for_a_kind_without_autonomy_declares_no_level():
    stub = card_stub_for(_finding(kind=Kind.OAUTH_GRANT, resource_type="oauth-app"))
    assert stub["schema_version"] == 2 and "level" not in stub["autonomy_profile"]
    assert "memory_persistence" in stub["autonomy_profile"]


def test_stub_round_trips_without_an_understated_level(tmp_path, index):
    _, agent = scan(tmp_path, index)
    stub = write(tmp_path, card_stub_for(agent), "stub.yaml")
    [entry] = Inventory.load([stub]).entries
    assert entry.autonomy_level == agent.metadata["autonomy"]["floor"] == 3
    assert Inventory.load([stub]).autonomy_warnings() == []
    _, registered = scan(tmp_path, index, [stub])
    assert registered.registry_match == entry.agent_id
    assert registered.metadata["autonomy"]["declared"] == 3 and UNDERSTATED_TAG not in registered.tags


def test_cli_stubs_write_schema_version_2_cards(tmp_path, index):
    result, _ = scan(tmp_path, index)
    report = tmp_path / "report.json"
    report.write_text(result.to_json())
    out = tmp_path / "pending"
    invocation = CliRunner().invoke(main, ["inventory", "stubs", str(report), "-o", str(out)])
    assert invocation.exit_code == 0, invocation.output
    [path] = sorted(out.iterdir())
    written = yaml.safe_load(path.read_text())
    assert written["schema_version"] == 2 and written["autonomy_profile"]["level"] == 3


# ------------------------------------------------------------------- fleet


def _report(tmp_path: Path, index) -> dict[str, Any]:
    result, _ = scan(tmp_path, index)
    return json.loads(result.to_json())


def _gated_report(tmp_path: Path, index, inventory: list[Path] | None = None) -> dict[str, Any]:
    """A report whose Bedrock agent confirms every function: ceiling L2, oversight gated."""
    config = ScanConfig(
        connectors=[
            ConnectorSpec(name="cloud.aws", config={"input": str(bedrock_export(tmp_path, "ENABLED"))})
        ],
        inventory=[str(path) for path in inventory or []],
    )
    report = json.loads(Engine(config, index=index).run().to_json())
    autonomy = report["findings"][0]["metadata"]["autonomy"]
    assert (autonomy["ceiling"], autonomy["oversight"]) == (2, "gated")
    return report


def _bypassed(report: dict[str, Any]) -> dict[str, Any]:
    later = json.loads(json.dumps(report))
    later["findings"][0]["tags"].append("posture-permissions-bypassed")
    later["findings"][0]["capabilities"].append("autonomous")
    later["findings"][0]["metadata"]["autonomy"] = classify(Finding.from_dict(later["findings"][0]))
    return later


@pytest.mark.parametrize("bypass_first", [False, True])
def test_fleet_merge_classifies_merged_evidence_in_either_order(tmp_path, index, bypass_first):
    # Regression: the first source's block (L2, gated) survived approval-bypass evidence that
    # only a later source recorded.
    gated = _gated_report(tmp_path, index)
    bypassed = _bypassed(gated)
    sources = [("later.json", bypassed), ("first.json", gated)]
    merged = merge_reports(sources if bypass_first else sources[::-1])
    [agent] = merged.findings
    autonomy = agent.metadata["autonomy"]
    assert valid_autonomy(autonomy)
    assert "posture-permissions-bypassed" in agent.tags
    assert (autonomy["ceiling"], autonomy["oversight"]) == (5, "bypassed")
    expected = classify(agent)
    assert expected is not None and (autonomy["floor"], autonomy["ceiling"]) == (
        expected["floor"],
        expected["ceiling"],
    )


def test_fleet_merge_never_admits_less_than_a_source_block(tmp_path, index):
    gated = _gated_report(tmp_path, index)
    # A source whose block admits more than its other fields show (an earlier classification).
    wider = json.loads(json.dumps(gated))
    wider["findings"][0]["metadata"]["autonomy"] = _bypassed(gated)["findings"][0]["metadata"]["autonomy"]
    [agent] = merge_reports([("first.json", gated), ("wider.json", wider)]).findings
    autonomy = agent.metadata["autonomy"]
    block = wider["findings"][0]["metadata"]["autonomy"]
    assert valid_autonomy(autonomy) and "posture-permissions-bypassed" not in agent.tags
    assert (autonomy["floor"], autonomy["ceiling"], autonomy["oversight"]) == (
        block["floor"],
        block["ceiling"],
        "bypassed",
    )
    # Each widened bound keeps the rules of the block that set it.
    for bound in ("floor", "ceiling", "oversight"):
        assert [item for item in autonomy["basis"] if item["bound"] == bound] == [
            item for item in block["basis"] if item["bound"] == bound
        ]
    assert [item for item in autonomy["basis"] if item["bound"] == "initiation"] == [
        {"bound": "initiation", "rule": "no-initiation-evidence", "value": "unknown"}
    ]


def test_fleet_merge_keeps_a_declared_level_only_for_registered_findings(tmp_path, index):
    path = write(tmp_path, card(schema_version=2, autonomy_profile={"level": 2}))
    registered = _gated_report(tmp_path, index, [path])
    assert registered["findings"][0]["metadata"]["autonomy"]["declared"] == 2
    bypassed = _bypassed(registered)
    [agent] = merge_reports([("first.json", registered), ("later.json", bypassed)]).findings
    autonomy = agent.metadata["autonomy"]
    assert agent.shadow is False and valid_autonomy(autonomy)
    assert (autonomy["declared"], autonomy["declared_source"]) == (2, "refunds-agent")
    # The merged floor rose above the declared level.
    assert autonomy["floor"] > 2 and UNDERSTATED_TAG in agent.tags
    # A source without an inventory leaves registration unassessed, so the match stands.
    unassessed = _gated_report(tmp_path, index)
    assert unassessed["findings"][0]["shadow"] is None
    [agent] = merge_reports([("first.json", registered), ("other.json", unassessed)]).findings
    assert agent.shadow is False and agent.metadata["autonomy"]["declared"] == 2
    # A source whose inventory does not list the agent found it unregistered, which wins.
    other_card = card(metadata={"agent_id": "billing-agent", "owner_team": "payments"})
    other_card["discovery"] = {"resources": [AGENT_ARN.replace("AGENTX", "AGENTY")]}
    unregistered = _gated_report(tmp_path, index, [write(tmp_path, other_card, "other-card.yaml")])
    assert unregistered["findings"][0]["shadow"] is True
    [agent] = merge_reports([("first.json", registered), ("other.json", unregistered)]).findings
    assert agent.shadow is True and "declared" not in agent.metadata["autonomy"]
    assert UNDERSTATED_TAG not in agent.tags


@pytest.mark.parametrize("reverse", [False, True])
def test_fleet_merge_keeps_the_lowest_declared_level_in_either_order(tmp_path, index, reverse):
    # Regression: merge kept only the first source's declared level, so `merge low high` kept
    # autonomy-understated and `merge high low` dropped it.
    low = _gated_report(
        tmp_path, index, [write(tmp_path, card(schema_version=2, autonomy_profile={"level": 0}), "low.yaml")]
    )
    high = _gated_report(
        tmp_path, index, [write(tmp_path, card(schema_version=2, autonomy_profile={"level": 5}), "high.yaml")]
    )
    sources = [("low.json", low), ("high.json", high)]
    [agent] = merge_reports(sources[::-1] if reverse else sources).findings
    autonomy = agent.metadata["autonomy"]
    assert agent.shadow is False and valid_autonomy(autonomy)
    assert (autonomy["declared"], autonomy["declared_source"]) == (0, "refunds-agent")
    assert autonomy["floor"] > 0 and UNDERSTATED_TAG in agent.tags
    assert "declared-above-ceiling" not in {item["rule"] for item in autonomy["basis"]}


@pytest.mark.parametrize("reverse", [False, True])
def test_fleet_merge_of_conflicting_registrations_declares_nothing(tmp_path, index, reverse):
    low = _gated_report(
        tmp_path, index, [write(tmp_path, card(schema_version=2, autonomy_profile={"level": 0}), "low.yaml")]
    )
    other = card(schema_version=2, autonomy_profile={"level": 5})
    other["metadata"] = {"agent_id": "billing-agent", "owner_team": "payments"}
    high = _gated_report(tmp_path, index, [write(tmp_path, other, "high.yaml")])
    sources = [("low.json", low), ("high.json", high)]
    [agent] = merge_reports(sources[::-1] if reverse else sources).findings
    # Two inventories registered it to different agents: ambiguous, so no declared level applies.
    assert agent.shadow is True and agent.metadata["registry_match_reason"] == "ambiguous-resource-approval"
    assert "declared" not in agent.metadata["autonomy"] and UNDERSTATED_TAG not in agent.tags


def test_fleet_merge_applies_combination_rules_across_reports():
    # Regression: bounds widened one by one skipped the combination rules, so approval bypassed
    # in one report and a schedule trigger in another merged to L4 instead of L5.
    def agent(*tags: str) -> Finding:
        return Finding(
            surface=Surface.CLOUD,
            connector="cloud.aws",
            kind=Kind.AGENT,
            title="Bedrock Agent: refunds",
            resource=AGENT_ARN,
            resource_type="bedrock-agent",
            capabilities=["saas-actions"],
            tags=list(tags),
        )

    bypassed, scheduled = classify(agent("posture-permissions-bypassed")), classify(agent("scheduled"))
    assert bypassed is not None and scheduled is not None
    assert (bypassed["floor"], bypassed["initiation"]) == (4, "unknown")
    assert (scheduled["floor"], scheduled["oversight"]) == (2, "unknown")
    merged = agent()
    merge_autonomy(merged, [bypassed, scheduled])
    autonomy = merged.metadata["autonomy"]
    assert valid_autonomy(autonomy)
    assert (autonomy["floor"], autonomy["ceiling"]) == (5, 5)
    assert (autonomy["oversight"], autonomy["initiation"]) == ("bypassed", "schedule")
    assert {"bound": "floor", "rule": "self-initiated", "value": 5} in autonomy["basis"]
    assert {"bound": "initiation", "rule": "schedule-trigger", "value": "schedule"} in autonomy["basis"]
    # The same evidence observed together classifies the same way.
    together = classify(agent("posture-permissions-bypassed", "scheduled"))
    assert together is not None and together["floor"] == autonomy["floor"]


def test_fleet_merge_notes_a_declared_level_above_the_merged_ceiling(tmp_path, index):
    path = write(tmp_path, card(schema_version=2, autonomy_profile={"level": 4}))
    registered = _gated_report(tmp_path, index, [path])
    [agent] = merge_reports([("a.json", registered), ("b.json", registered)]).findings
    autonomy = agent.metadata["autonomy"]
    assert autonomy["ceiling"] == 2 and autonomy["declared"] == 4 and valid_autonomy(autonomy)
    assert {"bound": "ceiling", "rule": "declared-above-ceiling", "value": 4} in autonomy["basis"]


@pytest.mark.parametrize(
    "damage",
    [
        lambda autonomy: autonomy.update(floor=9),
        lambda autonomy: autonomy.update(schema="other"),
        lambda autonomy: autonomy["basis"].append({"bound": "floor", "rule": "made-up", "value": 1}),
    ],
)
def test_fleet_merge_rejects_malformed_autonomy(tmp_path, index, damage):
    report = _report(tmp_path, index)
    damage(report["findings"][0]["metadata"]["autonomy"])
    with pytest.raises(ValueError, match="malformed autonomy metadata"):
        merge_reports([("broken.json", report)])


def test_fleet_merge_classifies_findings_of_reports_without_autonomy(tmp_path, index):
    report = _report(tmp_path, index)
    del report["findings"][0]["metadata"]["autonomy"]
    [agent] = merge_reports([("older.json", report)]).findings
    assert agent.metadata["autonomy"] == classify(agent)


def test_fleet_merge_drops_autonomy_for_a_kind_it_does_not_describe(tmp_path, index):
    report = _report(tmp_path, index)
    secret = json.loads(json.dumps(report))
    secret["findings"][0]["kind"] = "secret"
    [finding] = merge_reports([("secret.json", secret)]).findings
    assert "autonomy" not in finding.metadata
