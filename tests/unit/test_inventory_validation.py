"""Inventory approval boundaries reject malformed declarations before scanning."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from shadowscan.cli import _exit_code, main
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine
from shadowscan.models import Finding, Kind, Surface
from shadowscan.registry import Inventory, InventoryEntry, InventoryValidationError

APPROVED = "arn:aws:bedrock:*:111:agent/APPROVED"
OTHER = "arn:aws:bedrock:us-east-1:222:agent/OTHER"
LIST_FIELDS = ("resources", "names", "aliases", "frameworks", "surfaces", "providers", "accounts", "regions", "tags")


def _write_inventory(tmp_path, payload, suffix="yaml"):
    path = tmp_path / f"inventory.{suffix}"
    path.write_text(json.dumps(payload) if suffix == "json" else yaml.safe_dump(payload))
    return path


def _finding(resource):
    return Finding(surface=Surface.CLOUD, connector="cloud.aws", kind=Kind.AGENT,
                   title="Bedrock agent", resource=resource, resource_type="agent")


@pytest.mark.parametrize("format_name", ["simple", "card"])
@pytest.mark.parametrize("field", LIST_FIELDS)
def test_yaml_list_fields_never_accept_scalars(tmp_path, format_name, field):
    if format_name == "card":
        payload = {"metadata": {"agent_id": "approved"}, "discovery": {}}
        target = payload["metadata"] if field == "tags" else payload["discovery"]
    else:
        payload = {"id": "approved"}
        target = payload
    target[field] = APPROVED if field == "resources" else "*"
    with pytest.raises(InventoryValidationError, match=rf"\.{field}: expected a list"):
        Inventory.load([_write_inventory(tmp_path, payload)])


@pytest.mark.parametrize("bad_value", [None, True, 111, {}, [111], [None], [False], [["*"]], [""], ["   "]])
@pytest.mark.parametrize("suffix", ["json", "yaml"])
def test_approval_patterns_require_nonempty_string_items(tmp_path, bad_value, suffix):
    path = _write_inventory(tmp_path, {"id": "approved", "resources": bad_value}, suffix)
    with pytest.raises(InventoryValidationError, match="resources"):
        Inventory.load([path])


@pytest.mark.parametrize("field", ["names", "aliases", "frameworks", "surfaces", "providers", "accounts", "regions", "tags"])
def test_all_list_items_are_validated(tmp_path, field):
    path = _write_inventory(tmp_path, {"id": "approved", "resources": [APPROVED], field: ["cloud", 111]})
    with pytest.raises(InventoryValidationError, match=field):
        Inventory.load([path])


@pytest.mark.parametrize("payload", [
    False, True, 1, "approved", None,
    {"agents": {}}, {"agents": "*"}, {"agents": [None]}, {"agents": ["approved"]},
    {"agents": [{"id": "approved"}, {"resources": ["*"]}]},
    {"resources": ["*"]}, {"id": True}, {"id": {"token": "opaque-secret"}},
    {"id": "approved", "owner": ["team"]},
    {"id": "approved", "name": False},
    {"metadata": "approved"}, {"metadata": None}, {"metadata": []},
    {"metadata": {"agent_id": "approved"}, "discovery": "*"},
    {"metadata": {"agent_id": "approved"}, "discovery": None},
    {"metadata": {"agent_id": "approved", "owner_team": ["team"]}},
    {"metadata": {"agent_id": "approved", "classification": {"secret": "opaque-secret"}}},
    {"id": "approved", "resources": ["*"], "account": "111"},
    {"metadata": {"agent_id": "approved"}, "discovery": {"resources": ["*"], "account": "111"}},
    {"agents": [], "resources": ["*"]},
    {"id": "approved", "surfaces": ["could"]},
])
def test_malformed_inventory_is_not_silently_skipped(tmp_path, payload):
    with pytest.raises(InventoryValidationError):
        Inventory.load([_write_inventory(tmp_path, payload)])


def test_aliases_must_be_valid_even_when_names_take_precedence(tmp_path):
    payload = {"id": "approved", "names": ["accepted"], "aliases": {"invalid": True}}
    with pytest.raises(InventoryValidationError, match="aliases"):
        Inventory.load([_write_inventory(tmp_path, payload)])


@pytest.mark.parametrize("content,suffix", [
    ('id: approved\nresources: ["good"]\nresources: ["*"]\n', "yaml"),
    ('{"id": "approved", "resources": ["good"], "resources": ["*"]}', "json"),
    ('id: approved\nresources: ["unterminated credential sk-abcdefghijklmnop', "yaml"),
    ('{"id": "approved", "resources": ["sk-abcdefghijklmnop"', "json"),
    ('id: approved\nsk-abcdefghijklmnop: ["*"]\n', "yaml"),
    ('id: approved\nresources: [{password: opaque-secret}]\n', "yaml"),
])
def test_parse_and_schema_errors_do_not_echo_credential_values(tmp_path, content, suffix):
    path = tmp_path / f"inventory.{suffix}"
    path.write_text(content)
    with pytest.raises(InventoryValidationError) as exc:
        Inventory.load([path])
    assert "invalid inventory" in str(exc.value)
    assert "sk-abcdefghijklmnop" not in str(exc.value)
    assert "opaque-secret" not in str(exc.value)


def test_direct_inventory_entry_rejects_scalar_pattern():
    with pytest.raises(InventoryValidationError, match="resources"):
        InventoryEntry(agent_id="approved", resources=APPROVED)  # type: ignore[arg-type]


@pytest.mark.parametrize("content", [
    "", "agent_id,agent_id,resources\na,b,*\n", "agent_id,,resources\na,b,*\n",
    "agent_id,resources\na\n", "agent_id,resources\na,*,extra\n",
    "agent_id,resources\n,anything\n", "owner,resources\nteam,*\n",
    "agent_id,account,resources\na,111,*\n",
    "agent_id,surfaces\na,could\n", "agent_id,resources\na,good||*\n",
    'agent_id,resources\na,"unterminated\n',
])
def test_csv_header_rows_and_list_items_are_validated(tmp_path, content):
    path = tmp_path / "inventory.csv"
    path.write_text(content)
    with pytest.raises(InventoryValidationError):
        Inventory.load([path])


def test_csv_pipe_lists_remain_supported_for_every_list_field(tmp_path):
    path = tmp_path / "inventory.csv"
    path.write_text(
        "agent_id,name,owner,resources,names,aliases,frameworks,surfaces,providers,accounts,regions,tags\n"
        "approved, Approved Agent , Platform ,good|other,first|second,a|b,framework.one|framework.two,"
        "cloud|code,aws|gcp,111|222,us-east-1|eu-west-1,tag.one|tag.two\n"
    )
    entry = Inventory.load([path]).entries[0]
    assert entry.agent_id == "approved" and entry.owner == "Platform"
    assert entry.resources == ["good", "other"]
    assert entry.names == ["first", "second"]
    assert entry.frameworks == ["framework.one", "framework.two"]
    assert entry.surfaces == ["cloud", "code"]
    assert entry.providers == ["aws", "gcp"]
    assert entry.accounts == ["111", "222"]
    assert entry.regions == ["us-east-1", "eu-west-1"]
    assert entry.tags == ["tag.one", "tag.two"]


def test_explicit_empty_inventories_and_name_only_entries_remain_supported(tmp_path):
    for payload in ([], {"agents": []}):
        assert len(Inventory.load([_write_inventory(tmp_path, payload)])) == 0
    path = _write_inventory(tmp_path, {"agents": [{"id": "approved", "names": ["my agent"]}]})
    inventory = Inventory.load([path])
    assert len(inventory) == 1
    assert inventory.match(_finding(OTHER)) is None


def test_supported_inventory_formats_and_examples_still_load(tmp_path):
    root = Path(__file__).parents[2]
    assert len(Inventory.load([root / "agent-card.yaml"])) == 1
    assert len(Inventory.load([root / "examples/inventory/agents.yaml"])) == 2
    payload = {"metadata": {"agent_id": "approved", "classification": "Internal", "tags": ["reviewed"]},
               "discovery": {"resources": [APPROVED], "accounts": ["111"]},
               "autonomy_profile": {"level": 3}}
    for suffix in ("yaml", "json"):
        entry = Inventory.load([_write_inventory(tmp_path, payload, suffix)]).entries[0]
        assert entry.tags == ["reviewed", "Internal"]
        assert entry.resources == [APPROVED]
    path = tmp_path / "multi.yaml"
    path.write_text("id: one\nresources: [one]\n---\nmetadata:\n  agent_id: two\ndiscovery:\n  resources: [two]\n")
    assert len(Inventory.load([path])) == 2


def test_scalar_wildcard_cannot_reduce_unrelated_agent_risk_or_pass_security_gate(tmp_path, index):
    source = tmp_path / "cloud.jsonl"
    source.write_text(json.dumps({"_kind": "bedrock-agent", "_region": "us-east-1", "agentId": "OTHER",
                                  "agentArn": OTHER, "agentName": "Unregistered", "agentStatus": "PREPARED",
                                  "_action_groups": [], "_knowledge_bases": [], "_aliases": []}) + "\n")
    inventory = _write_inventory(tmp_path, {"agents": [{"id": "approved", "owner": "Platform", "resources": [APPROVED]}]})
    config = ScanConfig(connectors=[ConnectorSpec(name="cloud.aws", config={"input": str(source)})],
                        inventory=[str(inventory)], fail_on="high")
    result = Engine(config, index=index).run()
    assert result.complete and len(result.findings) == 1
    agent = result.findings[0]
    assert agent.resource == OTHER
    assert agent.shadow is True and agent.registry_match is None
    assert _exit_code(result, config.fail_on) == 2
    original_risk = agent.risk.score

    # The reviewed exploit converted this scalar into single-character patterns,
    # including '*', then inherited an owner and reduced the unrelated agent's risk.
    inventory.write_text(yaml.safe_dump({"agents": [{"id": "approved", "owner": "Platform", "resources": APPROVED}]}))
    with pytest.raises(InventoryValidationError, match="resources"):
        Engine(config, index=index)
    invocation = CliRunner().invoke(main, ["run", "cloud.aws", "--input", str(source), "--inventory", str(inventory),
                                          "--format", "json", "--fail-on", "high"])
    assert invocation.exit_code != 0
    assert "resources" in invocation.output or "resources" in str(invocation.exception)
    assert '"shadow": false' not in invocation.output
    assert '"status": "complete"' not in invocation.output

    # Correcting the declaration to a list restores the same conservative result.
    inventory.write_text(yaml.safe_dump({"agents": [{"id": "approved", "owner": "Platform", "resources": [APPROVED]}]}))
    repaired = Engine(config, index=index).run()
    assert repaired.findings[0].risk.score == original_risk
    assert _exit_code(repaired, config.fail_on) == 2
