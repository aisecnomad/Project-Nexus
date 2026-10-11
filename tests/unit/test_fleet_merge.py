"""Fleet merge: union of reports, identity-based deduplication, provenance and comparability."""

from __future__ import annotations

import itertools
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.fleet import merge_reports
from shadowscan.models import Kind
from shadowscan.reporters import render

MCP = '{"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/srv"]}}}\n'
AGENT = "from crewai import Agent, Crew, Task\nagent = Agent(role='r', goal='g', backstory='b')\ncrew = Crew(agents=[agent], tasks=[Task(description='d', agent=agent)])\n"


def _report(tmp_path: Path, name: str, files: dict[str, str]) -> Path:
    repo = tmp_path / name
    repo.mkdir()
    for rel, text in files.items():
        (repo / rel).write_text(text)
    return _scan(repo, tmp_path / f"{name}.json")


def _scan(repo: Path, out: Path, *options: str) -> Path:
    result = CliRunner().invoke(main, ["code", str(repo), "--format", "json", "-o", str(out), *options])
    assert result.exit_code == 0, result.output
    return out


def _inventory(tmp_path: Path, name: str, agent_id: str | None = None) -> Path:
    """An inventory that registers every MCP configuration as ``agent_id``, or an empty one."""
    path = tmp_path / f"{name}.yaml"
    entry = f"\n  - id: {agent_id}\n    resources: ['*/.mcp.json']\n" if agent_id else " []\n"
    path.write_text("agents:" + entry)
    return path


def test_merge_unions_reports_and_records_sources(tmp_path: Path):
    a = _report(tmp_path, "laptop-a", {".mcp.json": MCP})
    b = _report(tmp_path, "laptop-b", {"crew.py": AGENT, "requirements.txt": "crewai==0.186.0\n"})
    out = tmp_path / "merged.json"
    result = CliRunner().invoke(main, ["merge", str(a), str(b), "--format", "json", "-o", str(out)])
    assert result.exit_code == 0, result.output
    merged = json.loads(out.read_text())
    counts = [len(json.loads(p.read_text())["findings"]) for p in (a, b)]
    assert len(merged["findings"]) == sum(counts) > 0
    assert merged["summary"]["complete"] is True
    assert {f["metadata"]["merged_from"][0] for f in merged["findings"]} == {"laptop-a.json", "laptop-b.json"}
    fleet = merged["collection_scope"]["fleet"]
    assert [s["name"] for s in fleet["sources"]] == ["laptop-a.json", "laptop-b.json"]
    assert merged["collection_scope"]["comparable"] is True
    assert len(merged["stats"]) == 2


def test_merging_the_same_report_twice_deduplicates_by_identity(tmp_path: Path):
    a = _report(tmp_path, "laptop-a", {".mcp.json": MCP})
    report = json.loads(a.read_text())
    merged = merge_reports([("monday.json", report), ("tuesday.json", json.loads(a.read_text()))])
    assert len(merged.findings) == len(report["findings"])
    assert merged.findings[0].metadata["merged_from"] == ["monday.json", "tuesday.json"]


def test_merged_fleet_reports_compare_with_diff(tmp_path: Path):
    a = _report(tmp_path, "laptop-a", {".mcp.json": MCP})
    merged_1 = tmp_path / "fleet-1.json"
    merged_2 = tmp_path / "fleet-2.json"
    for out in (merged_1, merged_2):
        result = CliRunner().invoke(main, ["merge", str(a), "--format", "json", "-o", str(out)])
        assert result.exit_code == 0, result.output
    result = CliRunner().invoke(main, ["diff", str(merged_1), str(merged_2)])
    assert result.exit_code == 0, result.output
    assert "0 new" in result.output and "0 resolved" in result.output


def test_incomplete_source_makes_the_merge_incomplete(tmp_path: Path):
    a = _report(tmp_path, "laptop-a", {".mcp.json": MCP})
    report = json.loads(a.read_text())
    report["stats"][0]["errors"] = ["connector timed out"]
    report["summary"]["complete"] = False
    broken = tmp_path / "broken.json"
    broken.write_text(json.dumps(report))
    out = tmp_path / "merged.json"
    result = CliRunner().invoke(main, ["merge", str(a), str(broken), "--format", "json", "-o", str(out)])
    assert result.exit_code == 3, result.output
    merged = json.loads(out.read_text())
    assert merged["summary"]["complete"] is False
    assert merged["collection_scope"]["comparable"] is False
    assert "broken.json: scan incomplete" in merged["collection_scope"]["reason"]


def test_merge_rejects_reports_with_another_identity_schema(tmp_path: Path):
    a = _report(tmp_path, "laptop-a", {".mcp.json": MCP})
    report = json.loads(a.read_text())
    report["finding_identity_schema"] = "shadowscan.finding-identity/v1"
    old = tmp_path / "old.json"
    old.write_text(json.dumps(report))
    result = CliRunner().invoke(main, ["merge", str(a), str(old), "--format", "json"])
    assert result.exit_code == 1
    assert "identity schema" in result.output
    with pytest.raises(ValueError):
        merge_reports([])


@pytest.mark.parametrize("damage", ["no-stats", "summary-only", "truncated-findings", "bad-scope"])
def test_fleet_cannot_restore_invalid_source_completion(tmp_path: Path, damage: str):
    path = _report(tmp_path, "laptop", {".mcp.json": MCP})
    healthy = json.loads(path.read_text())
    broken = json.loads(path.read_text())
    if damage == "no-stats":
        broken["stats"] = []
    elif damage == "summary-only":
        broken["summary"]["complete"] = False
    elif damage == "truncated-findings":
        broken["findings"] = []
    else:
        broken["collection_scope"]["fingerprint"] = "not-a-digest"
    result = merge_reports([("healthy", healthy), ("broken", broken)])
    assert result.collection_scope["comparable"] is False
    if damage != "bad-scope":
        assert not result.complete


def test_fleet_preserves_highest_source_risk_in_either_order(tmp_path: Path):
    path = _report(tmp_path, "laptop", {".mcp.json": MCP})
    for reverse in (False, True):
        low = json.loads(path.read_text())
        high = json.loads(path.read_text())
        low["findings"][0]["risk"].update(score=10, level="low")
        low["findings"][0].update(shadow=False, registry_match="fs-mcp")
        high["findings"][0]["risk"].update(score=90, level="critical")
        high["findings"][0]["shadow"] = True
        # Registration counts only from sources that reconciled against an inventory.
        low["inventory_present"] = high["inventory_present"] = True
        inputs = [("low", low), ("high", high)]
        result = merge_reports(list(reversed(inputs)) if reverse else inputs)
        assert result.findings[0].risk.score == 90
        assert result.findings[0].shadow is True


def test_fleet_rejects_malformed_statistics(tmp_path: Path):
    path = _report(tmp_path, "laptop", {".mcp.json": MCP})
    report = json.loads(path.read_text())
    report["stats"][0]["errors"] = ""
    with pytest.raises(ValueError, match="diagnostics"):
        merge_reports([("broken", report)])


def test_merge_refuses_a_reused_id_for_another_identity(tmp_path: Path):
    # Report ids are untrusted: a copy that keeps the ids but names other
    # resources must not fold the original findings into its own.
    path = _report(tmp_path, "laptop-a", {".mcp.json": MCP, "crew.py": AGENT})
    original = json.loads(path.read_text())
    forged = json.loads(path.read_text())
    for finding in forged["findings"]:
        finding["resource"] = "endpoint:other/" + finding["resource"]
    for inputs in ([("a", original), ("forged", forged)], [("forged", forged), ("a", original)]):
        with pytest.raises(ValueError, match="another identity"):
            merge_reports(inputs)
    forged_path = tmp_path / "forged.json"
    forged_path.write_text(json.dumps(forged))
    result = CliRunner().invoke(main, ["merge", str(path), str(forged_path), "--format", "json"])
    assert result.exit_code == 1
    assert "another identity" in result.output


def test_merge_names_sources_by_their_path_below_a_common_directory(tmp_path: Path):
    path = _report(tmp_path, "laptop", {".mcp.json": MCP})
    healthy = json.loads(path.read_text())
    broken = json.loads(path.read_text())
    broken["stats"][0]["errors"] = ["connector timed out"]
    broken["summary"]["complete"] = False
    collected = tmp_path / "collected"
    sources = []
    for host, report in (("host-a", healthy), ("host-b", broken)):
        (collected / host).mkdir(parents=True)
        (collected / host / "report.json").write_text(json.dumps(report))
        sources.append(str(collected / host / "report.json"))
    out = tmp_path / "fleet.json"
    result = CliRunner().invoke(main, ["merge", *sources, "--format", "json", "-o", str(out)])
    assert result.exit_code == 3, result.output
    merged = json.loads(out.read_text())
    names = ["host-a/report.json", "host-b/report.json"]
    assert [s["name"] for s in merged["collection_scope"]["fleet"]["sources"]] == names
    assert "host-b/report.json: scan incomplete" in merged["collection_scope"]["reason"]
    assert merged["findings"][0]["metadata"]["merged_from"] == names


def test_merge_without_inventory_does_not_report_unregistered_findings(tmp_path: Path):
    # shadow None means no inventory was supplied, not "unregistered".
    a = _report(tmp_path, "laptop-a", {".mcp.json": MCP})
    b = _report(tmp_path, "laptop-b", {"crew.py": AGENT, "requirements.txt": "crewai==0.186.0\n"})
    out = tmp_path / "merged.json"
    result = CliRunner().invoke(main, ["merge", str(a), str(b), "--format", "json", "-o", str(out)])
    assert result.exit_code == 0, result.output
    merged = json.loads(out.read_text())
    assert merged["findings"] and all(f["shadow"] is None for f in merged["findings"])
    assert all(f["registry_match"] is None for f in merged["findings"])
    assert merged["summary"]["shadow"] == 0
    assert merged["inventory_present"] is False and merged["inventory_size"] == 0

    fleet = merge_reports([(p.name, json.loads(p.read_text())) for p in (a, b)])
    html = render(fleet, "html")
    assert "shadow (unregistered)" not in html and "registered agents" not in html
    assert "<span class=shadow>SHADOW</span>" not in html
    assert "not in the inventory" not in render(fleet, "markdown")
    table = CliRunner().invoke(main, ["merge", str(a), str(b)])
    assert table.exit_code == 0, table.output
    assert "SHADOW" not in table.output and "registered agents" not in table.output


def test_merge_takes_registration_only_from_sources_that_reconciled(tmp_path: Path):
    repo = tmp_path / "laptop"
    unassessed = _report(tmp_path, "laptop", {".mcp.json": MCP, "crew.py": AGENT})
    sources = [("none", json.loads(unassessed.read_text()))]
    matches = {"it": "fs-mcp", "ops": "files"}
    for name, agent_id in matches.items():
        inventory = _inventory(tmp_path, name, agent_id)
        report = _scan(repo, tmp_path / f"{name}.json", "--inventory", str(inventory))
        sources.append((name, json.loads(report.read_text())))
    # None + False and None + True in both orders, and every order of all three.
    for inputs in [*itertools.permutations(sources, 2), *itertools.permutations(sources)]:
        result = merge_reports(list(inputs))
        by_kind = {f.kind: f for f in result.findings}
        assert len(by_kind) == len(result.findings) == 2
        assessed = [name for name, _ in inputs if name in matches]
        mcp = by_kind[Kind.MCP_SERVER]
        if len(assessed) == 1:
            # Registered by the one source whose inventory matched it.
            assert (mcp.shadow, mcp.registry_match) == (False, matches[assessed[0]])
        else:
            # Two inventories matched it to different agents: ambiguous, as in one scan.
            assert (mcp.shadow, mcp.registry_match) == (True, None)
            assert mcp.metadata["registry_match_reason"] == "ambiguous-resource-approval"
            assert mcp.metadata["registry_suggestions"] == ["files", "fs-mcp"]
        # Unregistered where an inventory was supplied, whatever the other source's position.
        assert by_kind[Kind.AGENT].shadow is True and by_kind[Kind.AGENT].registry_match is None
        assert result.summary()["shadow"] == len(assessed)
        assert result.inventory_present is True and result.inventory_size == 1


def test_merge_drops_the_registry_match_of_a_finding_another_source_found_unregistered(tmp_path: Path):
    unassessed = _report(tmp_path, "laptop", {".mcp.json": MCP})
    repo = tmp_path / "laptop"
    registered = _scan(repo, tmp_path / "it.json", "--inventory", str(_inventory(tmp_path, "it", "fs-mcp")))
    empty = _scan(repo, tmp_path / "empty.json", "--inventory", str(_inventory(tmp_path, "agents")))
    sources = [(p.name, json.loads(p.read_text())) for p in (registered, empty, unassessed)]
    assert sources[0][1]["findings"][0]["registry_match"] == "fs-mcp"
    # Registered + unregistered in both orders, and every order with an unassessed source.
    for inputs in [*itertools.permutations(sources[:2]), *itertools.permutations(sources)]:
        result = merge_reports(list(inputs))
        [finding] = result.findings
        assert finding.kind is Kind.MCP_SERVER
        assert finding.shadow is True and finding.registry_match is None
        assert result.summary()["shadow"] == 1


@pytest.mark.parametrize("forged_match", [None, ""])
def test_merge_ignores_a_registration_that_names_no_match(tmp_path: Path, forged_match: str | None):
    _report(tmp_path, "laptop", {".mcp.json": MCP})
    inventory = _inventory(tmp_path, "it", "fs-mcp")
    path = _scan(tmp_path / "laptop", tmp_path / "it.json", "--inventory", str(inventory))
    genuine = json.loads(path.read_text())
    forged = json.loads(path.read_text())
    forged["findings"][0]["registry_match"] = forged_match
    for inputs in ([("forged", forged), ("genuine", genuine)], [("genuine", genuine), ("forged", forged)]):
        [finding] = merge_reports(inputs).findings
        assert finding.shadow is False and finding.registry_match == "fs-mcp"


def test_merge_ignores_registration_claimed_by_a_source_without_an_inventory(tmp_path: Path):
    # Regression: a plugin finding with shadow false in a scan without an inventory was merged
    # as registered, beside any other source that did have an inventory.
    path = _report(tmp_path, "laptop", {".mcp.json": MCP})
    claimed = json.loads(path.read_text())
    assert claimed["inventory_present"] is False
    claimed["findings"][0].update(shadow=False, registry_match="approved-by-plugin")
    empty = _scan(tmp_path / "laptop", tmp_path / "empty.json", "--inventory", str(_inventory(tmp_path, "e")))
    reconciled = json.loads(empty.read_text())
    [finding] = merge_reports([("claimed", claimed)]).findings
    assert finding.shadow is None and finding.registry_match is None
    # Beside a source that reconciled it, only that source's assessment counts.
    for inputs in (
        [("claimed", claimed), ("empty", reconciled)],
        [("empty", reconciled), ("claimed", claimed)],
    ):
        result = merge_reports(inputs)
        [finding] = result.findings
        assert (finding.shadow, finding.registry_match) == (True, None)
        assert result.inventory_present is True and result.summary()["shadow"] == 1


def test_merge_treats_shadow_false_without_a_match_as_unassessed(tmp_path: Path):
    _report(tmp_path, "laptop", {".mcp.json": MCP})
    path = _scan(
        tmp_path / "laptop", tmp_path / "it.json", "--inventory", str(_inventory(tmp_path, "it", "fs-mcp"))
    )
    bare = json.loads(path.read_text())
    bare["findings"][0]["registry_match"] = None
    [finding] = merge_reports([("bare", bare)]).findings
    assert finding.shadow is None and finding.registry_match is None


def test_merge_of_conflicting_registrations_is_ambiguous_in_either_order(tmp_path: Path):
    _report(tmp_path, "laptop", {".mcp.json": MCP})
    sources = [
        (
            name,
            json.loads(
                _scan(tmp_path / "laptop", tmp_path / f"{name}.json", "--inventory", str(inv)).read_text()
            ),
        )
        for name, inv in (
            ("low", _inventory(tmp_path, "low", "mcp-low")),
            ("high", _inventory(tmp_path, "high", "mcp-high")),
        )
    ]
    for inputs in (sources, sources[::-1]):
        [finding] = merge_reports(inputs).findings
        assert (finding.shadow, finding.registry_match) == (True, None)
        assert finding.metadata["registry_match_reason"] == "ambiguous-resource-approval"
        assert finding.metadata["registry_suggestions"] == ["mcp-high", "mcp-low"]


def test_merge_reports_a_supplied_inventory_even_when_empty(tmp_path: Path):
    path = _report(tmp_path, "laptop", {".mcp.json": MCP})
    inventory = _inventory(tmp_path, "agents")
    empty = _scan(tmp_path / "laptop", tmp_path / "empty.json", "--inventory", str(inventory))
    out = tmp_path / "merged.json"
    for order in ((path, empty), (empty, path)):
        result = CliRunner().invoke(main, ["merge", *map(str, order), "--format", "json", "-o", str(out)])
        assert result.exit_code == 0, result.output
        merged = json.loads(out.read_text())
        assert merged["inventory_present"] is True and merged["inventory_size"] == 0
        assert [f["shadow"] for f in merged["findings"]] == [True]
        assert merged["summary"]["shadow"] == 1


@pytest.mark.parametrize("value", ["canary", 1, None, {"present": True}])
def test_merge_refuses_a_malformed_inventory_presence(tmp_path: Path, value: object):
    report = json.loads(_report(tmp_path, "laptop", {".mcp.json": MCP}).read_text())
    del report["inventory_present"]  # older reports omit it
    assert merge_reports([("old", report)]).inventory_present is False
    report["inventory_present"] = value
    with pytest.raises(ValueError, match="inventory presence must be a boolean") as raised:
        merge_reports([("forged", report)])
    assert str(value) not in str(raised.value)


@pytest.mark.parametrize("verdict", ["shadow", "registered", "inventory-size"])
def test_merge_refuses_an_older_report_whose_registration_it_cannot_attribute(tmp_path: Path, verdict: str):
    # Regression: reports from the v0.1.x tags share the identity schema but omit
    # inventory_present. Reading the missing key as false turned their shadow verdicts into
    # unassessed and the merge exited 0 with a lower fleet shadow count.
    _report(tmp_path, "laptop", {".mcp.json": MCP})
    agent_id = "fs-mcp" if verdict == "registered" else None
    inventory = _inventory(tmp_path, "it", agent_id)
    report = json.loads(
        _scan(tmp_path / "laptop", tmp_path / "old.json", "--inventory", str(inventory)).read_text()
    )
    del report["inventory_present"]
    if verdict == "inventory-size":
        report["findings"][0].update(shadow=None, registry_match=None)
        report["inventory_size"] = 1
    current = json.loads(_report(tmp_path, "desktop", {".mcp.json": MCP}).read_text())
    for inputs in ([("old.json", report)], [("old.json", report), ("new.json", current)]):
        with pytest.raises(ValueError, match="old.json: report predates inventory_present"):
            merge_reports(inputs)
    legacy = tmp_path / "legacy.json"
    legacy.write_text(json.dumps(report))
    out = tmp_path / "merged.json"
    result = CliRunner().invoke(main, ["merge", str(legacy), "--format", "json", "-o", str(out)])
    assert result.exit_code == 1 and "rescan before merging" in result.output
    assert not out.exists()
