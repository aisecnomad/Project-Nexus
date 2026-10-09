"""Fleet merge: union of reports, identity-based deduplication, provenance and comparability."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.fleet import merge_reports

MCP = '{"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/srv"]}}}\n'
AGENT = "from crewai import Agent, Crew, Task\nagent = Agent(role='r', goal='g', backstory='b')\ncrew = Crew(agents=[agent], tasks=[Task(description='d', agent=agent)])\n"


def _report(tmp_path: Path, name: str, files: dict[str, str]) -> Path:
    repo = tmp_path / name
    repo.mkdir()
    for rel, text in files.items():
        (repo / rel).write_text(text)
    out = tmp_path / f"{name}.json"
    result = CliRunner().invoke(main, ["code", str(repo), "--format", "json", "-o", str(out)])
    assert result.exit_code == 0, result.output
    return out


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
        low["findings"][0]["shadow"] = False
        high["findings"][0]["risk"].update(score=90, level="critical")
        high["findings"][0]["shadow"] = True
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
