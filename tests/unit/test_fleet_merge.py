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
