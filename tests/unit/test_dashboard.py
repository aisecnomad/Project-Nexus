"""Static fleet dashboard and the shadowscan.inventory/v1 export: coverage first, nothing missing reads as zero."""

from __future__ import annotations

import base64
import hashlib
import html as html_lib
import json
import os
import re
import time
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from shadowscan import dashboard as dashboard_module
from shadowscan.autonomy import SCHEMA as AUTONOMY_SCHEMA
from shadowscan.autonomy import UNDERSTATED_TAG, apply_autonomy, level_title
from shadowscan.cli import main
from shadowscan.comparison import compare_reports, drift_counts, load_report_with_digest
from shadowscan.dashboard import (
    AUTONOMY_STATUSES,
    INVENTORY_SCHEMA,
    build_inventory,
    coverage_cell,
    load_history,
    parse_instant,
    render_inventory_json,
)
from shadowscan.fleet import FLEET_SCHEMA, merge_reports, report_result
from shadowscan.models import Finding, Kind, ScanResult, ScanStats, Surface
from shadowscan.registries import RECORD_KEY, RECORD_SCHEMA, reconcile_registries
from shadowscan.registry import InventoryEntry
from shadowscan.reporters import dashboard as page_module
from shadowscan.reporters.dashboard import _DASH_JS, render_dashboard

MCP = '{"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/srv"]}}}\n'
AGENT = "from crewai import Agent, Crew, Task\nagent = Agent(role='r', goal='g', backstory='b')\ncrew = Crew(agents=[agent], tasks=[Task(description='d', agent=agent)])\n"
SCOPE = "shadowscan.collection-scope/v1"


class _Page(HTMLParser):
    """Counts what a page could load or run, and collects attributes for accessibility checks."""

    def __init__(self) -> None:
        super().__init__()
        self.metas: list[dict[str, Any]] = []
        self.tags: list[tuple[str, dict[str, Any]]] = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "meta":
            self.metas.append(values)
        self.tags.append((tag, values))

    def count(self, tag: str) -> int:
        return sum(1 for name, _ in self.tags if name == tag)


def _parse(page: str) -> _Page:
    parser = _Page()
    parser.feed(page)
    return parser


def _hostile(name: str) -> str:
    # Markup, both quote characters and an ampersand: enough to break out of a text node or attribute.
    return f"<u>{name}</u>'\"&"


def _report(tmp_path: Path, name: str, files: dict[str, str], *args: str) -> Path:
    repo = tmp_path / name
    repo.mkdir()
    for rel, text in files.items():
        (repo / rel).write_text(text)
    out = tmp_path / f"{name}.json"
    result = CliRunner().invoke(main, ["code", str(repo), "--format", "json", "-o", str(out), *args])
    assert result.exit_code == 0, result.output
    return out


def _dashboard(tmp_path: Path, *args: str) -> tuple[Any, str, dict[str, Any]]:
    page, document = tmp_path / "dashboard.html", tmp_path / "inventory.json"
    result = CliRunner().invoke(
        main, ["dashboard", *args, "-o", str(page), "--inventory-json", str(document)]
    )
    if result.exit_code not in (0, 3):
        return result, "", {}
    return result, page.read_text(encoding="utf-8"), json.loads(document.read_text(encoding="utf-8"))


def _finding(title: str = "Agent", resource: str = "repo", **overrides: Any) -> Finding:
    fields: dict[str, Any] = {
        "surface": Surface.CODE,
        "connector": "code.filesystem",
        "kind": Kind.AGENT,
        "title": title,
        "resource": resource,
        "resource_type": "project",
    }
    fields.update(overrides)
    return Finding(**fields)


def _result(findings: list[Finding], **overrides: Any) -> ScanResult:
    started = overrides.pop("started", "2026-10-01T00:00:00+00:00")
    stats = overrides.pop("stats", None) or [
        ScanStats(connector="code.filesystem", started_at=started, finished_at=started)
    ]
    fingerprint = overrides.pop("fingerprint", "a" * 64)
    result = ScanResult(
        findings=findings,
        stats=stats,
        version="0.1.2",
        collection_scope={"schema": SCOPE, "comparable": True, "fingerprint": fingerprint},
        **overrides,
    )
    result.started_at = started
    result.finished_at = started
    return result


def _autonomy(floor: int) -> dict[str, Any]:
    return {
        "schema": AUTONOMY_SCHEMA,
        "floor": floor,
        "floor_label": level_title(floor),
        "ceiling": 5,
        "ceiling_label": level_title(5),
        "oversight": "bypassed",
        "initiation": "schedule",
        "basis": [],
    }


def _write(path: Path, report: dict[str, Any]) -> Path:
    path.write_text(json.dumps(report))
    return path


# ------------------------------------------------------------------ page security


def test_page_authorizes_only_its_script_and_loads_nothing(tmp_path):
    report = _report(tmp_path, "laptop", {".mcp.json": MCP, "crew.py": AGENT})
    result, page, _ = _dashboard(tmp_path, str(report))
    assert result.exit_code == 0, result.output
    parsed = _parse(page)
    policy = next(m["content"] for m in parsed.metas if m.get("http-equiv") == "Content-Security-Policy")
    expected = base64.b64encode(hashlib.sha256(_DASH_JS.encode()).digest()).decode()
    assert f"script-src 'sha256-{expected}'" in policy
    assert "default-src 'none'" in policy and "base-uri 'none'" in policy and "form-action 'none'" in policy
    assert {"name": "referrer", "content": "no-referrer"} in parsed.metas
    assert parsed.count("script") == 1
    for tag in ("img", "link", "iframe", "object", "embed", "form", "base"):
        assert parsed.count(tag) == 0, tag
    for tag, attrs in parsed.tags:
        assert not any(name.startswith("on") for name in attrs), tag
        if tag == "a":
            assert attrs["href"].startswith("#")
    assert "http://" not in page.replace("http://www.w3.org", "") and "https://" not in page


def test_every_untrusted_value_is_escaped_where_it_is_rendered():
    record = {
        "schema": RECORD_SCHEMA,
        "registry": "aws-agent-registry",
        "registry_id": _hostile("registry-id"),
        "record_id": _hostile("record"),
        "status": "approved",
        "descriptor_type": "agent",
        "bindings": [{"resource": _hostile("binding"), "coverage": "in-scope"}],
    }
    finding = _finding(
        title=_hostile("title"),
        resource=_hostile("resource"),
        connector=_hostile("connector"),
        provider=_hostile("provider"),
        account=_hostile("account"),
        region=_hostile("region"),
        owner=_hostile("owner"),
        tags=[_hostile("tag")],
        frameworks=[_hostile("framework")],
        shadow=False,
        registry_match=_hostile("registry-match"),
        metadata={"merged_from": [_hostile("merged")], RECORD_KEY: record},
    )
    stats = [
        ScanStats(
            connector=_hostile("stat-connector"),
            started_at="2026-10-01T00:00:00+00:00",
            errors=[_hostile("diagnostic")],
            warnings=[_hostile("warning")],
        )
    ]
    result = _result([finding], stats=stats)
    result.collection_scope = {
        "schema": SCOPE,
        "comparable": False,
        "reason": _hostile("reason"),
        "fleet": {
            "schema": FLEET_SCHEMA,
            "sources": [
                {
                    "name": _hostile("source"),
                    "version": _hostile("version"),
                    "complete": False,
                    "findings": 1,
                    "started_at": _hostile("started"),
                    "finished_at": None,
                    "inventory_present": True,
                    "connectors": [{"connector": _hostile("source-connector"), "status": "incomplete"}],
                }
            ],
        },
    }
    history = {
        "reports": 2,
        "shown": 1,
        "omitted": 0,
        "limit": 104,
        "undated": [_hostile("undated")],
        "points": [
            {
                "name": _hostile("point"),
                "sha256": "0" * 64,
                "started_at": _hostile("point-start"),
                "finished_at": None,
                "complete": True,
                "ai_systems": 1,
                "shadow": None,
                "l4_plus": None,
            }
        ],
        "pairs": [],
    }
    page = render_dashboard(build_inventory(result, name=_hostile("name"), history=history))
    assert "<u>" not in page
    for name in (
        "title",
        "resource",
        "provider",
        "account",
        "region",
        "owner",
        "tag",
        "registry-match",
        "registry-id",
        "stat-connector",
        "diagnostic",
        "warning",
        "reason",
        "source",
        "source-connector",
        "started",
        "point",
        "point-start",
        "undated",
    ):
        assert html_lib.escape(_hostile(name)) in page, name
    parsed = _parse(page)
    assert parsed.count("script") == 1 and parsed.count("img") == 0 and parsed.count("u") == 0


def test_lone_surrogates_and_controls_are_written_visibly(tmp_path):
    report = _report(tmp_path, "laptop", {"crew.py": AGENT})
    data = json.loads(report.read_text())
    data["findings"][0]["owner"] = "team\ud800\x1b[31m"
    report.write_text(json.dumps(data))
    result, page, document = _dashboard(tmp_path, str(report))
    assert result.exit_code == 0, result.output
    raw = (tmp_path / "dashboard.html").read_bytes()
    assert b"\x1b" not in raw and "\\ud800" in page and "\\u001b" in page
    text = (tmp_path / "inventory.json").read_bytes()
    assert text.isascii() and b"\x1b" not in text
    assert any(agent["owner"] == "team\ud800\x1b[31m" for agent in document["agents"])


# ------------------------------------------------------------------ coverage and completeness


def test_incomplete_and_uncollected_sources_never_read_as_zero(tmp_path):
    a = _report(tmp_path, "laptop-a", {".mcp.json": MCP})
    b = _report(tmp_path, "laptop-b", {"crew.py": AGENT})
    broken = json.loads(b.read_text())
    broken["stats"][0]["errors"] = ["connector timed out"]
    broken["summary"]["complete"] = False
    _write(b, broken)
    c = _report(tmp_path, "laptop-c", {".mcp.json": MCP})
    other = json.loads(c.read_text())
    other["stats"][0]["connector"] = "endpoint.mcp"
    _write(c, other)
    result, page, inventory = _dashboard(tmp_path, str(a), str(b), str(c))
    assert result.exit_code == 3, result.output
    assert (
        "INCOMPLETE SCAN" in page and inventory["complete"] is False and inventory["status"] == "incomplete"
    )
    sources = {source["name"]: source for source in inventory["sources"]}
    assert sources["laptop-b.json"]["complete"] is False
    connectors = inventory["coverage"]["connectors"]
    assert connectors == ["code.filesystem", "endpoint.mcp"]
    cells = {name: {c: coverage_cell(source, c) for c in connectors} for name, source in sources.items()}
    assert cells["laptop-b.json"]["code.filesystem"] == "incomplete"
    assert cells["laptop-a.json"] == {"code.filesystem": "complete", "endpoint.mcp": "not-collected"}
    assert cells["laptop-c.json"]["code.filesystem"] == "not-collected"
    # Only the connectors a source ran have a cell; the others read as not collected.
    assert sources["laptop-a.json"]["coverage"] == {"code.filesystem": "complete"}
    assert inventory["coverage"]["incomplete_sources"] == 1
    # The coverage panel comes first, and lists the incomplete source before the complete ones.
    assert page.index("id='coverage'") < page.index("id='overview'") < page.index("id='agents'")
    panel = page[page.index("id='coverage'") : page.index("id='overview'")]
    assert panel.index("laptop-b.json") < panel.index("laptop-a.json")
    assert "not collected" in panel and ">incomplete<" in panel
    assert "connector timed out" in panel


def test_a_skipped_connector_reads_skipped_and_exits_3(tmp_path):
    report = _report(tmp_path, "laptop", {"crew.py": AGENT})
    data = json.loads(report.read_text())
    data["stats"].append(
        {**data["stats"][0], "connector": "endpoint.mcp", "skipped": True, "skip_reason": "absent"}
    )
    data["summary"]["complete"] = False
    _write(report, data)
    result, page, inventory = _dashboard(tmp_path, str(report))
    assert result.exit_code == 3
    [source] = inventory["sources"]
    assert source["coverage"]["endpoint.mcp"] == "skipped" and not source["complete"]
    assert "st-skipped" in page and "INCOMPLETE SCAN" in page


def test_sources_of_an_older_fleet_report_have_unknown_coverage(tmp_path):
    a = _report(tmp_path, "laptop-a", {".mcp.json": MCP})
    fleet = merge_reports([("laptop-a.json", json.loads(a.read_text()))]).to_dict()
    for source in fleet["collection_scope"]["fleet"]["sources"]:
        for key in ("started_at", "finished_at", "inventory_present", "connectors"):
            source.pop(key)
    fleet["collection_scope"]["fleet"]["schema"] = "shadowscan.fleet-merge/v1"
    path = _write(tmp_path / "fleet.json", fleet)
    result, page, inventory = _dashboard(tmp_path, str(path))
    assert result.exit_code == 0, result.output
    [source] = inventory["sources"]
    assert source["connectors"] is None and source["inventory_present"] is None
    assert source["coverage"] == {} and inventory["coverage"]["unknown_coverage_sources"] == 1
    assert source["staleness_days"] is None
    assert "coverage is unknown" in page


def test_a_fleet_report_keeps_its_sources_and_provenance(tmp_path):
    a = _report(tmp_path, "laptop-a", {".mcp.json": MCP})
    b = _report(tmp_path, "laptop-b", {"crew.py": AGENT})
    out = tmp_path / "fleet.json"
    merged = CliRunner().invoke(main, ["merge", str(a), str(b), "--format", "json", "-o", str(out)])
    assert merged.exit_code == 0, merged.output
    result, _, inventory = _dashboard(tmp_path, str(out))
    assert result.exit_code == 0, result.output
    assert [source["name"] for source in inventory["sources"]] == ["laptop-a.json", "laptop-b.json"]
    assert all(source["coverage"] == {"code.filesystem": "complete"} for source in inventory["sources"])
    assert inventory["legacy_fleet"] is False
    assert {name for agent in inventory["agents"] for name in agent["merged_from"]} == {
        "laptop-a.json",
        "laptop-b.json",
    }
    # Staleness defaults to the newest source's last scan, never the wall clock.
    assert inventory["as_of"] == max(source["finished_at"] for source in inventory["sources"])


def test_staleness_is_measured_against_as_of(tmp_path):
    report = _report(tmp_path, "laptop", {"crew.py": AGENT})
    data = json.loads(report.read_text())
    data["finished_at"] = "2026-09-01T00:00:00+00:00"
    _write(report, data)
    result, page, inventory = _dashboard(tmp_path, str(report), "--as-of", "2026-09-15T12:00:00Z")
    assert result.exit_code == 0, result.output
    assert inventory["sources"][0]["staleness_days"] == 14
    assert inventory["as_of"] == "2026-09-15T12:00:00+00:00"
    assert "before 2026-09-15T12:00:00+00:00" in page
    bad = CliRunner().invoke(
        main, ["dashboard", str(report), "-o", str(tmp_path / "x.html"), "--as-of", "today"]
    )
    assert bad.exit_code == 1 and "UTC offset" in bad.output


def test_report_result_marks_inconsistent_completion_incomplete(tmp_path):
    report = json.loads(_report(tmp_path, "laptop", {"crew.py": AGENT}).read_text())
    report["summary"]["complete"] = False
    result = report_result("laptop.json", report)
    assert not result.complete
    assert any(st.connector == "engine.fleet" and st.incomplete for st in result.stats)
    truncated = json.loads(json.dumps(report))
    truncated["summary"]["complete"] = True
    truncated["findings"] = []
    assert not report_result("laptop.json", truncated).complete
    with pytest.raises(ValueError):
        report_result("x", {"findings": "nope"})


def test_malformed_fleet_sources_are_refused(tmp_path):
    report = _report(tmp_path, "laptop", {"crew.py": AGENT})
    data = json.loads(report.read_text())
    data["collection_scope"]["fleet"] = {
        "schema": FLEET_SCHEMA,
        "sources": [{"name": "a", "complete": "yes"}],
    }
    _write(report, data)
    result = CliRunner().invoke(main, ["dashboard", str(report), "-o", str(tmp_path / "d.html")])
    assert result.exit_code == 1 and "could not render dashboard" in result.output
    for sources in (
        [{"name": "a", "complete": True, "connectors": [{"connector": "x", "status": "fine"}]}],
        [{"name": "a", "complete": True, "connectors": "x"}],
        [{"name": "a", "complete": True, "findings": -1}],
        [],
    ):
        scan = _result([_finding()])
        scan.collection_scope = {"schema": SCOPE, "comparable": True, "fleet": {"sources": sources}}
        with pytest.raises(ValueError):
            build_inventory(scan)


def test_scan_level_records_are_not_coverage_columns(tmp_path):
    a = _report(tmp_path, "laptop-a", {"crew.py": AGENT})
    b = _report(tmp_path, "laptop-b", {"crew.py": AGENT})
    data = json.loads(a.read_text())
    # A warnings-only engine record, as a scan with an inventory kept in the scanned tree writes.
    data["stats"].append(
        {**data["stats"][0], "connector": "engine.inventory", "warnings": ["inventory in the scanned tree"]}
    )
    _write(a, data)
    result, page, inventory = _dashboard(tmp_path, str(a), str(b))
    assert result.exit_code == 0, result.output
    assert inventory["complete"] is True and inventory["coverage"]["connectors"] == ["code.filesystem"]
    assert all(source["coverage"] == {"code.filesystem": "complete"} for source in inventory["sources"])
    # It is still a diagnostic, and an incomplete engine record still makes its source incomplete.
    assert [entry["connector"] for entry in inventory["diagnostics"]] == ["engine.inventory"]
    assert "class='st-not-collected'" not in page


def test_coverage_grows_with_the_runs_listed_not_sources_times_connectors(monkeypatch):
    monkeypatch.setattr(page_module, "MAX_CONNECTOR_COLUMNS", 3)
    names = [f"plugin.c{n:03d}" for n in range(300)]
    sources: list[dict[str, Any]] = [
        {"name": f"s{n:03d}", "complete": True, "connectors": []} for n in range(300)
    ]
    sources[0]["connectors"] = [{"connector": name, "status": "complete"} for name in names]
    scan = _result([_finding()])
    scan.collection_scope = {
        "schema": SCOPE,
        "comparable": True,
        "fleet": {"schema": FLEET_SCHEMA, "sources": sources},
    }
    inventory = build_inventory(scan)
    assert inventory["coverage"]["connectors"] == names
    # One cell per run listed: 300, where one per source and connector would be 90,000.
    assert sum(len(source["coverage"]) for source in inventory["sources"]) == 300
    assert len(render_inventory_json(inventory)) < 200_000
    page = render_dashboard(inventory)
    panel = page[page.index("id='coverage'") : page.index("id='overview'")]
    assert "297 more connector column(s) are not shown" in panel and "plugin.c003" not in panel
    # A source that did not run a shown connector still reads not collected.
    assert panel.count("class='st-not-collected'") == 299 * 3
    assert panel.count("class='st-complete'>complete") == 300 + 3


def test_reports_without_inventory_present_have_no_inventory(tmp_path):
    # Reports written before inventory_present, whatever their inventory size or shadow values:
    # registration counts only from a report that says it reconciled, as shadowscan merge reads it.
    reports = []
    for name, finding, size in (
        ("a.json", _finding("a", "r1", shadow=True), 3),
        ("b.json", _finding("b", "r2", shadow=False, registry_match="agent-2"), 0),
        ("c.json", _finding("c", "r3"), 0),
    ):
        report = _result([finding], inventory_size=size).to_dict()
        report.pop("inventory_present")
        reports.append((name, report))
        _write(tmp_path / name, report)
    merged = merge_reports(reports)
    assert [source["inventory_present"] for source in merged.collection_scope["fleet"]["sources"]] == [
        False,
        False,
        False,
    ]
    assert merged.inventory_present is False
    # One report reads as it does among others.
    assert [report_result(name, report).inventory_present for name, report in reports] == [False] * 3
    assert {
        finding.shadow for name, report in reports for finding in report_result(name, report).findings
    } == {None}
    _, _, inventory = _dashboard(tmp_path, str(tmp_path / "a.json"), str(tmp_path / "b.json"))
    assert [source["inventory_present"] for source in inventory["sources"]] == [False, False]
    assert inventory["counts"]["inventory_status"] == {"shadow": 0, "sanctioned": 0, "no-inventory": 2}


def _v1_fleet(tmp_path: Path, *, inventory_size: int = 0) -> Path:
    """A fleet report as merges before fleet-merge/v2 wrote it: unreconciled findings were shadow."""
    findings = [
        _finding("rogue", f"r{n}", capabilities=["tool-use", "code-exec"], tags=["mcp-auto-approve"])
        for n in range(2)
    ]
    for finding in findings:
        apply_autonomy(finding)
    fleet = merge_reports([(f"{n}.json", _result([f]).to_dict()) for n, f in enumerate(findings)]).to_dict()
    fleet["collection_scope"]["fleet"]["schema"] = "shadowscan.fleet-merge/v1"
    for source in fleet["collection_scope"]["fleet"]["sources"]:
        for key in ("started_at", "finished_at", "inventory_present", "connectors"):
            source.pop(key)
    fleet["inventory_present"] = False
    fleet["inventory_size"] = inventory_size
    for item in fleet["findings"]:
        item["shadow"] = True
    return _write(tmp_path / f"fleet-v1-{inventory_size}.json", fleet)


def test_an_earlier_fleet_merge_without_an_inventory_is_not_shadow(tmp_path):
    path = _v1_fleet(tmp_path)
    result, page, inventory = _dashboard(tmp_path, str(path))
    assert result.exit_code == 0, result.output
    assert inventory["counts"]["inventory_status"] == {"shadow": 0, "sanctioned": 0, "no-inventory": 2}
    assert inventory["autonomy"]["priority"] == 0 and inventory["legacy_fleet"] is True
    assert "merged by an earlier version" in page and "have no inventory to reconcile against" in page
    # Merged again, or read as history, the same fleet reads the same.
    again = merge_reports([("fleet.json", json.loads(path.read_text()))])
    assert {finding.shadow for finding in again.findings} == {None} and again.inventory_present is False
    history = tmp_path / "history"
    history.mkdir()
    (history / "fleet.json").write_bytes(path.read_bytes())
    [point] = load_history(history)["points"]
    assert point["shadow"] is None and point["ai_systems"] == 2
    # An inventory size alone is not reconciliation: only inventory_present counts, so the
    # earlier fleet's shadow values are never read as registration evidence.
    result, page, inventory = _dashboard(tmp_path, str(_v1_fleet(tmp_path, inventory_size=3)))
    assert result.exit_code == 0, result.output
    assert inventory["counts"]["inventory_status"] == {"shadow": 0, "sanctioned": 0, "no-inventory": 2}
    assert inventory["legacy_fleet"] is True
    priority = page[page.index("id='priority'") : page.index("id='registries'")]
    assert "merge the source reports again" in priority
    # A report that is not a fleet merge is never legacy.
    report = _report(tmp_path, "laptop", {"crew.py": AGENT})
    assert _dashboard(tmp_path, str(report))[2]["legacy_fleet"] is False


# ------------------------------------------------------------------ shadow status, autonomy and priority


def test_shadow_sanctioned_and_no_inventory_stay_three_states():
    findings = [
        _finding("shadow", "r1", shadow=True),
        _finding("sanctioned", "r2", shadow=False, registry_match="agent-2"),
        _finding("unknown", "r3", shadow=None),
        _finding(
            "ambiguous",
            "r4",
            shadow=True,
            metadata={
                "registry_match_reason": "ambiguous-resource-approval",
                "registry_suggestions": ["a", "b"],
            },
        ),
    ]
    inventory = build_inventory(_result(findings))
    assert inventory["counts"]["inventory_status"] == {"shadow": 2, "sanctioned": 1, "no-inventory": 1}
    assert inventory["counts"]["ambiguous_registration"] == 1
    statuses = {agent["title"]: agent["inventory_status"] for agent in inventory["agents"]}
    assert statuses == {
        "shadow": "shadow",
        "sanctioned": "sanctioned",
        "unknown": "no-inventory",
        "ambiguous": "shadow",
    }
    page = render_dashboard(inventory)
    assert "sanctioned: agent-2" in page and "(matched to different agents)" in page
    assert "have no inventory to reconcile against" in page


def test_autonomy_matrix_emphasizes_and_links_the_shadow_l4_quadrant():
    findings = [
        _finding("rogue", "r1", shadow=True, metadata={"autonomy": _autonomy(4)}),
        _finding("governed", "r2", shadow=False, metadata={"autonomy": _autonomy(5)}),
        _finding("chat", "r3", shadow=None, metadata={"autonomy": _autonomy(0)}),
        _finding("grant", "r4", kind=Kind.IAM_GRANT, shadow=True),
        _finding("malformed", "r5", shadow=True, metadata={"autonomy": {"floor": 9}}),
    ]
    inventory = build_inventory(_result(findings))
    rows = {row["label"]: row for row in inventory["autonomy"]["rows"]}
    assert rows["L4 High Autonomy"]["shadow"] == 1 and rows["L5 Fully Autonomous"]["sanctioned"] == 1
    assert rows["L0 Chatbot"]["no-inventory"] == 1
    # The grant is a kind the scale does not describe; an agent whose interval is malformed is unknown.
    assert rows["not applicable"]["shadow"] == 1 and rows["not applicable"]["tier"] is None
    assert (
        rows["not classified"]["shadow"] == 1
        and rows["not classified"]["autonomy_status"] == "not-classified"
    )
    assert inventory["autonomy"]["priority"] == 1 and inventory["autonomy"]["not_classified"] == 1
    page = render_dashboard(inventory)
    matrix = page[page.index("id='autonomy'") : page.index("id='priority'")]
    assert matrix.count("class='num priority'") == 2
    assert (
        "<a href='#priority'>1 · priority</a>" in matrix and "<a href='#priority'>0 · priority</a>" in matrix
    )
    priority = page[page.index("id='priority'") : page.index("id='registries'")]
    assert "rogue" in priority and "governed" not in priority and "chat" not in priority


def test_a_report_without_autonomy_reads_the_same_alone_and_merged(tmp_path):
    rogue = _finding(
        "rogue", "r1", capabilities=["tool-use", "code-exec"], tags=["mcp-auto-approve"], shadow=True
    )
    chat = _finding("chat", "r2", shadow=False, registry_match="chat-1")
    paths = []
    for name, finding in (("a.json", rogue), ("b.json", chat)):
        report = _result([finding], inventory_present=True).to_dict()
        # Written before autonomy tiers existed.
        assert all("autonomy" not in item["metadata"] for item in report["findings"])
        paths.append(str(_write(tmp_path / name, report)))
    result, page, alone = _dashboard(tmp_path, paths[0])
    assert result.exit_code == 0, result.output
    _, _, merged = _dashboard(tmp_path, *paths)
    assert alone["autonomy"]["priority"] == merged["autonomy"]["priority"] == 1
    assert [agent["autonomy"]["floor"] for agent in alone["agents"]] == [4]
    assert {agent["title"]: agent["autonomy"]["floor"] for agent in merged["agents"]} == {
        "rogue": 4,
        "chat": 0,
    }
    assert alone["autonomy"]["not_classified"] == merged["autonomy"]["not_classified"] == 0
    assert "rogue" in page[page.index("id='priority'") : page.index("id='registries'")]


def test_report_result_keeps_the_interval_of_a_current_report(tmp_path):
    repo = {".mcp.json": MCP, "crew.py": AGENT}
    raw = json.loads(_report(tmp_path, "laptop", repo).read_text())
    result = report_result("laptop.json", raw)
    blocks = {finding.id: finding.metadata.get("autonomy") for finding in result.findings}
    assert blocks == {item["id"]: item["metadata"].get("autonomy") for item in raw["findings"]}
    assert any(block is not None for block in blocks.values())
    # A registered finding keeps its declared level and the understated tag, as a merge keeps them.
    registered = _finding(
        "ops", "r1", capabilities=["tool-use", "code-exec"], shadow=False, registry_match="ops"
    )
    apply_autonomy(registered, InventoryEntry(agent_id="ops", autonomy_level=0))
    assert UNDERSTATED_TAG in registered.tags
    report = _result([registered], inventory_present=True).to_dict()
    [read] = report_result("r.json", report).findings
    [merged] = merge_reports([("r.json", report)]).findings
    assert (
        read.metadata["autonomy"]
        == merged.metadata["autonomy"]
        == report["findings"][0]["metadata"]["autonomy"]
    )
    assert (
        read.metadata["autonomy"]["declared"] == 0
        and UNDERSTATED_TAG in read.tags
        and UNDERSTATED_TAG in merged.tags
    )


def test_an_unclassified_ai_system_is_unknown_not_absent():
    findings = [
        _finding("rogue", "r1", shadow=True),
        _finding("grant", "r2", kind=Kind.IAM_GRANT, shadow=True),
    ]
    inventory = build_inventory(_result(findings))
    assert {agent["title"]: agent["autonomy_status"] for agent in inventory["agents"]} == {
        "rogue": "not-classified",
        "grant": "not-applicable",
    }
    assert inventory["autonomy"]["priority"] == 0 and inventory["autonomy"]["not_classified"] == 1
    assert [row["autonomy_status"] for row in inventory["autonomy"]["rows"]][-3:] == list(AUTONOMY_STATUSES)
    page = render_dashboard(inventory)
    priority = page[page.index("id='priority'") : page.index("id='registries'")]
    assert "carry no valid autonomy interval" in priority and "unknown, not absent" in priority
    assert "No shadow AI system in these reports" not in priority
    assert "<b>1</b>autonomy not classified (unknown)" in page
    assert "<span class='warn'>not classified</span>" in page
    # Without any unknown, the empty quadrant says so plainly.
    known = build_inventory(
        _result([_finding("chat", "r3", shadow=True, metadata={"autonomy": _autonomy(0)})])
    )
    assert "No shadow AI system in these reports has an autonomy floor" in render_dashboard(known)


# ------------------------------------------------------------------ registries and references


def _record(record_id: str, resource: str, **overrides: Any) -> dict[str, Any]:
    record = {
        "schema": RECORD_SCHEMA,
        "registry": "aws-agent-registry",
        "registry_id": "arn:aws:bedrock-agentcore:us-east-1:111122223333:registry/main",
        "record_id": record_id,
        "status": "approved",
        "descriptor_type": "agent",
        "bindings": [
            {"resource": resource, "provider": "aws", "account": "111122223333", "coverage": "in-scope"}
        ],
        "listing_complete": True,
        "approval_mode": "manual",
    }
    record.update(overrides)
    return record


def test_registry_reconciliation_is_summarized_per_registry():
    cloud = {"surface": Surface.CLOUD, "connector": "cloud.aws", "provider": "aws", "account": "111122223333"}
    findings = [
        _finding("record-1", "rec-1", metadata={RECORD_KEY: _record("rec-1", "agent-1")}, **cloud),
        _finding(
            "record-2",
            "rec-2",
            metadata={RECORD_KEY: _record("rec-2", "gone", approval_mode="auto")},
            **cloud,
        ),
        _finding(
            "record-3", "rec-3", metadata={RECORD_KEY: _record("rec-3", "agent-3", status="pending")}, **cloud
        ),
        # An AWS registry binds AgentCore runtimes and gateways only (BINDABLE_RESOURCE_TYPES).
        _finding("observed", "agent-1", resource_type="agentcore-runtime", **cloud),
        _finding("unlisted", "agent-9", resource_type="agentcore-runtime", **cloud),
        _finding("broken", "rec-x", metadata={RECORD_KEY: {"schema": "other"}}, **cloud),
    ]
    reconcile_registries(findings)
    inventory = build_inventory(_result(findings))
    [row] = inventory["registries"]["registries"]
    assert row["records"] == 3
    assert row["registered-and-observed"] == 1 and row["registered-not-observed"] == 2
    assert row["observed-not-registered"] == 1
    assert (row["approved"], row["not_approved"], row["auto_approved"]) == (2, 1, 1)
    assert row["listing_complete"] is True
    assert inventory["registries"]["malformed_records"] == 1
    record = next(agent for agent in inventory["agents"] if agent["title"] == "record-1")
    assert record["registry"]["bindings"] == [
        {
            "resource": "agent-1",
            "provider": "aws",
            "account": "111122223333",
            "region": None,
            "coverage": "in-scope",
        }
    ]
    assert record["registry_reconciliation"]["status"] == "registered-and-observed"
    broken = next(agent for agent in inventory["agents"] if agent["title"] == "broken")
    assert broken["registry"] == {"malformed": True}
    page = render_dashboard(inventory)
    assert "Registered, not observed" in page and "1 registry record(s) were malformed" in page


def test_threat_and_control_counts_carry_titles_and_never_verdicts(tmp_path):
    report = _report(tmp_path, "laptop", {".mcp.json": MCP, "crew.py": AGENT})
    result, page, inventory = _dashboard(tmp_path, str(report))
    assert result.exit_code == 0, result.output
    threats, controls = inventory["references"]["threats"], inventory["references"]["controls"]
    assert threats and controls and all(row["title"] and row["count"] > 0 for row in threats + controls)
    assert inventory["references"]["note"] == "Evidence references, not compliance determinations."
    assert "Evidence references, not compliance determinations." in page
    words = set(re.findall(r"[a-z]+", re.sub(r"<[^>]+>", " ", page).lower()))
    assert not words & {
        "compliant",
        "certified",
        "certification",
        "pass",
        "passed",
        "fail",
        "failed",
        "score",
    }


# ------------------------------------------------------------------ inventory.json


def test_inventory_json_excludes_credentials_and_evidence(tmp_path):
    canary = "sk-proj-" + "Zq7Wv3Kp9Lm2Nx5B" * 3
    report = _report(tmp_path, "laptop", {"crew.py": AGENT, "settings.py": f'OPENAI_API_KEY = "{canary}"\n'})
    assert any(f["kind"] == "secret" for f in json.loads(report.read_text())["findings"])
    result, page, inventory = _dashboard(tmp_path, str(report))
    assert result.exit_code == 0, result.output
    document = (tmp_path / "inventory.json").read_text()
    assert inventory["schema"] == INVENTORY_SCHEMA and inventory["generator"]["name"] == "ShadowScan"
    assert canary not in document and canary not in page and canary[:20] not in document
    assert inventory["counts"]["excluded_credentials"] >= 1
    assert all(agent["kind"] not in {"secret", "token"} for agent in inventory["agents"])
    for key in ("snippet", "evidence", "permissions", "attributes"):
        assert f'"{key}"' not in document
    assert inventory["counts"]["ai_systems"] == len(inventory["agents"])
    assert document == render_inventory_json(json.loads(document))


def test_outputs_are_deterministic_private_and_never_follow_links(tmp_path):
    a = _report(tmp_path, "laptop-a", {".mcp.json": MCP})
    b = _report(tmp_path, "laptop-b", {"crew.py": AGENT})
    first, page, _ = _dashboard(tmp_path, str(a), str(b))
    assert first.exit_code == 0, first.output
    document = (tmp_path / "inventory.json").read_text()
    again, page_again, _ = _dashboard(tmp_path, str(a), str(b))
    assert page_again == page and (tmp_path / "inventory.json").read_text() == document
    for name in ("dashboard.html", "inventory.json"):
        assert (tmp_path / name).stat().st_mode & 0o777 == 0o600
    target = tmp_path / "keep.txt"
    target.write_text("retain")
    link = tmp_path / "link.html"
    link.symlink_to(target)
    refused = CliRunner().invoke(main, ["dashboard", str(a), "-o", str(link)])
    assert refused.exit_code == 1 and "could not write dashboard" in refused.output
    assert target.read_text() == "retain"
    same = CliRunner().invoke(
        main, ["dashboard", str(a), "-o", str(tmp_path / "x"), "--inventory-json", str(tmp_path / "x")]
    )
    assert same.exit_code == 1


def test_a_render_failure_keeps_the_previous_files(tmp_path, monkeypatch):
    report = _report(tmp_path, "laptop", {"crew.py": AGENT})
    page = tmp_path / "dashboard.html"
    page.write_text("previous")

    def broken(inventory):
        raise ValueError("synthetic")

    monkeypatch.setattr("shadowscan.cli.render_dashboard", broken)
    result = CliRunner().invoke(main, ["dashboard", str(report), "-o", str(page)])
    assert result.exit_code == 1 and "could not render dashboard" in result.output
    assert page.read_text() == "previous"


# ------------------------------------------------------------------ drift and history


def test_baseline_drift_is_counted_when_comparable(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".mcp.json").write_text(MCP)
    baseline = tmp_path / "baseline.json"
    assert (
        CliRunner().invoke(main, ["code", str(repo), "--format", "json", "-o", str(baseline)]).exit_code == 0
    )
    (repo / "crew.py").write_text(AGENT)
    current = tmp_path / "current.json"
    assert (
        CliRunner().invoke(main, ["code", str(repo), "--format", "json", "-o", str(current)]).exit_code == 0
    )
    result, page, inventory = _dashboard(tmp_path, str(current), "--baseline", str(baseline))
    assert result.exit_code == 0, result.output
    drift = inventory["drift"]
    assert drift["comparable"] is True and drift["counts"]["new"] >= 1 and drift["counts"]["unknown"] == 0
    assert drift["classes"]["inventory"] == drift["counts"]["new"] + drift["counts"]["resolved"]
    assert "New AI systems since the baseline" in page and "Not comparable with the baseline" not in page
    assert "BASELINE NOT COMPARABLE" not in page


def test_an_incomparable_baseline_leaves_missing_findings_unknown(tmp_path):
    baseline = _report(tmp_path, "before", {".mcp.json": MCP, "crew.py": AGENT})
    current = _report(tmp_path, "after", {"crew.py": AGENT})
    result, page, inventory = _dashboard(tmp_path, str(current), "--baseline", str(baseline))
    assert result.exit_code == 3
    drift = inventory["drift"]
    assert drift["comparable"] is False and drift["reasons"]
    assert drift["resolved"] == [] and drift["counts"]["resolved"] == 0 and drift["counts"]["unknown"] >= 1
    assert drift["adverse"]["coverage"] is True
    assert "Not comparable with the baseline" in page and "unknown, not resolved" in page
    assert inventory["complete"] is True
    # The exit code is 3 although every input is complete, so the page opens with its own banner.
    assert "INCOMPLETE SCAN" not in page
    assert page.index("BASELINE NOT COMPARABLE") < page.index("id='coverage'")
    # Coverage drift counts the comparison's reasons, never findings.
    section = page[page.index("id='drift'") : page.index("id='agents'")]
    assert f"<td class='num'>{len(drift['reasons'])} reason(s)</td>" in section


def _history_report(findings: list[Finding], started: str, **overrides: Any) -> dict[str, Any]:
    return _result(findings, started=started, **overrides).to_dict()


def test_history_orders_by_start_time_and_shows_gaps(tmp_path):
    history = tmp_path / "history"
    history.mkdir()
    agents = [_finding("a", "r1", shadow=True), _finding("b", "r2", shadow=False)]
    later = [*agents, _finding("c", "r3", shadow=True, metadata={"autonomy": _autonomy(4)})]
    # File names sort against time; the series follows started_at.
    _write(history / "a.json", _history_report(later, "2026-10-08T00:00:00+00:00", inventory_present=True))
    _write(history / "b.json", _history_report(agents, "2026-10-01T00:00:00+00:00", inventory_present=True))
    _write(
        history / "c.json",
        _history_report(later, "2026-10-15T00:00:00+00:00", fingerprint="b" * 64, inventory_present=True),
    )
    undated = _history_report(agents, "2026-10-01T00:00:00+00:00")
    undated["started_at"] = "last week"
    _write(history / "d.json", undated)
    (history / "notes.txt").write_text("ignored")
    summary = load_history(history)
    assert [point["name"] for point in summary["points"]] == ["b.json", "a.json", "c.json"]
    assert summary["undated"] == ["d.json"] and summary["reports"] == 4 and summary["omitted"] == 0
    first, second = summary["pairs"]
    assert first["comparable"] is True and first["counts"]["new"] == 1 and first["classes"]["inventory"] == 1
    assert second["comparable"] is False and second["reasons"] >= 1
    assert second["counts"] is None and second["classes"] is None
    assert [point["shadow"] for point in summary["points"]] == [1, 2, 2]
    assert [point["l4_plus"] for point in summary["points"]] == [None, 1, 1]
    report = _report(tmp_path, "laptop", {"crew.py": AGENT})
    result, page, inventory = _dashboard(tmp_path, str(report), "--history", str(history))
    assert result.exit_code == 0, result.output
    assert inventory["history"]["pairs"] == summary["pairs"]
    section = page[page.index("id='history'") : page.index("id='agents'")]
    assert "not comparable: 1 reason(s)" in section and "not classified" in section
    assert section.count("<polyline") == 1 and section.count("<circle") == 3
    assert "Not placed in the series" in section and "d.json" in section


def test_history_counts_match_compare_reports():
    before = [_finding("a", "r1", shadow=True), _finding("b", "r2", owner="team"), _finding("d", "r4")]
    after = [
        _finding("a", "r1", shadow=True, capabilities=["code-exec"]),
        _finding("b", "r2"),
        _finding("c", "r3", tags=["mcp-auto-approve"]),
    ]
    early, late = "2026-09-01T00:00:00+00:00", "2026-10-01T00:00:00+00:00"
    errors = [ScanStats(connector="code.filesystem", started_at=late, errors=["timed out"])]
    local = _finding("caller", "gateway:caller", metadata={"identity_scope": "run"})
    pairs = [
        (_history_report(before, early), _history_report(after, late)),
        (_history_report(before, early), _history_report(after, late, fingerprint="b" * 64)),
        (_history_report(before, early), _history_report(after, late, stats=errors)),
        (_history_report(before, early), _history_report([*after, local], late)),
        (_history_report(after, late), _history_report(before, early)),
    ]
    moment = parse_instant("2026-10-02T00:00:00+00:00")
    for old, new in pairs:
        for age in (None, 10):
            full = compare_reports(old, new, max_baseline_age_days=age, now=moment)
            counted = drift_counts(old, new, max_baseline_age_days=age, now=moment)
            assert counted["comparable"] == full["comparable"] and counted["reasons"] == full["reasons"]
            assert counted["counts"] == {
                key: len(full[key]) for key in ("new", "resolved", "unknown", "changed")
            }
            assert counted["drift_summary"] == full["drift_summary"] and counted["adverse"] == full["adverse"]
    first = drift_counts(*pairs[0], now=moment)
    assert first["comparable"] and first["counts"] == {"new": 1, "resolved": 1, "unknown": 0, "changed": 2}
    assert first["adverse"]["capability"] and first["adverse"]["governance"]
    with pytest.raises(ValueError):
        drift_counts([], {})  # type: ignore[arg-type]


def _history_directory(directory: Path, reports: int, findings: int) -> None:
    """``reports`` weekly copies of one report of ``findings`` MCP servers, written without a model pass."""
    directory.mkdir()
    report = _history_report(
        [_finding("MCP", "mcp", kind=Kind.MCP_SERVER, shadow=True)], "2026-01-01T00:00:00+00:00"
    )
    [template] = report["findings"]
    report["findings"] = [
        {**template, "id": f"ss-{n:016x}", "resource": f"endpoint:host-{n % 50}/mcp/{n}"}
        for n in range(findings)
    ]
    report["summary"].update(total=findings, by_surface={"code": findings}, by_kind={"mcp-server": findings})
    for week in range(reports):
        report["started_at"] = f"2026-{1 + week // 28:02d}-{1 + week % 28:02d}T00:00:00+00:00"
        _write(directory / f"w{week:03d}.json", report)


def test_history_time_grows_linearly_within_the_documented_budget(tmp_path):
    # docs/operations/dashboard.md documents the budget; SHADOWSCAN_HISTORY_FINDINGS raises the size.
    count = int(os.environ.get("SHADOWSCAN_HISTORY_FINDINGS", "5000"))
    timings = []
    for size in (count // 4, count):
        directory = tmp_path / f"history-{size}"
        _history_directory(directory, 10, size)
        started = time.perf_counter()
        summary = load_history(directory)
        timings.append(time.perf_counter() - started)
        assert len(summary["pairs"]) == 9 and all(pair["comparable"] for pair in summary["pairs"])
        assert all(pair["counts"] == {"new": 0, "resolved": 0, "changed": 0} for pair in summary["pairs"])
    quarter, elapsed = timings
    assert elapsed < 8 * quarter + 2.0, f"{count} findings took {elapsed:.1f}s, a quarter {quarter:.1f}s"
    budget = 10.0 + 120.0 * 10 * count / 1_000_000
    assert elapsed < budget, f"10 reports of {count} findings took {elapsed:.1f}s (budget {budget:.0f}s)"


def test_history_without_inventory_reports_unknown_shadow(tmp_path):
    history = tmp_path / "history"
    history.mkdir()
    _write(history / "a.json", _history_report([_finding("a", "r1")], "2026-10-01T00:00:00+00:00"))
    [point] = load_history(history)["points"]
    assert point["shadow"] is None and point["ai_systems"] == 1


def test_history_is_capped_with_a_visible_note(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard_module, "MAX_HISTORY", 2)
    monkeypatch.setattr(page_module, "MAX_HISTORY", 2)
    history = tmp_path / "history"
    history.mkdir()
    for day in range(1, 5):
        _write(history / f"{day}.json", _history_report([_finding()], f"2026-10-0{day}T00:00:00+00:00"))
    summary = load_history(history)
    assert [point["name"] for point in summary["points"]] == ["3.json", "4.json"]
    assert summary["omitted"] == 2 and len(summary["pairs"]) == 1
    inventory = build_inventory(_result([_finding()]), history=summary)
    assert "2 older report(s) left out" in render_dashboard(inventory)


def test_history_refuses_links_and_files_changed_between_reads(tmp_path, monkeypatch):
    history = tmp_path / "history"
    history.mkdir()
    real = _write(tmp_path / "real.json", _history_report([_finding()], "2026-10-01T00:00:00+00:00"))
    (history / "link.json").symlink_to(real)
    report = _report(tmp_path, "laptop", {"crew.py": AGENT})
    result = CliRunner().invoke(
        main, ["dashboard", str(report), "-o", str(tmp_path / "d.html"), "--history", str(history)]
    )
    assert result.exit_code == 1 and "symbolic link" in result.output
    (history / "link.json").unlink()
    _write(history / "a.json", _history_report([_finding()], "2026-10-01T00:00:00+00:00"))
    calls: list[Path] = []

    def changing(path, *, expected_sha256=None):
        loaded = load_report_with_digest(path, expected_sha256=expected_sha256)
        calls.append(Path(path))
        if len(calls) == 1:
            Path(path).write_text(Path(path).read_text() + "\n")
        return loaded

    monkeypatch.setattr(dashboard_module, "load_report_with_digest", changing)
    result = CliRunner().invoke(
        main, ["dashboard", str(report), "-o", str(tmp_path / "d.html"), "--history", str(history)]
    )
    assert result.exit_code == 1 and "changed while it was being read" in result.output
    (history / "b.json").write_text("{not json")
    monkeypatch.undo()
    result = CliRunner().invoke(
        main, ["dashboard", str(report), "-o", str(tmp_path / "d.html"), "--history", str(history)]
    )
    assert result.exit_code == 1 and "could not read a history report" in result.output


# ------------------------------------------------------------------ page structure


def test_tables_are_accessible_and_controls_are_buttons(tmp_path):
    report = _report(tmp_path, "laptop", {".mcp.json": MCP, "crew.py": AGENT})
    result, page, _ = _dashboard(tmp_path, str(report))
    assert result.exit_code == 0, result.output
    parsed = _parse(page)
    assert parsed.count("table") == page.count("<caption>") > 5
    assert all(attrs.get("type") == "button" for tag, attrs in parsed.tags if tag == "button")
    assert all("scope" in attrs for tag, attrs in parsed.tags if tag == "th")
    sortable = [attrs for tag, attrs in parsed.tags if tag == "th" and "data-k" in attrs]
    assert sortable and all(attrs["aria-sort"] in {"none", "descending"} for attrs in sortable)
    # Controls appear only when the script runs; every row is in the page without it.
    assert any(
        tag == "div" and attrs.get("id") == "agent-controls" and "hidden" in attrs
        for tag, attrs in parsed.tags
    )
    # The controls row is a flex box: without this rule the hidden attribute would not hide it.
    assert "[hidden]{display:none!important}" in page


def test_long_agent_lists_are_truncated_with_a_note(tmp_path, monkeypatch):
    monkeypatch.setattr(page_module, "MAX_AGENT_ROWS", 2)
    findings = [_finding(f"agent {n}", f"r{n}") for n in range(5)]
    inventory = build_inventory(_result(findings))
    page = render_dashboard(inventory)
    assert len(inventory["agents"]) == 5
    assert "Showing the 2 highest-risk of 5 AI systems" in page
    assert page.count("<tr class='agent'") == 2


def test_history_directory_edge_cases_fail_closed_or_stay_visible(tmp_path, monkeypatch):
    report = tmp_path / "report.json"
    _write(report, _history_report([_finding()], "2026-10-01T00:00:00+00:00"))
    with pytest.raises(dashboard_module.HistoryError, match="must be a directory"):
        load_history(report)
    history = tmp_path / "history"
    history.mkdir()
    (history / "nested.json").mkdir()
    with pytest.raises(dashboard_module.HistoryError, match="not a regular file"):
        load_history(history)
    (history / "nested.json").rmdir()
    link = tmp_path / "linked"
    link.symlink_to(history, target_is_directory=True)
    with pytest.raises(dashboard_module.HistoryError, match="symbolic links"):
        load_history(link)
    for day in (1, 2):
        _write(history / f"{day}.json", _history_report([_finding()], f"2026-10-0{day}T00:00:00+00:00"))
    monkeypatch.setattr(dashboard_module, "MAX_HISTORY_FILES", 1)
    with pytest.raises(dashboard_module.HistoryError, match="more than 1 reports"):
        load_history(history)
    monkeypatch.undo()

    def broken(*args, **kwargs):
        raise ValueError("synthetic")

    monkeypatch.setattr(dashboard_module, "drift_counts", broken)
    [pair] = load_history(history)["pairs"]
    assert pair["comparable"] is False and pair["reasons"] == 1 and pair["counts"] is None
    monkeypatch.undo()
    undated = tmp_path / "undated"
    undated.mkdir()
    data = _history_report([_finding()], "2026-10-01T00:00:00+00:00")
    data["started_at"] = None
    _write(undated / "a.json", data)
    summary = load_history(undated)
    assert summary["points"] == [] and summary["undated"] == ["a.json"]
    page = render_dashboard(build_inventory(_result([_finding()]), history=summary))
    assert "No dated reports in the history directory." in page


def test_long_priority_and_drift_lists_and_repeated_runs(monkeypatch):
    monkeypatch.setattr(page_module, "MAX_PRIORITY_ROWS", 1)
    monkeypatch.setattr(page_module, "MAX_DRIFT_ROWS", 1)
    findings = [
        _finding(f"rogue {n}", f"r{n}", shadow=True, metadata={"autonomy": _autonomy(5)}) for n in range(3)
    ]
    stats = [
        ScanStats(connector="code.filesystem", started_at="2026-10-01T00:00:00+00:00", cached=True),
        ScanStats(connector="code.filesystem", started_at="2026-10-01T00:00:00+00:00", errors=["timed out"]),
        ScanStats(connector="code.filesystem", started_at="2026-10-01T00:00:00+00:00"),
    ]
    current = _result(findings, stats=stats)
    baseline = _result(
        [], stats=[ScanStats(connector="code.filesystem", started_at="2026-09-01T00:00:00+00:00")]
    )
    baseline.started_at = baseline.finished_at = None  # type: ignore[assignment]
    inventory = build_inventory(current, baseline=baseline.to_dict())
    # Of one source's runs of a connector, the least complete one shows.
    assert inventory["sources"][0]["coverage"] == {"code.filesystem": "incomplete"}
    assert inventory["drift"]["baseline_started_at"] is None and len(inventory["drift"]["new"]) == 3
    page = render_dashboard(inventory)
    priority = page[page.index("id='priority'") : page.index("id='registries'")]
    drift = page[page.index("id='drift'") : page.index("id='agents'")]
    assert "2 more in inventory.json." in priority and "2 more in inventory.json." in drift
    assert "Baseline started" not in drift
    with pytest.raises(ValueError, match="UTC offset"):
        build_inventory(current, as_of="2026-10-01")


def test_overview_counts_show_missing_values_and_cap_long_tables(monkeypatch):
    monkeypatch.setattr(page_module, "MAX_VALUE_ROWS", 2)
    findings = [
        _finding(f"agent {n}", f"r{n}", owner=f"team-{n}" if n else None, provider="aws" if n % 2 else None)
        for n in range(4)
    ]
    findings.append(_finding("key", "r-key", kind=Kind.SECRET))
    inventory = build_inventory(_result(findings))
    counts = inventory["counts"]
    assert counts["ai_systems"] == 4 and counts["excluded_credentials"] == 1 and counts["unowned"] == 1
    # Ties keep recorded values first; a missing value is listed as null, never dropped.
    assert counts["by_provider"] == [{"value": "aws", "count": 2}, {"value": None, "count": 2}]
    assert [(row["value"], row["count"]) for row in counts["by_risk_level"]] == [
        ("critical", 0),
        ("high", 0),
        ("medium", 0),
        ("low", 0),
        ("info", 4),
    ]
    page = render_dashboard(inventory)
    overview = page[page.index("id='overview'") : page.index("id='autonomy'")]
    assert "<b>4</b>AI systems" in overview and "<b>1</b>credential findings left out" in overview
    assert "not recorded" in overview and "2 more values in inventory.json" in overview


def _large_result(count: int, monkeypatch: pytest.MonkeyPatch) -> ScanResult:
    """A synthetic fleet whose findings are marked clean, as loading a report leaves them.

    A full sanitizer pass per finding would dominate the test's run time. The markers are taken
    under the redaction policy in force, so the timed run still checks every finding against it.
    """
    from shadowscan import models

    token = models.policy_token()
    with monkeypatch.context() as patch:
        patch.setattr(Finding, "sanitize", lambda self: None)
        patch.setattr(models, "policy_token", lambda: token)
        findings = [
            _finding(
                f"MCP server {n}",
                f"endpoint:host-{n % 500}/mcp/{n}",
                surface=Surface.ENDPOINT,
                connector="endpoint.mcp",
                kind=Kind.MCP_SERVER if n % 3 else Kind.AGENT,
                provider="workstation",
                account=f"host-{n % 500}",
                owner=None if n % 4 else f"team-{n % 7}",
                capabilities=["tool-use", "code-exec"] if n % 2 else ["tool-use"],
                shadow=bool(n % 2),
                metadata={"autonomy": _autonomy(n % 6)},
            )
            for n in range(count)
        ]
        result = _result(findings)
        for finding in findings:
            marker = models._clean_state(finding._digest_state(), bounded=True)
            object.__setattr__(finding, "_clean_digest", marker)
    return result


def _render(result: ScanResult) -> tuple[float, dict[str, Any], str, str]:
    started = time.perf_counter()
    inventory = build_inventory(result, name="fleet.json")
    page = render_dashboard(inventory)
    document = render_inventory_json(inventory)
    return time.perf_counter() - started, inventory, page, document


def test_a_large_fleet_renders_within_the_documented_budget(monkeypatch):
    # docs/operations/dashboard.md documents the budget; set SHADOWSCAN_DASHBOARD_FINDINGS=100000
    # to run the full-size case. The default keeps CI time reasonable.
    count = int(os.environ.get("SHADOWSCAN_DASHBOARD_FINDINGS", "20000"))
    quarter, *_ = _render(_large_result(count // 4, monkeypatch))
    elapsed, inventory, page, document = _render(_large_result(count, monkeypatch))
    assert len(inventory["agents"]) == count and page.count("<tr class='agent'") == min(count, 5_000)
    assert len(document) > count
    # Linear: four times the findings take about four times as long, where a step that grows with
    # the square of the input would take sixteen. Coverage tracing slows both runs alike.
    assert elapsed < 8 * quarter + 2.0, f"{count} findings took {elapsed:.1f}s, a quarter {quarter:.1f}s"
    # A ceiling generous enough for coverage tracing on a shared CI runner.
    budget = 150.0 * count / 100_000 + 30.0
    assert elapsed < budget, f"{count} findings took {elapsed:.1f}s (budget {budget:.0f}s)"
