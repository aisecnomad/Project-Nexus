"""Reports preserve privilege evidence and distinguish a supplied empty inventory."""

from __future__ import annotations

import csv
import io

import pytest
from rich.console import Console

from shadowscan.models import ScanResult, ScanStats
from shadowscan.reporters.csv_ import render_csv
from shadowscan.reporters.html import render_html
from shadowscan.reporters.markdown import render_markdown
from shadowscan.reporters.table import print_table


def _stats() -> list[ScanStats]:
    return [ScanStats(connector="identity.entra", started_at="2026-10-09T00:00:00Z")]


def _table(result: ScanResult) -> str:
    stream = io.StringIO()
    print_table(result, console=Console(file=stream, width=200))
    return stream.getvalue()


def test_csv_keeps_privileged_permissions_beyond_the_thirtieth(make_finding):
    permissions = [f"permission-{number:02d}" for number in range(30)]
    permissions.append("Directory.ReadWrite.All")
    finding = make_finding(permissions=permissions)
    result = ScanResult(findings=[finding], stats=_stats())

    rows = list(csv.DictReader(io.StringIO(render_csv(result))))

    assert result.complete
    assert len(rows) == 1
    assert rows[0]["permissions"].split("|") == permissions


def test_csv_retained_permission_cells_still_neutralize_formulas(make_finding):
    permissions = [f"permission-{number:02d}" for number in range(30)]
    permissions.extend(["Directory.ReadWrite.All", "=SUM(1)", "@SUM(2)"])
    finding = make_finding(permissions=permissions)
    result = ScanResult(findings=[finding], stats=_stats())

    row = next(csv.DictReader(io.StringIO(render_csv(result))))

    assert row["permissions"].split("|") == [*permissions[:31], "'=SUM(1)", "'@SUM(2)"]


def test_table_shows_shadow_findings_with_an_empty_inventory(make_finding):
    finding = make_finding(shadow=True)
    result = ScanResult(findings=[finding], stats=_stats(), inventory_size=0)

    output = _table(result)

    assert "1 shadow" in output
    assert "inventory: 0 registered agents" in output
    assert " Shadow " in output
    assert "SHADOW" in output


def test_table_without_inventory_does_not_claim_shadow_status(make_finding):
    result = ScanResult(findings=[make_finding(shadow=None)], stats=_stats())

    output = _table(result)

    assert "registered agents" not in output
    assert "SHADOW" not in output
    assert " Shadow " not in output


@pytest.mark.parametrize("with_findings", [False, True])
def test_explicit_empty_inventory_remains_visible_even_without_findings(make_finding, with_findings):
    findings = [make_finding(shadow=True)] if with_findings else []
    result = ScanResult(findings=findings, stats=_stats(), inventory_size=0, inventory_present=True)

    output = _table(result)

    assert f"{len(findings)} shadow" in output
    assert "inventory: 0 registered agents" in output
    assert " Shadow " in output


def test_empty_scan_without_inventory_does_not_claim_reconciliation():
    output = _table(ScanResult(stats=_stats()))

    assert "registered agents" not in output
    assert "0 shadow" not in output
    assert " Shadow " not in output


@pytest.mark.parametrize("with_findings", [False, True])
@pytest.mark.parametrize("render", [render_markdown, render_html])
def test_saved_report_summaries_show_a_supplied_empty_inventory(make_finding, with_findings, render):
    findings = [make_finding(shadow=True)] if with_findings else []
    result = ScanResult(findings=findings, stats=_stats(), inventory_size=0, inventory_present=True)

    output = render(result)

    assert "registered agents" in output
    if render is render_html:
        assert f"<b class='shadow'>{len(findings)}</b>shadow (unregistered)" in output
        assert "<b>0</b>registered agents" in output
    else:
        assert f"**{len(findings)} shadow**" in output
        assert "inventory of 0 registered agents" in output


@pytest.mark.parametrize("render", [render_markdown, render_html])
def test_saved_report_summaries_keep_legacy_shadow_status(make_finding, render):
    result = ScanResult(findings=[make_finding(shadow=True)], stats=_stats(), inventory_size=0)

    output = render(result)

    assert "registered agents" in output


@pytest.mark.parametrize("with_findings", [False, True])
@pytest.mark.parametrize("render", [render_markdown, render_html])
def test_saved_report_summaries_do_not_claim_an_inventory_when_absent(make_finding, with_findings, render):
    findings = [make_finding(shadow=None)] if with_findings else []

    output = render(ScanResult(findings=findings, stats=_stats()))

    assert "registered agents" not in output
