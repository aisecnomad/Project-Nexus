"""CSV carries a completeness signal; saved CSV/HTML reports neutralize terminal controls."""

from __future__ import annotations

import csv
import io
from pathlib import Path

import pytest
from click.testing import CliRunner

from shadowscan.cli import _emit, main
from shadowscan.models import ScanResult, ScanStats, now_iso
from shadowscan.reporters.csv_ import COLUMNS, render_csv
from shadowscan.reporters.html import render_html

CONTROLS = "name\x1b]0;pwned\x07\x1b[2J\x9b2J\x7f\x08‮reordered"


def _stats(**overrides) -> ScanStats:
    fields = dict(connector="code.filesystem", started_at=now_iso(), finished_at=now_iso())
    fields.update(overrides)
    return ScanStats(**fields)


def _rows(text: str) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(text)))


def test_incomplete_csv_is_not_identical_to_a_complete_empty_csv():
    complete = render_csv(ScanResult(stats=[_stats()]))
    incomplete = render_csv(
        ScanResult(
            stats=[_stats(skipped=True, incomplete=True, errors=["code.filesystem: path not found: x"])]
        )
    )

    assert incomplete != complete
    assert _rows(complete) == []
    # The header stays the first line, so DictReader consumers keep working,
    # and the status row is the first record: an empty-looking file is impossible.
    assert incomplete.splitlines()[0].split(",") == COLUMNS
    rows = _rows(incomplete)
    assert len(rows) == 1
    assert rows[0]["id"] == "SCAN-INCOMPLETE"
    assert rows[0]["kind"] == "scan-status"
    assert rows[0]["title"].startswith("INCOMPLETE SCAN")
    assert "code.filesystem" in rows[0]["connector"]
    assert rows[0]["risk_level"] == "" and rows[0]["risk_score"] == ""


def test_incomplete_csv_with_findings_keeps_findings_after_the_status_row(make_finding):
    result = ScanResult(
        findings=[make_finding(title="Kept")],
        stats=[
            _stats(),
            _stats(connector="identity.okta", incomplete=True, errors=["identity.okta: denied"]),
        ],
    )

    rows = _rows(render_csv(result))

    assert [row["id"] for row in rows][0] == "SCAN-INCOMPLETE"
    assert [row["title"] for row in rows[1:]] == ["Kept"]
    # Only connectors that did not complete are named.
    assert rows[0]["connector"] == "identity.okta"


def test_complete_csv_has_no_status_row(make_finding):
    rows = _rows(render_csv(ScanResult(findings=[make_finding()], stats=[_stats()])))
    assert [row["kind"] for row in rows] == ["agent"]


def test_incomplete_status_row_never_echoes_diagnostics():
    secret = "sk-proj-" + "c" * 40
    result = ScanResult(stats=[_stats(incomplete=True, errors=[f"failed with token {secret}"])])
    assert secret not in render_csv(result)


@pytest.mark.parametrize("render", [render_csv, render_html])
def test_saved_report_neutralizes_terminal_controls(make_finding, render):
    result = ScanResult(
        findings=[make_finding(title=CONTROLS, owner=CONTROLS, resource=CONTROLS)],
        stats=[_stats(incomplete=True, errors=[CONTROLS])],
    )

    text = render(result)

    for control in ("\x1b", "\x07", "\x9b", "\x7f", "\x08", "‮"):
        assert control not in text, repr(control)
    assert "\\u001b" in text and "\\u0007" in text and "\\u202e" in text


def test_csv_keeps_tab_and_newline_cells_as_before(make_finding):
    # Whitespace is data, not a terminal command; formula guards depend on it.
    rows = _rows(render_csv(ScanResult(findings=[make_finding(title="a\tb\nc")], stats=[_stats()])))
    assert rows[0]["title"] == "a\tb\nc"


@pytest.mark.parametrize("fmt", ["csv", "html"])
def test_file_and_stdout_outputs_both_hide_controls(make_finding, fmt: str, tmp_path: Path, monkeypatch):
    result = ScanResult(findings=[make_finding(title=CONTROLS)], stats=[_stats()])
    emitted: list[str] = []
    monkeypatch.setattr("shadowscan.cli.click.echo", emitted.append)
    _emit(result, fmt, None, verbose=False, max_rows=None)
    destination = tmp_path / f"report.{fmt}"
    _emit(result, fmt, str(destination), verbose=False, max_rows=None)
    saved = destination.read_text(encoding="utf-8")
    for text in (emitted[0], saved):
        assert all(control not in text for control in ("\x1b", "\x07", "\x9b", "‮"))
        assert "\\u001b" in text


def test_cli_incomplete_scan_csv_is_not_empty_looking(tmp_path: Path):
    config = tmp_path / "scan.yaml"
    config.write_text("connectors:\n  - name: code.filesystem\n    path: " + str(tmp_path / "gone") + "\n")
    out = tmp_path / "incomplete.csv"

    result = CliRunner().invoke(main, ["scan", "-c", str(config), "-f", "csv", "-o", str(out)])

    assert result.exit_code == 3, result.output
    rows = _rows(out.read_text(encoding="utf-8"))
    assert [row["id"] for row in rows] == ["SCAN-INCOMPLETE"]
