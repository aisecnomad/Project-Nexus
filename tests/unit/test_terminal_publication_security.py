"""Repository and report data cannot issue terminal commands during display."""

from __future__ import annotations

import io
import json

import pytest
from click.testing import CliRunner
from rich.console import Console

from shadowscan.cli import _emit, main
from shadowscan.models import Evidence, Finding, Kind, Risk, RiskFactor, ScanResult, ScanStats, Surface
from shadowscan.reporters.table import print_table
from shadowscan.utils.output import encodable_text, terminal_text, write_private_text

PAYLOAD = "hostile\x1b]52;c;Y2xpcGJvYXJk\x07\x1b[2J\x9b2J\u202ereordered"


def _assert_no_payload_controls(output: str) -> None:
    # Rich may emit its own trusted color codes. Attacker-supplied OSC, erase,
    # C1 CSI, bell and bidi controls must never survive publication.
    assert "\x1b]52" not in output and "\x1b[2J" not in output
    assert all(control not in output for control in ("\x07", "\x9b", "\u202e"))
    assert "\\u001b" in output


def test_terminal_text_retains_printable_unicode_and_exposes_control_characters():
    assert terminal_text("Étude ✓ 🤖 日本") == "Étude ✓ 🤖 日本"
    assert terminal_text("one\r\ntwo\tthree") == "one\\u000d\\u000atwo\\u0009three"
    _assert_no_payload_controls(terminal_text(PAYLOAD))


def test_terminal_text_exposes_characters_that_show_nothing():
    # Zero-width characters, the byte-order mark and Unicode tag characters can hide
    # text or a message in an otherwise ordinary line.
    assert terminal_text("a​b‌c‍d⁠e﻿") == "a\\u200bb\\u200cc\\u200dd\\u2060e\\ufeff"
    assert terminal_text("tag\U000e0041\U000e007f") == "tag\\U000e0041\\U000e007f"
    assert terminal_text("x\ud800y\udfffz") == "x\\ud800y\\udfffz"
    # Letters, marks and emoji stay; a joiner between emoji is shown like any zero-width character.
    assert terminal_text("café 👩💻 日本語 ✓ ü") == "café 👩💻 日本語 ✓ ü"
    assert terminal_text("👩‍💻") == "👩\\u200d💻"


def _surrogate_result() -> ScanResult:
    finding = Finding(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.AGENT,
        title="x\ud800y",
        resource="repo\udc00",
        resource_type="repository",
        owner="o\udbff",
        evidence=[Evidence(signal="s", description="e\ud800", location="f.py:1")],
    )
    return ScanResult(findings=[finding], stats=[ScanStats(connector="code.filesystem", started_at="now")])


@pytest.mark.parametrize("fmt", ["json", "sarif", "csv", "markdown", "html", "table"])
def test_lone_surrogates_do_not_stop_a_report_written_to_a_file(tmp_path, fmt, monkeypatch):
    monkeypatch.setattr("shadowscan.cli.console", Console(file=io.StringIO(), width=200))
    monkeypatch.setattr("shadowscan.cli.err_console", Console(file=io.StringIO(), width=200))
    destination = tmp_path / f"report.{fmt}"
    _emit(_surrogate_result(), fmt, str(destination), verbose=False, max_rows=None)
    text = destination.read_text(encoding="utf-8")  # valid UTF-8: nothing was dropped or garbled
    assert text
    if fmt in {"csv", "markdown", "html"}:
        assert "x\\ud800y" in text


def test_a_lone_surrogate_is_written_as_a_visible_escape(tmp_path):
    destination = tmp_path / "report.txt"
    write_private_text(destination, "x\ud800y ✓")
    assert destination.read_text(encoding="utf-8") == "x\\ud800y ✓"
    assert encodable_text("x\udc00y") == "x\\udc00y"
    assert encodable_text("plain ✓ \U0001f916") == "plain ✓ \U0001f916"


@pytest.mark.parametrize("fmt", ["json", "sarif", "csv", "markdown", "html", "table"])
def test_lone_surrogates_do_not_stop_a_report_written_to_stdout(fmt, capsys):
    _emit(_surrogate_result(), fmt, None, verbose=False, max_rows=None)
    out = capsys.readouterr().out
    assert out
    if fmt in {"csv", "markdown", "html"}:
        assert "x\\ud800y" in out


def test_table_neutralizes_controls_in_findings_and_connector_diagnostics():
    finding = Finding(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.AGENT,
        title=PAYLOAD,
        resource=PAYLOAD,
        resource_type="repository",
        owner=PAYLOAD,
        frameworks=[PAYLOAD],
        capabilities=[PAYLOAD],
        registry_match=PAYLOAD,
        evidence=[Evidence(signal="example", description=PAYLOAD, location=PAYLOAD)],
        risk=Risk(factors=[RiskFactor(id="example", description=PAYLOAD, weight=1)]),
        metadata={"runtime_activity": {"status": PAYLOAD}},
    )
    result = ScanResult(
        findings=[finding],
        inventory_size=1,
        version=PAYLOAD,
        stats=[ScanStats(connector=PAYLOAD, started_at="now", errors=[PAYLOAD], warnings=[PAYLOAD])],
    )
    output = io.StringIO()
    print_table(result, console=Console(file=output, force_terminal=True, width=600), verbose=True)
    _assert_no_payload_controls(output.getvalue())
    # Publication escapes controls without changing the stored observation.
    assert finding.title == PAYLOAD and finding.resource == PAYLOAD


def test_diff_terminal_output_neutralizes_imported_title_and_resource(tmp_path):
    finding = Finding(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.AGENT,
        title=PAYLOAD,
        resource=PAYLOAD,
        resource_type="repository",
    )
    report = ScanResult(
        findings=[finding],
        stats=[ScanStats(connector="code.filesystem", started_at="now")],
        collection_scope={
            "schema": "shadowscan.collection-scope/v1",
            "comparable": True,
            "fingerprint": "a" * 64,
        },
    ).to_dict()
    after = tmp_path / "after.json"
    after.write_text(json.dumps(report))
    # A baseline without the finding; its summary must match its findings.
    report["findings"] = []
    report["summary"].update(total=0, by_surface={}, by_kind={}, by_risk_level={})
    before = tmp_path / "before.json"
    before.write_text(json.dumps(report))
    result = CliRunner().invoke(main, ["diff", str(before), str(after)])
    assert result.exit_code == 0, result.output
    _assert_no_payload_controls(result.output)


def test_output_notice_treats_path_as_literal_text(tmp_path, monkeypatch):
    output = io.StringIO()
    monkeypatch.setattr("shadowscan.cli.err_console", Console(file=output, force_terminal=True, width=600))
    destination = tmp_path / ("[red]" + PAYLOAD + ".json")
    _emit(ScanResult(), "json", str(destination), verbose=False, max_rows=None)
    assert destination.exists()
    _assert_no_payload_controls(output.getvalue())
    assert "[red]" in output.getvalue()
