"""Repository and report data cannot issue terminal commands during display."""

from __future__ import annotations

import io
import json

from click.testing import CliRunner
from rich.console import Console

from shadowscan.cli import _emit, main
from shadowscan.models import Evidence, Finding, Kind, Risk, RiskFactor, ScanResult, ScanStats, Surface
from shadowscan.reporters.table import print_table
from shadowscan.utils.output import terminal_text

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


def test_table_neutralizes_controls_in_findings_and_connector_diagnostics():
    finding = Finding(
        surface=Surface.CODE, connector="code.filesystem", kind=Kind.AGENT,
        title=PAYLOAD, resource=PAYLOAD, resource_type="repository", owner=PAYLOAD,
        frameworks=[PAYLOAD], capabilities=[PAYLOAD], registry_match=PAYLOAD,
        evidence=[Evidence(signal="example", description=PAYLOAD, location=PAYLOAD)],
        risk=Risk(factors=[RiskFactor(id="example", description=PAYLOAD, weight=1)]),
        metadata={"runtime_activity": {"status": PAYLOAD}},
    )
    result = ScanResult(
        findings=[finding], inventory_size=1, version=PAYLOAD,
        stats=[ScanStats(connector=PAYLOAD, started_at="now", errors=[PAYLOAD], warnings=[PAYLOAD])],
    )
    output = io.StringIO()
    print_table(result, console=Console(file=output, force_terminal=True, width=600), verbose=True)
    _assert_no_payload_controls(output.getvalue())
    # Publication escapes controls without changing the stored observation.
    assert finding.title == PAYLOAD and finding.resource == PAYLOAD


def test_diff_terminal_output_neutralizes_imported_title_and_resource(tmp_path):
    finding = Finding(surface=Surface.CODE, connector="code.filesystem", kind=Kind.AGENT,
                      title=PAYLOAD, resource=PAYLOAD, resource_type="repository")
    report = ScanResult(
        findings=[finding], stats=[ScanStats(connector="code.filesystem", started_at="now")],
        collection_scope={"schema": "shadowscan.collection-scope/v1", "comparable": True,
                          "fingerprint": "a" * 64},
    ).to_dict()
    after = tmp_path / "after.json"
    after.write_text(json.dumps(report))
    report["findings"] = []
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
