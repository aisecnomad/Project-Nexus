"""Reporter boundaries remain safe for plugin and imported result data."""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any, cast

import click
import pytest
from rich.console import Console

from shadowscan.cli import _emit
from shadowscan.models import Evidence, Finding, Kind, ScanResult, ScanStats, Surface
from shadowscan.reporters import render
from shadowscan.reporters.csv_ import render_csv
from shadowscan.reporters.html import render_html
from shadowscan.reporters.json_ import render_json
from shadowscan.reporters.markdown import render_markdown
from shadowscan.reporters.sarif import _physical_locations, render_sarif
from shadowscan.reporters.table import print_table

CONTROL_PAYLOAD = "name\x1b]52;c;Y2xpcGJvYXJk\x07\x1b[2J\x9b2J\u202ereordered"
STATS_SECRET = "opaque-stats-publisher-credential"


def _finding(**overrides: Any) -> Finding:
    fields: dict[str, Any] = {
        "surface": Surface.CODE,
        "connector": "code.filesystem",
        "kind": Kind.AGENT,
        "title": "Agent",
        "resource": "repository",
        "resource_type": "project",
    }
    fields.update(overrides)
    return Finding(**fields)


@pytest.mark.parametrize("report_format", ["html", "csv"])
def test_stdout_and_saved_reports_neutralize_report_controls(
    report_format: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    result = ScanResult(findings=[_finding(title=CONTROL_PAYLOAD)])
    emitted: list[str] = []
    monkeypatch.setattr("shadowscan.cli.click.echo", emitted.append)

    _emit(result, report_format, None, verbose=False, max_rows=None)

    assert len(emitted) == 1
    terminal = emitted[0]
    assert all(control not in terminal for control in ("\x1b", "\x07", "\x9b", "\u202e"))
    assert "\\u001b" in terminal and "\\u0007" in terminal and "\\u202e" in terminal

    # A saved artifact is read with cat or less as often as it is opened in a
    # viewer, so it must not carry raw escape sequences either.
    destination = tmp_path / f"report.{report_format}"
    _emit(result, report_format, str(destination), verbose=False, max_rows=None)
    saved = destination.read_text(encoding="utf-8")
    assert CONTROL_PAYLOAD not in saved
    assert all(control not in saved for control in ("\x1b", "\x07", "\x9b", "\u202e"))
    assert "\\u001b" in saved and "\\u0007" in saved and "\\u202e" in saved
    # The data is still there, only its controls are visible.
    assert "name\\u001b]52;c;Y2xpcGJvYXJk\\u0007" in saved


def test_every_stats_publisher_redacts_direct_caller_diagnostics() -> None:
    url = f"https://gateway.invalid/logs?api_key={STATS_SECRET}"
    stats = ScanStats(
        connector=f"gateway.logs?api_key={STATS_SECRET}",
        started_at="now",
        errors=[f"request failed: {url}"],
        warnings=[f'API_KEY = "{STATS_SECRET}"'],
        skipped=True,
        skip_reason=f"token={STATS_SECRET}",
    )
    result = ScanResult(stats=[stats])
    outputs = [
        render_json(result),
        render_sarif(result),
        render_html(result),
        render_markdown(result),
        render_csv(result),
    ]
    terminal = io.StringIO()
    print_table(result, Console(file=terminal, force_terminal=False, width=240), verbose=True)
    outputs.append(terminal.getvalue())

    assert all(STATS_SECRET not in output for output in outputs)
    assert all("REDACTED" in output for output in outputs[:4])
    assert "REDACTED" in outputs[-1]
    # Publication sanitizes a copy so evidence retained for in-process handling
    # is not unexpectedly rewritten by selecting a report format.
    assert STATS_SECRET in stats.errors[0]


def test_json_redacts_credential_copies_across_connector_statistics() -> None:
    credential = ScanStats("first", "now", errors=["--api-key", STATS_SECRET])
    reflected = ScanStats("second", "now", warnings=[f"reflected caller {STATS_SECRET}"])
    result = ScanResult(stats=[credential, reflected])

    output = render_json(result)

    assert STATS_SECRET not in output
    assert "REDACTED" in output
    assert credential.errors == ["--api-key", STATS_SECRET]
    assert reflected.warnings == [f"reflected caller {STATS_SECRET}"]


def test_table_preflights_stats_before_publishing_any_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cyclic: list[Any] = []
    cyclic.append(cyclic)
    result = ScanResult(
        stats=[ScanStats(connector="plugin", started_at="now", warnings=cast(list[str], cyclic))]
    )
    direct_stream = io.StringIO()
    with pytest.raises(RecursionError):
        print_table(result, Console(file=direct_stream, force_terminal=False, width=160))
    assert direct_stream.getvalue() == ""

    cli_stream = io.StringIO()
    monkeypatch.setattr(
        "shadowscan.cli.console",
        Console(file=cli_stream, force_terminal=False, width=160),
    )
    with pytest.raises(click.ClickException, match="result data is invalid"):
        _emit(result, "table", None, verbose=False, max_rows=None)
    assert cli_stream.getvalue() == ""


@pytest.mark.parametrize("malformed", [{"id": "ss-wrong-shape"}, 7, "ss-not-a-list"])
def test_html_and_markdown_ignore_malformed_related_metadata(malformed: Any) -> None:
    finding = _finding(metadata={"related": malformed})
    result = ScanResult(findings=[finding])

    assert "<b>Related</b>" not in render_html(result)
    assert "**Related findings:**" not in render_markdown(result)


def test_html_and_markdown_keep_only_string_related_ids() -> None:
    finding = _finding(metadata={"related": [{"id": "bad"}, "ss-good", 7]})
    result = ScanResult(findings=[finding])

    assert "<code>ss-good</code>" in render_html(result)
    assert "**Related findings:** `ss-good`" in render_markdown(result)


def test_sarif_distinguishes_source_prefixes_from_remote_resource_ids() -> None:
    finding = _finding(
        evidence=[
            Evidence(signal="source", description="source", location="http_client.py:7"),
            Evidence(signal="source", description="source", location="projects/app/agent.py:12"),
            Evidence(signal="remote", description="remote", location="https://example.invalid/agent"),
            Evidence(signal="remote", description="remote", location="arn:aws:bedrock:eu-west-2:1:agent/x"),
            Evidence(
                signal="remote",
                description="remote",
                location="projects/acme/locations/europe-west1/agents/x",
            ),
            Evidence(
                signal="remote",
                description="remote",
                location="/subscriptions/123/resourceGroups/rg/providers/Microsoft.Web/sites/app",
            ),
            Evidence(signal="remote", description="remote", location="ocid1.generativeaiagent.oc1..x"),
        ]
    )

    locations = _physical_locations(finding)
    physical = [location["physicalLocation"] for location in locations]
    assert [item["artifactLocation"]["uri"] for item in physical] == [
        "http_client.py",
        "projects/app/agent.py",
    ]
    assert [item["region"]["startLine"] for item in physical] == [7, 12]

    remote_fallback = _finding(
        evidence=[Evidence(signal="remote", description="remote", location="https://example.invalid/agent")],
        metadata={"path": "projects/acme/locations/europe-west1/agents/x"},
    )
    assert _physical_locations(remote_fallback) == []


def test_sarif_and_cli_refuse_nonfinite_plugin_values_before_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    finding = _finding()
    result = ScanResult(findings=[finding])
    finding.confidence = float("nan")
    with pytest.raises(ValueError, match="Out of range float values"):
        render_sarif(result)

    finding.confidence = 0.5
    finding.metadata["plugin_score"] = float("inf")
    emitted: list[str] = []
    monkeypatch.setattr("shadowscan.cli.click.echo", emitted.append)
    with pytest.raises(click.ClickException, match="result data is invalid"):
        _emit(result, "json", None, verbose=False, max_rows=None)
    assert emitted == []

    destination = tmp_path / "existing.json"
    destination.write_text("previous valid report", encoding="utf-8")
    with pytest.raises(click.ClickException, match="result data is invalid"):
        _emit(result, "json", str(destination), verbose=False, max_rows=None)
    assert destination.read_text(encoding="utf-8") == "previous valid report"


def test_render_dispatch_preserves_safe_nonterminal_formats() -> None:
    """The stdout safeguard is format-scoped rather than a global report rewrite."""
    result = ScanResult(findings=[_finding(title=CONTROL_PAYLOAD)])
    assert render(result, "html") == render_html(result)
