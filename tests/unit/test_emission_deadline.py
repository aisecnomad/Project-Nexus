"""A connector deadline reached while findings are reported keeps the findings already reported.

In the real-world benchmark, one large repository finished its walk inside the
connector deadline, but reporting its findings ran past it, and the engine
discarded every finding. Reporting now stops early enough for the engine to
accept the result, which is marked incomplete.
"""

from __future__ import annotations

import time
from pathlib import Path

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.code import filesystem
from shadowscan.connectors.code.filesystem import FilesystemConnector


def _projects(tmp_path: Path, count: int) -> None:
    for number in range(count):
        name = f"p{number:02d}"
        (tmp_path / name).mkdir()
        (tmp_path / name / "requirements.txt").write_text("openai\n")
        (tmp_path / name / "app.py").write_text("from openai import OpenAI\nOpenAI()\n")


def test_reporting_stops_before_the_deadline_and_keeps_earlier_findings(tmp_path: Path, index, monkeypatch):
    _projects(tmp_path, 2)
    original = FilesystemConnector._emit_findings
    deadline = time.monotonic() + 3.0

    def slow_emission(self, scan):
        for number, finding in enumerate(original(self, scan)):
            if number == 1:
                time.sleep(max(0.0, deadline - 0.03 - time.monotonic()))  # past the reporting cutoff
            yield finding

    monkeypatch.setattr(FilesystemConnector, "_emit_findings", slow_emission)
    ctx = ConnectorContext(config={"path": str(tmp_path), "use_git": False}, index=index, deadline=deadline)
    findings = FilesystemConnector(ctx).run()
    assert time.monotonic() < deadline
    assert len(findings) == 1
    assert ctx.stats.incomplete
    assert any("deadline reached while reporting findings" in e and "after 1" in e for e in ctx.stats.errors)


def test_project_analysis_stops_before_the_deadline_and_keeps_built_findings(
    tmp_path: Path, index, monkeypatch
):
    # Project findings are built before they are reported: the analysis loop
    # itself must stop in time, and a project as slow as the slowest so far
    # must not start when it would finish past the cutoff.
    _projects(tmp_path, 12)
    original = FilesystemConnector._emit_project

    def slow_project(self, *args, **kwargs):
        time.sleep(0.25)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(FilesystemConnector, "_emit_project", slow_project)
    deadline = time.monotonic() + 2.0
    config = {"path": str(tmp_path), "use_git": False, "scan_timeout": 0.5}
    ctx = ConnectorContext(config=config, index=index, deadline=deadline)
    findings = FilesystemConnector(ctx).run()
    assert time.monotonic() < deadline
    assert 1 <= len(findings) < 12
    assert ctx.stats.incomplete
    assert any("deadline reached while reporting findings" in e for e in ctx.stats.errors)


def test_emission_reserve_is_a_quarter_of_the_walk_margin() -> None:
    assert filesystem._emission_reserve(10) == 0.125
    assert filesystem._emission_reserve(900) == 11.25
