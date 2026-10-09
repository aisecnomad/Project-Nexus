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


def test_reporting_stops_before_the_deadline_and_keeps_earlier_findings(tmp_path: Path, index, monkeypatch):
    for name in ("one", "two"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "requirements.txt").write_text("openai\n")
        (tmp_path / name / "app.py").write_text("from openai import OpenAI\nOpenAI()\n")
    original = FilesystemConnector._emit_findings

    def slow_emission(self, scan):
        for number, finding in enumerate(original(self, scan)):
            if number == 1:
                time.sleep(1.7)  # the second finding is ready only after the reporting cutoff
            yield finding

    monkeypatch.setattr(FilesystemConnector, "_emit_findings", slow_emission)
    deadline = time.monotonic() + 2.5
    ctx = ConnectorContext(config={"path": str(tmp_path), "use_git": False}, index=index, deadline=deadline)
    findings = FilesystemConnector(ctx).run()
    assert time.monotonic() < deadline
    assert len(findings) == 1
    assert ctx.stats.incomplete
    assert any("deadline reached while reporting findings" in e and "after 1" in e for e in ctx.stats.errors)


def test_emission_reserve_scales_with_the_budget() -> None:
    assert filesystem._emission_reserve(10) == 1.0
    assert filesystem._emission_reserve(900) == 18.0
