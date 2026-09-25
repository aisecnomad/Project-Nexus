"""Exclusions apply as configured; cancellation stops the walk instead of being logged per file."""

from __future__ import annotations

import time
from threading import Event

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.models import ScanStats

SECRET = 'OPENAI_API_KEY = "sk-proj-' + "A" * 90 + '"\n'


def test_bare_exclude_names_apply_without_a_glob(tmp_path, run_connector):
    (tmp_path / "secrets.py").write_text(SECRET)
    (tmp_path / "main.py").write_text("x = 1\n")
    findings, _ = run_connector("code.filesystem", path=str(tmp_path), use_git=False, exclude=["secrets.py"])
    assert findings == []
    findings, _ = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert "secret" in {f.kind.value for f in findings}


def test_expired_deadline_stops_the_file_walk_early(tmp_path, index):
    for i in range(40):
        (tmp_path / f"m{i}.py").write_text("import os\n")
    cancelled = Event()
    cancelled.set()
    ctx = ConnectorContext(config={"path": str(tmp_path), "use_git": False}, index=index,
                           deadline=time.monotonic() - 1, cancelled=cancelled)
    ctx.stats = ScanStats(connector="code.filesystem", started_at="2026-09-25T00:00:00Z")
    findings = FilesystemConnector(ctx).run()
    assert findings == []
    assert ctx.stats.incomplete is True
    assert not any("file analysis incomplete (ConnectorError)" in error for error in ctx.stats.errors)
    assert ctx.stats.objects_examined <= 1
