from __future__ import annotations

import time

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors.base import BaseConnector
from shadowscan.engine import Engine
from shadowscan.models import Surface


class _SlowConnector(BaseConnector):
    name = "code.filesystem"
    surface = Surface.CODE

    def collect(self):
        time.sleep(5)
        return []

    def analyze(self, records):
        return []


def test_connector_deadline_marks_scan_incomplete(monkeypatch, index, tmp_path):
    monkeypatch.setattr("shadowscan.engine.get_connector_class", lambda name, **kwargs: _SlowConnector)
    repo = tmp_path / "repo"
    repo.mkdir()
    cfg = ScanConfig(
        connectors=[ConnectorSpec("code.filesystem", {"path": str(repo)})],
        connector_timeout=1,
        parallel=1,
    )
    result = Engine(cfg, index).run()
    assert not result.complete
    assert any("deadline" in error for stat in result.stats for error in stat.errors)
