from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from shadowscan.connectors.base import BaseConnector, ConnectorContext
from shadowscan.connectors.code.github import GitHubConnector
from shadowscan.connectors.code.gitlab import GitLabConnector
from shadowscan.connectors.gateway.logs import GatewayLogConnector
from shadowscan.models import ScanStats, Surface


class _OfflineProbe(BaseConnector):
    name = "test.offline"
    surface = Surface.CODE

    def collect(self):
        return []

    def analyze(self, records):
        return []


def _context(index, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="test", started_at="2026-01-01T00:00:00Z")
    return ctx


def test_base_offline_directory_skips_symlinked_files_and_directories(tmp_path, index):
    root = tmp_path / "input"
    root.mkdir()
    (root / "safe.jsonl").write_text('{"safe":true}\n')
    outside_file = tmp_path / "outside.jsonl"
    outside_file.write_text('{"outside":true}\n')
    outside_dir = tmp_path / "outside-dir"
    outside_dir.mkdir()
    (outside_dir / "leak.jsonl").write_text('{"leak":true}\n')
    (root / "escape.jsonl").symlink_to(outside_file)
    (root / "linked-dir").symlink_to(outside_dir, target_is_directory=True)

    ctx = _context(index)
    records = list(_OfflineProbe(ctx).load_offline(str(root)))

    assert records == [{"safe": True}]
    assert ctx.stats.incomplete
    assert any("symlinks are skipped" in warning for warning in ctx.stats.warnings)


def test_base_jsonl_reader_stops_at_aggregate_byte_budget(tmp_path, index):
    source = tmp_path / "events.jsonl"
    source.write_text('{"a":1}\n{"b":2}\n')
    ctx = _context(index, max_input_bytes=8, max_input_file_bytes=64)

    records = list(_OfflineProbe(ctx).load_offline(str(source)))

    assert records == [{"a": 1}]
    assert ctx.stats.incomplete
    assert any("max_input_bytes" in warning for warning in ctx.stats.warnings)


def test_base_offline_directory_stops_at_file_budget(tmp_path, index):
    root = tmp_path / "input"
    root.mkdir()
    (root / "a.jsonl").write_text('{"first":true}\n')
    (root / "b.jsonl").write_text('{"second":true}\n')
    ctx = _context(index, max_input_files=1)

    records = list(_OfflineProbe(ctx).load_offline(str(root)))

    assert records == [{"first": True}]
    assert ctx.stats.incomplete
    assert any("max_input_files (1) reached" in warning for warning in ctx.stats.warnings)


def test_gateway_max_records_caps_analysis_and_marks_incomplete(tmp_path, run_connector):
    source = tmp_path / "gateway.jsonl"
    event = {"service": "worker", "model": "gpt-4o", "user_agent": "langchain/0.3"}
    source.write_text("".join(json.dumps(event) + "\n" for _ in range(3)))

    findings, ctx = run_connector("gateway.logs", input=str(source), max_records=2)

    assert len(findings) == 1
    assert findings[0].metadata["events"] == 2
    assert ctx.stats.objects_examined == 2
    assert ctx.stats.incomplete
    assert any("max_records (2) reached" in warning for warning in ctx.stats.warnings)


def test_gateway_gzip_expansion_is_bounded(tmp_path, index):
    source = tmp_path / "expanded.log.gz"
    with gzip.open(source, "wt", encoding="utf-8") as stream:
        stream.write("x" * 2_000 + "\n")
    ctx = _context(index, max_input_bytes=64, max_input_file_bytes=64)

    records = list(GatewayLogConnector(ctx).load_offline(str(source)))

    assert records == []
    assert ctx.stats.incomplete
    assert any("max_input_" in warning for warning in ctx.stats.warnings)


@pytest.mark.parametrize(
    ("connector_type", "config_key"),
    [(GitHubConnector, "max_repos"), (GitLabConnector, "max_projects")],
)
def test_offline_clone_loaders_skip_symlinks_and_enforce_repo_caps(tmp_path, index, connector_type, config_key):
    root = tmp_path / "clones"
    root.mkdir()
    (root / "repo-a").mkdir()
    (root / "repo-b").mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "escape").symlink_to(outside, target_is_directory=True)
    ctx = _context(index, **{config_key: 1})

    records = list(connector_type(ctx).load_offline(str(root)))

    assert len(records) == 1
    assert Path(records[0]["_local_path"]).parent == root
    assert ctx.stats.incomplete
