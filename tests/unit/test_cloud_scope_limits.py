"""Live cloud collection must honor requested scope before expensive reads."""

from __future__ import annotations

from unittest.mock import Mock

from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.cloud.gcp import GcpConnector
from shadowscan.models import ScanStats

ACCOUNT = "123456789012"


def context(index, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="test", started_at="2026-09-24")
    return ctx


def test_gcp_project_limit_stops_discovery_before_exhausting_all_pages(index):
    ctx = context(index, max_projects=2)
    connector = GcpConnector(ctx)
    connector._auth = Mock()
    connector._collect_project = Mock(return_value=[])
    connector.http = Mock()
    connector.http.get_json.side_effect = [
        {"projects": [{"projectId": f"project-{n}"}], "nextPageToken": f"token-{n}"} for n in range(10)
    ]
    assert list(connector.collect()) == []
    assert [call.args[0] for call in connector._collect_project.call_args_list] == ["project-0", "project-1"]
    assert connector.http.get_json.call_count == 3
    assert ctx.stats.incomplete
    assert any("max_projects" in warning for warning in ctx.stats.warnings)

