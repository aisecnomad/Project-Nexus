"""GitHub App permissions map to the capabilities they actually grant."""

from __future__ import annotations

import pytest

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.saas.github_apps import GitHubAppsConnector
from shadowscan.models import ScanStats


def installation(**permissions):
    return {"id": 7, "app_slug": "review-helper", "app_id": 7, "repository_selection": "selected", "permissions": permissions}


@pytest.fixture
def connector(index):
    ctx = ConnectorContext(config={"org": "acme", "input": "x"}, index=index)
    ctx.stats = ScanStats(connector="saas.github_apps", started_at="2026-09-26T00:00:00Z")
    return GitHubAppsConnector(ctx)


def test_pull_request_write_is_write_access_but_not_code_execution(connector):
    finding = connector._installation_finding(installation(pull_requests="write", metadata="read"))
    assert finding is not None
    assert "write-access" in finding.tags and "saas-actions" in finding.capabilities
    assert "code-exec" not in finding.capabilities


@pytest.mark.parametrize("permission", ["contents", "workflows"])
def test_pushing_code_or_editing_workflows_is_code_execution(connector, permission):
    finding = connector._installation_finding(installation(**{permission: "write"}))
    assert finding is not None and "code-exec" in finding.capabilities
