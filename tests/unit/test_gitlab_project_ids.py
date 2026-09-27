"""GitLab project ids reach request paths only as positive integers.

Regression: ids from the group project listing were interpolated into
``/projects/{id}/...`` request paths unvalidated, so a hostile or corrupted
listing entry such as ``"1/../../users/1"`` addressed a different endpoint
with the scan token.
"""

from __future__ import annotations

import shutil
from unittest.mock import Mock

import pytest

from shadowscan.connectors.base import ConnectorContext, ConnectorError
from shadowscan.connectors.code.gitlab import GitLabConnector
from shadowscan.models import ScanStats

# Values a hostile or corrupted listing could place in a project's ``id``.
MALFORMED_IDS = ["1/../../users/1", "../7", "7?private=1", "7", True, 0, -3, 1.5, None, [7], {"id": 7}]


def _gitlab(index, **config):
    ctx = ConnectorContext(config={"use_git": False, **config}, index=index)
    ctx.stats = ScanStats(connector="code.gitlab", started_at="2026-09-27T00:00:00Z")
    return GitLabConnector(ctx)


def _requested_paths(http: Mock) -> list[str]:
    calls = [*http.try_get_json.call_args_list, *http.paginate_link.call_args_list, *http.get.call_args_list]
    return [str(call.args[0]) for call in calls]


@pytest.mark.parametrize("project_id", [*MALFORMED_IDS, "missing"])
def test_group_listing_malformed_project_id_is_an_error_and_never_requested(index, project_id):
    connector = _gitlab(index, group="acme", mode="api")
    hostile = {"path_with_namespace": "acme/hostile", "default_branch": "main"}
    if project_id != "missing":
        hostile["id"] = project_id
    valid = {"id": 8, "path_with_namespace": "acme/valid", "default_branch": "main"}
    connector.http = Mock()
    connector.http.paginate_link.side_effect = (
        lambda path, **_: [hostile, valid] if path == "/groups/acme/projects" else []
    )
    connector.http.try_get_json.return_value = {}

    assert connector.run() == []
    paths = _requested_paths(connector.http)
    assert all(path.startswith(("/groups/acme", "/projects/8/")) for path in paths), paths
    # The valid neighbour is still scanned; only the malformed entry is dropped.
    assert "/projects/8/repository/commits/main" in paths
    stats = connector.ctx.stats
    assert stats.objects_examined == 1
    assert stats.incomplete
    assert any("no valid numeric id" in error for error in stats.errors)


@pytest.mark.parametrize("project_id", MALFORMED_IDS)
def test_project_requests_refuse_malformed_id_before_sending(tmp_path, index, monkeypatch, project_id):
    connector = _gitlab(index, mode="clone")
    connector.http = Mock()
    connector.http.try_get_json.return_value = {}
    connector.http.paginate_link.return_value = []
    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/git")
    project = {"id": project_id, "path_with_namespace": "acme/hostile", "default_branch": "main"}

    with pytest.raises(ConnectorError, match="positive integer"):
        connector._fetch(project, str(tmp_path))  # size lookup, then the API fallback
    with pytest.raises(ConnectorError, match="positive integer"):
        connector._fetch_via_api(project, str(tmp_path))
    with pytest.raises(ConnectorError, match="positive integer"):
        list(connector._project_level(project))
    assert _requested_paths(connector.http) == []


def test_analyze_records_malformed_project_id_as_an_error(index):
    connector = _gitlab(index, mode="api")
    connector.http = Mock()
    connector.http.try_get_json.return_value = {}

    assert list(connector.analyze([{"id": "../admin", "path_with_namespace": "acme/hostile"}])) == []
    assert _requested_paths(connector.http) == []
    assert connector.ctx.stats.incomplete
    errors = connector.ctx.stats.errors
    assert any(error.startswith("code.gitlab: acme/hostile: ConnectorError") for error in errors)


def test_valid_project_id_is_used_verbatim(tmp_path, index):
    connector = _gitlab(index, mode="api")
    connector.http = Mock()
    connector.http.try_get_json.return_value = {"id": "a" * 40}
    connector.http.paginate_link.return_value = []

    dest = connector._fetch_via_api({"id": 12345, "default_branch": "main"}, str(tmp_path))
    assert dest == str(tmp_path / "repo")
    assert _requested_paths(connector.http) == [
        "/projects/12345/repository/commits/main", "/projects/12345/repository/tree",
    ]
    assert not connector.ctx.stats.incomplete
