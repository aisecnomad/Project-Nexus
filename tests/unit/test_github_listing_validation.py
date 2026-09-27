"""GitHub repository names reach request paths and clone URLs only as owner/name.

Regression: ``full_name`` values from the org or user repository listing were
interpolated into ``/repos/{full_name}/git/trees``, ``/git/blobs``, the
secret-name endpoints and the fallback clone URL unvalidated, while explicit
``repos`` responses were shape-checked. A hostile or corrupted listing entry
such as ``"acme/../../orgs/acme/actions"`` addressed a different endpoint with
the scan token.
"""

from __future__ import annotations

import shutil
from typing import Any
from unittest.mock import Mock

import pytest

from shadowscan.connectors.base import ConnectorContext, ConnectorError
from shadowscan.connectors.code import remote
from shadowscan.connectors.code.github import GitHubConnector
from shadowscan.models import ScanStats

# Values a hostile or corrupted listing could place in a repository's ``full_name``.
MALFORMED_NAMES = [
    "acme/../../orgs/acme/actions", "../admin", "acme/..", "./app", "acme/.", "acme", "acme/app/extra",
    "/app", "acme/", "acme/app?per_page=1", "acme/app#x", "acme/app%2F..", "acme/a pp", "acme/app\n",
    "acme\\app/x", "", True, 7, None, ["acme/app"], {"full_name": "acme/app"},
]
VALID_NAMES = ["acme/app", "Acme-Corp/.github", "octocat_acme/my.repo-2", "a/_", "acme/..."]


def _github(index: Any, **config: Any) -> GitHubConnector:
    ctx = ConnectorContext(config={"use_git": False, **config}, index=index)
    ctx.stats = ScanStats(connector="code.github", started_at="2026-09-27T00:00:00Z")
    return GitHubConnector(ctx)


def _requested_paths(http: Mock) -> list[str]:
    calls = [*http.try_get_json.call_args_list, *http.paginate_link.call_args_list, *http.get.call_args_list]
    return [str(call.args[0]) for call in calls]


@pytest.mark.parametrize("full_name", [*MALFORMED_NAMES, "missing"])
def test_listing_malformed_full_name_is_an_error_and_never_requested(index, full_name):
    connector = _github(index, org="acme", mode="api")
    hostile: dict[str, Any] = {"default_branch": "main", "owner": {"login": "acme"}}
    if full_name != "missing":
        hostile["full_name"] = full_name
    valid = {"full_name": "acme/valid", "default_branch": "main", "owner": {"login": "acme"}}
    connector.http = Mock()
    connector.http.paginate_link.side_effect = (
        lambda path, **_: [hostile, valid] if path == "/orgs/acme/repos" else []
    )
    connector.http.try_get_json.return_value = {}

    assert connector.run() == []
    paths = _requested_paths(connector.http)
    assert all(path == "/orgs/acme/repos" or path.startswith("/repos/acme/valid/") for path in paths), paths
    # The valid neighbour is still scanned; only the malformed entry is dropped.
    assert "/repos/acme/valid/git/trees/main" in paths
    stats = connector.ctx.stats
    assert stats is not None
    assert stats.objects_examined == 1
    assert stats.incomplete
    assert any("listing entry has no valid owner/name" in error for error in stats.errors)


def test_user_listing_is_validated_like_the_org_listing(index):
    connector = _github(index, user="octo")
    connector.http = Mock()
    connector.http.paginate_link.return_value = [
        {"full_name": "octo/../../user/keys"}, {"full_name": "octo/tool"},
    ]

    assert [record["full_name"] for record in connector.collect()] == ["octo/tool"]
    stats = connector.ctx.stats
    assert stats is not None and stats.incomplete
    assert stats.errors == [
        "code.github: repository listing entry has no valid owner/name; repository skipped"
    ]


@pytest.mark.parametrize("full_name", [*MALFORMED_NAMES, "missing"])
def test_repository_requests_refuse_malformed_full_name_before_sending(
    tmp_path, index, monkeypatch, full_name
):
    connector = _github(index, mode="clone")
    connector.http = Mock()
    connector.http.try_get_json.return_value = {}
    connector.http.paginate_link.return_value = []
    monkeypatch.setattr(shutil, "which", lambda _name: "/usr/bin/git")
    clone = Mock(return_value=True)
    monkeypatch.setattr(remote, "run_bounded_clone", clone)
    repo: dict[str, Any] = {"default_branch": "main", "size": 1, "owner": {"login": "acme"}}
    if full_name != "missing":
        repo["full_name"] = full_name

    with pytest.raises(ConnectorError, match="plain owner/name"):
        connector._fetch_repo(repo, str(tmp_path))  # clone target, before git runs
    with pytest.raises(ConnectorError, match="plain owner/name"):
        connector._fetch_via_api(repo, str(tmp_path))
    with pytest.raises(ConnectorError, match="plain owner/name"):
        connector._download_blob(repo, "a" * 40)
    with pytest.raises(ConnectorError, match="plain owner/name"):
        list(connector._repo_level_findings(repo))
    clone.assert_not_called()
    assert _requested_paths(connector.http) == []


def test_analyze_records_malformed_full_name_as_an_error(index):
    connector = _github(index, mode="api")
    connector.http = Mock()
    connector.http.try_get_json.return_value = {}

    assert list(connector.analyze([{"full_name": "acme/../admin", "default_branch": "main"}])) == []
    assert _requested_paths(connector.http) == []
    stats = connector.ctx.stats
    assert stats is not None and stats.incomplete
    assert any("ConnectorError" in error and "plain owner/name" in error for error in stats.errors)


def test_explicit_repository_response_with_dot_segment_is_refused(index):
    connector = _github(index, repos=["acme/.."])
    connector.http = Mock()
    connector.http.try_get_json.return_value = {"full_name": "acme/.."}

    assert list(connector.collect()) == []
    stats = connector.ctx.stats
    assert stats is not None and stats.incomplete
    assert any("does not match the requested name" in warning for warning in stats.warnings)


@pytest.mark.parametrize("full_name", VALID_NAMES)
def test_valid_full_names_are_listed_and_used_verbatim(tmp_path, index, full_name):
    connector = _github(index, org="acme", mode="api")
    connector.http = Mock()
    connector.http.paginate_link.return_value = [{"full_name": full_name, "default_branch": "main"}]
    connector.http.try_get_json.return_value = {"sha": "b" * 40, "tree": []}

    records = list(connector.collect())
    assert [record["full_name"] for record in records] == [full_name]
    assert connector._fetch_via_api(records[0], str(tmp_path)) == str(tmp_path / "repo")
    assert connector.http.try_get_json.call_args.args[0] == f"/repos/{full_name}/git/trees/main"
    stats = connector.ctx.stats
    assert stats is not None and not stats.incomplete and not stats.errors
