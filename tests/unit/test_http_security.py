from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import requests

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.code.github import GitHubConnector, repository_target
from shadowscan.connectors.code.gitlab import GitLabConnector
from shadowscan.utils.http import HttpClient, HttpError


def response(data=None, status=200, headers=None):
    result = requests.Response()
    result.status_code = status
    result._content = json.dumps(data).encode()
    result.headers.update(headers or {})
    return result


def client(*responses, **kwargs):
    session = Mock(headers={})
    session.request.side_effect = responses
    return HttpClient("https://api.example.com/v1", session=session, **kwargs), session


@pytest.mark.parametrize("target", ["https://evil.example/items", "http://api.example.com/items", "https://api.example.com:444/items", "https://api.example.com@evil.example/items", "//evil.example/items"])
def test_untrusted_origin_rejected_before_credentials_are_sent(target):
    http, session = client()
    with pytest.raises(ValueError):
        http.get(target)
    session.request.assert_not_called()


@pytest.mark.parametrize("target", ["https://evil.example/items", "http://api.example.com/items"])
def test_redirect_cannot_forward_custom_credentials(target):
    http, session = client(response(status=302, headers={"Location": target}))
    with pytest.raises(ValueError):
        http.get("/items", headers={"PRIVATE-TOKEN": "synthetic"})
    assert session.request.call_count == 1
    assert session.request.call_args.kwargs["allow_redirects"] is False


def test_same_origin_redirect_allowed():
    http, session = client(response(status=302, headers={"Location": "/new"}), response({"ok": True}))
    assert http.get_json("/old") == {"ok": True}
    assert session.request.call_count == 2


def test_server_retry_after_is_bounded(monkeypatch):
    sleep = Mock()
    monkeypatch.setattr("shadowscan.utils.http.time.sleep", sleep)
    http, _ = client(response(status=429, headers={"Retry-After": "999999999999999999999"}), response({"ok": True}))
    assert http.get_json("/items") == {"ok": True}
    sleep.assert_called_once_with(120)


@pytest.mark.parametrize("paginator", ["paginate_link", "paginate_odata"])
def test_pagination_refuses_cross_origin_links(paginator):
    http, session = client(response({"value": []}, headers={"Link": '<https://evil.example/next>; rel="next"'}))
    if paginator == "paginate_odata":
        session.request.side_effect = [response({"value": [], "@odata.nextLink": "https://evil.example/next"})]
    with pytest.raises(ValueError):
        list(getattr(http, paginator)("/items"))
    assert session.request.call_count == 1


@pytest.mark.parametrize("status", [401, 403, 404, 422])
def test_optional_get_does_not_silently_erase_coverage(status):
    http, _ = client(response(status=status))
    with pytest.raises(HttpError):
        http.try_get_json("/items")


def test_http_error_never_retains_echoed_opaque_credentials():
    secret = "opaque-secret-without-provider-prefix"
    http, _ = client(response({"message": f"Denied request for {secret}"}, status=403))
    with pytest.raises(HttpError) as caught:
        http.get_json(f"/items?custom={secret}")
    assert secret not in str(caught.value)
    assert secret not in caught.value.url
    assert caught.value.body == ""
    assert secret not in str(HttpError(403, "https://api.example.com/items", secret))


def test_denied_optional_get_marks_incomplete_through_callback():
    warn = Mock()
    http, _ = client(response(status=403), on_warning=warn)
    assert http.try_get_json("/items", default=[]) == []
    assert "403" in warn.call_args.args[0]


def test_explicit_optional_feature_404_is_allowed():
    http, _ = client(response(status=404))
    assert http.try_get_json("/feature", default=[], ok_statuses={404}) == []


def test_explicit_status_cannot_suppress_denied_access():
    http, _ = client(response(status=403))
    with pytest.raises(HttpError):
        http.try_get_json("/items", ok_statuses={403})


def test_pagination_budget_exhaustion_is_an_error():
    http, _ = client(response([], headers={"Link": '<https://api.example.com/next>; rel="next"'}))
    with pytest.raises(RuntimeError, match="limit"):
        list(http.paginate_link("/items", max_pages=1))


@pytest.mark.parametrize("path", ["../escape.py", "/escape.py", "nested/../../escape.py", "..\\escape.py", "C:/escape.py", "."])
def test_repository_api_paths_stay_inside_checkout(tmp_path, path):
    with pytest.raises(RuntimeError):
        repository_target(str(tmp_path), path)


def test_repository_symlink_escape_is_rejected(tmp_path):
    checkout = tmp_path / "repo"
    checkout.mkdir()
    (checkout / "nested").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(RuntimeError):
        repository_target(str(checkout), "nested/escape.py")


@pytest.mark.parametrize("cls,record", [(GitHubConnector, {"full_name": "org/repo", "clone_url": "https://evil.example/repo.git"}), (GitLabConnector, {"path_with_namespace": "org/repo", "http_url_to_repo": "https://evil.example/repo.git"})])
def test_clone_refuses_metadata_credential_destination(cls, record, tmp_path, index, monkeypatch):
    run = Mock()
    monkeypatch.setattr("subprocess.run", run)
    connector = cls(ConnectorContext(config={"token": "synthetic-token"}, index=index))
    with pytest.raises(ValueError):
        connector._clone(record, str(tmp_path))
    run.assert_not_called()


@pytest.mark.parametrize("cls,record,origin", [(GitHubConnector, {"full_name": "org/repo", "clone_url": "https://github.com/org/repo.git"}, "https://github.com/"), (GitLabConnector, {"path_with_namespace": "org/repo", "http_url_to_repo": "https://gitlab.com/org/repo.git"}, "https://gitlab.com/")])
def test_clone_credential_header_is_origin_scoped(cls, record, origin, tmp_path, index, monkeypatch):
    run = Mock(return_value=SimpleNamespace(returncode=0))
    monkeypatch.setattr("subprocess.run", run)
    connector = cls(ConnectorContext(config={"token": "synthetic-token"}, index=index))
    assert connector._clone(record, str(tmp_path))
    env = run.call_args.kwargs["env"]
    settings = {env[f"GIT_CONFIG_KEY_{n}"]: env[f"GIT_CONFIG_VALUE_{n}"] for n in range(int(env["GIT_CONFIG_COUNT"]))}
    assert "http.extraheader" not in settings
    assert settings[f"http.{origin}.extraheader"].startswith("Authorization: Basic ")
    assert settings["http.followRedirects"] == "false"
    assert "synthetic-token" not in " ".join(run.call_args.args[0])


def test_github_api_download_rejects_traversal_before_request(tmp_path, index):
    connector = GitHubConnector(ConnectorContext(index=index))
    connector.http = Mock()
    connector.http.try_get_json.return_value = {"tree": [{"path": "../escape.py", "type": "blob", "size": 10}]}
    with pytest.raises(RuntimeError):
        connector._fetch_via_api({"full_name": "org/repo"}, str(tmp_path))
    assert connector.http.try_get_json.call_count == 1
    assert not (tmp_path / "escape.py").exists()


def test_gitlab_api_download_rejects_traversal_before_request(tmp_path, index):
    connector = GitLabConnector(ConnectorContext(index=index))
    connector.http = Mock()
    connector.http.paginate_link.return_value = [{"path": "../escape.py", "type": "blob"}]
    with pytest.raises(RuntimeError):
        connector._fetch_via_api({"id": 1}, str(tmp_path))
    connector.http.get.assert_not_called()
