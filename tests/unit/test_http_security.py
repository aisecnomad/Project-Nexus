from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import requests
from requests.adapters import HTTPAdapter

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.code.github import GitHubConnector, repository_target
from shadowscan.connectors.code.gitlab import GitLabConnector
from shadowscan.utils.http import HttpClient, HttpError, _DestinationPolicyAdapter


def response(data=None, status=200, headers=None):
    result = requests.Response()
    result.status_code = status
    result._content = json.dumps(data).encode()
    result._content_consumed = True
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
    initial = [] if paginator == "paginate_link" else {"value": []}
    http, session = client(response(initial, headers={"Link": '<https://evil.example/next>; rel="next"'}))
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
    connector.http.try_get_json.return_value = {"id": "a" * 40}
    connector.http.paginate_link.return_value = [{"path": "../escape.py", "type": "blob"}]
    with pytest.raises(RuntimeError):
        connector._fetch_via_api({"id": 1}, str(tmp_path))
    connector.http.get.assert_not_called()


@pytest.mark.parametrize("host", ["127.0.0.1", "169.254.169.254", "10.2.3.4", "[::1]", "[::ffff:127.0.0.1]", "100.64.0.1", "metadata.google.internal"])
def test_private_destinations_rejected_before_request(host):
    http, session = client()
    # Use an empty base URL to isolate the destination policy from origin checks.
    http.base_url = ""
    with pytest.raises(ValueError, match="Refusing"):
        http.get(f"https://{host}/credentials")
    session.request.assert_not_called()


def test_dns_rebinding_cannot_change_the_connected_address(monkeypatch):
    import socket

    from shadowscan.utils.http import _PublicHTTPSConnection

    resolver = Mock(side_effect=[
        [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 443))],
        [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 443))],
    ])
    sock = Mock()
    monkeypatch.setattr("shadowscan.utils.http.socket.getaddrinfo", resolver)
    monkeypatch.setattr("shadowscan.utils.http.socket.socket", Mock(return_value=sock))
    connection = _PublicHTTPSConnection("issuer.example", timeout=5)
    assert connection._new_conn() is sock
    resolver.assert_called_once()
    sock.connect.assert_called_once_with(("8.8.8.8", 443))
    # HTTPSConnection retains the DNS hostname for TLS SNI/certificate checks.
    assert connection.host == "issuer.example"


def test_connect_rejects_private_dns_answer_without_creating_socket(monkeypatch):
    import socket

    from shadowscan.utils.http import _PublicHTTPSConnection

    monkeypatch.setattr("shadowscan.utils.http.socket.getaddrinfo", Mock(return_value=[
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 443)),
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("10.0.0.1", 443)),
    ]))
    factory = Mock()
    monkeypatch.setattr("shadowscan.utils.http.socket.socket", factory)
    with pytest.raises(ValueError, match="Refusing"):
        _PublicHTTPSConnection("issuer.example", timeout=5)._new_conn()
    factory.assert_not_called()


def test_connect_rejects_rebinding_after_url_preflight(monkeypatch):
    import socket

    from shadowscan.utils.http import _PublicHTTPSConnection, validate_url

    resolver = Mock(side_effect=[
        [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 443))],
        [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("169.254.169.254", 443))],
    ])
    monkeypatch.setattr("shadowscan.utils.http.socket.getaddrinfo", resolver)
    factory = Mock()
    monkeypatch.setattr("shadowscan.utils.http.socket.socket", factory)
    validate_url("https://issuer.example/keys")
    with pytest.raises(ValueError, match="Refusing"):
        _PublicHTTPSConnection("issuer.example", timeout=5)._new_conn()
    factory.assert_not_called()


def test_private_override_is_worker_scoped_and_reset():
    from concurrent.futures import ThreadPoolExecutor

    from shadowscan.utils.http import reset_allow_private_origin, set_allow_private_origin, validate_url

    def default_worker():
        with pytest.raises(ValueError, match="Refusing"):
            validate_url("https://127.0.0.1/keys")

    token = set_allow_private_origin(True)
    try:
        assert validate_url("https://127.0.0.1/keys") == "https://127.0.0.1/keys"
        with ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(default_worker).result()
    finally:
        reset_allow_private_origin(token)
    default_worker()


def test_private_override_does_not_mutate_another_clients_pool():
    from shadowscan.utils.http import _PrivateHTTPSConnection, _PublicHTTPSConnection

    public = HttpClient()
    private = HttpClient(allow_private_origin=True)
    try:
        public_pool = public.session.get_adapter("https://").poolmanager.connection_from_url("https://example.com")
        private_pool = private.session.get_adapter("https://").poolmanager.connection_from_url("https://example.com")
        assert public_pool.ConnectionCls is _PublicHTTPSConnection
        assert private_pool.ConnectionCls is _PrivateHTTPSConnection
    finally:
        public.session.close()
        private.session.close()


def test_environment_proxy_and_explicit_proxy_cannot_bypass_destination_policy(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "https://127.0.0.1:8080")
    http = HttpClient("https://example.com")
    try:
        assert http.session.trust_env is False
        with pytest.raises(ValueError, match="Proxies"):
            http.get("/keys", proxies={"https": "https://proxy.example"})
        with pytest.raises(ValueError, match="Proxies"):
            http.session.get_adapter("https://").proxy_manager_for("https://proxy.example")
    finally:
        http.session.close()


def test_tls_verification_cannot_be_disabled():
    http, session = client()
    with pytest.raises(ValueError, match="TLS"):
        http.get("/keys", verify=False)
    session.request.assert_not_called()


def test_bounded_json_reads_streamed_decoded_bytes_and_closes_response():
    result = response({"keys": []})
    result.iter_content = Mock(return_value=iter([b'{"keys":', b'[]}']))
    result.close = Mock()
    http, session = client(result)
    assert http.get_json("/keys", max_bytes=16) == {"keys": []}
    assert session.request.call_args.kwargs["stream"] is True
    result.close.assert_called_once()


@pytest.mark.parametrize("content_length,chunks", [("1000", []), (None, [b"x" * 9, b"y" * 9]), ("3", [b"x" * 17])])
def test_bounded_json_refuses_oversized_declared_or_decoded_body(content_length, chunks):
    result = response(headers={"Content-Length": content_length} if content_length else {})
    result.iter_content = Mock(return_value=iter(chunks))
    result.close = Mock()
    http, _ = client(result)
    with pytest.raises(ValueError, match="byte limit"):
        http.get_json("/keys", max_bytes=16)
    result.close.assert_called_once()

def test_default_json_limit_is_enforced_while_streaming():
    result = response({"keys": []})
    result.iter_content = Mock(return_value=iter([b"x" * 9]))
    result.close = Mock()
    http, session = client(result, max_response_bytes=8)

    with pytest.raises(ValueError, match="byte limit"):
        http.get_json("/keys")

    assert session.request.call_args.kwargs["stream"] is True
    result.close.assert_called_once()


def test_json_limit_can_be_overridden_for_a_documented_page():
    result = response({"ok": True})
    result.iter_content = Mock(return_value=iter([b'{"ok": true}']))
    http, _ = client(result, max_response_bytes=4)

    assert http.get_json("/keys", max_bytes=16) == {"ok": True}


def test_injected_session_specific_adapter_cannot_bypass_destination_policy():
    session = requests.Session()
    legacy = HTTPAdapter()
    session.mount("https://8.8.8.8/private", legacy)
    session.mount("HTTPS://8.8.8.8", legacy)
    http = HttpClient("https://8.8.8.8", session=session)
    try:
        assert set(session.adapters) == {"https://"}
        assert isinstance(session.get_adapter("https://8.8.8.8/private/items"), _DestinationPolicyAdapter)
        # A session retained by its caller must not replace the adapter later.
        session.mount("https://8.8.8.8/private", legacy)
        with pytest.raises(ValueError, match="adapter was replaced"):
            http.get("/private/items", stream=True)
    finally:
        session.close()


@pytest.mark.parametrize("method", ["get", "post"])
def test_default_raw_response_is_bounded_before_returning_content(method):
    oversized = response(headers={"Content-Length": "17"})
    oversized.iter_content = Mock(side_effect=AssertionError("oversize body should not be read"))
    oversized.close = Mock()
    http, session = client(oversized, max_response_bytes=16)

    with pytest.raises(ValueError, match="byte limit"):
        getattr(http, method)("/items")
    assert session.request.call_args.kwargs["stream"] is True
    oversized.iter_content.assert_not_called()
    oversized.close.assert_called_once()


def test_default_raw_response_preserves_cached_content_after_close():
    result = response({"ok": True})
    result.close = Mock()
    http, _ = client(result)
    returned = http.get("/items")
    assert returned is result
    assert returned.json() == {"ok": True}
    result.close.assert_called_once()


def test_post_json_uses_the_default_streamed_body_limit():
    result = response({"keys": []})
    result.iter_content = Mock(return_value=iter([b"x" * 9]))
    result.close = Mock()
    http, session = client(result, max_response_bytes=8)

    with pytest.raises(ValueError, match="byte limit"):
        http.post_json("/keys", json={"query": "test"})

    assert session.request.call_args.kwargs["stream"] is True
    result.close.assert_called_once()


@pytest.mark.parametrize(
    "paginator,data,kwargs",
    [
        ("paginate_link", {"error": "upstream failure"}, {"item_key": "items"}),
        ("paginate_link", {"items": {}}, {"item_key": "items"}),
        ("paginate_odata", {"error": "upstream failure"}, {}),
        ("paginate_odata", {"value": {}}, {}),
        ("paginate_token", {"nextPageToken": None}, {}),
        ("paginate_token", {"items": None}, {}),
        ("paginate_cursor", {"ok": True}, {}),
        ("paginate_cursor", {"results": {}}, {}),
    ],
)
def test_paginators_fail_closed_on_missing_or_invalid_collection(paginator, data, kwargs):
    http, _ = client(response(data))

    with pytest.raises(RuntimeError, match="collection"):
        list(getattr(http, paginator)("/items", **kwargs))
