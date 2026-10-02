from __future__ import annotations

import ipaddress
import json
import socket
import traceback
from unittest.mock import Mock

import pytest
import requests
from requests.adapters import HTTPAdapter

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.code.github import GitHubConnector, repository_target
from shadowscan.connectors.code.gitlab import GitLabConnector
from shadowscan.utils.http import (
    HttpClient,
    HttpError,
    _blocked_host,
    _blocked_ip,
    _DestinationPolicyAdapter,
    validate_url,
)


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


def test_invalid_custom_header_does_not_echo_credential():
    credential = "synthetic-header-credential"
    with pytest.raises(ValueError) as exc:
        HttpClient(
            "https://api.example.com/v1", headers={"Authorization": f"Bearer {credential}\nInjected: yes"}
        )
    assert credential not in str(exc.value)
    assert "invalid characters" in str(exc.value)


@pytest.mark.parametrize(
    "target",
    [
        "https://evil.example/items",
        "http://api.example.com/items",
        "https://api.example.com:444/items",
        "https://api.example.com@evil.example/items",
        "//evil.example/items",
    ],
)
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
    http, _ = client(
        response(status=429, headers={"Retry-After": "999999999999999999999"}), response({"ok": True})
    )
    assert http.get_json("/items") == {"ok": True}
    sleep.assert_called_once_with(120)


@pytest.mark.parametrize("paginator", ["paginate_link", "paginate_odata"])
def test_pagination_refuses_cross_origin_links(paginator):
    initial = [] if paginator == "paginate_link" else {"value": []}
    http, session = client(response(initial, headers={"Link": '<https://evil.example/next>; rel="next"'}))
    if paginator == "paginate_odata":
        session.request.side_effect = [
            response({"value": [], "@odata.nextLink": "https://evil.example/next"})
        ]
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


@pytest.mark.parametrize(
    "path", ["../escape.py", "/escape.py", "nested/../../escape.py", "..\\escape.py", "C:/escape.py", "."]
)
def test_repository_api_paths_stay_inside_checkout(tmp_path, path):
    with pytest.raises(RuntimeError):
        repository_target(str(tmp_path), path)


def test_repository_symlink_escape_is_rejected(tmp_path):
    checkout = tmp_path / "repo"
    checkout.mkdir()
    (checkout / "nested").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(RuntimeError):
        repository_target(str(checkout), "nested/escape.py")


@pytest.mark.parametrize(
    "cls,record",
    [
        (GitHubConnector, {"full_name": "org/repo", "clone_url": "https://evil.example/repo.git"}),
        (
            GitLabConnector,
            {"path_with_namespace": "org/repo", "http_url_to_repo": "https://evil.example/repo.git"},
        ),
    ],
)
def test_clone_refuses_metadata_credential_destination(cls, record, tmp_path, index, monkeypatch):
    run = Mock()
    monkeypatch.setattr("shadowscan.connectors.code.remote.run_bounded_clone", run)
    connector = cls(ConnectorContext(config={"token": "synthetic-token"}, index=index))
    with pytest.raises(ValueError):
        connector._clone(record, str(tmp_path))
    run.assert_not_called()


@pytest.mark.parametrize(
    "cls,record,origin",
    [
        (
            GitHubConnector,
            {"full_name": "org/repo", "clone_url": "https://github.com/org/repo.git"},
            "https://github.com/",
        ),
        (
            GitLabConnector,
            {"path_with_namespace": "org/repo", "http_url_to_repo": "https://gitlab.com/org/repo.git"},
            "https://gitlab.com/",
        ),
    ],
)
def test_clone_credential_header_is_origin_scoped(cls, record, origin, tmp_path, index, monkeypatch):
    run = Mock(return_value=True)
    monkeypatch.setattr("shadowscan.connectors.code.remote.run_bounded_clone", run)
    connector = cls(ConnectorContext(config={"token": "synthetic-token"}, index=index))
    assert connector._clone(record, str(tmp_path))
    env = run.call_args.args[1]
    settings = {
        env[f"GIT_CONFIG_KEY_{n}"]: env[f"GIT_CONFIG_VALUE_{n}"] for n in range(int(env["GIT_CONFIG_COUNT"]))
    }
    assert "http.extraheader" not in settings
    assert settings[f"http.{origin}.extraheader"].startswith("Authorization: Basic ")
    assert settings["http.followRedirects"] == "false"
    assert "synthetic-token" not in " ".join(run.call_args.args[0])


def test_github_api_download_rejects_traversal_before_request(tmp_path, index):
    connector = GitHubConnector(ConnectorContext(index=index))
    connector.http = Mock()
    connector.http.try_get_json.return_value = {
        "tree": [{"path": "../escape.py", "type": "blob", "size": 10}]
    }
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


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",
        "169.254.169.254",
        "10.2.3.4",
        "[::1]",
        "[::ffff:127.0.0.1]",
        "100.64.0.1",
        "metadata.google.internal",
    ],
)
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

    resolver = Mock(
        side_effect=[
            [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 443))],
            [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 443))],
        ]
    )
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

    monkeypatch.setattr(
        "shadowscan.utils.http.socket.getaddrinfo",
        Mock(
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 443)),
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("10.0.0.1", 443)),
            ]
        ),
    )
    factory = Mock()
    monkeypatch.setattr("shadowscan.utils.http.socket.socket", factory)
    with pytest.raises(ValueError, match="Refusing"):
        _PublicHTTPSConnection("issuer.example", timeout=5)._new_conn()
    factory.assert_not_called()


def test_connect_rejects_rebinding_after_url_preflight(monkeypatch):
    import socket

    from shadowscan.utils.http import _PublicHTTPSConnection, validate_url

    resolver = Mock(
        side_effect=[
            [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 443))],
            [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("169.254.169.254", 443))],
        ]
    )
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
        public_pool = public.session.get_adapter("https://").poolmanager.connection_from_url(
            "https://example.com"
        )
        private_pool = private.session.get_adapter("https://").poolmanager.connection_from_url(
            "https://example.com"
        )
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
    result.iter_content = Mock(return_value=iter([b'{"keys":', b"[]}"]))
    result.close = Mock()
    http, session = client(result)
    assert http.get_json("/keys", max_bytes=16) == {"keys": []}
    assert session.request.call_args.kwargs["stream"] is True
    result.close.assert_called_once()


@pytest.mark.parametrize(
    "content_length,chunks", [("1000", []), (None, [b"x" * 9, b"y" * 9]), ("3", [b"x" * 17])]
)
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
    ],
)
def test_paginators_fail_closed_on_missing_or_invalid_collection(paginator, data, kwargs):
    http, _ = client(response(data))

    with pytest.raises(RuntimeError, match="collection"):
        list(getattr(http, paginator)("/items", **kwargs))


# TLS policy cannot be disabled through requests' other falsy settings.
@pytest.mark.parametrize("setting", [False, 0, "", []])
def test_falsy_per_request_tls_settings_never_reach_transport(setting):
    session = Mock(headers={}, verify=True)
    client = HttpClient("https://8.8.8.8", session=session)
    with pytest.raises(ValueError, match="TLS certificate verification"):
        client.get("/items", verify=setting)
    session.request.assert_not_called()


@pytest.mark.parametrize("setting", [False, None, 0, "", []])
def test_falsy_session_tls_settings_never_reach_transport(setting):
    session = Mock(headers={}, verify=setting)
    client = HttpClient("https://8.8.8.8", session=session)
    with pytest.raises(ValueError, match="TLS certificate verification"):
        client.get("/items")
    session.request.assert_not_called()


@pytest.mark.parametrize(
    "entry",
    [
        {"Authorization": "opaque-secret-value\n"},
        {"Authorization": "opaque-secret-value\rInjected: header"},
        {"Authorization": "opaque-secret-value\0"},
        {"Authorization": "opaque-secret-value\x7f"},
        {"Authorization": "opaque-secret-value\u2603"},
        {"opaque-secret-value\n": "value"},
        {"opaque-secret-value:bad": "value"},
        {"Authorization": ["opaque-secret-value"]},
    ],
)
@pytest.mark.parametrize("source", ["constructor", "injected", "override", "mutated"])
def test_invalid_header_never_echoes_credentials_or_reaches_transport(entry, source):
    session = Mock(headers={})
    with pytest.raises(ValueError) as failure:
        if source == "constructor":
            HttpClient("https://8.8.8.8", session=session, headers=entry)
        elif source == "injected":
            session.headers.update(entry)
            HttpClient("https://8.8.8.8", session=session)
        else:
            client = HttpClient("https://8.8.8.8", session=session)
            if source == "override":
                client.get("/items", headers=entry)
            else:
                session.headers.update(entry)
                client.get("/items")
    assert "opaque-secret-value" not in str(failure.value)
    session.request.assert_not_called()


def test_invalid_header_from_auth_handler_has_no_exposed_exception_chain():
    session = Mock(headers={})
    session.request.side_effect = requests.exceptions.InvalidHeader("opaque-secret-value")
    client = HttpClient("https://8.8.8.8", session=session)
    with pytest.raises(ValueError) as failure:
        client.get("/items")
    assert "opaque-secret-value" not in "".join(traceback.format_exception(failure.value))


def test_valid_byte_headers_and_request_header_removal_are_supported():
    session = requests.Session()
    response = requests.Response()
    response.status_code = 200
    response._content = b"{}"
    response._content_consumed = True
    session.send = Mock(return_value=response)
    client = HttpClient(
        "https://8.8.8.8",
        session=session,
        headers={"Authorization": "Bearer synthetic", "X-Label": b"caf\xe9"},
    )
    client.get("/items", headers={"Authorization": None, "X-Correlation-ID": "a\tb"})
    request = session.send.call_args.args[0]
    assert "Authorization" not in request.headers
    assert request.headers["X-Label"] == b"caf\xe9"


def test_http_client_rejects_control_characters_in_headers_without_echoing_them():
    with pytest.raises(ValueError) as failure:
        HttpClient("https://example.com", headers={"Authorization": "SSWS 00SuperSecret\n"})
    assert "SuperSecret" not in str(failure.value)


def test_link_pagination_reports_each_validated_page_to_the_callback():
    link = '<https://api.example.com/v1/items?page=2>; rel="next"'
    http, _ = client(
        response([{"id": 1}], headers={"Link": link, "X-Total": "2"}),
        response([{"id": 2}], headers={"X-Total": "2"}),
    )
    totals = []
    items = list(http.paginate_link("/items", on_page=lambda page: totals.append(page.headers["X-Total"])))
    assert [item["id"] for item in items] == [1, 2]
    assert totals == ["2", "2"]


def test_link_pagination_callback_never_sees_an_invalid_page():
    http, _ = client(response({"error": "denied"}))
    seen = []
    with pytest.raises(RuntimeError, match="collection failed"):
        list(http.paginate_link("/items", on_page=seen.append))
    assert seen == []


def test_get_json_reports_the_response_headers_once_the_body_is_decoded():
    http, session = client(response({"result": []}, headers={"X-Total-Count": "7"}))
    totals = []
    page = http.get_json(
        "/table", params={"q": "x"}, on_response=lambda resp: totals.append(resp.headers["X-Total-Count"])
    )
    assert page == {"result": []} and totals == ["7"]
    assert "on_response" not in session.request.call_args.kwargs


@pytest.mark.parametrize("failed", [response({"result": []}, status=403), response(None)])
def test_get_json_callback_never_sees_a_rejected_response(failed):
    if failed.status_code == 200:
        failed._content = b'{"result": [], "result": [1]}'  # an ambiguous body is rejected
    http, _ = client(failed)
    seen = []
    with pytest.raises((HttpError, ValueError)):
        http.get_json("/table", on_response=seen.append)
    assert seen == []


# ----------------------------------------------------------------- destination policy
@pytest.mark.parametrize(
    "address,blocked",
    [
        # Azure's wire server looks public but is the VM's own metadata endpoint; only that one address.
        ("168.63.129.16", True),
        ("168.63.129.15", False),
        ("168.63.129.17", False),
        # Deprecated site-local space: ipaddress calls it global, but it is routed inside some networks.
        ("fec0::1", True),
        ("fec0:0:0:1::1", True),
        ("feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", True),
        # Forms that carry a blocked IPv4 address stay blocked.
        ("::ffff:169.254.169.254", True),
        ("::ffff:a9fe:a9fe", True),
        ("::ffff:168.63.129.16", True),
        ("::ffff:127.0.0.1", True),
        ("2002:a9fe:a9fe::1", True),
        ("2002:a83f:8110::1", True),
        ("2002:7f00:1::", True),
        ("64:ff9b::a9fe:a9fe", True),
        ("64:ff9b::a83f:8110", True),
        ("64:ff9b::7f00:1", True),
        ("fd00:ec2::254", True),
        ("100.64.0.1", True),
        # Ordinary public addresses remain reachable.
        ("8.8.8.8", False),
        ("2606:4700:4700::1111", False),
    ],
)
def test_destination_policy_address_table(address, blocked):
    assert _blocked_ip(ipaddress.ip_address(address)) is blocked


@pytest.mark.parametrize(
    "host",
    ["168.63.129.16", "[fec0::1]", "[::ffff:168.63.129.16]", "[2002:a83f:8110::1]", "[64:ff9b::a9fe:a9fe]"],
)
def test_newly_listed_destinations_rejected_before_request(host):
    http, session = client()
    http.base_url = ""
    with pytest.raises(ValueError, match="Refusing"):
        http.get(f"https://{host}/credentials")
    session.request.assert_not_called()


class _Unflagged(ipaddress.IPv6Address):
    """An address whose own flags say ordinary global unicast: only the IPv4 address inside can block it."""

    is_global = True
    is_loopback = is_link_local = is_private = is_unspecified = False
    is_multicast = is_reserved = is_site_local = False


def _teredo(server: str, client_ip: str) -> str:
    value = (0x20010000 << 96) | (int(ipaddress.IPv4Address(server)) << 64)
    return str(ipaddress.IPv6Address(value | (int(ipaddress.IPv4Address(client_ip)) ^ 0xFFFFFFFF)))


@pytest.mark.parametrize(
    "address",
    [
        "::ffff:169.254.169.254",  # IPv4-mapped
        "::ffff:168.63.129.16",
        "2002:a9fe:a9fe::1",  # 6to4
        "2002:a83f:8110::1",
        _teredo("169.254.169.254", "8.8.8.8"),  # Teredo server
        _teredo("8.8.8.8", "169.254.169.254"),  # Teredo client
        _teredo("168.63.129.16", "8.8.8.8"),
    ],
)
def test_ipv4_inside_an_ipv6_wrapper_blocks_it(address):
    assert _blocked_ip(_Unflagged(address)) is True


@pytest.mark.parametrize("address", ["::ffff:8.8.8.8", "2002:0808:0808::1", _teredo("8.8.8.8", "1.1.1.1")])
def test_a_public_ipv4_inside_a_wrapper_does_not_block_it(address):
    assert _blocked_ip(_Unflagged(address)) is False


@pytest.mark.parametrize(
    "host", ["api.corp.internal", "printer.local", "API.CORP.INTERNAL.", "deep.sub.host.local", "a.internal"]
)
def test_internal_and_local_names_need_the_private_origin_opt_in(host, monkeypatch):
    assert _blocked_host(host)
    http, session = client()
    http.base_url = ""
    with pytest.raises(ValueError, match="Refusing"):
        http.get(f"https://{host}/x")
    session.request.assert_not_called()
    # Never resolve a .local name in a test: mDNS lookups can stall.
    monkeypatch.setattr("shadowscan.utils.http.socket.getaddrinfo", Mock(side_effect=socket.gaierror))
    assert validate_url(f"https://{host}/x", allow_private=True) == f"https://{host}/x"
    private = HttpClient("", session=Mock(headers={}), allow_private_origin=True)
    assert private._url(f"https://{host}/x") == f"https://{host}/x"


@pytest.mark.parametrize(
    "host", ["internal.example.com", "local.example.com", "notlocal", "myinternal", "locale.example"]
)
def test_names_that_merely_contain_internal_or_local_are_not_blocked(host, monkeypatch):
    monkeypatch.setattr("shadowscan.utils.http.socket.getaddrinfo", Mock(side_effect=socket.gaierror))
    assert not _blocked_host(host)
    assert validate_url(f"https://{host}/x") == f"https://{host}/x"


# ----------------------------------------------------------------- URL validation
@pytest.mark.parametrize(
    "url",
    [
        " https://api.example.com/x",
        "https://api.example.com/x ",
        "https://api.example.com/x\n",
        "\thttps://api.example.com/x",
        "https://api.example.com/\tx",
        "https://api.example.com/x\r\n",
        "https://api.exa\nmple.com/x",
        "https://api.example.com/a b",
        "https://api.example.com/x\x00",
        "https://api.example.com/x\x7f",
        "https://api.example.com/​x",
        "https://api.example.com/ x",
        "https://api.example.com/x ",
        "\x1bhttps://api.example.com/x",
    ],
    ids=lambda url: repr(url),
)
def test_urls_with_whitespace_or_control_characters_are_refused_not_cleaned(url):
    """urlsplit drops tabs and line breaks and strips leading blanks; git and libcurl do not."""
    with pytest.raises(ValueError, match="whitespace or control characters"):
        validate_url(url)
    with pytest.raises(ValueError, match="whitespace or control characters"):
        validate_url(url, "https://api.example.com", allow_private=True)


def test_a_valid_url_is_returned_exactly_as_validated():
    url = "https://api.example.com/v1/items?per_page=100&q=a%20b#frag"
    assert validate_url(url, "https://api.example.com") == url


@pytest.mark.parametrize(
    "url",
    [
        "http://api.example.com/items",
        "HTTP://API.EXAMPLE.COM/items",
        "ftp://api.example.com/x",
        "file:///etc/passwd",
        "//api.example.com/x",
        "api.example.com/x",
        "https:///x",
        "https://:443/x",
        "https://user:synthetic-pw@api.example.com/x",
        "https://user@api.example.com/x",
    ],
)
def test_only_https_urls_without_credentials_are_accepted(url):
    with pytest.raises(ValueError, match="HTTPS without embedded credentials"):
        validate_url(url)
    with pytest.raises(ValueError, match="HTTPS without embedded credentials"):
        validate_url(url, allow_private=True)  # the private-address opt-in never allows plain HTTP


def test_plain_http_base_url_is_refused_before_any_request():
    session = Mock(headers={})
    plain = HttpClient("http://api.example.com/v1", session=session)
    with pytest.raises(ValueError, match="HTTPS"):
        plain.get_json("/items")
    session.request.assert_not_called()


def test_clone_url_with_whitespace_is_refused_before_git_runs(tmp_path, index, monkeypatch):
    run = Mock()
    monkeypatch.setattr("shadowscan.connectors.code.remote.run_bounded_clone", run)
    connector = GitHubConnector(ConnectorContext(index=index))
    for url in (" https://github.com/org/repo.git", "https://github.com/org/repo.git\n"):
        with pytest.raises(ValueError, match="whitespace or control"):
            connector._clone({"full_name": "org/repo", "clone_url": url}, str(tmp_path))
    run.assert_not_called()


# ----------------------------------------------------------------- repository tree paths
@pytest.mark.parametrize(
    "path",
    [
        ".git/config",
        ".GIT/hooks/post-checkout",
        "sub/.git/config",
        "a/.Git",
        ".git",
        ".git ",
        ".git.",
        "x/.GIT./y",
        ".git  . .",
    ],
)
def test_repository_paths_never_name_a_git_directory(tmp_path, path):
    with pytest.raises(RuntimeError, match="Refusing unsafe repository tree path"):
        repository_target(str(tmp_path), path)


@pytest.mark.parametrize(
    "path",
    [
        ".github/workflows/ci.yml",
        ".gitignore",
        ".gitattributes",
        "docs/.gitkeep",
        "git/config",
        "my.git/x",
        "a/b.git",
        "a/.git.md",
        "gitignore",
    ],
)
def test_repository_paths_that_only_resemble_git_metadata_are_allowed(tmp_path, path):
    assert repository_target(str(tmp_path), path) == (tmp_path / path).resolve()


def test_github_api_snapshot_rejects_a_git_directory_before_any_download(tmp_path, index):
    connector = GitHubConnector(ConnectorContext(index=index))
    connector.http = Mock()
    connector.http.try_get_json.return_value = {
        "tree": [{"path": ".git/hooks/post-checkout.py", "type": "blob", "size": 10, "sha": "a" * 40}]
    }
    with pytest.raises(RuntimeError, match="Refusing unsafe repository tree path"):
        connector._fetch_via_api({"full_name": "org/repo"}, str(tmp_path))
    assert connector.http.try_get_json.call_count == 1  # the tree request only; no blob was requested
    assert not (tmp_path / "repo" / ".git").exists()


# ----------------------------------------------------------------- pagination limits
def _next(url):
    return {"@odata.nextLink": url}


def test_odata_pagination_that_never_ends_is_an_error_at_its_limit():
    http, session = client(
        response({"value": [{"id": 1}], **_next("https://api.example.com/v1/items?page=2")}),
        response({"value": [{"id": 2}], **_next("https://api.example.com/v1/items?page=3")}),
        response({"value": [{"id": 3}]}),
    )
    seen = []
    with pytest.raises(RuntimeError, match="Pagination limit reached; collection incomplete"):
        for item in http.paginate_odata("/items", max_pages=2):
            seen.append(item["id"])
    assert seen == [1, 2] and session.request.call_count == 2


def test_odata_pagination_that_ends_within_its_limit_is_complete():
    http, _ = client(
        response({"value": [{"id": 1}], **_next("https://api.example.com/v1/items?page=2")}),
        response({"value": [{"id": 2}]}),
    )
    assert [item["id"] for item in http.paginate_odata("/items", max_pages=2)] == [1, 2]


def test_token_pagination_that_never_ends_is_an_error_at_its_limit():
    http, session = client(
        *(response({"items": [{"id": n}], "nextPageToken": f"token-{n}"}) for n in range(1, 5))
    )
    seen = []
    with pytest.raises(RuntimeError, match="Pagination limit reached; collection incomplete"):
        for item in http.paginate_token("/items", max_pages=3):
            seen.append(item["id"])
    assert seen == [1, 2, 3] and session.request.call_count == 3


def test_token_pagination_that_ends_within_its_limit_is_complete():
    http, _ = client(
        response({"items": [{"id": 1}], "nextPageToken": "token-1"}),
        response({"items": [{"id": 2}]}),
    )
    assert [item["id"] for item in http.paginate_token("/items", max_pages=2)] == [1, 2]


# ----------------------------------------------------------------- errors never carry the body
def test_http_error_carries_no_response_body_anywhere():
    body = "synthetic-response-body-9f3c1a"
    http, _ = client(response({"message": body}, status=403))
    with pytest.raises(HttpError) as caught:
        http.get_json("/items")
    error = caught.value
    assert error.body == ""
    for text in (str(error), repr(error), repr(error.args), error.url):
        assert body not in text
    # A caller that hands a body to the constructor does not get it retained or printed either.
    direct = HttpError(500, "https://api.example.com/v1/items", body)
    assert direct.body == ""
    for text in (str(direct), repr(direct), repr(direct.args)):
        assert body not in text


def test_incomplete_scan_message_for_a_denied_request_has_no_body():
    body = "synthetic-response-body-9f3c1a"
    warnings = []
    http, _ = client(response({"message": body}, status=403), on_warning=warnings.append)
    assert http.try_get_json("/items", default=[]) == []
    assert warnings == ["Collection incomplete: HTTP 403 for /v1/items"]


@pytest.mark.parametrize("url", [None, b"https://api.example.com/x"])
def test_non_text_urls_are_rejected_as_not_https(url):
    with pytest.raises(ValueError, match="HTTPS"):
        validate_url(url)
