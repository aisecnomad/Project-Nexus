"""Response resource budgets and fail-closed API pagination contracts."""

from __future__ import annotations

import gzip
import json
import socket
import time
from io import BytesIO
from unittest.mock import Mock

import pytest
import requests
from requests.adapters import HTTPAdapter
from urllib3.response import HTTPResponse

from shadowscan.utils.http import (
    DEFAULT_MAX_RESPONSE_BYTES,
    HttpClient,
    HttpError,
    _DestinationPolicyAdapter,
    _PublicHTTPSConnection,
    _SocketDeadline,
)


def response(data=None, *, status=200, headers=None):
    result = requests.Response()
    result.status_code = status
    result._content = json.dumps(data).encode()
    result._content_consumed = True
    result.headers.update(headers or {})
    result.close = Mock()
    return result


def client(*responses, **kwargs):
    session = Mock(headers={})
    session.request.side_effect = responses
    return HttpClient("https://8.8.8.8", session=session, **kwargs), session


@pytest.mark.parametrize("value", [None, 0, 1, "false", []])
def test_invalid_stream_flag_cannot_change_response_policy(value):
    http, session = client(response([]))
    with pytest.raises(ValueError, match="stream must be a boolean"):
        http.get("/items", stream=value)
    session.request.assert_not_called()


@pytest.mark.parametrize("operation", ["get", "post", "get_json", "post_json", "paginate_link"])
def test_all_default_response_paths_reject_oversized_body_before_reading(operation):
    result = response([], headers={"Content-Length": str(DEFAULT_MAX_RESPONSE_BYTES + 1)})
    result.iter_content = Mock()
    http, session = client(result)
    with pytest.raises(ValueError, match="byte limit"):
        output = getattr(http, operation)("/items")
        if operation == "paginate_link":
            list(output)
    assert session.request.call_args.kwargs["stream"] is True
    result.iter_content.assert_not_called()
    result.close.assert_called_once()


@pytest.mark.parametrize("operation", ["get", "post", "get_json", "post_json", "paginate_link"])
@pytest.mark.parametrize("headers", [{}, {"Content-Length": "2"}])
def test_response_budget_counts_actual_chunks_even_when_length_is_missing_or_false(operation, headers):
    result = response([], headers=headers)
    result.iter_content = Mock(return_value=iter([b"[", b" " * 16, b"]"]))
    http, _ = client(result, max_response_bytes=16)
    with pytest.raises(ValueError, match="byte limit"):
        output = getattr(http, operation)("/items")
        if operation == "paginate_link":
            list(output)
    result.close.assert_called_once()


def test_budget_applies_after_real_gzip_decoding():
    compressed = gzip.compress(b" " * 128)
    result = response(headers={"Content-Length": str(len(compressed))})
    result._content = False
    result._content_consumed = False
    result.raw = HTTPResponse(
        body=BytesIO(compressed),
        headers={"Content-Encoding": "gzip"},
        preload_content=False,
    )
    http, _ = client(result, max_response_bytes=64)
    with pytest.raises(ValueError, match="byte limit"):
        http.get_json("/items")
    result.close.assert_called_once()


@pytest.mark.parametrize("status", [302, 429, 503, 403])
def test_discarded_response_bodies_are_never_buffered(status, monkeypatch):
    result = response(status=status, headers={"Location": "/next"})
    result.iter_content = Mock(side_effect=AssertionError("must not consume discarded body"))
    http, session = client(result, response({"ok": True}))
    monkeypatch.setattr("shadowscan.utils.http.time.sleep", Mock())
    if status == 403:
        with pytest.raises(HttpError):
            http.get_json("/items")
    else:
        assert http.get_json("/items") == {"ok": True}
    assert all(call.kwargs["stream"] is True for call in session.request.call_args_list)
    result.iter_content.assert_not_called()
    result.close.assert_called_once()


@pytest.mark.parametrize("operation", ["get_json", "post_json"])
def test_json_helpers_close_invalid_json_without_reflecting_response_body(operation):
    result = response()
    result._content = b"opaque-secret-reflected-by-provider"
    http, _ = client(result)
    with pytest.raises(ValueError, match="Invalid JSON response") as caught:
        getattr(http, operation)("/items")
    assert "opaque-secret" not in str(caught.value)
    result.close.assert_called_once()


def test_raw_response_retains_bounded_content_after_closing_transport():
    result = response({"ok": True})
    http, _ = client(result)
    assert http.get("/items").json() == {"ok": True}
    result.close.assert_called_once()


@pytest.mark.parametrize(
    "headers,expected_range",
    [
        # A malformed hint falls back to the jittered exponential step for attempt 1.
        ({"Retry-After": "²"}, (1, 2)),
        ({"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "9" * 5000}, (120, 120)),
    ],
)
def test_malformed_or_extreme_retry_headers_remain_bounded_and_close_response(
    headers, expected_range, monkeypatch
):
    first = response(status=429, headers=headers)
    http, _ = client(first, response({"ok": True}))
    sleep = Mock()
    monkeypatch.setattr("shadowscan.utils.http.time.sleep", sleep)
    assert http.get_json("/items") == {"ok": True}
    sleep.assert_called_once()
    (delay,), _ = sleep.call_args
    assert expected_range[0] <= delay <= expected_range[1]
    first.close.assert_called_once()


@pytest.mark.parametrize("limit", [False, 0, -1, 1.2, "1024"])
def test_invalid_client_response_budget_rejected(limit):
    with pytest.raises(ValueError, match="positive integer"):
        HttpClient(max_response_bytes=limit)


def test_injected_session_cannot_keep_a_longer_prefix_transport_adapter():
    session = requests.Session()
    legacy = HTTPAdapter()
    session.mount("https://service.example/private", legacy)
    session.mount("HTTPS://service.example", legacy)
    session.mount("https", legacy)
    legacy.close = Mock()
    http = HttpClient(session=session)
    try:
        adapter = http.session.get_adapter("https://service.example/private/items")
        assert isinstance(adapter, _DestinationPolicyAdapter)
        assert set(session.adapters) == {"https://"}
        pool = adapter.poolmanager.connection_from_url("https://service.example")
        assert pool.ConnectionCls is _PublicHTTPSConnection
        legacy.close.assert_called_once()
    finally:
        session.close()


def test_late_dns_resolution_cannot_start_a_connection_after_acquisition_deadline(monkeypatch):
    def resolve(*args, **kwargs):
        # DNS is synchronous and cannot be forcibly cancelled; nevertheless
        # its result must never authorize a connection after the budget expires.
        time.sleep(0.1)
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 443))]

    monkeypatch.setattr("shadowscan.utils.http.socket.getaddrinfo", resolve)
    create_socket = Mock(side_effect=AssertionError("must not connect after late DNS"))
    monkeypatch.setattr("shadowscan.utils.http.socket.socket", create_socket)
    connection = _PublicHTTPSConnection("service.example", timeout=1)
    guard = _SocketDeadline(connection, time.monotonic() + 0.05)
    connection.acquisition_guard = guard
    try:
        with pytest.raises(ValueError, match="acquisition deadline"):
            connection._new_conn()
    finally:
        guard.finish()
        connection.acquisition_guard = None
    create_socket.assert_not_called()


PAGINATORS = [
    ("paginate_link", {"item_key": "items"}, "items"),
    ("paginate_odata", {}, "value"),
    ("paginate_token", {}, "items"),
]


@pytest.mark.parametrize("paginator,kwargs,key", PAGINATORS)
@pytest.mark.parametrize("body", [{}, None, [], {"error": "opaque-secret"}])
def test_paginated_envelopes_must_contain_expected_collection(paginator, kwargs, key, body):
    http, _ = client(response(body))
    with pytest.raises(RuntimeError, match="collection incomplete") as caught:
        list(getattr(http, paginator)("/items", **kwargs))
    assert "opaque-secret" not in str(caught.value)


@pytest.mark.parametrize("paginator,kwargs,key", PAGINATORS)
@pytest.mark.parametrize("items", [None, "", {}, ["record"], [None], [1]])
def test_paginated_items_must_be_arrays_of_objects(paginator, kwargs, key, items):
    http, _ = client(response({key: items}))
    with pytest.raises(RuntimeError, match="collection incomplete"):
        list(getattr(http, paginator)("/items", **kwargs))


@pytest.mark.parametrize("paginator,kwargs,key", PAGINATORS)
def test_explicit_empty_collections_are_valid(paginator, kwargs, key):
    result = response({key: []})
    http, _ = client(result)
    assert list(getattr(http, paginator)("/items", **kwargs)) == []
    result.close.assert_called_once()


@pytest.mark.parametrize("paginator,kwargs,key", PAGINATORS)
def test_error_envelope_with_empty_items_cannot_claim_complete(paginator, kwargs, key):
    http, _ = client(response({key: [], "error": "opaque-secret-reflected-by-provider"}))
    with pytest.raises(RuntimeError, match="collection incomplete") as caught:
        list(getattr(http, paginator)("/items", **kwargs))
    assert "opaque-secret" not in str(caught.value)


@pytest.mark.parametrize("token", [False, 0, [], {}, 123, " "])
@pytest.mark.parametrize(
    "paginator,key,continuation",
    [
        ("paginate_odata", "value", "@odata.nextLink"),
        ("paginate_token", "items", "nextPageToken"),
    ],
)
def test_continuations_cannot_coerce_malformed_values_to_end_of_collection(
    paginator, key, continuation, token
):
    http, _ = client(response({key: [], continuation: token}))
    with pytest.raises(RuntimeError, match="collection incomplete"):
        list(getattr(http, paginator)("/items"))


def test_google_empty_collection_exception_requires_documented_kind():
    http, _ = client(response({"kind": "admin#directory#users", "etag": "opaque-etag"}))
    assert (
        list(http.paginate_token("/users", items_key="users", expected_empty_kind="admin#directory#users"))
        == []
    )


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"kind": "unexpected"},
        {"kind": "admin#directory#users", "nextPageToken": "next"},
        {"kind": "admin#directory#users", "error": "denied"},
        {"kind": "admin#directory#users", "users": None},
        {"kind": "admin#directory#users", "ok": False},
    ],
)
def test_google_empty_collection_exception_does_not_suppress_malformed_pages(body):
    http, _ = client(response(body))
    with pytest.raises(RuntimeError, match="collection incomplete"):
        list(http.paginate_token("/users", items_key="users", expected_empty_kind="admin#directory#users"))


def test_token_post_pagination_is_bounded_and_preserves_request_body():
    http, session = client(
        response({"items": [{"id": 1}], "nextPageToken": "next"}),
        response({"items": [{"id": 2}]}),
    )
    original = {"filter": "agents"}
    assert list(http.paginate_token("/items", method="POST", body=original)) == [{"id": 1}, {"id": 2}]
    assert original == {"filter": "agents"}
    assert session.request.call_args.kwargs["json"] == {"filter": "agents", "pageToken": "next"}
    assert all(call.kwargs["stream"] is True for call in session.request.call_args_list)


@pytest.mark.parametrize("operation", ["get", "post"])
def test_explicit_buffered_calls_cannot_disable_the_transport_body_limit(operation):
    result = response(headers={"Content-Length": "17"})
    result.iter_content = Mock()
    http, session = client(result, max_response_bytes=16)
    with pytest.raises(ValueError, match="byte limit"):
        getattr(http, operation)("/items", stream=False)
    assert session.request.call_args.kwargs["stream"] is True
    result.iter_content.assert_not_called()
    result.close.assert_called_once()


@pytest.mark.parametrize("helper", ["read_response_bytes", "read_json_response"])
def test_public_stream_read_helpers_enforce_the_client_default_limit(helper):
    result = response(headers={"Content-Length": "17"})
    result.iter_content = Mock()
    http, _ = client(max_response_bytes=16)
    with pytest.raises(ValueError, match="byte limit"):
        getattr(http, helper)(result)
    result.iter_content.assert_not_called()
    result.close.assert_called_once()


def test_public_json_reader_supports_documented_explicit_limit_for_streamed_oauth_response():
    result = response({"access_token": "synthetic-token"})
    http, session = client(result, max_response_bytes=8)
    stream = http.post("/oauth/token", stream=True, data={"grant_type": "client_credentials"})
    assert http.read_json_response(stream, max_bytes=64) == {"access_token": "synthetic-token"}
    assert session.request.call_args.kwargs["stream"] is True
    result.close.assert_called_once()


@pytest.mark.parametrize("status", [429, 500, 503])
def test_retry_opt_out_does_not_repeat_oauth_posts(status, monkeypatch):
    result = response(status=status)
    http, session = client(result, max_retries=0)
    sleep = Mock()
    monkeypatch.setattr("shadowscan.utils.http.time.sleep", sleep)
    with pytest.raises(HttpError):
        http.post_json("/oauth/token", data={"grant_type": "client_credentials"})
    assert session.request.call_count == 1
    sleep.assert_not_called()
    result.close.assert_called_once()


@pytest.mark.parametrize("length", ["²", "-1", "1.0", "", "9" * 5000])
def test_public_reader_rejects_malformed_or_extreme_content_length_without_reading(length):
    result = response(headers={"Content-Length": length})
    result.iter_content = Mock()
    http, _ = client(max_response_bytes=16)
    with pytest.raises(ValueError):
        http.read_response_bytes(result)
    result.iter_content.assert_not_called()
    result.close.assert_called_once()


def test_public_reader_accepts_padded_content_length():
    result = response([], headers={"Content-Length": "0" * 5000 + "2"})
    http, _ = client(max_response_bytes=16)
    assert http.read_response_bytes(result) == b"[]"
    result.close.assert_called_once()


@pytest.mark.parametrize("invalid_chunk", ["text", None, False])
def test_public_reader_rejects_nonbyte_chunks(invalid_chunk):
    result = response()
    result.iter_content = Mock(return_value=iter([invalid_chunk]))
    http, _ = client()
    with pytest.raises(ValueError, match="Invalid HTTP response chunk"):
        http.read_response_bytes(result)
    result.close.assert_called_once()


def test_public_reader_closes_response_if_per_call_limit_is_invalid():
    result = response()
    http, _ = client()
    with pytest.raises(ValueError, match="positive integer"):
        http.read_response_bytes(result, max_bytes=0)
    result.close.assert_called_once()
