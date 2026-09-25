"""Ambiguous API JSON must not erase observations or redefine signing keys."""

from __future__ import annotations

import json
import traceback
from unittest.mock import Mock

import pytest
import requests

from shadowscan.utils.http import HttpClient
from shadowscan.utils.jwks import fetch_jwks


def response(body: bytes) -> requests.Response:
    result = requests.Response()
    result.status_code = 200
    result._content = body
    result._content_consumed = True
    result.close = Mock()
    return result


@pytest.mark.parametrize("paginator,key,kwargs", [
    ("paginate_link", "items", {"item_key": "items"}),
    ("paginate_odata", "value", {}),
    ("paginate_token", "items", {}),
    ("paginate_cursor", "results", {}),
])
def test_duplicate_collection_cannot_replace_detected_records_with_an_empty_inventory(paginator, key, kwargs):
    body = ('{"' + key + '":[{"id":"agent"}],"' + key + '":[]}').encode()
    result = response(body)
    session = Mock(headers={})
    session.request.return_value = result
    client = HttpClient("https://8.8.8.8", session=session)
    with pytest.raises(ValueError, match="Invalid JSON response"):
        list(getattr(client, paginator)("/items", **kwargs))
    result.close.assert_called_once()


@pytest.mark.parametrize("body", [
    b'{"items":[{"role":"administrator","role":"reader"}]}',
    b'{"items":[],"nextPageToken":"continue","nextPageToken":null}',
    b'{"items":[],"ok":false,"ok":true}',
    b'{"items":[],"\\u0069tems":[]}',
])
def test_duplicate_fields_are_rejected_after_decoding_names_and_at_every_depth(body):
    with pytest.raises(ValueError, match="Invalid JSON response"):
        HttpClient().read_json_response(response(body))


@pytest.mark.parametrize("number", ["NaN", "Infinity", "-Infinity", "1e309", "-1e309"])
@pytest.mark.parametrize("template", ['{"items":[{"score":%s}]}', '[%s]'])
def test_nonfinite_numbers_are_rejected_before_connector_analysis(number, template):
    with pytest.raises(ValueError, match="Invalid JSON response"):
        HttpClient().read_json_response(response((template % number).encode()))


def test_duplicate_field_diagnostics_do_not_reflect_provider_data():
    secret = "provider-reflected-opaque-secret"
    body = json.dumps({secret: "first"})[:-1] + "," + json.dumps(secret) + ':"second"}'
    with pytest.raises(ValueError, match="Invalid JSON response") as caught:
        HttpClient().read_json_response(response(body.encode()))
    assert secret not in "".join(traceback.format_exception(caught.value))


def test_valid_json_preserves_finite_numeric_and_collection_types():
    expected = {"items": [{"count": 7, "score": 1.5e2, "tiny": 1e-300, "active": True}], "nextPageToken": None}
    assert HttpClient().read_json_response(response(json.dumps(expected).encode())) == expected


@pytest.mark.parametrize("body", [
    b'{"keys":[{"kid":"original"}],"keys":[]}',
    b'{"keys":[{"kid":"original","kid":"replacement"}]}',
])
def test_jwks_documents_inherit_ambiguous_json_rejection(body, monkeypatch):
    result = response(body)
    transport = Mock(return_value=result)
    monkeypatch.setattr(requests.Session, "request", transport)
    with pytest.raises(ValueError, match="Invalid JSON response"):
        fetch_jwks("https://8.8.8.8/jwks")
    transport.assert_called_once()
    result.close.assert_called_once()
