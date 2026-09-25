"""Trust-boundary regressions while consolidating independent review branches."""

from __future__ import annotations

import traceback
from unittest.mock import Mock

import pytest
import requests

from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.registry import Inventory, InventoryEntry
from shadowscan.utils import redaction
from shadowscan.utils.http import HttpClient


def _finding():
    return Finding(surface=Surface.CODE, connector="code.filesystem", kind=Kind.AGENT,
                   title="sample", resource="repo:sample", resource_type="repository")


@pytest.mark.parametrize("entry", [
    {"Authorization": "opaque-secret-value\n"},
    {"Authorization": "opaque-secret-value\rInjected: header"},
    {"Authorization": "opaque-secret-value\0"},
    {"Authorization": "opaque-secret-value\x7f"},
    {"Authorization": "opaque-secret-value\u2603"},
    {"opaque-secret-value\n": "value"},
    {"opaque-secret-value:bad": "value"},
    {"Authorization": ["opaque-secret-value"]},
])
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
    client = HttpClient("https://8.8.8.8", session=session,
                        headers={"Authorization": "Bearer synthetic", "X-Label": b"caf\xe9"})
    client.get("/items", headers={"Authorization": None, "X-Correlation-ID": "a\tb"})
    request = session.send.call_args.args[0]
    assert "Authorization" not in request.headers
    assert request.headers["X-Label"] == b"caf\xe9"


@pytest.mark.parametrize("field", ["score", "factor", "evidence", "confidence"])
@pytest.mark.parametrize("value", [True, False, None, "opaque-secret-value", [], {}, float("nan"), float("inf")])
def test_finding_import_rejects_malformed_numeric_fields_without_echoing_them(field, value):
    payload = _finding().to_dict()
    if field == "score":
        payload["risk"]["score"] = value
    elif field == "factor":
        payload["risk"]["factors"] = [{"id": "test", "description": "test", "weight": value}]
    elif field == "evidence":
        payload["evidence"] = [{"signal": "test", "description": "test", "weight": value}]
    else:
        payload["confidence"] = value
    with pytest.raises(ValueError) as failure:
        Finding.from_dict(payload)
    assert "opaque-secret-value" not in str(failure.value)


@pytest.mark.parametrize("risk", [False, 0, [], ""])
def test_empty_malformed_risk_cannot_masquerade_as_missing(risk):
    payload = _finding().to_dict()
    payload["risk"] = risk
    with pytest.raises(ValueError, match="risk must be an object"):
        Finding.from_dict(payload)


@pytest.mark.parametrize("field,value", [("score", -1), ("score", 101), ("confidence", -0.1),
                                         ("confidence", 1.1), ("evidence", -0.1), ("evidence", 1.1)])
def test_finding_import_rejects_out_of_range_scores(field, value):
    payload = _finding().to_dict()
    if field == "score":
        payload["risk"]["score"] = value
    elif field == "evidence":
        payload["evidence"] = [{"signal": "test", "description": "test", "weight": value}]
    else:
        payload["confidence"] = value
    with pytest.raises(ValueError, match="range"):
        Finding.from_dict(payload)


def test_finding_sanitization_does_not_serialize_alias_dags_before_budget_check():
    finding = _finding()
    value = {"label": "ordinary"}
    for _ in range(12):
        value = {"children": [value] * 10}
    finding.metadata = value
    with pytest.raises(redaction.SanitizationLimitError, match="expanded output"):
        finding.sanitize()


def test_repeated_finding_sanitization_observes_new_redaction_policy(monkeypatch):
    finding = _finding()
    finding.metadata["new_secret_format"] = "opaque-secret-value"
    finding.evidence.append(Evidence("test", "opaque-secret-value"))
    finding.sanitize()
    monkeypatch.setattr(redaction, "_SENSITIVE_NAMES", redaction._SENSITIVE_NAMES | {"newsecretformat"})
    finding.sanitize()
    assert finding.metadata["new_secret_format"] == redaction.REDACTED
    assert finding.evidence[0].description == redaction.REDACTED


def test_repeated_sanitization_observes_lowered_resource_budgets(monkeypatch):
    value = "plain text with no credentials"
    assert redaction.sanitize_text(value) == value
    monkeypatch.setattr(redaction, "_MAX_SANITIZATION_CHARS", 1)
    with pytest.raises(redaction.SanitizationLimitError, match="size limit"):
        redaction.sanitize_text(value)


def test_inventory_pattern_cache_is_bounded_and_does_not_confer_approval(monkeypatch):
    monkeypatch.setattr("shadowscan.registry._MAX_NAME_PATTERNS", 2)
    inventory = Inventory([InventoryEntry(agent_id="sample", resources=["elsewhere:*"])])
    finding = _finding()
    assert inventory.suggest(finding)
    for name in ("second", "third", "fourth"):
        inventory._name_pattern(name)
    assert len(inventory._name_patterns) == 2
    assert inventory.suggest(finding)
    assert not inventory.match(finding)
