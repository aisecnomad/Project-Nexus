"""Strict decoding at ancillary report, policy, CLI and credential boundaries."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import jwt
import pytest

import shadowscan.connectors.identity.google_workspace as google_workspace
from shadowscan.comparison import load_report
from shadowscan.config import parse_set_options
from shadowscan.connectors.base import ConnectorError
from shadowscan.connectors.identity.google_workspace import SCOPES, _dwd_token
from shadowscan.registry import Inventory, InventoryValidationError


@pytest.mark.parametrize("number", ["NaN", "Infinity", "-Infinity", "1e999", "-1e999"])
def test_imported_reports_reject_nonfinite_numbers_anywhere(tmp_path: Path, number: str) -> None:
    report = tmp_path / "report.json"
    report.write_text(
        '{"findings":[],"stats":[{"connector":"code.filesystem","objects_examined":' + number + "}]}",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="finite"):
        load_report(report)


@pytest.mark.parametrize(
    ("suffix", "document"),
    [
        (
            "json",
            '{"metadata":{"agent_id":"approved","private-extension":1e999},'
            '"discovery":{"resources":["agent-one"]}}',
        ),
        (
            "yaml",
            "metadata:\n  agent_id: approved\n  private-extension: .nan\n"
            "discovery:\n  resources: [agent-one]\n",
        ),
    ],
)
def test_inventory_extensions_cannot_retain_nonfinite_numbers(
    tmp_path: Path, suffix: str, document: str
) -> None:
    path = tmp_path / f"inventory.{suffix}"
    path.write_text(document, encoding="utf-8")

    with pytest.raises(InventoryValidationError) as raised:
        Inventory.load([path])

    assert "invalid syntax or duplicate mapping key" in str(raised.value)
    assert "private-extension" not in str(raised.value)


@pytest.mark.parametrize(
    "value",
    [
        '{"scope":"first","scope":"second"}',
        '{"scope":NaN}',
        '{"scope":Infinity}',
        '{"scope":1e999}',
        "[1e999]",
    ],
)
def test_structured_set_values_reject_ambiguous_or_nonfinite_json(value: str) -> None:
    with pytest.raises(ValueError, match="unique fields and finite numbers"):
        parse_set_options([f"metadata={value}"])


@pytest.mark.parametrize(
    "document",
    [
        '{"client_email":"service@example.test","private_key":"key",'
        '"token_uri":"https://oauth2.googleapis.com/token",'
        '"token_uri":"https://attacker.example/token"}',
        '{"client_email":"service@example.test","private_key":"key","private-extension":1e999}',
    ],
)
def test_workspace_service_account_json_fails_closed_without_echoing_values(
    tmp_path: Path, document: str
) -> None:
    key = tmp_path / "service-account.json"
    key.write_text(document, encoding="utf-8")

    with pytest.raises(ConnectorError, match="service account key is unreadable or invalid") as raised:
        _dwd_token(key, "admin@example.test", SCOPES)

    assert "attacker.example" not in str(raised.value)
    assert "private-extension" not in str(raised.value)


def test_workspace_service_account_cannot_redirect_signed_assertion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = tmp_path / "service-account.json"
    key.write_text(
        '{"client_email":"service@example.test","private_key":"synthetic-key",'
        '"private_key_id":"key-id","token_uri":"https://attacker.example/token"}',
        encoding="utf-8",
    )
    observed: dict[str, Any] = {}

    def encode(payload: dict[str, Any], key: str, **kwargs: Any) -> str:
        observed.update(payload=payload, key=key, encode_kwargs=kwargs)
        return "signed-assertion"

    class Client:
        def post(self, url: str, *, data: dict[str, str]) -> object:
            observed.update(url=url, post_data=data)
            return object()

        def read_json_response(self, response: object) -> dict[str, str]:
            observed["response"] = response
            return {"access_token": "google-token"}

    monkeypatch.setattr(jwt, "encode", encode)
    monkeypatch.setattr(google_workspace, "HttpClient", Client)

    assert _dwd_token(key, "admin@example.test", SCOPES) == "google-token"
    assert observed["url"] == "https://oauth2.googleapis.com/token"
    assert observed["payload"]["aud"] == "https://oauth2.googleapis.com/token"
    assert "attacker.example" not in str(observed)
