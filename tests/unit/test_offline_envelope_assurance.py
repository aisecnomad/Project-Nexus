"""An offline page cannot claim completeness through resource-shaped labels."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.connectors.base import BaseConnector


@pytest.mark.parametrize("label", [
    {"type": "collection"}, {"object": "collection"},
    {"type": "app"}, {"id": "page-1", "name": "listed apps"},
])
def test_labeled_page_with_continuation_is_incomplete(tmp_path: Path, label: dict) -> None:
    source = tmp_path / "export.json"
    source.write_text(json.dumps({**label, "items": [
        {"_kind": "approved_app", "app": {"id": "A1", "name": "Claude"}, "scopes": []},
    ], "next_cursor": "opaque-page-token"}), encoding="utf-8")
    result = CliRunner().invoke(main, [
        "run", "saas.slack", "--input", str(source), "--format", "json", "--set", "team_id=T1",
    ])
    assert result.exit_code == 3, result.output
    report = json.loads(result.stdout)
    assert report["summary"]["complete"] is False
    assert len(report["findings"]) == 1
    assert "opaque-page-token" not in result.output


def test_collection_data_and_nested_error_page_are_not_native_records() -> None:
    item = {"id": "observed-app"}
    errors: list[str] = []
    assert list(BaseConnector._unwrap({
        "object": "collection", "data": [item], "next_cursor": "next-page",
    }, errors.append)) == [item]
    assert errors == ["offline export contains an uncollected next page"]

    errors.clear()
    page = {"id": "failed-page", "error": {"message": "denied"},
            "data": [{"timestamp": "2026-01-01", "items": [item]}]}
    assert list(BaseConnector._unwrap(page, errors.append)) == [page["data"][0]]
    assert errors == ["provider error response in offline export; coverage is incomplete"]


# Page identities and malformed successful responses must not hide collection gaps.
_APP = {"_kind": "approved_app", "app": {"id": "A1", "name": "Claude"}, "scopes": []}


def _cli_scan(tmp_path, connector: str, body: object):
    source = tmp_path / "export.json"
    report = tmp_path / "report.json"
    source.write_text(json.dumps(body), encoding="utf-8")
    outcome = CliRunner().invoke(
        main, ["run", connector, "--input", str(source), "--format", "json", "-o", str(report), "--fail-on", "high"]
        + (["--set", "team_id=T1"] if connector == "saas.slack" else [])
    )
    return outcome, json.loads(report.read_text(encoding="utf-8"))


@pytest.mark.parametrize("connector,record", [
    ("saas.slack", _APP),
    ("identity.entra", {"_kind": "servicePrincipal", "id": "sp-1", "appId": "app-1", "displayName": "Claude"}),
    ("lowcode.power-platform", {"_kind": "bot", "botid": "bot-1", "name": "Claude Agent"}),
])
def test_id_on_export_envelope_does_not_hide_items(tmp_path, connector, record):
    outcome, report = _cli_scan(tmp_path, connector, {"id": "export-1", "items": [record]})
    assert outcome.exit_code in {0, 2}, outcome.output
    assert report["summary"]["complete"] is True
    assert len(report["findings"]) == 1
    assert not report["stats"][0]["incomplete"]


@pytest.mark.parametrize("connector", ["saas.slack", "identity.entra", "lowcode.power-platform"])
@pytest.mark.parametrize("body", [
    {"id": "export-1", "error": {"code": "access_denied", "message": "synthetic denied"}},
    {"id": "export-1", "ok": False, "error": "access_denied"},
    {"id": "export-1", "name": "OpenAI", "error": "access_denied"},
    {"object": "error", "error": "access_denied"},
    {"id": "export-1", "items": [], "error": "access_denied"},
])
def test_provider_error_with_page_id_is_incomplete_for_cli(tmp_path, connector, body):
    outcome, report = _cli_scan(tmp_path, connector, body)
    assert outcome.exit_code == 3, outcome.output
    assert report["summary"]["complete"] is False
    assert not report["findings"]
    assert report["stats"][0]["incomplete"] and report["stats"][0]["errors"]


def test_export_error_keeps_valid_items_without_claiming_completeness(tmp_path):
    outcome, report = _cli_scan(tmp_path, "saas.slack", {"id": "export-1", "error": "later page denied", "items": [_APP]})
    assert outcome.exit_code == 3, outcome.output
    assert report["summary"]["complete"] is False
    assert len(report["findings"]) == 1


def test_id_on_explicit_empty_envelope_is_complete(tmp_path):
    outcome, report = _cli_scan(tmp_path, "saas.slack", {"id": "export-1", "items": []})
    assert outcome.exit_code == 0, outcome.output
    assert report["summary"]["complete"] is True
    assert not report["findings"]


def test_labelled_export_items_are_unwrapped(tmp_path):
    outcome, report = _cli_scan(tmp_path, "saas.slack", {"name": "export-1", "items": [_APP]})
    assert outcome.exit_code in {0, 2}, outcome.output
    assert len(report["findings"]) == 1 and report["summary"]["complete"] is True


def test_jsonl_error_with_request_id_is_incomplete_and_preserves_neighbor(tmp_path):
    source = tmp_path / "export.jsonl"
    output = tmp_path / "report.json"
    source.write_text(json.dumps({"error": "permission denied", "id": "req1"}) + "\n" + json.dumps(_APP) + "\n")
    outcome = CliRunner().invoke(
        main, ["run", "saas.slack", "--input", str(source), "--format", "json", "-o", str(output), "--fail-on", "high", "--set", "team_id=T1"]
    )
    report = json.loads(output.read_text())
    assert outcome.exit_code == 3, outcome.output
    assert len(report["findings"]) == 1 and report["summary"]["complete"] is False


def test_csv_error_row_is_incomplete_and_preserves_valid_neighbor(tmp_path):
    source = tmp_path / "export.csv"
    output = tmp_path / "report.json"
    source.write_text("id,name,error\napp1,Claude,\nreq1,,permission denied\n")
    outcome = CliRunner().invoke(
        main, ["run", "saas.generic", "--input", str(source), "--format", "json", "-o", str(output), "--fail-on", "high"]
    )
    report = json.loads(output.read_text())
    assert outcome.exit_code == 3, outcome.output
    assert len(report["findings"]) == 1 and report["summary"]["complete"] is False


@pytest.mark.parametrize("connector,record", [
    ("saas.microsoft-teams", {
        "_kind": "teamsApp", "id": "A1", "displayName": "OpenAI", "distributionMethod": "organization",
        "error": "access_denied",
    }),
    ("saas.generic", {"_kind": "saas-app", "id": "A1", "name": "Claude", "error": "access_denied"}),
])
@pytest.mark.parametrize("as_array", [False, True])
def test_typed_provider_error_is_not_a_complete_native_app(tmp_path, connector, record, as_array):
    outcome, report = _cli_scan(tmp_path, connector, [record] if as_array else record)
    assert outcome.exit_code == 3, outcome.output
    assert report["summary"]["complete"] is False
    assert report["findings"] == []


def test_failed_nested_page_keeps_observed_items_but_marks_incomplete(tmp_path):
    another = {"_kind": "approved_app", "app": {"id": "A2", "name": "Claude"}, "scopes": []}
    outcome, report = _cli_scan(tmp_path, "saas.slack", [_APP, {"id": "req1", "error": "denied", "items": [another]}])
    assert outcome.exit_code == 3, outcome.output
    assert report["summary"]["complete"] is False
    assert len(report["findings"]) == 2
