"""An empty page must not turn a partial provider export into a clean scan."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.connectors.base import BaseConnector


@pytest.mark.parametrize("pagination", [
    {"response_metadata": {"next_cursor": "opaque-page-secret"}},
    {"next_cursor": "opaque-page-secret"},
    {"IsTruncated": True},
    {"NextMarker": "opaque-page-secret"},
])
@pytest.mark.parametrize("suffix", ["json", "jsonl", "yaml"])
def test_partial_slack_export_is_incomplete(tmp_path, pagination, suffix):
    import yaml

    source = tmp_path / f"partial.{suffix}"
    body = {"ok": True, "approved_apps": [], **pagination}
    source.write_text(yaml.safe_dump(body) if suffix == "yaml" else json.dumps(body))
    result = CliRunner().invoke(main, ["run", "saas.slack", "--input", str(source), "--format", "json"])

    assert result.exit_code == 3, result.output
    report = json.loads(result.stdout)
    assert report["summary"]["complete"] is False
    assert report["findings"] == []
    assert "uncollected next page" in result.output
    assert "opaque-page-secret" not in result.output


@pytest.mark.parametrize("pagination", [
    {"response_metadata": []},
    {"response_metadata": {"next_cursor": []}},
    {"next_cursor": False},
    {"has_more": 0},
    {"IsTruncated": None},
])
def test_malformed_pagination_preserves_observed_records(pagination):
    errors = []
    record = {"id": "observed-agent"}
    assert list(BaseConnector._unwrap({"items": [record], **pagination}, errors.append)) == [record]
    assert errors == ["offline export has invalid pagination metadata"]


@pytest.mark.parametrize("key", [
    "next_page_token", "nextPageToken", "nextToken", "NextToken", "NextMarker",
    "@odata.nextLink", "nextLink", "nextCursor", "next_cursor", "next_page", "nextPage",
])
@pytest.mark.parametrize("value", [False, 0, [], {}])
def test_falsey_malformed_cursors_cannot_attest_complete_collection(key, value):
    errors = []
    assert list(BaseConnector._unwrap({"items": [], key: value}, errors.append)) == []
    assert errors == ["offline export has invalid pagination metadata"]


@pytest.mark.parametrize("key", ["next_page", "nextPage"])
@pytest.mark.parametrize("value", [2, "2", "https://example.test/items?page=2"])
def test_page_number_and_link_continuations_remain_incomplete(key, value):
    errors = []
    assert list(BaseConnector._unwrap({"items": [], key: value}, errors.append)) == []
    assert errors == ["offline export contains an uncollected next page"]


@pytest.mark.parametrize("pagination", [
    {},
    {"response_metadata": {}},
    {"response_metadata": {"next_cursor": ""}},
    {"response_metadata": {"next_cursor": None}},
    {"has_more": False, "next_cursor": None},
    {"IsTruncated": False},
])
def test_terminal_pagination_remains_complete(pagination):
    errors = []
    assert list(BaseConnector._unwrap({"items": [], **pagination}, errors.append)) == []
    assert errors == []


def test_native_resource_pagination_named_fields_are_not_envelope_metadata():
    record = {"id": "resource", "response_metadata": {"next_cursor": "application-data"}}
    assert list(BaseConnector._unwrap(record)) == [record]


def test_gateway_context_envelope_marks_partial_export_incomplete(tmp_path, run_connector):
    source = tmp_path / "partial.json"
    source.write_text(json.dumps({"logEvents": [], "next_cursor": "opaque-page-secret"}))
    findings, ctx = run_connector("gateway.logs", input=str(source))

    assert findings == []
    assert ctx.stats.incomplete
    assert any("uncollected next page" in error for error in ctx.stats.errors)
    assert "opaque-page-secret" not in str(ctx.stats.errors)
