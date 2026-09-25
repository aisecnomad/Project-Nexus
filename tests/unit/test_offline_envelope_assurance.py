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
