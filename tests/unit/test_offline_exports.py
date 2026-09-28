"""shadowscan.connectors.offline: export parsing behind BaseConnector's offline methods.

BaseConnector keeps thin methods under the historical names. The offline
functions must call back through them so connector overrides still apply.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

import pytest

from shadowscan.connectors import offline
from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.models import Finding, ScanStats, Surface


class _Widgets(BaseConnector):
    name: ClassVar[str] = "test.widgets"
    surface: ClassVar[Surface] = Surface.SAAS
    _OFFLINE_COLLECTION_KINDS: ClassVar[dict[str, str]] = {"widgets": "widget"}

    def collect(self) -> list[dict[str, Any]]:
        return []

    def analyze(self, records: Any) -> list[Finding]:
        return []

    @staticmethod
    def _is_native_offline_record(data: dict[str, Any]) -> bool:
        return data.get("kind") == "widget-bundle" or BaseConnector._is_native_offline_record(data)


def _connector(index: Any, **config: Any) -> _Widgets:
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="test", started_at="2026-01-01T00:00:00Z")
    return _Widgets(ctx)


def test_unwrap_uses_the_connector_class_hooks():
    bundle = {"kind": "widget-bundle", "widgets": [{"id": "w1"}]}
    assert list(_Widgets._unwrap(bundle)) == [bundle]
    assert list(_Widgets._unwrap({"widgets": [{"id": "w1"}]})) == [{"id": "w1", "_kind": "widget"}]
    # The base class knows neither the collection kind nor the native bundle.
    assert list(BaseConnector._unwrap({"widgets": [{"id": "w1"}]})) == [{"widgets": [{"id": "w1"}]}]


def test_unwrap_without_a_handler_raises_connector_error_from_nested_pages():
    page = {"error": "later page denied", "items": [{"id": "ok"}, {"id": "bad", "error": "denied"}]}
    errors: list[str] = []
    assert list(BaseConnector._unwrap(page, errors.append)) == [{"id": "ok"}]
    assert len(errors) == 2
    with pytest.raises(ConnectorError, match="provider error response"):
        list(BaseConnector._unwrap(page))


def test_jsonl_envelope_diagnostics_name_their_own_line(tmp_path, index):
    source = tmp_path / "widgets.jsonl"
    source.write_text("\n".join(json.dumps({"widgets": [{"id": f"w{n}"}, "bad"]}) for n in (1, 2, 3)) + "\n")
    connector = _connector(index, input=str(source))
    records = list(connector.load_offline(str(source)))
    assert [record["id"] for record in records] == ["w1", "w2", "w3"]
    assert connector.ctx.stats.errors == [
        f"test.widgets: line {n}: invalid export record 2; expected a nonempty object with string keys"
        for n in (1, 2, 3)
    ]


def test_json_lines_fallback_names_each_line(index):
    errors: list[str] = []
    text = '{"widgets": ["bad"]}\n{"widgets": [{"id": "w2"}]}\n'
    assert list(_Widgets._json_lines(text, errors.append)) == [{"id": "w2", "_kind": "widget"}]
    assert errors == ["line 1: invalid export record 1; expected a nonempty object with string keys"]


def test_bounded_diagnostics_summarise_after_the_limit():
    reports: list[str] = []
    limited = offline.bounded_diagnostics(reports.append, 2)
    for number in range(5):
        limited(f"problem {number}")
    assert reports == [
        "problem 0",
        "problem 1",
        "further invalid records in this export are not listed individually",
    ]


def test_connector_wide_offline_limits_are_overridable_per_class(tmp_path, index, monkeypatch):
    source = tmp_path / "widgets.json"
    source.write_text(json.dumps({"widgets": [{"id": "w1"}]}))
    monkeypatch.setattr(_Widgets, "_MAX_OFFLINE_FILE_BYTES", 8)
    connector = _connector(index)
    assert list(connector.load_offline(str(source))) == []
    assert connector.ctx.stats.warnings == [
        "test.widgets: max_input_file_bytes reached; oversized offline input was skipped"
    ]
    assert BaseConnector._MAX_OFFLINE_FILE_BYTES == offline.MAX_OFFLINE_FILE_BYTES


def test_offline_suffixes_stay_a_plain_set_on_base_connector():
    # BaseConnector exposed a plain set before the extraction and keeps doing
    # so; the module default it is copied from is immutable.
    assert type(BaseConnector._OFFLINE_SUFFIXES) is set
    assert BaseConnector._OFFLINE_SUFFIXES == offline.OFFLINE_SUFFIXES
    assert isinstance(offline.OFFLINE_SUFFIXES, frozenset)


def test_offline_file_discovery_goes_through_the_connector_method(tmp_path, index):
    exported = tmp_path / "a.json"
    exported.write_text(json.dumps([{"id": "w1"}]))
    connector = _connector(index)
    seen: list[str] = []
    discover = connector._offline_files

    def recorded(path: str, suffixes: Any = None) -> Any:
        seen.append(path)
        return discover(path, suffixes)

    connector._offline_files = recorded
    assert list(connector.load_offline(str(tmp_path))) == [{"id": "w1"}]
    assert seen == [str(tmp_path)]


# Page identities and malformed successful responses must not hide collection gaps.
def test_native_resource_with_id_name_and_items_is_not_unwrapped():
    native = {"id": "app-1", "name": "Native", "type": "app", "items": [{"id": "child"}]}
    assert list(BaseConnector._unwrap(native)) == [native]


def test_csv_native_log_event_with_error_column_is_preserved():
    errors: list[str] = []
    records = list(
        BaseConnector._csv_records(
            "id,name,error,timestamp\nlog-1,OpenAI,timeout,2026-01-01\n", errors.append
        )
    )
    assert len(records) == 1 and records[0]["id"] == "log-1" and not errors


@pytest.mark.parametrize(
    "record",
    [
        {
            "_kind": "cloudtrail-event",
            "eventName": "InvokeModel",
            "eventTime": "2026-01-01",
            "error": "AccessDenied",
        },
        {
            "_kind": "audit-event",
            "principal": "agent@example.test",
            "timestamp": "2026-01-01",
            "error": "AccessDenied",
        },
        {"_kind": "integration_log", "change_type": "enabled", "app_id": "A1", "error": "install-failed"},
    ],
)
def test_known_native_error_event_is_preserved(record):
    assert list(BaseConnector._unwrap(record)) == [record]
    assert list(BaseConnector._unwrap([record])) == [record]


def test_base_json_lines_caps_per_line_errors():
    reports: list[str] = []
    text = "\n".join(['{"id": "ok"}'] + ["{broken"] * 40)
    records = list(BaseConnector._json_lines(text, reports.append))
    assert records == [{"id": "ok"}]
    assert len(reports) == BaseConnector._MAX_INVALID_LINE_ERRORS + 1
    reports.clear()
    assert list(BaseConnector._json_lines('[\n  {"a": 1},\n', reports.append)) == []
    assert reports == ["invalid JSON export"]


class _Probe(BaseConnector):
    name = "test.offline"

    def collect(self):
        return []

    def analyze(self, records):
        return []


@pytest.mark.parametrize("suffix", [".jsonl", ".json"])
def test_corrupt_record_flood_preserves_later_valid_record(tmp_path, index, suffix):
    source = tmp_path / f"export{suffix}"
    source.write_text("invalid\n" * 100 + '{"id":"survivor"}\n')
    ctx = ConnectorContext(index=index)
    ctx.stats = ScanStats(connector=_Probe.name, started_at="now")
    records = list(_Probe(ctx).load_offline(str(source)))
    assert records == [{"id": "survivor"}]
    assert ctx.stats.incomplete
    assert len(ctx.stats.errors) == BaseConnector._MAX_INVALID_LINE_ERRORS + 1
    assert "not listed individually" in ctx.stats.errors[-1]
