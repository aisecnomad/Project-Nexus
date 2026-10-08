"""Published connector exports must fit replay limits without losing live analysis."""

from __future__ import annotations

import json

import pytest

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors.base import BaseConnector, ConnectorContext
from shadowscan.connectors.offline import DEFAULT_MAX_INPUT_FILE_BYTES, MAX_OFFLINE_LINE_BYTES
from shadowscan.engine import Engine
from shadowscan.models import Finding, Kind, Surface


class ExportProbe(BaseConnector):
    name = "test.export-replay"
    surface = Surface.CLOUD

    def collect(self):
        return self.ctx.config.get("records", [])

    def analyze(self, records):
        for record in records:
            self.ctx.examined()
            yield Finding(
                surface=self.surface,
                connector=self.name,
                kind=Kind.AGENT,
                title=record["id"],
                resource=record["id"],
                resource_type="test",
            )


def _export(tmp_path, index, records, **config):
    target = tmp_path / "records.jsonl"
    context = ConnectorContext({"_dump_path": str(target), **config}, index=index)
    connector = ExportProbe(context)
    # Live records arrive from collection, not from trusted configuration.
    connector.collect = lambda: iter(records)
    findings = connector.run()
    return target, findings, context


def _replay(target, index, **config):
    context = ConnectorContext({"input": str(target), **config}, index=index)
    findings = ExportProbe(context).run()
    return findings, context.stats


def _record_with_encoded_line_bytes(size, *, character="x", identifier="edge"):
    record = {"id": identifier, "description": ""}
    overhead = len((json.dumps(record) + "\n").encode("utf-8"))
    character_bytes = len(json.dumps(character).encode("utf-8")) - 2
    count, padding = divmod(size - overhead, character_bytes)
    record["description"] = character * count + "x" * padding
    assert len((json.dumps(record) + "\n").encode("utf-8")) == size
    return record


@pytest.mark.parametrize("character", ["x", "é"])
def test_real_line_limit_including_newline_roundtrips(tmp_path, index, character):
    record = _record_with_encoded_line_bytes(MAX_OFFLINE_LINE_BYTES, character=character)
    target, findings, context = _export(tmp_path, index, [record])
    assert not context.stats.incomplete
    assert target.stat().st_size == MAX_OFFLINE_LINE_BYTES
    replayed, stats = _replay(target, index)
    assert not stats.incomplete
    assert (
        [finding.resource for finding in findings] == [finding.resource for finding in replayed] == ["edge"]
    )


@pytest.mark.parametrize("character", ["x", "é"])
def test_over_line_limit_preserves_live_findings_without_publishing_partial_export(
    tmp_path, index, character
):
    records = [
        {"id": "first"},
        _record_with_encoded_line_bytes(MAX_OFFLINE_LINE_BYTES + 1, character=character),
        {"id": "last"},
    ]
    target, findings, context = _export(tmp_path, index, records)
    assert [finding.resource for finding in findings] == ["first", "edge", "last"]
    assert context.stats.incomplete
    assert any("replay line byte limit" in error for error in context.stats.errors)
    assert context.dump_path is None and not target.exists()
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("number", [float("nan"), float("inf"), float("-inf")])
def test_nonfinite_json_record_is_omitted_without_losing_live_analysis_or_neighbors(tmp_path, index, number):
    records = [{"id": "first"}, {"id": "nonfinite", "score": number}, {"id": "last"}]
    target, findings, context = _export(tmp_path, index, records)
    assert [finding.resource for finding in findings] == ["first", "nonfinite", "last"]
    assert context.stats.incomplete
    assert context.stats.errors == [f"{ExportProbe.name}: export record omitted: record is not strict JSON"]
    assert context.dump_path is None and not target.exists()
    assert not list(tmp_path.iterdir())


def test_strict_json_failure_preserves_prior_export_and_masks_encoding_error(
    tmp_path, index, monkeypatch, caplog
):
    target = tmp_path / "records.jsonl"
    prior = '{"id": "prior"}\n'
    target.write_text(prior)
    private_detail = "opaque-private-encoding-error"
    original = json.JSONEncoder.iterencode

    def failed_encoding(self, value, *args, **kwargs):
        if isinstance(value, dict) and value.get("id") == "current":
            raise ValueError(private_detail)
        return original(self, value, *args, **kwargs)

    monkeypatch.setattr(json.JSONEncoder, "iterencode", failed_encoding)
    records = [{"id": "first"}, {"id": "current"}, {"id": "last"}]
    target, findings, context = _export(tmp_path, index, records)
    assert [finding.resource for finding in findings] == ["first", "current", "last"]
    assert context.stats.incomplete and context.dump_path is None
    assert target.read_text() == prior
    assert private_detail not in repr(context.stats) + caplog.text


def test_sanitizer_unsafe_record_is_skipped_and_entire_new_export_is_discarded(tmp_path, index):
    target = tmp_path / "records.jsonl"
    prior = '{"id": "prior"}\n'
    target.write_text(prior)
    unsafe = {"id": "unsafe", "children": [0] * 100_001}
    target, findings, context = _export(tmp_path, index, [{"id": "first"}, unsafe, {"id": "last"}])
    assert [finding.resource for finding in findings] == ["first", "last"]
    assert context.stats.objects_examined == 2
    assert context.stats.incomplete and context.dump_path is None
    assert target.read_text() == prior
    assert list(tmp_path.iterdir()) == [target]


@pytest.mark.parametrize("extra", [0, 1])
def test_real_default_file_limit_roundtrips_or_discards_without_losing_analysis(tmp_path, index, extra):
    record = _record_with_encoded_line_bytes(MAX_OFFLINE_LINE_BYTES)
    records = [record] * (DEFAULT_MAX_INPUT_FILE_BYTES // MAX_OFFLINE_LINE_BYTES + extra)
    target, findings, context = _export(tmp_path, index, records)
    assert len(findings) == len(records)
    if extra:
        assert context.stats.incomplete
        assert any("replay file byte limit" in error for error in context.stats.errors)
        assert context.dump_path is None and not target.exists()
        assert not list(tmp_path.iterdir())
    else:
        assert not context.stats.incomplete
        assert target.stat().st_size == DEFAULT_MAX_INPUT_FILE_BYTES
        replayed, stats = _replay(target, index)
        assert not stats.incomplete
        assert len(replayed) == len(records)


@pytest.mark.parametrize("limit_key", ["max_input_file_bytes", "max_input_bytes"])
@pytest.mark.parametrize("extra", [0, 1])
def test_configured_file_and_aggregate_byte_limits_include_newline(tmp_path, index, limit_key, extra):
    record = {"id": "unicode", "description": "é" * 10}
    limit = len((json.dumps(record) + "\n").encode("utf-8")) - extra
    target, findings, context = _export(tmp_path, index, [record], **{limit_key: limit})
    assert [finding.resource for finding in findings] == ["unicode"]
    if extra:
        assert context.stats.incomplete and context.dump_path is None
        assert not target.exists()
    else:
        assert not context.stats.incomplete
        assert target.stat().st_size == limit
        replayed, stats = _replay(target, index, **{limit_key: limit})
        assert not stats.incomplete and len(replayed) == 1


def test_empty_successful_export_is_explicit_and_roundtrips(tmp_path, index):
    target, findings, context = _export(tmp_path, index, [])
    assert not findings and not context.stats.incomplete
    assert json.loads(target.read_text()) == {"records": []}
    replayed, stats = _replay(target, index)
    assert not replayed and not stats.incomplete


def test_empty_export_that_cannot_fit_preserves_prior_file(tmp_path, index):
    target = tmp_path / "records.jsonl"
    prior = '{"records": []}\n'
    target.write_text(prior)
    target, findings, context = _export(tmp_path, index, [], max_input_bytes=1)
    assert not findings and context.stats.incomplete and context.dump_path is None
    assert target.read_text() == prior


def test_engine_manifest_marks_omitted_export_records_incomplete(tmp_path, index, monkeypatch):
    monkeypatch.setattr("shadowscan.engine.get_connector_class", lambda *args, **kwargs: ExportProbe)
    records = [{"id": "first"}, {"id": "too-large", "description": "x" * 300}, {"id": "last"}]
    exports = tmp_path / "exports"
    result = Engine(
        ScanConfig(
            connectors=[ConnectorSpec(ExportProbe.name, {"records": records, "max_input_file_bytes": 256})],
            dump_records=str(exports),
        ),
        index,
    ).run()
    assert not result.complete
    assert {finding.resource for finding in result.findings} == {"first", "too-large", "last"}
    manifest = json.loads((exports / "manifest.json").read_text())
    assert manifest["complete"] is False
    assert manifest["exports"][0]["complete"] is False
    assert manifest["exports"][0]["exported"] is False
    assert manifest["exports"][0]["filename"] is None
    assert list(exports.iterdir()) == [exports / "manifest.json"]
