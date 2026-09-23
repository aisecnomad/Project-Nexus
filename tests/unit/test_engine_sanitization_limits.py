"""Sanitizer limits drop unsafe findings, without losing neighboring results."""

from __future__ import annotations

import json

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors.base import BaseConnector
from shadowscan.engine import Engine
from shadowscan.models import Finding, Kind, ScanStats, Surface
from shadowscan.utils.redaction import SanitizationLimitError


def _finding(resource="same", **metadata):
    return Finding(surface=Surface.CODE, connector="test.probe", kind=Kind.AGENT,
                   title="Agent", resource=resource, resource_type="test", metadata=metadata)


def _run(monkeypatch, index, connector, **config):
    monkeypatch.setattr("shadowscan.engine.get_connector_class", lambda *args, **kwargs: connector)
    return Engine(ScanConfig(connectors=[ConnectorSpec(name="test.probe")], **config), index=index).run()


class _Probe(BaseConnector):
    name = "test.probe"

    def collect(self):
        return []

    def analyze(self, records):
        yield _finding(resource="neighbor")


def test_merged_findings_over_budget_do_not_abort_report(monkeypatch, index, tmp_path):
    class MergingProbe(_Probe):
        def analyze(self, records):
            yield _finding(left=[0] * 50_001)
            yield _finding(right=[0] * 50_001)
            yield _finding(resource="neighbor")

    dump_directory = tmp_path / "exports"
    result = _run(monkeypatch, index, MergingProbe, dump_records=str(dump_directory))
    assert not result.complete
    assert [finding.resource for finding in result.findings] == ["neighbor"]
    assert any("omitted after aggregation" in error for stats in result.stats for error in stats.errors)
    assert len(json.loads(result.to_json())["findings"]) == 1
    assert json.loads((dump_directory / "manifest.json").read_text())["complete"] is False


def test_custom_connector_returning_unsafe_finding_keeps_safe_neighbors(monkeypatch, index):
    class CustomProbe(_Probe):
        def run(self):
            self.ctx.stats = ScanStats(connector=self.name, started_at="now", finished_at="now")
            bad = _finding()
            # A custom connector bypasses BaseConnector.run after construction.
            bad.metadata = {"raw": ["opaque-private-value"] * 100_001}
            return [_finding("first"), bad, _finding("last")]

    result = _run(monkeypatch, index, CustomProbe)
    assert not result.complete
    assert {finding.resource for finding in result.findings} == {"first", "last"}
    assert "opaque-private-value" not in result.to_json()


def test_post_correlation_growth_is_bounded_without_losing_safe_neighbor(monkeypatch, index):
    class TwoProbe(_Probe):
        def analyze(self, records):
            yield _finding(resource="large")
            yield _finding(resource="neighbor")

    def grow(findings):
        next(f for f in findings if f.resource == "large").metadata["runtime_activity"] = [0] * 100_001

    monkeypatch.setattr("shadowscan.engine.correlate_runtime", grow)
    result = _run(monkeypatch, index, TwoProbe)
    assert not result.complete
    assert [finding.resource for finding in result.findings] == ["neighbor"]
    assert len(json.loads(result.to_json())["findings"]) == 1


def test_correlation_sanitization_limit_marks_partial_analysis(monkeypatch, index):
    def over_budget(findings):
        raise SanitizationLimitError("bounded failure")

    monkeypatch.setattr("shadowscan.engine.correlate_runtime", over_budget)
    result = _run(monkeypatch, index, _Probe)
    assert not result.complete
    assert [finding.resource for finding in result.findings] == ["neighbor"]
    assert any("runtime correlation incomplete" in error for stats in result.stats for error in stats.errors)
