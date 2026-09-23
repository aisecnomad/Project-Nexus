"""YAML aliases are bounded before construction and before report expansion."""

from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from shadowscan.connectors.base import BaseConnector, ConnectorContext
from shadowscan.connectors.code.manifests import parse_conda_env
from shadowscan.models import ScanStats
from shadowscan.utils.redaction import REDACTED, SanitizationLimitError, credential_id, sanitize
from shadowscan.utils.safe_yaml import BoundedSafeLoader, YAMLResourceLimitError, bounded_safe_load
from shadowscan.utils.text import redact, sanitize_record


def _bomb(*, merge=False):
    lines = ['a0: &a0 {label: "ordinary"}' if merge else 'a0: &a0 ["ordinary"]']
    for level in range(1, 10):
        aliases = ", ".join([f"*a{level - 1}"] * 10)
        value = "{<<: [" + aliases + "]}" if merge else "[" + aliases + "]"
        lines.append(f"a{level}: &a{level} " + value)
    return "\n".join(lines)


@pytest.mark.parametrize("merge", [False, True])
def test_alias_amplification_rejected_before_object_construction(merge):
    class NoConstruction(BoundedSafeLoader):
        def construct_document(self, node):
            pytest.fail("hostile graph reached object construction")

    loader = NoConstruction(_bomb(merge=merge))
    try:
        with pytest.raises(YAMLResourceLimitError, match="expansion"):
            loader.get_single_data()
    finally:
        loader.dispose()


@pytest.mark.parametrize("text", ["root: &root [*root]", "root: &root {<<: *root}", "[" * 70 + "0" + "]" * 70])
def test_cycles_and_excessive_nesting_rejected(text):
    with pytest.raises(YAMLResourceLimitError):
        bounded_safe_load(text)


def test_ordinary_aliases_and_merges_preserve_values():
    data = bounded_safe_load("defaults: &base {model: gpt-4o, region: eu}\nagent: {<<: *base, region: us}\ncopy: *base")
    assert data["agent"] == {"model": "gpt-4o", "region": "us"}
    assert json.loads(json.dumps(sanitize(data))) == data


def test_stream_input_is_read_with_a_limit():
    class SmallLoader(BoundedSafeLoader):
        MAX_INPUT_SIZE = 64

    stream = io.StringIO(" " * 1_000)
    with pytest.raises(YAMLResourceLimitError, match="input size"):
        SmallLoader(stream)
    assert stream.tell() == 65


def test_alias_and_document_budgets_apply_across_stream():
    class SmallLoader(BoundedSafeLoader):
        MAX_ALIASES = 2

    loader = SmallLoader("a: &a [1]\nb: [*a, *a, *a]")
    try:
        with pytest.raises(YAMLResourceLimitError, match="alias limit"):
            loader.get_single_data()
    finally:
        loader.dispose()

    class SmallStreamLoader(BoundedSafeLoader):
        MAX_EXPANDED_NODES = 10

    with pytest.raises(YAMLResourceLimitError, match="expanded stream"):
        list(yaml.load_all("---\na: 1\n" * 4, Loader=SmallStreamLoader))


def test_node_count_is_bounded_during_composition():
    class SmallLoader(BoundedSafeLoader):
        MAX_NODES = 10

    loader = SmallLoader("[" + ",".join(["0"] * 20) + "]")
    try:
        with pytest.raises(YAMLResourceLimitError, match="node limit"):
            loader.get_single_data()
    finally:
        loader.dispose()


class _OfflineProbe(BaseConnector):
    name = "test.yaml"

    def collect(self):
        return []

    def analyze(self, records):
        for _ in records:
            self.ctx.examined()
        return []


def test_offline_yaml_limit_marks_scan_incomplete(tmp_path, index):
    source = tmp_path / "hostile.yaml"
    source.write_text(_bomb(merge=True))
    ctx = ConnectorContext(config={"input": str(source)}, index=index)
    assert _OfflineProbe(ctx).run() == []
    assert ctx.stats.incomplete
    assert ctx.stats.objects_examined == 0
    assert any("YAML safety limit" in error for error in ctx.stats.errors)


def test_conda_limit_returns_explicit_manifest_error():
    result = parse_conda_env(_bomb())
    assert result.errors == ["YAML safety limit exceeded"]
    assert not result.deps


@pytest.mark.parametrize("merge", [False, True])
def test_full_source_scan_reports_yaml_limit_and_retains_neighboring_findings(tmp_path, run_connector, merge):
    (tmp_path / "hostile.yaml").write_text(_bomb(merge=merge))
    (tmp_path / "agent.py").write_text("from crewai import Agent\n")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, scan_timeout=0.2)
    assert ctx.stats.incomplete
    assert any("YAMLResourceLimitError" in error for error in ctx.stats.errors)
    assert any("framework.crewai" in finding.frameworks for finding in findings)


def test_python_alias_dag_is_rejected_by_both_sanitizer_entry_points():
    value = {"label": "ordinary"}
    for _ in range(9):
        value = {"children": [value] * 10}
    for sanitizer in (sanitize, sanitize_record):
        with pytest.raises(SanitizationLimitError, match="expanded output"):
            sanitizer(value)


def test_shared_strings_cannot_expand_export_without_bound():
    value = {"records": ["ordinary" * 10_000] * 1_000}
    with pytest.raises(SanitizationLimitError, match="expanded output"):
        sanitize(value)


def test_over_budget_config_cannot_break_diagnostic_reporting(index):
    value = {"label": "ordinary"}
    for _ in range(9):
        value = {"children": [value] * 10}
    ctx = ConnectorContext(config=value, index=index)
    ctx.stats = ScanStats(connector="test", started_at="now")
    ctx.error("opaque private diagnostic")
    assert ctx.stats.incomplete
    assert REDACTED in ctx.stats.errors[0]
    assert "private" not in ctx.stats.errors[0]


def test_export_serialization_budget_preserves_prior_complete_file(tmp_path, index):
    class ExportProbe(_OfflineProbe):
        _MAX_OFFLINE_FILE_BYTES = 256

        def collect(self):
            yield {"label": "ordinary" * 40}

    target = tmp_path / "export.jsonl"
    target.write_text('{"prior":"complete"}\n')
    ctx = ConnectorContext(config={"_dump_path": str(target)}, index=index)
    assert ExportProbe(ctx).run() == []
    assert ctx.stats.incomplete
    assert ctx.dump_path is None
    assert target.read_text() == '{"prior":"complete"}\n'
    assert list(tmp_path.iterdir()) == [target]


def test_export_path_is_confirmed_only_after_successful_publication(tmp_path, index):
    class ExportProbe(_OfflineProbe):
        def collect(self):
            yield {"label": "ordinary"}

    target = tmp_path / "export.jsonl"
    ctx = ConnectorContext(config={"_dump_path": str(target)}, index=index)
    ExportProbe(ctx).run()
    assert ctx.dump_path == str(target)
    assert json.loads(target.read_text()) == {"label": "ordinary"}
    assert not ctx.stats.incomplete


def test_rejected_export_record_preserves_valid_neighbors_without_partial_json(tmp_path, index):
    class ExportProbe(_OfflineProbe):
        _MAX_OFFLINE_FILE_BYTES = 256

        def collect(self):
            yield {"id": "first"}
            yield {"partial": "must roll back", "label": "ordinary" * 40}
            yield {"id": "last"}

    target = tmp_path / "export.jsonl"
    ctx = ConnectorContext(config={"_dump_path": str(target)}, index=index)
    ExportProbe(ctx).run()
    assert ctx.stats.incomplete
    assert ctx.stats.objects_examined == 2
    assert ctx.dump_path == str(target)
    assert [json.loads(line) for line in target.read_text().splitlines()] == [{"id": "first"}, {"id": "last"}]
    assert list(tmp_path.iterdir()) == [target]


def test_legacy_redact_uses_stable_opaque_identity():
    value = "sk-proj-synthetic-credential-no-real-key"
    assert redact(value) == credential_id(value)
    assert redact(redact(value)) == redact(value)
    assert value not in redact(value)
    assert redact("") == ""


def test_amplification_rejection_completes_in_bounded_subprocess():
    script = """
import json
import resource
from shadowscan.utils.safe_yaml import bounded_safe_load, YAMLResourceLimitError
from shadowscan.utils.redaction import sanitize, SanitizationLimitError
resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
for merge in (False, True):
    lines = ['a0: &a0 {label: ordinary}' if merge else 'a0: &a0 [ordinary]']
    for level in range(1, 10):
        refs = ', '.join(['*a' + str(level - 1)] * 10)
        lines.append('a%d: &a%d ' % (level, level) + ('{<<: [' + refs + ']}' if merge else '[' + refs + ']'))
    try:
        bounded_safe_load('\\n'.join(lines))
    except YAMLResourceLimitError:
        pass
    else:
        raise AssertionError('unbounded YAML accepted')
value = {'label': 'ordinary'}
for _ in range(9):
    value = {'children': [value] * 10}
try:
    json.dumps(sanitize(value))
except SanitizationLimitError:
    pass
else:
    raise AssertionError('unbounded sanitizer accepted')
"""
    pytest.importorskip("resource")
    result = subprocess.run([sys.executable, "-c", script], cwd=Path(__file__).resolve().parents[2],
                            capture_output=True, text=True, timeout=15, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
