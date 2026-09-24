"""Regression contracts for the combined source scanning hardening changes."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.code import manifests
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.connectors.code.github import GitHubConnector
from shadowscan.connectors.code.gitlab import GitLabConnector
from shadowscan.connectors.code.manifests import _LineIndex, parse_manifest
from shadowscan.models import Kind
from shadowscan.signatures import SignatureIndex
from shadowscan.signatures import matcher as matcher_module
from shadowscan.signatures.loader import signature_from_dict
from shadowscan.signatures.matcher import MatchTimeoutError
from shadowscan.utils.text import parse_timestamp


def _index(pattern="token"):
    return SignatureIndex([signature_from_dict({
        "id": "custom.test",
        "category": "framework",
        "signals": [{"type": "code", "patterns": [pattern]}],
    })])


def test_explicit_scan_budget_is_not_silently_capped_at_default(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(matcher_module.time, "monotonic", lambda: clock[0])
    original = matcher_module._finditer

    def delayed_match(*args, **kwargs):
        clock[0] = 3.0  # valid for the requested 5-second budget, not the default 2
        return original(*args, **kwargs)

    monkeypatch.setattr(matcher_module, "_finditer", delayed_match)
    index = _index()
    with index.scan_budget(seconds=5):
        assert [m.value for m in index.match_code("token")] == ["token"]


def test_unscoped_matching_still_opens_default_budget(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(matcher_module.time, "monotonic", lambda: clock[0])
    original = matcher_module._finditer

    def delayed_match(*args, **kwargs):
        clock[0] = 3.0
        return original(*args, **kwargs)

    monkeypatch.setattr(matcher_module, "_finditer", delayed_match)
    with pytest.raises(MatchTimeoutError, match="input execution budget"):
        _index().match_code("token")


def test_manifest_regex_respects_outer_input_deadline(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(matcher_module.time, "monotonic", lambda: clock[0])
    with pytest.raises(MatchTimeoutError, match="input execution budget"), _index().scan_budget(seconds=0.1):
        clock[0] = 0.2
        parse_manifest("Dockerfile", "FROM python:3.12\n")


@pytest.mark.parametrize("offset, expected", [(0, 1), (1, 1), (2, 2), (3, 2), (4, 3)])
def test_manifest_line_index_matches_original_source_offsets(offset, expected):
    assert _LineIndex("a\nb\nc").at(offset) == expected


def test_signature_match_starting_at_newline_has_original_line_number():
    matches = _index(r"\n+token").match_code("prefix\n\ntoken")
    assert [(m.value, m.line) for m in matches] == [("\n\ntoken", 1)]


def test_yaml_chunk_matching_retries_scheduler_contention(monkeypatch):
    actual = manifests._YAML_IMAGE

    class SuspendedPattern:
        calls = 0

        def finditer(self, *args, **kwargs):
            self.calls += 1
            if self.calls == 1:
                raise TimeoutError("another worker's CPU charged to iterator")
            return actual.finditer(*args, **kwargs)

    pattern = SuspendedPattern()
    monkeypatch.setattr(manifests, "_YAML_IMAGE", pattern)
    result = parse_manifest("compose.yaml", "services:\n  worker:\n    image: acme/agent:1\n")
    assert result is not None and not result.errors
    assert [(a.kind, a.value, a.line) for a in result.artifacts] == [("image", "acme/agent:1", 3)]
    assert pattern.calls == 2


@pytest.mark.parametrize("value", [True, False, float("inf"), float("nan"), 10**400, "9" * 5000],
                         ids=["true", "false", "infinity", "nan", "huge-number", "huge-string"])
def test_untrusted_invalid_timestamps_do_not_raise_or_become_valid_dates(value):
    assert parse_timestamp(value) is None


def test_fractional_epoch_strings_support_gateway_timestamps():
    assert parse_timestamp("1704067200.125") == datetime(2024, 1, 1, microsecond=125000, tzinfo=UTC)
    assert parse_timestamp("1704067200125") == datetime(2024, 1, 1, microsecond=125000, tzinfo=UTC)


def test_same_text_from_distinct_signals_retains_agent_capabilities(tmp_path):
    index = SignatureIndex([signature_from_dict({
        "id": "custom.agent",
        "category": "framework",
        "signals": [
            {"type": "code", "patterns": [r"execute_agent\("], "weight": 0.5},
            {"type": "code", "patterns": [r"execute_agent\("], "weight": 0.95,
             "agent_indicator": True, "capabilities": ["code-exec"]},
        ],
    })])
    (tmp_path / "agent.py").write_text("execute_agent()\n")
    context = ConnectorContext(config={"path": str(tmp_path), "use_git": False}, index=index)
    findings = FilesystemConnector(context).run()
    project = next(f for f in findings if f.resource_type == "project")
    assert project.kind == Kind.AGENT
    assert "code-exec" in project.capabilities
    assert len(project.evidence) == 2


@pytest.mark.parametrize("cls, fetch_method, metadata_method", [
    (GitHubConnector, "_fetch_repo", "_repo_level_findings"),
    (GitLabConnector, "_fetch", "_project_level"),
])
def test_live_download_under_symlinked_temp_parent_is_scanned(tmp_path, index, monkeypatch, cls, fetch_method, metadata_method):
    actual = tmp_path / "actual"
    actual.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(actual, target_is_directory=True)
    context = ConnectorContext(config={"use_git": False}, index=index, workdir=str(alias))
    connector = cls(context)
    record = {"full_name": "org/agent", "path_with_namespace": "org/agent"}
    monkeypatch.setattr(connector, "collect", lambda: iter([record]))
    downloaded = []

    def fetch(_record, destination):
        root = Path(destination)
        downloaded.append(root)
        (root / "agent.py").write_text("from crewai import Agent\n")
        return destination

    monkeypatch.setattr(connector, fetch_method, fetch)
    monkeypatch.setattr(connector, metadata_method, lambda _record: iter([]))
    findings = connector.run()
    assert any("framework.crewai" in f.frameworks for f in findings)
    assert not context.stats.errors
    assert downloaded and downloaded[0].parent == actual
    assert not downloaded[0].exists()  # temporary source remains cleaned up
