"""Failure isolation in the filesystem connector's walk and emit phases.

A failure while building one finding is contained to a diagnostic so the other
findings survive. A ConnectorError (cancellation or an exhausted connector
deadline) is never contained: it ends the scan, which is then reported as
skipped and incomplete instead of as one "incomplete" error per file.
"""

from __future__ import annotations

import json
import threading
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import NoReturn

import pytest

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.base import ConnectorError
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.models import Finding, Kind
from shadowscan.signatures import SignatureIndex

CANCELLED = "connector completion deadline exceeded"

# Emit-phase builder -> (resource types it produces, diagnostic for a contained failure).
EMITTERS = {
    "_emit_project": ({"project", "coding-agent-config"}, "project analysis incomplete (RuntimeError)"),
    "_mcp_finding": ({"mcp-config"}, "MCP analysis incomplete (RuntimeError)"),
    "_card_finding": ({"agent-manifest"}, "agent manifest analysis incomplete (RuntimeError)"),
    "_workflow_finding": ({"workflow-export"}, "workflow analysis incomplete (RuntimeError)"),
    "_infra_finding": ({"iac"}, "infrastructure analysis incomplete (RuntimeError)"),
    "_secret_finding": ({"file"}, "credential analysis incomplete (RuntimeError)"),
}


def _run(index: SignatureIndex, root: Path) -> tuple[list[Finding], ConnectorContext]:
    ctx = ConnectorContext(config={"path": str(root), "use_git": False}, index=index)
    return FilesystemConnector(ctx).run(), ctx


def _raiser(exc: Exception) -> Callable[..., NoReturn]:
    def fail(*_args: object, **_kwargs: object) -> NoReturn:
        raise exc

    return fail


def test_sample_repo_exercises_every_emitter(index: SignatureIndex, fixtures: Path) -> None:
    findings, ctx = _run(index, fixtures / "sample_repo")
    produced = Counter(f.resource_type for f in findings)
    assert all(produced[kind] for kinds, _ in EMITTERS.values() for kind in kinds), produced
    assert not ctx.stats.errors and not ctx.stats.skipped


def test_connector_error_from_secret_finding_ends_the_scan(
    index: SignatureIndex,
    fixtures: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Regression: the credential emit loop caught every Exception, so a
    # cancellation raised while building a secret finding became a per-file
    # "credential analysis incomplete" error and the scan looked finished.
    monkeypatch.setattr(FilesystemConnector, "_secret_finding", _raiser(ConnectorError(CANCELLED)))
    _, ctx = _run(index, fixtures / "sample_repo")
    assert ctx.stats.skipped and ctx.stats.skip_reason == CANCELLED
    assert ctx.stats.incomplete
    assert not any("credential analysis incomplete" in error for error in ctx.stats.errors)

    connector = FilesystemConnector(ConnectorContext(config={"use_git": False}, index=index))
    with pytest.raises(ConnectorError, match=CANCELLED):
        list(connector.scan_tree(fixtures / "sample_repo"))


@pytest.mark.parametrize("method", sorted(EMITTERS))
def test_emit_phase_connector_error_propagates(
    method: str,
    index: SignatureIndex,
    fixtures: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(FilesystemConnector, method, _raiser(ConnectorError(CANCELLED)))
    _, ctx = _run(index, fixtures / "sample_repo")
    assert ctx.stats.skipped and ctx.stats.skip_reason == CANCELLED
    assert ctx.stats.errors == [CANCELLED]


@pytest.mark.parametrize("method", sorted(EMITTERS))
def test_emit_phase_failure_is_isolated(
    method: str,
    index: SignatureIndex,
    fixtures: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resource_types, message = EMITTERS[method]
    baseline, _ = _run(index, fixtures / "sample_repo")
    monkeypatch.setattr(FilesystemConnector, method, _raiser(RuntimeError("synthetic")))
    findings, ctx = _run(index, fixtures / "sample_repo")
    assert not ctx.stats.skipped and ctx.stats.incomplete
    failed = [error for error in ctx.stats.errors if message in error]
    assert failed and len(failed) == len(ctx.stats.errors)
    assert "synthetic" not in " ".join(ctx.stats.errors)
    # Every other kind of finding is still reported.
    others = Counter(f.resource_type for f in baseline if f.resource_type not in resource_types)
    assert others <= Counter(f.resource_type for f in findings)


def test_file_pass_connector_error_is_not_reported_per_file(
    index: SignatureIndex,
    fixtures: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(index, "match_secrets", _raiser(ConnectorError(CANCELLED)))
    _, ctx = _run(index, fixtures / "sample_repo")
    assert ctx.stats.skipped and ctx.stats.errors == [CANCELLED]


def test_credential_detection_failure_keeps_the_content_passes(
    index: SignatureIndex,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "agent.py").write_text("from crewai import Agent\n")
    monkeypatch.setattr(index, "match_secrets", _raiser(RuntimeError("synthetic")))
    findings, ctx = _run(index, tmp_path)
    assert any("framework.crewai" in f.frameworks for f in findings)
    assert ctx.stats.errors == ["code.filesystem: agent.py: credential detection incomplete (RuntimeError)"]


SECRET = "sk-proj-aP9rVv3qN4zY7bC2hJ8Lm5Qw6Dt0KsX1eR7uT4p"


def _scan(index, root: Path, **config):
    ctx = ConnectorContext(config={"path": str(root), **config}, index=index)
    return FilesystemConnector(ctx).run(), ctx


def test_cancellation_stops_the_tree_walk(tmp_path, index):
    for i in range(300):
        directory = tmp_path / f"d{i % 10}"
        directory.mkdir(exist_ok=True)
        (directory / f"f{i}.py").write_text("import openai\n")
    cancelled = threading.Event()
    ctx = ConnectorContext(config={"path": str(tmp_path)}, index=index, cancelled=cancelled)
    connector = FilesystemConnector(ctx)
    walked = 0
    original = connector._iter_entries

    def counting(root):
        nonlocal walked
        for item in original(root):
            walked += 1
            if walked == 10:
                cancelled.set()
            yield item

    connector._iter_entries = counting  # type: ignore[method-assign]
    assert connector.run() == []
    assert walked == 10 and ctx.stats is not None and ctx.stats.skipped
    assert len(ctx.stats.errors) == 1 and "deadline" in ctx.stats.errors[0]


def test_credentials_are_reported_when_a_content_pass_times_out(tmp_path, index, monkeypatch):
    (tmp_path / "app.js").write_text(f'const k = "{SECRET}"; const model = "gpt-4";\n')

    # Force a failure after the independent credential pass. Wall-clock timing
    # depends on the machine and on #47's optimized matchers.
    def exhausted(*args, **kwargs):
        raise TimeoutError("simulated content budget")

    monkeypatch.setattr(index, "match_domains_in_text", exhausted)
    findings, ctx = _scan(index, tmp_path, scan_timeout=60)
    assert any(f.kind == Kind.SECRET for f in findings)
    assert ctx.stats is not None and ctx.stats.incomplete
    assert SECRET not in json.dumps([f.to_dict() for f in findings])


def test_credentials_are_reported_when_structured_sanitization_exceeds_its_budget(tmp_path, index):
    (tmp_path / "fixture.json").write_text(
        json.dumps({"OPENAI_API_KEY": SECRET, "values": list(range(110_000))})
    )
    findings, ctx = _scan(index, tmp_path)
    secret = next(f for f in findings if f.kind == Kind.SECRET)
    assert ctx.stats is not None and any("excerpts withheld" in e for e in ctx.stats.errors)
    assert all(not e.snippet for e in secret.evidence)
    assert SECRET not in json.dumps([f.to_dict() for f in findings])


def _run_configured(index, root, **config):
    ctx = ConnectorContext(config={"path": str(root), "use_git": False, **config}, index=index)
    return FilesystemConnector(ctx).run(), ctx


def test_emit_phase_failures_are_isolated_per_finding(tmp_path, index, monkeypatch):
    (tmp_path / "agent.py").write_text("from crewai import Agent\n")
    (tmp_path / "config.py").write_text(
        "OPENAI_API_KEY = 'sk-proj-kLKFlNfzW2mTofMpnx1qOu7fTm9F8IRv6iKzoC2h'\n"
    )

    def boom(self, *args, **kwargs):
        raise RuntimeError("synthetic")

    monkeypatch.setattr(FilesystemConnector, "_secret_finding", boom)
    findings, ctx = _run_configured(index, tmp_path)
    assert any("framework.crewai" in f.frameworks for f in findings)
    assert any("credential analysis incomplete (RuntimeError)" in error for error in ctx.stats.errors)


def test_project_isolation_error_names_the_project(tmp_path, index, monkeypatch):
    (tmp_path / "agent.py").write_text("from crewai import Agent\n")

    def boom(self, *args, **kwargs):
        raise RuntimeError("synthetic")
        yield  # pragma: no cover - generator shape

    monkeypatch.setattr(FilesystemConnector, "_emit_project", boom)
    findings, ctx = _run_configured(index, tmp_path)
    assert findings == []
    assert any("project analysis incomplete (RuntimeError)" in error for error in ctx.stats.errors)
