"""Failure isolation in the filesystem connector's walk and emit phases.

A failure while building one finding is contained to a diagnostic so the other
findings survive. A ConnectorError (cancellation or an exhausted connector
deadline) is never contained: it ends the scan, which is then reported as
skipped and incomplete instead of as one "incomplete" error per file.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import NoReturn

import pytest

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.base import ConnectorError
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.models import Finding
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
