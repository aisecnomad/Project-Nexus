"""GitHub code connector: explicit repository identity and credential handling."""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.code.github import GitHubConnector
from shadowscan.models import ScanStats
from shadowscan.utils.redaction import REDACTED


def test_github_wrong_explicit_repository_does_not_hide_valid_neighbor(index, fixtures, monkeypatch):
    ctx = ConnectorContext(config={"repos": ["acme/agent", "acme/valid"], "use_git": False}, index=index)
    connector = GitHubConnector(ctx)
    connector.http.try_get_json = Mock(side_effect=[
        {"full_name": "acme/other"},
        {"full_name": "acme/valid", "owner": {"login": "acme"}},
    ])
    fetch = Mock(return_value=str(fixtures / "sample_repo"))
    monkeypatch.setattr(connector, "_fetch_repo", fetch)
    monkeypatch.setattr(connector, "_repo_level_findings", lambda _repo: iter(()))

    findings = connector.run()
    assert any(f.resource_type == "project" and f.frameworks for f in findings)
    assert fetch.call_count == 1
    assert fetch.call_args.args[0]["full_name"] == "acme/valid"
    assert connector.http.try_get_json.call_count == 2
    assert ctx.stats is not None and ctx.stats.incomplete
    assert any("does not match the requested name" in warning for warning in ctx.stats.warnings)


@pytest.mark.parametrize("response", [
    {"full_name": "acme/other"}, {"full_name": "acme/agent/extra"},
    {"full_name": []}, {"name": "agent"}, ["acme/agent"],
])
def test_github_invalid_explicit_repository_response_marks_incomplete(response, index):
    ctx = ConnectorContext(config={"repos": ["acme/agent"]}, index=index)
    ctx.stats = ScanStats(connector="code.github", started_at="2026-01-01T00:00:00Z")
    connector = GitHubConnector(ctx)
    connector.http.try_get_json = Mock(return_value=response)

    records = list(connector.collect())
    assert records == [] and list(connector.analyze(records)) == []
    assert ctx.stats.incomplete
    assert any("does not match the requested name" in warning for warning in ctx.stats.warnings)


def test_github_explicit_repository_accepts_case_insensitive_identity(index):
    ctx = ConnectorContext(config={"repos": ["AcMe/Agent"]}, index=index)
    ctx.stats = ScanStats(connector="code.github", started_at="2026-01-01T00:00:00Z")
    connector = GitHubConnector(ctx)
    connector.http.try_get_json = Mock(return_value={"full_name": "acme/agent"})

    assert list(connector.collect()) == [{"full_name": "acme/agent"}]
    assert not ctx.stats.incomplete


def test_github_fallback_token_is_registered_for_diagnostic_redaction(index, monkeypatch):
    secret = "synthetic-opaque-github-cli-token-0123456789"
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.setenv("GH_TOKEN", secret)
    ctx = ConnectorContext(config={}, index=index)
    connector = GitHubConnector(ctx)
    assert connector.token == secret
    assert ctx.sanitize_message(f"provider rejected {secret}") == f"provider rejected {REDACTED}"
