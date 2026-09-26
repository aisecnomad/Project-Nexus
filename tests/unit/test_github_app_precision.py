"""GitHub App installations: permissions alone do not make an app an AI agent."""

from __future__ import annotations

import json

import pytest

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.base import ConnectorError
from shadowscan.connectors.saas.github_apps import UNRECOGNISED_APP_MAX_CONFIDENCE, GitHubAppsConnector
from shadowscan.models import Likelihood


def _installation(slug: str, permissions: dict[str, str], selection: str = "all", **extra) -> dict:
    return {"id": abs(hash(slug)) % 10_000, "app_id": 1, "app_slug": slug, "repository_selection": selection,
            "permissions": permissions, "events": ["push"], "html_url": f"https://github.com/apps/{slug}",
            "target_type": "Organization", **extra}


def _run(index, tmp_path, installations, **config):
    path = tmp_path / "installations.json"
    path.write_text(json.dumps({"installations": installations}))
    ctx = ConnectorContext(config={"input": str(path), **config}, index=index)
    return {f.metadata["app_slug"]: f for f in GitHubAppsConnector(ctx).run()}


DEPENDENCY_BOT = _installation("renovate", {"contents": "write", "pull_requests": "write"})
AI_REVIEWER = _installation("coderabbitai", {"contents": "write", "pull_requests": "write", "issues": "write"})
CODING_AGENT = _installation("claude", {"contents": "write", "pull_requests": "write", "actions": "write"}, "selected")


def test_write_access_without_ai_evidence_is_not_an_agent(index, tmp_path):
    found = _run(index, tmp_path, [DEPENDENCY_BOT, AI_REVIEWER])
    assert set(found) == {"coderabbitai"}


def test_repository_writes_are_not_code_execution(index, tmp_path):
    found = _run(index, tmp_path, [AI_REVIEWER, CODING_AGENT])
    assert "code-exec" not in found["coderabbitai"].capabilities
    assert "saas-actions" in found["coderabbitai"].capabilities
    # Dispatching workflow runs executes code with the repository's CI credentials.
    assert "code-exec" in found["claude"].capabilities


@pytest.mark.parametrize("permission", ["workflows", "actions"])
def test_workflow_control_is_code_execution(index, tmp_path, permission):
    found = _run(index, tmp_path, [_installation("coderabbitai", {permission: "write"})])
    assert "code-exec" in found["coderabbitai"].capabilities


def test_unrecognised_apps_are_opt_in_and_capped(index, tmp_path):
    found = _run(index, tmp_path, [DEPENDENCY_BOT, _installation("readme-badge", {"metadata": "read"})],
                 include_unrecognized_apps=True)
    assert set(found) == {"renovate"}  # read-only apps are never reported
    bot = found["renovate"]
    assert "unrecognized-app" in bot.tags
    assert bot.confidence <= UNRECOGNISED_APP_MAX_CONFIDENCE + 1e-9
    assert bot.likelihood in {Likelihood.POSSIBLE, Likelihood.WEAK}


def test_ai_like_names_are_still_reported(index, tmp_path):
    found = _run(index, tmp_path, [_installation("acme-gpt-reviewer", {"pull_requests": "write"})])
    assert "acme-gpt-reviewer" in found and "unrecognized-app" not in found["acme-gpt-reviewer"].tags


def test_include_unrecognized_apps_must_be_boolean(index, tmp_path):
    with pytest.raises(ConnectorError):
        _run(index, tmp_path, [DEPENDENCY_BOT], include_unrecognized_apps="yes")
