"""Slack first_seen is the first enable event; a failed clone never leaks into API mode."""

from __future__ import annotations

import os

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.code.github import GitHubConnector
from shadowscan.connectors.code.gitlab import GitLabConnector
from shadowscan.connectors.saas.slack import SlackConnector
from shadowscan.models import ScanStats


def context(index, name, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector=name, started_at="2026-09-25T00:00:00Z")
    return ctx


def test_slack_first_seen_and_installer_come_from_the_earliest_enable_event(index):
    connector = SlackConnector(context(index, "saas.slack", input="x"))
    records = [
        {"_kind": "team", "id": "T1", "name": "acme", "domain": "acme"},
        {"_kind": "approved_app", "app": {"id": "A1", "name": "Otter.ai Meeting Notes", "app_homepage_url": "https://otter.ai"}, "scopes": [{"name": "channels:history"}]},
        {"_kind": "integration_log", "app_id": "A1", "change_type": "expanded", "date": "1725235200", "user_name": "later.user", "scope": "files:read"},
        {"_kind": "integration_log", "app_id": "A1", "change_type": "added", "date": "1704067200", "user_name": "first.user"},
    ]
    findings = list(connector.analyze(records))
    assert len(findings) == 1
    assert findings[0].owner == "first.user"
    assert findings[0].first_seen.startswith("2024-01-01")


def test_failed_clone_directory_is_removed_before_api_fallback(index, monkeypatch, tmp_path):
    for cls, name, repo in (
        (GitHubConnector, "code.github", {"full_name": "acme/app", "default_branch": "main", "clone_url": "https://github.com/acme/app.git"}),
        (GitLabConnector, "code.gitlab", {"path_with_namespace": "acme/app", "default_branch": "main", "http_url_to_repo": "https://gitlab.com/acme/app.git"}),
    ):
        connector = cls(context(index, name, token="synthetic-token", mode="clone"))
        monkeypatch.setattr("shutil.which", lambda _name: "/usr/bin/git")
        seen = {}

        def partial_clone(_repo, dest):
            os.makedirs(dest)
            with open(os.path.join(dest, "partial.py"), "w") as handle:
                handle.write("from crewai import Agent\n")
            return False

        def api_mode(_repo, tmp):
            seen["leftover"] = os.path.exists(os.path.join(tmp, "repo"))
            return None

        monkeypatch.setattr(connector, "_clone", partial_clone)
        monkeypatch.setattr(connector, "_fetch_via_api", api_mode)
        fetch = connector._fetch_repo if hasattr(connector, "_fetch_repo") else connector._fetch
        assert fetch(repo, str(tmp_path / name.replace(".", "-"))) is None
        assert seen["leftover"] is False
