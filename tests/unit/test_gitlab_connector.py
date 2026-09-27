"""GitLab code connector: explicit project identity and group-level CI variables."""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.code.gitlab import GitLabConnector, _GitLabMetadata
from shadowscan.models import ScanStats


def test_group_variables_keep_all_names_in_one_finding(index):
    connector = GitLabConnector(ConnectorContext(index=index))
    findings = list(connector.analyze([
        _GitLabMetadata("group_variable", {"group": "team", "key": "OPENAI_API_KEY", "masked": True}),
        _GitLabMetadata("group_variable", {"group": "team", "key": "ANTHROPIC_API_KEY", "masked": False}),
        _GitLabMetadata("group_variables", {"group": "team", "variables": [
            {"key": "GEMINI_API_KEY", "masked": True},
            {"key": 42, "masked": False},
        ]}),
    ]))
    assert len(findings) == 1
    assert set(findings[0].metadata["variable_names"]) == {
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY"
    }
    assert "unmasked-ci-variable" in findings[0].tags


def test_group_collection_redacts_all_variable_values(index):
    connector = GitLabConnector(ConnectorContext(index=index))
    connector._optional_list = Mock(side_effect=[[], [], [
        {"key": "OPENAI_API_KEY", "value": "synthetic-secret-1"},
        {"key": "ANTHROPIC_API_KEY", "value": "synthetic-secret-2"},
    ]])
    connector.http = Mock()
    connector.http.try_get_json.return_value = {}
    records = list(connector._group_identities("team"))
    assert len(records) == 1 and records[0]["_kind"] == "group_variables"
    assert [var["key"] for var in records[0]["variables"]] == ["OPENAI_API_KEY", "ANTHROPIC_API_KEY"]
    assert "synthetic-secret" not in str(records)


@pytest.mark.parametrize("response", [
    {}, None, [], {"id": 7}, {"id": 0, "path_with_namespace": "acme/agent"},
    {"id": 7, "path_with_namespace": " "}, {"id": True, "path_with_namespace": "acme/agent"},
])
def test_gitlab_malformed_explicit_project_response_marks_scan_incomplete(response, index):
    ctx = ConnectorContext(config={"projects": ["acme/agent"]}, index=index)
    ctx.stats = ScanStats(connector="code.gitlab", started_at="2026-01-01T00:00:00Z")
    connector = GitLabConnector(ctx)
    connector.http.try_get_json = Mock(return_value=response)

    records = list(connector.collect())
    assert list(connector.analyze(records)) == []
    assert records == []
    assert ctx.stats.incomplete
    assert any("explicit project response" in warning for warning in ctx.stats.warnings)


def test_gitlab_invalid_explicit_response_does_not_hide_valid_project(index, fixtures, monkeypatch):
    ctx = ConnectorContext(config={"projects": ["acme/broken", "acme/agent"], "use_git": False}, index=index)
    connector = GitLabConnector(ctx)
    connector.http.try_get_json = Mock(side_effect=[{}, {"id": 7, "path_with_namespace": "acme/agent"}])
    fetch = Mock(return_value=str(fixtures / "sample_repo"))
    monkeypatch.setattr(connector, "_fetch", fetch)
    monkeypatch.setattr(connector, "_project_level", lambda _project: iter(()))

    findings = connector.run()  # exercises collect() and analyze() together
    assert any(f.resource_type == "project" and f.frameworks for f in findings)
    assert fetch.call_count == 1
    assert fetch.call_args.args[0]["path_with_namespace"] == "acme/agent"
    assert connector.http.try_get_json.call_count == 2
    assert ctx.stats is not None and ctx.stats.objects_examined >= 1
    assert ctx.stats.incomplete


def test_gitlab_wrong_explicit_project_does_not_hide_valid_neighbor(index, fixtures, monkeypatch):
    ctx = ConnectorContext(config={"projects": ["acme/agent", "acme/valid"], "use_git": False}, index=index)
    connector = GitLabConnector(ctx)
    connector.http.try_get_json = Mock(side_effect=[
        {"id": 7, "path_with_namespace": "acme/other"},
        {"id": 8, "path_with_namespace": "acme/valid"},
    ])
    fetch = Mock(return_value=str(fixtures / "sample_repo"))
    monkeypatch.setattr(connector, "_fetch", fetch)
    monkeypatch.setattr(connector, "_project_level", lambda _project: iter(()))

    findings = connector.run()
    assert any(f.resource_type == "project" and f.frameworks for f in findings)
    assert fetch.call_count == 1
    assert fetch.call_args.args[0]["path_with_namespace"] == "acme/valid"
    assert connector.http.try_get_json.call_count == 2
    assert ctx.stats is not None and ctx.stats.incomplete
    assert any("does not match the requested path or id" in warning for warning in ctx.stats.warnings)


@pytest.mark.parametrize("requested,response", [
    ("Acme/Agent", {"id": 7, "path_with_namespace": "acme/agent"}),
    ("7", {"id": 7, "path_with_namespace": "acme/agent"}),
    ("007", {"id": 7, "path_with_namespace": "acme/agent"}),
])
def test_gitlab_explicit_project_accepts_case_and_numeric_id(requested, response, index):
    ctx = ConnectorContext(config={"projects": [requested]}, index=index)
    ctx.stats = ScanStats(connector="code.gitlab", started_at="2026-01-01T00:00:00Z")
    connector = GitLabConnector(ctx)
    connector.http.try_get_json = Mock(return_value=response)

    assert list(connector.collect()) == [response]
    assert not ctx.stats.incomplete


def test_gitlab_empty_group_listing_is_valid_when_optional_metadata_is_empty(index):
    ctx = ConnectorContext(config={"group": "acme"}, index=index)
    ctx.stats = ScanStats(connector="code.gitlab", started_at="2026-01-01T00:00:00Z")
    connector = GitLabConnector(ctx)
    connector.http.paginate_link = Mock(side_effect=lambda *args, **kwargs: iter(()))
    connector.http.try_get_json = Mock(return_value={})

    records = list(connector.collect())
    assert records == [] and list(connector.analyze(records)) == []
    assert not ctx.stats.incomplete


def test_gitlab_group_records_keep_the_plain_group_path(index):
    connector = GitLabConnector(ConnectorContext(index=index))
    connector._optional_list = Mock(side_effect=[[{"id": 7, "name": "bot"}], [], [{"key": "OPENAI_API_KEY", "masked": True}]])
    connector.http = Mock()
    connector.http.try_get_json.return_value = {}
    records = list(connector._group_identities("my-org/platform"))
    assert {record["_kind"] for record in records} == {"service_account", "group_variables"}
    assert all(record["group"] == "my-org/platform" for record in records)
    assert "%2F" not in str(records)
    calls = [call.args[0] for call in connector._optional_list.call_args_list]
    assert all("/groups/my-org%2Fplatform/" in call for call in calls)
