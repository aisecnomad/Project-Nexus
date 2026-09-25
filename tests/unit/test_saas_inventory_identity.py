"""Tenant identity and malformed provider data must survive complete scan gates."""

from __future__ import annotations

import json
from unittest.mock import Mock

import pytest

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors.base import ConnectorContext, ConnectorError
from shadowscan.connectors.saas.slack import SlackConnector
from shadowscan.connectors.saas.teams import TeamsConnector
from shadowscan.engine import Engine, merge

SLACK_APP = {"_kind": "approved_app", "app": {"id": "A1", "name": "Claude"}, "scopes": []}
TEAMS_APP = {"_kind": "teamsApp", "id": "valid-app", "distributionMethod": "organization", "displayName": "ChatGPT"}


def scan(tmp_path, connector, records, **settings):
    source = tmp_path / "inventory.json"
    source.write_text(json.dumps(records), encoding="utf-8")
    return Engine(ScanConfig(connectors=[ConnectorSpec(connector, {"input": str(source), **settings})], parallel=1)).run()


def test_slack_same_app_in_same_named_workspaces_stays_separate(tmp_path):
    first = scan(tmp_path, "saas.slack", [{"_kind": "team", "id": "T1", "name": "Engineering"}, SLACK_APP])
    second = scan(tmp_path, "saas.slack", [{"_kind": "team", "id": "T2", "name": "Engineering"}, SLACK_APP])
    assert first.complete and second.complete
    combined = merge(first.findings + second.findings)
    assert len(combined) == 2
    assert {finding.account for finding in combined} == {"T1", "T2"}
    assert {finding.metadata["workspace_name"] for finding in combined} == {"Engineering"}


def test_slack_workspace_rename_preserves_finding_identity(tmp_path):
    first = scan(tmp_path, "saas.slack", [{"_kind": "team", "id": "T1", "name": "Before"}, SLACK_APP])
    second = scan(tmp_path, "saas.slack", [SLACK_APP, {"_kind": "team", "id": "T1", "name": "After"}])
    assert first.complete and second.complete
    assert first.findings[0].id == second.findings[0].id
    assert second.findings[0].metadata["workspace_name"] == "After"


@pytest.mark.parametrize("records,settings", [
    ([SLACK_APP], {}),
    ([], {}),
    ([{"_kind": "team", "id": "T1"}, SLACK_APP], {"team_id": "T2"}),
    ([{"_kind": "team", "id": "T1"}, SLACK_APP, {"_kind": "team", "id": "T2"}], {}),
    ([{"_kind": "team", "id": "T1"}, SLACK_APP, {"_kind": "team", "name": "Missing"}], {}),
    ([SLACK_APP, {"_kind": "team", "id": None}], {"team_id": "T1"}),
    ([SLACK_APP, {"_kind": "team", "id": "Engineering"}], {}),
    ([{"_kind": "team", "id": "T1"}, {**SLACK_APP, "team_id": "T2"}], {}),
    ([{"_kind": "team", "id": "T1"}, {**SLACK_APP, "team_id": []}], {}),
])
def test_slack_missing_or_conflicting_scope_cannot_pass_or_relabel(tmp_path, records, settings):
    result = scan(tmp_path, "saas.slack", records, **settings)
    assert not result.complete and not result.findings
    assert result.stats[0].warnings


def test_slack_legacy_export_uses_explicit_scope_without_claiming_live_verification(tmp_path):
    result = scan(tmp_path, "saas.slack", [SLACK_APP], team_id="T1")
    assert result.complete and len(result.findings) == 1
    finding = result.findings[0]
    assert finding.account == "T1"
    assert finding.metadata["workspace_scope_source"] == "operator-configured"
    assert finding.metadata["workspace_name"] is None


def test_slack_repeated_matching_team_records_are_safe(tmp_path):
    team = {"_kind": "team", "id": "T1", "name": "Engineering"}
    result = scan(tmp_path, "saas.slack", [team, SLACK_APP, team], team_id="T1")
    assert result.complete and len(result.findings) == 1
    assert result.findings[0].metadata["workspace_scope_source"] == "team-record"


@pytest.mark.parametrize("team_id", ["Engineering", "", " T1", 123, ["T1"]])
def test_slack_config_scope_requires_workspace_id(index, team_id):
    with pytest.raises(ConnectorError, match="Slack workspace ID"):
        SlackConnector(ConnectorContext(index=index, config={"team_id": team_id}))


@pytest.mark.parametrize("record", [
    {"_kind": "teamsApp", "displayName": "ChatGPT", "distributionMethod": "organization"},
    {**TEAMS_APP, "id": None},
    {**TEAMS_APP, "id": " "},
    {**TEAMS_APP, "id": ["bad"]},
    {**TEAMS_APP, "_kind": "unsupported"},
    {**TEAMS_APP, "displayName": []},
    {**TEAMS_APP, "appDefinitions": None},
    {**TEAMS_APP, "appDefinitions": {}},
    {**TEAMS_APP, "appDefinitions": [123]},
    {**TEAMS_APP, "appDefinitions": [{"bot": []}]},
    {**TEAMS_APP, "appDefinitions": [{"bot": {}}]},
    {**TEAMS_APP, "appDefinitions": [{"teamsAppId": "other-app"}]},
    {**TEAMS_APP, "appDefinitions": [{"createdBy": {"user": {"displayName": []}}}]},
    {**TEAMS_APP, "appDefinitions": [{"authorization": []}]},
    {**TEAMS_APP, "appDefinitions": [{"authorization": {"requiredPermissionSet": {"resourceSpecificPermissions": None}}}]},
    {**TEAMS_APP, "appDefinitions": [{"authorization": {"requiredPermissionSet": {"resourceSpecificPermissions": [{"permissionValue": []}]}}}]},
    {"_kind": "installedApp", "id": "installation-is-not-app-identity"},
    {"_kind": "installedApp", "teamsApp": []},
    {"_kind": "installedApp", "teamsApp": {"id": "A1"}, "teamsAppDefinition": []},
    {"_kind": "installedApp", "teamsApp": {"id": "A1"}, "teamsAppDefinition": {"teamsAppId": "A2"}},
])
def test_teams_malformed_records_are_incomplete_and_keep_valid_neighbors(tmp_path, record):
    result = scan(tmp_path, "saas.microsoft-teams", [record, TEAMS_APP], tenant_id="tenant-a")
    assert not result.complete
    assert [finding.resource for finding in result.findings] == ["teams:app:valid-app"]
    assert result.stats[0].warnings and not result.stats[0].errors


def test_teams_missing_app_id_never_invents_none_resource(tmp_path):
    result = scan(tmp_path, "saas.microsoft-teams", [{"_kind": "teamsApp", "distributionMethod": "organization", "displayName": "ChatGPT"}])
    assert not result.complete and not result.findings


def test_teams_installation_uses_definition_catalog_identity(tmp_path):
    result = scan(tmp_path, "saas.microsoft-teams", [{
        "_kind": "installedApp", "id": "installation-1", "_team": "Engineering",
        "teamsAppDefinition": {"teamsAppId": "catalog-1", "displayName": "ChatGPT", "bot": {"id": "bot-1"}},
    }], tenant_id="tenant-a")
    assert result.complete
    finding, = result.findings
    assert finding.resource == "teams:app:catalog-1"
    assert finding.metadata["install_count"] == 1


def test_teams_malformed_live_team_does_not_abort_other_inventory(index):
    connector = TeamsConnector(ConnectorContext(index=index, config={"tenant_id": "tenant-a"}))
    http = Mock()
    connector._client = Mock(return_value=http)

    def pages(path, **kwargs):
        if path == "/appCatalogs/teamsApps":
            yield TEAMS_APP
        elif path == "/teams":
            yield {"displayName": "Missing identity"}
            yield {"id": "team-1"}
        elif path == "/teams/team-1/installedApps":
            yield {"teamsApp": {"id": "valid-app"}}
        else:
            raise AssertionError("unexpected inventory path")

    http.paginate_odata.side_effect = pages
    findings = connector.run()
    assert len(findings) == 1 and findings[0].metadata["install_count"] == 1
    assert connector.ctx.stats.incomplete and not connector.ctx.stats.errors
