"""Provider record collisions must not silently select an attacker-controlled snapshot."""

from __future__ import annotations

import json
from unittest.mock import Mock

import pytest

from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.cloud.azure import AzureConnector
from shadowscan.connectors.identity.entra import EntraConnector
from shadowscan.models import ScanStats


def _run_records(run_connector, tmp_path, connector, records, **config):
    source = tmp_path / "inventory.json"
    source.write_text(json.dumps(records), encoding="utf-8")
    return run_connector(connector, input=str(source), **config)


TEAMS_RISKY = {
    "_kind": "teamsApp",
    "id": "same-app",
    "distributionMethod": "organization",
    "displayName": "OpenAI ChatGPT",
}
TEAMS_BENIGN = {
    "_kind": "teamsApp",
    "id": "same-app",
    "distributionMethod": "store",
    "displayName": "Calendar",
}
TEAMS_NEIGHBOR = {
    "_kind": "teamsApp",
    "id": "neighbor-app",
    "distributionMethod": "organization",
    "displayName": "Claude",
}


@pytest.mark.parametrize("reverse", [False, True])
def test_teams_conflicting_app_snapshots_are_poisoned_and_keep_neighbors(run_connector, tmp_path, reverse):
    pair = [TEAMS_RISKY, TEAMS_BENIGN]
    findings, ctx = _run_records(
        run_connector,
        tmp_path,
        "saas.microsoft-teams",
        [*(pair[::-1] if reverse else pair), TEAMS_NEIGHBOR],
        tenant_id="tenant",
    )

    assert ctx.stats.incomplete and not ctx.stats.errors
    assert [finding.resource for finding in findings] == ["teams:app:neighbor-app"]
    assert sum("conflicting Teams app records" in warning for warning in ctx.stats.warnings) == 1


def test_teams_exact_duplicate_app_snapshot_is_deduplicated(run_connector, tmp_path):
    findings, ctx = _run_records(
        run_connector,
        tmp_path,
        "saas.microsoft-teams",
        [TEAMS_RISKY, TEAMS_RISKY],
        tenant_id="tenant",
    )

    assert not ctx.stats.incomplete
    assert [finding.resource for finding in findings] == ["teams:app:same-app"]


SLACK_TEAM = {"_kind": "team", "id": "T1", "name": "Engineering"}
SLACK_NEIGHBOR = {
    "_kind": "approved_app",
    "app": {"id": "neighbor-app", "name": "Claude"},
    "scopes": [],
}
SLACK_BOT_RISKY = {
    "_kind": "bot_user",
    "id": "U1",
    "is_bot": True,
    "profile": {"api_app_id": "same-app", "real_name": "OpenAI ChatGPT"},
}
SLACK_BOT_BENIGN = {
    "_kind": "bot_user",
    "id": "U2",
    "is_bot": True,
    "profile": {"api_app_id": "same-app", "real_name": "Calendar"},
}
SLACK_APP_RISKY = {
    "_kind": "approved_app",
    "app": {"id": "same-app", "name": "OpenAI ChatGPT"},
    "scopes": ["channels:history"],
}
SLACK_APP_BENIGN = {
    "_kind": "restricted_app",
    "app": {"id": "same-app", "name": "Calendar"},
    "scopes": [],
}


@pytest.mark.parametrize(
    "pair,warning",
    [
        ([SLACK_BOT_RISKY, SLACK_BOT_BENIGN], "conflicting bot records"),
        ([SLACK_APP_RISKY, SLACK_APP_BENIGN], "conflicting app records"),
    ],
)
@pytest.mark.parametrize("reverse", [False, True])
def test_slack_conflicting_identity_snapshots_are_poisoned_and_keep_neighbors(
    run_connector, tmp_path, pair, warning, reverse
):
    findings, ctx = _run_records(
        run_connector,
        tmp_path,
        "saas.slack",
        [SLACK_TEAM, *(pair[::-1] if reverse else pair), SLACK_NEIGHBOR],
    )

    assert ctx.stats.incomplete and not ctx.stats.errors
    assert [finding.resource for finding in findings] == ["slack:app:neighbor-app"]
    assert sum(warning in item for item in ctx.stats.warnings) == 1


@pytest.mark.parametrize("record", [SLACK_BOT_RISKY, SLACK_APP_RISKY])
def test_slack_exact_duplicate_identity_snapshot_is_deduplicated(run_connector, tmp_path, record):
    findings, ctx = _run_records(run_connector, tmp_path, "saas.slack", [SLACK_TEAM, record, record])

    assert not ctx.stats.incomplete
    assert [finding.resource for finding in findings] == ["slack:app:same-app"]


ENTRA_TARGET = {
    "_kind": "servicePrincipal",
    "id": "target",
    "appId": "target-app",
    "displayName": "Internal service",
}
ENTRA_ASSIGNMENT = {
    "_kind": "appRoleAssignment",
    "principalId": "target",
    "appRoleId": "role-1",
}
ENTRA_NEIGHBOR = {
    "_kind": "servicePrincipal",
    "id": "neighbor",
    "appId": "neighbor-app",
    "displayName": "Claude",
}
ENTRA_ROLE_MAP = {"_kind": "roleMap", "roles": {"role-1": "Directory.ReadWrite.All"}}
ENTRA_ROLE_SOURCE = {
    "_kind": "servicePrincipal",
    "id": "resource-service",
    "appId": "resource-app",
    "displayName": "Resource service",
    "appRoles": [{"id": "role-1", "value": "User.Read"}],
}


@pytest.mark.parametrize("reverse", [False, True])
def test_entra_cross_source_role_label_collision_uses_unresolved_id_and_keeps_neighbors(
    run_connector, tmp_path, reverse
):
    definitions = [ENTRA_ROLE_MAP, ENTRA_ROLE_SOURCE]
    findings, ctx = _run_records(
        run_connector,
        tmp_path,
        "identity.entra",
        [*(definitions[::-1] if reverse else definitions), ENTRA_TARGET, ENTRA_ASSIGNMENT, ENTRA_NEIGHBOR],
        tenant_id="tenant",
    )

    assert ctx.stats.incomplete and not ctx.stats.errors
    target = next(finding for finding in findings if finding.resource == "entra:sp:target")
    assert target.metadata["application_permissions"] == ["role-1"]
    assert "Directory.ReadWrite.All" not in target.permissions
    assert "User.Read" not in target.permissions
    assert any(finding.resource == "entra:sp:neighbor" for finding in findings)
    assert sum("conflicting role labels" in warning for warning in ctx.stats.warnings) == 1


def test_entra_exact_duplicate_role_labels_are_deduplicated(run_connector, tmp_path):
    findings, ctx = _run_records(
        run_connector,
        tmp_path,
        "identity.entra",
        [ENTRA_ROLE_MAP, ENTRA_ROLE_MAP, ENTRA_TARGET, ENTRA_ASSIGNMENT],
        tenant_id="tenant",
    )

    assert not ctx.stats.incomplete
    target = next(finding for finding in findings if finding.resource == "entra:sp:target")
    assert target.metadata["application_permissions"] == ["Directory.ReadWrite.All"]


def test_entra_live_collection_preserves_conflicting_role_labels(index):
    context = ConnectorContext(index=index, config={"tenant_id": "tenant"})
    connector = EntraConnector(context)
    connector._auth = Mock()
    connector.http = Mock()

    def pages(path, **kwargs):
        del kwargs
        if path == "/servicePrincipals":
            yield ENTRA_ROLE_SOURCE
            yield {
                **ENTRA_TARGET,
                "appRoles": [{"id": "role-1", "value": "Directory.ReadWrite.All"}],
            }
            yield ENTRA_NEIGHBOR
        elif path == "/servicePrincipals/target/appRoleAssignments":
            yield ENTRA_ASSIGNMENT

    connector._pages = pages
    findings = connector.run()

    assert context.stats.incomplete and not context.stats.errors
    target = next(finding for finding in findings if finding.resource == "entra:sp:target")
    assert target.metadata["application_permissions"] == ["role-1"]
    assert any(finding.resource == "entra:sp:neighbor" for finding in findings)
    assert sum("conflicting role labels" in warning for warning in context.stats.warnings) == 1


POWER_RISKY = {
    "_kind": "bot",
    "botid": "same-bot",
    "name": "OpenAI agent",
    "authenticationmode": 0,
}
POWER_BENIGN = {
    "_kind": "bot",
    "botid": "same-bot",
    "name": "Calendar",
    "authenticationmode": 1,
}
POWER_NEIGHBOR = {"_kind": "bot", "botid": "neighbor-bot", "name": "Claude"}
SALESFORCE_RISKY = {
    "_kind": "BotDefinition",
    "Id": "same-bot",
    "DeveloperName": "OpenAI_Agent",
    "MasterLabel": "OpenAI Agent",
}
SALESFORCE_BENIGN = {
    "_kind": "BotDefinition",
    "Id": "same-bot",
    "DeveloperName": "Calendar",
    "MasterLabel": "Calendar",
}
SALESFORCE_NEIGHBOR = {
    "_kind": "BotDefinition",
    "Id": "neighbor-bot",
    "DeveloperName": "Claude",
    "MasterLabel": "Claude",
}


@pytest.mark.parametrize(
    "connector,pair,neighbor,expected_resource,warning",
    [
        (
            "lowcode.power-platform",
            [POWER_RISKY, POWER_BENIGN],
            POWER_NEIGHBOR,
            "power-platform:bot:neighbor-bot",
            "conflicting bot records",
        ),
        (
            "lowcode.salesforce",
            [SALESFORCE_RISKY, SALESFORCE_BENIGN],
            SALESFORCE_NEIGHBOR,
            "salesforce:bot:neighbor-bot",
            "conflicting bot definitions",
        ),
    ],
)
@pytest.mark.parametrize("reverse", [False, True])
def test_lowcode_conflicting_bot_snapshots_are_poisoned_and_keep_neighbors(
    run_connector, tmp_path, connector, pair, neighbor, expected_resource, warning, reverse
):
    findings, ctx = _run_records(
        run_connector,
        tmp_path,
        connector,
        [*(pair[::-1] if reverse else pair), neighbor],
    )

    assert ctx.stats.incomplete and not ctx.stats.errors
    assert [finding.resource for finding in findings] == [expected_resource]
    assert sum(warning in item for item in ctx.stats.warnings) == 1


@pytest.mark.parametrize(
    "connector,record,expected_resource",
    [
        ("lowcode.power-platform", POWER_RISKY, "power-platform:bot:same-bot"),
        ("lowcode.salesforce", SALESFORCE_RISKY, "salesforce:bot:same-bot"),
    ],
)
def test_lowcode_exact_duplicate_bot_snapshot_is_deduplicated(
    run_connector, tmp_path, connector, record, expected_resource
):
    findings, ctx = _run_records(run_connector, tmp_path, connector, [record, record])

    assert not ctx.stats.incomplete
    assert [finding.resource for finding in findings] == [expected_resource]


@pytest.mark.parametrize("allow_partial", [False, True])
def test_azure_conflicting_continuation_aliases_fail_closed_and_keep_partial_page(index, allow_partial):
    context = ConnectorContext(index=index)
    context.stats = ScanStats(connector="cloud.azure", started_at="2026-01-01")
    connector = AzureConnector(context)
    connector.http = Mock()
    connector.http.get_json.return_value = {
        "value": [{"id": "observed"}],
        "nextLink": "",
        "@odata.nextLink": "/hidden-next-page",
    }

    result = connector._list("/resources", "2022-12-01", allow_partial=allow_partial)

    assert result == ([{"id": "observed"}] if allow_partial else None)
    assert context.stats.incomplete
    assert connector.http.get_json.call_count == 1
    assert sum("conflicting list continuations" in warning for warning in context.stats.warnings) == 1


def test_azure_exact_duplicate_continuation_aliases_are_deduplicated(index):
    context = ConnectorContext(index=index)
    context.stats = ScanStats(connector="cloud.azure", started_at="2026-01-01")
    connector = AzureConnector(context)
    connector.http = Mock()
    connector.http.get_json.side_effect = [
        {
            "value": [{"id": "first"}],
            "nextLink": "/next",
            "@odata.nextLink": "/next",
        },
        {"value": [{"id": "second"}]},
    ]

    assert connector._list("/resources", "2022-12-01") == [
        {"id": "first"},
        {"id": "second"},
    ]
    assert not context.stats.incomplete
