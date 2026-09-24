"""Coverage and policy regressions using provider-shaped responses, no credentials."""

from __future__ import annotations

import json
from unittest.mock import Mock

import pytest
from requests import ConnectionError, Timeout

from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.cloud.aws import AwsConnector
from shadowscan.connectors.lowcode.automation import N8nConnector
from shadowscan.connectors.saas.slack import SlackConnector
from shadowscan.models import ScanStats

ACCOUNT = "123456789012"


def aws(index, service):
    connector = AwsConnector(ConnectorContext(index=index, config={
        "account_id": ACCOUNT, "services": [service], "regions": ["us-east-1"],
        "cloudtrail_days": 0,
    }))
    connector.check_requirements = Mock()
    connector._session_ = Mock()
    connector._client = Mock(return_value=Mock(list_tags=Mock(return_value={"Tags": {}})))
    return connector


@pytest.mark.parametrize("environment", [
    {"Error": {"ErrorCode": "KMSAccessDeniedException", "Message": "sensitive-error-text"}},
    {"Error": {}}, {"Error": None}, None, {"Variables": None},
    {"Variables": {"invalid": 42, "OPENAI_API_KEY": "${SECRET}"}},
    {"Error": {"ErrorCode": "KMSAccessDeniedException"}, "Variables": {"OPENAI_API_KEY": "${SECRET}"}},
])
def test_lambda_environment_failure_preserves_other_signals_and_marks_unknown(index, environment):
    connector = aws(index, "lambda")
    connector._paginate = Mock(return_value=iter([{
        "FunctionName": "worker",
        "FunctionArn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:worker",
        "Environment": environment,
        "Layers": [{"Arn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:layer:langchain:1"}],
    }]))
    findings = connector.run()
    assert len(findings) == 1
    assert "framework.langchain" in findings[0].frameworks
    assert findings[0].metadata["environment_coverage"] == "unknown"
    assert connector.ctx.stats.incomplete and not connector.ctx.stats.errors
    assert "sensitive-error-text" not in str(connector.ctx.stats.warnings)
    if isinstance(environment, dict) and "OPENAI_API_KEY" in (environment.get("Variables") or {}):
        assert "provider.openai" in findings[0].model_providers


def test_lambda_environment_failure_without_ai_signal_still_fails_coverage(index):
    connector = aws(index, "lambda")
    connector._paginate = Mock(return_value=iter([{
        "FunctionName": "worker", "FunctionArn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:worker",
        "Environment": {"Error": {"ErrorCode": "KMSAccessDeniedException"}},
    }]))
    assert connector.run() == []
    assert connector.ctx.stats.incomplete


@pytest.mark.parametrize("fields", [{}, {"Environment": {}}, {"Environment": {"Variables": {}}}])
def test_lambda_known_empty_environment_remains_complete(index, fields):
    connector = aws(index, "lambda")
    connector._paginate = Mock(return_value=iter([{
        "FunctionName": "worker", "FunctionArn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:worker", **fields,
    }]))
    assert connector.run() == []
    assert not connector.ctx.stats.incomplete


def iam(index, statements, **extra):
    connector = aws(index, "iam")
    connector._paginate_details = Mock(return_value=iter([{
        "_type": "RoleDetailList", "RoleName": "PowerRole",
        "Arn": f"arn:aws:iam::{ACCOUNT}:role/PowerRole",
        "RolePolicyList": [{"PolicyDocument": {"Statement": statements}}], **extra,
    }]))
    return connector


def test_notaction_power_policy_is_visible_as_potential_not_effective_access(index):
    connector = iam(index, [{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}])
    findings = connector.run()
    assert len(findings) == 1
    finding = findings[0]
    assert "bedrock:InvokeModel" in finding.metadata["potential_actions"]
    assert "sagemaker:InvokeEndpoint" in finding.metadata["potential_actions"]
    assert finding.metadata["effective_permissions"] == "not-evaluated"
    assert "bedrock:InvokeModel" not in finding.permissions  # inferred actions are separate
    assert "potential" in finding.title
    assert connector.ctx.stats.incomplete and not connector.ctx.stats.errors


@pytest.mark.parametrize("resource", ["arn:aws:s3:::bucket/*", ["arn:aws:iam::123456789012:role/*", "arn:aws:s3:::bucket/*"]])
def test_notaction_non_ai_resource_cannot_imply_ai_access(index, resource):
    connector = iam(index, [{"Effect": "Allow", "NotAction": "s3:DeleteBucket", "Resource": resource}])
    assert connector.run() == []
    assert connector.ctx.stats.incomplete  # complement evaluation is deliberately partial


@pytest.mark.parametrize("action,resource", [
    ("s3:*", "*"), ("iam:*", "*"), ("lambda:*", "*"),
    ("*", "arn:aws:s3:::bucket/*"), ("bedrock:*", "arn:aws:s3:::bucket/*"),
])
def test_explicit_non_ai_permission_scope_does_not_emit_llm_grant(index, action, resource):
    connector = iam(index, [{"Effect": "Allow", "Action": action, "Resource": resource}])
    assert connector.run() == []
    assert not connector.ctx.stats.incomplete


@pytest.mark.parametrize("actions", [["s3:*"], ["iam:*"], ["s3:*", "iam:*", "lambda:*"]])
def test_legacy_iam_records_with_unrelated_wildcards_do_not_emit_llm_grant(index, actions):
    connector = aws(index, "iam")
    connector.collect = Mock(return_value=iter([{
        "_kind": "iam-principal", "name": "storage-admin", "type": "Role",
        "arn": f"arn:aws:iam::{ACCOUNT}:role/storage-admin", "actions": actions,
    }]))
    assert connector.run() == []
    assert not connector.ctx.stats.incomplete


def test_iam_ai_grant_retains_ancillary_privilege_evidence(index):
    connector = iam(index, [{"Effect": "Allow", "Action": ["bedrock:InvokeModel", "s3:*", "iam:*"], "Resource": "*"}])
    finding, = connector.run()
    assert finding.metadata["ai_action_patterns"] == ["bedrock:InvokeModel"]
    assert {"s3:*", "iam:*"} <= set(finding.permissions)
    assert "policy.privileged-scopes" in finding.tags


def test_ai_action_pattern_grants_are_not_limited_to_literal_prefixes(index):
    connector = iam(index, [{"Effect": "Allow", "Action": "bed*:*", "Resource": "*"}])
    finding, = connector.run()
    assert finding.metadata["ai_action_patterns"] == ["bed*:*"]


def test_notaction_exclusions_are_case_insensitive_and_resource_scoped(index):
    connector = iam(index, [{"Effect": "Allow", "NotAction": "BeDrOcK:InvokeModel*", "Resource": "arn:aws:bedrock:us-east-1:*:*"}])
    finding, = connector.run()
    potential = finding.metadata["potential_actions"]
    assert "bedrock:InvokeAgent" in potential
    assert all(action.startswith("bedrock:") and not action.startswith("bedrock:InvokeModel") for action in potential)


@pytest.mark.parametrize("statement", [
    {"Effect": "Allow", "NotAction": "*", "Resource": "*"},
    {"Effect": "Allow", "NotAction": "iam:*", "NotResource": "arn:aws:s3:::bucket/*"},
    {"Effect": "Allow", "NotAction": "iam:*", "Resource": 12},
    {"Effect": "Allow", "NotAction": 12, "Resource": "*"},
    {"Effect": ["Allow"], "Action": "bedrock:*", "Resource": "*"},
])
def test_unhandled_iam_semantics_never_silently_claim_complete(index, statement):
    connector = iam(index, [statement])
    assert connector.run() == []
    assert connector.ctx.stats.incomplete and not connector.ctx.stats.errors


@pytest.mark.parametrize("extra,statements,limitation", [
    ({"PermissionsBoundary": {"PermissionsBoundaryArn": "arn:aws:iam::123456789012:policy/boundary"}}, [], "permissions-boundary-not-evaluated"),
    ({}, [{"Effect": "Deny", "Action": "bedrock:*", "Resource": "*"}], "explicit-deny-not-evaluated"),
    ({}, [{"Effect": "Allow", "Action": "bedrock:*", "Resource": "*", "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}], "conditions-not-evaluated"),
])
def test_iam_qualifiers_remain_visible_without_asserting_effective_permissions(index, extra, statements, limitation):
    connector = iam(index, [{"Effect": "Allow", "Action": "bedrock:*", "Resource": "*"}, *statements], **extra)
    finding, = connector.run()
    assert limitation in finding.metadata["policy_limitations"]
    assert finding.metadata["effective_permissions"] == "not-evaluated"
    assert connector.ctx.stats.incomplete


def slack(index, monkeypatch, responses, **config):
    connector = SlackConnector(ConnectorContext(index=index, config={"token": "test", **config}))
    calls = []

    def get(path, params=None):
        calls.append(path)
        default = {
            "/team.info": {"ok": True, "team": {"id": "T1", "name": "Example"}},
            "/users.list": {"ok": True, "members": []},
            "/admin.apps.approved.list": {"ok": True, "approved_apps": []},
            "/admin.apps.restricted.list": {"ok": True, "restricted_apps": []},
            "/admin.apps.requests.list": {"ok": True, "app_requests": []},
            "/team.integrationLogs": {"ok": True, "logs": [], "paging": {"pages": 0}},
        }
        response = responses.get(path, default[path])
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr("shadowscan.connectors.saas.slack.HttpClient", Mock(return_value=Mock(get_json=get)))
    return connector, calls


@pytest.mark.parametrize("path,key", [
    ("/users.list", "members"), ("/admin.apps.approved.list", "approved_apps"),
    ("/admin.apps.restricted.list", "restricted_apps"), ("/admin.apps.requests.list", "app_requests"),
    ("/team.integrationLogs", "logs"),
])
@pytest.mark.parametrize("value", [None, "missing", {}, "invalid"])
def test_slack_missing_or_invalid_success_collections_are_incomplete(index, monkeypatch, path, key, value):
    response = {"ok": True, "paging": {"pages": 0}}
    if value != "missing":
        response[key] = value
    connector, _ = slack(index, monkeypatch, {path: response})
    assert connector.run() == []
    assert connector.ctx.stats.incomplete and not connector.ctx.stats.errors


def test_slack_explicit_empty_inventories_are_complete(index, monkeypatch):
    connector, _ = slack(index, monkeypatch, {}, team_id="T1")
    assert connector.run() == []
    assert not connector.ctx.stats.incomplete


@pytest.mark.parametrize("response", [{"ok": True}, {"ok": True, "team": {}}, {"ok": True, "team": {"id": "T2"}}])
def test_slack_unknown_or_mismatched_workspace_stops_before_inventory(index, monkeypatch, response):
    connector, calls = slack(index, monkeypatch, {"/team.info": response}, team_id="T1")
    assert connector.run() == []
    assert connector.ctx.stats.incomplete
    assert calls == ["/team.info"]


@pytest.mark.parametrize("failure", [ConnectionError("sensitive-provider-message"), Timeout("sensitive-provider-message"), ValueError("sensitive-provider-message")])
def test_slack_later_transport_or_parse_failure_preserves_collected_bot(index, monkeypatch, failure):
    connector, calls = slack(index, monkeypatch, {
        "/users.list": {"ok": True, "members": [{"id": "U1", "name": "Claude", "is_bot": True,
            "profile": {"api_app_id": "A1", "real_name": "Claude"}}]},
        "/admin.apps.approved.list": failure,
    })
    finding, = connector.run()
    assert finding.resource == "slack:app:A1"
    assert "/admin.apps.restricted.list" in calls
    assert connector.ctx.stats.incomplete and not connector.ctx.stats.errors
    assert "sensitive-provider-message" not in str(connector.ctx.stats.warnings)


@pytest.mark.parametrize("metadata", [None, [], {"next_cursor": True}, {"next_cursor": 1}, {"next_cursor": None}])
def test_slack_invalid_cursor_is_unknown_coverage(index, monkeypatch, metadata):
    connector, _ = slack(index, monkeypatch, {"/users.list": {"ok": True, "members": [], "response_metadata": metadata}})
    assert connector.run() == []
    assert connector.ctx.stats.incomplete


@pytest.mark.parametrize("paging", [None, {}, {"pages": "1"}, {"pages": True}, {"pages": -1}])
def test_slack_invalid_integration_paging_is_unknown_coverage(index, monkeypatch, paging):
    connector, _ = slack(index, monkeypatch, {"/team.integrationLogs": {"ok": True, "logs": [], "paging": paging}})
    assert connector.run() == []
    assert connector.ctx.stats.incomplete


@pytest.mark.parametrize("graph", [{}, {"nodes": None}, {"nodes": {}}, {"nodes": [] , "error": "denied"}])
def test_n8n_missing_or_invalid_graph_preserves_next_workflow(index, graph):
    connector = N8nConnector(ConnectorContext(index=index))
    connector.collect = Mock(return_value=iter([
        {"id": "bad", "name": "unknown", **graph},
        {"id": "good", "name": "assistant", "nodes": [{"type": "@n8n/n8n-nodes-langchain.agent", "name": "Agent"}]},
    ]))
    finding, = connector.run()
    assert finding.resource == "n8n:workflow:good"
    assert connector.ctx.stats.incomplete and not connector.ctx.stats.errors


def test_n8n_empty_graph_is_known_empty(index):
    connector = N8nConnector(ConnectorContext(index=index))
    connector.collect = Mock(return_value=iter([{"id": "empty", "name": "Empty", "nodes": []}]))
    assert connector.run() == []
    assert not connector.ctx.stats.incomplete


@pytest.mark.parametrize("code,expected", [("AccessDenied", "access denied"), ("AccessDeniedException", "access denied"), ("UnauthorizedOperation", "access denied"), ("ExpiredToken", "SDKError")])
def test_aws_denial_diagnostic_has_safe_machine_readable_code(index, code, expected):
    class SDKError(Exception):
        response = {"Error": {"Code": code, "Message": "sensitive-provider-message"}}

    connector = aws(index, "lambda")
    connector.ctx.stats = ScanStats(connector=connector.name, started_at="2026-09-24")
    client = Mock()
    client.get_paginator.side_effect = SDKError("sensitive-provider-message")
    assert list(connector._pages(client, "list_functions")) == []
    assert expected in connector.ctx.stats.warnings[0]
    assert "sensitive-provider-message" not in connector.ctx.stats.warnings[0]


def test_aws_transport_ignores_ambient_service_endpoint_overrides(index, monkeypatch):
    boto3 = pytest.importorskip("boto3")
    monkeypatch.setenv("AWS_ENDPOINT_URL", "https://untrusted.example")
    monkeypatch.setenv("AWS_ENDPOINT_URL_STS", "https://untrusted-sts.example")
    client = boto3.client("sts", region_name="us-east-1", aws_access_key_id="test",
                         aws_secret_access_key="test", config=AwsConnector._sdk_config())
    assert client.meta.endpoint_url == "https://sts.us-east-1.amazonaws.com"


@pytest.mark.parametrize("assume_role", [False, True])
def test_aws_signed_endpoint_rules_ignore_external_sdk_models(index, monkeypatch, tmp_path, assume_role):
    boto3 = pytest.importorskip("boto3")
    from botocore.loaders import Loader

    external = tmp_path / "models" / "sts" / "2011-06-15"
    external.mkdir(parents=True)
    (external / "endpoint-rule-set-1.json").write_text(json.dumps({
        "version": "1.0", "parameters": {}, "rules": [{"conditions": [], "type": "endpoint",
            "endpoint": {"url": "http://127.0.0.1:8000", "properties": {}, "headers": {}}}],
    }))
    monkeypatch.setenv("AWS_DATA_PATH", str(tmp_path / "models"))
    monkeypatch.setattr(Loader, "CUSTOMER_DATA_PATH", str(tmp_path / "models"))
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    sts = Mock()
    sts.get_caller_identity.return_value = {"Account": ACCOUNT}
    sts.assume_role.return_value = {"Credentials": {
        "AccessKeyId": "assumed-test", "SecretAccessKey": "assumed-test", "SessionToken": "assumed-token",
    }}
    monkeypatch.setattr(boto3.Session, "client", Mock(return_value=sts))
    connector = AwsConnector(ConnectorContext(index=index, config={
        "account_id": ACCOUNT, **({"role_arn": f"arn:aws:iam::{ACCOUNT}:role/audit"} if assume_role else {}),
    }))
    session = connector._session_()
    loader = session._session.get_component("data_loader")
    assert str(tmp_path / "models") not in loader.search_paths
    assert "127.0.0.1" not in json.dumps(loader.load_service_model("sts", "endpoint-rule-set-1"))
    assert sts.assume_role.call_count == int(assume_role)
