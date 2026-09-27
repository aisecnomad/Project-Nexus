"""AWS IAM policy analysis: NotAction complements, AI action patterns and unevaluated qualifiers."""

from __future__ import annotations

from unittest import mock
from unittest.mock import Mock

import pytest

from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.cloud.aws import AwsConnector, _iam_policy_signals
from shadowscan.models import ScanStats

ACCOUNT = "123456789012"


def _context(index, **config) -> ConnectorContext:
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="cloud.aws", started_at="2026-01-01T00:00:00+00:00")
    return ctx


def aws(index, service):
    connector = AwsConnector(ConnectorContext(index=index, config={
        "account_id": ACCOUNT, "services": [service], "regions": ["us-east-1"],
        "cloudtrail_days": 0,
    }))
    connector.check_requirements = Mock()
    connector._session_ = Mock()
    connector._client = Mock(return_value=Mock(list_tags=Mock(return_value={"Tags": {}})))
    return connector


def iam(index, statements, **extra):
    connector = aws(index, "iam")
    connector._paginate_details = Mock(return_value=iter([{
        "_type": "RoleDetailList", "RoleName": "PowerRole",
        "Arn": f"arn:aws:iam::{ACCOUNT}:role/PowerRole",
        "RolePolicyList": [{"PolicyDocument": {"Statement": statements}}], **extra,
    }]))
    return connector


@pytest.mark.parametrize("statement, explicit, potential", [
    ({"Effect": "Allow", "NotAction": ["iam:*", "organizations:*"], "Resource": "*"}, set(), True),
    ({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}, set(), True),
    ({"Effect": "Allow", "NotAction": ["*"], "Resource": "*"}, set(), False),
    ({"Effect": "Deny", "NotAction": ["iam:*"], "Resource": "*"}, set(), False),
    ({"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}, {"s3:GetObject"}, False),
])
def test_not_action_allow_statements_grant_everything_not_listed(statement, explicit, potential):
    actions, _patterns, potential_actions, _limits = _iam_policy_signals([{"Version": "2012-10-17", "Statement": [statement]}])
    assert actions == explicit
    assert bool(potential_actions) is potential
    if potential:
        assert "bedrock:InvokeModel" in potential_actions and not any(a.startswith("iam:") for a in potential_actions)


@pytest.mark.parametrize("actions, reported", [
    (["sagemaker:*"], True), (["sagemaker:InvokeEndpoint"], True), (["sagemaker:ListModels"], False),
    (["bedrock:*"], True), (["*"], True), (["s3:GetObject"], False),
])
def test_iam_collection_reports_service_wildcards_that_include_invoke_actions(index, actions, reported):
    ctx = _context(index, services=["iam"])
    connector = AwsConnector(ctx)
    connector.account = ACCOUNT
    details = [{"_type": "RoleDetailList", "RoleName": "r", "Arn": f"arn:aws:iam::{ACCOUNT}:role/r",
                "RolePolicyList": [{"PolicyName": "p", "PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}]}}],
                "AttachedManagedPolicies": []}]
    with mock.patch.object(connector, "_client", lambda *a, **k: object()), \
            mock.patch.object(connector, "_paginate_details", lambda iam: iter(details)):
        names = [rec["name"] for rec in connector._collect_iam()]
    assert names == (["r"] if reported else [])


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
