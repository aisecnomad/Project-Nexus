"""Cloud coverage and access-evidence regressions without live credentials."""

from __future__ import annotations

import sys
from types import SimpleNamespace
from unittest.mock import Mock, call

import pytest

from shadowscan.connectors.base import ConnectorContext, ConnectorError
from shadowscan.connectors.cloud.aws import DEFAULT_REGIONS, AwsConnector
from shadowscan.connectors.cloud.gcp import GcpConnector
from shadowscan.models import Kind, ScanStats, Surface

ACCOUNT = "123456789012"
REGION = "us-east-1"
CLUSTER = f"arn:aws:ecs:{REGION}:{ACCOUNT}:cluster/prod"
SERVICE = f"arn:aws:ecs:{REGION}:{ACCOUNT}:service/prod/worker"
TASK = f"arn:aws:ecs:{REGION}:{ACCOUNT}:task/prod/task1"


def context(index, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="test", started_at="2026-09-23")
    return ctx


def definition(revision, *, family="worker", status="ACTIVE"):
    return {"taskDefinition": {
        "taskDefinitionArn": f"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/{family}:{revision}",
        "family": family, "revision": revision, "status": status,
        "containerDefinitions": [{"name": "worker", "image": "app:latest",
                                  "environment": [{"name": "OPENAI_API_KEY", "value": "${SECRET}"}]}],
    }}


def ecs_connector(index, **config):
    ctx = context(index, **config)
    connector = AwsConnector(ctx)
    client = Mock()
    client.list_clusters.return_value = {"clusterArns": [CLUSTER]}
    client.list_tasks.return_value = {"taskArns": []}
    client.list_services.return_value = {"serviceArns": []}
    client.list_task_definition_families.return_value = {"families": []}
    connector._client = Mock(return_value=client)
    return connector, client, ctx


@pytest.mark.parametrize("regions", [None, [REGION], "all"])
def test_aws_authenticates_before_account_record_without_account_override(index, monkeypatch, regions):
    pytest.importorskip("botocore")  # the live client is configured with the SDK's retry/timeout types
    session = Mock()
    session.client.return_value.get_caller_identity.return_value = {"Account": ACCOUNT}
    session.client.return_value.describe_regions.return_value = {"Regions": [{"RegionName": REGION}]}
    monkeypatch.setitem(sys.modules, "boto3", SimpleNamespace(Session=Mock(return_value=session)))
    ctx = context(index, services=["ecs"], **({"regions": regions} if regions is not None else {}))
    connector = AwsConnector(ctx)
    connector._collect_ecs = Mock(return_value=[])
    records = list(connector.collect())
    assert records == [{"_kind": "account", "account": ACCOUNT,
                        "regions": DEFAULT_REGIONS if regions is None else [REGION]}]
    assert list(connector.analyze(records)) == []
    session.client.return_value.get_caller_identity.assert_called_once_with()
    assert not ctx.stats.incomplete


def test_aws_authentication_failure_does_not_emit_invalid_account_metadata(index, monkeypatch):
    pytest.importorskip("botocore")  # the live client is configured with the SDK's retry/timeout types
    session = Mock()
    session.client.return_value.get_caller_identity.side_effect = RuntimeError("AccessDenied")
    monkeypatch.setitem(sys.modules, "boto3", SimpleNamespace(Session=Mock(return_value=session)))
    connector = AwsConnector(context(index, regions=[REGION]))
    with pytest.raises(ConnectorError, match="cannot authenticate"):
        next(iter(connector.collect()))
    assert connector.run() == []
    assert connector.ctx.stats.incomplete
    assert connector.ctx.stats.errors


def test_ecs_finds_exact_old_inactive_revision_and_keeps_latest_registered_definition(index):
    connector, client, ctx = ecs_connector(index)
    old = definition(7, status="INACTIVE")
    latest = definition(9)
    latest["taskDefinition"]["containerDefinitions"][0]["environment"] = []
    old_arn = old["taskDefinition"]["taskDefinitionArn"]
    latest_arn = latest["taskDefinition"]["taskDefinitionArn"]
    client.list_tasks.return_value = {"taskArns": [TASK]}
    client.describe_tasks.return_value = {"tasks": [{"taskArn": TASK, "taskDefinitionArn": old_arn,
                                                      "lastStatus": "RUNNING", "desiredStatus": "RUNNING"}]}
    client.list_services.return_value = {"serviceArns": [SERVICE]}
    client.describe_services.return_value = {"services": [{"serviceArn": SERVICE, "status": "ACTIVE",
                                                           "taskDefinition": old_arn, "runningCount": 1}]}
    client.list_task_definition_families.return_value = {"families": ["worker"]}
    client.describe_task_definition.side_effect = lambda *, taskDefinition: old if taskDefinition == old_arn else latest
    records = {record["taskDefinitionArn"]: record for record in connector._collect_ecs(REGION)}
    assert set(records) == {old_arn, latest_arn}
    assert records[old_arn]["status"] == "INACTIVE"
    assert records[old_arn]["deployment_state"] == "running-task-observed"
    assert set(records[old_arn]["discovery_sources"]) == {"task", "service"}
    assert records[latest_arn]["deployment_state"] == "registered-only"
    assert records[latest_arn]["workload_references"] == []
    client.describe_task_definition.assert_has_calls([call(taskDefinition=old_arn), call(taskDefinition="worker")])
    assert client.describe_task_definition.call_count == 2
    finding = connector._h_ecs_task_definition(records[old_arn])
    assert finding.kind == Kind.CLOUD_RESOURCE
    assert finding.resource == old_arn
    assert finding.metadata["revision"] == 7
    assert finding.metadata["deployment_state"] == "running-task-observed"
    assert any(e.signal == "aws:ecs-workload-reference" for e in finding.evidence)
    assert connector._h_ecs_task_definition(records[latest_arn]) is None
    assert not ctx.stats.incomplete


def test_ecs_scans_service_rollouts_task_sets_and_pending_tasks_without_claiming_running(index):
    connector, client, ctx = ecs_connector(index)
    revisions = {definition(n)["taskDefinition"]["taskDefinitionArn"]: definition(n) for n in range(1, 5)}
    arns = list(revisions)
    client.list_tasks.return_value = {"taskArns": [TASK]}
    client.describe_tasks.return_value = {"tasks": [{"taskArn": TASK, "taskDefinitionArn": arns[0],
                                                      "lastStatus": "PENDING", "desiredStatus": "RUNNING"}]}
    client.list_services.return_value = {"serviceArns": [SERVICE]}
    client.describe_services.return_value = {"services": [{
        "serviceArn": SERVICE, "status": "ACTIVE", "taskDefinition": arns[1], "desiredCount": 0,
        "deployments": [{"id": "old-rollout", "taskDefinition": arns[2], "runningCount": 0}],
        "taskSets": [{"id": "external", "taskDefinition": arns[3]}],
    }]}
    client.describe_task_definition.side_effect = lambda *, taskDefinition: revisions[taskDefinition]
    records = list(connector._collect_ecs(REGION))
    assert {record["taskDefinitionArn"] for record in records} == set(arns)
    assert {record["deployment_state"] for record in records} == {"workload-referenced"}
    client.list_tasks.assert_called_once_with(maxResults=100, cluster=CLUSTER, desiredStatus="RUNNING")
    assert not ctx.stats.incomplete


def test_ecs_paginates_clusters_tasks_services_and_families_and_batches_descriptions(index):
    connector, client, ctx = ecs_connector(index)
    arn = definition(1)["taskDefinition"]["taskDefinitionArn"]
    cluster2 = CLUSTER + "-2"
    tasks = [TASK + str(i) for i in range(101)]
    services = [SERVICE + str(i) for i in range(11)]
    client.list_clusters.side_effect = [{"clusterArns": [CLUSTER], "nextToken": "c2"}, {"clusterArns": [cluster2]}]

    def list_tasks(**kwargs):
        if kwargs["cluster"] == cluster2:
            return {"taskArns": []}
        return {"taskArns": tasks[100:]} if "nextToken" in kwargs else {"taskArns": tasks[:100], "nextToken": "t2"}

    def list_services(**kwargs):
        if kwargs["cluster"] == cluster2:
            return {"serviceArns": []}
        return {"serviceArns": services[10:]} if "nextToken" in kwargs else {"serviceArns": services[:10], "nextToken": "s2"}

    client.list_tasks.side_effect = list_tasks
    client.list_services.side_effect = list_services
    client.describe_tasks.side_effect = lambda **kw: {"tasks": [{"taskArn": task, "taskDefinitionArn": arn} for task in kw["tasks"]]}
    client.describe_services.side_effect = lambda **kw: {"services": [{"serviceArn": service, "taskDefinition": arn} for service in kw["services"]]}
    client.describe_task_definition.return_value = definition(1)
    client.list_task_definition_families.side_effect = [{"families": [], "nextToken": "f2"}, {"families": ["worker"]}]
    records = list(connector._collect_ecs(REGION))
    assert len(records) == 1
    assert len(records[0]["workload_references"]) == 100
    assert records[0]["workload_reference_count"] == 112
    assert records[0]["workload_references_truncated"] is True
    assert set(records[0]["discovery_sources"]) == {"task", "service", "registered-family"}
    assert [len(c.kwargs["tasks"]) for c in client.describe_tasks.call_args_list] == [100, 1]
    assert [len(c.kwargs["services"]) for c in client.describe_services.call_args_list] == [10, 1]
    assert client.list_clusters.call_count == 2
    assert client.list_task_definition_families.call_count == 2
    assert not ctx.stats.incomplete


@pytest.mark.parametrize("failure", ["denied", "partial", "missing"])
def test_ecs_collection_failures_mark_incomplete_and_preserve_registered_results(index, failure):
    connector, client, ctx = ecs_connector(index)
    client.list_services.return_value = {"serviceArns": [SERVICE]}
    if failure == "denied":
        client.describe_services.side_effect = RuntimeError("AccessDenied")
    elif failure == "partial":
        client.describe_services.return_value = {"services": [], "failures": [{"arn": SERVICE, "reason": "MISSING"}]}
    else:
        client.describe_services.return_value = {"services": []}
    client.list_task_definition_families.return_value = {"families": ["worker"]}
    client.describe_task_definition.return_value = definition(1)
    records = list(connector._collect_ecs(REGION))
    assert len(records) == 1
    assert records[0]["deployment_state"] == "registered-only"
    assert ctx.stats.incomplete


def test_ecs_call_budget_retains_already_described_workloads(index):
    connector, client, ctx = ecs_connector(index, max_ecs_api_calls=5)
    arn = definition(1)["taskDefinition"]["taskDefinitionArn"]
    client.list_tasks.return_value = {"taskArns": [TASK]}
    client.describe_tasks.return_value = {"tasks": [{"taskArn": TASK, "taskDefinitionArn": arn}]}
    client.describe_task_definition.return_value = definition(1)
    records = list(connector._collect_ecs(REGION))
    assert len(records) == 1
    assert len(client.mock_calls) == 5
    assert ctx.stats.incomplete
    assert any("max_ecs_api_calls" in warning for warning in ctx.stats.warnings)


def test_ecs_repeated_pagination_token_marks_incomplete_without_looping(index):
    connector, client, ctx = ecs_connector(index)
    client.list_clusters.side_effect = [{"clusterArns": [], "nextToken": "same"}] * 2
    assert list(connector._collect_ecs(REGION)) == []
    assert client.list_clusters.call_count == 2
    assert ctx.stats.incomplete


@pytest.mark.parametrize("role", ["roles/owner", "roles/editor"])
@pytest.mark.parametrize("member", ["user:owner@example.com", "serviceAccount:worker@test.iam.gserviceaccount.com"])
def test_gcp_broad_roles_are_access_evidence_without_agent_execution_claim(index, role, member):
    connector = GcpConnector(context(index))
    findings = list(connector._h_iam_policy({"_project": "project", "bindings": [{"role": role, "members": [member]}]}))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.kind == Kind.IAM_GRANT
    assert finding.surface == Surface.IDENTITY
    assert finding.permissions == [role]
    assert finding.metadata["broad_roles"] == [role]
    assert finding.metadata["evidence_class"] == "access-grant"
    assert not finding.frameworks and not finding.model_providers and not finding.capabilities
    assert "broad-project-access" in finding.tags
    assert any(e.signal == "gcp:iam-broad-role" for e in finding.evidence)


def test_gcp_combines_broad_and_ai_specific_roles_once_per_member_and_ignores_viewer(index):
    connector = GcpConnector(context(index))
    findings = list(connector._h_iam_policy({"_project": "project", "bindings": [
        {"role": role, "members": ["serviceAccount:worker@example.com"]}
        for role in ["roles/editor", "roles/editor", "roles/aiplatform.user", "roles/viewer"]
    ]}))
    assert len(findings) == 1
    assert findings[0].permissions == ["roles/aiplatform.user", "roles/editor", "roles/viewer"]
    assert "service-account" in findings[0].tags
    assert list(connector._h_iam_policy({"_project": "project", "bindings": [{"role": "roles/viewer", "members": ["user:viewer@example.com"]}]})) == []
