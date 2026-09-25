"""Regressions from the 2026-09-24 cloud connector review.

All identifiers and credentials below are synthetic.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest import mock

import pytest

from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.cloud.aws import AwsConnector, _iam_policy_signals
from shadowscan.models import ScanStats
from shadowscan.utils.redaction import REDACTED, sanitize

ACCOUNT = "123456789012"
KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN"


def _context(index, **config) -> ConnectorContext:
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="cloud.aws", started_at="2026-01-01T00:00:00+00:00")
    return ctx


def _lambda_record() -> dict:
    return {
        "_kind": "lambda", "_region": "us-east-1", "FunctionName": "prod-agent",
        "FunctionArn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:prod-agent", "Runtime": "python3.12",
        "Role": f"arn:aws:iam::{ACCOUNT}:role/prod-agent", "Handler": "app.handler",
        # Ordinary settings whose values occur inside sibling identifiers, plus a real key.
        "Environment": {"OPENAI_API_KEY": KEY, "STAGE": "prod", "WORKERS": "4", "REGION": "us-east-1"},
        "Layers": [f"arn:aws:lambda:us-east-1:{ACCOUNT}:layer:langchain:3"], "LastModified": "2025-01-01",
        "PackageType": "Zip", "Description": None, "ImageUri": None, "Tags": {},
    }


def test_sanitize_env_values_policy_distinguishes_configuration_from_secrets():
    record = {"arn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:prod-agent", "env": {"STAGE": "prod", "N": "4"}}
    # Tool/agent configuration keeps the strict default: env values are credentials everywhere.
    assert sanitize(record)["arn"] == REDACTED
    inventory = sanitize(record, env_values_are_secrets=False)
    assert inventory["arn"] == record["arn"]
    assert inventory["env"] == {"STAGE": REDACTED, "N": REDACTED}
    # Values under sensitive names and recognizable formats are still removed from siblings.
    leaky = {"note": f"uses {KEY} and opaque-configured-value", "env": {"API_KEY": "opaque-configured-value"}}
    clean = sanitize(leaky, env_values_are_secrets=False)
    assert KEY not in clean["note"] and "opaque-configured-value" not in clean["note"]


def test_lambda_record_export_round_trip_keeps_resource_identity(tmp_path, index):
    dump = tmp_path / "aws.jsonl"
    ctx = _context(index, services=["lambda"], regions=["us-east-1"], _dump_path=str(dump))
    connector = AwsConnector(ctx)
    connector.account = ACCOUNT
    with mock.patch.object(connector, "_session_", lambda: None), \
            mock.patch.object(connector, "_regions", lambda: ["us-east-1"]), \
            mock.patch.object(connector, "_collect_lambda", lambda region: iter([_lambda_record()])):
        live = connector.run()
    assert ctx.stats.incomplete is False and len(live) == 1
    exported = [json.loads(line) for line in dump.read_text().splitlines()]
    lam = next(rec for rec in exported if rec.get("_kind") == "lambda")
    assert lam["FunctionArn"] == f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:prod-agent"
    assert lam["Role"] == f"arn:aws:iam::{ACCOUNT}:role/prod-agent" and lam["FunctionName"] == "prod-agent"
    assert set(lam["Environment"].values()) == {REDACTED}
    assert KEY not in dump.read_text()
    offline_ctx = _context(index, input=str(dump))
    offline = AwsConnector(offline_ctx).run()
    assert offline_ctx.stats.incomplete is False and not offline_ctx.stats.warnings
    assert [(f.id, f.resource, f.account, f.region) for f in offline] == [(live[0].id, live[0].resource, ACCOUNT, "us-east-1")]


def test_sagemaker_environment_values_never_enter_findings_or_wipe_identity(index):
    record = {
        "_kind": "sagemaker-endpoint", "_region": "us-east-1", "EndpointName": "llama-3-endpoint",
        "EndpointArn": f"arn:aws:sagemaker:us-east-1:{ACCOUNT}:endpoint/llama-3-endpoint", "EndpointStatus": "InService",
        "models": [{"name": "llama3", "instance": "ml.g5.12xlarge", "images": ["huggingface-pytorch-tgi-inference:2.3.0"],
                    "env": {"HF_MODEL_ID": "meta-llama/Llama-3-8B", "SM_NUM_GPUS": "4"}, "model_data": []}],
    }
    ctx = _context(index)
    connector = AwsConnector(ctx)
    connector.account = ACCOUNT
    (finding,) = list(connector.analyze([record]))
    finding.sanitize()
    assert finding.account == ACCOUNT and finding.region == "us-east-1"
    assert finding.resource == f"arn:aws:sagemaker:us-east-1:{ACCOUNT}:endpoint/llama-3-endpoint"
    (model,) = finding.metadata["models"]
    assert "env" not in model and model["env_names"] == ["HF_MODEL_ID", "SM_NUM_GPUS"]
    assert "meta-llama" not in json.dumps(finding.to_dict())


def test_bedrock_agent_draft_details_are_a_snapshot_that_survives_export(tmp_path, index):
    class FakeAgents:
        def get_agent(self, agentId):
            return {"agent": {"agentId": agentId, "agentArn": f"arn:aws:bedrock:us-east-1:{ACCOUNT}:agent/{agentId}",
                              "agentName": "ops", "agentStatus": "PREPARED",
                              "foundationModel": "anthropic.claude-3-haiku-20240307-v1:0",
                              "guardrailConfiguration": {"guardrailIdentifier": "g1", "guardrailVersion": "1"}}}

    def paginate(client, op, key, **kwargs):
        return iter([{"agentId": "AGENT1", "agentName": "ops", "agentStatus": "PREPARED"}] if op == "list_agents" else [])

    dump = tmp_path / "aws.jsonl"
    ctx = _context(index, services=["bedrock"], regions=["us-east-1"], _dump_path=str(dump))
    connector = AwsConnector(ctx)
    connector.account = ACCOUNT
    connector._session = object()
    original_safe = connector._safe

    def safe(fn, *args, **kwargs):
        result = original_safe(fn, *args, **kwargs)
        return None if isinstance(result, mock.MagicMock) else result

    with mock.patch.object(connector, "_client", lambda svc, region=None: FakeAgents() if svc == "bedrock-agent" else mock.MagicMock()), \
            mock.patch.object(connector, "_paginate", paginate), mock.patch.object(connector, "_safe", safe), \
            mock.patch.object(connector, "_session_", lambda: None), mock.patch.object(connector, "_regions", lambda: ["us-east-1"]):
        live = connector.run()
    assert not ctx.stats.warnings and [f.metadata["version_models"] for f in live] == [{"DRAFT": "anthropic.claude-3-haiku-20240307-v1:0"}]
    exported = next(json.loads(line) for line in dump.read_text().splitlines() if '"bedrock-agent"' in line)
    assert exported["_version_details"]["DRAFT"]["foundationModel"] == "anthropic.claude-3-haiku-20240307-v1:0"
    assert not any(key.startswith("_") for key in exported["_version_details"]["DRAFT"])
    offline_ctx = _context(index, input=str(dump))
    offline = AwsConnector(offline_ctx).run()
    assert offline_ctx.stats.incomplete is False and not offline_ctx.stats.warnings
    assert offline[0].metadata["version_guardrails"] == {"DRAFT": {"guardrailIdentifier": "g1", "guardrailVersion": "1"}}


def test_bedrock_agent_reads_collapsed_draft_from_older_exports_without_incomplete_coverage(index):
    record = {"_kind": "bedrock-agent", "_region": "us-east-1", "agentId": "AGENT1",
              "agentArn": f"arn:aws:bedrock:us-east-1:{ACCOUNT}:agent/AGENT1", "agentName": "ops", "agentStatus": "PREPARED",
              "foundationModel": "amazon.nova-pro-v1:0", "_version_details": {"DRAFT": REDACTED}, "_action_groups": [],
              "_knowledge_bases": [], "_aliases": []}
    ctx = _context(index)
    connector = AwsConnector(ctx)
    connector.account = ACCOUNT
    (finding,) = list(connector.analyze([record]))
    assert finding.metadata["version_models"] == {"DRAFT": "amazon.nova-pro-v1:0"} and not ctx.stats.warnings


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


def test_bedrock_logging_record_without_configuration_is_unknown_coverage(index):
    ctx = _context(index)
    connector = AwsConnector(ctx)
    connector.account = ACCOUNT
    findings = list(connector.analyze([
        {"_kind": "bedrock-logging", "_region": "us-east-1", "error": {"code": "AccessDenied"}},
        {"_kind": "bedrock-logging", "_region": "eu-west-1"},
        {"_kind": "bedrock-logging", "_region": "us-west-2", "loggingConfig": None},
    ]))
    assert [f.region for f in findings] == ["us-west-2"] and "no-invocation-logging" in findings[0].tags
    assert ctx.stats.incomplete and sum("logging configuration unavailable" in w for w in ctx.stats.warnings) == 2


def test_oci_custom_models_are_selected_by_type_not_vendor(index):
    oci = pytest.importorskip("oci")
    from shadowscan.connectors.cloud.oci import OciConnector

    ctx = _context(index)
    connector = OciConnector(ctx)
    connector.tenancy = "ocid1.tenancy.oc1..t"
    custom = oci.generative_ai.models.ModelSummary(
        id="ocid1.generativeaimodel.oc1..custom1", compartment_id="ocid1.compartment.oc1..c", display_name="my-finetune",
        type="CUSTOM", vendor="cohere", capabilities=["TEXT_GENERATION"], base_model_id="ocid1.generativeaimodel.oc1..base",
        lifecycle_state="ACTIVE")
    base = oci.generative_ai.models.ModelSummary(
        id="ocid1.generativeaimodel.oc1..base", compartment_id="ocid1.compartment.oc1..c", display_name="cohere.command",
        type="BASE", vendor="cohere", capabilities=["TEXT_GENERATION", "FINE_TUNE"], base_model_id=None, lifecycle_state="ACTIVE")

    class GenAI:
        def list_endpoints(self, comp, **kwargs):
            return SimpleNamespace(data=[], has_next_page=False)

        def list_dedicated_ai_clusters(self, comp, **kwargs):
            return SimpleNamespace(data=[], has_next_page=False)

        def list_models(self, comp, **kwargs):
            return SimpleNamespace(data=[custom, base], has_next_page=False)

    def client(cls, region=None):
        if cls is oci.generative_ai.GenerativeAiClient:
            return GenAI()
        raise AttributeError("service unavailable in this test")

    with mock.patch.object(connector, "_client", client):
        records = list(connector._collect_region_comp("us-chicago-1", "ocid1.compartment.oc1..c"))
    custom_models = [(r["display_name"], r["type"]) for r in records if r["_kind"] == "genai-custom-model"]
    assert custom_models == [("my-finetune", "CUSTOM")]
