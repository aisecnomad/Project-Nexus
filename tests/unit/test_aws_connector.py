"""AWS connector collection, analysis and SDK transport contracts, without cloud credentials."""

from __future__ import annotations

import json
from unittest import mock
from unittest.mock import Mock

import pytest

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.base import ConnectorError
from shadowscan.connectors.cloud.aws import AwsConnector
from shadowscan.models import ScanStats
from shadowscan.utils.redaction import REDACTED

ACCOUNT = "123456789012"
KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN"


def context(index, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="test", started_at="2026-01-01")
    return ctx


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


def aws(index, service):
    connector = AwsConnector(ConnectorContext(index=index, config={
        "account_id": ACCOUNT, "services": [service], "regions": ["us-east-1"],
        "cloudtrail_days": 0,
    }))
    connector.check_requirements = Mock()
    connector._session_ = Mock()
    connector._client = Mock(return_value=Mock(list_tags=Mock(return_value={"Tags": {}})))
    return connector


def test_aws_scalar_settings_are_single_items_and_unknown_services_are_rejected(index):
    connector = AwsConnector(context(index, services="lambda", regions="us-east-1"))
    assert connector.services == {"lambda"} and connector.regions == ["us-east-1"]
    with pytest.raises(ConnectorError):
        AwsConnector(context(index, services="nope"))
    with pytest.raises(ConnectorError):
        AwsConnector(context(index, regions="US East"))


def test_aws_layer_name_and_ssm_parameter_arn(index):
    connector = AwsConnector(context(index, account_id="123456789012"))
    finding = connector._h_lambda({
        "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:f", "FunctionName": "f", "_region": "us-east-1",
        "Layers": ["arn:aws:lambda:us-east-1:123456789012:layer:langchain-deps:4"],
    })
    assert finding is not None and "framework.langchain" in finding.frameworks
    plain = connector._h_ssm_parameter({"Name": "OPENAI_API_KEY", "_region": "us-east-1"})
    nested = connector._h_ssm_parameter({"Name": "/prod/OPENAI_API_KEY", "_region": "us-east-1"})
    assert plain is not None and plain.resource == "arn:aws:ssm:us-east-1:123456789012:parameter/OPENAI_API_KEY"
    assert nested is not None and nested.resource == "arn:aws:ssm:us-east-1:123456789012:parameter/prod/OPENAI_API_KEY"


def test_aws_clients_carry_explicit_timeouts(index, monkeypatch):
    pytest.importorskip("botocore")
    connector = AwsConnector(context(index, account_id="123456789012"))
    session = Mock()
    connector._session = session
    connector._client("lambda", "us-east-1")
    config = session.client.call_args.kwargs["config"]
    assert config.connect_timeout == 10 and config.read_timeout == 30
    assert config.retries == {"mode": "standard", "total_max_attempts": 3}


def test_lambda_record_export_round_trip_keeps_resource_identity(tmp_path, index):
    pytest.importorskip("boto3")  # live collection path needs the [aws] extra
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
