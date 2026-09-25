"""Canary acceptance contracts. All transport is stubbed; no live tenant claim."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from shadowscan.models import ScanResult, ScanStats
from tools.canaries.run import CanaryConfigError, evaluate, load_config, main, run, validate

EXAMPLES = Path(__file__).resolve().parents[1] / "examples/canaries"


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE",
                "AWS_DEFAULT_PROFILE", "AWS_WEB_IDENTITY_TOKEN_FILE", "NEXUS_CANARY_SLACK_TOKEN"):
        monkeypatch.delenv(key, raising=False)


@pytest.mark.parametrize("provider", ["aws", "slack"])
def test_replay_contract_is_not_live_acceptance(provider):
    report = run(load_config(EXAMPLES / f"{provider}-replay.yaml"))
    assert report["status"] == "REPLAY_PASS"
    assert report["live_acceptance"] is False
    assert report["scope_verified"] and report["collection_complete"]
    assert all(control["collected_records"] for control in report["controls"])
    assert len(report["signature_sha256"]) == 64
    assert len(report["scanner"]["source_sha256"]) == 64


@pytest.mark.parametrize("provider", ["aws", "slack"])
def test_live_missing_credentials_never_runs_engine(provider, monkeypatch):
    from shadowscan.engine import Engine
    monkeypatch.setattr(Engine, "run", lambda *args: pytest.fail("must not contact tenant without credentials"))
    report = run(load_config(EXAMPLES / f"{provider}-live.yaml"))
    assert report["status"] == "LIVE_NOT_RUN"
    assert not report["live_acceptance"]


def test_cli_missing_credentials_records_truthful_nonzero_result(tmp_path):
    output = tmp_path / "receipt.json"
    assert main([str(EXAMPLES / "aws-live.yaml"), "--output", str(output)]) == 3
    assert json.loads(output.read_text())["status"] == "LIVE_NOT_RUN"
    assert output.stat().st_mode & 0o777 == 0o600


def test_missing_positive_and_missing_negative_both_fail(tmp_path):
    config = load_config(EXAMPLES / "aws-replay.yaml")
    records = Path(config["connector"]["input"]).read_text().splitlines()
    for omitted in (1, 2):
        fixture = tmp_path / "partial.jsonl"
        fixture.write_text("\n".join(row for i, row in enumerate(records) if i != omitted) + "\n")
        config["connector"]["input"] = str(fixture)
        report = run(config)
        assert report["status"] == "REPLAY_FAIL"
        assert report["controls"][omitted - 1]["collected_records"] == 0


def test_positive_misclassification_fails():
    config = load_config(EXAMPLES / "aws-replay.yaml")
    config["controls"][0]["finding"]["kind"] = "agent"
    report = run(config)
    assert report["status"] == "REPLAY_FAIL"
    assert report["controls"][0]["observed_kinds"] == ["cloud-resource"]


def test_expected_benign_false_positive_fails(tmp_path):
    config = load_config(EXAMPLES / "aws-replay.yaml")
    records = [json.loads(line) for line in Path(config["connector"]["input"]).read_text().splitlines()]
    records[2]["Environment"] = {"OPENAI_BASE_URL": "https://api.openai.com/v1"}
    fixture = tmp_path / "false-positive.jsonl"
    fixture.write_text("\n".join(json.dumps(row) for row in records) + "\n")
    config["connector"]["input"] = str(fixture)
    assert run(config)["status"] == "REPLAY_FAIL"


def test_scope_mismatch_fails_even_when_controls_found(tmp_path):
    config = load_config(EXAMPLES / "slack-replay.yaml")
    text = Path(config["connector"]["input"]).read_text().replace('"id":"TEXAMPLE"', '"id":"TOTHER"')
    fixture = tmp_path / "wrong-workspace.jsonl"
    fixture.write_text(text)
    config["connector"]["input"] = str(fixture)
    report = run(config)
    assert report["status"] == "REPLAY_FAIL"
    assert not report["scope_verified"]


def test_slack_canary_rejects_findings_attributed_to_another_workspace(index):
    from shadowscan.connectors.base import ConnectorContext
    from shadowscan.connectors.saas.slack import SlackConnector

    config = load_config(EXAMPLES / "slack-replay.yaml")
    records = [json.loads(line) for line in Path(config["connector"]["input"]).read_text().splitlines()]
    context = ConnectorContext(index=index, config=config["connector"])
    findings = list(SlackConnector(context).analyze(records))
    result = ScanResult(findings=findings, stats=[ScanStats("saas.slack", "now")])
    assert evaluate(config, result, records)["passed"]
    for finding in findings:
        finding.account = "TOTHER"
    verification = evaluate(config, result, records)
    assert not verification["passed"] and not verification["scope_verified"]


@pytest.mark.parametrize("extra", [{"profile": "unreviewed"}, {"role_arn": "arn:aws:iam::123456789012:role/x"},
                                   {"allow_instance_credentials": True}, {"endpoint_url": "http://localhost"}])
def test_connector_escape_hatches_rejected(extra):
    config = load_config(EXAMPLES / "aws-live.yaml")
    config["connector"].update(extra)
    with pytest.raises(CanaryConfigError):
        validate(config)


def test_plugins_code_and_mixed_credentials_rejected():
    for connector in ("code.github", "identity.jwt", "thirdparty.reader"):
        config = load_config(EXAMPLES / "aws-live.yaml")
        config["connector"]["name"] = connector
        with pytest.raises(CanaryConfigError):
            validate(config)
    config = load_config(EXAMPLES / "slack-live.yaml")
    config["connector"]["token"] = "literal-secret-do-not-echo"
    with pytest.raises(CanaryConfigError) as exc:
        validate(config)
    assert "literal-secret" not in str(exc.value)


def test_no_empty_complete_canary_or_replayed_denial():
    config = load_config(EXAMPLES / "aws-replay.yaml")
    config["controls"] = []
    with pytest.raises(CanaryConfigError):
        validate(config)
    config["expectation"] = "permission-denied"
    with pytest.raises(CanaryConfigError):
        validate(config)


@pytest.mark.parametrize("message", ["connection timeout", "invalid_auth", "missing_scope and connection timeout"])
def test_arbitrary_incomplete_result_does_not_pass_denial(message):
    config = load_config(EXAMPLES / "aws-denied.yaml")
    stats = ScanStats("cloud.aws", "now", incomplete=True, warnings=[message])
    records = [{"_kind": "account", "account": "123456789012", "regions": ["us-east-1"]}]
    # A mixed diagnostic list never passes; tokens must not classify an arbitrary
    # error string as permission-only success.
    if " and " in message:
        stats.warnings = message.split(" and ")
    assert not evaluate(config, ScanResult(stats=[stats]), records)["passed"]


def _stub_slack(monkeypatch, *, deny=False, wrong_scope=False, omit_collection=False):
    from shadowscan.utils.http import HttpClient
    calls = []
    records = [json.loads(line) for line in (EXAMPLES / "slack-records.jsonl").read_text().splitlines()]

    def get_json(self, path, params=None):
        calls.append(path)
        if path == "/team.info":
            return {"ok": True, "team": {"id": "TOTHER" if wrong_scope else "TEXAMPLE", "name": "example-workspace"}}
        if deny:
            return {"ok": False, "error": "missing_scope"}
        responses = {
            "/users.list": {"ok": True, "members": []},
            "/admin.apps.approved.list": {"ok": True, "approved_apps": [r for r in records if r.get("app")]},
            "/admin.apps.restricted.list": {"ok": True, "restricted_apps": []},
            "/admin.apps.requests.list": {"ok": True, "app_requests": []},
            "/team.integrationLogs": {"ok": True, "logs": [], "paging": {"pages": 0}},
        }
        if omit_collection and path == "/users.list":
            return {"ok": True}
        assert path in responses, "unexpected endpoint; canaries may only read approved collections"
        return copy.deepcopy(responses[path])

    monkeypatch.setattr(HttpClient, "get_json", get_json)
    monkeypatch.setenv("NEXUS_CANARY_SLACK_TOKEN", "synthetic-transport-test-token")
    return calls


def test_slack_live_path_uses_only_read_operations_with_stubbed_transport(monkeypatch):
    calls = _stub_slack(monkeypatch)
    report = run(load_config(EXAMPLES / "slack-live.yaml"))
    assert report["status"] == "LIVE_PASS"  # Simulated path; never a live tenant evidence artifact.
    assert len(calls) == 6
    assert "synthetic-transport-test-token" not in json.dumps(report)


def test_slack_scope_mismatch_stops_before_inventory(monkeypatch):
    calls = _stub_slack(monkeypatch, wrong_scope=True)
    report = run(load_config(EXAMPLES / "slack-live.yaml"))
    assert report["status"] == "LIVE_FAIL"
    assert calls == ["/team.info"]


def test_slack_denied_identity_is_detected_but_missing_collection_fails(monkeypatch):
    _stub_slack(monkeypatch, deny=True)
    report = run(load_config(EXAMPLES / "slack-denied.yaml"))
    assert report["status"] == "LIVE_PASS"
    assert report["collection_complete"] is False
    assert report["classified_permission_denial"]
    _stub_slack(monkeypatch, omit_collection=True)
    assert run(load_config(EXAMPLES / "slack-live.yaml"))["status"] == "LIVE_FAIL"


def _stub_aws(monkeypatch, *, deny=False, wrong_scope=False):
    boto3 = pytest.importorskip("boto3")
    from botocore.exceptions import ClientError
    calls = []
    records = [json.loads(line) for line in (EXAMPLES / "aws-records.jsonl").read_text().splitlines()][1:]

    class Client:
        def get_caller_identity(self):
            calls.append("sts:GetCallerIdentity")
            return {"Account": "999999999999" if wrong_scope else "123456789012"}

        def get_paginator(self, operation):
            assert operation == "list_functions"
            return self

        def paginate(self, **kwargs):
            calls.append("lambda:ListFunctions")
            if deny:
                raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "not displayed"}}, "ListFunctions")
            functions = [{**record, "Environment": {"Variables": record["Environment"]}} for record in records]
            yield {"Functions": functions}

        def list_tags(self, Resource):
            calls.append("lambda:ListTags")
            return {"Tags": {}}

    class Session:
        def client(self, service, **kwargs):
            assert service in {"sts", "lambda"}, "no unapproved service access"
            return Client()

    monkeypatch.setattr(boto3, "Session", lambda **kwargs: Session())
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "synthetic-access-key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "synthetic-secret-key")
    return calls


def test_aws_live_path_read_only_and_scope_bound_using_stubbed_sdk(monkeypatch):
    calls = _stub_aws(monkeypatch)
    report = run(load_config(EXAMPLES / "aws-live.yaml"))
    assert report["status"] == "LIVE_PASS"
    assert calls == ["sts:GetCallerIdentity", "lambda:ListFunctions", "lambda:ListTags", "lambda:ListTags"]
    assert "synthetic-secret-key" not in json.dumps(report)


def test_aws_wrong_account_never_lists_inventory(monkeypatch):
    calls = _stub_aws(monkeypatch, wrong_scope=True)
    assert run(load_config(EXAMPLES / "aws-live.yaml"))["status"] == "LIVE_FAIL"
    assert calls == ["sts:GetCallerIdentity"]


def test_aws_restricted_existing_identity_requires_denial(monkeypatch):
    _stub_aws(monkeypatch, deny=True)
    report = run(load_config(EXAMPLES / "aws-denied.yaml"))
    assert report["status"] == "LIVE_PASS"
    assert report["classified_permission_denial"]
    assert not report["collection_complete"]


@pytest.mark.parametrize("variable", ["AWS_PROFILE", "AWS_DATA_PATH"])
def test_aws_profiles_rejected_before_transport(monkeypatch, variable):
    monkeypatch.setenv(variable, "unsafe-process-profile")
    report = run(load_config(EXAMPLES / "aws-live.yaml"))
    assert report["status"] == "LIVE_NOT_RUN"
    assert report["reason"] == "ambient_profile_or_web_identity_forbidden"


def test_negative_control_cannot_substitute_account_record_or_unobserved_resource():
    config = load_config(EXAMPLES / "aws-replay.yaml")
    config["controls"][1]["record"] = {"_kind": "account"}
    config["controls"][1]["finding"]["resource"] = "arn:aws:lambda:us-east-1:123456789012:function:DOES-NOT-EXIST"
    with pytest.raises(CanaryConfigError, match="canonical identity"):
        validate(config)
    config = load_config(EXAMPLES / "aws-replay.yaml")
    config["controls"][1]["finding"]["resource"] = "arn:aws:lambda:us-east-1:123456789012:function:DOES-NOT-EXIST"
    with pytest.raises(CanaryConfigError, match="same object"):
        validate(config)


@pytest.mark.parametrize("field", ["mode", "expectation"])
def test_malformed_enum_is_safe_configuration_error(field):
    config = load_config(EXAMPLES / "aws-live.yaml")
    config[field] = {"malformed": []}
    with pytest.raises(CanaryConfigError):
        validate(config)


def test_duplicate_fields_rejected(tmp_path):
    path = tmp_path / "ambiguous.yaml"
    path.write_text((EXAMPLES / "aws-replay.yaml").read_text() + "mode: live\n")
    with pytest.raises(ValueError, match="unique strings"):
        load_config(path)


def test_custom_endpoint_environment_never_runs(monkeypatch):
    monkeypatch.setenv("AWS_ENDPOINT_URL_STS", "http://unapproved.example")
    report = run(load_config(EXAMPLES / "aws-live.yaml"))
    assert report["status"] == "LIVE_NOT_RUN"
    assert report["reason"] == "ambient_endpoint_override_forbidden"


def test_denial_phrase_in_arbitrary_error_never_counts():
    config = load_config(EXAMPLES / "aws-denied.yaml")
    records = [{"_kind": "account", "account": "123456789012", "regions": ["us-east-1"]}]
    stats = ScanStats("cloud.aws", "now", incomplete=True, warnings=["unexpected failure: access denied"])
    assert not evaluate(config, ScanResult(stats=[stats]), records)["passed"]
