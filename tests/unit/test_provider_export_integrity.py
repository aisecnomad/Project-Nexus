"""Provider errors and unsupported exports must never satisfy a clean scan gate."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.connectors.base import BaseConnector

CASES = [
    (
        "identity.entra",
        {"_kind": "servicePrincipal", "id": "sp-valid", "appId": "app-valid", "displayName": "Claude"},
        {"value": []},
        {"_kind": "servicePrincipal", "displayName": "Missing identity"},
        {"_kind": "roleMap", "roles": {}},
    ),
    (
        "lowcode.power-platform",
        {"_kind": "bot", "botid": "bot-valid", "name": "Agent"},
        {"value": []},
        {"_kind": "flow", "properties": {"displayName": "Missing identity"}},
        {"_kind": "environment", "name": "env-valid", "properties": {}},
    ),
    (
        "saas.slack",
        {"_kind": "approved_app", "app": {"id": "A-valid", "name": "Claude"}, "scopes": ["channels:history"]},
        {"ok": True, "approved_apps": []},
        {"_kind": "approved_app", "app": {"name": "Missing identity"}, "scopes": []},
        {"id": "U1", "name": "alice", "is_bot": False, "is_app_user": False},
    ),
]


@pytest.mark.parametrize("connector,valid,empty,malformed,informational", CASES)
@pytest.mark.parametrize("body", [
    {"error": {"code": "Authorization_RequestDenied", "message": "opaque-synthetic-sensitive-error"}},
    {"ok": False, "error": "invalid_auth"},
    {"unexpected": "wrong-export-file"},
    {"_kind": "unknown-record-type", "id": "looks-valid"},
])
def test_cli_rejects_failed_or_unknown_exports(tmp_path, connector, valid, empty, malformed, informational, body):
    source = tmp_path / "failed.json"
    output = tmp_path / "report.json"
    source.write_text(json.dumps(body), encoding="utf-8")
    result = CliRunner().invoke(main, ["run", connector, "--input", str(source), "--format", "json", "-o", str(output), "--fail-on", "high"])
    assert result.exit_code == 3, result.output
    report = json.loads(output.read_text())
    assert report["summary"]["complete"] is False
    assert report["findings"] == []
    assert report["stats"][0]["incomplete"]
    assert report["stats"][0]["errors"] or report["stats"][0]["warnings"]
    assert "opaque-synthetic-sensitive-error" not in output.read_text() + result.output


@pytest.mark.parametrize("connector,valid,empty,malformed,informational", CASES)
@pytest.mark.parametrize("suffix", ["json", "jsonl"])
def test_mixed_provider_records_keep_valid_neighbors(tmp_path, run_connector, connector, valid, empty, malformed, informational, suffix):
    source = tmp_path / f"mixed.{suffix}"
    records = [{"error": {"message": "denied"}}, malformed, valid, {"_kind": "unsupported", "id": "x"}, informational]
    source.write_text(json.dumps(records) if suffix == "json" else "\n".join(json.dumps(record) for record in records), encoding="utf-8")
    findings, ctx = run_connector(connector, input=str(source))
    assert len(findings) == 1
    assert ctx.stats.objects_examined == 1
    assert ctx.stats.incomplete
    assert not any("unexpected error" in message.lower() for message in ctx.stats.errors)


@pytest.mark.parametrize("connector,valid,empty,malformed,informational", CASES)
@pytest.mark.parametrize("kind", ["array", "native", "informational"])
def test_explicit_empty_and_informational_records_remain_complete(tmp_path, run_connector, connector, valid, empty, malformed, informational, kind):
    body = {"array": [], "native": empty, "informational": informational}[kind]
    source = tmp_path / "valid.json"
    source.write_text(json.dumps(body), encoding="utf-8")
    findings, ctx = run_connector(connector, input=str(source))
    assert not findings and not ctx.stats.incomplete
    assert not ctx.stats.errors and not ctx.stats.warnings


@pytest.mark.parametrize("connector,record", [
    ("identity.entra", {"_kind": "servicePrincipal", "id": ["invalid"], "displayName": "Claude"}),
    ("identity.entra", {"_kind": "servicePrincipal", "id": "bad", "appRoles": [123]}),
    ("identity.entra", {"_kind": "servicePrincipal", "id": "bad", "verifiedPublisher": {"displayName": ["invalid"]}}),
    ("identity.entra", {"_kind": "application", "appId": "bad", "requiredResourceAccess": [{"resourceAccess": [123]}]}),
    ("identity.entra", {"_kind": "roleMap", "roles": {"role": []}}),
    ("identity.entra", {"_kind": "oauth2PermissionGrant", "clientId": "sp", "scope": []}),
    ("identity.entra", {"_kind": "appRoleAssignment", "principalId": "sp"}),
    ("lowcode.power-platform", {"_kind": "flow", "name": "bad", "properties": []}),
    ("lowcode.power-platform", {"_kind": "flow", "name": "bad", "properties": {"definitionSummary": "invalid"}}),
    ("lowcode.power-platform", {"_kind": "flow", "name": "bad", "properties": {"definitionSummary": {"actions": [{"type": {"bad": True}}]}}}),
    ("lowcode.power-platform", {"_kind": "botcomponent", "botcomponentid": "orphan"}),
    ("lowcode.power-platform", {"_kind": "bot", "botid": {"bad": True}}),
    ("saas.slack", {"_kind": "approved_app", "app": ["invalid"]}),
    ("saas.slack", {"_kind": "bot_user", "id": "bad", "profile": []}),
    ("saas.slack", {"_kind": "bot_user", "id": "bad", "real_name": ["invalid"]}),
    ("saas.slack", {"_kind": "integration_log", "change_type": "added"}),
    ("saas.slack", {"_kind": "app_request", "app": {"id": {"bad": True}}}),
])
def test_malformed_provider_fields_do_not_abort_valid_neighbors(tmp_path, run_connector, connector, record):
    valid = next(case[1] for case in CASES if case[0] == connector)
    source = tmp_path / "mixed.json"
    source.write_text(json.dumps([record, valid]), encoding="utf-8")
    findings, ctx = run_connector(connector, input=str(source))
    assert len(findings) == 1 and ctx.stats.incomplete
    assert ctx.stats.warnings and not ctx.stats.errors


@pytest.mark.parametrize("envelope,status", [("approved_apps", "approved"), ("restricted_apps", "restricted"), ("app_requests", "requested")])
def test_slack_native_admin_envelopes_preserve_record_kind(tmp_path, run_connector, envelope, status):
    source = tmp_path / "slack.json"
    source.write_text(json.dumps({"ok": True, envelope: [{"app": {"id": "A1", "name": "Claude"}, "scopes": []}]}), encoding="utf-8")
    findings, ctx = run_connector("saas.slack", input=str(source))
    assert len(findings) == 1 and not ctx.stats.incomplete
    assert findings[0].metadata["status"] == status


def test_error_envelope_keeps_successful_partial_records(tmp_path, run_connector):
    source = tmp_path / "partial.json"
    source.write_text(json.dumps({"value": [CASES[0][1]], "error": {"message": "later page denied"}}), encoding="utf-8")
    findings, ctx = run_connector("identity.entra", input=str(source))
    assert len(findings) == 1 and ctx.stats.incomplete and ctx.stats.errors


def test_native_resource_with_error_field_is_not_treated_as_provider_response():
    # Log events may legitimately describe an application error; the shared
    # loader must preserve their payload for the owning connector to interpret.
    record = {"id": "log-1", "error": {"code": "upstream-timeout"}, "data": [{"attempt": 1}]}
    assert list(BaseConnector._unwrap(record)) == [record]


TOKEN = {"clientId": "client-1", "displayText": "Claude", "scopes": ["https://www.googleapis.com/auth/gmail.readonly"]}


@pytest.mark.parametrize("suffix", ["json", "yaml", "jsonl"])
def test_google_per_user_exports_are_equivalent(tmp_path, run_connector, suffix):
    import yaml

    per_user = {"user": "alice@example.test", "tokens": [TOKEN]}
    if suffix == "jsonl":
        variants = [per_user, {"records": [per_user]}, {"userEmail": "alice@example.test", **TOKEN}]
    else:
        variants = [per_user, [per_user], {"records": [per_user]}, {"userEmail": "alice@example.test", **TOKEN}]
    findings = []
    for number, body in enumerate(variants):
        source = tmp_path / f"tokens-{number}.{suffix}"
        source.write_text(yaml.safe_dump(body) if suffix == "yaml" else json.dumps(body), encoding="utf-8")
        result, ctx = run_connector("identity.google-workspace", input=str(source))
        assert not ctx.stats.incomplete
        assert len(result) == 1 and ctx.stats.objects_examined == 1
        assert result[0].metadata["user_count"] == 1
        assert result[0].metadata["users_sample"] == ["alice@example.test"]
        findings.append(result[0].to_dict())
    assert all(finding == findings[0] for finding in findings)


def test_google_multiple_users_are_aggregated_after_normalization(tmp_path, run_connector):
    source = tmp_path / "tokens.json"
    source.write_text(json.dumps([
        {"user": "alice@example.test", "tokens": [TOKEN]},
        {"user": "bob@example.test", "tokens": [TOKEN]},
        {"user": "alice@example.test", "tokens": [TOKEN]},
    ]), encoding="utf-8")
    findings, ctx = run_connector("identity.google-workspace", input=str(source))
    assert not ctx.stats.incomplete and len(findings) == 1
    assert findings[0].metadata["user_count"] == 2


@pytest.mark.parametrize("invalid", [
    {"user": "alice@example.test", "tokens": None},
    {"user": ["not-a-user"], "tokens": [TOKEN]},
    {"user": "alice@example.test", "tokens": [{"clientId": ["invalid"]}]},
    {"user": "alice@example.test", "tokens": [{"error": "denied"}]},
])
def test_google_malformed_user_exports_keep_other_users(tmp_path, run_connector, invalid):
    source = tmp_path / "tokens.json"
    source.write_text(json.dumps([invalid, {"user": "bob@example.test", "tokens": [TOKEN]}]), encoding="utf-8")
    findings, ctx = run_connector("identity.google-workspace", input=str(source))
    assert ctx.stats.incomplete and len(findings) == 1
    assert findings[0].metadata["user_count"] == 1
    assert findings[0].metadata["users_sample"] == ["bob@example.test"]
