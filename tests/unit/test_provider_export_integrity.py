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
    findings, ctx = run_connector(connector, input=str(source), **({"team_id": "T1"} if connector == "saas.slack" else {}))
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
    findings, ctx = run_connector(connector, input=str(source), **({"team_id": "T1"} if connector == "saas.slack" else {}))
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
    findings, ctx = run_connector(connector, input=str(source), **({"team_id": "T1"} if connector == "saas.slack" else {}))
    assert len(findings) == 1 and ctx.stats.incomplete
    assert ctx.stats.warnings and not ctx.stats.errors


@pytest.mark.parametrize("envelope,status", [("approved_apps", "approved"), ("restricted_apps", "restricted"), ("app_requests", "requested")])
def test_slack_native_admin_envelopes_preserve_record_kind(tmp_path, run_connector, envelope, status):
    source = tmp_path / "slack.json"
    source.write_text(json.dumps({"ok": True, envelope: [{"app": {"id": "A1", "name": "Claude"}, "scopes": []}]}), encoding="utf-8")
    findings, ctx = run_connector("saas.slack", input=str(source), team_id="T1")
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
        result, ctx = run_connector("identity.google-workspace", input=str(source), customer="C01234567")
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
    findings, ctx = run_connector("identity.google-workspace", input=str(source), customer="C01234567")
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
    findings, ctx = run_connector("identity.google-workspace", input=str(source), customer="C01234567")
    assert ctx.stats.incomplete and len(findings) == 1
    assert findings[0].metadata["user_count"] == 1
    assert findings[0].metadata["users_sample"] == ["bob@example.test"]


def _offline(run_connector, tmp_path, name, payload, **config):
    path = tmp_path / f"{name.replace('.', '_')}.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return run_connector(name, input=str(path), **config)


@pytest.mark.parametrize("connector,body", [
    ("lowcode.n8n", {"message": "'X-N8N-API-KEY' header required"}),
    ("lowcode.make", {"detail": "Access denied", "message": "Access denied", "code": "IM002"}),
    ("lowcode.workato", {"message": "Unauthorized"}),
    ("saas.notion", {"object": "error", "status": 401, "code": "unauthorized", "message": "API token is invalid."}),
])
def test_provider_error_bodies_are_not_empty_inventories(run_connector, tmp_path, connector, body):
    findings, ctx = _offline(run_connector, tmp_path, connector, body)
    assert findings == []
    assert ctx.stats.incomplete and ctx.stats.warnings and not ctx.stats.errors


_GOOD = {
    "lowcode.n8n": ({"id": "w1", "name": "Good workflow", "nodes": [{"name": "Agent", "type": "@n8n/n8n-nodes-langchain.agent", "parameters": {"model": "gpt-4o"}}]}, "Good workflow"),
    "lowcode.workato": ({"id": 1, "name": "Good recipe", "code": "{\"provider\":\"openai\"}", "config": [{"provider": "openai"}]}, "Good recipe"),
    "lowcode.make": ({"_kind": "ai-agent", "id": "ag1", "name": "Good agent", "model": "gpt-4o"}, "Good agent"),
    "lowcode.zapier": ({"id": "z1", "title": "Claude summarizer", "steps": [{"app": {"title": "Anthropic (Claude)"}}]}, "Claude summarizer"),
    "saas.microsoft-teams": ({"id": "app-1", "displayName": "Copilot Helper Bot", "distributionMethod": "organization", "appDefinitions": [{"displayName": "Copilot Helper Bot", "bot": {"id": "bot-1"}}]}, "Copilot Helper Bot"),
    "saas.generic": ({"name": "ChatGPT", "scopes": ["drive.readonly"]}, "ChatGPT"),
    "saas.notion": ({"object": "user", "id": "n1", "type": "bot", "name": "Notion AI helper", "bot": {"owner": {"type": "workspace"}, "workspace_name": "Acme"}}, "Notion AI helper"),
}


@pytest.mark.parametrize("connector,bad,rejected", [
    ("lowcode.n8n", {"id": "w0", "name": "Bad", "nodes": ["not-a-node"]}, True),
    ("lowcode.workato", {"id": 0, "name": "Bad", "code": "{truncated", "config": []}, True),
    ("lowcode.workato", {"id": 0, "name": "Bad", "code": "", "config": 5}, True),
    ("lowcode.make", {"_kind": "ai-agent", "id": "ag0", "name": "Bad", "model": "gpt-4o", "tools": 5}, True),
    ("lowcode.make", {"_kind": "scenario", "id": 7, "name": "Bad", "blueprint": {"flow": 5}}, True),
    ("saas.microsoft-teams", {"id": "app-0", "displayName": "Bad", "appDefinitions": [{"bot": "not-a-dict"}]}, True),
    ("saas.microsoft-teams", {"id": "inst-0", "teamsApp": "not-a-dict", "teamsAppDefinition": {"teamsAppId": "x"}}, True),
    ("saas.notion", {"object": "user", "id": "n0", "type": "bot", "name": "Bad", "bot": "not-a-dict"}, True),
    # Scalar-typed fields are coerced to text instead of rejected; coverage stays complete.
    ("lowcode.zapier", {"id": "z0", "title": 123, "steps": []}, False),
    ("saas.generic", {"name": "Otter.ai", "scopes": ["admin", 5]}, False),
    ("saas.generic", {"name": "Otter.ai", "url": [123]}, False),
])
def test_one_malformed_record_does_not_abort_analysis(run_connector, tmp_path, connector, bad, rejected):
    good, title = _GOOD[connector]
    findings, ctx = _offline(run_connector, tmp_path, connector, [bad, good])
    assert not ctx.stats.errors
    assert any(title in f.title for f in findings)
    if rejected:
        assert ctx.stats.incomplete and ctx.stats.warnings
    else:
        assert not ctx.stats.incomplete and not ctx.stats.warnings
