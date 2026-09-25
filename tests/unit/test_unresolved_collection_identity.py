"""Incomplete exports retain evidence without manufacturing approvable identities."""
from __future__ import annotations

import json
from unittest.mock import Mock

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.cloud.aws import AwsConnector
from shadowscan.connectors.identity.entra import EntraConnector
from shadowscan.models import Finding
from shadowscan.registry import Inventory, InventoryEntry, card_stub_for

ACCOUNT = "111111111111"
OTHER = "222222222222"


def assert_unresolved(finding):
    assert finding.metadata["identity_unresolved"] is True
    assert card_stub_for(finding)["discovery"]["resources"] == []
    inventory = Inventory([InventoryEntry(agent_id="historical", resources=[finding.resource])])
    assert inventory.match(finding) is None
    assert inventory.match(Finding.from_dict(finding.to_dict())) is None


@pytest.mark.parametrize("connector,fixture", [
    ("identity.entra", "entra_orphan_permissions.json"),
    ("cloud.aws", "aws_conflicting_accounts.json"),
    ("lowcode.n8n", "n8n_missing_identity.json"),
])
def test_cli_unresolved_export_is_incomplete_but_keeps_known_neighbors(fixtures, connector, fixture):
    result = CliRunner().invoke(main, ["run", connector, "--input", str(fixtures / "assurance" / fixture), "--format", "json"])
    assert result.exit_code == 3, result.output
    report = json.loads(result.stdout)
    assert report["summary"]["complete"] is False
    findings = [Finding.from_dict(item) for item in report["findings"]]
    assert len(findings) == 2
    unresolved = [f for f in findings if f.metadata.get("identity_unresolved")]
    assert len(unresolved) == 1
    assert_unresolved(unresolved[0])
    assert "None" not in unresolved[0].resource
    if connector == "identity.entra":
        assert {"Mail.Read", "Directory.ReadWrite.All"} <= set(unresolved[0].permissions)
        assert unresolved[0].metadata["admin_consent"] is True


@pytest.mark.parametrize("reverse", [False, True])
def test_entra_orphan_resolution_is_independent_of_record_order(run_connector, fixtures, tmp_path, reverse):
    records = json.loads((fixtures / "assurance" / "entra_orphan_permissions.json").read_text())
    records.append({"_kind": "servicePrincipal", "id": "missing", "appId": "resolved", "displayName": "Resolved app"})
    source = tmp_path / "entra.json"
    source.write_text(json.dumps(records[::-1] if reverse else records))
    findings, ctx = run_connector("identity.entra", input=str(source), tenant_id="tenant")
    assert not ctx.stats.incomplete
    resolved = next(f for f in findings if f.resource == "entra:sp:missing")
    assert {"Mail.Read", "Directory.ReadWrite.All"} <= set(resolved.permissions)
    assert "identity_unresolved" not in resolved.metadata


def test_entra_live_missing_principal_retains_grant_evidence(monkeypatch, run_connector):
    class Graph:
        def paginate_odata(self, path, **kwargs):
            if path == "/oauth2PermissionGrants":
                yield {"clientId": "missing", "scope": "Mail.Read", "consentType": "AllPrincipals"}
    monkeypatch.setattr(EntraConnector, "_auth", lambda self: setattr(self, "http", Graph()))
    findings, ctx = run_connector("identity.entra", tenant_id="tenant")
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert_unresolved(findings[0])
    assert "Mail.Read" in findings[0].permissions


@pytest.mark.parametrize("reverse", [False, True])
def test_entra_conflicting_principals_preserve_permissions_without_guessing_identity(run_connector, tmp_path, reverse):
    records = [
        {"_kind": "servicePrincipal", "id": "same", "appId": "app-a", "displayName": "Claude"},
        {"_kind": "oauth2PermissionGrant", "clientId": "same", "scope": "Mail.Read"},
        {"_kind": "servicePrincipal", "id": "same", "appId": "app-b", "displayName": "Other"},
    ]
    source = tmp_path / "conflict.json"
    source.write_text(json.dumps(records[::-1] if reverse else records))
    findings, ctx = run_connector("identity.entra", input=str(source))
    assert ctx.stats.incomplete
    assert len(findings) == 1
    assert_unresolved(findings[0])
    assert findings[0].metadata["app_id"] is None
    assert "Mail.Read" in findings[0].permissions


@pytest.mark.parametrize("reverse", [False, True])
def test_aws_conflicting_envelopes_are_order_independent(run_connector, fixtures, tmp_path, reverse):
    records = json.loads((fixtures / "assurance" / "aws_conflicting_accounts.json").read_text())
    source = tmp_path / "aws.json"
    source.write_text(json.dumps(records[::-1] if reverse else records))
    findings, ctx = run_connector("cloud.aws", input=str(source))
    assert ctx.stats.incomplete and not ctx.stats.errors
    unresolved = next(f for f in findings if f.resource == "short-agent")
    assert unresolved.account is None
    assert_unresolved(unresolved)
    known = next(f for f in findings if f.resource.startswith("arn:"))
    assert known.account == OTHER
    assert "identity_unresolved" not in known.metadata


@pytest.mark.parametrize("late", [False, True])
@pytest.mark.parametrize("record", [
    {"_kind": "bedrock-agent", "agentId": "short-agent", "agentName": "Known"},
    {"_kind": "qbusiness-application", "applicationId": "known", "displayName": "Known"},
    {"_kind": "lex-bot", "botId": "known", "botName": "Known"},
    {"_kind": "bedrock-logging", "loggingConfig": None},
    {"_kind": "ssm-parameter", "Name": "/openai/key"},
    {"_kind": "cloudtrail-event", "principal": "service", "eventName": "InvokeModel", "eventTime": "2026-01-01"},
])
def test_aws_account_envelope_can_follow_resource(run_connector, tmp_path, late, record):
    envelope = {"_kind": "account", "account": ACCOUNT}
    source = tmp_path / "aws.json"
    source.write_text(json.dumps([record, envelope] if late else [envelope, record]))
    findings, ctx = run_connector("cloud.aws", input=str(source))
    assert not ctx.stats.incomplete, ctx.stats.warnings
    assert len(findings) == 1
    finding = findings[0]
    assert finding.account == ACCOUNT
    assert finding.id == finding.compute_id()
    if finding.resource.startswith("arn:"):
        assert finding.resource.split(":")[4] == ACCOUNT
    assert "identity_unresolved" not in finding.metadata


@pytest.mark.parametrize("bad_account", [None, "", "invalid", True, [], "１２３４５６７８９０１２"])
def test_aws_invalid_account_envelope_cannot_be_ignored(run_connector, tmp_path, bad_account):
    source = tmp_path / "aws.json"
    source.write_text(json.dumps([
        {"_kind": "account", "account": ACCOUNT},
        {"_kind": "bedrock-agent", "agentId": "short-agent"},
        {"_kind": "account", "account": bad_account},
    ]))
    findings, ctx = run_connector("cloud.aws", input=str(source))
    assert ctx.stats.incomplete
    assert findings[0].account is None
    assert_unresolved(findings[0])


def test_aws_live_collect_account_stays_verified(index):
    connector = AwsConnector(ConnectorContext({"account_id": ACCOUNT, "services": ["bedrock"]}, index=index))
    connector.check_requirements = Mock()
    connector._session_ = Mock()  # authenticated identity is fixed to ACCOUNT
    connector._regions = Mock(return_value=["us-east-1"])
    connector._collect_bedrock = Mock(return_value=iter([{"_kind": "bedrock-agent", "agentId": "agent"}]))
    finding, = connector.run()
    assert finding.account == ACCOUNT
    assert not connector.ctx.stats.incomplete


def test_aws_preserves_observations_before_collection_failure(index):
    connector = AwsConnector(ConnectorContext({"account_id": ACCOUNT}, index=index))
    connector.check_requirements = Mock()
    def records():
        yield {"_kind": "bedrock-agent", "agentId": "agent"}
        raise RuntimeError("provider unavailable")
    connector.collect = records
    finding, = connector.run()
    assert finding.account == ACCOUNT
    assert connector.ctx.stats.incomplete


@pytest.mark.parametrize("identifier", [None, "", " ", False, 0, -1, [], {}, 1.2])
def test_n8n_malformed_id_preserves_blueprint_as_unresolved(run_connector, tmp_path, identifier):
    source = tmp_path / "n8n.json"
    source.write_text(json.dumps({"id": identifier, "name": "Named blueprint", "nodes": [{"type": "@n8n/n8n-nodes-langchain.agent"}]}))
    findings, ctx = run_connector("lowcode.n8n", input=str(source))
    assert ctx.stats.incomplete
    assert len(findings) == 1
    assert_unresolved(findings[0])
    assert findings[0].resource.startswith("n8n:unresolved-workflow:")


@pytest.mark.parametrize("identifier", ["workflow-id", 7])
def test_n8n_valid_provider_id_does_not_require_a_display_name(run_connector, tmp_path, identifier):
    source = tmp_path / "n8n.json"
    source.write_text(json.dumps({"id": identifier, "nodes": [{"type": "@n8n/n8n-nodes-langchain.agent"}]}))
    findings, ctx = run_connector("lowcode.n8n", input=str(source))
    assert not ctx.stats.incomplete
    assert findings[0].resource == f"n8n:workflow:{identifier}"
    assert "identity_unresolved" not in findings[0].metadata


@pytest.mark.parametrize("configured", [False, True])
def test_aws_resource_arn_must_agree_with_single_account_scope(run_connector, tmp_path, configured):
    source = tmp_path / "aws.json"
    source.write_text(json.dumps([
        {"_kind": "bedrock-agent", "agentArn": f"arn:aws:bedrock:us-east-1:{OTHER}:agent/conflicting"},
        *([] if configured else [{"_kind": "account", "account": ACCOUNT}]),
    ]))
    findings, ctx = run_connector("cloud.aws", input=str(source), **({"account_id": ACCOUNT} if configured else {}))
    assert ctx.stats.incomplete
    assert findings[0].account == OTHER  # preserve observed identity, never relabel the ARN
    assert_unresolved(findings[0])


def test_aws_cloudtrail_caller_may_legitimately_belong_to_another_account(run_connector, tmp_path):
    source = tmp_path / "aws.json"
    source.write_text(json.dumps([
        {"_kind": "account", "account": ACCOUNT},
        {"_kind": "cloudtrail-event", "principal": f"arn:aws:iam::{OTHER}:user/caller", "eventName": "InvokeModel", "eventTime": "2026-01-01"},
    ]))
    findings, ctx = run_connector("cloud.aws", input=str(source), account_id=ACCOUNT)
    assert not ctx.stats.incomplete
    assert findings[0].account == OTHER
    assert "identity_unresolved" not in findings[0].metadata


@pytest.mark.parametrize("record", [
    {"_kind": "bedrock-logging", "loggingConfig": None},
    {"_kind": "qbusiness-application", "applicationId": "known"},
    {"_kind": "lex-bot", "botId": "known"},
    {"_kind": "ssm-parameter", "Name": "/openai/key"},
])
def test_aws_generated_arns_cannot_hide_conflicting_envelopes(run_connector, tmp_path, record):
    source = tmp_path / "aws.json"
    source.write_text(json.dumps([
        {"_kind": "account", "account": ACCOUNT}, record,
        {"_kind": "account", "account": OTHER},
    ]))
    findings, ctx = run_connector("cloud.aws", input=str(source), account_id=ACCOUNT)
    assert ctx.stats.incomplete
    assert findings[0].account is None
    assert findings[0].resource.split(":")[4] == ""
    assert_unresolved(findings[0])
    assert all(e.location != f"arn:aws:ssm:None:{ACCOUNT}:parameter/openai/key" for e in findings[0].evidence)


def test_aws_offline_connector_does_not_reuse_previous_export_identity(index, tmp_path):
    source = tmp_path / "aws.json"
    connector = AwsConnector(ConnectorContext({"input": str(source)}, index=index))
    for account in (ACCOUNT, OTHER):
        source.write_text(json.dumps([
            {"_kind": "account", "account": account},
            {"_kind": "bedrock-agent", "agentId": "agent"},
        ]))
        finding, = connector.run()
        assert finding.account == account
        assert not connector.ctx.stats.incomplete


@pytest.mark.parametrize("reverse", [False, True])
def test_entra_conflicting_snapshots_keep_ai_evidence_without_grants(run_connector, tmp_path, reverse):
    records = [
        {"_kind": "servicePrincipal", "id": "same", "appId": "app-a", "displayName": "Claude"},
        {"_kind": "servicePrincipal", "id": "same", "appId": "app-b", "displayName": "Other"},
        {"_kind": "servicePrincipal", "id": "neighbor", "appId": "known-app", "displayName": "ChatGPT"},
    ]
    source = tmp_path / "conflict.json"
    source.write_text(json.dumps(records[::-1] if reverse else records))
    findings, ctx = run_connector("identity.entra", input=str(source), tenant_id="tenant")
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert len(findings) == 2
    observed = next(f for f in findings if f.resource == "entra:unresolved-principal:same")
    assert_unresolved(observed)
    assert observed.metadata.get("app_id") is None
    assert observed.metadata["conflicting_principal_snapshots"] == 2
    assert observed.frameworks or observed.model_providers
    assert any("Claude" in evidence.description for evidence in observed.evidence)
    assert not observed.permissions
    assert any(f.resource == "entra:sp:neighbor" and not f.metadata.get("identity_unresolved") for f in findings)


def test_entra_conflicting_snapshot_limit_preserves_evidence_and_neighbors(run_connector, tmp_path):
    from shadowscan.connectors.identity.entra import MAX_CONFLICTING_SNAPSHOTS

    source = tmp_path / "many-conflicts.json"
    source.write_text(json.dumps([
        *[{"_kind": "servicePrincipal", "id": "same", "appId": f"app-{number}", "displayName": "Claude"}
          for number in range(MAX_CONFLICTING_SNAPSHOTS + 10)],
        {"_kind": "servicePrincipal", "id": "neighbor", "appId": "known", "displayName": "Claude"},
    ]))
    findings, ctx = run_connector("identity.entra", input=str(source))
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert len(findings) == 2
    unresolved = next(f for f in findings if f.metadata.get("identity_unresolved"))
    assert unresolved.metadata["conflicting_principal_snapshots"] == MAX_CONFLICTING_SNAPSHOTS
    assert unresolved.metadata["conflicting_principal_evidence_truncated"] is True
    assert sum("snapshot limit reached" in warning for warning in ctx.stats.warnings) == 1
    assert_unresolved(unresolved)


def test_entra_conflicting_evidence_limit_keeps_a_publishable_finding(monkeypatch, run_connector, tmp_path):
    monkeypatch.setattr("shadowscan.connectors.identity.entra.MAX_CONFLICTING_EVIDENCE", 1)
    source = tmp_path / "evidence-limit.json"
    source.write_text(json.dumps([
        {"_kind": "servicePrincipal", "id": "same", "appId": "a", "displayName": "Claude"},
        {"_kind": "servicePrincipal", "id": "same", "appId": "b", "displayName": "ChatGPT"},
    ]))
    findings, ctx = run_connector("identity.entra", input=str(source))
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert len(findings) == 1
    assert len(findings[0].evidence) == 1
    assert findings[0].metadata["conflicting_principal_evidence_truncated"] is True
    assert sum("evidence limit reached" in warning for warning in ctx.stats.warnings) == 1
    assert_unresolved(findings[0])


def test_n8n_yaml_blueprint_without_id_keeps_its_evidence(run_connector, tmp_path):
    # YAML exports carry values JSON cannot encode, such as timestamps.
    source = tmp_path / "workflow.yaml"
    source.write_text("name: Blueprint\nnodes:\n  - name: Agent\n    type: '@n8n/n8n-nodes-langchain.agent'\n"
                      "    parameters:\n      notBefore: 2024-01-01T00:00:00Z\n")
    findings, ctx = run_connector("lowcode.n8n", input=str(source))
    assert ctx.stats.incomplete and not ctx.stats.errors
    assert len(findings) == 1
    assert_unresolved(findings[0])


def test_entra_unresolved_principal_invents_no_attributes(run_connector, fixtures):
    findings, _ = run_connector("identity.entra", input=str(fixtures / "assurance" / "entra_orphan_permissions.json"))
    unresolved = next(f for f in findings if f.metadata.get("identity_unresolved"))
    for key in ("app_id", "service_principal_type", "publisher", "first_party", "owner_tenant", "account_enabled"):
        assert unresolved.metadata[key] is None, key
    described = " ".join(evidence.description for evidence in unresolved.evidence)
    assert "third-party" not in described and "first-party" not in described
    assert "unknown" in described
