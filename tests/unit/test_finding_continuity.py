from __future__ import annotations

import copy
import json

import pytest
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.comparison import compare_reports
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine, merge
from shadowscan.models import FINDING_IDENTITY_SCHEMA, Finding, Kind, ScanResult, ScanStats, Surface


def _finding(**changes):
    values = dict(
        surface=Surface.IDENTITY, connector="identity.entra", provider="entra", account="tenant",
        kind=Kind.OAUTH_GRANT, title="Application", resource="entra:sp:1", resource_type="service-principal/Application",
    )
    return Finding(**{**values, **changes})


def _report(*findings):
    return ScanResult(
        findings=list(findings), stats=[ScanStats(connector="identity.entra", started_at="2026-01-01")],
        collection_scope={"schema": "shadowscan.collection-scope/v1", "comparable": True, "fingerprint": "a" * 64},
    ).to_dict()


def test_classification_and_resource_subtype_are_not_identity():
    before = _finding()
    after = _finding(kind=Kind.SERVICE_IDENTITY, resource_type="service-principal/ManagedIdentity")
    assert before.id == after.id
    comparison = compare_reports(_report(before), _report(after))
    assert comparison["comparable"] and not comparison["new"] and not comparison["resolved"]
    assert comparison["changed"][0]["changed_fields"] == ["kind", "resource_type"]


def test_distinct_observation_types_of_same_resource_remain_separate():
    base = dict(surface=Surface.CODE, connector="code.filesystem", resource="repo/agent.yaml", provider="filesystem")
    findings = [
        _finding(**base, kind=kind, resource_type=resource_type)
        for kind, resource_type in ((Kind.AGENT, "agent-manifest"), (Kind.MCP_SERVER, "mcp-config"), (Kind.SECRET, "file"))
    ]
    assert len(merge(findings)) == len({finding.id for finding in findings}) == 3
    a = _finding(identity_discriminator="grant:a")
    b = _finding(identity_discriminator="grant:b")
    assert len(merge([a, b])) == 2


def test_identity_component_boundaries_and_regions_cannot_collide():
    assert _finding(provider="a|b", account="c").id != _finding(provider="a", account="b|c").id
    assert _finding(region="us-east-1").id != _finding(region="us-west-2").id


def test_same_entity_classifications_merge_without_completion_order_dependence():
    before, after = _finding(), _finding(kind=Kind.SERVICE_IDENTITY, resource_type="service-principal/ManagedIdentity")
    reports = []
    for observations in ([before, after], [after, before]):
        result = merge(copy.deepcopy(observations))
        assert len(result) == 1 and result[0].kind == Kind.SERVICE_IDENTITY
        assert result[0].resource_type == "service-principal/ManagedIdentity"
        assert result[0].metadata["observed_kinds"] == ["oauth-grant", "service-identity"]
        assert result[0].metadata["observed_resource_types"] == [
            "service-principal/Application", "service-principal/ManagedIdentity",
        ]
        reports.append(_report(*result))
    comparison = compare_reports(*reports)
    assert comparison["comparable"] and not comparison["changed"] and not comparison["new"] and not comparison["resolved"]


def test_resource_subtype_merge_is_associative_for_same_kind():
    observations = [_finding(kind=Kind.SERVICE_IDENTITY, resource_type=f"service-principal/{subtype}")
                    for subtype in ("Application", "ManagedIdentity", "Legacy")]
    forward = merge(copy.deepcopy(observations))
    grouped = merge([*merge(copy.deepcopy(observations[1:])), copy.deepcopy(observations[0])])
    assert forward[0].resource_type == grouped[0].resource_type == "service-principal/ManagedIdentity"
    assert forward[0].metadata["observed_resource_types"] == grouped[0].metadata["observed_resource_types"]
    assert not compare_reports(_report(*forward), _report(*grouped))["changed"]


@pytest.mark.parametrize("field,value", [
    ("permissions", ["Mail.ReadWrite"]), ("capabilities", ["code-exec"]),
    ("shadow", False), ("registry_match", "approved-agent"), ("owner", "platform-team"),
])
def test_substantive_security_changes_are_reported(field, value):
    before = _finding()
    after = _finding(**{field: value})
    assert field in compare_reports(_report(before), _report(after))["changed"][0]["changed_fields"]


def test_numeric_risk_changes_within_same_band_are_reported():
    before, after = _finding(), _finding()
    before.risk.score, after.risk.score = 27, 33
    changes = compare_reports(_report(before), _report(after))["changed"]
    assert changes[0]["changed_fields"] == ["risk.score"]


def test_volatile_observations_and_set_order_do_not_cause_changes():
    before = _finding(permissions=["Mail.Read", "Files.Read"], tags=["b", "a"])
    after = _finding(permissions=["Files.Read", "Mail.Read", "Mail.Read"], tags=["a", "b"])
    after.first_seen, after.last_seen = "2026-01-01", "2026-01-02"
    after.title = "Renamed app: 10 calls"
    after.metadata = {"requests": 10, "duration": 0.5}
    assert not compare_reports(_report(before), _report(after))["changed"]


@pytest.mark.parametrize("mutation", ["missing_report_schema", "legacy_finding", "future_schema"])
def test_identity_schema_migration_never_resolves_old_findings(mutation):
    before, after = _report(_finding()), _report()
    if mutation == "missing_report_schema":
        before.pop("finding_identity_schema")
    elif mutation == "legacy_finding":
        before["findings"][0].pop("identity_schema")
    else:
        before["finding_identity_schema"] = "future/v3"
    result = compare_reports(before, after)
    assert not result["comparable"] and not result["resolved"] and len(result["unknown"]) == 1
    assert any("identity schema" in reason for reason in result["reasons"])


def test_legacy_deserialization_preserves_id_and_schema():
    data = _finding().to_dict()
    data.pop("identity_schema")
    data.pop("identity_discriminator")
    legacy = Finding.from_dict(data)
    assert legacy.id == data["id"]
    assert legacy.identity_schema != FINDING_IDENTITY_SCHEMA
    assert Finding.from_dict(_finding().to_dict()).to_dict() == _finding().to_dict()


def test_entra_permission_transition_retains_identity_in_full_pipeline(tmp_path, index):
    source = tmp_path / "entra.json"
    principal = {
        "_kind": "servicePrincipal", "id": "sp-1", "appId": "app-otter",
        "displayName": "Otter.ai", "servicePrincipalType": "Application",
    }
    grant = {"_kind": "oauth2PermissionGrant", "clientId": "sp-1", "consentType": "Principal",
             "principalId": "user-1", "resourceId": "graph", "scope": "Mail.Read"}
    source.write_text(json.dumps([principal, grant]))
    config = ScanConfig(connectors=[ConnectorSpec("identity.entra", {"input": str(source), "tenant_id": "t"})])
    before = Engine(config, index).run()
    source.write_text(json.dumps([principal, {"_kind": "appRoleAssignment", "principalId": "sp-1",
                                            "appRoleId": "Mail.ReadWrite", "resourceId": "graph"}]))
    after = Engine(config, index).run()
    assert before.complete and after.complete
    comparison = compare_reports(before.to_dict(), after.to_dict())
    assert comparison["comparable"] and not comparison["new"] and not comparison["resolved"]
    assert {"kind", "permissions"} <= set(comparison["changed"][0]["changed_fields"])


def test_zapier_title_heuristic_does_not_change_source_identity(run_connector, tmp_path):
    source = tmp_path / "zaps.json"
    source.write_text(json.dumps([{"id": "1", "title": "AI workflow", "steps": ["OpenAI"]}]))
    before, _ = run_connector("lowcode.zapier", input=str(source))
    source.write_text(json.dumps([{"id": "1", "title": "AI agent", "steps": ["OpenAI"]}]))
    after, _ = run_connector("lowcode.zapier", input=str(source))
    assert before[0].kind == Kind.WORKFLOW and after[0].kind == Kind.AGENT
    assert before[0].id == after[0].id and before[0].resource == after[0].resource == "zapier:zap:1"


def test_cli_diff_renders_permission_changes_without_claiming_risk_transition(tmp_path):
    paths = [tmp_path / name for name in ("before.json", "after.json")]
    for path, finding in zip(paths, [_finding(), _finding(permissions=["Mail.Read"])], strict=True):
        path.write_text(json.dumps(_report(finding)))
    result = CliRunner().invoke(main, ["diff", *map(str, paths)])
    assert result.exit_code == 0, result.output
    assert "1 changed" in result.output and "permissions" in result.output
    assert "changed risk" not in result.output
