"""Microsoft Agent 365 packages, Entra Agent ID and delegated Graph auth in ``identity.entra``.

The package, agent identity and agent registry records here are synthetic, modeled on the
Microsoft Graph reference pages; nothing was validated against a live tenant.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import jwt as pyjwt
import pytest
import responses

from shadowscan.cli import _exit_code
from shadowscan.comparison import build_collection_scope
from shadowscan.config import ConfigValidationError, ScanConfig
from shadowscan.connectors.base import ConnectorContext, ConnectorError
from shadowscan.connectors.identity.entra import (
    AGENT_IDENTITIES,
    COPILOT_PACKAGES,
    COVERAGE_KIND,
    FIRST_PARTY_OWNER,
    GRAPH,
    GRAPH_BETA,
    EntraConnector,
    _package_status,
)
from shadowscan.engine import Engine
from shadowscan.models import Kind, ScanResult, ScanStats
from shadowscan.registries import registry_record
from shadowscan.reporters.html import render_html
from shadowscan.reporters.sarif import render_sarif
from shadowscan.utils.http import HttpError

TENANT = "tenant-0365"
LISTING = GRAPH + COPILOT_PACKAGES
_TEST_HMAC_KEY = "synthetic-test-only-hmac-key-0123456789abcdef"


def _context(index, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="test", started_at="2026-01-01")
    return ctx


def _assert_incomplete(ctx, findings):
    result = ScanResult(findings=findings, stats=[ctx.stats])
    assert not result.complete
    assert _exit_code(result, None) == 3
    invocation = json.loads(render_sarif(result))["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is False


def _by_resource(findings):
    return {f.resource: f for f in findings}


def _record(finding) -> dict[str, Any]:
    return finding.metadata["registry_record"]


def _offline(tmp_path, run_connector, records, **config):
    source = tmp_path / "entra.json"
    source.write_text(json.dumps(records), encoding="utf-8")
    return run_connector("identity.entra", input=str(source), **config)


def _package(package_id="P_1", **fields):
    return {
        "_kind": "copilotPackage",
        "id": package_id,
        "displayName": f"Package {package_id}",
        "type": "custom",
        "isBlocked": False,
        "elementTypes": ["declarativeAgent"],
        "availableTo": "allowedForAll",
        "requestStatus": "approved",
        **fields,
    }


COMPLETE_MARKER = {
    "_kind": COVERAGE_KIND,
    "packages": "complete",
    "agentIdentities": "complete",
    "applications": "complete",
    "listingScope": "registry",
}


# ------------------------------------------------------------------ offline analysis
def test_agent_registry_fixture(run_connector, fixtures):
    findings, ctx = run_connector(
        "identity.entra", input=str(fixtures / "identity" / "entra_agent_registry.json"), tenant_id=TENANT
    )
    assert not ctx.stats.incomplete and not ctx.stats.warnings and not ctx.stats.errors
    by = _by_resource(findings)
    records = {
        resource: (record["status"], record["approval_mode"])
        for resource, f in by.items()
        if (record := f.metadata.get("registry_record"))
    }
    assert records == {
        "entra:copilot-package:P_hr-agent-0001": ("approved", "manual"),
        "entra:copilot-package:P_sales-agent-0002": ("blocked", "unknown"),
        "entra:copilot-package:P_pending-agent-0003": ("pending", "unknown"),
        "entra:copilot-package:P_draft-agent-0004": ("draft", "unknown"),
        "entra:copilot-package:P_rejected-agent-0005": ("rejected", "unknown"),
        "entra:copilot-package:P_vendor-addin-0006": ("approved", "unknown"),
        "entra:copilot-package:P_unknown-agent-0007": ("unknown", "unknown"),
        "entra:agent-registry-instance:instance-ca-0001": ("deprecated", "unknown"),
        "entra:agent-registry-card:card-orphan-0002": ("deprecated", "unknown"),
    }
    hr = by["entra:copilot-package:P_hr-agent-0001"]
    assert hr.kind == Kind.AGENT and hr.resource_type == "copilot-package" and hr.account == TENANT
    record = registry_record(hr)
    assert record is not None
    assert (record.registry, record.registry_id, record.descriptor_type) == (
        "microsoft-agent-365",
        TENANT,
        "package",
    )
    assert record.listing_complete and record.listing_scope == "registry" and record.publisher == "Contoso"
    assert record.updated_at == "2026-09-01T10:00:00Z"
    assert [(b.resource, b.provider, b.account, b.coverage) for b in record.bindings] == [
        ("entra:sp:sp-agent-hr", "entra", TENANT, "in-scope"),
        ("entra:app:app-hr-agent", "entra", TENANT, "in-scope"),
    ]
    assert hr.metadata["app_id"] == "app-hr-agent"  # correlation key for Azure Bot msa_app_id
    assert hr.metadata["allowed_principals"] == 2 and hr.metadata["acquired_principals"] == 0
    assert hr.metadata["governance_class"] == "PromptAgent" and hr.metadata["package_detail"] == "observed"
    evidence = next(e for e in hr.evidence if e.signal == "registry:microsoft-agent-365")
    assert evidence.weight == 0.5 and evidence.attributes["confidence_group"] == "registry-record"
    assert "registry-record" in hr.tags and "registry-blocked" not in hr.tags
    # Member ids are counted, never reported.
    assert "group-hr-staff" not in json.dumps([f.to_dict() for f in findings])
    blocked = by["entra:copilot-package:P_sales-agent-0002"]
    assert {"registry-record", "registry-blocked"} <= set(blocked.tags)
    vendor = by["entra:copilot-package:P_vendor-addin-0006"]
    assert vendor.kind == Kind.AI_APP
    # A vendor package's app is registered in the vendor's tenant: it never binds one of this tenant.
    assert _record(vendor)["bindings"] == []
    unknown = by["entra:copilot-package:P_unknown-agent-0007"]
    assert unknown.metadata["request_status"] == "unknownFutureValue"
    # Agent identities: one enriches its service principal, one stands alone.
    enriched = by["entra:sp:sp-agent-hr"]
    assert (
        enriched.resource_type == "service-principal/ServiceIdentity"
        and enriched.kind == Kind.SERVICE_IDENTITY
    )
    assert "entra-agent-identity" in enriched.tags and enriched.metadata["agent_identity"] is True
    assert enriched.metadata["agent_identity_blueprint_id"] == "bp-app-hr"
    assert enriched.metadata["created_by_app_id"] == "app-agent-builder"
    assert enriched.metadata["registry_bound"] is True
    standalone = by["entra:sp:ai-sales"]
    assert standalone.resource_type == "service-principal/AgentIdentity"
    assert standalone.kind == Kind.SERVICE_IDENTITY and "Mail.Read" in standalone.permissions
    # App registrations without AI signals of their own are kept because a package names them.
    assert by["entra:app:app-hr-agent"].metadata["registry_bound"] is True
    instance = by["entra:agent-registry-instance:instance-ca-0001"]
    assert _record(instance)["registry"] == "entra-agent-registry"
    assert _record(instance)["listing_complete"] is False
    assert instance.metadata["agent_card"]["skills"] == ["Review policy"]
    assert instance.metadata["agent_card"]["security_schemes"] == ["entra"]
    assert instance.metadata["owners"] == 2 and "owner-1" not in json.dumps(instance.to_dict())
    # The embedded card is attached to its instance; only the orphan card stands alone.
    assert "entra:agent-registry-card:card-ca-0001" not in by
    assert (
        by["entra:agent-registry-card:card-orphan-0002"].metadata["agent_card"]["name"]
        == "Ticket Triage Helper"
    )


@pytest.mark.parametrize(
    "fields,status",
    [
        ({"isBlocked": True, "requestStatus": "pending"}, "blocked"),
        ({"requestStatus": "pending"}, "pending"),
        ({"requestStatus": "Rejected"}, "rejected"),
        ({"availableTo": "none"}, "draft"),
        ({"availableTo": "allowedForNone"}, "draft"),
        ({"availableTo": "all", "requestStatus": None}, "approved"),
        ({"availableTo": "AllowedForSome"}, "approved"),
        ({"availableTo": "some"}, "approved"),
        ({"isBlocked": None}, "unknown"),
        ({"requestStatus": "unknownFutureValue"}, "unknown"),
        ({"availableTo": "unknownFutureValue"}, "unknown"),
        ({"availableTo": None}, "unknown"),
    ],
)
def test_package_status_mapping(fields, status):
    package = {key: value for key, value in _package(**fields).items() if value is not None}
    assert _package_status(package) == status


@pytest.mark.parametrize(
    "fields,kind,approval_mode",
    [
        ({"elementTypes": ["Bots"]}, Kind.AGENT, "manual"),
        ({"elementTypes": ["CustomEngineAgent"], "type": "shared"}, Kind.AGENT, "manual"),
        ({"elementTypes": ["officeAddIn"], "governanceMetadata": "HostedAgent"}, Kind.AGENT, "manual"),
        ({"elementTypes": ["officeAddIn"], "governanceMetadata": "AIApp"}, Kind.AI_APP, "manual"),
        ({"type": "microsoft"}, Kind.AGENT, "unknown"),
        ({"type": "external"}, Kind.AGENT, "unknown"),
        ({"type": "unknownFutureValue"}, Kind.AGENT, "unknown"),
        ({"requestStatus": None}, Kind.AGENT, "unknown"),
    ],
)
def test_package_kind_and_approval_mode(tmp_path, run_connector, fields, kind, approval_mode):
    package = {key: value for key, value in _package(**fields).items() if value is not None}
    findings, ctx = _offline(tmp_path, run_connector, [package], tenant_id=TENANT)
    assert not ctx.stats.incomplete
    [finding] = findings
    assert finding.kind == kind and _record(finding)["approval_mode"] == approval_mode


def test_agent_identity_identity_is_stable_when_the_service_principal_is_listed(tmp_path, run_connector):
    identity = {
        "@odata.type": "#microsoft.graph.agentIdentity",
        "id": "ai-1",
        "displayName": "Helper",
        "agentIdentityBlueprintId": "bp-1",
        "servicePrincipalType": "ServiceIdentity",
    }
    principal = {
        "_kind": "servicePrincipal",
        "id": "ai-1",
        "appId": "app-1",
        "displayName": "Helper",
        "servicePrincipalType": "ServiceIdentity",
    }
    alone, alone_ctx = _offline(tmp_path, run_connector, [identity], tenant_id=TENANT)
    both, both_ctx = _offline(tmp_path, run_connector, [principal, identity], tenant_id=TENANT)
    plain, _ = _offline(tmp_path, run_connector, [principal], tenant_id=TENANT)
    # The cast is read as an agent identity, not a conflicting second service principal.
    assert not alone_ctx.stats.incomplete and not both_ctx.stats.incomplete
    assert [f.id for f in alone] == [f.id for f in both]
    assert alone[0].resource_type == "service-principal/AgentIdentity"
    assert both[0].metadata["app_id"] == "app-1" and both[0].metadata["agent_identity"] is True
    # Without the agent identity the principal shows nothing AI-related and is dropped.
    assert plain == []


def test_agent_identity_grants_are_resolved_by_the_agent_identity(tmp_path, run_connector):
    records = [
        {"id": "ai-1", "displayName": "Helper", "agentIdentityBlueprintId": "bp-1"},
        {
            "_kind": "oauth2PermissionGrant",
            "clientId": "ai-1",
            "consentType": "AllPrincipals",
            "scope": "Mail.Read",
        },
    ]
    findings, ctx = _offline(tmp_path, run_connector, records, tenant_id=TENANT)
    assert not ctx.stats.incomplete
    assert [f.resource for f in findings] == ["entra:sp:ai-1"]
    assert findings[0].metadata["admin_consent"] is True


def test_conflicting_agent_identity_records_are_unresolved(tmp_path, run_connector):
    identity = {
        "_kind": "agentIdentity",
        "id": "ai-1",
        "displayName": "Helper",
        "agentIdentityBlueprintId": "a",
    }
    findings, ctx = _offline(
        tmp_path, run_connector, [identity, {**identity, "agentIdentityBlueprintId": "b"}], tenant_id=TENANT
    )
    assert ctx.stats.incomplete
    assert "conflicting agent identity records" in " ".join(ctx.stats.warnings)
    [finding] = findings
    assert finding.resource == "entra:unresolved-principal:ai-1"
    assert finding.metadata["identity_unresolved"] is True and finding.metadata["agent_identity"] is True
    assert finding.metadata["conflicting_agent_identity_snapshots"] == 2
    assert "entra-agent-identity" in finding.tags


def test_conflicting_service_principal_folds_its_agent_identity(tmp_path, run_connector):
    principal = {"_kind": "servicePrincipal", "id": "ai-1", "displayName": "Helper"}
    identity = {
        "_kind": "agentIdentity",
        "id": "ai-1",
        "displayName": "Helper",
        "agentIdentityBlueprintId": "a",
    }
    findings, ctx = _offline(
        tmp_path,
        run_connector,
        [principal, {**principal, "displayName": "Other"}, identity],
        tenant_id=TENANT,
    )
    assert ctx.stats.incomplete
    [finding] = findings
    assert finding.metadata["identity_unresolved"] is True and finding.metadata["agent_identity"] is True


def test_conflicting_package_records_are_unresolved_and_close_the_listing(tmp_path, run_connector):
    findings, ctx = _offline(
        tmp_path,
        run_connector,
        [COMPLETE_MARKER, _package(), _package(isBlocked=True), _package("P_2")],
        tenant_id=TENANT,
    )
    assert ctx.stats.incomplete
    assert "conflicting package records" in " ".join(ctx.stats.warnings)
    by = _by_resource(findings)
    conflicted = by["entra:copilot-package:P_1"]
    assert conflicted.metadata["identity_unresolved"] is True
    assert conflicted.metadata["conflicting_package_snapshots"] == 2
    assert _record(conflicted)["status"] == "unknown" and _record(conflicted)["bindings"] == []
    assert "unresolved-identity" in conflicted.tags
    # A listing with inconsistent records is not complete.
    assert _record(by["entra:copilot-package:P_2"])["listing_complete"] is False


def test_records_without_a_coverage_marker_have_unknown_coverage(tmp_path, run_connector):
    package = _package(appId="app-1", agentIdentityId="ai-1")
    identity = {
        "_kind": "agentIdentity",
        "id": "ai-1",
        "displayName": "Helper",
        "agentIdentityBlueprintId": "bp",
    }
    findings, ctx = _offline(tmp_path, run_connector, [package, identity], tenant_id=TENANT)
    assert not ctx.stats.incomplete
    record = _record(_by_resource(findings)["entra:copilot-package:P_1"])
    assert record["listing_complete"] is False
    assert [b["coverage"] for b in record["bindings"]] == ["unknown", "unknown"]


def test_caller_scoped_listing_is_never_complete(tmp_path, run_connector):
    marker = {**COMPLETE_MARKER, "listingScope": "caller"}
    identity = {
        "_kind": "agentIdentity",
        "id": "ai-1",
        "displayName": "Helper",
        "agentIdentityBlueprintId": "bp",
    }
    package = _package(appId="app-1", agentIdentityId="ai-1")
    findings, ctx = _offline(tmp_path, run_connector, [marker, package, identity], tenant_id=TENANT)
    assert not ctx.stats.incomplete
    finding = _by_resource(findings)["entra:copilot-package:P_1"]
    record = registry_record(finding)
    assert record is not None and record.listing_scope == "caller" and not record.listing_complete
    # The reported metadata, not only the parsed record, says so; and what the signed-in user
    # could not see is not known to be absent, so no binding is in scope.
    raw = _record(finding)
    assert raw["listing_complete"] is False
    assert [b["coverage"] for b in raw["bindings"]] == ["unknown", "unknown"]


@pytest.mark.parametrize(
    "scope,status", [("registry", "registered-not-observed"), ("caller", "not-comparable")]
)
def test_caller_scoped_bindings_never_report_an_object_missing(index, tmp_path, scope, status):
    source = tmp_path / "entra.json"
    marker = {**COMPLETE_MARKER, "listingScope": scope}
    source.write_text(json.dumps([marker, _package(appId="app-unseen")]), encoding="utf-8")
    result = _scan(index, source, trusted=False)
    package = _by_resource(result.findings)["entra:copilot-package:P_1"]
    assert package.metadata["registry_reconciliation"]["status"] == status


def test_records_without_a_tenant_name_no_registry(monkeypatch, tmp_path, run_connector):
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    findings, _ = _offline(tmp_path, run_connector, [COMPLETE_MARKER, _package(appId="app-1")])
    record = registry_record(findings[0])
    assert record is not None and record.registry_id == "" and not record.identified
    assert findings[0].account is None
    assert _record(findings[0])["bindings"][0]["account"] is None


@pytest.mark.parametrize(
    "marker,warning",
    [
        ({"packages": "incomplete"}, "exported Agent 365 package listing was incomplete"),
        ({"agentIdentities": "incomplete"}, "exported agent identity collection was incomplete"),
        ({"applications": "incomplete"}, "exported app registration collection was incomplete"),
    ],
)
def test_replayed_incomplete_collections_stay_incomplete(tmp_path, run_connector, marker, warning):
    findings, ctx = _offline(
        tmp_path,
        run_connector,
        [{**COMPLETE_MARKER, **marker}, _package(agentIdentityId="ai-1")],
        tenant_id=TENANT,
    )
    assert ctx.stats.incomplete and warning in " ".join(ctx.stats.warnings)
    assert len(findings) == 1


@pytest.mark.parametrize("detail", ["unavailable", "limit"])
def test_replayed_missing_package_details_stay_incomplete(tmp_path, run_connector, detail):
    findings, ctx = _offline(
        tmp_path, run_connector, [COMPLETE_MARKER, _package(_detail=detail)], tenant_id=TENANT
    )
    assert ctx.stats.incomplete and "package details were unavailable or capped" in " ".join(
        ctx.stats.warnings
    )
    assert len(findings) == 1


def test_disagreeing_coverage_markers_count_as_incomplete(tmp_path, run_connector):
    findings, ctx = _offline(
        tmp_path,
        run_connector,
        [COMPLETE_MARKER, {**COMPLETE_MARKER, "packages": "not-collected"}, _package()],
        tenant_id=TENANT,
    )
    assert ctx.stats.incomplete
    assert _record(findings[0])["listing_complete"] is False


def test_coverage_marker_alone_is_a_clean_export(tmp_path, run_connector):
    findings, ctx = _offline(tmp_path, run_connector, [COMPLETE_MARKER], tenant_id=TENANT)
    assert findings == [] and not ctx.stats.incomplete and not ctx.stats.warnings


@pytest.mark.parametrize(
    "record",
    [
        _package(isBlocked="no"),
        _package(elementTypes=[1]),
        _package(availableTo=["all"]),
        _package(_accessCounts={"members": 1}),
        _package(_accessCounts={"allowedUsersAndGroups": -1}),
        _package(allowedUsersAndGroups=["user-1"]),
        _package(activeUsers=True),
        _package(_detail="partial"),
        _package(appId="a" * 5000),
        {"_kind": "copilotPackage", "displayName": "No id"},
        {"_kind": "agentIdentity", "id": "ai-1", "agentIdentityBlueprintId": 5},
        {"_kind": "agentIdentity", "id": "ai-1", "managerApplications": [1]},
        {"_kind": "agentInstance", "id": "i-1", "ownerIds": [1]},
        {"_kind": "agentInstance", "id": "i-1", "additionalInterfaces": [{"url": 1}]},
        {"_kind": "agentInstance", "id": "i-1", "signatures": ["sig"]},
        {"_kind": "agentInstance", "id": "i-1", "agentCardManifest": {"skills": "triage"}},
        {"_kind": "agentCardManifest", "id": "c-1", "skills": [{"name": 1}]},
        {"_kind": "agentCardManifest", "id": "c-1", "provider": {"organization": []}},
        {"_kind": "agentCardManifest", "id": "c-1", "defaultInputModes": [1]},
        {**COMPLETE_MARKER, "packages": "maybe"},
        {**COMPLETE_MARKER, "listingScope": "tenant"},
    ],
)
def test_malformed_agent_records_keep_neighbors_and_close_the_listing(tmp_path, run_connector, record):
    findings, ctx = _offline(
        tmp_path, run_connector, [COMPLETE_MARKER, record, _package("P_ok")], tenant_id=TENANT
    )
    assert ctx.stats.incomplete and "unsupported or malformed Graph record" in " ".join(ctx.stats.warnings)
    assert [f.resource for f in findings] == ["entra:copilot-package:P_ok"]
    assert _record(findings[0])["listing_complete"] is False


def test_untyped_agent_records_are_inferred_from_their_shape(tmp_path, run_connector):
    records = [
        {"id": "P_1", "displayName": "Package", "supportedHosts": ["Copilot"]},
        {
            "id": "i-1",
            "displayName": "Instance",
            "preferredTransport": "JSONRPC",
            "agentIdentityBlueprintId": "bp",
        },
        {"id": "c-1", "displayName": "Card", "protocolVersion": "0.3.0", "skills": []},
        {"id": "ai-1", "displayName": "Identity", "agentIdentityBlueprintId": "bp"},
    ]
    findings, ctx = _offline(tmp_path, run_connector, records, tenant_id=TENANT)
    assert not ctx.stats.incomplete
    assert {f.resource for f in findings} == {
        "entra:copilot-package:P_1",
        "entra:agent-registry-instance:i-1",
        "entra:agent-registry-card:c-1",
        "entra:sp:ai-1",
    }


def test_conflicting_deprecated_records_are_unresolved(tmp_path, run_connector):
    instance = {"_kind": "agentInstance", "id": "i-1", "displayName": "A", "agentIdentityId": "ai-1"}
    card = {"_kind": "agentCardManifest", "id": "c-1", "displayName": "A"}
    findings, ctx = _offline(
        tmp_path,
        run_connector,
        [instance, {**instance, "displayName": "B"}, card, {**card, "displayName": "B"}],
        tenant_id=TENANT,
    )
    assert ctx.stats.incomplete
    assert {f.resource: f.metadata["identity_unresolved"] for f in findings} == {
        "entra:agent-registry-instance:i-1": True,
        "entra:agent-registry-card:c-1": True,
    }
    assert all(_record(f)["bindings"] == [] and _record(f)["status"] == "deprecated" for f in findings)


# ------------------------------------------------------------------ engine: trust and reconciliation
def _scan(index, source, *, trusted=True, allow_auto_approved=False, **config):
    entry = {"registry": "microsoft-agent-365", "id": TENANT, "allow_auto_approved": allow_auto_approved}
    options = {"trusted_registries": [entry]} if trusted else {}
    cfg = ScanConfig.from_dict(
        {
            "connectors": [{"name": "identity.entra", "input": str(source), "tenant_id": TENANT, **config}],
            "options": options,
        }
    )
    return Engine(cfg, index).run()


def test_trusted_agent_365_registry_approves_only_approved_manual_package_bindings(index, fixtures):
    result = _scan(index, fixtures / "identity" / "entra_agent_registry.json")
    assert result.complete and result.inventory_present
    by = _by_resource(result.findings)
    approved = {f.resource: f.registry_match for f in result.findings if f.shadow is False}
    hr = "microsoft-agent-365:P_hr-agent-0001"
    assert approved == {
        # The approved, manually approved organization package and the objects it binds.
        "entra:copilot-package:P_hr-agent-0001": hr,
        "entra:sp:sp-agent-hr": hr,
        "entra:app:app-hr-agent": hr,
    }
    # An approved vendor package has approval_mode unknown: no person in this tenant is known
    # to have approved it, so it stays shadow unless the entry sets allow_auto_approved.
    assert by["entra:copilot-package:P_vendor-addin-0006"].shadow is True
    # Bindings of blocked packages never approve.
    assert by["entra:sp:ai-sales"].shadow is True and by["entra:app:app-sales-agent"].shadow is True
    # The deprecated registry never approves, even for an object it binds.
    assert by["entra:agent-registry-instance:instance-ca-0001"].shadow is True
    reconciliation = {
        resource: f.metadata["registry_reconciliation"]["status"]
        for resource, f in by.items()
        if "registry_reconciliation" in f.metadata
    }
    assert reconciliation["entra:copilot-package:P_hr-agent-0001"] == "registered-and-observed"
    assert reconciliation["entra:sp:sp-agent-hr"] == "registered-and-observed"
    # In scope and complete, yet absent: the app registration was not observed.
    assert reconciliation["entra:copilot-package:P_pending-agent-0003"] == "registered-not-observed"
    assert reconciliation["entra:copilot-package:P_vendor-addin-0006"] == "not-comparable"


def test_untrusted_agent_365_registry_approves_nothing(index, fixtures):
    result = _scan(index, fixtures / "identity" / "entra_agent_registry.json", trusted=False)
    assert not result.inventory_present
    assert all(f.registry_match is None for f in result.findings)


def test_conflicting_packages_never_approve_their_bindings(index, tmp_path):
    package = _package(agentIdentityId="ai-1")
    identity = {
        "_kind": "agentIdentity",
        "id": "ai-1",
        "displayName": "Helper",
        "agentIdentityBlueprintId": "bp",
    }
    source = tmp_path / "entra.json"
    source.write_text(json.dumps([COMPLETE_MARKER, identity, package, {**package, "version": "2"}]))
    result = _scan(index, source)
    assert not result.complete
    by = _by_resource(result.findings)
    assert by["entra:sp:ai-1"].shadow is True and by["entra:copilot-package:P_1"].shadow is True


# A tenant app registration and its ordinary service principal, which a package may name.
_TENANT_APP = [
    {"_kind": "application", "id": "reg-1", "appId": "app-tenant", "displayName": "OpenAI mail summarizer"},
    {
        "_kind": "servicePrincipal",
        "id": "sp-priv",
        "appId": "app-tenant",
        "displayName": "OpenAI mail summarizer",
        "servicePrincipalType": "Application",
    },
]


@pytest.mark.parametrize("package_type", ["external", "microsoft", "unknownFutureValue"])
def test_vendor_packages_never_approve_tenant_objects(index, tmp_path, package_type):
    # Vendor-declared ids name a tenant app registration and a service principal that is not an
    # agent identity. An approved vendor package has no known reviewer in this tenant, so it
    # approves nothing by default; with allow_auto_approved it approves only its own record.
    package = _package(
        "P_vendor", type=package_type, requestStatus=None, appId="app-tenant", agentIdentityId="sp-priv"
    )
    source = tmp_path / "entra.json"
    source.write_text(json.dumps([COMPLETE_MARKER, *_TENANT_APP, package]), encoding="utf-8")
    for allow, expected in ((False, None), (True, "microsoft-agent-365:P_vendor")):
        result = _scan(index, source, allow_auto_approved=allow)
        assert result.complete
        by = _by_resource(result.findings)
        record = registry_record(by["entra:copilot-package:P_vendor"])
        assert record is not None and record.status == "approved" and record.bindings == ()
        assert record.approval_mode == "unknown"
        assert by["entra:copilot-package:P_vendor"].registry_match == expected
        for resource in ("entra:app:app-tenant", "entra:sp:sp-priv"):
            assert by[resource].shadow is True and by[resource].registry_match is None
            assert "registry_bound" not in by[resource].metadata


def test_vendor_package_binds_a_listed_agent_identity(tmp_path, run_connector):
    identity = {
        "_kind": "agentIdentity",
        "id": "ai-1",
        "displayName": "Helper",
        "agentIdentityBlueprintId": "bp",
    }
    package = _package(type="external", requestStatus=None, appId="app-vendor", agentIdentityId="ai-1")
    findings, ctx = _offline(tmp_path, run_connector, [COMPLETE_MARKER, identity, package], tenant_id=TENANT)
    assert not ctx.stats.incomplete
    record = _record(_by_resource(findings)["entra:copilot-package:P_1"])
    assert record["approval_mode"] == "unknown"
    assert record["bindings"] == [
        {"resource": "entra:sp:ai-1", "provider": "entra", "account": TENANT, "coverage": "in-scope"}
    ]


def test_packages_bind_only_listed_agent_identities(index, tmp_path):
    # An organization's own, manually approved package that names an ordinary service principal
    # as its agent identity approves its app registration, never that principal.
    package = _package(appId="app-tenant", agentIdentityId="sp-priv")
    source = tmp_path / "entra.json"
    source.write_text(json.dumps([COMPLETE_MARKER, *_TENANT_APP, package]), encoding="utf-8")
    result = _scan(index, source)
    by = _by_resource(result.findings)
    record = registry_record(by["entra:copilot-package:P_1"])
    assert record is not None and record.approval_mode == "manual"
    assert [binding.resource for binding in record.bindings] == ["entra:app:app-tenant"]
    assert by["entra:app:app-tenant"].registry_match == "microsoft-agent-365:P_1"
    assert by["entra:sp:sp-priv"].shadow is True and by["entra:sp:sp-priv"].registry_match is None


def test_conflicting_agent_identities_are_never_bound(tmp_path, run_connector):
    identity = {
        "_kind": "agentIdentity",
        "id": "ai-1",
        "displayName": "Helper",
        "agentIdentityBlueprintId": "a",
    }
    findings, _ = _offline(
        tmp_path,
        run_connector,
        [
            COMPLETE_MARKER,
            identity,
            {**identity, "agentIdentityBlueprintId": "b"},
            _package(agentIdentityId="ai-1"),
        ],
        tenant_id=TENANT,
    )
    assert _record(_by_resource(findings)["entra:copilot-package:P_1"])["bindings"] == []


# ------------------------------------------------------------------ live collection
class _Graph:
    """A fake Graph client: listings by path, details by URL, and the calls made."""

    def __init__(self, pages=None, details=None, failures=None):
        self.pages: dict[str, list[dict[str, Any]]] = pages or {}
        self.details: dict[str, Any] = details or {}
        self.failures: dict[str, Exception] = failures or {}
        self.listed: list[tuple[str, Any]] = []
        self.fetched: list[str] = []

    def paginate_odata(self, path, params=None):
        self.listed.append((path, params))
        yield from self.pages.get(path, [])
        if path in self.failures:
            raise self.failures[path]

    def get_json(self, path, **kwargs):
        self.fetched.append(path)
        value = self.details.get(path)
        if isinstance(value, Exception):
            raise value
        return value


def _live(index, graph, **config):
    ctx = _context(index, tenant_id=TENANT, **config)
    connector = EntraConnector(ctx)
    connector._auth = Mock()
    connector.http = graph
    return connector, ctx


_IDENTITY = {
    "@odata.type": "#microsoft.graph.agentIdentity",
    "id": "ai-1",
    "displayName": "Helper",
    "agentIdentityBlueprintId": "bp-1",
    "servicePrincipalType": "ServiceIdentity",
}
_LISTED = {"id": "P_1", "displayName": "Helper", "type": "custom", "isBlocked": False, "availableTo": "all"}
_DETAIL = {
    **_LISTED,
    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#copilot/admin/catalog/packages/$entity",
    "elementTypes": ["declarativeAgent"],
    "requestStatus": "approved",
    "agentIdentityId": "ai-1",
    "appId": "app-1",
    "allowedUsersAndGroups": [{"resourceId": "group-1", "resourceType": "group"}],
    "acquireUsersAndGroups": [],
    "elementDetails": [{"elementType": "bot", "elements": [{"id": "bot-1", "definition": "{}"}]}],
    "zipFile": "UEsDBA==",
}


def _registry_graph(listing=LISTING, **overrides):
    pages = {AGENT_IDENTITIES: [_IDENTITY], listing: [_LISTED]}
    details = {f"{listing}/P_1": _DETAIL}
    return _Graph(
        pages={**pages, **overrides.pop("pages", {})},
        details={**details, **overrides.pop("details", {})},
        **overrides,
    )


def test_agent_collections_are_opt_in(index):
    graph = _Graph()
    connector, ctx = _live(index, graph)
    assert list(connector.collect()) == []
    assert [path for path, _ in graph.listed] == [
        "/servicePrincipals",
        "/oauth2PermissionGrants",
        "/applications",
    ]
    assert graph.fetched == []


def test_opted_in_collection_requests_exact_paths_and_strips_member_ids(index):
    graph = _registry_graph()
    connector, ctx = _live(index, graph, include_agent_identities=True, include_agent_registry=True)
    records = list(connector.collect())
    assert [path for path, _ in graph.listed] == [
        "/servicePrincipals",
        "/oauth2PermissionGrants",
        "/applications",
        AGENT_IDENTITIES,
        # The agent identity is not a listed service principal: its app role assignments are read too.
        "/servicePrincipals/ai-1/appRoleAssignments",
        LISTING,
    ]
    assert (
        AGENT_IDENTITIES == "https://graph.microsoft.com/beta/servicePrincipals/microsoft.graph.agentIdentity"
    )
    assert dict(graph.listed)[AGENT_IDENTITIES] is None and dict(graph.listed)[LISTING] is None
    assert graph.fetched == [f"{LISTING}/P_1"]
    identity, package, marker = records
    assert identity["_kind"] == "agentIdentity"
    assert package["_kind"] == "copilotPackage" and package["_detail"] == "observed"
    assert package["_accessCounts"] == {"allowedUsersAndGroups": 1, "acquireUsersAndGroups": 0}
    for dropped in (
        "allowedUsersAndGroups",
        "acquireUsersAndGroups",
        "zipFile",
        "elementDetails",
        "@odata.context",
    ):
        assert dropped not in package
    assert marker == {
        "_kind": COVERAGE_KIND,
        "packages": "complete",
        "agentIdentities": "complete",
        "applications": "complete",
        "listingScope": "registry",
    }
    findings = list(connector.analyze(records))
    assert not ctx.stats.incomplete
    record = registry_record(_by_resource(findings)["entra:copilot-package:P_1"])
    assert record is not None and record.status == "approved" and record.approval_mode == "manual"
    assert record.listing_complete and {b.coverage for b in record.bindings} == {"in-scope"}


def test_agent_identity_app_role_assignments_are_read(index):
    resource = {
        "id": "graph-sp",
        "appId": "graph-app",
        "displayName": "Resource API",
        "appRoles": [{"id": "role-1", "value": "Mail.ReadWrite"}],
    }
    # Listed as a first-party service principal, so the principal listing skips its lookup.
    first_party = {**_IDENTITY, "id": "ai-2", "appOwnerOrganizationId": FIRST_PARTY_OWNER}
    assignment = {"principalId": "ai-1", "appRoleId": "role-1", "resourceId": "graph-sp"}
    graph = _Graph(
        pages={
            "/servicePrincipals": [
                resource,
                {"id": "ai-2", "displayName": "Helper 2", "appOwnerOrganizationId": FIRST_PARTY_OWNER},
            ],
            AGENT_IDENTITIES: [_IDENTITY, first_party],
            "/servicePrincipals/ai-1/appRoleAssignments": [assignment],
            "/servicePrincipals/ai-2/appRoleAssignments": [{**assignment, "principalId": "ai-2"}],
        }
    )
    connector, ctx = _live(index, graph, include_agent_identities=True)
    findings = connector.run()
    assert not ctx.stats.incomplete, ctx.stats.warnings
    lookups = [path for path, _ in graph.listed if path.endswith("/appRoleAssignments")]
    # Each principal is read once: the resource from the principal listing, both agent identities after.
    assert lookups == [
        "/servicePrincipals/graph-sp/appRoleAssignments",
        "/servicePrincipals/ai-1/appRoleAssignments",
        "/servicePrincipals/ai-2/appRoleAssignments",
    ]
    by = _by_resource(findings)
    assert by["entra:sp:ai-1"].resource_type == "service-principal/AgentIdentity"
    assert by["entra:sp:ai-1"].metadata["application_permissions"] == ["Mail.ReadWrite"]
    assert by["entra:sp:ai-2"].metadata["application_permissions"] == ["Mail.ReadWrite"]


def test_agent_identity_lookups_share_the_app_role_lookup_cap(index):
    graph = _Graph(
        pages={
            "/servicePrincipals": [{"id": "sp-1", "displayName": "Fireflies.ai Notetaker"}],
            AGENT_IDENTITIES: [_IDENTITY],
        }
    )
    connector, ctx = _live(index, graph, include_agent_identities=True, max_app_role_lookups=1)
    findings = connector.run()
    _assert_incomplete(ctx, findings)
    assert [path for path, _ in graph.listed if path.endswith("/appRoleAssignments")] == [
        "/servicePrincipals/sp-1/appRoleAssignments"
    ]
    assert sum("max_app_role_lookups reached" in w for w in ctx.stats.warnings) == 1


def test_beta_catalog_api_uses_the_beta_listing(index):
    listing = GRAPH_BETA + COPILOT_PACKAGES
    graph = _registry_graph(listing)
    connector, ctx = _live(index, graph, include_agent_registry=True, agent_registry_api="beta")
    connector.run()
    assert (listing, None) in graph.listed and graph.fetched == [f"{listing}/P_1"]
    assert not ctx.stats.incomplete


def test_package_detail_ids_are_path_quoted(index):
    listed = {**_LISTED, "id": "P_1/x?y"}
    graph = _Graph(
        pages={LISTING: [listed]}, details={f"{LISTING}/P_1%2Fx%3Fy": {**_DETAIL, "id": "P_1/x?y"}}
    )
    connector, ctx = _live(index, graph, include_agent_registry=True)
    connector.run()
    assert graph.fetched == [f"{LISTING}/P_1%2Fx%3Fy"] and not ctx.stats.incomplete


@pytest.mark.parametrize("path", [LISTING, AGENT_IDENTITIES])
def test_denied_agent_collection_is_incomplete_and_keeps_neighbors(index, path):
    principal = {"id": "sp-1", "appId": "a", "displayName": "Fireflies.ai Notetaker"}
    graph = _registry_graph(
        pages={"/servicePrincipals": [principal]},
        failures={path: HttpError(403, "https://graph.microsoft.com")},
    )
    connector, ctx = _live(index, graph, include_agent_identities=True, include_agent_registry=True)
    findings = connector.run()
    _assert_incomplete(ctx, findings)
    assert "entra:sp:sp-1" in _by_resource(findings)
    assert "HTTP 403" in " ".join(ctx.stats.warnings)
    package = _by_resource(findings)["entra:copilot-package:P_1"]
    record = _record(package)
    if path == LISTING:
        # The package listed before the failure is kept; the listing is not complete.
        assert record["listing_complete"] is False
    else:
        assert record["listing_complete"] is True
        # The agent identity listed before the failure is bound, but the listing is not complete.
        assert record["bindings"][0] == {
            "resource": "entra:sp:ai-1",
            "provider": "entra",
            "account": TENANT,
            "coverage": "unknown",
        }


def test_listing_page_cap_is_incomplete(index):
    graph = _registry_graph(
        failures={LISTING: RuntimeError("Pagination limit reached; collection incomplete")}
    )
    connector, ctx = _live(index, graph, include_agent_registry=True)
    findings = connector.run()
    _assert_incomplete(ctx, findings)
    assert _record(findings[0])["listing_complete"] is False


@pytest.mark.parametrize(
    "detail,warning",
    [
        (HttpError(404, "https://graph.microsoft.com"), "package details unreadable (HTTP 404)"),
        ([], "do not describe the listed package"),
        ({**_DETAIL, "id": "P_other"}, "do not describe the listed package"),
    ],
)
def test_unusable_package_detail_keeps_the_listed_package(index, detail, warning):
    graph = _registry_graph(details={f"{LISTING}/P_1": detail})
    connector, ctx = _live(index, graph, include_agent_registry=True)
    findings = connector.run()
    _assert_incomplete(ctx, findings)
    assert warning in " ".join(ctx.stats.warnings)
    [package] = findings
    assert package.metadata["package_detail"] == "unavailable"
    assert _record(package)["listing_complete"] is False and _record(package)["status"] == "approved"


def test_package_detail_cap_is_incomplete(index):
    second = {**_LISTED, "id": "P_2"}
    third = {**_LISTED, "id": "P_3"}
    graph = _registry_graph(pages={LISTING: [_LISTED, second, third]})
    connector, ctx = _live(index, graph, include_agent_registry=True, max_package_lookups=1)
    findings = connector.run()
    _assert_incomplete(ctx, findings)
    assert graph.fetched == [f"{LISTING}/P_1"]
    assert sum("max_package_lookups reached" in w for w in ctx.stats.warnings) == 1
    assert {f.metadata["package_detail"] for f in findings} == {"observed", "limit"}


def test_listed_package_without_an_id_is_incomplete(index):
    graph = _registry_graph(pages={LISTING: [{"displayName": "No id"}, _LISTED]})
    connector, ctx = _live(index, graph, include_agent_registry=True)
    findings = connector.run()
    _assert_incomplete(ctx, findings)
    assert [f.resource for f in findings] == ["entra:copilot-package:P_1"]
    assert _record(findings[0])["listing_complete"] is False


def test_agent_registry_export_round_trip(index, tmp_path, run_connector):
    dump = tmp_path / "entra.jsonl"
    graph = _registry_graph()
    connector, ctx = _live(
        index, graph, include_agent_identities=True, include_agent_registry=True, _dump_path=str(dump)
    )
    live = connector.run()
    assert not ctx.stats.incomplete and ctx.dump_path == str(dump)
    exported = dump.read_text(encoding="utf-8")
    assert "group-1" not in exported and "zipFile" not in exported and "bot-1" not in exported
    replay, replay_ctx = run_connector("identity.entra", input=str(dump), tenant_id=TENANT)
    assert not replay_ctx.stats.incomplete and not replay_ctx.stats.warnings
    assert sorted(f.id for f in live) == sorted(f.id for f in replay)
    assert {f.id: f.metadata.get("registry_record") for f in live} == {
        f.id: f.metadata.get("registry_record") for f in replay
    }


# ------------------------------------------------------------------ delegated auth
def _token(**claims):
    payload = {
        "tid": TENANT,
        "scp": "CopilotPackages.Read.All Application.Read.All",
        "exp": int(time.time()) + 3600,
    }
    payload.update(claims)
    return pyjwt.encode(
        {key: value for key, value in payload.items() if value is not None}, _TEST_HMAC_KEY, algorithm="HS256"
    )


def _mock_graph(*, detail_status=200, detail_body=None, second_page_status=200):
    for path in (
        "/servicePrincipals",
        "/oauth2PermissionGrants",
        "/applications",
        "/servicePrincipals/ai-1/appRoleAssignments",
    ):
        responses.get(GRAPH + path, json={"value": []})
    responses.get(AGENT_IDENTITIES, json={"value": [_IDENTITY]})
    responses.get(LISTING, json={"value": [_LISTED], "@odata.nextLink": LISTING + "?$skiptoken=page-2"})
    second = {**_LISTED, "id": "P_2"}
    if second_page_status == 200:
        responses.get(LISTING + "?$skiptoken=page-2", json={"value": [second]})
    else:
        responses.get(LISTING + "?$skiptoken=page-2", status=second_page_status)
    if detail_status == 200:
        responses.get(f"{LISTING}/P_1", json=_DETAIL)
    else:
        responses.get(f"{LISTING}/P_1", status=detail_status, body=detail_body or "")
    responses.get(f"{LISTING}/P_2", json={**_DETAIL, "id": "P_2"})


@responses.activate
def test_delegated_token_comes_only_from_the_named_environment_variable(monkeypatch, index):
    token = _token()
    monkeypatch.setenv("CONTOSO_GRAPH_USER_TOKEN", token)
    # App-only credentials in the environment are never consulted in delegated mode.
    monkeypatch.setenv("GRAPH_ACCESS_TOKEN", "app-only-environment-token")
    monkeypatch.setenv("AZURE_CLIENT_ID", "client")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "synthetic-client-secret-value")
    _mock_graph()
    ctx = _context(
        index,
        tenant_id=TENANT,
        auth_mode="delegated",
        delegated_token_env="CONTOSO_GRAPH_USER_TOKEN",
        include_agent_registry=True,
        include_agent_identities=True,
    )
    findings = EntraConnector(ctx).run()
    assert not ctx.stats.incomplete, ctx.stats.warnings
    assert responses.calls and all(call.request.method == "GET" for call in responses.calls)
    assert {call.request.headers["Authorization"] for call in responses.calls} == {f"Bearer {token}"}
    assert not any("login.microsoftonline.com" in call.request.url for call in responses.calls)
    # The opaque next link was followed until absent.
    packages = {f.resource for f in findings if f.resource.startswith("entra:copilot-package:")}
    assert packages == {"entra:copilot-package:P_1", "entra:copilot-package:P_2"}
    # What a signed-in user sees is caller-scoped: never a complete registry listing.
    record = registry_record(_by_resource(findings)["entra:copilot-package:P_1"])
    assert record is not None and record.listing_scope == "caller" and not record.listing_complete


@responses.activate
def test_delegated_token_expiring_mid_scan_is_incomplete(monkeypatch, index):
    monkeypatch.setenv("GRAPH_DELEGATED_TOKEN", _token())
    _mock_graph(second_page_status=401)
    ctx = _context(index, tenant_id=TENANT, auth_mode="delegated", include_agent_registry=True)
    findings = EntraConnector(ctx).run()
    _assert_incomplete(ctx, findings)
    assert "HTTP 401" in " ".join(ctx.stats.warnings)
    assert [f.resource for f in findings] == ["entra:copilot-package:P_1"]


@responses.activate
@pytest.mark.parametrize(
    "token,message",
    [
        (None, "environment variable GRAPH_DELEGATED_TOKEN is not set"),
        ("", "environment variable GRAPH_DELEGATED_TOKEN is not set"),
        ("has a space", "does not hold a usable access token"),
        ("a" * (16 * 1024 + 1), "does not hold a usable access token"),
        ("opaque.token.value", "not a decodable JWT"),
        (lambda: _token(tid="other-tenant"), "does not match tenant_id"),
        (lambda: _token(tid=None), "does not match tenant_id"),
        (lambda: _token(idtyp="app"), "not a delegated user token"),
        (lambda: _token(scp=None, roles=["CopilotPackages.Read.All"]), "not a delegated user token"),
        (lambda: _token(exp=int(time.time()) - 60), "has expired"),
    ],
)
def test_unusable_delegated_tokens_fail_closed_without_echoing(monkeypatch, index, token, message):
    value = token() if callable(token) else token
    if value is None:
        monkeypatch.delenv("GRAPH_DELEGATED_TOKEN", raising=False)
    else:
        monkeypatch.setenv("GRAPH_DELEGATED_TOKEN", value)
    ctx = _context(index, tenant_id=TENANT, auth_mode="delegated", include_agent_registry=True)
    findings = EntraConnector(ctx).run()
    assert findings == [] and ctx.stats.skipped
    _assert_incomplete(ctx, findings)
    assert message in ctx.stats.skip_reason
    diagnostics = " ".join([ctx.stats.skip_reason, *ctx.stats.errors, *ctx.stats.warnings])
    if value:
        assert value not in diagnostics
        assert all(part not in diagnostics for part in value.split(".") if len(part) > 8)
    assert len(responses.calls) == 0


@responses.activate
@pytest.mark.parametrize(
    "token,message",
    [
        ("opaque-app-only-value", "the access_token is not a decodable JWT"),
        (lambda: _token(tid="other-tenant", scp=None, idtyp="app"), "does not match tenant_id"),
        (lambda: _token(tid=None, scp=None, idtyp="app"), "does not match tenant_id"),
    ],
)
def test_pre_issued_token_of_another_tenant_never_produces_registry_records(
    monkeypatch, index, token, message
):
    value = token() if callable(token) else token
    monkeypatch.setenv("GRAPH_ACCESS_TOKEN", value)
    ctx = _context(index, tenant_id=TENANT, include_agent_registry=True)
    findings = EntraConnector(ctx).run()
    assert findings == [] and ctx.stats.skipped
    _assert_incomplete(ctx, findings)
    assert message in ctx.stats.skip_reason
    diagnostics = " ".join([ctx.stats.skip_reason, *ctx.stats.errors, *ctx.stats.warnings])
    assert value not in diagnostics
    assert all(part not in diagnostics for part in value.split(".") if len(part) > 8)
    assert len(responses.calls) == 0


@responses.activate
def test_pre_issued_token_of_the_tenant_collects_registry_records(monkeypatch, index):
    token = _token(scp=None, idtyp="app", roles=["CopilotPackages.Read.All"])
    monkeypatch.setenv("GRAPH_ACCESS_TOKEN", token)
    _mock_graph()
    ctx = _context(index, tenant_id=TENANT, include_agent_registry=True)
    findings = EntraConnector(ctx).run()
    assert not ctx.stats.incomplete, ctx.stats.warnings
    assert {call.request.headers["Authorization"] for call in responses.calls} == {f"Bearer {token}"}
    record = registry_record(_by_resource(findings)["entra:copilot-package:P_1"])
    assert record is not None and record.registry_id == TENANT and record.listing_complete


@responses.activate
@pytest.mark.parametrize("config", [{"tenant_id": TENANT}, {"include_agent_registry": True}])
def test_pre_issued_token_tenant_is_checked_only_for_attributed_registry_records(monkeypatch, index, config):
    # Without the registry collection nothing is attributed to a trusted registry; without
    # tenant_id the records have an empty registry id and can never be trusted.
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    monkeypatch.setenv("GRAPH_ACCESS_TOKEN", "opaque-app-only-value")
    _mock_graph()
    ctx = _context(index, **config)
    findings = EntraConnector(ctx).run()
    assert not ctx.stats.skipped and not ctx.stats.incomplete, ctx.stats.warnings
    records = [registry_record(f) for f in findings if "registry_record" in f.metadata]
    assert all(record is not None and record.registry_id == "" for record in records)
    assert bool(records) == bool(config.get("include_agent_registry"))


@pytest.mark.parametrize(
    "config,message",
    [
        ({"auth_mode": "delegated", "client_secret": "synthetic-secret"}, "does not accept"),
        ({"auth_mode": "delegated", "access_token": "synthetic-token"}, "does not accept"),
        ({"auth_mode": "delegated", "client_id": "client"}, "does not accept"),
        ({"auth_mode": "delegated", "tenant_id": None}, "requires tenant_id"),
        ({"auth_mode": "delegated", "tenant_id": "  "}, "requires tenant_id"),
        ({"auth_mode": "user"}, "auth_mode must be app-only or delegated"),
        ({"delegated_token_env": "1BAD"}, "must name an environment variable"),
        ({"delegated_token_env": "GRAPH-TOKEN"}, "must name an environment variable"),
        ({"delegated_token_env": 5}, "must name an environment variable"),
        ({"agent_registry_api": "v2"}, "agent_registry_api must be v1.0 or beta"),
        ({"max_package_lookups": 0}, "max_package_lookups"),
    ],
)
def test_invalid_auth_configuration_is_rejected(monkeypatch, index, config, message):
    monkeypatch.delenv("AZURE_TENANT_ID", raising=False)
    with pytest.raises(ConnectorError, match=message) as failure:
        EntraConnector(_context(index, **{"tenant_id": TENANT, **config}))
    assert "synthetic-secret" not in str(failure.value) and "synthetic-token" not in str(failure.value)


def test_inline_delegated_tokens_are_not_configuration():
    with pytest.raises(ConfigValidationError) as failure:
        ScanConfig.from_dict(
            {"connectors": [{"name": "identity.entra", "delegated_access_token": "synthetic-inline-value"}]}
        )
    assert "synthetic-inline-value" not in str(failure.value)


def test_agent_registry_keys_are_accepted(monkeypatch):
    monkeypatch.setenv("NEXUS_AGENT_FLAG", "false")
    cfg = ScanConfig.from_dict(
        {
            "connectors": [
                {
                    "name": "identity.entra",
                    "tenant_id": TENANT,
                    "auth_mode": "delegated",
                    "delegated_token_env": "CONTOSO_GRAPH_USER_TOKEN",
                    "include_agent_registry": "${NEXUS_AGENT_FLAG}",
                    "include_agent_identities": True,
                    "agent_registry_api": "beta",
                    "max_package_lookups": 10,
                }
            ]
        }
    )
    config = cfg.connectors[0].config
    assert config["include_agent_registry"] is False and config["include_agent_identities"] is True


def test_secret_env_registers_the_value_for_redaction(monkeypatch, index):
    monkeypatch.setenv("NEXUS_SYNTHETIC_CREDENTIAL", "opaque-synthetic-credential-0123")
    monkeypatch.setenv("NEXUS_EMPTY_CREDENTIAL", "")
    ctx = _context(index)
    assert ctx.secret_env("NEXUS_EMPTY_CREDENTIAL") is None
    assert ctx.secret_env("NEXUS_UNSET_CREDENTIAL_NAME") is None
    value = ctx.secret_env("NEXUS_SYNTHETIC_CREDENTIAL")
    ctx.warn(f"upstream echoed {value}")
    assert "opaque-synthetic-credential-0123" not in ctx.stats.warnings[0]


@responses.activate
def test_delegated_token_never_reaches_reports_logs_stats_or_exports(monkeypatch, index, tmp_path, caplog):
    token = _token()
    monkeypatch.setenv("GRAPH_DELEGATED_TOKEN", token)
    # An upstream error body that echoes the token.
    _mock_graph(detail_status=400, detail_body=f"invalid request for {token}")
    caplog.set_level(logging.DEBUG)
    exports = tmp_path / "exports"
    cfg = ScanConfig.from_dict(
        {
            "connectors": [
                {
                    "name": "identity.entra",
                    "tenant_id": TENANT,
                    "auth_mode": "delegated",
                    "include_agent_registry": True,
                    "include_agent_identities": True,
                }
            ],
            "options": {"dump_records": str(exports)},
        }
    )
    result = Engine(cfg, index).run()
    assert not result.complete and result.findings
    assert any("package details unreadable (HTTP 400)" in w for s in result.stats for w in s.warnings)
    written = "".join(
        path.read_text(encoding="utf-8") for path in sorted(Path(exports).rglob("*")) if path.is_file()
    )
    assert "copilotPackage" in written
    output = "".join(
        [json.dumps(result.to_dict()), render_sarif(result), render_html(result), caplog.text, written]
    )
    assert token not in output
    assert all(segment not in output for segment in token.split("."))


def test_auth_mode_is_part_of_the_collection_scope_fingerprint(index, fixtures):
    source = str(fixtures / "identity" / "entra_agent_registry.json")

    def scope(**config):
        cfg = ScanConfig.from_dict(
            {"connectors": [{"name": "identity.entra", "input": source, "tenant_id": TENANT, **config}]}
        )
        return build_collection_scope(cfg, index, cfg.connectors)

    app_only, delegated = scope(), scope(auth_mode="delegated")
    assert app_only["comparable"] and delegated["comparable"]
    assert app_only["fingerprint"] != delegated["fingerprint"]
