"""Threat and control mapping catalogs: validation, rule matching and report output.

References are evidence references and author mappings. These tests pin every
packaged rule to the references the roadmap specified, check each with a
finding it should match, and keep the derived keys out of identity and diff.
"""

from __future__ import annotations

import json
import re
import shutil
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
import yaml

from shadowscan import mappings
from shadowscan.comparison import compare_reports
from shadowscan.mappings import (
    MappingCatalogError,
    MappingEntry,
    MappingIndex,
    control_references,
    describe,
    finding_references,
    load_mappings,
    threat_references,
)
from shadowscan.mappings import validate as validate_module
from shadowscan.mappings.loader import builtin_mapping_dir
from shadowscan.mappings.schema import FindingFacts
from shadowscan.models import DERIVED_METADATA_KEYS, Finding, Kind, ScanResult, ScanStats, Surface
from shadowscan.reporters import render
from shadowscan.risk import TAG_WEIGHTS

ROOT = Path(__file__).parents[2]
LLM = "owasp-llm-2026:"
ASI = "owasp-asi-2026:"
ATLAS = "mitre-atlas-2026.09:"
MAESTRO = "maestro-2025:"
NIST = "nist-ai-rmf-1.0:"
ISO = "iso-iec-42001-2023:"
EU = "eu-ai-act-2024:"
AIUC = "aiuc-1-2026q2:"
CREDENTIAL_TAGS = (
    "hardcoded-credential",
    "plaintext-credential",
    "inline-secrets",
    "secret-in-env",
    "unmasked-ci-variable",
)
EXPOSURE_TAGS = (
    "exposed-llm-server",
    "public-ingress",
    "public-principal",
    "posture-exposed-gateway",
    "posture-unauthenticated-gateway",
    "unauthenticated-mcp",
    "no-authentication",
)

# The references the roadmap specified for each packaged rule. A change to a
# rule's references must change this table, so every mapping has a test.
EXPECTED_REFS: dict[str, list[str]] = {
    "tool-poisoning": [f"{LLM}LLM01", f"{ASI}ASI01", f"{ATLAS}AML.T0110.000", f"{ATLAS}AML.T0051.001"],
    "unsafe-serialization": [f"{LLM}LLM04", f"{ASI}ASI04", f"{ATLAS}AML.T0011.000", f"{ATLAS}AML.T0010.003"],
    "credential-exposure": [f"{LLM}LLM02", f"{ASI}ASI03", f"{ATLAS}AML.T0055"],
    "credential-finding": [f"{ASI}ASI03"],
    "agent-config-credentials": [f"{ATLAS}AML.T0083"],
    "privileged-workload": [f"{LLM}LLM03", f"{ASI}ASI03"],
    "privileged-pod-escape": [f"{ATLAS}AML.T0105"],
    "code-execution-capability": [f"{LLM}LLM03", f"{ASI}ASI05", f"{ATLAS}AML.T0050"],
    "code-execution-configuration": [f"{LLM}LLM03", f"{ASI}ASI05", f"{ATLAS}AML.T0050"],
    "saas-actions": [f"{LLM}LLM03", f"{ASI}ASI02", f"{ATLAS}AML.T0053"],
    "approval-bypass": [f"{LLM}LLM03", f"{ASI}ASI02", f"{ASI}ASI09"],
    "unsandboxed-agent": [f"{ASI}ASI05", f"{ATLAS}AML.T0105"],
    "exposed-ai-service": [f"{ATLAS}AML.T0132"],
    "exposed-inference-server": [f"{LLM}LLM06", f"{ATLAS}AML.T0040"],
    "unauthenticated-endpoint": [f"{ASI}ASI03"],
    "mcp-unpinned-package": [f"{LLM}LLM04", f"{ASI}ASI04", f"{ATLAS}AML.T0010.005", f"{ATLAS}AML.T0109"],
    "mcp-unvetted-source": [f"{LLM}LLM04", f"{ASI}ASI04", f"{ATLAS}AML.T0010.005"],
    "mcp-broad-filesystem": [f"{LLM}LLM03", f"{ASI}ASI02", f"{ATLAS}AML.T0086"],
    "hidden-instructions": [f"{LLM}LLM01", f"{ASI}ASI01", f"{ATLAS}AML.T0051.001", f"{ATLAS}AML.T0068"],
    "memory-capability": [f"{ASI}ASI06", f"{ATLAS}AML.T0080.000"],
    "rag-capability": [f"{LLM}LLM09", f"{ASI}ASI06", f"{ATLAS}AML.T0070"],
    "browsing-capability": [f"{LLM}LLM01", f"{ATLAS}AML.T0051.001"],
    "multi-agent-capability": [f"{ASI}ASI07", f"{ASI}ASI08", f"{ATLAS}AML.T0118"],
    "delegated-identity-capability": [f"{ASI}ASI03"],
    "agent-card-without-security-scheme": [f"{ASI}ASI07", f"{ASI}ASI03"],
    "a2a-plaintext-interface": [f"{ASI}ASI07", f"{ATLAS}AML.T0118.001"],
    "a2a-card-signature-invalid": [f"{ASI}ASI07", f"{ASI}ASI04"],
    "high-autonomy": [f"{LLM}LLM03", f"{ASI}ASI08"],
    "maestro-l1-local-model": [f"{MAESTRO}L1"],
    "maestro-l1-model-artifact": [f"{MAESTRO}L1"],
    "maestro-l2-data": [f"{MAESTRO}L2"],
    "maestro-l3-agent-framework": [f"{MAESTRO}L3"],
    "maestro-l4-infrastructure": [f"{MAESTRO}L4"],
    "maestro-l4-infrastructure-posture": [f"{MAESTRO}L4"],
    "maestro-l5-gateway-caller": [f"{MAESTRO}L5"],
    "maestro-l5-logging": [f"{MAESTRO}L5"],
    "maestro-l6-identity-and-credentials": [f"{MAESTRO}L6"],
    "maestro-l7-multi-agent": [f"{MAESTRO}L7"],
    "maestro-l7-bot-app": [f"{MAESTRO}L7"],
    "maestro-l7-agent-card": [f"{MAESTRO}L7"],
    "shadow-ai-system": [f"{NIST}GOVERN-1.6", f"{ISO}A.4.2", f"{AIUC}E"],
    "registry-gap": [f"{NIST}GOVERN-1.6", f"{ISO}A.4.2"],
    "stale-registration": [f"{NIST}GOVERN-1.7"],
    "missing-owner": [f"{NIST}GOVERN-2.1", f"{ISO}A.3.2", f"{AIUC}E"],
    "oversight-bypassed": [
        f"{NIST}GOVERN-3.2",
        f"{NIST}MAP-3.5",
        f"{EU}Art.14",
        f"{ISO}A.9.2",
        f"{AIUC}D003",
    ],
    "high-autonomy-oversight": [
        f"{NIST}GOVERN-3.2",
        f"{NIST}MAP-3.5",
        f"{EU}Art.14",
        f"{ISO}A.9.2",
        f"{AIUC}D003",
    ],
    "logging-gap": [f"{EU}Art.12", f"{ISO}A.6.2.8", f"{NIST}MEASURE-3.1"],
    "security-exposure": [f"{NIST}MEASURE-2.7", f"{EU}Art.15", f"{AIUC}B"],
    "third-party-components": [f"{NIST}GOVERN-6.1", f"{NIST}MANAGE-3.1", f"{NIST}MAP-4.1", f"{ISO}A.10.3"],
    "mcp-unvetted-component": [f"{NIST}GOVERN-6.1", f"{ISO}A.10.3"],
    "user-facing-ai": [f"{EU}Art.50"],
    "agentic-monitoring": [f"{NIST}MANAGE-4.1", f"{ISO}A.6.2.6"],
    "declared-high-risk": [f"{EU}Art.12", f"{EU}Art.14", f"{EU}Art.26"],
    "declared-transparency": [f"{EU}Art.50"],
}


def _autonomy(floor: int, oversight: str = "unknown") -> dict[str, Any]:
    return {"autonomy": {"floor": floor, "ceiling": 5, "oversight": oversight, "initiation": "unknown"}}


def _registry(status: str) -> dict[str, Any]:
    return {"registry_reconciliation": {"status": status}}


def _declared(risk_class: str) -> dict[str, Any]:
    # What the engine records for a finding matched to a card that declares the class.
    return {"metadata": {"declared_governance": {"eu_ai_act_risk_class": risk_class, "source": "card"}}}


# A minimal finding each rule should match.
RULE_CASES: dict[str, dict[str, Any]] = {
    "tool-poisoning": {"kind": Kind.MCP_SERVER, "tags": ["tool-poisoning"]},
    "unsafe-serialization": {"kind": Kind.LOCAL_MODEL, "tags": ["unsafe-serialization"]},
    "credential-exposure": {"tags": ["hardcoded-credential"]},
    "credential-finding": {"kind": Kind.SECRET},
    "agent-config-credentials": {"kind": Kind.AGENT_CONFIG, "tags": ["inline-secrets"]},
    "privileged-workload": {"kind": Kind.INFRA, "tags": ["wildcard-permissions"]},
    "privileged-pod-escape": {"kind": Kind.INFRA, "tags": ["privileged-pod"]},
    "code-execution-capability": {"capabilities": ["code-exec"]},
    "code-execution-configuration": {"kind": Kind.MCP_SERVER, "tags": ["mcp-shell-command"]},
    "saas-actions": {"kind": Kind.WORKFLOW, "capabilities": ["saas-actions"]},
    "approval-bypass": {"kind": Kind.AGENT_CONFIG, "tags": ["posture-permissions-bypassed"]},
    "unsandboxed-agent": {"kind": Kind.AGENT_CONFIG, "tags": ["posture-unsandboxed"]},
    "exposed-ai-service": {"kind": Kind.CLOUD_RESOURCE, "tags": ["public-ingress"]},
    "exposed-inference-server": {"kind": Kind.INFRA, "tags": ["exposed-llm-server"]},
    "unauthenticated-endpoint": {"kind": Kind.MCP_SERVER, "tags": ["unauthenticated-mcp"]},
    "mcp-unpinned-package": {"kind": Kind.MCP_SERVER, "tags": ["mcp-unpinned-package"]},
    "mcp-unvetted-source": {"kind": Kind.MCP_SERVER, "tags": ["mcp-unpublished"]},
    "mcp-broad-filesystem": {"kind": Kind.MCP_SERVER, "tags": ["mcp-broad-filesystem"]},
    "hidden-instructions": {"kind": Kind.AGENT_CONFIG, "tags": ["hidden-instructions"]},
    "memory-capability": {"capabilities": ["memory"]},
    "rag-capability": {"capabilities": ["rag"]},
    "browsing-capability": {"capabilities": ["browsing"]},
    "multi-agent-capability": {"capabilities": ["multi-agent"]},
    "delegated-identity-capability": {"capabilities": ["delegated-identity"]},
    "agent-card-without-security-scheme": {"tags": ["no-auth-declared"]},
    "a2a-plaintext-interface": {"tags": ["a2a-plaintext-interface"]},
    "a2a-card-signature-invalid": {"tags": ["a2a-card-signature-invalid"]},
    "high-autonomy": {"metadata": _autonomy(4)},
    "maestro-l1-local-model": {"kind": Kind.LOCAL_MODEL},
    "maestro-l1-model-artifact": {"kind": Kind.CLOUD_RESOURCE, "tags": ["unsafe-serialization"]},
    "maestro-l2-data": {"capabilities": ["data-access"]},
    "maestro-l3-agent-framework": {"kind": Kind.FRAMEWORK_USAGE},
    "maestro-l4-infrastructure": {"kind": Kind.RUNTIME_PROCESS},
    "maestro-l4-infrastructure-posture": {"kind": Kind.CLOUD_RESOURCE, "tags": ["no-egress-policy"]},
    "maestro-l5-gateway-caller": {"kind": Kind.GATEWAY_CALLER},
    "maestro-l5-logging": {"kind": Kind.CLOUD_RESOURCE, "tags": ["tracing-disabled"]},
    "maestro-l6-identity-and-credentials": {"kind": Kind.OAUTH_GRANT},
    "maestro-l7-multi-agent": {"capabilities": ["multi-agent"]},
    "maestro-l7-bot-app": {"kind": Kind.BOT_APP},
    "maestro-l7-agent-card": {"kind": Kind.CLOUD_RESOURCE, "tags": ["no-auth-declared"]},
    "shadow-ai-system": {"shadow": True},
    "registry-gap": {"metadata": _registry("observed-not-registered")},
    "stale-registration": {"metadata": _registry("registered-not-observed")},
    "missing-owner": {"kind": Kind.WORKFLOW, "owner": None},
    "oversight-bypassed": {"metadata": _autonomy(2, "bypassed")},
    "high-autonomy-oversight": {"metadata": _autonomy(5, "gated")},
    "logging-gap": {"kind": Kind.CLOUD_RESOURCE, "tags": ["no-invocation-logging"]},
    "security-exposure": {"kind": Kind.IAM_GRANT, "tags": ["policy.privileged-scopes"]},
    "third-party-components": {"kind": Kind.MCP_SERVER, "tags": ["mcp-unpinned-package"]},
    "mcp-unvetted-component": {"kind": Kind.MCP_SERVER, "tags": ["mcp-registry-deleted"]},
    "user-facing-ai": {"kind": Kind.AI_APP},
    "agentic-monitoring": {"metadata": _autonomy(3)},
    "declared-high-risk": {"shadow": False, **_declared("high")},
    "declared-transparency": {"kind": Kind.AGENT, "shadow": False, **_declared("gpai")},
}


def _rules_by_id() -> dict[str, Any]:
    return {rule.id: rule for rule in load_mappings().rules}


# ---------------------------------------------------------------- packaged data


def test_validator_passes_on_the_packaged_data(capsys):
    assert validate_module.main([]) == 0
    index = load_mappings()
    out = capsys.readouterr().out
    assert out == (
        f"Validated {len(index.catalogs)} catalogs, {len(index.entries)} entries and {len(index.rules)} rules.\n"
    )
    assert len(index.catalogs) == 8


def test_every_packaged_rule_has_a_pinned_reference_list_and_a_case():
    rules = _rules_by_id()
    assert set(rules) == set(EXPECTED_REFS) == set(RULE_CASES)
    for rule_id, rule in rules.items():
        assert list(rule.refs) == EXPECTED_REFS[rule_id], rule_id
        assert rule.rationale


@pytest.mark.parametrize("rule_id", sorted(RULE_CASES))
def test_each_rule_applies_to_a_finding_it_describes(make_finding, rule_id):
    rule = _rules_by_id()[rule_id]
    finding = make_finding(**RULE_CASES[rule_id])
    threats, controls = finding_references(finding)
    produced = controls if rule.kind == "control" else threats
    assert set(EXPECTED_REFS[rule_id]) <= set(produced), (rule_id, threats, controls)
    assert rule.when.matches(FindingFacts.of(finding))


def test_finding_without_triggering_facts_has_no_references(make_finding):
    finding = make_finding(kind=Kind.NETWORK_CONTACT, owner="platform-team")
    assert finding_references(finding) == ([], [])
    metadata = finding.to_dict()["metadata"]
    assert not DERIVED_METADATA_KEYS & set(metadata)


def test_catalog_identifiers_are_edition_qualified_and_well_formed():
    index = load_mappings()
    atlas = [entry for entry in index.entries.values() if entry.framework == "mitre-atlas"]
    assert atlas
    assert all(re.fullmatch(r"AML\.T\d{4}(\.\d{3})?", entry.id) for entry in atlas)
    for catalog in index.catalogs:
        assert catalog.prefix == f"{catalog.framework}-{catalog.edition}"
        assert catalog.source_url.startswith("https://")
        for entry in catalog.entries:
            assert entry.ref == f"{catalog.prefix}:{entry.id}"
    owasp = {entry.id: entry.title for entry in index.entries.values() if entry.framework == "owasp-llm"}
    assert owasp["LLM03"] == "Excessive Agency" and owasp["LLM07"] == "Misinformation"
    assert sorted(owasp) == [f"LLM{n:02d}" for n in range(1, 11)]
    asi = {entry.id: entry.title for entry in index.entries.values() if entry.framework == "owasp-asi"}
    assert sorted(asi) == [f"ASI{n:02d}" for n in range(1, 11)]
    assert asi["ASI08"] == "Cascading Failures"
    layers = {entry.id for entry in index.entries.values() if entry.kind == "layer"}
    assert layers == {f"L{n}" for n in range(1, 8)}


def test_iso_catalog_records_its_copyright_limit():
    (iso,) = [catalog for catalog in load_mappings().catalogs if catalog.framework == "iso-iec-42001"]
    assert "Identifiers only; the standard's text is copyrighted." in iso.notes
    assert iso.verification == "secondary"


def test_extra_known_tags_are_emitted_by_the_scanner():
    sources = "\n".join(
        path.read_text(encoding="utf-8") for path in (ROOT / "shadowscan").rglob("*.py") if path.is_file()
    )
    for path in (builtin_mapping_dir() / "rules").glob("*.yaml"):
        extra = yaml.safe_load(path.read_text(encoding="utf-8")).get("extra_known_tags", [])
        for tag in extra:
            assert tag not in TAG_WEIGHTS
            assert f'"{tag}"' in sources or f"'{tag}'" in sources, (path.name, tag)


def test_describe_returns_catalog_details():
    entry = describe("owasp-llm-2026:LLM01")
    assert entry is not None
    assert (entry.title, entry.edition, entry.kind) == ("Prompt Injection", "2026", "threat")
    assert entry.framework_name == "OWASP Top 10 for LLM Applications"
    assert entry.url.startswith("https://")
    assert describe("owasp-llm-2026:LLM11") is None
    assert describe("OWASP-LLM-01") is None


# ------------------------------------------------- corrected earlier references


def test_exposed_inference_server_no_longer_maps_to_llm07(make_finding):
    threats = threat_references(make_finding(kind=Kind.INFRA, tags=["exposed-llm-server"]))
    assert not [ref for ref in threats if ref.endswith(":LLM07")]
    assert f"{ASI}ASI05" not in threats
    assert {f"{LLM}LLM06", f"{ATLAS}AML.T0040", f"{ATLAS}AML.T0132"} <= set(threats)


def test_unauthenticated_mcp_no_longer_maps_to_llm07_or_asi05(make_finding):
    threats = threat_references(make_finding(kind=Kind.MCP_SERVER, tags=["unauthenticated-mcp"]))
    assert not [ref for ref in threats if ref.endswith((":LLM07", ":ASI05"))]
    assert f"{ASI}ASI03" in threats


@pytest.mark.parametrize(
    "overrides",
    [
        {"tags": ["cluster-admin"]},
        {"tags": ["privileged-pod"]},
        {"tags": ["wildcard-permissions"]},
        {"tags": ["policy.privileged-scopes"]},
        {"capabilities": ["code-exec"]},
        {"capabilities": ["saas-actions"]},
    ],
)
def test_privilege_and_action_findings_no_longer_map_to_cascading_failures(make_finding, overrides):
    threats = threat_references(make_finding(kind=Kind.INFRA, **overrides))
    assert f"{ASI}ASI08" not in threats
    assert f"{LLM}LLM03" in threats


def test_credentials_map_to_disclosure_not_supply_chain(make_finding):
    threats = threat_references(make_finding(tags=["hardcoded-credential"]))
    assert {f"{LLM}LLM02", f"{ASI}ASI03"} <= set(threats)
    assert f"{ASI}ASI04" not in threats and f"{LLM}LLM04" not in threats


@pytest.mark.parametrize(
    "tags",
    [["managed-secret"], ["ci-credentials"], ["unrestricted-api-key"], []],
    ids=["managed-secret", "encrypted-ci-secret", "api-key", "untagged"],
)
def test_a_stored_credential_is_not_reported_as_exposed(make_finding, tags):
    # Secrets Manager, Secret Manager, OCI Vault and encrypted CI secrets are
    # secret findings too; only an exposure tag supports disclosure references.
    threats, controls = finding_references(make_finding(kind=Kind.SECRET, tags=tags))
    assert f"{LLM}LLM02" not in threats and f"{ATLAS}AML.T0055" not in threats
    assert {f"{ASI}ASI03", f"{MAESTRO}L6"} <= set(threats)
    assert f"{NIST}MEASURE-2.7" not in controls


@pytest.mark.parametrize(
    ("connector", "fixture"),
    [
        ("cloud.aws", "aws_records.jsonl"),
        ("cloud.gcp", "gcp_records.jsonl"),
        ("cloud.oci", "oci_records.jsonl"),
    ],
)
def test_managed_secret_store_findings_are_not_unsecured_credentials(
    run_connector, fixtures, connector, fixture
):
    findings, _ctx = run_connector(connector, input=str(fixtures / "cloud" / fixture))
    managed = [finding for finding in findings if "managed-secret" in finding.tags]
    assert managed, f"{fixture} no longer yields a managed-secret finding"
    for finding in managed:
        threats = finding.to_dict()["metadata"]["threats"]
        assert f"{LLM}LLM02" not in threats and f"{ATLAS}AML.T0055" not in threats, finding.resource
        assert f"{ASI}ASI03" in threats


@pytest.mark.parametrize("tag", ["hardcoded-credential", "unmasked-ci-variable"])
def test_an_exposed_secret_finding_keeps_its_disclosure_references(make_finding, tag):
    threats = threat_references(make_finding(kind=Kind.SECRET, tags=[tag, "ci-credentials"]))
    assert {f"{LLM}LLM02", f"{ASI}ASI03", f"{ATLAS}AML.T0055", f"{MAESTRO}L6"} <= set(threats)


@pytest.mark.parametrize("tag", CREDENTIAL_TAGS)
def test_every_credential_tag_is_a_disclosure_and_security_reference(make_finding, tag):
    threats, controls = finding_references(make_finding(kind=Kind.INFRA, tags=[tag]))
    assert {f"{LLM}LLM02", f"{ASI}ASI03", f"{ATLAS}AML.T0055"} <= set(threats)
    assert {f"{NIST}MEASURE-2.7", f"{EU}Art.15", f"{AIUC}B"} <= set(controls)


@pytest.mark.parametrize("tag", EXPOSURE_TAGS)
def test_every_exposure_tag_is_an_exposed_service_reference(make_finding, tag):
    threats, controls = finding_references(make_finding(kind=Kind.CLOUD_RESOURCE, tags=[tag]))
    assert f"{ATLAS}AML.T0132" in threats
    assert {f"{NIST}MEASURE-2.7", f"{EU}Art.15", f"{AIUC}B"} <= set(controls)


def test_capabilities_are_not_matched_as_tags(make_finding):
    # The earlier table looked for code-exec among tags, where no connector puts it.
    assert f"{ASI}ASI05" not in threat_references(make_finding(kind=Kind.INFRA, tags=["code-exec"]))


def test_credentials_in_agent_configuration_need_both_kind_and_tag(make_finding):
    assert f"{ATLAS}AML.T0083" not in threat_references(
        make_finding(kind=Kind.INFRA, tags=["inline-secrets"])
    )
    assert f"{ATLAS}AML.T0083" not in threat_references(make_finding(kind=Kind.MCP_SERVER))
    assert f"{ATLAS}AML.T0083" in threat_references(
        make_finding(kind=Kind.MCP_SERVER, tags=["inline-secrets"])
    )


# ------------------------------------------------ metadata read from other slices


@pytest.mark.parametrize(
    "metadata",
    [
        {"autonomy": None},
        {"autonomy": "L5"},
        {"autonomy": 5},
        {"autonomy": ["floor", 5]},
        {"autonomy": {"floor": "5"}},
        {"autonomy": {"floor": True}},
        {"autonomy": {"floor": 4.0}},
        {"autonomy": {"floor": 6}},
        {"autonomy": {"floor": -1}},
        {"autonomy": {"floor": None, "oversight": ["bypassed"]}},
        {"autonomy": {"oversight": 1}},
        {"autonomy": {"oversight": "BYPASSED"}},
        {"registry_reconciliation": None},
        {"registry_reconciliation": "observed-not-registered"},
        {"registry_reconciliation": ["observed-not-registered"]},
        {"registry_reconciliation": {"status": 3}},
        {"registry_reconciliation": {"status": ["observed-not-registered"]}},
        {"registry_reconciliation": {"status": "Observed-Not-Registered"}},
        {"declared_governance": None},
        {"declared_governance": "high"},
        {"declared_governance": {"eu_ai_act_risk_class": "high"}},
        {"declared_governance": {"eu_ai_act_risk_class": "High", "source": "card"}},
        {"declared_governance": {"eu_ai_act_risk_class": ["high"], "source": "card"}},
        {"declared_governance": {"eu_ai_act_risk_class": "high", "source": " "}},
        {"declared_governance": {"eu_ai_act_risk_class": "high", "source": "card", "score": 1}},
        {"declared_governance": {"eu_ai_act_risk_class": "high", "source": "card", "iso42001_scope": "yes"}},
    ],
)
def test_malformed_autonomy_and_registry_metadata_never_match(make_finding, metadata):
    finding = make_finding(kind=Kind.NETWORK_CONTACT, owner="team", shadow=False, metadata=metadata)
    assert finding_references(finding) == ([], [])
    exported = finding.to_dict()["metadata"]
    assert "threats" not in exported and "controls" not in exported


def test_autonomy_floor_thresholds(make_finding):
    def refs(floor: int) -> tuple[list[str], list[str]]:
        return finding_references(
            make_finding(kind=Kind.NETWORK_CONTACT, owner="t", metadata=_autonomy(floor))
        )

    assert refs(2) == ([], [])
    assert refs(3) == ([], [f"{ISO}A.6.2.6", f"{NIST}MANAGE-4.1"])
    threats, controls = refs(4)
    assert threats == [f"{ASI}ASI08", f"{LLM}LLM03"]
    assert {f"{EU}Art.14", f"{AIUC}D003", f"{NIST}MANAGE-4.1"} <= set(controls)


def test_unknown_shadow_status_and_present_owner_match_nothing(make_finding):
    unknown = make_finding(kind=Kind.WORKFLOW, owner="automation-team", shadow=None)
    assert control_references(unknown) == []
    registered = make_finding(kind=Kind.WORKFLOW, owner="automation-team", shadow=False)
    assert control_references(registered) == []


@pytest.mark.parametrize("owner", [None, "", "   "])
def test_blank_owner_counts_as_missing(make_finding, owner):
    assert f"{NIST}GOVERN-2.1" in control_references(make_finding(kind=Kind.WORKFLOW, owner=owner))


# --------------------------------------------------------------- finding export


def test_to_dict_writes_threats_and_controls_and_never_compliance(make_finding):
    finding = make_finding(kind=Kind.MCP_SERVER, tags=["tool-poisoning"], shadow=True, owner="team")
    metadata = finding.to_dict()["metadata"]
    assert metadata["threats"] == sorted(metadata["threats"])
    assert metadata["controls"] == [f"{AIUC}E", f"{ISO}A.4.2", f"{NIST}GOVERN-1.6"]
    assert f"{LLM}LLM01" in metadata["threats"] and f"{MAESTRO}L3" in metadata["threats"]
    assert "compliance" not in metadata
    # Derived only for the export; the finding itself is unchanged.
    assert not DERIVED_METADATA_KEYS & set(finding.metadata)


def test_derived_keys_supplied_by_a_connector_or_report_are_not_republished(make_finding):
    planted = {"threats": ["owasp-llm-2026:LLM10"], "controls": ["made-up:1"], "compliance": ["OWASP-LLM-01"]}
    finding = make_finding(kind=Kind.NETWORK_CONTACT, owner="team", metadata=dict(planted, keep="yes"))
    exported = finding.to_dict()["metadata"]
    assert exported == {"keep": "yes"}
    record = make_finding(kind=Kind.MCP_SERVER, tags=["tool-poisoning"], owner="team").to_dict()
    record["metadata"].update(planted)
    imported = Finding.from_dict(record)
    assert not DERIVED_METADATA_KEYS & set(imported.metadata)
    republished = imported.to_dict()["metadata"]
    assert "compliance" not in republished and "made-up:1" not in republished.get("controls", [])
    assert republished["threats"] == threat_references(imported)


def test_packaged_data_failure_stops_export(monkeypatch, tmp_path, make_finding):
    (tmp_path / "frameworks").mkdir()
    (tmp_path / "rules").mkdir()
    monkeypatch.setattr(mappings, "builtin_mapping_dir", lambda: tmp_path)
    load_mappings.cache_clear()
    try:
        with pytest.raises(MappingCatalogError):
            make_finding().to_dict()
    finally:
        monkeypatch.undo()
        load_mappings.cache_clear()
    assert load_mappings().rules


def _report(*findings: dict[str, Any]) -> dict[str, Any]:
    report = ScanResult(
        stats=[ScanStats(connector="code.filesystem", started_at="2026-01-01")],
        collection_scope={
            "schema": "shadowscan.collection-scope/v1",
            "comparable": True,
            "fingerprint": "a" * 64,
        },
    ).to_dict()
    report["findings"] = list(findings)
    report["summary"].update(
        total=len(findings),
        by_surface=dict(Counter(finding["surface"] for finding in findings)),
        by_kind=dict(Counter(finding["kind"] for finding in findings)),
    )
    return report


def test_mapping_only_differences_are_not_drift(make_finding):
    current = make_finding(kind=Kind.MCP_SERVER, tags=["tool-poisoning"], owner="team").to_dict()
    baseline = json.loads(json.dumps(current))
    # An earlier build's output, and a catalog that has since changed.
    del baseline["metadata"]["threats"]
    baseline["metadata"]["compliance"] = ["OWASP-LLM-01", "OWASP-ASI-01", "MITRE-ATLAS-AML.T0051"]
    baseline["metadata"]["controls"] = ["nist-ai-rmf-1.0:GOVERN-1.6"]
    result = compare_reports(_report(baseline), _report(current))
    assert result["comparable"] is True, result["reasons"]
    assert result["changed"] == [] and result["new"] == [] and result["resolved"] == []


# ------------------------------------------------------------------- reporters


def _references_finding(**overrides: Any) -> Finding:
    fields: dict[str, Any] = {
        "surface": Surface.CODE,
        "connector": "code.filesystem",
        "kind": Kind.MCP_SERVER,
        "title": "MCP configuration",
        "resource": "/repo/.mcp.json",
        "resource_type": "mcp-config",
        "frameworks": ["protocol.mcp"],
        "tags": ["tool-poisoning", "mcp-unpinned-package"],
    }
    fields.update(overrides)
    return Finding(**fields)


def _result(*findings: Finding) -> ScanResult:
    return ScanResult(
        findings=list(findings), stats=[ScanStats(connector="code.filesystem", started_at="2026-01-01")]
    )


def test_html_shows_threats_and_controls_with_titles_and_one_disclaimer():
    page = render(_result(_references_finding(shadow=True)), "html")
    assert "<b>Threats</b>" in page and "<b>Controls</b>" in page
    assert "<code>owasp-llm-2026:LLM01</code> Prompt Injection" in page
    assert "<code>nist-ai-rmf-1.0:GOVERN-1.6</code> Mechanisms exist to inventory AI systems" in page
    assert page.count("Evidence references, not compliance determinations.") == 1
    assert "Compliance</b>" not in page


def test_html_escapes_catalog_titles(monkeypatch):
    import shadowscan.reporters.html as html_reporter

    hostile = MappingEntry(
        ref="owasp-llm-2026:LLM01",
        id="LLM01",
        title="<img src=x onerror=alert(1)>",
        framework="owasp-llm",
        framework_name="x",
        edition="2026",
        kind="threat",
        url="https://example.invalid/",
        verification="primary",
    )
    monkeypatch.setattr(html_reporter, "describe", lambda ref: hostile)
    page = render(_result(_references_finding()), "html")
    assert "<img src=x" not in page
    assert "&lt;img src=x onerror=alert(1)&gt;" in page


def test_markdown_lists_references_in_details():
    text = render(_result(_references_finding()), "markdown")
    assert "- **Threats:** `maestro-2025:L3` Agent Frameworks; " in text
    assert "`owasp-llm-2026:LLM01` Prompt Injection" in text
    assert (
        "- **Controls:** `aiuc-1-2026q2:E` Accountability; `iso-iec-42001-2023:A.10.3` Managing AI suppliers; "
        in text
    )
    assert text.count("evidence references, not compliance determinations") == 1
    empty = render(_result(), "markdown")
    assert "compliance determinations" not in empty


def test_cyclonedx_carries_threat_and_control_properties():
    bom = json.loads(render(_result(_references_finding()), "cyclonedx"))
    entries = [*bom.get("components", []), *bom.get("services", [])]
    properties = {
        item["name"]: item["value"]
        for entry in entries
        if entry.get("bom-ref") == _references_finding().id
        for item in entry["properties"]
    }
    assert properties["shadowscan:threats"].split(", ") == threat_references(_references_finding())
    assert properties["shadowscan:controls"].split(", ") == control_references(_references_finding())


def _sarif(*findings: Finding) -> dict[str, Any]:
    return json.loads(render(_result(*findings), "sarif"))


def test_sarif_results_and_rules_carry_edition_qualified_references():
    finding = _references_finding()
    document = _sarif(finding)
    (rule,) = document["runs"][0]["tool"]["driver"]["rules"]
    (result,) = document["runs"][0]["results"]
    threats, controls = finding_references(finding)
    assert result["properties"]["threats"] == threats
    assert result["properties"]["controls"] == controls
    assert result["properties"]["tags"] == finding.tags
    assert rule["properties"]["shadowscan/threats"] == threats
    assert rule["properties"]["shadowscan/controls"] == controls
    assert rule["properties"]["tags"] == ["ai-agent", "code", "mcp-server", *threats, *controls]
    assert not [tag for tag in rule["properties"]["tags"] if tag.startswith(("OWASP-", "MITRE-"))]


def test_sarif_rule_references_are_a_capped_order_independent_union():
    many = _references_finding(
        tags=[
            "tool-poisoning",
            "unsafe-serialization",
            "hardcoded-credential",
            "cluster-admin",
            "privileged-pod",
            "exposed-llm-server",
            "unauthenticated-mcp",
            "mcp-broad-filesystem",
            "hidden-instructions",
            "no-invocation-logging",
        ],
        capabilities=["code-exec", "memory", "rag", "multi-agent"],
    )
    other = _references_finding(resource="/repo/other/.mcp.json", tags=["no-auth-declared"], shadow=True)
    first, second = _sarif(many, other), _sarif(other, many)
    rule = first["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule == second["runs"][0]["tool"]["driver"]["rules"][0]
    union = [set(), set()]
    for finding in (many, other):
        for index, refs in enumerate(finding_references(finding)):
            union[index].update(refs)
    assert rule["properties"]["shadowscan/threats"] == sorted(union[0])
    assert rule["properties"]["shadowscan/controls"] == sorted(union[1])
    tags = rule["properties"]["tags"]
    assert len(tags) == 20 < 3 + len(union[0]) + len(union[1])
    assert tags == ["ai-agent", "code", "mcp-server", *sorted(union[0])][:20]
    assert len(set(tags)) == len(tags)


def test_sarif_without_references_keeps_the_base_rule_tags(make_finding):
    finding = make_finding(kind=Kind.NETWORK_CONTACT, owner="team", surface=Surface.NETWORK)
    (rule,) = _sarif(finding)["runs"][0]["tool"]["driver"]["rules"]
    (result,) = _sarif(finding)["runs"][0]["results"]
    assert rule["properties"]["tags"] == ["ai-agent", "network", "network-contact"]
    assert "shadowscan/threats" not in rule["properties"] and "threats" not in result["properties"]


# ----------------------------------------------------------- validator failures


def _copy_data(tmp_path: Path) -> Path:
    root = tmp_path / "data"
    shutil.copytree(builtin_mapping_dir(), root)
    return root


def _edit(path: Path, change: Any) -> None:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    change(data)
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")


def _problems(root: Path) -> list[str]:
    with pytest.raises(MappingCatalogError) as info:
        MappingIndex.from_directory(root)
    return list(info.value.problems)


def _rule(data: dict[str, Any], rule_id: str) -> dict[str, Any]:
    (rule,) = [rule for rule in data["rules"] if rule["id"] == rule_id]
    return rule


def test_copied_packaged_data_loads(tmp_path):
    index = MappingIndex.from_directory(_copy_data(tmp_path))
    assert len(index.rules) == len(load_mappings().rules)


@pytest.mark.parametrize(
    ("file", "change", "problem"),
    [
        (
            "rules/threats.yaml",
            lambda d: _rule(d, "tool-poisoning")["refs"].append("owasp-llm-2026:LLM11"),
            "rule tool-poisoning: unknown reference owasp-llm-2026:LLM11",
        ),
        (
            "rules/threats.yaml",
            lambda d: _rule(d, "tool-poisoning")["refs"].append("OWASP-LLM-01"),
            "unknown reference OWASP-LLM-01",
        ),
        (
            "rules/threats.yaml",
            lambda d: _rule(d, "tool-poisoning")["refs"].append("nist-ai-rmf-1.0:GOVERN-1.6"),
            "reference nist-ai-rmf-1.0:GOVERN-1.6 is a control entry, not a threat entry",
        ),
        (
            "rules/controls.yaml",
            lambda d: _rule(d, "logging-gap")["refs"].append("maestro-2025:L5"),
            "reference maestro-2025:L5 is a layer entry, not a control entry",
        ),
        (
            "rules/threats.yaml",
            lambda d: _rule(d, "tool-poisoning")["when"]["tags_any"].append("tool-posioning"),
            "has unknown tags: tool-posioning",
        ),
        (
            "rules/threats.yaml",
            lambda d: _rule(d, "rag-capability")["when"].update(capabilities_any=["telepathy"]),
            "has unknown capabilities: telepathy",
        ),
        (
            "rules/layers.yaml",
            lambda d: _rule(d, "maestro-l1-local-model")["when"].update(kinds_any=["local_model"]),
            "has unknown kinds: local_model",
        ),
        (
            "rules/threats.yaml",
            lambda d: _rule(d, "tool-poisoning")["when"].update(surfaces_any=["mainframe"]),
            "has unknown surfaces: mainframe",
        ),
        (
            "rules/controls.yaml",
            lambda d: _rule(d, "oversight-bypassed")["when"].update(oversight_any=["skipped"]),
            "has unknown oversight values: skipped",
        ),
        (
            "rules/controls.yaml",
            lambda d: _rule(d, "registry-gap")["when"].update(registry_status_any=["unregistered"]),
            "has unknown registry statuses: unregistered",
        ),
        (
            "rules/controls.yaml",
            lambda d: _rule(d, "declared-high-risk")["when"].update(declared_risk_class_any=["High"]),
            "has unknown declared risk classes: High",
        ),
        (
            "frameworks/eu-ai-act.yaml",
            lambda d: d.update(review="independent"),
            "frameworks/eu-ai-act.yaml: review must be one of author",
        ),
        ("frameworks/eu-ai-act.yaml", lambda d: d.pop("review"), "missing keys: review"),
        (
            "rules/threats.yaml",
            lambda d: _rule(d, "tool-poisoning").update(when={}),
            "rule tool-poisoning: when must be a non-empty mapping",
        ),
        (
            "rules/threats.yaml",
            lambda d: d["rules"].append(dict(_rule(d, "tool-poisoning"))),
            "rule id tool-poisoning is also used in rules/threats.yaml",
        ),
        (
            "rules/controls.yaml",
            lambda d: _rule(d, "logging-gap").update(id="tool-poisoning"),
            "rules/controls.yaml: rule id tool-poisoning is also used in rules/threats.yaml",
        ),
        (
            "rules/threats.yaml",
            lambda d: _rule(d, "high-autonomy")["when"].update(autonomy_floor_at_least=6),
            "autonomy_floor_at_least must be an integer from 0 to 5",
        ),
        (
            "rules/threats.yaml",
            lambda d: _rule(d, "high-autonomy")["when"].update(autonomy_floor_at_least="4"),
            "autonomy_floor_at_least must be an integer from 0 to 5",
        ),
        (
            "rules/threats.yaml",
            lambda d: _rule(d, "high-autonomy")["when"].update(autonomy_floor_at_least=True),
            "autonomy_floor_at_least must be an integer from 0 to 5",
        ),
        (
            "rules/controls.yaml",
            lambda d: _rule(d, "shadow-ai-system")["when"].update(shadow="yes"),
            "shadow must be true or false",
        ),
        (
            "rules/threats.yaml",
            lambda d: _rule(d, "tool-poisoning")["when"].update(tag_any=["tool-poisoning"]),
            "when has unknown keys: tag_any",
        ),
        (
            "rules/threats.yaml",
            lambda d: _rule(d, "tool-poisoning").update(severity="high"),
            "has unknown keys: severity",
        ),
        ("rules/threats.yaml", lambda d: d.update(version=2), "rules/threats.yaml has unknown keys: version"),
        (
            "rules/threats.yaml",
            lambda d: d.update(extra_known_tags=["tool-poisoning"]),
            "extra_known_tags repeats weighted tags: tool-poisoning",
        ),
        (
            "rules/threats.yaml",
            lambda d: _rule(d, "tool-poisoning").pop("rationale"),
            "rule 1: missing keys: rationale",
        ),
        (
            "rules/threats.yaml",
            lambda d: _rule(d, "tool-poisoning").update(id="Tool_Poisoning"),
            "id must match",
        ),
        (
            "frameworks/owasp-llm.yaml",
            lambda d: d.update(publisher="OWASP"),
            "frameworks/owasp-llm.yaml has unknown keys: publisher",
        ),
        (
            "frameworks/owasp-llm.yaml",
            lambda d: d["entries"]["LLM01"].update(text="copied text"),
            "entry LLM01 has unknown keys: text",
        ),
        (
            "frameworks/owasp-llm.yaml",
            lambda d: d.update(prefix="owasp-llm"),
            "prefix must be '<framework>-<edition>'",
        ),
        (
            "frameworks/owasp-llm.yaml",
            lambda d: d.update(edition=2026),
            "frameworks/owasp-llm.yaml: edition must be a non-empty string",
        ),
        (
            "frameworks/owasp-llm.yaml",
            lambda d: d.update(source_url="http://example.org/"),
            "source_url must be an https:// URL",
        ),
        (
            "frameworks/owasp-llm.yaml",
            lambda d: d.update(checked="2026-02-30"),
            "checked must be a YYYY-MM-DD date string",
        ),
        (
            "frameworks/owasp-llm.yaml",
            lambda d: d.update(retrieved=d.pop("checked")),
            "frameworks/owasp-llm.yaml has unknown keys: retrieved",
        ),
        ("frameworks/owasp-llm.yaml", lambda d: d.update(kind="risk"), "kind must be one of"),
        (
            "frameworks/owasp-llm.yaml",
            lambda d: d.update(verification="vendor"),
            "verification must be one of",
        ),
        ("frameworks/owasp-llm.yaml", lambda d: d.pop("licence"), "missing keys: licence"),
        (
            "frameworks/owasp-llm.yaml",
            lambda d: d["entries"].update({"LLM 11": {"title": "x"}}),
            "entry LLM 11: id must match",
        ),
        (
            "frameworks/owasp-llm.yaml",
            lambda d: d["entries"]["LLM02"].update(title="two\nlines"),
            "title must be printable text on one line",
        ),
        (
            "frameworks/maestro.yaml",
            lambda d: d.update(prefix="owasp-llm-2026", framework="owasp-llm", edition="2026"),
            "prefix owasp-llm-2026 is also used by frameworks/",
        ),
        ("frameworks/owasp-llm.yaml", lambda d: d.update(framework="OWASP_LLM"), "framework must match"),
        ("frameworks/owasp-llm.yaml", lambda d: d.update(edition="2026 Q2"), "edition must be lowercase"),
        ("frameworks/owasp-llm.yaml", lambda d: d.update(entries=[]), "entries must be a non-empty mapping"),
        (
            "frameworks/owasp-llm.yaml",
            lambda d: d["entries"].update(LLM01="Prompt Injection"),
            "entry LLM01 must be a mapping with a title",
        ),
        ("frameworks/owasp-llm.yaml", lambda d: d.update(notes=5), "notes must be a non-empty string"),
        (
            "rules/threats.yaml",
            lambda d: _rule(d, "tool-poisoning")["when"].update(tags_any=[]),
            "when.tags_any must be a non-empty list",
        ),
        (
            "rules/threats.yaml",
            lambda d: _rule(d, "tool-poisoning")["when"].update(tags_any=[1]),
            "when.tags_any must list strings",
        ),
        (
            "rules/threats.yaml",
            lambda d: _rule(d, "tool-poisoning")["when"].update(
                tags_any=["tool-poisoning", "tool-poisoning"]
            ),
            "when.tags_any lists a value twice",
        ),
        (
            "rules/threats.yaml",
            lambda d: _rule(d, "tool-poisoning").update(refs="owasp-llm-2026:LLM01"),
            "refs must be a non-empty list of references",
        ),
        (
            "rules/threats.yaml",
            lambda d: _rule(d, "tool-poisoning")["refs"].append("owasp-llm-2026:LLM01"),
            "refs lists a reference twice",
        ),
    ],
)
def test_validator_rejects_invalid_data(tmp_path, file, change, problem):
    root = _copy_data(tmp_path)
    _edit(root / file, change)
    problems = _problems(root)
    assert any(problem in item for item in problems), problems


def test_validator_lists_every_problem(tmp_path):
    root = _copy_data(tmp_path)
    _edit(root / "rules/threats.yaml", lambda d: _rule(d, "tool-poisoning")["refs"].append("x:1"))
    _edit(root / "rules/controls.yaml", lambda d: _rule(d, "logging-gap")["refs"].append("y:2"))
    problems = _problems(root)
    assert any("unknown reference x:1" in item for item in problems)
    assert any("unknown reference y:2" in item for item in problems)


@pytest.mark.parametrize("target", ["frameworks/owasp-asi.yaml", "rules/layers.yaml"])
def test_validator_rejects_symlinked_files(tmp_path, target):
    root = _copy_data(tmp_path)
    real = tmp_path / "elsewhere.yaml"
    shutil.move(root / target, real)
    (root / target).symlink_to(real)
    problems = _problems(root)
    assert f"{target}: symbolic links are not followed" in problems
    if target.startswith("rules/"):
        assert f"{target}: missing" in problems


def test_validator_rejects_a_symlinked_directory(tmp_path):
    root = _copy_data(tmp_path)
    shutil.move(root / "frameworks", tmp_path / "frameworks")
    (root / "frameworks").symlink_to(tmp_path / "frameworks")
    assert any(item.startswith("frameworks: directory is missing") for item in _problems(root))


@pytest.mark.parametrize(
    ("name", "content", "problem"),
    [
        ("frameworks/notes.md", "notes\n", "frameworks/notes.md: only .yaml files are allowed"),
        ("frameworks/old.yml", "framework: x\n", "frameworks/old.yml: only .yaml files are allowed"),
        ("frameworks/nested/extra.yaml", "framework: x\n", "subdirectories are not allowed"),
        ("rules/extra.yaml", "rules: []\n", "rules/extra.yaml: unexpected rules file"),
        ("frameworks/broken.yaml", "framework: [unterminated\n", "frameworks/broken.yaml: invalid YAML"),
        (
            "frameworks/duplicate.yaml",
            "framework: a\nframework: b\n",
            "frameworks/duplicate.yaml: invalid YAML",
        ),
        ("frameworks/list.yaml", "- framework\n", "frameworks/list.yaml: a catalog must be a mapping"),
        ("rules/threats.yaml", "- rule\n", "rules/threats.yaml: a rules file must be a mapping"),
        ("rules/threats.yaml", "rules: []\n", "rules/threats.yaml: rules must be a non-empty list"),
        ("rules/threats.yaml", "rules: [x]\n", "rules/threats.yaml: rule 1 must be a mapping"),
        (
            "rules/threats.yaml",
            "extra_known_tags: tool-poisoning\nrules: [x]\n",
            "extra_known_tags must be a list of tag names",
        ),
    ],
)
def test_validator_rejects_unexpected_files(tmp_path, name, content, problem):
    root = _copy_data(tmp_path)
    path = root / name
    path.parent.mkdir(exist_ok=True)
    path.write_text(content, encoding="utf-8")
    problems = _problems(root)
    assert any(problem in item for item in problems), problems


def test_validator_rejects_unreadable_files(tmp_path):
    root = _copy_data(tmp_path)
    (root / "frameworks" / "latin1.yaml").write_bytes(b"name: caf\xe9\n")
    assert any(item.startswith("frameworks/latin1.yaml: cannot be read") for item in _problems(root))


def test_condition_reads_the_finding_surface(make_finding):
    from shadowscan.mappings.schema import Condition

    condition = Condition(surfaces_any=frozenset({"cloud"}))
    assert condition.matches(FindingFacts.of(make_finding(surface=Surface.CLOUD)))
    assert not condition.matches(FindingFacts.of(make_finding(surface=Surface.CODE)))


def test_validator_requires_every_rules_file(tmp_path):
    root = _copy_data(tmp_path)
    (root / "rules" / "controls.yaml").unlink()
    assert "rules/controls.yaml: missing" in _problems(root)


def test_validator_cli_reports_problems(monkeypatch, tmp_path, capsys):
    root = _copy_data(tmp_path)
    _edit(root / "rules/threats.yaml", lambda d: _rule(d, "tool-poisoning")["refs"].append("x:1"))
    monkeypatch.setattr(validate_module, "builtin_mapping_dir", lambda: root)
    assert validate_module.main([]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Mapping validation failed:" in captured.err
    assert "rules/threats.yaml: rule tool-poisoning: unknown reference x:1" in captured.err


def test_cyclonedx_fallback_ref_does_not_depend_on_the_catalog(monkeypatch):
    from shadowscan.reporters.cyclonedx import _finding_digest

    finding = _references_finding()
    before = _finding_digest(finding)
    monkeypatch.setattr(mappings, "finding_references", lambda f: (["x:1"], ["y:2"]))
    assert finding.to_dict()["metadata"]["threats"] == ["x:1"]
    assert _finding_digest(finding) == before
