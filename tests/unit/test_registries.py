"""Vendor registry record contract, reconciliation statuses and trusted-registry approvals."""

from __future__ import annotations

import fnmatch
import itertools
from typing import Any

import pytest

from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.registries import (
    MAX_BINDINGS,
    MAX_LINKS,
    RECONCILIATION_KEY,
    RECORD_KEY,
    RECORD_SCHEMA,
    REGISTRY_TYPES,
    RegistryBinding,
    TrustedApprovals,
    TrustedRegistry,
    parse_registry_record,
    prune_reconciliation_links,
    reconcile_registries,
    registry_evidence,
    registry_record,
    shown_registry_id,
)
from shadowscan.registry import Inventory, InventoryEntry, literal_resource_pattern
from shadowscan.utils.redaction import REDACTED

ACCOUNT = "123456789012"
OTHER_ACCOUNT = "210987654321"
REGION = "us-east-1"
RUNTIME = f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:runtime/agent-a1"
REGISTRY = "aws-agent-registry"
REGISTRY_ARN = f"arn:aws:agent-registry:{REGION}:{ACCOUNT}:registry/abcd1234abcd"
OTHER_REGISTRY_ARN = f"arn:aws:agent-registry:{REGION}:{ACCOUNT}:registry/ffff0000ffff"


def binding(**overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "resource": RUNTIME,
        "provider": "aws",
        "account": ACCOUNT,
        "region": REGION,
        "coverage": "in-scope",
    }
    value.update(overrides)
    return value


def record(**overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema": RECORD_SCHEMA,
        "registry": REGISTRY,
        "registry_id": REGISTRY_ARN,
        "record_id": "rec-1",
        "status": "approved",
        "descriptor_type": "agent",
        "bindings": [binding()],
        "publisher": "platform-team",
        "updated_at": "2026-09-01T00:00:00Z",
        "listing_complete": True,
        # A person approved it; other approval modes need allow_auto_approved.
        "approval_mode": "manual",
    }
    value.update(overrides)
    return value


def observed(**overrides: Any) -> Finding:
    fields: dict[str, Any] = {
        "surface": Surface.CLOUD,
        "connector": "test.observed",
        "kind": Kind.AGENT,
        "title": "AgentCore runtime agent-a1",
        "resource": RUNTIME,
        "resource_type": "agentcore-runtime",
        "provider": "aws",
        "account": ACCOUNT,
        "region": REGION,
        "evidence": [Evidence("cloud:agentcore-runtime", "runtime listed", weight=0.9)],
    }
    fields.update(overrides)
    return Finding(**fields)


_DEFAULT = object()


def record_finding(value: Any = _DEFAULT, record_id: str = "rec-1", **overrides: Any) -> Finding:
    registry_id = value.get("registry_id", REGISTRY_ARN) if isinstance(value, dict) else REGISTRY_ARN
    fields: dict[str, Any] = {
        "surface": Surface.CLOUD,
        "connector": "test.registry",
        "kind": Kind.AGENT,
        "title": f"Registry record {record_id}",
        "resource": f"{registry_id or REGISTRY_ARN}/record/{record_id}",
        "resource_type": "agent-registry-record",
        "provider": "aws",
        "account": ACCOUNT,
        "region": REGION,
        "evidence": [registry_evidence(REGISTRY, "listed in the agent registry")],
        "metadata": {RECORD_KEY: record(record_id=record_id) if value is _DEFAULT else value},
    }
    fields.update(overrides)
    return Finding(**fields)


def status(finding: Finding) -> str | None:
    block = finding.metadata.get(RECONCILIATION_KEY)
    return block["status"] if isinstance(block, dict) else None


# ------------------------------------------------------------------ contract


def test_a_valid_record_parses_into_the_contract():
    parsed = parse_registry_record(record())
    assert parsed is not None
    assert (parsed.registry, parsed.registry_id, parsed.record_id) == (REGISTRY, REGISTRY_ARN, "rec-1")
    assert (parsed.status, parsed.descriptor_type, parsed.publisher) == ("approved", "agent", "platform-team")
    assert parsed.listing_complete is True and parsed.identified
    assert parsed.agent_id == "aws-agent-registry:rec-1"
    assert parsed.bindings == (RegistryBinding(RUNTIME, "aws", ACCOUNT, REGION, "in-scope"),)
    assert parsed.bindings[0].usable


def test_optional_fields_default_to_the_fail_closed_values():
    minimal = {key: record()[key] for key in ("schema", "registry", "registry_id", "record_id")}
    minimal |= {"status": "pending", "descriptor_type": "mcp"}
    parsed = parse_registry_record(minimal)
    assert parsed is not None
    assert parsed.bindings == () and parsed.listing_complete is False
    assert parsed.publisher is None and parsed.updated_at is None
    lone = parse_registry_record(record(bindings=[{"resource": RUNTIME}]))
    assert lone is not None and lone.bindings == (RegistryBinding(RUNTIME),)
    assert lone.bindings[0].coverage == "unknown"


@pytest.mark.parametrize("registry", REGISTRY_TYPES)
def test_every_registry_type_is_accepted(registry):
    parsed = parse_registry_record(record(registry=registry))
    assert parsed is not None and parsed.registry == registry


@pytest.mark.parametrize(
    "value",
    [
        None,
        "record",
        [record()],
        {key: value for key, value in record().items() if key != "status"},
        {**record(), "display_name": "extra fields are not part of the contract"},
        record(schema="shadowscan.registry-record/v2"),
        record(registry="aws"),
        record(registry="AWS-AGENT-REGISTRY"),
        record(status="APPROVED"),
        record(status="active"),
        record(descriptor_type="server"),
        record(registry_id=None),
        record(registry_id=123),
        record(registry_id="x" * 2049),
        record(record_id=""),
        record(record_id="   "),
        record(record_id=7),
        record(bindings="arn"),
        record(bindings={"resource": RUNTIME}),
        record(bindings=[binding()] * (MAX_BINDINGS + 1)),
        record(bindings=[RUNTIME]),
        record(bindings=[{"provider": "aws"}]),
        record(bindings=[binding(resource=None)]),
        record(bindings=[binding(resource=["a"])]),
        record(bindings=[binding(provider=1)]),
        record(bindings=[binding(account=123456789012)]),
        record(bindings=[binding(region=True)]),
        record(bindings=[binding(coverage="full")]),
        record(bindings=[{**binding(), "service": "agentcore"}]),
        record(listing_complete="true"),
        record(listing_complete=1),
        record(listing_complete=None),
        record(publisher=["team"]),
        record(updated_at=20260901),
    ],
)
def test_malformed_records_are_rejected(value):
    assert parse_registry_record(value) is None
    assert registry_record(record_finding(value)) is None


def test_the_binding_cap_is_inclusive():
    parsed = parse_registry_record(record(bindings=[binding()] * MAX_BINDINGS))
    assert parsed is not None and len(parsed.bindings) == MAX_BINDINGS


@pytest.mark.parametrize(
    "changed",
    [
        {"resource": ""},
        {"resource": f"{RUNTIME}/{REDACTED}"},
        {"resource": f" {RUNTIME}"},
        {"provider": ""},
        {"account": REDACTED},
        {"region": "us-east-1 "},
    ],
)
def test_empty_padded_or_redacted_bindings_are_valid_but_unusable(changed):
    parsed = parse_registry_record(record(bindings=[binding(**changed)]))
    assert parsed is not None and not parsed.bindings[0].usable


@pytest.mark.parametrize("registry_id", ["", REDACTED, f" {REGISTRY_ARN}"])
def test_a_record_without_an_exact_registry_identity_parses_but_is_unidentified(registry_id):
    parsed = parse_registry_record(record(registry_id=registry_id))
    assert parsed is not None and not parsed.identified


def test_a_blank_publisher_is_absent():
    parsed = parse_registry_record(record(publisher="  "))
    assert parsed is not None and parsed.publisher is None


def test_a_finding_without_the_key_has_no_record():
    assert registry_record(observed()) is None


def test_registry_evidence_is_a_grouped_declaration():
    evidence = registry_evidence(REGISTRY, "listed", location=REGISTRY_ARN)
    assert evidence.signal == "registry:aws-agent-registry" and evidence.weight == 0.5
    assert (
        evidence.attributes == {"confidence_group": "registry-record"} and evidence.location == REGISTRY_ARN
    )
    finding = record_finding()
    finding.add_evidence(registry_evidence("mcp-registry", "also listed"))
    finding.recompute_confidence()
    # Two declarations are one group: a second registry listing never adds confidence.
    assert finding.confidence == 0.5
    with pytest.raises(ValueError, match="unknown registry type"):
        registry_evidence("aws", "listed")


# ------------------------------------------------------------ reconciliation


def test_an_exact_binding_match_is_registered_and_observed_on_both_sides():
    agent, rec = observed(), record_finding()
    assert reconcile_registries([agent, rec]) == []
    assert rec.metadata[RECONCILIATION_KEY] == {"status": "registered-and-observed", "observed": [agent.id]}
    assert agent.metadata[RECONCILIATION_KEY] == {
        "status": "registered-and-observed",
        "records": [rec.id],
        "registries": [{"registry": REGISTRY, "registry_id": REGISTRY_ARN}],
    }


def test_an_unmatched_in_scope_binding_is_registered_not_observed():
    rec = record_finding()
    reconcile_registries([observed(resource=f"{RUNTIME}-other"), rec])
    assert rec.metadata[RECONCILIATION_KEY] == {"status": "registered-not-observed", "observed": []}


@pytest.mark.parametrize("coverage", ["out-of-scope", "unknown"])
def test_an_unmatched_binding_outside_collected_scope_is_not_comparable(coverage):
    rec = record_finding(record(bindings=[binding(coverage=coverage)]))
    reconcile_registries([rec])
    assert rec.metadata[RECONCILIATION_KEY] == {
        "status": "not-comparable",
        "observed": [],
        "reason": "binding-not-in-scope",
    }


def test_one_out_of_scope_binding_keeps_an_unmatched_record_not_comparable():
    rec = record_finding(record(bindings=[binding(), binding(resource="other", coverage="out-of-scope")]))
    reconcile_registries([rec])
    assert status(rec) == "not-comparable"


@pytest.mark.parametrize("bindings", [[], [binding(resource=f"{RUNTIME}{REDACTED}")]])
def test_a_record_without_usable_bindings_is_not_comparable(bindings):
    rec = record_finding(record(bindings=bindings))
    agent = observed()
    reconcile_registries([agent, rec])
    assert rec.metadata[RECONCILIATION_KEY]["reason"] == "no-usable-binding"
    assert status(rec) == "not-comparable"
    # The listing is complete, but nothing binds the registry to a provider and account.
    assert RECONCILIATION_KEY not in agent.metadata


@pytest.mark.parametrize(
    "changed",
    [{"provider": "gcp"}, {"account": OTHER_ACCOUNT}, {"region": "eu-west-1"}, {"resource": RUNTIME.upper()}],
)
def test_scope_and_case_mismatches_never_match(changed):
    rec = record_finding(record(bindings=[binding(**changed)]))
    agent = observed()
    reconcile_registries([agent, rec])
    assert status(rec) == "registered-not-observed"
    assert status(agent) != "registered-and-observed"


def test_an_unset_binding_scope_matches_any_value():
    rec = record_finding(record(bindings=[binding(provider=None, account=None, region=None)]))
    agent = observed()
    reconcile_registries([agent, rec])
    assert status(rec) == status(agent) == "registered-and-observed"


def test_multiple_registries_are_listed_on_the_observed_finding():
    first = record_finding()
    second = record_finding(record(registry="aws-agentcore-registry", registry_id=OTHER_REGISTRY_ARN))
    agent = observed()
    reconcile_registries([second, agent, first])
    block = agent.metadata[RECONCILIATION_KEY]
    assert block["records"] == sorted([first.id, second.id])
    assert block["registries"] == [
        {"registry": "aws-agent-registry", "registry_id": REGISTRY_ARN},
        {"registry": "aws-agentcore-registry", "registry_id": OTHER_REGISTRY_ARN},
    ]


def test_observed_not_registered_requires_a_complete_listing():
    unregistered = observed(resource=f"{RUNTIME}-shadow", title="unregistered runtime")
    complete = record_finding()
    reconcile_registries([unregistered, observed(), complete])
    assert unregistered.metadata[RECONCILIATION_KEY] == {
        "status": "observed-not-registered",
        "registries": [{"registry": REGISTRY, "registry_id": REGISTRY_ARN}],
    }
    partial = record_finding(record(listing_complete=False))
    reconcile_registries([unregistered, observed(), partial])
    assert RECONCILIATION_KEY not in unregistered.metadata


def test_one_incomplete_record_withholds_absence_for_its_whole_registry():
    unregistered = observed(resource=f"{RUNTIME}-shadow")
    records = [record_finding(), record_finding(record(record_id="rec-2", listing_complete=False), "rec-2")]
    reconcile_registries([unregistered, *records])
    assert RECONCILIATION_KEY not in unregistered.metadata


def test_registered_in_one_registry_wins_over_absence_from_another():
    agent = observed()
    other = record_finding(
        record(registry_id=OTHER_REGISTRY_ARN, bindings=[binding(resource=f"{RUNTIME}-elsewhere")])
    )
    reconcile_registries([agent, other, record_finding()])
    assert status(agent) == "registered-and-observed"
    reconcile_registries([agent, other])
    assert status(agent) == "observed-not-registered"


@pytest.mark.parametrize(
    "changed",
    [
        {"kind": Kind.SERVICE_IDENTITY},
        {"kind": Kind.CLOUD_RESOURCE},
        {
            "account": OTHER_ACCOUNT,
            "resource": f"arn:aws:bedrock-agentcore:{REGION}:{OTHER_ACCOUNT}:runtime/x",
        },
        {"provider": "gcp"},
        {"account": None},
        {"resource": f"{RUNTIME}/{REDACTED}"},
        {"metadata": {"identity_unresolved": True}},
    ],
)
def test_absence_is_claimed_only_for_agentic_kinds_with_an_exact_identity_in_scope(changed):
    unregistered = observed(**{"resource": f"{RUNTIME}-shadow", **changed})
    reconcile_registries([unregistered, record_finding()])
    assert RECONCILIATION_KEY not in unregistered.metadata


@pytest.mark.parametrize("kind", [Kind.WORKFLOW, Kind.BOT_APP, Kind.MCP_SERVER])
def test_absence_covers_workflows_bots_and_mcp_servers(kind):
    unregistered = observed(resource=f"{RUNTIME}-shadow", kind=kind)
    reconcile_registries([unregistered, record_finding()])
    assert status(unregistered) == "observed-not-registered"


@pytest.mark.parametrize("record_status", ["draft", "rejected", "deprecated", "blocked", "unknown"])
def test_a_record_that_is_not_a_registration_never_registers_what_it_binds(record_status):
    # Regression: a REJECTED, DEPRECATED or DRAFT record bound to a running runtime made it
    # registered-and-observed, which hid observed-not-registered and the registry-gap rule.
    agent, rec = observed(), record_finding(record(status=record_status))
    assert reconcile_registries([agent, rec]) == []
    assert rec.metadata[RECONCILIATION_KEY] == {
        "status": "not-comparable",
        "observed": [],
        "reason": "record-status",
    }
    # The record still shows the registry's complete listing covers the account.
    assert agent.metadata[RECONCILIATION_KEY] == {
        "status": "observed-not-registered",
        "registries": [{"registry": REGISTRY, "registry_id": REGISTRY_ARN}],
    }


@pytest.mark.parametrize("record_status", ["approved", "registered", "pending"])
def test_approved_registered_and_pending_records_register_what_they_bind(record_status):
    agent, rec = observed(), record_finding(record(status=record_status))
    reconcile_registries([agent, rec])
    assert status(agent) == status(rec) == "registered-and-observed"


def test_a_rejected_record_beside_an_approved_one_keeps_only_the_approved_registration():
    agent = observed()
    rejected = record_finding(record(record_id="rec-2", status="rejected"), "rec-2")
    approved = record_finding()
    reconcile_registries([agent, rejected, approved])
    assert agent.metadata[RECONCILIATION_KEY]["records"] == [approved.id]


def test_absence_is_claimed_only_for_resource_types_the_registry_can_bind():
    # Regression: an AWS registry binds AgentCore runtimes and gateways only, yet a Bedrock agent
    # in an account with one bound runtime was reported observed-not-registered.
    bedrock = observed(
        resource=f"arn:aws:bedrock:{REGION}:{ACCOUNT}:agent/AGENTX", resource_type="bedrock-agent"
    )
    gateway = observed(
        resource=f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:gateway/tools",
        resource_type="agentcore-gateway",
        kind=Kind.MCP_SERVER,
    )
    for registry in ("aws-agent-registry", "aws-agentcore-registry"):
        reconcile_registries([bedrock, gateway, observed(), record_finding(record(registry=registry))])
        assert RECONCILIATION_KEY not in bedrock.metadata
        assert status(gateway) == "observed-not-registered"
    # A registry type without declared bindable types keeps the provider and account scope.
    reconcile_registries([bedrock, observed(), record_finding(record(registry="mcp-registry"))])
    assert status(bedrock) == "observed-not-registered"


def test_an_unidentified_registry_never_defines_a_scope():
    unregistered = observed(resource=f"{RUNTIME}-shadow")
    anonymous = record_finding(record(registry_id=""))
    reconcile_registries([unregistered, anonymous])
    assert RECONCILIATION_KEY not in unregistered.metadata


def test_reconciliation_is_recomputed_and_never_trusted_from_input():
    agent = observed(metadata={RECONCILIATION_KEY: {"status": "registered-and-observed", "records": ["x"]}})
    reconcile_registries([agent])
    assert RECONCILIATION_KEY not in agent.metadata
    rec = record_finding()
    reconcile_registries([agent, rec])
    first = (dict(agent.metadata[RECONCILIATION_KEY]), dict(rec.metadata[RECONCILIATION_KEY]))
    reconcile_registries([agent, rec])
    assert (agent.metadata[RECONCILIATION_KEY], rec.metadata[RECONCILIATION_KEY]) == first


def test_malformed_records_are_counted_and_never_observed():
    broken = record_finding(record(status="live"), resource=RUNTIME)
    agent = observed(resource=f"{RUNTIME}-shadow")
    assert reconcile_registries([broken, agent, record_finding(record(registry="x"))]) == [
        "malformed registry record metadata on 2 finding(s)"
    ]
    assert RECONCILIATION_KEY not in broken.metadata and RECONCILIATION_KEY not in agent.metadata


def test_link_lists_are_capped():
    agents = [observed(resource_type=f"agentcore-runtime-{number}") for number in range(MAX_LINKS + 5)]
    rec = record_finding()
    reconcile_registries([*agents, rec])
    assert len(rec.metadata[RECONCILIATION_KEY]["observed"]) == MAX_LINKS


def test_pruning_drops_links_to_omitted_findings_and_keeps_statuses():
    agent, rec = observed(), record_finding()
    reconcile_registries([agent, rec])
    prune_reconciliation_links([agent])
    assert agent.metadata[RECONCILIATION_KEY]["records"] == []
    assert status(agent) == "registered-and-observed"
    malformed = observed(resource=f"{RUNTIME}-other", metadata={RECONCILIATION_KEY: "not a mapping"})
    prune_reconciliation_links([malformed, rec])
    assert rec.metadata[RECONCILIATION_KEY]["observed"] == []


# ---------------------------------------------------------- trusted approvals


TRUSTED = [TrustedRegistry(REGISTRY, REGISTRY_ARN)]


def test_an_approved_record_of_a_trusted_registry_approves_itself_and_its_exact_binding():
    rec, agent = record_finding(), observed()
    approvals = TrustedApprovals([rec, agent], TRUSTED)
    assert approvals.entries == 1 and approvals.warnings() == []
    assert approvals.approve_record(rec) and not approvals.approve_record(agent)
    assert (rec.shadow, rec.registry_match, rec.owner) == (False, "aws-agent-registry:rec-1", "platform-team")
    entry = Inventory().match(agent, approvals.candidates(agent))
    assert entry is not None and entry.agent_id == "aws-agent-registry:rec-1"
    assert entry.owner == "platform-team" and entry.source == f"trusted-registry:{REGISTRY_ARN}"
    assert (entry.providers, entry.accounts, entry.regions) == (["aws"], [ACCOUNT], [REGION])
    assert entry.names == [] and entry.resources == [RUNTIME]


def test_a_record_approval_keeps_an_owner_the_finding_already_has():
    rec = record_finding(owner="observed-owner")
    TrustedApprovals([rec], TRUSTED).approve_record(rec)
    assert rec.owner == "observed-owner"


@pytest.mark.parametrize(
    "record_status", ["pending", "draft", "rejected", "deprecated", "blocked", "unknown"]
)
def test_records_that_are_not_approved_never_approve(record_status):
    rec, agent = record_finding(record(status=record_status)), observed()
    approvals = TrustedApprovals([rec, agent], TRUSTED)
    assert approvals.entries == 0 and approvals.warnings() == []
    assert not approvals.approve_record(rec) and approvals.candidates(agent) == []


@pytest.mark.parametrize(
    "trusted",
    [
        [],
        [TrustedRegistry(REGISTRY, OTHER_REGISTRY_ARN)],
        [TrustedRegistry("aws-agentcore-registry", REGISTRY_ARN)],
    ],
)
def test_approval_in_an_untrusted_registry_never_approves(trusted):
    rec, agent = record_finding(), observed()
    approvals = TrustedApprovals([rec, agent], trusted)
    assert not approvals.approve_record(rec) and approvals.candidates(agent) == []
    assert rec.shadow is None and approvals.entries == 0


def test_a_record_with_an_unusable_identity_never_approves():
    redacted = record_finding(record(record_id=f"rec-{REDACTED}"))
    assert not TrustedApprovals([redacted], TRUSTED).approve_record(redacted)


def test_unusable_and_duplicate_bindings_add_no_entries():
    rec = record_finding(
        record(bindings=[binding(), binding(), binding(resource=REDACTED), binding(region=" ")])
    )
    assert TrustedApprovals([rec], TRUSTED).entries == 1


def test_wildcards_in_a_binding_resource_are_literal():
    rec = record_finding(
        record(bindings=[binding(resource="agent-*", provider=None, account=None, region=None)])
    )
    lookalike = observed(resource="agent-x", provider=None, account=None, region=None)
    literal = observed(resource="agent-*", provider=None, account=None, region=None)
    approvals = TrustedApprovals([rec, lookalike, literal], TRUSTED)
    inventory = Inventory()
    assert inventory.match(lookalike, approvals.candidates(lookalike)) is None
    # Even offered directly, the escaped pattern cannot approve another resource.
    assert inventory.match(lookalike, approvals.candidates(literal)) is None
    entry = inventory.match(literal, approvals.candidates(literal))
    assert entry is not None and entry.resources == ["agent-[*]"]


def test_a_binding_scope_is_enforced_by_inventory_matching():
    rec = record_finding(record(bindings=[binding(region="eu-west-1")]))
    agent = observed()
    approvals = TrustedApprovals([rec, agent], TRUSTED)
    assert Inventory().match(agent, approvals.candidates(agent)) is None


def test_an_approval_in_two_places_is_ambiguous():
    rec, agent = record_finding(), observed()
    approvals = TrustedApprovals([rec, agent], TRUSTED)
    card = InventoryEntry(agent_id="card", resources=[RUNTIME])
    assert Inventory([card]).match(agent, approvals.candidates(agent)) is None
    assert agent.metadata["registry_match_reason"] == "ambiguous-resource-approval"
    assert agent.metadata["registry_suggestions"] == ["aws-agent-registry:rec-1", "card"]


def test_bindings_of_one_record_that_cover_a_finding_are_one_approval():
    # Regression: a record binding one resource with and without a region was ambiguous with
    # itself, left its own agent shadow and counted twice in the inventory size.
    rec = record_finding(record(bindings=[binding(), binding(region=None), binding(account=None)]))
    agent = observed()
    approvals = TrustedApprovals([rec, agent], TRUSTED)
    assert approvals.entries == 1
    entry = Inventory().match(agent, approvals.candidates(agent))
    assert entry is not None and entry.agent_id == "aws-agent-registry:rec-1"
    assert "registry_match_reason" not in agent.metadata
    # The same record emitted twice (two connector entries, say) is still one approval.
    again = record_finding(record(bindings=[binding(region=None)]))
    approvals = TrustedApprovals([rec, again, agent], TRUSTED)
    assert approvals.entries == 1
    assert Inventory().match(agent, approvals.candidates(agent)) is not None


def test_two_records_or_two_registries_binding_one_finding_stay_ambiguous():
    agent = observed()
    two_records = TrustedApprovals([record_finding(), record_finding(record_id="rec-2")], TRUSTED)
    assert two_records.entries == 2
    assert Inventory().match(agent, two_records.candidates(agent)) is None
    assert agent.metadata["registry_suggestions"] == ["aws-agent-registry:rec-1", "aws-agent-registry:rec-2"]
    other = record_finding(record(registry_id=OTHER_REGISTRY_ARN))
    two_registries = TrustedApprovals(
        [record_finding(), other], [*TRUSTED, TrustedRegistry(REGISTRY, OTHER_REGISTRY_ARN)]
    )
    assert two_registries.entries == 2
    assert Inventory().match(agent, two_registries.candidates(agent)) is None
    assert agent.metadata["registry_match_reason"] == "ambiguous-resource-approval"


def test_a_trusted_registry_without_records_is_reported_by_a_short_sanitized_id():
    approvals = TrustedApprovals([observed()], [*TRUSTED, TrustedRegistry("microsoft-agent-365", "tenant")])
    assert approvals.warnings() == [
        f"trusted registry aws-agent-registry ...{REGISTRY_ARN[-16:]} produced no records; "
        "its approvals were not applied",
        "trusted registry microsoft-agent-365 tenant produced no records; its approvals were not applied",
    ]
    assert shown_registry_id(REGISTRY_ARN) == "...try/abcd1234abcd"
    # A pending record still shows the registry was read.
    assert TrustedApprovals([record_finding(record(status="pending"))], TRUSTED).warnings() == []


def test_literal_resource_patterns_match_only_their_resource():
    # Every string of up to three glob-significant characters, against every other one.
    strings = ["".join(chars) for size in range(4) for chars in itertools.product("a*?[]!\\", repeat=size)]
    for resource in strings:
        pattern = literal_resource_pattern(resource)
        assert [other for other in strings if fnmatch.fnmatchcase(other, pattern)] == [resource]
