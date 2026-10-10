"""Vendor agent registries: the record contract, reconciliation and trusted approvals.

A connector that reads a vendor registry (an AWS Agent Registry, Microsoft Agent 365, a Google
Agent Registry, ...) emits one finding per registry record. The finding carries
``metadata["registry_record"]`` with schema ``shadowscan.registry-record/v1``::

    {"schema": "shadowscan.registry-record/v1",
     "registry": "aws-agent-registry",            # registry type: one of REGISTRY_TYPES
     "registry_id": "arn:aws:...:registry/abcd",   # exact identity of this registry ("" if unknown)
     "record_id": "rec-123",
     "status": "approved",                         # one of RECORD_STATUSES
     "descriptor_type": "agent",                   # one of DESCRIPTOR_TYPES
     "bindings": [{"resource": "<exact finding.resource of the deployed object>",
                   "provider": "aws", "account": "123456789012", "region": "us-east-1",
                   "coverage": "in-scope"}],       # in-scope, out-of-scope or unknown
     "publisher": "platform-team",                 # optional
     "updated_at": "2026-09-01T00:00:00Z",         # optional
     "listing_complete": true,                     # optional, default false
     "approval_mode": "manual",                    # optional: auto, manual, none or unknown (default)
     "listing_scope": "registry"}                  # optional: registry (default) or caller

The emitting connector normalizes vendor statuses into :data:`RECORD_STATUSES` (an unknown one
becomes ``unknown``) and sets a binding's ``coverage`` to ``in-scope`` only when it collected that
resource type for the binding's account and region in the same run. ``listing_complete`` is true
only when the full record listing of that registry finished without truncation or denial; a
``caller``-scoped listing (one that shows only what the caller can see) is never complete.
``approval_mode`` says how the registry approves records: ``auto`` when it approves every record
without a person, ``manual`` when a person does, ``none`` when it has no approval workflow (its
records are ``registered``, never ``approved``).
Evidence for a record finding comes from :func:`registry_evidence`: a declaration, not proof that
the agent runs.

Only a built-in connector class that declares ``emits_registry_records`` (a ``BaseConnector``
engine hook) may carry the key, and only for the registry types it lists in
``registry_record_types``. The engine drops it from every other connector's findings,
including a plugin's that declares the hook: an approved record of a trusted registry approves
findings, so a record copied from an untrusted export or repository, or emitted by third-party
code, must never reach reconciliation.

The engine then, keyed only on this metadata:

* reconciles records with observed findings (:func:`reconcile_registries`), writing
  ``metadata["registry_reconciliation"]``; and
* for registries the operator lists in ``options.trusted_registries`` (exact registry identity,
  never by type), turns approved records into exact-resource inventory approvals for that run
  (:class:`TrustedApprovals`). Nothing is cached: a revoked approval stops applying on the next
  scan.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from shadowscan.models import Evidence, Finding, Kind
from shadowscan.registry import InventoryEntry, clear_match_state, literal_resource_pattern
from shadowscan.utils.redaction import REDACTED, sanitize_text

RECORD_SCHEMA = "shadowscan.registry-record/v1"
RECORD_KEY = "registry_record"
RECONCILIATION_KEY = "registry_reconciliation"
REGISTRY_TYPES = (
    "aws-agent-registry",
    "aws-agentcore-registry",
    "microsoft-agent-365",
    "entra-agent-registry",
    "google-agent-registry",
    "gemini-enterprise",
    "mcp-registry",
    "a2a-card",
)
RECORD_STATUSES = (
    "approved",
    "registered",
    "pending",
    "draft",
    "rejected",
    "deprecated",
    "blocked",
    "unknown",
)
# Statuses under which a record registers what it binds: the registry lists the agent as
# approved, registered or awaiting approval. A draft, rejected, deprecated, blocked or unknown
# record is not a registration, so it never makes an observed finding registered.
REGISTERING_STATUSES = frozenset({"approved", "registered", "pending"})
APPROVAL_MODES = ("auto", "manual", "none", "unknown")
LISTING_SCOPES = ("registry", "caller")
# Records of a deprecated source never approve, so the source cannot be trusted.
UNTRUSTABLE_REGISTRY_TYPES = frozenset({"entra-agent-registry"})
# The resource types of the observed findings a registry type's records can bind. A registry
# can list only these, so only these are reported absent from it (``observed-not-registered``):
# an AWS registry binds AgentCore runtimes and gateways, never a Bedrock agent in the same
# account. A registry type without an entry may bind any reconciled kind.
BINDABLE_RESOURCE_TYPES: dict[str, frozenset[str]] = {
    "aws-agent-registry": frozenset({"agentcore-runtime", "agentcore-gateway"}),
    "aws-agentcore-registry": frozenset({"agentcore-runtime", "agentcore-gateway"}),
}
DESCRIPTOR_TYPES = ("agent", "mcp", "a2a", "custom", "agent-skills", "package")
COVERAGE_VALUES = ("in-scope", "out-of-scope", "unknown")
RECONCILIATION_STATUSES = (
    "registered-and-observed",
    "registered-not-observed",
    "observed-not-registered",
    "not-comparable",
)
# Kinds an operator expects a registry to list. Credentials, grants and infrastructure are not
# registered on their own, so their absence from a registry says nothing.
RECONCILED_KINDS = frozenset({Kind.AGENT, Kind.WORKFLOW, Kind.BOT_APP, Kind.MCP_SERVER})
MAX_BINDINGS = 64
MAX_IDENTIFIER_LENGTH = 2048
MAX_TRUSTED_REGISTRIES = 64
# Finding ids and registries listed in one reconciliation block.
MAX_LINKS = 50
EVIDENCE_GROUP = "registry-record"
EVIDENCE_WEIGHT = 0.5
TRUSTED_SOURCE_PREFIX = "trusted-registry:"

_REQUIRED_FIELDS = frozenset({"schema", "registry", "registry_id", "record_id", "status", "descriptor_type"})
_RECORD_FIELDS = _REQUIRED_FIELDS | {
    "bindings",
    "publisher",
    "updated_at",
    "listing_complete",
    "approval_mode",
    "listing_scope",
}
_BINDING_FIELDS = frozenset({"resource", "provider", "account", "region", "coverage"})
_SHOWN_ID_SUFFIX = 16


def _usable(value: Any) -> bool:
    """An exact identity: a nonempty unpadded string that redaction did not change."""
    return isinstance(value, str) and bool(value) and value == value.strip() and REDACTED not in value


def _bounded(value: Any) -> bool:
    return isinstance(value, str) and len(value) <= MAX_IDENTIFIER_LENGTH


@dataclass(frozen=True, slots=True)
class RegistryBinding:
    """A record's claim that it describes one deployed object, by that object's exact finding resource."""

    resource: str
    provider: str | None = None
    account: str | None = None
    region: str | None = None
    coverage: str = "unknown"

    @property
    def usable(self) -> bool:
        """Whether the binding names an exact identity: no empty, padded or redacted value."""
        return _usable(self.resource) and all(
            value is None or _usable(value) for value in (self.provider, self.account, self.region)
        )

    def matches(self, finding: Finding) -> bool:
        """Exact resource equality, and equal provider, account and region where the binding sets them."""
        return (
            finding.resource == self.resource
            and (self.provider is None or finding.provider == self.provider)
            and (self.account is None or finding.account == self.account)
            and (self.region is None or finding.region == self.region)
        )


@dataclass(frozen=True, slots=True)
class RegistryRecord:
    """A validated ``metadata["registry_record"]``."""

    registry: str
    registry_id: str
    record_id: str
    status: str
    descriptor_type: str
    bindings: tuple[RegistryBinding, ...] = ()
    publisher: str | None = None
    updated_at: str | None = None
    listing_complete: bool = False
    approval_mode: str = "unknown"
    listing_scope: str = "registry"

    @property
    def key(self) -> tuple[str, str]:
        return (self.registry, self.registry_id)

    @property
    def identified(self) -> bool:
        """Whether ``registry_id`` names one registry; an empty or redacted id never does."""
        return _usable(self.registry_id)

    @property
    def agent_id(self) -> str:
        """The inventory id an approval of this record carries."""
        return f"{self.registry}:{self.record_id}"


def _binding(value: Any) -> RegistryBinding | None:
    if not isinstance(value, dict) or "resource" not in value or not value.keys() <= _BINDING_FIELDS:
        return None
    resource = value["resource"]
    scope = [value.get(name) for name in ("provider", "account", "region")]
    coverage = value.get("coverage", "unknown")
    if not _bounded(resource) or any(item is not None and not _bounded(item) for item in scope):
        return None
    if coverage not in COVERAGE_VALUES:
        return None
    return RegistryBinding(resource, scope[0], scope[1], scope[2], coverage)


def parse_registry_record(value: Any) -> RegistryRecord | None:
    """Validate a registry record mapping; None when it does not follow the contract exactly.

    Unknown fields, an unknown schema, registry type, status or descriptor type, more than
    :data:`MAX_BINDINGS` bindings and non-string identities are all malformed. A binding whose
    resource is empty or redacted is valid but unusable: it can neither match nor approve.
    """
    if not isinstance(value, dict) or not _REQUIRED_FIELDS <= value.keys() <= _RECORD_FIELDS:
        return None
    if (
        value["schema"] != RECORD_SCHEMA
        or value["registry"] not in REGISTRY_TYPES
        or value["status"] not in RECORD_STATUSES
        or value["descriptor_type"] not in DESCRIPTOR_TYPES
        or not _bounded(value["registry_id"])
        or not _bounded(value["record_id"])
        or not value["record_id"].strip()
    ):
        return None
    raw_bindings = value.get("bindings", [])
    if not isinstance(raw_bindings, list) or len(raw_bindings) > MAX_BINDINGS:
        return None
    bindings = tuple(_binding(item) for item in raw_bindings)
    publisher = value.get("publisher")
    updated_at = value.get("updated_at")
    listing_complete = value.get("listing_complete", False)
    approval_mode = value.get("approval_mode", "unknown")
    listing_scope = value.get("listing_scope", "registry")
    if (
        any(binding is None for binding in bindings)
        or (publisher is not None and not _bounded(publisher))
        or (updated_at is not None and not _bounded(updated_at))
        or type(listing_complete) is not bool
        or approval_mode not in APPROVAL_MODES
        or listing_scope not in LISTING_SCOPES
    ):
        return None
    return RegistryRecord(
        registry=value["registry"],
        registry_id=value["registry_id"],
        record_id=value["record_id"],
        status=value["status"],
        descriptor_type=value["descriptor_type"],
        bindings=tuple(binding for binding in bindings if binding is not None),
        publisher=(publisher.strip() or None) if isinstance(publisher, str) else None,
        updated_at=updated_at,
        # What a caller-scoped listing omits may exist, so it never proves a complete listing.
        listing_complete=listing_complete and listing_scope == "registry",
        approval_mode=approval_mode,
        listing_scope=listing_scope,
    )


def registry_record(finding: Finding) -> RegistryRecord | None:
    """The finding's registry record; None when it carries none or the record is malformed."""
    return parse_registry_record(finding.metadata.get(RECORD_KEY))


def registry_evidence(registry: str, description: str, *, location: str | None = None) -> Evidence:
    """Evidence for a registry record finding.

    A record proves that someone registered the agent, not that it runs: the evidence has weight
    0.5 and its own confidence group, so it never adds to the confidence of an observation.
    """
    if registry not in REGISTRY_TYPES:
        raise ValueError("unknown registry type")
    return Evidence(
        signal=f"registry:{registry}",
        description=description,
        location=location,
        weight=EVIDENCE_WEIGHT,
        attributes={"confidence_group": EVIDENCE_GROUP},
    )


def _parsed_records(findings: Sequence[Finding]) -> tuple[list[tuple[Finding, RegistryRecord]], int]:
    records: list[tuple[Finding, RegistryRecord]] = []
    malformed = 0
    for finding in findings:
        if RECORD_KEY not in finding.metadata:
            continue
        record = registry_record(finding)
        if record is None:
            malformed += 1
        else:
            records.append((finding, record))
    return records, malformed


def _references(references: set[tuple[str, str]]) -> list[dict[str, str]]:
    return [{"registry": registry, "registry_id": rid} for registry, rid in sorted(references)[:MAX_LINKS]]


def _bindable(registry: str, finding: Finding) -> bool:
    """Whether records of the registry type could bind ``finding``, so its absence means something."""
    types = BINDABLE_RESOURCE_TYPES.get(registry)
    return types is None or finding.resource_type in types


def reconcile_registries(findings: Sequence[Finding]) -> list[str]:
    """Write ``metadata["registry_reconciliation"]`` from registry records; return warnings.

    Observed findings are those without a registry record. A record whose status is in
    :data:`REGISTERING_STATUSES` and whose usable binding matches an observed finding exactly
    is ``registered-and-observed``, and so is that finding. Such a record is
    ``registered-not-observed`` only when every usable binding was in scope of the emitting
    connector's collection and none matched; otherwise it is ``not-comparable``. A record of any
    other status registers nothing: it is ``not-comparable`` (``reason: record-status``) and
    the findings it binds count as unregistered. An unmatched observed agent, workflow, bot or
    MCP server in a registry's provider and account scope, of a resource type the registry can
    bind (:data:`BINDABLE_RESOURCE_TYPES`), is ``observed-not-registered`` only when every
    record of that registry says its listing was complete; a match in any registry wins. The
    pass removes earlier values first, so it can run again on the same findings.
    """
    for finding in findings:
        finding.metadata.pop(RECONCILIATION_KEY, None)
    records, malformed = _parsed_records(findings)
    observed = [finding for finding in findings if RECORD_KEY not in finding.metadata]
    by_resource: dict[str, list[Finding]] = {}
    for finding in observed:
        if _usable(finding.resource):
            by_resource.setdefault(finding.resource, []).append(finding)
    matched_records: dict[int, set[str]] = {}
    matched_registries: dict[int, set[tuple[str, str]]] = {}
    scopes: dict[tuple[str, str], set[tuple[str, str]]] = {}
    complete: dict[tuple[str, str], bool] = {}
    for record_finding, record in records:
        usable = [binding for binding in record.bindings if binding.usable]
        if record.identified:
            # Every record of a registry, whatever its status, shows what its listing covers.
            complete[record.key] = complete.get(record.key, True) and record.listing_complete
            pairs = scopes.setdefault(record.key, set())
            pairs.update((b.provider, b.account) for b in usable if b.provider and b.account)
        if record.status not in REGISTERING_STATUSES:
            # A draft, rejected, deprecated, blocked or unknown record registers nothing.
            record_finding.metadata[RECONCILIATION_KEY] = {
                "status": "not-comparable",
                "observed": [],
                "reason": "record-status",
            }
            continue
        hits: dict[int, Finding] = {}
        unmatched_in_scope = 0
        for binding in usable:
            matches = [item for item in by_resource.get(binding.resource, []) if binding.matches(item)]
            hits.update((id(item), item) for item in matches)
            unmatched_in_scope += not matches and binding.coverage == "in-scope"
        for key in hits:
            matched_records.setdefault(key, set()).add(record_finding.id)
            matched_registries.setdefault(key, set()).add(record.key)
        block: dict[str, Any]
        if hits:
            ids = sorted({item.id for item in hits.values()})[:MAX_LINKS]
            block = {"status": "registered-and-observed", "observed": ids}
        elif usable and unmatched_in_scope == len(usable):
            block = {"status": "registered-not-observed", "observed": []}
        else:
            reason = "binding-not-in-scope" if usable else "no-usable-binding"
            block = {"status": "not-comparable", "observed": [], "reason": reason}
        record_finding.metadata[RECONCILIATION_KEY] = block
    for finding in observed:
        key = id(finding)
        if key in matched_records:
            finding.metadata[RECONCILIATION_KEY] = {
                "status": "registered-and-observed",
                "records": sorted(matched_records[key])[:MAX_LINKS],
                "registries": _references(matched_registries[key]),
            }
            continue
        if (
            finding.kind not in RECONCILED_KINDS
            or not _usable(finding.resource)
            or not (_usable(finding.provider) and _usable(finding.account))
            or finding.metadata.get("identity_unresolved") is True
        ):
            continue
        scope = (finding.provider, finding.account)
        absent_from = {
            registry
            for registry, pairs in scopes.items()
            if complete[registry] and scope in pairs and _bindable(registry[0], finding)
        }
        if absent_from:
            finding.metadata[RECONCILIATION_KEY] = {
                "status": "observed-not-registered",
                "registries": _references(absent_from),
            }
    return [f"malformed registry record metadata on {malformed} finding(s)"] if malformed else []


def prune_reconciliation_links(findings: Sequence[Finding]) -> None:
    """Drop reconciliation links to findings absent from ``findings``; statuses stay as computed."""
    retained = {finding.id for finding in findings}
    for finding in findings:
        block = finding.metadata.get(RECONCILIATION_KEY)
        if not isinstance(block, dict):
            continue
        for name in ("records", "observed"):
            links = block.get(name)
            if isinstance(links, list):
                block[name] = [link for link in links if link in retained]


@dataclass(frozen=True, slots=True)
class TrustedRegistry:
    """One registry instance whose approved records the operator accepts as sanctioned inventory.

    ``allow_auto_approved`` also accepts approved records of a registry that approves every
    record without a person (``approval_mode: auto``); ``allow_registered_only`` also accepts
    ``registered`` records of a registry without an approval workflow. Both default to false:
    neither kind of record shows that a person reviewed the agent.
    """

    registry: str
    id: str
    allow_auto_approved: bool = False
    allow_registered_only: bool = False


def shown_registry_id(registry_id: str) -> str:
    """A short, sanitized form of a registry id for diagnostics."""
    suffix = registry_id if len(registry_id) <= _SHOWN_ID_SUFFIX else "..." + registry_id[-_SHOWN_ID_SUFFIX:]
    return sanitize_text(suffix)


class TrustedApprovals:
    """The approvals the approved records of trusted registries confer in one scan.

    Built from the findings of the current run every time; nothing is cached, so a revoked or
    deleted record stops approving on the next scan. Only a record whose registry type and exact
    id are trusted approves anything, and only when its status is ``approved`` with
    ``approval_mode: manual`` (any other approval mode only if the trusted entry sets
    ``allow_auto_approved``) or ``registered`` with ``allow_registered_only`` set. Records of
    :data:`UNTRUSTABLE_REGISTRY_TYPES` never approve:

    * the record finding itself is registered as ``<registry>:<record_id>``; and
    * each usable binding becomes an inventory entry for exactly that resource (glob
      metacharacters escaped) and the binding's provider, account and region, matched together
      with the loaded inventory, so all of its fail-closed rules still apply. Entries of one
      record count as one approval there.

    ``entries`` counts the approved records, one inventory item each, whatever their bindings.
    """

    def __init__(self, findings: Sequence[Finding], trusted: Sequence[TrustedRegistry]) -> None:
        policies = {
            (item.registry, item.id): item
            for item in trusted
            if item.registry not in UNTRUSTABLE_REGISTRY_TYPES
        }
        self._trusted = list(trusted)
        self._approved: dict[int, RegistryRecord] = {}
        self._by_resource: dict[str, list[InventoryEntry]] = {}
        self._produced: set[tuple[str, str]] = set()
        self._withheld: dict[tuple[str, str], dict[str, int]] = {}
        approved: set[tuple[str, str]] = set()
        seen: set[tuple[str, str, str, str | None, str | None, str | None]] = set()
        for finding in findings:
            record = registry_record(finding)
            policy = policies.get(record.key) if record is not None else None
            if record is None or policy is None:
                continue
            self._produced.add(record.key)
            withheld = _withheld_reason(record, policy)
            if withheld:
                counts = self._withheld.setdefault(record.key, {})
                counts[withheld] = counts.get(withheld, 0) + 1
                continue
            if not _approves(record, policy) or not _usable(record.record_id):
                continue
            self._approved[id(finding)] = record
            approved.add((record.agent_id, record.registry_id))
            for binding in record.bindings:
                identity = (
                    record.agent_id,
                    record.registry_id,
                    binding.resource,
                    binding.provider,
                    binding.account,
                    binding.region,
                )
                if not binding.usable or identity in seen:
                    continue
                seen.add(identity)
                self._by_resource.setdefault(binding.resource, []).append(
                    InventoryEntry(
                        agent_id=record.agent_id,
                        owner=record.publisher,
                        resources=[literal_resource_pattern(binding.resource)],
                        providers=[binding.provider] if binding.provider else [],
                        accounts=[binding.account] if binding.account else [],
                        regions=[binding.region] if binding.region else [],
                        source=TRUSTED_SOURCE_PREFIX + record.registry_id,
                    )
                )
        self.entries = len(approved)

    def approve_record(self, finding: Finding) -> bool:
        """Register an approved record finding of a trusted registry; False for any other finding."""
        record = self._approved.get(id(finding))
        if record is None:
            return False
        clear_match_state(finding)
        finding.registry_match = record.agent_id
        finding.shadow = False
        if not finding.owner and record.publisher:
            finding.owner = record.publisher
        return True

    def candidates(self, finding: Finding) -> list[InventoryEntry]:
        """Entries whose literal resource equals the finding's; the inventory checks everything else."""
        return self._by_resource.get(finding.resource, [])

    def warnings(self) -> list[str]:
        """Advisory notices: trusted registries without records, and records withheld by policy."""
        notices = [
            f"trusted registry {item.registry} {shown_registry_id(item.id)} produced no records; "
            "its approvals were not applied"
            for item in self._trusted
            if (item.registry, item.id) not in self._produced
        ]
        for (registry, registry_id), counts in sorted(self._withheld.items()):
            for reason, count in sorted(counts.items()):
                notices.append(
                    f"trusted registry {registry} {shown_registry_id(registry_id)}: {count} {reason} "
                    "record(s) were not treated as sanctioned"
                )
        return notices


def _withheld_reason(record: RegistryRecord, policy: TrustedRegistry) -> str | None:
    """Why the trust policy declines a record that would otherwise approve, for the warning."""
    if record.status == "approved" and record.approval_mode != "manual" and not policy.allow_auto_approved:
        if record.approval_mode == "auto":
            return "auto-approved (set allow_auto_approved to accept them)"
        return "approved without a known reviewer (set allow_auto_approved to accept them)"
    if record.status == "registered" and not policy.allow_registered_only:
        return "registered-only (set allow_registered_only to accept them)"
    return None


def _approves(record: RegistryRecord, policy: TrustedRegistry) -> bool:
    # Only an approval the registry shows a person made is sanctioned by default: an
    # automatic approval, or one whose approval mode the connector could not establish,
    # needs the operator's explicit allow_auto_approved for that registry.
    if record.status == "approved":
        return record.approval_mode == "manual" or policy.allow_auto_approved
    return record.status == "registered" and policy.allow_registered_only
