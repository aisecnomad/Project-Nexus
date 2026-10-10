"""Shapes of mapping catalogs and rules, with strict validation.

A framework catalog names one edition of a threat taxonomy, a layer model or a
control framework and the entries ShadowScan references from it. A rule names
the finding facts that make a finding relevant to some of those entries. Both
are author mappings: evidence references, never compliance determinations.

Validation collects every problem it finds instead of stopping at the first,
so ``python -m shadowscan.mappings.validate`` can list them all. Messages name
files, rule ids and fields, never whole values.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from datetime import date
from typing import Any

from shadowscan.models import Finding, Kind, Surface
from shadowscan.risk import TAG_WEIGHTS
from shadowscan.signatures.schema import CAPABILITIES

CATALOG_KINDS = ("threat", "layer", "control")
VERIFICATION_LEVELS = ("primary", "secondary")
# Each rule file references entries of exactly one catalog kind.
RULE_FILES = {"threats.yaml": "threat", "layers.yaml": "layer", "controls.yaml": "control"}
# What ``metadata.threats`` and ``metadata.controls`` collect.
THREAT_KINDS = frozenset({"threat", "layer"})
CONTROL_KINDS = frozenset({"control"})

# Contracts of the metadata other subsystems write and rules may read.
AUTONOMY_LEVELS = range(6)
OVERSIGHT_VALUES = frozenset({"gated", "bypassed", "unknown"})
REGISTRY_STATUSES = frozenset(
    {"registered-and-observed", "registered-not-observed", "observed-not-registered", "not-comparable"}
)

_FRAMEWORK = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_EDITION = re.compile(r"[a-z0-9]+(?:\.[a-z0-9]+)*\Z")
_ENTRY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_RULE_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_TAG = re.compile(r"[a-z0-9][a-z0-9._:-]{0,99}\Z")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}\Z")
_MAX_TITLE = 120
_MAX_TEXT = 600

_CATALOG_REQUIRED = (
    "framework",
    "edition",
    "prefix",
    "name",
    "kind",
    "source_url",
    "licence",
    "checked",
    "verification",
    "entries",
)
_CATALOG_KEYS = frozenset({*_CATALOG_REQUIRED, "notes"})
_RULE_FILE_KEYS = frozenset({"rules", "extra_known_tags"})
_RULE_KEYS = frozenset({"id", "when", "refs", "rationale"})
_LIST_CONDITIONS = (
    "tags_any",
    "capabilities_any",
    "kinds_any",
    "surfaces_any",
    "oversight_any",
    "registry_status_any",
)
_BOOL_CONDITIONS = ("shadow", "owner_missing")
_CONDITION_KEYS = frozenset({*_LIST_CONDITIONS, *_BOOL_CONDITIONS, "autonomy_floor_at_least"})


class MappingCatalogError(ValueError):
    """The packaged mapping data is invalid; ``problems`` lists every problem found."""

    def __init__(self, problems: Collection[str]) -> None:
        self.problems = tuple(problems)
        super().__init__("; ".join(self.problems))


@dataclass(frozen=True, slots=True)
class MappingEntry:
    """One catalog entry, as reports describe a reference to it."""

    ref: str  # "<prefix>:<id>", the form findings and reports carry
    id: str
    title: str
    framework: str
    framework_name: str
    edition: str
    kind: str
    url: str  # the catalog's source
    verification: str


@dataclass(frozen=True, slots=True)
class Catalog:
    framework: str
    edition: str
    prefix: str
    name: str
    kind: str
    source_url: str
    licence: str
    # When the catalog was compiled and its entries last checked against the
    # sources ``verification`` names; not a claim that ``source_url`` was retrieved.
    checked: str
    verification: str
    notes: str
    entries: tuple[MappingEntry, ...]
    source: str  # file name below the data directory


@dataclass(frozen=True, slots=True)
class FindingFacts:
    """The finding state rules read, with malformed metadata reduced to "absent"."""

    tags: frozenset[str]
    capabilities: frozenset[str]
    kind: str
    surface: str
    shadow: bool | None
    owner_missing: bool
    autonomy_floor: int | None
    oversight: str | None
    registry_status: str | None

    @classmethod
    def of(cls, finding: Finding) -> FindingFacts:
        metadata = finding.metadata if isinstance(finding.metadata, dict) else {}
        autonomy = metadata.get("autonomy")
        autonomy = autonomy if isinstance(autonomy, dict) else {}
        floor = autonomy.get("floor")
        oversight = autonomy.get("oversight")
        registry = metadata.get("registry_reconciliation")
        status = registry.get("status") if isinstance(registry, dict) else None
        owner = finding.owner
        return cls(
            tags=frozenset(tag for tag in finding.tags if isinstance(tag, str)),
            capabilities=frozenset(cap for cap in finding.capabilities if isinstance(cap, str)),
            kind=finding.kind.value if isinstance(finding.kind, Kind) else "",
            surface=finding.surface.value if isinstance(finding.surface, Surface) else "",
            shadow=finding.shadow if isinstance(finding.shadow, bool) else None,
            owner_missing=not (isinstance(owner, str) and owner.strip()),
            # bool is an int subclass; True is not autonomy level 1.
            autonomy_floor=floor if type(floor) is int and floor in AUTONOMY_LEVELS else None,
            oversight=oversight if isinstance(oversight, str) else None,
            registry_status=status if isinstance(status, str) else None,
        )


@dataclass(frozen=True, slots=True)
class Condition:
    """Every present key must hold; a set matches when it shares any value with the finding."""

    tags_any: frozenset[str] | None = None
    capabilities_any: frozenset[str] | None = None
    kinds_any: frozenset[str] | None = None
    surfaces_any: frozenset[str] | None = None
    oversight_any: frozenset[str] | None = None
    registry_status_any: frozenset[str] | None = None
    autonomy_floor_at_least: int | None = None
    shadow: bool | None = None
    owner_missing: bool | None = None

    def matches(self, facts: FindingFacts) -> bool:
        if self.tags_any is not None and self.tags_any.isdisjoint(facts.tags):
            return False
        if self.capabilities_any is not None and self.capabilities_any.isdisjoint(facts.capabilities):
            return False
        if self.kinds_any is not None and facts.kind not in self.kinds_any:
            return False
        if self.surfaces_any is not None and facts.surface not in self.surfaces_any:
            return False
        if self.oversight_any is not None and facts.oversight not in self.oversight_any:
            return False
        if self.registry_status_any is not None and facts.registry_status not in self.registry_status_any:
            return False
        if self.autonomy_floor_at_least is not None and (
            facts.autonomy_floor is None or facts.autonomy_floor < self.autonomy_floor_at_least
        ):
            return False
        # An unknown shadow status (no inventory supplied) matches neither value.
        if self.shadow is not None and facts.shadow is not self.shadow:
            return False
        return self.owner_missing is None or facts.owner_missing is self.owner_missing


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    kind: str  # the catalog kind every reference resolves to
    when: Condition
    refs: tuple[str, ...]
    rationale: str
    source: str  # rules file name


def _text(value: Any, context: str, problems: list[str], *, limit: int = _MAX_TEXT) -> str:
    """A non-empty single-line string of at most ``limit`` characters, or "" after recording a problem."""
    if not isinstance(value, str) or not value.strip():
        problems.append(f"{context} must be a non-empty string")
        return ""
    if len(value) > limit or any(ch in value for ch in "\r\n\t") or not value.isprintable():
        problems.append(f"{context} must be printable text on one line of at most {limit} characters")
        return ""
    return value


def _unknown_keys(
    data: Mapping[str, Any], allowed: Collection[str], context: str, problems: list[str]
) -> None:
    unknown = sorted(str(key) for key in data if key not in allowed)
    if unknown:
        problems.append(f"{context} has unknown keys: {', '.join(unknown)}")


def parse_catalog(data: Any, source: str, problems: list[str]) -> Catalog | None:
    """Validate one framework catalog document; record problems and return None when invalid."""
    start = len(problems)
    if not isinstance(data, dict):
        problems.append(f"{source}: a catalog must be a mapping")
        return None
    _unknown_keys(data, _CATALOG_KEYS, source, problems)
    missing = [key for key in _CATALOG_REQUIRED if key not in data]
    if missing:
        problems.append(f"{source}: missing keys: {', '.join(missing)}")
        return None
    fields = {
        key: _text(data[key], f"{source}: {key}", problems) for key in _CATALOG_REQUIRED if key != "entries"
    }
    notes = "" if data.get("notes") is None else _text(data["notes"], f"{source}: notes", problems)
    if fields["framework"] and not _FRAMEWORK.match(fields["framework"]):
        problems.append(f"{source}: framework must match [a-z0-9]+(-[a-z0-9]+)*")
    if fields["edition"] and not _EDITION.match(fields["edition"]):
        problems.append(f"{source}: edition must be lowercase letters and digits separated by dots")
    if (
        fields["framework"]
        and fields["edition"]
        and fields["prefix"] != f"{fields['framework']}-{fields['edition']}"
    ):
        # The prefix carries the edition, so a reference cannot outlive its edition.
        problems.append(f"{source}: prefix must be '<framework>-<edition>'")
    if fields["kind"] and fields["kind"] not in CATALOG_KINDS:
        problems.append(f"{source}: kind must be one of {', '.join(CATALOG_KINDS)}")
    if fields["verification"] and fields["verification"] not in VERIFICATION_LEVELS:
        problems.append(f"{source}: verification must be one of {', '.join(VERIFICATION_LEVELS)}")
    if fields["source_url"] and not fields["source_url"].startswith("https://"):
        problems.append(f"{source}: source_url must be an https:// URL")
    checked = fields["checked"]
    if checked:
        try:
            valid_date = bool(_DATE.match(checked)) and bool(date.fromisoformat(checked))
        except ValueError:
            valid_date = False
        if not valid_date:
            problems.append(f"{source}: checked must be a YYYY-MM-DD date string")
    raw_entries = data["entries"]
    entries: list[MappingEntry] = []
    if not isinstance(raw_entries, dict) or not raw_entries:
        problems.append(f"{source}: entries must be a non-empty mapping")
    else:
        for entry_id, entry in raw_entries.items():
            context = f"{source}: entry {entry_id!s}"
            if not isinstance(entry_id, str) or not _ENTRY.match(entry_id):
                problems.append(f"{context}: id must match [A-Za-z0-9][A-Za-z0-9._-]*")
                continue
            if not isinstance(entry, dict):
                problems.append(f"{context} must be a mapping with a title")
                continue
            _unknown_keys(entry, {"title"}, context, problems)
            title = _text(entry.get("title"), f"{context}: title", problems, limit=_MAX_TITLE)
            entries.append(
                MappingEntry(
                    ref=f"{fields['prefix']}:{entry_id}",
                    id=entry_id,
                    title=title,
                    framework=fields["framework"],
                    framework_name=fields["name"],
                    edition=fields["edition"],
                    kind=fields["kind"],
                    url=fields["source_url"],
                    verification=fields["verification"],
                )
            )
    if len(problems) > start:
        return None
    return Catalog(
        framework=fields["framework"],
        edition=fields["edition"],
        prefix=fields["prefix"],
        name=fields["name"],
        kind=fields["kind"],
        source_url=fields["source_url"],
        licence=fields["licence"],
        checked=checked,
        verification=fields["verification"],
        notes=notes,
        entries=tuple(entries),
        source=source,
    )


def _values(
    value: Any, context: str, allowed: Collection[str], noun: str, problems: list[str]
) -> frozenset[str] | None:
    """A non-empty list of distinct known strings."""
    if not isinstance(value, list) or not value:
        problems.append(f"{context} must be a non-empty list")
        return None
    if any(not isinstance(item, str) for item in value):
        problems.append(f"{context} must list strings")
        return None
    if len(set(value)) != len(value):
        problems.append(f"{context} lists a value twice")
    unknown = sorted(set(value) - set(allowed))
    if unknown:
        problems.append(f"{context} has unknown {noun}: {', '.join(unknown)}")
        return None
    return frozenset(value)


def parse_condition(
    data: Any, context: str, known_tags: Collection[str], problems: list[str]
) -> Condition | None:
    """Validate a rule's ``when`` mapping; an empty condition would match every finding."""
    if not isinstance(data, dict) or not data:
        problems.append(f"{context} must be a non-empty mapping")
        return None
    start = len(problems)
    _unknown_keys(data, _CONDITION_KEYS, context, problems)
    vocabularies: dict[str, tuple[Collection[str], str]] = {
        "tags_any": (known_tags, "tags"),
        "capabilities_any": (CAPABILITIES, "capabilities"),
        "kinds_any": ({kind.value for kind in Kind}, "kinds"),
        "surfaces_any": ({surface.value for surface in Surface}, "surfaces"),
        "oversight_any": (OVERSIGHT_VALUES, "oversight values"),
        "registry_status_any": (REGISTRY_STATUSES, "registry statuses"),
    }
    values: dict[str, Any] = {}
    for key, (allowed, noun) in vocabularies.items():
        if key in data:
            values[key] = _values(data[key], f"{context}.{key}", allowed, noun, problems)
    for key in _BOOL_CONDITIONS:
        if key in data:
            if not isinstance(data[key], bool):
                problems.append(f"{context}.{key} must be true or false")
            values[key] = data[key]
    if "autonomy_floor_at_least" in data:
        level = data["autonomy_floor_at_least"]
        if type(level) is not int or level not in AUTONOMY_LEVELS:
            problems.append(f"{context}.autonomy_floor_at_least must be an integer from 0 to 5")
        values["autonomy_floor_at_least"] = level
    if len(problems) > start:
        return None
    return Condition(**values)


def parse_rules(
    data: Any,
    source: str,
    kind: str,
    entries: Mapping[str, MappingEntry],
    problems: list[str],
) -> list[Rule]:
    """Validate one rules document whose references must all be catalog entries of ``kind``."""
    if not isinstance(data, dict):
        problems.append(f"{source}: a rules file must be a mapping with a rules list")
        return []
    _unknown_keys(data, _RULE_FILE_KEYS, source, problems)
    known_tags = set(TAG_WEIGHTS)
    extra = data.get("extra_known_tags", [])
    if not isinstance(extra, list) or any(not isinstance(tag, str) or not _TAG.match(tag) for tag in extra):
        problems.append(f"{source}: extra_known_tags must be a list of tag names")
    else:
        redundant = sorted(set(extra) & known_tags)
        if redundant:
            problems.append(f"{source}: extra_known_tags repeats weighted tags: {', '.join(redundant)}")
        known_tags.update(extra)
    raw_rules = data.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        problems.append(f"{source}: rules must be a non-empty list")
        return []
    rules: list[Rule] = []
    for number, item in enumerate(raw_rules, 1):
        context = f"{source}: rule {number}"
        if not isinstance(item, dict):
            problems.append(f"{context} must be a mapping")
            continue
        start = len(problems)
        _unknown_keys(item, _RULE_KEYS, context, problems)
        missing = [key for key in ("id", "when", "refs", "rationale") if key not in item]
        if missing:
            problems.append(f"{context}: missing keys: {', '.join(missing)}")
            continue
        rule_id = item["id"]
        if not isinstance(rule_id, str) or not _RULE_ID.match(rule_id):
            problems.append(f"{context}: id must match [a-z0-9]+(-[a-z0-9]+)*")
        else:
            context = f"{source}: rule {rule_id}"
        condition = parse_condition(item["when"], f"{context}: when", known_tags, problems)
        refs = item["refs"]
        if not isinstance(refs, list) or not refs or any(not isinstance(ref, str) for ref in refs):
            problems.append(f"{context}: refs must be a non-empty list of references")
            refs = []
        elif len(set(refs)) != len(refs):
            problems.append(f"{context}: refs lists a reference twice")
        for ref in refs:
            entry = entries.get(ref)
            if entry is None:
                problems.append(f"{context}: unknown reference {ref}")
            elif entry.kind != kind:
                problems.append(f"{context}: reference {ref} is a {entry.kind} entry, not a {kind} entry")
        rationale = _text(item["rationale"], f"{context}: rationale", problems)
        if len(problems) > start or condition is None:
            continue
        rules.append(Rule(rule_id, kind, condition, tuple(refs), rationale, source))
    return rules
