"""Edition-qualified threat and control references for findings.

The packaged catalogs (``data/frameworks``) record framework editions and
their entries; the rules (``data/rules``) say which finding facts make a
finding relevant to which entries. A finding's references are derived when it
is exported, as ``metadata.threats`` (OWASP, MITRE ATLAS and MAESTRO layers)
and ``metadata.controls`` (NIST AI RMF, ISO/IEC 42001, EU AI Act, AIUC-1).

They are evidence references written by the project's author, not compliance
determinations and not independently reviewed. They never feed identity, risk,
diff state, merging or the incremental cache.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from shadowscan.mappings.loader import builtin_mapping_dir, load_mapping_directory
from shadowscan.mappings.schema import (
    CONTROL_KINDS,
    THREAT_KINDS,
    Catalog,
    FindingFacts,
    MappingCatalogError,
    MappingEntry,
    Rule,
)
from shadowscan.models import Finding

__all__ = [
    "Catalog",
    "MappingCatalogError",
    "MappingEntry",
    "MappingIndex",
    "Rule",
    "control_references",
    "describe",
    "finding_references",
    "load_mappings",
    "threat_references",
]


@dataclass(frozen=True, slots=True)
class MappingIndex:
    """Validated catalogs and rules, with every entry indexed by its reference."""

    catalogs: tuple[Catalog, ...]
    rules: tuple[Rule, ...]
    entries: Mapping[str, MappingEntry]

    @classmethod
    def from_directory(cls, root: Path) -> MappingIndex:
        catalogs, rules = load_mapping_directory(root)
        entries = {entry.ref: entry for catalog in catalogs for entry in catalog.entries}
        return cls(catalogs, rules, entries)

    def references(self, finding: Finding) -> tuple[list[str], list[str]]:
        """The sorted threat (and layer) references and control references for ``finding``."""
        facts = FindingFacts.of(finding)
        threats: set[str] = set()
        controls: set[str] = set()
        for rule in self.rules:
            if rule.when.matches(facts):
                if rule.kind in THREAT_KINDS:
                    threats.update(rule.refs)
                elif rule.kind in CONTROL_KINDS:
                    controls.update(rule.refs)
        return sorted(threats), sorted(controls)

    def describe(self, ref: str) -> MappingEntry | None:
        return self.entries.get(ref)


@lru_cache(maxsize=1)
def load_mappings() -> MappingIndex:
    """The packaged catalogs, validated once per process; invalid data raises MappingCatalogError."""
    return MappingIndex.from_directory(builtin_mapping_dir())


def finding_references(finding: Finding) -> tuple[list[str], list[str]]:
    """``(threats, controls)`` for a finding, from its tags, capabilities, kind and metadata."""
    return load_mappings().references(finding)


def threat_references(finding: Finding) -> list[str]:
    return finding_references(finding)[0]


def control_references(finding: Finding) -> list[str]:
    return finding_references(finding)[1]


def describe(ref: str) -> MappingEntry | None:
    """Title, framework, edition and source of a reference, or None when no catalog lists it."""
    return load_mappings().describe(ref)
