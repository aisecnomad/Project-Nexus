"""Sanctioned agent inventory ("registry") and reconciliation.

A *shadow* agent is one that ShadowScan discovers but that nobody registered.
The inventory can be supplied as:

* **Agent Capability Cards** – the YAML format used in this repository
  (``metadata.agent_id``, ``metadata.owner_team`` ...), one file per agent,
  optionally extended with a ``discovery:`` block that lists the concrete
  resources the agent is deployed as::

      discovery:
        resources:                     # glob patterns matched against finding.resource
          - "arn:aws:bedrock:*:123456789012:agent/ABCDEF*"
          - "github:acme/ops-agent"
          - "okta:app:0oa1b2c3*"
        names: ["ops provisioning agent", "ops-bot"]   # aliases matched against titles / names
        frameworks: [framework.langgraph]

* a simple inventory list ``agents: [{id, name, owner, resources, names}]`` (YAML/JSON)
* a CSV with columns ``agent_id, name, owner, resources`` (resources separated by ``|``)

Automatic approval requires an explicit, case-sensitive resource pattern and
all configured ``surfaces``, ``providers`` and ``accounts`` constraints. Names
and aliases are review suggestions only; they never confer sanctioned status.
"""

from __future__ import annotations

import csv
import fnmatch
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from shadowscan.models import Finding, Surface
from shadowscan.utils.files import policy_files, policy_glob, read_policy_text, require_no_symlinks
from shadowscan.utils.redaction import sanitize_text
from shadowscan.utils.safe_yaml import BoundedSafeLoader

NAME_FIELDS = ("agent_name", "name", "names", "display_name", "displayName", "app_slug", "okta_name", "developer_name", "schema_name", "caller", "principal", "function_name", "repository", "project", "agents", "agent_definitions")


def _meta_names(finding: Finding) -> set[str]:
    out: set[str] = set()
    for k in NAME_FIELDS:
        v = finding.metadata.get(k)
        if isinstance(v, str):
            out.add(v.lower())
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, str):
                    out.add(item.lower())
                elif isinstance(item, dict):
                    for kk in ("name", "agent_id", "display_name"):
                        if isinstance(item.get(kk), str):
                            out.add(item[kk].lower())
    return out


@dataclass(slots=True)
class InventoryEntry:
    agent_id: str
    name: str | None = None
    owner: str | None = None
    resources: list[str] = field(default_factory=list)
    names: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    surfaces: list[str] = field(default_factory=list)
    providers: list[str] = field(default_factory=list)
    accounts: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    source: str | None = None
    card: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Direct users of the public model must not bypass parser type checks.
        path = Path(self.source or "<entry>")
        values = {name: getattr(self, name) for name in _SIMPLE_FIELDS if hasattr(self, name)}
        for name in ("agent_id", "name", "owner"):
            _optional_string(values, name, path, "entry")
        if not self.agent_id:
            raise _invalid(path, "entry.agent_id", "a nonempty string is required")
        for name in _LIST_FIELDS - {"aliases"}:
            setattr(self, name, _string_list(values, name, path, "entry"))

    def all_names(self) -> list[str]:
        out = [self.agent_id]
        if self.name:
            out.append(self.name)
        out.extend(self.names)
        return [n.strip().lower() for n in out if n and n.strip()]


class Inventory:
    def __init__(self, entries: list[InventoryEntry] | None = None):
        self.entries: list[InventoryEntry] = entries or []
        self.sources: list[str] = []

    def __len__(self) -> int:
        return len(self.entries)

    # ---------------------------------------------------------------- load
    @classmethod
    def load(cls, paths: Sequence[str | Path]) -> Inventory:
        inv = cls()
        for p in paths:
            path = Path(p).expanduser()
            files: list[Path]
            if path.is_dir():
                files = list(policy_files(path, {".yaml", ".yml", ".json", ".csv"}))
            elif path.exists() or path.is_symlink():
                require_no_symlinks(path)
                files = [path]
            elif any(ch in str(path) for ch in "*?["):
                files = sorted(policy_glob(path))
            else:
                raise FileNotFoundError(f"inventory path not found: {p}")
            for f in files:
                inv.entries.extend(cls._load_file(f))
                inv.sources.append(str(f))
        return inv

    @classmethod
    def _load_file(cls, path: Path) -> list[InventoryEntry]:
        try:
            text = read_policy_text(path)
        except (OSError, UnicodeError, ValueError):
            raise _invalid(path, "document", "could not read bounded regular UTF-8 inventory") from None
        if path.suffix.lower() == ".csv":
            return cls._load_csv(text, path)
        try:
            if path.suffix.lower() == ".json":
                docs = [json.loads(text, object_pairs_hook=_unique_json_object)]
            else:
                docs = list(yaml.load_all(_strip_cite_markers(text), Loader=_InventoryLoader))
        except (json.JSONDecodeError, yaml.YAMLError, _DuplicateKeyError):
            # Parser errors include source excerpts, which can contain credentials.
            raise _invalid(path, "document", "invalid syntax or duplicate mapping key") from None
        if not docs:
            raise _invalid(path, "document", "empty inventory; use agents: [] for an empty inventory")
        out: list[InventoryEntry] = []
        for number, doc in enumerate(docs, 1):
            location = f"document {number}"
            if isinstance(doc, dict) and "agents" in doc:
                _check_fields(doc, {"agents"}, path, location)
                if not isinstance(doc["agents"], list):
                    raise _invalid(path, f"{location}.agents", "expected a list of inventory entries")
                items = doc["agents"]
            elif isinstance(doc, list):
                items = doc
            elif isinstance(doc, dict):
                items = [doc]
            else:
                raise _invalid(path, location, "expected an entry, a list of entries, or an agents mapping")
            for number, item in enumerate(items, 1):
                entry_location = f"{location}.entry {number}"
                if not isinstance(item, dict):
                    raise _invalid(path, entry_location, "expected an inventory mapping")
                parser = cls._entry_from_card if "metadata" in item else cls._entry_from_simple
                out.append(parser(item, path, entry_location))
        return out

    @classmethod
    def _load_csv(cls, text: str, path: Path) -> list[InventoryEntry]:
        # Use the same typed entry parser after the CSV-only pipe-list adaptation.
        reader = csv.DictReader(text.splitlines(), strict=True)
        try:
            headers = reader.fieldnames
            if not headers or any(not header.strip() for header in headers):
                raise _invalid(path, "CSV header", "expected nonempty column names")
            headers = [header.strip() for header in headers]
            if len(headers) != len(set(headers)):
                raise _invalid(path, "CSV header", "duplicate column names")
            _check_fields(dict.fromkeys(headers), _SIMPLE_FIELDS, path, "CSV header")
            if not {"id", "agent_id", "name"}.intersection(headers):
                raise _invalid(path, "CSV header", "agent_id, id, or name is required")
            reader.fieldnames = headers
            out: list[InventoryEntry] = []
            for row in reader:
                location = f"CSV row {reader.line_num}"
                if None in row or any(value is None for value in row.values()):
                    raise _invalid(path, location, "column count does not match the header")
                item: dict[str, Any] = dict(row)
                for name in _LIST_FIELDS:
                    if name in row:
                        value = row[name].strip()
                        item[name] = [part.strip() for part in value.split("|")] if value else []
                # Blank optional CSV cells are absent, not invalid empty strings.
                item = {name: value for name, value in item.items() if value != ""}
                out.append(cls._entry_from_simple(item, path, location))
            return out
        except csv.Error:
            raise _invalid(path, "CSV document", "invalid CSV syntax") from None

    @staticmethod
    def _entry_from_card(doc: dict[str, Any], path: Path, location: str = "entry") -> InventoryEntry:
        if not isinstance(doc, dict) or not isinstance(doc.get("metadata"), dict):
            raise _invalid(path, f"{location}.metadata", "expected a mapping")
        meta = doc["metadata"]
        disc = doc.get("discovery", {})
        if not isinstance(disc, dict):
            raise _invalid(path, f"{location}.discovery", "expected a mapping")
        _check_fields(disc, _LIST_FIELDS - {"tags"}, path, f"{location}.discovery")
        for name in ("agent_id", "id", "name", "display_name", "owner_team", "owner", "owner_email", "classification"):
            _optional_string(meta, name, path, f"{location}.metadata")
        aid = meta.get("agent_id") or meta.get("id") or meta.get("name")
        if not aid:
            raise _invalid(path, f"{location}.metadata", "agent_id, id, or name is required")
        lists = {name: _string_list(disc, name, path, f"{location}.discovery") for name in _LIST_FIELDS - {"tags"}}
        tags = _string_list(meta, "tags", path, f"{location}.metadata")
        if meta.get("classification"):
            tags.append(meta["classification"].strip())
        return InventoryEntry(
            agent_id=aid.strip(),
            name=_first_string(meta, "name", "display_name"),
            owner=_first_string(meta, "owner_team", "owner", "owner_email"),
            resources=lists["resources"],
            names=lists["names"] or lists["aliases"],
            frameworks=lists["frameworks"],
            surfaces=lists["surfaces"],
            providers=lists["providers"],
            accounts=lists["accounts"],
            tags=tags,
            source=str(path),
            card=doc,
        )

    @staticmethod
    def _entry_from_simple(item: dict[str, Any], path: Path, location: str = "entry") -> InventoryEntry:
        if not isinstance(item, dict):
            raise _invalid(path, location, "expected an inventory mapping")
        _check_fields(item, _SIMPLE_FIELDS, path, location)
        for name in _SIMPLE_FIELDS - _LIST_FIELDS:
            _optional_string(item, name, path, location)
        aid = item.get("id") or item.get("agent_id") or item.get("name")
        if not aid:
            raise _invalid(path, location, "id, agent_id, or name is required")
        lists = {name: _string_list(item, name, path, location) for name in _LIST_FIELDS}
        return InventoryEntry(
            agent_id=aid.strip(),
            name=_first_string(item, "name"),
            owner=_first_string(item, "owner", "owner_team"),
            resources=lists["resources"],
            names=lists["names"] or lists["aliases"],
            frameworks=lists["frameworks"],
            surfaces=lists["surfaces"],
            providers=lists["providers"],
            accounts=lists["accounts"],
            tags=lists["tags"],
            source=str(path),
            card=item,
        )

    # --------------------------------------------------------------- match
    def match(self, finding: Finding) -> InventoryEntry | None:
        """Return one unambiguous, explicitly scoped resource approval.

        Case folding resource IDs can approve a different object (for example,
        a case-sensitive cloud ARN or repository path). Unknown scopes and
        conflicting inventory identities fail closed.
        """
        finding.metadata.pop("registry_suggestions", None)
        finding.metadata.pop("registry_match_reason", None)
        matches = [
            entry for entry in self.entries
            if self._scope_matches(entry, finding)
            and any(fnmatch.fnmatchcase(finding.resource or "", pattern) for pattern in entry.resources)
        ]
        if len(matches) == 1:
            finding.metadata.pop("registry_suggestions", None)
            return matches[0]
        if len(matches) > 1:
            finding.metadata["registry_suggestions"] = sorted({e.agent_id for e in matches})
            finding.metadata["registry_match_reason"] = "ambiguous-resource-approval"
            return None
        suggestions = self.suggest(finding)
        if suggestions:
            finding.metadata["registry_suggestions"] = [entry.agent_id for entry in suggestions]
            finding.metadata["registry_match_reason"] = "name-only-review-required"
        return None

    @staticmethod
    def _scope_matches(entry: InventoryEntry, finding: Finding) -> bool:
        return (
            (not entry.surfaces or finding.surface.value in entry.surfaces)
            and (not entry.providers or finding.provider in entry.providers)
            and (not entry.accounts or finding.account in entry.accounts)
        )

    def suggest(self, finding: Finding) -> list[InventoryEntry]:
        """Return name hints for human review; never use them for approval."""
        res = (finding.resource or "").lower()
        title = (finding.title or "").lower()
        names = _meta_names(finding)
        out = []
        for e in self.entries:
            for n in e.all_names():
                if len(n) < 4:
                    continue
                if n in names or re.search(rf"(?<![a-z0-9]){re.escape(n)}(?![a-z0-9])", title) or re.search(rf"(?<![a-z0-9]){re.escape(n)}(?![a-z0-9])", res):
                    out.append(e)
                    break
        return out


class InventoryValidationError(ValueError):
    """Malformed inventory cannot participate in approval or risk scoring."""


def _invalid(path: Path, location: str, message: str) -> InventoryValidationError:
    return InventoryValidationError(sanitize_text(f"invalid inventory {path}: {location}: {message}"))


_LIST_FIELDS = {"resources", "names", "aliases", "frameworks", "surfaces", "providers", "accounts", "tags"}
_SIMPLE_FIELDS = _LIST_FIELDS | {"id", "agent_id", "name", "owner", "owner_team"}


def _check_fields(value: dict, allowed: set[str], path: Path, location: str) -> None:
    if any(not isinstance(key, str) or key not in allowed for key in value):
        # Do not echo arbitrary unknown keys: they may themselves contain secrets.
        raise _invalid(path, location, "unsupported field; allowed fields: " + ", ".join(sorted(allowed)))


def _optional_string(value: dict, name: str, path: Path, location: str) -> None:
    if name in value and value[name] is not None and (not isinstance(value[name], str) or not value[name].strip()):
        raise _invalid(path, f"{location}.{name}", "expected a nonempty string")


def _first_string(value: dict, *names: str) -> str | None:
    return next((value[name].strip() for name in names if value.get(name)), None)


def _string_list(value: dict, name: str, path: Path, location: str) -> list[str]:
    if name not in value:
        return []
    items = value[name]
    if not isinstance(items, list) or any(not isinstance(item, str) or not item.strip() for item in items):
        raise _invalid(path, f"{location}.{name}", "expected a list of nonempty strings (quote numeric identifiers)")
    if name == "surfaces" and any(item.strip() not in {surface.value for surface in Surface} for item in items):
        raise _invalid(path, f"{location}.{name}", "contains an unknown discovery surface")
    return [item.strip() for item in items]


class _DuplicateKeyError(ValueError):
    pass


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError("duplicate inventory key")
        result[key] = value
    return result


class _InventoryLoader(BoundedSafeLoader):
    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict:
        self.flatten_mapping(node)
        mapping: dict = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise _DuplicateKeyError("inventory mapping keys must be strings")
            if key in mapping:
                raise _DuplicateKeyError("duplicate inventory key")
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


_CITE = re.compile(r"\[cite(?:_start)?(?::[^\]]*)?\]")


def _strip_cite_markers(text: str) -> str:
    """The sample capability card carries `[cite_start]` / `[cite: n]` markers from a document export; ignore them."""
    return "\n".join(_CITE.sub("", line) for line in text.splitlines())


def card_stub_for(finding: Finding) -> dict[str, Any]:
    """Generate an Agent Capability Card skeleton for a discovered agent (to register it)."""
    caps = finding.capabilities
    autonomy = 4 if "autonomous" in caps else 3 if "tool-use" in caps else 2
    return {
        "metadata": {
            "agent_id": _slug(finding.metadata.get("agent_name") or finding.metadata.get("name") or finding.title.split(":")[-1].strip()),
            "version": "0.1.0",
            "owner_team": finding.owner or "UNKNOWN",
            "classification": "Internal",
            "discovered_by": "shadowscan",
            "discovered_as": finding.resource,
        },
        "autonomy_profile": {
            "level": autonomy,
            "memory_persistence": "memory" in caps,
            "max_loop_iterations": None,
            "velocity_limit": None,
        },
        "identity_and_delegation": {"spiffe_id": None, "auth_mechanism": None, "privileged_account": "policy.privileged-scopes" in finding.tags},
        "capability_surface (Tools)": {"authorized_tools": [{"name": c} for c in caps]},
        "security_controls": {"egress_proxy_required": True, "sandbox_type": None, "kill_switch_enabled": False},
        "risk_scoring": {"AARS_initial_score": finding.risk.score, "blast_radius": finding.risk.level.value},
        "discovery": {
            # The discovered ID is literal. Hand-authored resource entries may
            # still deliberately use wildcards; generated approvals never do.
            "resources": [finding.resource.translate({ord("*"): "[*]", ord("?"): "[?]", ord("["): "[[]"})],
            "names": sorted({str(finding.metadata.get(k)) for k in NAME_FIELDS if finding.metadata.get(k)}),
            "frameworks": finding.frameworks,
            "surfaces": [finding.surface.value],
            "providers": [finding.provider] if finding.provider else [],
            "accounts": [finding.account] if finding.account else [],
        },
    }


def _slug(s: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", str(s).lower()).strip("-")
    return s[:64] or "agent"
