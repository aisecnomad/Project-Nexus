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

from shadowscan.models import Finding

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
            if any(ch in str(path) for ch in "*?["):
                files = sorted(Path().glob(str(path)))
            elif path.is_dir():
                files = sorted(f for f in path.rglob("*") if f.suffix.lower() in {".yaml", ".yml", ".json", ".csv"})
            elif path.exists():
                files = [path]
            else:
                raise FileNotFoundError(f"inventory path not found: {p}")
            for f in files:
                inv.entries.extend(cls._load_file(f))
                inv.sources.append(str(f))
        return inv

    @classmethod
    def _load_file(cls, path: Path) -> list[InventoryEntry]:
        text = path.read_text(encoding="utf-8", errors="replace")
        out: list[InventoryEntry] = []
        if path.suffix.lower() == ".csv":
            for row in csv.DictReader(text.splitlines()):
                aid = row.get("agent_id") or row.get("id") or row.get("name")
                if not aid:
                    continue
                out.append(
                    InventoryEntry(
                        agent_id=str(aid),
                        name=row.get("name"),
                        owner=row.get("owner") or row.get("owner_team"),
                        resources=[r.strip() for r in str(row.get("resources") or "").split("|") if r.strip()],
                        names=[n.strip() for n in str(row.get("names") or row.get("aliases") or "").split("|") if n.strip()],
                        surfaces=_list(row.get("surfaces")),
                        providers=_list(row.get("providers")),
                        accounts=_list(row.get("accounts")),
                        source=str(path),
                        card=dict(row),
                    )
                )
            return out
        if path.suffix.lower() == ".json":
            data: Any = json.loads(text)
            docs = [data]
        else:
            docs = list(yaml.safe_load_all(_strip_cite_markers(text)))
        for doc in docs:
            if not doc:
                continue
            if isinstance(doc, dict) and isinstance(doc.get("agents"), list):
                for item in doc["agents"]:
                    e = cls._entry_from_simple(item, path)
                    if e:
                        out.append(e)
            elif isinstance(doc, list):
                for item in doc:
                    e = cls._entry_from_simple(item, path) if isinstance(item, dict) and "metadata" not in item else cls._entry_from_card(item, path)
                    if e:
                        out.append(e)
            elif isinstance(doc, dict):
                e = cls._entry_from_card(doc, path) if "metadata" in doc else cls._entry_from_simple(doc, path)
                if e:
                    out.append(e)
        return out

    @staticmethod
    def _entry_from_card(doc: dict[str, Any], path: Path) -> InventoryEntry | None:
        meta = doc.get("metadata") or {}
        aid = meta.get("agent_id") or meta.get("id") or meta.get("name")
        if not aid:
            return None
        disc = doc.get("discovery") or {}
        frameworks = list(disc.get("frameworks") or [])
        return InventoryEntry(
            agent_id=str(aid),
            name=meta.get("name") or meta.get("display_name"),
            owner=meta.get("owner_team") or meta.get("owner") or meta.get("owner_email"),
            resources=[str(r) for r in disc.get("resources") or []],
            names=[str(n) for n in disc.get("names") or disc.get("aliases") or []],
            frameworks=frameworks,
            surfaces=_list(disc.get("surfaces")),
            providers=_list(disc.get("providers")),
            accounts=_list(disc.get("accounts")),
            tags=[str(t) for t in (meta.get("tags") or []) + ([meta["classification"]] if meta.get("classification") else [])],
            source=str(path),
            card=doc,
        )

    @staticmethod
    def _entry_from_simple(item: dict[str, Any], path: Path) -> InventoryEntry | None:
        aid = item.get("id") or item.get("agent_id") or item.get("name")
        if not aid:
            return None
        return InventoryEntry(
            agent_id=str(aid),
            name=item.get("name"),
            owner=item.get("owner") or item.get("owner_team"),
            resources=[str(r) for r in item.get("resources") or []],
            names=[str(n) for n in item.get("names") or item.get("aliases") or []],
            frameworks=[str(f) for f in item.get("frameworks") or []],
            surfaces=_list(item.get("surfaces")),
            providers=_list(item.get("providers")),
            accounts=_list(item.get("accounts")),
            tags=[str(t) for t in item.get("tags") or []],
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


def _list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [item.strip() for item in value.split("|") if item.strip()]
    return [str(item) for item in value or []]


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
            "resources": [finding.resource],
            "names": [n for n in {str(finding.metadata.get(k)) for k in NAME_FIELDS if finding.metadata.get(k)}],
            "frameworks": finding.frameworks,
            "surfaces": [finding.surface.value],
            "providers": [finding.provider] if finding.provider else [],
            "accounts": [finding.account] if finding.account else [],
        },
    }


def _slug(s: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", str(s).lower()).strip("-")
    return s[:64] or "agent"
