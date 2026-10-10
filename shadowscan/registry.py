"""Sanctioned agent inventory ("registry") and reconciliation.

A *shadow* agent is one that ShadowScan discovers but that nobody registered.
The inventory can be supplied as:

* **Agent Capability Cards** – the YAML format of ``agent-card.yaml`` in this
  repository (``metadata.agent_id``, ``metadata.owner_team`` ...), one file per agent,
  optionally extended with a ``discovery:`` block that lists the concrete
  resources the agent is deployed as::

      discovery:
        resources:                     # glob patterns matched against finding.resource
          - "arn:aws:bedrock:*:123456789012:agent/ABCDEF*"
          - "github:acme/ops-agent"
          - "okta:app:0oa1b2c3*"
        names: ["ops provisioning agent", "ops-bot"]   # aliases matched against titles / names
        frameworks: [framework.langgraph]

  A card with top-level ``schema_version: 2`` declares ``autonomy_profile.level`` on the L0-L5
  scale of :mod:`shadowscan.autonomy`; an earlier card's level is ignored and reported.

* a simple inventory list ``agents: [{id, name, owner, resources, names, autonomy_level}]`` (YAML/JSON)
* a CSV with columns ``agent_id, name, owner, resources`` (resources separated by ``|``)
  and an optional ``autonomy_level``

Automatic approval requires an explicit, case-sensitive resource pattern and
all configured ``surfaces``, ``providers``, ``accounts``, ``regions`` and
``discriminators`` constraints. Names and aliases are review suggestions only;
they never confer sanctioned status.

Approved records of the vendor registries an operator trusts (``options.trusted_registries``,
see :mod:`shadowscan.registries`) add exact-resource entries for one run; the loaded inventory
itself is never changed.
"""

from __future__ import annotations

import csv
import fnmatch
import io
import re
from collections import OrderedDict
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from shadowscan.autonomy import observed_floor, valid_autonomy
from shadowscan.errors import SetupError, SetupPathError
from shadowscan.models import Finding, Surface
from shadowscan.utils.files import (
    SKIPPED_LINK,
    policy_files,
    policy_glob,
    read_policy_text,
    require_no_symlinks,
)
from shadowscan.utils.identity import (
    has_aws_account_scope,
    has_google_workspace_account_scope,
    requires_card_account_scope,
)
from shadowscan.utils.redaction import REDACTED, sanitize_text
from shadowscan.utils.safe_json import strict_json_loads
from shadowscan.utils.safe_yaml import strict_bounded_safe_load_all

NAME_FIELDS = (
    "agent_name",
    "name",
    "names",
    "display_name",
    "displayName",
    "app_slug",
    "okta_name",
    "developer_name",
    "schema_name",
    "caller",
    "principal",
    "function_name",
    "repository",
    "project",
    "agents",
    "agent_definitions",
)
_MAX_NAME_PATTERNS = 4096


def _has_valid_account_scope(finding: Finding) -> bool:
    """Whether the finding's own account/resource pairing is internally consistent.

    Shared by ``Inventory.match`` (which also reports which specific check
    failed) and ``card_stub_for`` (which only needs the yes/no answer before
    deciding whether a generated card may bind account/resource evidence).
    """
    return has_aws_account_scope(
        finding.provider, finding.account, finding.resource
    ) and has_google_workspace_account_scope(finding.provider, finding.account)


def _has_usable_resource_identity(finding: Finding) -> bool:
    return isinstance(finding.resource, str) and bool(finding.resource) and REDACTED not in finding.resource


def _has_usable_scope_identity(finding: Finding) -> bool:
    # These fields can distinguish otherwise identical resource IDs. Redaction
    # also turns different accounts/providers/regions into the same placeholder.
    return all(
        value is None or (isinstance(value, str) and REDACTED not in value)
        for value in (finding.provider, finding.account, finding.region)
    )


def _has_usable_discriminator(finding: Finding) -> bool:
    # Inventory lists hold stripped, nonempty strings: an empty or padded value
    # could not be written as a binding that matches this finding again.
    value = finding.identity_discriminator
    return bool(value) and value == value.strip()


# A gateway resource such as ``principal:svc-ops`` is a field the log producer
# (often the caller itself) wrote. A match on it is flagged, not trusted.
UNVERIFIED_IDENTITY_TAG = "registry-identity-unverified"


def clear_match_state(finding: Finding) -> None:
    """Remove what an earlier reconciliation pass (or a connector or plugin) wrote about approval."""
    finding.metadata.pop("registry_suggestions", None)
    finding.metadata.pop("registry_match_reason", None)
    finding.metadata.pop("registry_match_assurance", None)
    if UNVERIFIED_IDENTITY_TAG in finding.tags:
        finding.tags.remove(UNVERIFIED_IDENTITY_TAG)


def literal_resource_pattern(resource: str) -> str:
    """A resource pattern that matches exactly ``resource``: glob metacharacters are escaped."""
    return resource.translate({ord("*"): "[*]", ord("?"): "[?]", ord("["): "[[]"})


def _unauthenticated_caller_assurance(finding: Finding) -> str | None:
    """Weakest identity assurance behind a gateway caller name, unless it is provider-authenticated.

    Returns ``operator-asserted`` or ``unverified``; a gateway finding whose
    observations carry no recognizable assurance counts as ``unverified``.
    """
    if finding.surface != Surface.GATEWAY:
        return None
    observations = finding.metadata.get("runtime_observations")
    levels = (
        {item.get("identity_assurance") for item in observations if isinstance(item, dict)}
        if isinstance(observations, list)
        else set()
    )
    if not levels or not levels <= {"operator-asserted", "provider-authenticated-field"}:
        return "unverified"
    return "operator-asserted" if "operator-asserted" in levels else None


def _metadata_names(finding: Finding) -> list[str]:
    """Name strings in finding metadata, including names of listed agent definitions."""
    out: list[str] = []
    for k in NAME_FIELDS:
        v = finding.metadata.get(k)
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, str):
                    out.append(item)
                elif isinstance(item, dict):
                    for kk in ("name", "agent_id", "display_name"):
                        if isinstance(item.get(kk), str):
                            out.append(item[kk])
    return out


def _meta_names(finding: Finding) -> set[str]:
    return {name.lower() for name in _metadata_names(finding)}


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
    regions: list[str] = field(default_factory=list)
    discriminators: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    source: str | None = None
    card: dict[str, Any] = field(default_factory=dict)
    # Declared autonomy level (0-5): ``autonomy_profile.level`` of a schema_version 2 card, or a
    # simple entry's ``autonomy_level``. None when the entry declares none.
    autonomy_level: int | None = None
    # A card without schema_version 2 set autonomy_profile.level; it was not read (older scale).
    ignored_autonomy_level: bool = False

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
        _autonomy_level(values, "autonomy_level", path, "entry")
        if type(self.ignored_autonomy_level) is not bool:
            raise _invalid(path, "entry.ignored_autonomy_level", "expected a boolean")

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
        # Symbolic links a directory or glob passed over; links are never followed.
        self.skipped_links: list[str] = []
        # Bound the cache even when callers repeatedly replace inventory entries.
        self._name_patterns: OrderedDict[str, re.Pattern[str]] = OrderedDict()

    def __len__(self) -> int:
        return len(self.entries)

    def autonomy_warnings(self) -> list[str]:
        """Advisory notices for cards whose autonomy level was not read (no schema_version 2)."""
        return [
            f"inventory entry {entry.agent_id}{f' in {entry.source}' if entry.source else ''}: "
            f"{IGNORED_AUTONOMY_LEVEL}"
            for entry in self.entries
            if entry.ignored_autonomy_level
        ]

    # ---------------------------------------------------------------- load
    @classmethod
    def load(cls, paths: Sequence[str | Path]) -> Inventory:
        inv = cls()
        for p in paths:
            path = Path(p).expanduser()
            files: list[Path]
            if path.is_dir():
                skipped: list[tuple[str, str]] = []
                files = list(policy_files(path, {".yaml", ".yml", ".json", ".csv"}, skipped))
                inv.skipped_links += [str(path / name) for name, reason in skipped if reason == SKIPPED_LINK]
            elif path.exists() or path.is_symlink():
                require_no_symlinks(path)
                files = [path]
            elif any(ch in str(path) for ch in "*?["):
                links: list[str] = []
                files = sorted(policy_glob(path, links))
                inv.skipped_links += links
                if not files:
                    # Like a missing literal path: a typo must not load an empty inventory.
                    raise SetupPathError(
                        sanitize_text(
                            f"inventory glob matched no files (symbolic links are not followed): {p}"
                        )
                    )
            else:
                # A missing path is reported by name only: the message must stay
                # safe for the CLI to print verbatim (see shadowscan.errors).
                raise SetupPathError(
                    sanitize_text(
                        f"inventory path not found: {p} "
                        "(create it, pass an existing card file or directory such as agent-card.yaml, "
                        "or omit the inventory)"
                    )
                )
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
                docs = [strict_json_loads(text)]
            else:
                docs = strict_bounded_safe_load_all(_strip_cite_markers(text))
        except (ValueError, yaml.YAMLError, RecursionError):
            # JSON syntax errors, duplicate or nonfinite JSON fields (JSONIntegrityError) and
            # SafeLoader's plain ValueError for an impossible date or an over-long integer are
            # all ValueErrors; like YAML integrity and resource errors they are malformed input.
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
        # Let the CSV parser distinguish record separators from quoted field
        # content. splitlines() removes embedded newlines (including Unicode
        # separators), changing resource and scope identities before approval.
        reader = csv.DictReader(io.StringIO(text, newline=""), strict=True)
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
                level = row.get("autonomy_level", "").strip()
                if _CSV_LEVEL.fullmatch(level):
                    item["autonomy_level"] = int(level)
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
        for name in (
            "agent_id",
            "id",
            "name",
            "display_name",
            "owner_team",
            "owner",
            "owner_email",
            "classification",
        ):
            _optional_string(meta, name, path, f"{location}.metadata")
        aid = meta.get("agent_id") or meta.get("id") or meta.get("name")
        if not aid:
            raise _invalid(path, f"{location}.metadata", "agent_id, id, or name is required")
        lists = {
            name: _string_list(disc, name, path, f"{location}.discovery") for name in _LIST_FIELDS - {"tags"}
        }
        tags = _string_list(meta, "tags", path, f"{location}.metadata")
        if meta.get("classification"):
            tags.append(meta["classification"].strip())
        level, ignored = _card_autonomy(doc, path, location)
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
            regions=lists["regions"],
            discriminators=lists["discriminators"],
            tags=tags,
            source=str(path),
            card=doc,
            autonomy_level=level,
            ignored_autonomy_level=ignored,
        )

    @staticmethod
    def _entry_from_simple(item: dict[str, Any], path: Path, location: str = "entry") -> InventoryEntry:
        if not isinstance(item, dict):
            raise _invalid(path, location, "expected an inventory mapping")
        _check_fields(item, _SIMPLE_FIELDS, path, location)
        for name in _SIMPLE_FIELDS - _LIST_FIELDS - {"autonomy_level"}:
            _optional_string(item, name, path, location)
        aid = item.get("id") or item.get("agent_id") or item.get("name")
        if not aid:
            raise _invalid(path, location, "id, agent_id, or name is required")
        lists = {name: _string_list(item, name, path, location) for name in _LIST_FIELDS}
        level = _autonomy_level(item, "autonomy_level", path, location)
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
            regions=lists["regions"],
            discriminators=lists["discriminators"],
            tags=lists["tags"],
            source=str(path),
            card=item,
            autonomy_level=level,
        )

    # --------------------------------------------------------------- match
    def match(self, finding: Finding, extra: Sequence[InventoryEntry] = ()) -> InventoryEntry | None:
        """Return one unambiguous, explicitly scoped resource approval.

        Case folding resource IDs can approve a different object (for example,
        a case-sensitive cloud ARN or repository path). Unknown scopes and
        conflicting inventory identities fail closed. A match on a gateway
        caller name whose identity is only operator-asserted or unverified is
        kept but flagged with ``metadata['registry_match_assurance']`` and the
        ``registry-identity-unverified`` tag.

        ``extra`` entries (approvals of trusted vendor registries for this run) are matched
        together with the loaded entries, so an approval in both places is ambiguous. They
        carry no names and produce no suggestions.
        """
        clear_match_state(finding)
        # Finding construction redacts credentials before reconciliation. A
        # lossy resource ID is not an identity: distinct repositories, URLs or
        # cloud objects can all become the same ".../[REDACTED]" string. Even
        # an explicitly authored wildcard must not approve such a finding.
        if not _has_usable_resource_identity(finding):
            finding.metadata["registry_match_reason"] = "redacted-or-missing-resource-identity"
            return None
        if not _has_usable_scope_identity(finding):
            finding.metadata["registry_match_reason"] = "redacted-scope-identity"
            return None
        if not has_aws_account_scope(finding.provider, finding.account, finding.resource):
            finding.metadata["registry_match_reason"] = "missing-aws-account-scope"
            return None
        if not has_google_workspace_account_scope(finding.provider, finding.account):
            finding.metadata["registry_match_reason"] = "missing-google-workspace-account-scope"
            return None
        if finding.metadata.get("identity_unresolved") is True:
            finding.metadata["registry_match_reason"] = "unresolved-resource-identity"
            return None
        matches = [
            entry
            for entry in (*self.entries, *extra)
            if self._scope_matches(entry, finding)
            and any(fnmatch.fnmatchcase(finding.resource or "", pattern) for pattern in entry.resources)
        ]
        if len(matches) == 1:
            finding.metadata.pop("registry_suggestions", None)
            assurance = _unauthenticated_caller_assurance(finding)
            if assurance:
                # Keep the documented match, but a caller name taken from a log
                # does not prove the caller is the registered agent: say so.
                finding.metadata["registry_match_assurance"] = assurance
                finding.add_tag(UNVERIFIED_IDENTITY_TAG)
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
            # Older generated cards omitted the tenant. A global OAuth client
            # resource cannot confer approval across unrelated customers.
            and (not requires_card_account_scope(finding.provider) or bool(entry.accounts))
            and (not entry.regions or finding.region in entry.regions)
            # Several observations can share one resource (a repository's
            # agent project and its coding-agent configuration). The stable
            # observation type keeps an approval to the one it names.
            and (not entry.discriminators or finding.identity_discriminator in entry.discriminators)
        )

    def _name_pattern(self, name: str) -> re.Pattern[str]:
        pattern = self._name_patterns.get(name)
        if pattern is None:
            pattern = self._name_patterns[name] = re.compile(rf"(?<![a-z0-9]){re.escape(name)}(?![a-z0-9])")
            if len(self._name_patterns) > _MAX_NAME_PATTERNS:
                self._name_patterns.popitem(last=False)
        else:
            self._name_patterns.move_to_end(name)
        return pattern

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
                pattern = self._name_pattern(n)
                if n in names or pattern.search(title) or pattern.search(res):
                    out.append(e)
                    break
        return out


class InventoryValidationError(SetupError, ValueError):
    """Malformed inventory cannot participate in approval or risk scoring.

    Messages name the file, the location inside it and a fixed reason; they
    are sanitized and safe to print verbatim.
    """


def _invalid(path: Path, location: str, message: str) -> InventoryValidationError:
    return InventoryValidationError(sanitize_text(f"invalid inventory {path}: {location}: {message}"))


_LIST_FIELDS = {
    "resources",
    "names",
    "aliases",
    "frameworks",
    "surfaces",
    "providers",
    "accounts",
    "regions",
    "discriminators",
    "tags",
}
_SIMPLE_FIELDS = _LIST_FIELDS | {"id", "agent_id", "name", "owner", "owner_team", "autonomy_level"}
_CSV_LEVEL = re.compile(r"[0-5]")
CARD_SCHEMA_VERSIONS = (1, 2)
IGNORED_AUTONOMY_LEVEL = "autonomy_profile.level ignored: card has no schema_version 2"


def _autonomy_level(value: dict, name: str, path: Path, location: str) -> int | None:
    """An optional declared autonomy level: an integer from 0 to 5 (booleans are not levels)."""
    level = value.get(name)
    if level is None:
        # Like an optional string, an omitted or null level declares nothing.
        return None
    if type(level) is not int or not 0 <= level <= 5:
        raise _invalid(path, f"{location}.{name}", "expected an integer from 0 to 5")
    return level


def _card_autonomy(doc: dict[str, Any], path: Path, location: str) -> tuple[int | None, bool]:
    """``(declared level, ignored)`` for a card: only schema_version 2 cards declare a level.

    Earlier cards used ``autonomy_profile.level`` on an undefined scale. Reading it on the
    L0-L5 scale could misstate a card, so it counts as undeclared and is reported.
    """
    version = doc.get("schema_version", 1)
    if type(version) is not int or version not in CARD_SCHEMA_VERSIONS:
        raise _invalid(path, f"{location}.schema_version", "unsupported card schema version; expected 1 or 2")
    profile = doc.get("autonomy_profile")
    if version == 1:
        return None, isinstance(profile, dict) and "level" in profile
    if profile is None:
        return None, False
    if not isinstance(profile, dict):
        raise _invalid(path, f"{location}.autonomy_profile", "expected a mapping")
    return _autonomy_level(profile, "level", path, f"{location}.autonomy_profile"), False


def _check_fields(value: dict, allowed: set[str], path: Path, location: str) -> None:
    if any(not isinstance(key, str) or key not in allowed for key in value):
        # Do not echo arbitrary unknown keys: they may themselves contain secrets.
        raise _invalid(path, location, "unsupported field; allowed fields: " + ", ".join(sorted(allowed)))


def _optional_string(value: dict, name: str, path: Path, location: str) -> None:
    if (
        name in value
        and value[name] is not None
        and (not isinstance(value[name], str) or not value[name].strip())
    ):
        raise _invalid(path, f"{location}.{name}", "expected a nonempty string")


def _first_string(value: dict, *names: str) -> str | None:
    return next((value[name].strip() for name in names if value.get(name)), None)


def _string_list(value: dict, name: str, path: Path, location: str) -> list[str]:
    if name not in value:
        return []
    items = value[name]
    if not isinstance(items, list) or any(not isinstance(item, str) or not item.strip() for item in items):
        raise _invalid(
            path, f"{location}.{name}", "expected a list of nonempty strings (quote numeric identifiers)"
        )
    if name == "resources" and any(_has_cite_marker(item) for item in items):
        # Citation markers in a resource pattern can silently turn a specific
        # approval into a glob if stripped. Require the author to correct it.
        raise _invalid(path, f"{location}.{name}", "citation marker in resource pattern")
    if name == "surfaces" and any(
        item.strip() not in {surface.value for surface in Surface} for item in items
    ):
        raise _invalid(path, f"{location}.{name}", "contains an unknown discovery surface")
    return [item.strip() for item in items]


_CITE = re.compile(r"\[cite(?:_start)?(?::[^\]]*)?\]")


def _has_cite_marker(text: str) -> bool:
    """Whether ``text`` holds a citation marker (``_CITE`` anywhere), in a single pass.

    ``_CITE.search`` rescans to the end of a long item from every ``[cite:`` that has no ``]``, which
    is quadratic in the length of a hostile approval pattern. Once no ``]`` follows a ``[cite:``, no
    later marker can close either, so the search ends there.
    """
    start = text.find("[cite")
    while start >= 0:
        after = start + len("[cite")
        if text.startswith("_start", after):
            after += len("_start")
        if text.startswith("]", after):
            return True
        if text.startswith(":", after):
            return text.find("]", after + 1) >= 0
        start = text.find("[cite", start + 1)
    return False


def _strip_cite_markers(text: str) -> str:
    """Ignore standalone export markers only before YAML content starts.

    A global substitution would broaden a quoted ``agent-[cite_start]*``
    resource approval to ``agent-*`` before the inventory parser could reject
    it. Even a marker alone at column zero can be part of a multiline YAML
    scalar; after the document begins, preserve every line for validation.
    """
    result: list[str] = []
    preamble = True
    for line in text.splitlines(keepends=True):
        if preamble and line == line.lstrip() and _CITE.fullmatch(line.strip()):
            result.append(line[len(line.rstrip("\r\n")) :])
            continue
        result.append(line)
        if line.strip() and not line.lstrip().startswith("#"):
            preamble = False
    return "".join(result)


def _stub_autonomy_level(finding: Finding) -> int | None:
    """The observed autonomy floor: the report's value when well formed, else recomputed."""
    recorded = finding.metadata.get("autonomy")
    if isinstance(recorded, dict) and valid_autonomy(recorded):
        return int(recorded["floor"])
    return observed_floor(finding)


def card_stub_for(finding: Finding) -> dict[str, Any]:
    """Generate an Agent Capability Card skeleton for a discovered agent (to register it).

    The card uses schema version 2 and declares the finding's observed autonomy floor, the
    lowest level its evidence proves. A reviewer raises it to the level the agent is approved for.
    """
    caps = finding.capabilities
    level = _stub_autonomy_level(finding)
    return {
        "schema_version": 2,
        "metadata": {
            "agent_id": _slug(
                finding.metadata.get("agent_name")
                or finding.metadata.get("name")
                or finding.title.split(":")[-1].strip()
            ),
            "version": "0.1.0",
            "owner_team": finding.owner or "UNKNOWN",
            "classification": "Internal",
            "discovered_by": "shadowscan",
            "discovered_as": finding.resource,
        },
        "autonomy_profile": {
            **({"level": level} if level is not None else {}),
            "memory_persistence": "memory" in caps,
            "max_loop_iterations": None,
            "velocity_limit": None,
        },
        "identity_and_delegation": {
            "spiffe_id": None,
            "auth_mechanism": None,
            "privileged_account": "policy.privileged-scopes" in finding.tags,
        },
        "capability_surface (Tools)": {"authorized_tools": [{"name": c} for c in caps]},
        "security_controls": {
            "egress_proxy_required": True,
            "sandbox_type": None,
            "kill_switch_enabled": False,
        },
        "risk_scoring": {"AARS_initial_score": finding.risk.score, "blast_radius": finding.risk.level.value},
        "discovery": {
            # The discovered ID is literal. Hand-authored resource entries may
            # still deliberately use wildcards; generated approvals never do.
            # Redacted resource or scope values can collide across objects.
            # Leave this approval unbound pending an exact, reviewed identity.
            "resources": []
            if not (
                _has_usable_resource_identity(finding)
                and _has_usable_scope_identity(finding)
                and _has_valid_account_scope(finding)
                and finding.metadata.get("identity_unresolved") is not True
                and _has_usable_discriminator(finding)
            )
            else [literal_resource_pattern(finding.resource)],
            "names": sorted({name.strip() for name in _metadata_names(finding) if name.strip()}),
            "frameworks": finding.frameworks,
            "surfaces": [finding.surface.value],
            "providers": [finding.provider] if finding.provider else [],
            "accounts": [finding.account] if finding.account else [],
            "regions": [finding.region] if finding.region else [],
            # Other findings can share this resource; approve this observation only.
            "discriminators": [finding.identity_discriminator] if _has_usable_discriminator(finding) else [],
        },
    }


def _slug(s: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", str(s).lower()).strip("-")
    return s[:64] or "agent"
