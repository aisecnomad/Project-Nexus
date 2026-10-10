"""MCP Registry snapshots: where configured MCP servers are published, and approved MCP catalogs.

``options.mcp_registries`` pins MCP Registry snapshots, each opted in by its own ``id``. A
snapshot is a file ``shadowscan mcp-registry snapshot`` wrote from a registry that serves the
MCP Registry API (the official registry, or an organisation's private one), pinned by the
SHA-256 of its bytes::

    {"schema": "shadowscan.mcp-registry-snapshot/v1",
     "registry": "https://registry.modelcontextprotocol.io",
     "api": "v0.1",
     "fetched_at": "2026-10-10T00:00:00Z",
     "complete": true,
     "servers": [<a ServerResponse of GET /v0.1/servers>, ...]}

The producer keeps of each listed server version only what matching reads (name, version,
packages, remote URLs and the official status, latest flag and publication time); a full
official listing is otherwise about three times larger. Other fields are accepted and
ignored. Every scan reads each snapshot again without following links, checks the pinned
digest, decodes strict JSON and validates every entry; nothing is fetched during a scan. Any
failure leaves that registry unused and the scan incomplete.

After correlation the engine matches every MCP server that a finding lists
(``metadata.servers``, or the ``metadata.server`` URL of an MCP tool finding) against each
loaded registry: by the package its launch names (registry type and normalized identifier),
then by remote URL (scheme and host lowercased, default port, query, fragment and trailing
``/`` dropped; templated URLs never match), then, for an MCP server manifest only, by its
registry name. An identifiable server gets ``registry``: one entry per registry that lists it,
sorted by registry id::

    {"registry": "official", "name": "io.github.acme/tool", "namespace": "io.github.acme",
     "match": "package", "configured_version": "1.2.0", "version_published": true,
     "latest_version": "1.3.0", "is_latest": false, "status": "active",
     "published_at": "2026-09-01T00:00:00Z", "ambiguous": false}

A package or URL that several registry names list is ``ambiguous``: the first name is shown and
nothing about versions or status is claimed. The finding gets ``metadata.mcp_registry``
(``registries`` loaded, ``approved_checked``, ``not_in_approved``) and review tags with
zero-weight evidence, which never lower risk. A registry marked ``approved`` is the
organisation's approved MCP catalog: when one is configured and every approved registry
loaded, ``not_in_approved`` counts the enabled, identifiable servers that no approved registry
lists, or lists only as deleted, and scoring adds the governance factor
``mcp-not-in-approved-registry``. Disabled servers are matched but add no tags and no count.
A server is ``mcp-unpublished`` only when every configured registry loaded. The pass first
removes what an earlier pass wrote, so it can run again on the same findings.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeGuard
from urllib.parse import urlsplit

from shadowscan.connectors.mcp_risk import PackageRef, registry_package, server_package
from shadowscan.models import Evidence, Finding, Kind
from shadowscan.utils.files import NotRegularFileError, changed_since, open_confined_file
from shadowscan.utils.safe_json import JSONIntegrityError, strict_json_loads

SNAPSHOT_SCHEMA = "shadowscan.mcp-registry-snapshot/v1"
API_VERSION = "v0.1"
DEFAULT_REGISTRY_URL = "https://registry.modelcontextprotocol.io"
OFFICIAL_META = "io.modelcontextprotocol.registry/official"
STATUSES = ("active", "deprecated", "deleted")
MAX_MCP_REGISTRIES = 16
MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024
MAX_SNAPSHOT_SERVERS = 500_000
PAGE_LIMIT = 100
MAX_PAGE_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_PAGES = 5000
METADATA_KEY = "mcp_registry"
SERVER_KEY = "registry"
# Where an MCP tool finding, which lists no servers, keeps its server's registry entries.
MATCHES_KEY = "matches"
EVIDENCE_PREFIX = "mcp-registry:"
MANIFEST_CLIENT = "MCP server manifest"
TAG_PUBLISHED = "mcp-registry-published"
TAG_UNPUBLISHED = "mcp-unpublished"
TAG_DEPRECATED = "mcp-registry-deprecated"
TAG_DELETED = "mcp-registry-deleted"
TAG_VERSION_UNPUBLISHED = "mcp-registry-version-unpublished"
TAG_OUTDATED = "mcp-registry-outdated"
REGISTRY_TAGS = (
    TAG_PUBLISHED,
    TAG_UNPUBLISHED,
    TAG_DEPRECATED,
    TAG_DELETED,
    TAG_VERSION_UNPUBLISHED,
    TAG_OUTDATED,
)
GOVERNANCE_FACTOR = "mcp-not-in-approved-registry"

_DESCRIPTIONS = {
    TAG_PUBLISHED: "{count} MCP server(s) listed in a configured MCP registry",
    TAG_UNPUBLISHED: "{count} enabled MCP server(s) listed in no configured MCP registry",
    TAG_DEPRECATED: "{count} MCP server(s) marked deprecated in an MCP registry",
    TAG_DELETED: "{count} MCP server(s) marked deleted in an MCP registry",
    TAG_VERSION_UNPUBLISHED: "{count} MCP server(s) pin a version their registry entry does not list",
    TAG_OUTDATED: "{count} MCP server(s) use a version or endpoint other than the registry's latest",
}
_SNAPSHOT_FIELDS = frozenset({"schema", "registry", "api", "fetched_at", "complete", "servers"})
_SERVER_NAME = re.compile(r"[a-zA-Z0-9.-]+/[a-zA-Z0-9._-]+\Z")
_MAX_NAME = 200
_MAX_VERSION = 255
_MAX_TIMESTAMP = 64
_MAX_TEXT = 2048
_MAX_ENTRY_ITEMS = 64
_MAX_CURSOR = 1024
# What a snapshot keeps of each listed server version: the fields matching reads.
_SERVER_FIELDS = ("name", "version")
_PACKAGE_FIELDS = ("registryType", "identifier", "version")
_REMOTE_FIELDS = ("type", "url")
_STATUS_FIELDS = ("status", "isLatest", "publishedAt")


class SnapshotError(ValueError):
    """A snapshot or registry listing that cannot be used; the message never quotes its content."""


@dataclass(frozen=True, slots=True)
class McpRegistrySource:
    """One pinned snapshot of ``options.mcp_registries``; ``approved`` marks an approved MCP catalog."""

    id: str
    snapshot: str
    sha256: str
    approved: bool = False


@dataclass(frozen=True, slots=True)
class _Entry:
    """One server version a registry lists."""

    name: str
    version: str
    status: str
    published_at: str | None
    is_latest: bool
    packages: tuple[PackageRef, ...]
    remotes: frozenset[str]


@dataclass(slots=True)
class RegistrySnapshot:
    """A validated snapshot, indexed by server name, package identity and remote URL."""

    source: McpRegistrySource
    registry: str
    fetched_at: str
    by_name: dict[str, list[_Entry]] = field(default_factory=dict)
    by_package: dict[tuple[str, str], set[str]] = field(default_factory=dict)
    by_remote: dict[str, set[str]] = field(default_factory=dict)
    # The one version marked latest; None when a name has no such version or several.
    latest: dict[str, _Entry | None] = field(default_factory=dict)

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.source.id,
            "sha256": self.source.sha256,
            "fetched_at": self.fetched_at,
            "approved": self.source.approved,
        }


@dataclass(frozen=True, slots=True)
class LoadedRegistries:
    """The snapshots one scan loaded and the registries that failed to load."""

    snapshots: tuple[RegistrySnapshot, ...] = ()
    errors: tuple[str, ...] = ()
    configured: int = 0
    approved_configured: int = 0

    @property
    def complete(self) -> bool:
        """Whether every configured registry loaded."""
        return len(self.snapshots) == self.configured

    @property
    def approved_checked(self) -> bool:
        """Whether an approved registry is configured and every approved registry loaded."""
        loaded = sum(snapshot.source.approved for snapshot in self.snapshots)
        return self.approved_configured > 0 and loaded == self.approved_configured


@dataclass(frozen=True, slots=True)
class _Identity:
    """What a configured server can be matched by."""

    package: PackageRef | None
    remotes: frozenset[str]
    name: str | None

    @property
    def known(self) -> bool:
        return self.package is not None or bool(self.remotes) or self.name is not None


# ---------------------------------------------------------------- snapshots


def load_registries(sources: Sequence[McpRegistrySource]) -> LoadedRegistries:
    """Load every configured snapshot; a registry that fails is reported and left out."""
    snapshots: list[RegistrySnapshot] = []
    errors: list[str] = []
    for source in sources:
        try:
            snapshots.append(load_snapshot(source))
        except SnapshotError as exc:
            errors.append(f"MCP registry {source.id}: {exc}; registry not used")
    return LoadedRegistries(
        snapshots=tuple(sorted(snapshots, key=lambda snapshot: snapshot.source.id)),
        errors=tuple(errors),
        configured=len(sources),
        approved_configured=sum(source.approved for source in sources),
    )


def load_snapshot(source: McpRegistrySource, *, max_bytes: int = MAX_SNAPSHOT_BYTES) -> RegistrySnapshot:
    """Read, verify and index one pinned snapshot; raise :class:`SnapshotError` on any problem."""
    raw = _read_snapshot(Path(os.path.abspath(source.snapshot)), max_bytes)
    if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), source.sha256):
        raise SnapshotError("snapshot SHA-256 does not match the pinned sha256")
    try:
        document = strict_json_loads(raw)
    except JSONIntegrityError:
        raise SnapshotError("snapshot has a duplicate field or a nonfinite number") from None
    except (ValueError, RecursionError):
        raise SnapshotError("snapshot is not valid JSON") from None
    # A full official listing is tens of megabytes: release the bytes before indexing.
    del raw
    return _index(source, document)


def _read_snapshot(path: Path, max_bytes: int) -> bytes:
    """The file's raw bytes, which the pin covers; no link in the path is followed."""
    try:
        with open_confined_file(path, label="MCP registry snapshot") as (stream, before):
            if before.st_size > max_bytes:
                raise SnapshotError("snapshot exceeds the byte limit")
            raw = stream.read(max_bytes + 1)
            if len(raw) > max_bytes:
                raise SnapshotError("snapshot exceeds the byte limit")
            if changed_since(before, stream.fileno()):
                raise SnapshotError("snapshot changed while it was read")
            return raw
    except SnapshotError:
        raise
    except NotRegularFileError:
        raise SnapshotError("snapshot is not a regular file") from None
    except (OSError, ValueError):
        # OSError text names the path; the message names the conditions instead.
        raise SnapshotError(
            "snapshot could not be read (missing, unreadable, or a symbolic link, which is not followed)"
        ) from None


def _index(source: McpRegistrySource, document: Any) -> RegistrySnapshot:
    if not isinstance(document, dict) or set(document) != _SNAPSHOT_FIELDS:
        raise SnapshotError(
            "snapshot must be an object with exactly the fields " + ", ".join(sorted(_SNAPSHOT_FIELDS))
        )
    if document["schema"] != SNAPSHOT_SCHEMA:
        raise SnapshotError("snapshot has an unknown schema")
    if document["api"] != API_VERSION:
        raise SnapshotError(f"snapshot is not of the registry API {API_VERSION}")
    if document["complete"] is not True:
        raise SnapshotError("snapshot is not complete")
    registry, fetched_at = document["registry"], document["fetched_at"]
    if not _text(registry) or not _text(fetched_at, _MAX_TIMESTAMP):
        raise SnapshotError("snapshot registry and fetched_at must be nonempty strings")
    servers = document["servers"]
    if not isinstance(servers, list):
        raise SnapshotError("snapshot servers must be a list")
    if len(servers) > MAX_SNAPSHOT_SERVERS:
        raise SnapshotError(f"snapshot lists more than {MAX_SNAPSHOT_SERVERS} server versions")
    snapshot = RegistrySnapshot(source, registry, fetched_at)
    seen: set[tuple[str, str]] = set()
    for number, item in enumerate(servers, 1):
        entry = _entry(item, f"server entry {number}")
        if (entry.name, entry.version) in seen:
            raise SnapshotError(f"server entry {number} repeats an earlier name and version")
        seen.add((entry.name, entry.version))
        snapshot.by_name.setdefault(entry.name, []).append(entry)
        for package in entry.packages:
            snapshot.by_package.setdefault((package.registry_type, package.identifier), set()).add(entry.name)
        for url in entry.remotes:
            snapshot.by_remote.setdefault(url, set()).add(entry.name)
    for name, entries in snapshot.by_name.items():
        latest = [entry for entry in entries if entry.is_latest]
        snapshot.latest[name] = latest[0] if len(latest) == 1 else None
    return snapshot


def _text(value: Any, limit: int = _MAX_TEXT) -> TypeGuard[str]:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= limit


def _entry(item: Any, where: str) -> _Entry:
    server = item.get("server") if isinstance(item, dict) else None
    meta = item.get("_meta") if isinstance(item, dict) else None
    official = meta.get(OFFICIAL_META) if isinstance(meta, dict) else None
    if not isinstance(server, dict) or not isinstance(official, dict):
        raise SnapshotError(f"{where} must have a server and official registry metadata")
    name, version = server.get("name"), server.get("version")
    if not isinstance(name, str) or len(name) > _MAX_NAME or not _SERVER_NAME.match(name):
        raise SnapshotError(f"{where} has a missing or invalid name")
    if not _text(version, _MAX_VERSION):
        raise SnapshotError(f"{where} has a missing or invalid version")
    status, is_latest, published = (
        official.get("status"),
        official.get("isLatest"),
        official.get("publishedAt"),
    )
    if not isinstance(status, str) or status not in STATUSES:
        raise SnapshotError(f"{where} has an unknown status")
    if type(is_latest) is not bool:
        raise SnapshotError(f"{where} has an invalid isLatest flag")
    if published is not None and not _text(published, _MAX_TIMESTAMP):
        raise SnapshotError(f"{where} has an invalid publishedAt")
    return _Entry(
        name=name,
        version=version,
        status=status,
        published_at=published,
        is_latest=is_latest,
        packages=_packages(server.get("packages"), where),
        remotes=_remotes(server.get("remotes"), where),
    )


def _packages(value: Any, where: str) -> tuple[PackageRef, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or len(value) > _MAX_ENTRY_ITEMS:
        raise SnapshotError(f"{where} has an invalid packages list")
    refs: list[PackageRef] = []
    for package in value:
        kind = package.get("registryType") if isinstance(package, dict) else None
        identifier = package.get("identifier") if isinstance(package, dict) else None
        version = package.get("version") if isinstance(package, dict) else None
        if (
            not _text(kind)
            or not _text(identifier)
            or (version is not None and not _text(version, _MAX_VERSION))
        ):
            raise SnapshotError(f"{where} has an invalid package")
        ref = registry_package(kind, identifier, version)
        if ref is not None:
            refs.append(ref)
    return tuple(refs)


def _remotes(value: Any, where: str) -> frozenset[str]:
    if value is None:
        return frozenset()
    if not isinstance(value, list) or len(value) > _MAX_ENTRY_ITEMS:
        raise SnapshotError(f"{where} has an invalid remotes list")
    urls: set[str] = set()
    for remote in value:
        url = remote.get("url") if isinstance(remote, dict) else None
        if not _text(url):
            raise SnapshotError(f"{where} has an invalid remote")
        normalized = normalize_remote(url)
        if normalized is not None:
            urls.add(normalized)
    return frozenset(urls)


def normalize_remote(url: Any) -> str | None:
    """A comparable form of an MCP endpoint URL; None for a template or a URL that is not HTTP(S).

    The scheme and host are lowercased, a default port, user information, the query, the
    fragment and a trailing ``/`` are dropped; the path is compared as written.
    """
    if not isinstance(url, str) or "{" in url or "}" in url:
        return None
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError:
        return None
    scheme, host = parts.scheme.lower(), parts.hostname
    if scheme not in {"http", "https"} or not host:
        return None
    if ":" in host:
        host = f"[{host}]"
    netloc = host if port is None or port == (443 if scheme == "https" else 80) else f"{host}:{port}"
    return f"{scheme}://{netloc}{parts.path.rstrip('/')}"


# ---------------------------------------------------------------- matching


def _identity(server: dict[str, Any], *, manifest: bool) -> _Identity:
    raw_urls = server.get("urls")
    urls = [url for url in raw_urls if isinstance(url, str)] if isinstance(raw_urls, list) else []
    if isinstance(server.get("url"), str):
        urls.append(server["url"])
    name = server.get("name")
    if not (manifest and isinstance(name, str) and len(name) <= _MAX_NAME and _SERVER_NAME.match(name)):
        name = None
    return _Identity(
        package=server_package(server),
        remotes=frozenset(filter(None, map(normalize_remote, urls))),
        name=name,
    )


def _package_version(entry: _Entry, key: tuple[str, str]) -> str | None:
    return next(
        (p.version for p in entry.packages if (p.registry_type, p.identifier) == key and p.version), None
    )


def _newest(entries: list[_Entry]) -> _Entry:
    return max(entries, key=lambda entry: (entry.published_at or "", entry.version))


def _is_among(entry: _Entry | None, entries: list[_Entry]) -> bool:
    return entry is not None and any(candidate is entry for candidate in entries)


def _match(identity: _Identity, snapshot: RegistrySnapshot) -> tuple[dict[str, Any], bool] | None:
    """The registry entry for one server and whether the registry lists it other than as deleted."""
    package = identity.package
    names: set[str] = set()
    how = ""
    if package is not None:
        names, how = set(snapshot.by_package.get((package.registry_type, package.identifier), ())), "package"
    if not names and identity.remotes:
        names, how = {name for url in identity.remotes for name in snapshot.by_remote.get(url, ())}, "remote"
    if not names and identity.name is not None and identity.name in snapshot.by_name:
        names, how = {identity.name}, "name"
    if not names:
        return None
    ordered = sorted(names)
    name = ordered[0]
    block: dict[str, Any] = {
        "registry": snapshot.source.id,
        "name": name,
        "namespace": name.split("/", 1)[0],
        "match": how,
        "configured_version": package.version if how == "package" and package is not None else None,
        "version_published": None,
        "latest_version": None,
        "is_latest": None,
        "status": None,
        "published_at": None,
        "ambiguous": len(ordered) > 1,
    }
    if block["ambiguous"]:
        listed = any(entry.status != "deleted" for other in ordered for entry in snapshot.by_name[other])
        return block, listed
    entries = snapshot.by_name[name]
    latest = snapshot.latest.get(name)
    if how == "package" and package is not None:
        key = (package.registry_type, package.identifier)
        carrying = [entry for entry in entries if _lists(entry, key)]
        latest_version = _package_version(latest, key) if latest is not None else None
        known = {version for entry in carrying if (version := _package_version(entry, key))}
        exact = [
            entry
            for entry in carrying
            if package.version is not None and _package_version(entry, key) == package.version
        ]
        if package.version is not None and known:
            block["version_published"] = bool(exact)
        if exact:
            selected = latest if latest is not None and _is_among(latest, exact) else _newest(exact)
        else:
            selected = latest if latest is not None and _is_among(latest, carrying) else _newest(carrying)
        if package.version is not None and latest_version is not None:
            block["is_latest"] = package.version == latest_version
        block["latest_version"] = latest_version
    elif how == "remote":
        carrying = [entry for entry in entries if entry.remotes & identity.remotes]
        selected = latest if latest is not None and _is_among(latest, carrying) else _newest(carrying)
        if latest is not None:
            block["is_latest"] = _is_among(latest, carrying)
            block["latest_version"] = latest.version
    else:
        selected = latest if latest is not None else _newest(entries)
        block["latest_version"] = latest.version if latest is not None else None
    block["status"] = selected.status
    block["published_at"] = selected.published_at
    return block, selected.status != "deleted"


def _lists(entry: _Entry, key: tuple[str, str]) -> bool:
    return any((p.registry_type, p.identifier) == key for p in entry.packages)


def _server_tags(blocks: list[dict[str, Any]]) -> set[str]:
    if not blocks:
        return {TAG_UNPUBLISHED}
    tags = {TAG_PUBLISHED}
    for block in blocks:
        if block["ambiguous"]:
            continue
        if block["status"] == "deprecated":
            tags.add(TAG_DEPRECATED)
        elif block["status"] == "deleted":
            tags.add(TAG_DELETED)
        if block["version_published"] is False:
            tags.add(TAG_VERSION_UNPUBLISHED)
        elif block["is_latest"] is False:
            tags.add(TAG_OUTDATED)
    return tags


def _clear(finding: Finding) -> None:
    """Remove what an earlier pass, or a connector imitating one, wrote."""
    finding.metadata.pop(METADATA_KEY, None)
    if finding.kind == Kind.MCP_SERVER:
        servers = finding.metadata.get("servers")
        for server in servers if isinstance(servers, list) else ():
            if isinstance(server, dict):
                server.pop(SERVER_KEY, None)
    finding.tags[:] = [tag for tag in finding.tags if tag not in REGISTRY_TAGS]
    finding.evidence[:] = [
        ev
        for ev in finding.evidence
        if not (isinstance(ev.signal, str) and ev.signal.startswith(EVIDENCE_PREFIX))
    ]


def _targets(finding: Finding) -> list[tuple[dict[str, Any] | None, _Identity, bool]] | None:
    """Each server of an MCP finding: its record (None for a tool finding), identity and disabled state."""
    metadata = finding.metadata
    servers = metadata.get("servers")
    if isinstance(servers, list):
        manifest = metadata.get("client") == MANIFEST_CLIENT
        return [
            (server, _identity(server, manifest=manifest), bool(server.get("disabled")))
            for server in servers
            if isinstance(server, dict)
        ]
    server, tool = metadata.get("server"), metadata.get("tool")
    if isinstance(server, str) and isinstance(tool, str):
        remote = normalize_remote(server)
        return [(None, _Identity(None, frozenset({remote}) if remote else frozenset(), None), False)]
    return None


def enrich_mcp_findings(findings: Iterable[Finding], registries: LoadedRegistries) -> list[str]:
    """Match the MCP servers of ``findings`` against the loaded registries; return error messages."""
    failed = 0
    for finding in findings:
        _clear(finding)
        if not registries.configured or finding.kind != Kind.MCP_SERVER:
            continue
        try:
            _enrich(finding, registries)
        except (AttributeError, TypeError, ValueError):
            # A finding whose server records cannot be matched is left without registry data.
            _clear(finding)
            failed += 1
    return [f"MCP registry matching failed on {failed} finding(s)"] if failed else []


def _enrich(finding: Finding, registries: LoadedRegistries) -> None:
    targets = _targets(finding)
    if targets is None:
        return
    tally: dict[str, int] = {}
    not_in_approved = 0
    matches: list[dict[str, Any]] | None = None
    for server, identity, disabled in targets:
        if not identity.known or not registries.snapshots:
            continue
        blocks: list[dict[str, Any]] = []
        in_approved = False
        for snapshot in registries.snapshots:
            matched = _match(identity, snapshot)
            if matched is not None:
                blocks.append(matched[0])
                in_approved = in_approved or (matched[1] and snapshot.source.approved)
        if server is not None:
            server[SERVER_KEY] = blocks
        else:
            matches = blocks
        if disabled:
            continue
        tags = _server_tags(blocks)
        if not registries.complete:
            # A registry that failed to load may list the server.
            tags.discard(TAG_UNPUBLISHED)
        for tag in tags:
            tally[tag] = tally.get(tag, 0) + 1
        if registries.approved_checked and not in_approved:
            not_in_approved += 1
    block: dict[str, Any] = {
        "registries": [snapshot.summary() for snapshot in registries.snapshots],
        "approved_checked": registries.approved_checked,
        "not_in_approved": not_in_approved,
    }
    if matches is not None:
        block[MATCHES_KEY] = matches
    finding.metadata[METADATA_KEY] = block
    for tag in REGISTRY_TAGS:
        if tag in tally:
            finding.add_tag(tag)
            finding.add_evidence(
                Evidence(
                    signal=EVIDENCE_PREFIX + tag,
                    description=_DESCRIPTIONS[tag].format(count=tally[tag]),
                    weight=0.0,
                )
            )


# ---------------------------------------------------------------- producer


def registry_base_url(url: str, *, allow_private_origin: bool = False) -> str:
    """Validate a registry origin for the snapshot producer: HTTPS, no credentials, query or fragment."""
    from shadowscan.utils.http import validate_url

    try:
        parts = urlsplit(url)
    except ValueError:
        raise SnapshotError("registry URL is invalid") from None
    if parts.query or parts.fragment:
        raise SnapshotError("registry URL must not have a query or fragment")
    try:
        validate_url(url, allow_private=allow_private_origin)
    except ValueError as exc:
        # validate_url messages are fixed text that never quotes the URL.
        raise SnapshotError(f"registry URL rejected: {exc}") from None
    return url.rstrip("/")


def _pick(value: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    return {key: value[key] for key in fields if key in value}


def _project(item: dict[str, Any]) -> dict[str, Any]:
    """One listed server version reduced to the fields matching reads, in the ServerResponse shape.

    Descriptions, icons, arguments and environment and header definitions are dropped, which keeps
    a full listing about a third of its size. A field of the wrong shape is kept as listed, so the
    validation that follows rejects it.
    """
    server, meta = item.get("server"), item.get("_meta")
    official = meta.get(OFFICIAL_META) if isinstance(meta, dict) else None
    if not isinstance(server, dict) or not isinstance(official, dict):
        return item
    projected = _pick(server, _SERVER_FIELDS)
    for key, fields in (("packages", _PACKAGE_FIELDS), ("remotes", _REMOTE_FIELDS)):
        value = server.get(key)
        if isinstance(value, list):
            projected[key] = [_pick(part, fields) if isinstance(part, dict) else part for part in value]
        elif key in server:
            projected[key] = value
    return {"server": projected, "_meta": {OFFICIAL_META: _pick(official, _STATUS_FIELDS)}}


def _compact(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _listing_page(page: Any) -> tuple[list[dict[str, Any]], str | None]:
    """The servers of one listing page and its continuation cursor (None on the last page)."""
    if not isinstance(page, dict) or "error" in page or "errors" in page:
        raise SnapshotError("registry returned an invalid page")
    items, metadata = page.get("servers"), page.get("metadata")
    if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
        raise SnapshotError("registry returned an invalid page")
    if (
        not isinstance(metadata, dict)
        or type(metadata.get("count")) is not int
        or metadata["count"] != len(items)
    ):
        raise SnapshotError("registry page count does not match its servers")
    cursor = metadata.get("nextCursor")
    if cursor is None or cursor == "":
        return items, None
    if not isinstance(cursor, str) or not cursor.strip() or len(cursor) > _MAX_CURSOR:
        raise SnapshotError("registry returned an invalid pagination cursor")
    return items, cursor


def fetch_snapshot(
    url: str = DEFAULT_REGISTRY_URL,
    *,
    max_pages: int = DEFAULT_MAX_PAGES,
    ca_bundle: str | None = None,
    allow_private_origin: bool = False,
) -> str:
    """List every server version of a registry (deleted ones included) as snapshot text.

    The listing is complete or nothing is returned: a failed request, an invalid page, a
    repeated cursor, more than ``max_pages`` pages or the byte and entry limits raise
    :class:`SnapshotError`. The result is validated as a scan would validate it.
    """
    from shadowscan.utils.http import HttpClient, HttpError

    base = registry_base_url(url, allow_private_origin=allow_private_origin)
    client = HttpClient(
        base_url=base,
        ca_bundle=ca_bundle,
        allow_private_origin=allow_private_origin,
        max_response_bytes=MAX_PAGE_BYTES,
    )
    servers: list[dict[str, Any]] = []
    size = 0
    seen: set[str] = set()
    cursor: str | None = None
    try:
        for _ in range(max_pages):
            params = {"limit": str(PAGE_LIMIT), "include_deleted": "true"}
            if cursor is not None:
                params["cursor"] = cursor
            try:
                page = client.get_json(f"{API_VERSION}/servers", params=params)
            except HttpError as exc:
                raise SnapshotError(f"registry request failed (HTTP {exc.status})") from None
            except Exception as exc:  # noqa: BLE001 - transport and parser text can quote the response
                raise SnapshotError(f"registry request failed ({type(exc).__name__})") from None
            items, cursor = _listing_page(page)
            for item in map(_project, items):
                size += len(_compact(item)) + 1
                if size > MAX_SNAPSHOT_BYTES:
                    raise SnapshotError("registry listing exceeds the snapshot byte limit")
                servers.append(item)
            if len(servers) > MAX_SNAPSHOT_SERVERS:
                raise SnapshotError(f"registry listing has more than {MAX_SNAPSHOT_SERVERS} server versions")
            if cursor is None:
                break
            if cursor in seen:
                raise SnapshotError("registry repeated a pagination cursor")
            seen.add(cursor)
        else:
            raise SnapshotError(f"registry listing has more than {max_pages} page(s)")
    finally:
        client.session.close()
    document = {
        "schema": SNAPSHOT_SCHEMA,
        "registry": base,
        "api": API_VERSION,
        "fetched_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "complete": True,
        "servers": servers,
    }
    text = _compact(document) + "\n"
    if len(text) > MAX_SNAPSHOT_BYTES:
        raise SnapshotError("registry listing exceeds the snapshot byte limit")
    _index(McpRegistrySource(id="snapshot", snapshot="", sha256=""), document)
    return text
