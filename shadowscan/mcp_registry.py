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
packages with their registry, remote URLs and the official status, latest flag and
publication time); a full official listing is otherwise about three times larger. Other
fields are accepted and ignored. Every scan reads each snapshot again without following
links, checks the pinned digest, decodes strict JSON and validates every entry's structure,
name, version and status; nothing is fetched during a scan. Any failure leaves that registry
unused and the scan incomplete. A package or remote URL that nothing configured could match
(a URL that is templated, carries user information or does not parse; a package on another
registry than its type's public one) is not indexed, and its entry is otherwise kept.

After correlation the engine matches every MCP server that a finding lists
(``metadata.servers``, or the ``metadata.server`` URL of an MCP tool finding) against each
loaded registry, by what the client fetches or connects to: for a command, the package its
launch names (registry type and normalized identifier); for a URL, the URL (scheme and host
lowercased, default port, query, fragment and trailing ``/`` dropped); for an MCP server
manifest (a ``server.json`` document), every package and remote it declares, which one
registry name must list together. One identity is chosen and never falls back to another. A
server that has none (a local path or a launcher run from one, a shell command line, a
launcher option, environment variable, working directory, environment file or container
mount that can change what is fetched or run, both a command and a URL, a URL with user
information) is unidentified; a manifest's own name then gives provenance hints only. An
identified or named server gets ``registry``: one entry per registry that lists it, sorted
by registry id::

    {"registry": "official", "name": "io.github.acme/tool", "namespace": "io.github.acme",
     "match": "package", "configured_version": "1.2.0", "version_published": true,
     "latest_version": "1.3.0", "is_latest": false, "status": "active",
     "published_at": "2026-09-01T00:00:00Z", "ambiguous": false}

A package or URL that several registry names list is ``ambiguous``: the first name is shown and
nothing about versions or status is claimed. The finding gets ``metadata.mcp_registry``
(``registries`` loaded, ``approved_checked``, ``not_in_approved``, ``unidentified``) and review
tags with zero-weight evidence, which never lower risk. A registry marked ``approved`` is the
organisation's approved MCP catalog: when one is configured and every approved registry
loaded, ``not_in_approved`` counts the enabled servers that no approved registry lists by their
identity, or lists only as deleted in the version they are matched to (for an ambiguous one,
under every name that lists it), unidentified servers included (an allowlist cannot vouch
for what it cannot identify), and scoring adds the governance factor
``mcp-not-in-approved-registry``. Disabled servers are matched but add no tags and no count.
A server is ``mcp-unpublished`` only when every configured registry loaded. The pass first
removes what an earlier pass wrote, so it can run again on the same findings.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
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
TAG_PUBLISHED = "mcp-registry-published"
TAG_UNPUBLISHED = "mcp-unpublished"
TAG_DEPRECATED = "mcp-registry-deprecated"
TAG_DELETED = "mcp-registry-deleted"
TAG_VERSION_UNPUBLISHED = "mcp-registry-version-unpublished"
TAG_OUTDATED = "mcp-registry-outdated"
TAG_UNIDENTIFIED = "mcp-registry-unidentified"
REGISTRY_TAGS = (
    TAG_PUBLISHED,
    TAG_UNPUBLISHED,
    TAG_DEPRECATED,
    TAG_DELETED,
    TAG_VERSION_UNPUBLISHED,
    TAG_OUTDATED,
    TAG_UNIDENTIFIED,
)
GOVERNANCE_FACTOR = "mcp-not-in-approved-registry"

_DESCRIPTIONS = {
    TAG_PUBLISHED: "{count} MCP server(s) listed in a configured MCP registry",
    TAG_UNPUBLISHED: "{count} enabled MCP server(s) listed in no configured MCP registry",
    TAG_DEPRECATED: "{count} MCP server(s) marked deprecated in an MCP registry",
    TAG_DELETED: "{count} MCP server(s) marked deleted in an MCP registry",
    TAG_VERSION_UNPUBLISHED: "{count} MCP server(s) pin a version their registry entry does not list",
    TAG_OUTDATED: "{count} MCP server(s) use a version or endpoint other than the registry's latest",
    TAG_UNIDENTIFIED: "{count} enabled MCP server(s) whose package or endpoint could not be identified",
}
_SNAPSHOT_FIELDS = frozenset({"schema", "registry", "api", "fetched_at", "complete", "servers"})
_SERVER_NAME = re.compile(r"[a-zA-Z0-9.-]+/[a-zA-Z0-9._-]+\Z")
_MAX_NAME = 200
_MAX_VERSION = 255
_MAX_TIMESTAMP = 64
_MAX_TEXT = 2048
_MAX_CURSOR = 1024
# What a snapshot keeps of each listed server version: the fields matching reads.
_SERVER_FIELDS = ("name", "version")
_PACKAGE_FIELDS = ("registryType", "identifier", "version", "registryBaseUrl")
_REMOTE_FIELDS = ("type", "url")
_STATUS_FIELDS = ("status", "isLatest", "publishedAt")
_URL_PARTS = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]*)([^?#]*)")
# A host as written: no user information, escape, bracket, port separator, space or control.
_URL_HOST = re.compile(r"[^\x00-\x20\x7f\\/@\[\]:?#%]+")
_PORT = re.compile(r"[0-9]{1,5}")
# Transport values that start a command, and those that connect to a URL (letters only, lowercased).
_STDIO_TRANSPORTS = frozenset({"stdio", "local"})
_REMOTE_TRANSPORTS = frozenset({"http", "https", "sse", "streamablehttp", "remote", "ws", "wss", "websocket"})


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
    """What a configured server is matched by.

    ``packages`` and ``remotes`` are what the client fetches or connects to: one package for a
    command, every URL of a remote transport, every package and remote of a server manifest.
    ``name`` is a manifest's own registry name: provenance hints, never approved membership.
    """

    packages: tuple[PackageRef, ...] = ()
    remotes: tuple[str, ...] = ()
    name: str | None = None

    @property
    def known(self) -> bool:
        return bool(self.packages or self.remotes)


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


def _optional_string(value: Any) -> TypeGuard[str | None]:
    return value is None or isinstance(value, str)


def _packages(value: Any, where: str) -> tuple[PackageRef, ...]:
    """The packages a launch can be matched to; the structure is checked, the values are not limited.

    A package that names nothing a launch fetches, or that lives on another registry than its
    type's public one (``registryBaseUrl``), is left out: no configured launch can match it.
    """
    if value is None:
        return ()
    if not isinstance(value, list):
        raise SnapshotError(f"{where} has an invalid packages list")
    refs: list[PackageRef] = []
    for package in value:
        if not isinstance(package, dict):
            raise SnapshotError(f"{where} has an invalid package")
        kind, identifier = package.get("registryType"), package.get("identifier")
        version, base = package.get("version"), package.get("registryBaseUrl")
        if not isinstance(kind, str) or not isinstance(identifier, str):
            raise SnapshotError(f"{where} has an invalid package")
        if not _optional_string(version) or not _optional_string(base):
            raise SnapshotError(f"{where} has an invalid package")
        ref = registry_package(kind, identifier, version if version and version.strip() else None, base)
        if ref is not None:
            refs.append(ref)
    return tuple(refs)


def _remotes(value: Any, where: str) -> frozenset[str]:
    """The remote URLs a configured URL can be matched to; one that cannot be compared is left out."""
    if value is None:
        return frozenset()
    if not isinstance(value, list):
        raise SnapshotError(f"{where} has an invalid remotes list")
    urls: set[str] = set()
    for remote in value:
        url = remote.get("url") if isinstance(remote, dict) else None
        if not isinstance(url, str):
            raise SnapshotError(f"{where} has an invalid remote")
        normalized = normalize_remote(url)
        if normalized is not None:
            urls.add(normalized)
    return frozenset(urls)


def normalize_remote(url: Any) -> str | None:
    """A comparable form of an MCP endpoint URL; None when the URL cannot be compared.

    The scheme and host are lowercased; a default port, the query, the fragment and a trailing
    ``/`` are dropped; the path is compared as written. A template, a URL that is not HTTP(S)
    and a URL with user information give None. Configuration parsing redacts user information,
    and what it hid can name another host to the client (``https://evil.example\\@host/`` reaches
    ``evil.example``), so such a URL never matches a listed endpoint.
    """
    if not isinstance(url, str) or "{" in url or "}" in url:
        return None
    parts = _URL_PARTS.match(url.strip())
    if parts is None or parts.group(1).lower() not in {"http", "https"}:
        return None
    scheme, (host, port) = parts.group(1).lower(), _host_port(parts.group(2))
    if host is None:
        return None
    netloc = host if port is None or port == (443 if scheme == "https" else 80) else f"{host}:{port}"
    return f"{scheme}://{netloc}{parts.group(3).rstrip('/')}"


def _host_port(authority: str) -> tuple[str | None, int | None]:
    """The lowercased host and the port of a URL authority; no host when it is not a plain one."""
    if authority.startswith("["):
        end = authority.find("]")
        try:
            ipaddress.IPv6Address(authority[1:end] if end > 0 else "")
        except ValueError:
            return None, None
        host, rest = f"[{authority[1:end].lower()}]", authority[end + 1 :]
        if rest and not rest.startswith(":"):
            return None, None
        port = rest[1:]
    else:
        host, _, port = authority.partition(":")
        if not _URL_HOST.fullmatch(host):
            return None, None
        host = host.lower()
    if not port:
        return host, None
    if not _PORT.fullmatch(port) or int(port) > 65535:
        return None, None
    return host, int(port)


# ---------------------------------------------------------------- matching


def _identity(server: dict[str, Any]) -> _Identity:
    """What a parsed server record is matched by: what its client fetches or connects to."""
    declared = server.get("packages")
    if isinstance(declared, list):
        return _manifest_identity(server, declared)
    command, url = server.get("command"), server.get("url")
    has_command = isinstance(command, str) and bool(command.strip())
    has_url = isinstance(url, str) and bool(url.strip())
    transport = server.get("transport")
    kind = re.sub(r"[^a-z]", "", transport.lower()) if isinstance(transport, str) else ""
    if has_command and has_url:
        # Clients differ on which one they use (some ignore the transport), so whatever the
        # transport says, neither is surely what the client runs or connects to.
        return _Identity()
    if has_command and kind not in _REMOTE_TRANSPORTS:
        package = server_package(server)
        return _Identity(packages=(package,) if package is not None else ())
    if has_url and kind not in _STDIO_TRANSPORTS:
        # Every endpoint the record lists (its URL, then each ``remotes[]`` entry) is one the
        # client may reach, so each must be listed; one that cannot be compared leaves none.
        listed = server.get("urls")
        endpoints = listed if isinstance(listed, list) and listed else [url]
        remotes = [normalize_remote(endpoint) for endpoint in endpoints]
        if any(remote is None for remote in remotes):
            return _Identity()
        return _Identity(remotes=tuple(dict.fromkeys(filter(None, remotes))))
    # A command declared as a remote transport, or a URL declared as a local one.
    return _Identity()


def _manifest_identity(server: dict[str, Any], declared: list[Any]) -> _Identity:
    """Every package and remote an MCP server manifest declares; none when one cannot be compared."""
    name = server.get("name")
    named = name if isinstance(name, str) and len(name) <= _MAX_NAME and _SERVER_NAME.match(name) else None
    packages: list[PackageRef] = []
    for package in declared:
        ref = _manifest_package(package) if isinstance(package, dict) else None
        if ref is None:
            return _Identity(name=named)
        packages.append(ref)
    raw_urls = server.get("urls")
    remotes = [normalize_remote(url) for url in raw_urls] if isinstance(raw_urls, list) else []
    if any(remote is None for remote in remotes):
        return _Identity(name=named)
    return _Identity(tuple(packages), tuple(dict.fromkeys(filter(None, remotes))), named)


def _manifest_package(package: dict[str, Any]) -> PackageRef | None:
    kind, identifier = package.get("registry_type"), package.get("identifier")
    version, base = package.get("version"), package.get("registry_base_url")
    if not isinstance(kind, str) or not isinstance(identifier, str):
        return None
    if not _optional_string(version) or not _optional_string(base):
        return None
    return registry_package(kind, identifier, version or None, base)


def _package_version(entry: _Entry, key: tuple[str, str]) -> str | None:
    return next(
        (p.version for p in entry.packages if (p.registry_type, p.identifier) == key and p.version), None
    )


def _newest(entries: list[_Entry]) -> _Entry:
    return max(entries, key=lambda entry: (entry.published_at or "", entry.version))


def _is_among(entry: _Entry | None, entries: list[_Entry]) -> bool:
    return entry is not None and any(candidate is entry for candidate in entries)


def _select(
    snapshot: RegistrySnapshot, name: str, how: str, package: PackageRef | None, remotes: frozenset[str]
) -> tuple[_Entry, list[_Entry], list[_Entry]]:
    """The version of ``name`` a server is matched to, the versions that list the server's
    identity, and those that list its pinned package version.

    The matched version is the registry's latest when it lists the pinned version (or, without
    one, the identity), else the newest version that does.
    """
    entries = snapshot.by_name[name]
    latest = snapshot.latest.get(name)
    exact: list[_Entry] = []
    if how == "package" and package is not None:
        key = (package.registry_type, package.identifier)
        carrying = [entry for entry in entries if _lists(entry, key)]
        if package.version is not None:
            exact = [entry for entry in carrying if _package_version(entry, key) == package.version]
    elif how == "remote":
        carrying = [entry for entry in entries if entry.remotes & remotes]
    else:
        carrying = entries
    pool = exact or carrying
    selected = latest if latest is not None and _is_among(latest, pool) else _newest(pool)
    return selected, carrying, exact


def _match(identity: _Identity, snapshot: RegistrySnapshot) -> tuple[dict[str, Any], bool] | None:
    """The registry entry for one server and whether the registry lists it, other than as deleted,
    by its identity; a name match lists nothing."""
    package = identity.packages[0] if identity.packages else None
    if identity.known:
        # One registry name must list every package and remote the server is identified by.
        listing = [snapshot.by_package.get((p.registry_type, p.identifier), set()) for p in identity.packages]
        listing += [snapshot.by_remote.get(url, set()) for url in identity.remotes]
        names, how = set.intersection(*(set(names) for names in listing)), "package" if package else "remote"
    elif identity.name is not None and identity.name in snapshot.by_name:
        names, how = {identity.name}, "name"
    else:
        return None
    if not names:
        return None
    remotes = frozenset(identity.remotes)
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
        # Which name the server is cannot be told: it is listed when one of them lists it, other
        # than as deleted, in the version it would be matched to were that name the only one.
        listed = any(
            _select(snapshot, other, how, package, remotes)[0].status != "deleted" for other in ordered
        )
        return block, listed and how != "name"
    selected, carrying, exact = _select(snapshot, name, how, package, remotes)
    latest = snapshot.latest.get(name)
    if how == "package" and package is not None:
        key = (package.registry_type, package.identifier)
        latest_version = _package_version(latest, key) if latest is not None else None
        known = {version for entry in carrying if (version := _package_version(entry, key))}
        if package.version is not None and known:
            block["version_published"] = bool(exact)
        if package.version is not None and latest_version is not None:
            block["is_latest"] = package.version == latest_version
        block["latest_version"] = latest_version
    elif how == "remote":
        if latest is not None:
            block["is_latest"] = _is_among(latest, carrying)
            block["latest_version"] = latest.version
    else:
        block["latest_version"] = latest.version if latest is not None else None
    block["status"] = selected.status
    block["published_at"] = selected.published_at
    return block, selected.status != "deleted" and how != "name"


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
        return [
            (server, _identity(server), bool(server.get("disabled")))
            for server in servers
            if isinstance(server, dict)
        ]
    server, tool = metadata.get("server"), metadata.get("tool")
    if isinstance(server, str) and isinstance(tool, str):
        remote = normalize_remote(server)
        return [(None, _Identity(remotes=(remote,) if remote else ()), False)]
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
    not_in_approved = unidentified = 0
    matches: list[dict[str, Any]] | None = None
    for server, identity, disabled in targets:
        if not registries.snapshots:
            continue
        blocks: list[dict[str, Any]] = []
        in_approved = False
        if identity.known or identity.name is not None:
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
        if identity.known:
            tags = _server_tags(blocks)
            if not registries.complete:
                # A registry that failed to load may list the server.
                tags.discard(TAG_UNPUBLISHED)
        else:
            unidentified += 1
            tags = (_server_tags(blocks) if blocks else set()) | {TAG_UNIDENTIFIED}
        for tag in tags:
            tally[tag] = tally.get(tag, 0) + 1
        # An unidentified server is never in an approved catalog: an allowlist cannot vouch for it.
        if registries.approved_checked and not in_approved:
            not_in_approved += 1
    block: dict[str, Any] = {
        "registries": [snapshot.summary() for snapshot in registries.snapshots],
        "approved_checked": registries.approved_checked,
        "not_in_approved": not_in_approved,
        "unidentified": unidentified,
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
