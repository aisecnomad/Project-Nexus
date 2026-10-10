"""Endpoint inventory: AI tools, agents and models installed on developer workstations.

``endpoint.inventory`` reads a fixed list of documented user-scope locations
below one or more home directories (see :mod:`.catalog`):

* AI client and agent configurations (Claude Desktop, Claude Code, Cursor,
  VS Code, Windsurf, Gemini CLI, Codex, Kiro, Amazon Q, Continue, Goose,
  Cline, Roo Code, Aider, OpenClaw, LM Studio), with their MCP servers, the
  servers' static risks and the agent's posture;
* AI editor extensions in VS Code, VS Code Server, VSCodium, Cursor and
  Windsurf extension directories;
* AI browser extensions in Chrome, Chromium, Edge, Brave and Firefox profiles,
  matched by product name;
* local model stores (Ollama, LM Studio, the Hugging Face hub cache, GPT4All,
  Jan);
* opt-in: AI command-line tools named in shell history, kept as tool names and
  counts only.

Offline, ``input`` replays records exported with ``--dump-records`` or reads
osquery results from the ``vscode_extensions``, ``chrome_extensions`` and
``firefox_addons`` tables, so a fleet can be inventoried without running
ShadowScan on each laptop.

Every file and directory is opened without following a symbolic link in any
component. A link, an unreadable location or an exhausted entry budget is a
coverage gap that marks the scan incomplete; a location that does not exist
is not. File contents never enter a record: MCP server entries are the
configuration parser's sanitized projection, browser extensions are recorded
only when their name matches an AI product, and shell history keeps counts.
"""

from __future__ import annotations

import errno
import json
import os
import re
import socket
import stat
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, ClassVar

import yaml

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError, _positive_limit
from shadowscan.connectors.code.mcp_config import _parse_mcp_servers
from shadowscan.connectors.common import config_boolean, finalize
from shadowscan.connectors.endpoint.catalog import (
    AI_EXTENSION_NAME,
    CHROMIUM_USER_DATA,
    CONFIG_LOCATIONS,
    FIREFOX_PROFILE_DIRS,
    IDE_EXTENSION_DIRS,
    IDE_EXTENSIONS,
    MODEL_FILE_SUFFIXES,
    MODEL_STORES,
    SHELL_HISTORY_FILES,
    SHELL_TOOLS,
    ConfigLocation,
    ModelStore,
)
from shadowscan.connectors.mcp_risk import record_server_risks
from shadowscan.connectors.posture import (
    POSTURE_DESCRIPTIONS,
    approval_settings,
    posture_client,
    record_approval,
    record_posture,
    unreadable_settings,
    valid_approval,
)
from shadowscan.connectors.posture import assess as assess_posture
from shadowscan.connectors.posture import parseable as posture_parseable
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.utils.files import NotRegularFileError, open_confined_directory, open_confined_file
from shadowscan.utils.jsonc import load_json_lenient
from shadowscan.utils.safe_yaml import strict_bounded_safe_load

DEFAULT_MAX_ENTRIES = 50_000
MAX_CONFIG_BYTES = 1024 * 1024
MAX_CLAUDE_STATE_BYTES = 8 * 1024 * 1024  # ~/.claude.json also holds per-project history
MAX_MANIFEST_BYTES = 512 * 1024
MAX_FIREFOX_ADDONS_BYTES = 8 * 1024 * 1024
MAX_HISTORY_BYTES = 8 * 1024 * 1024
MAX_LISTED_MODELS = 50
_EXTENSION_VERSION = re.compile(
    r"^(?P<id>[a-z0-9][a-z0-9-]*\.[a-z0-9][a-z0-9._-]*?)-(?P<version>\d[\w.+-]*)$"
)
_ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_RECORD_TYPES = {"agent_config", "ide_extension", "browser_extension", "local_model", "shell_history"}
# Internal marker on a replayed record that lost approval or posture entries; never exported.
_GATE_INCOMPLETE = "_approval_entries_dropped"
_OWN_STRINGS = (
    "device", "home", "client", "product", "signature", "location", "editor", "extension_id", "version",
    "browser", "profile", "name", "runtime", "provider", "shell", "tool",
)  # fmt: skip
_OWN_REQUIRED: dict[str, tuple[str, ...]] = {
    "agent_config": ("client",),
    "ide_extension": ("extension_id",),
    "browser_extension": ("extension_id", "name"),
    "local_model": ("runtime",),
    "shell_history": ("tool",),
}


class _Gap(Exception):
    """A location that exists but cannot be read safely."""


@dataclass
class _Home:
    """One home directory being inventoried."""

    ref: str  # account name shown in resources and as owner
    fd: int
    entries: int = 0
    exhausted: bool = False
    # Relative paths that could not be read or parsed at all (not a problem inside a file that
    # was read): a settings file among them may loosen its client's approval gate.
    unread: set[str] = field(default_factory=set)


@dataclass
class _Group:
    """Records for one finding before it is built."""

    records: list[dict[str, Any]] = field(default_factory=list)


# Links a running Chromium browser keeps in its user-data directory (the
# process-singleton lock, cookie and socket, and the macOS running-version
# marker). They are never followed and hold no profile or extension.
_CHROMIUM_OWN_LINKS = frozenset(
    {"SingletonLock", "SingletonCookie", "SingletonSocket", "RunningChromeVersion"}
)


class EndpointInventoryConnector(BaseConnector):
    name: ClassVar[str] = "endpoint.inventory"
    surface: ClassVar[Surface] = Surface.ENDPOINT
    provider: ClassVar[str | None] = "endpoint"
    description: ClassVar[str] = (
        "AI clients, agent configurations, MCP servers, editor and browser extensions and local models "
        "in home directories (or osquery exports)."
    )
    config_keys: ClassVar[dict[str, str]] = {
        "path": "home directory to inventory (default: the home directory of the user running the scan)",
        "paths": "list of home directories to inventory instead of `path`",
        "label": "device label used in resource ids and titles (default: the host name)",
        "shell_history": (
            "read shell history for AI command-line tools; only tool names and counts are kept "
            "(default false)"
        ),
        "max_entries": (
            f"maximum directory entries examined per home directory (default {DEFAULT_MAX_ENTRIES:,})"
        ),
        "input": (
            "offline: records exported with --dump-records, or osquery results from the vscode_extensions, "
            "chrome_extensions and firefox_addons tables"
        ),
    }
    offline_formats: ClassVar[str] = "JSON / JSONL (exported endpoint records or osquery results)"

    @classmethod
    def scanned_local_paths(cls, config: dict[str, Any]) -> list[str]:
        if config.get("input"):
            return []
        paths = config.get("paths")
        if isinstance(paths, list):
            return [str(p) for p in paths if isinstance(p, str)]
        path = config.get("path")
        return [str(path)] if isinstance(path, str) else []

    def __init__(self, ctx: ConnectorContext) -> None:
        super().__init__(ctx)
        self.label = str(ctx.get("label") or socket.gethostname() or "endpoint")
        self.shell_history = config_boolean(ctx.get("shell_history", False), "shell_history")
        self.max_entries = _positive_limit(ctx.get("max_entries", DEFAULT_MAX_ENTRIES), "max_entries")
        paths = ctx.get("paths")
        path = ctx.get("path")
        if paths is not None and path is not None:
            raise ConnectorError("endpoint.inventory: set either path or paths, not both")
        if paths is not None:
            if (
                not isinstance(paths, list)
                or not paths
                or not all(isinstance(p, str) and p.strip() for p in paths)
            ):
                raise ConnectorError("endpoint.inventory: paths must be a non-empty list of directories")
            self.homes = [str(p) for p in paths]
        elif path is not None:
            if not isinstance(path, str) or not path.strip():
                raise ConnectorError("endpoint.inventory: path must be a directory")
            self.homes = [path]
        else:
            self.homes = [str(Path.home())]

    # ------------------------------------------------------------------ collect
    def collect(self) -> Iterable[dict[str, Any]]:
        for raw in self.homes:
            home_path = Path(os.path.expanduser(raw)).absolute()
            try:
                fd = open_confined_directory(home_path)
            except (OSError, ValueError) as exc:
                self.ctx.error(
                    f"endpoint.inventory: cannot open home directory {home_path.name!r}: {_reason(exc)}"
                )
                continue
            home = _Home(ref=home_path.name or "root", fd=fd)
            try:
                yield from self._home_records(home)
            finally:
                os.close(fd)

    def _home_records(self, home: _Home) -> Iterator[dict[str, Any]]:
        base = {"device": self.label, "home": home.ref}
        configs = [
            {**base, **record}
            for record in (self._config_record(home, loc) for loc in CONFIG_LOCATIONS)
            if record is not None
        ]
        # A settings file that could not be read may loosen its client's approval gate: each of
        # the client's records carries an entry that keeps the gate partial, also on replay.
        unread = {
            client: f"~/{rel}"
            for rel in sorted(home.unread)
            if (client := posture_client(rel)) is not None and client != "openclaw"
        }
        for record in configs:
            client = record.get("client")
            if isinstance(client, str) and client in unread:
                entry = {**unreadable_settings(client).as_dict(), "file": unread[client]}
                record["approval"] = [*record.get("approval", []), entry]
        yield from configs
        for rec in self._ide_extensions(home):
            yield {**base, **rec}
        for rec in self._browser_extensions(home):
            yield {**base, **rec}
        for store in MODEL_STORES:
            model_record = self._model_store(home, store)
            if model_record is not None:
                yield {**base, **model_record}
        if self.shell_history:
            for rec in self._shell_history(home):
                yield {**base, **rec}
        if home.exhausted:
            self.ctx.warn(
                f"endpoint.inventory: entry budget ({self.max_entries:,}) exhausted in home {home.ref!r}; "
                "raise max_entries to inventory the rest"
            )

    # ------------------------------------------------------- safe file access
    def _gap(self, home: _Home, rel: str, reason: str, *, unread: bool = True) -> None:
        if unread:
            home.unread.add(rel)
        self.ctx.warn(f"endpoint.inventory: ~{home.ref}/{rel} not read: {reason}")

    def _open_dir(self, home: _Home, rel: str) -> int | None:
        """Open a directory below the home without following links; None when it does not exist."""
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        current = home.fd
        owned = False
        try:
            for part in PurePosixPath(rel).parts:
                child = os.open(part, flags, dir_fd=current)
                if owned:
                    os.close(current)
                current, owned = child, True
        except FileNotFoundError:
            if owned:
                os.close(current)
            return None
        except OSError as exc:
            if owned:
                os.close(current)
            if exc.errno == errno.ENOTDIR and not self._link_in_path(home, rel):
                return None
            self._gap(home, rel, "symbolic link not followed" if exc.errno == errno.ENOTDIR else _reason(exc))
            return None
        return current if owned else os.dup(current)

    @staticmethod
    def _link_in_path(home: _Home, rel: str) -> bool:
        """Whether a component of ``rel`` is a symbolic link (Linux reports such a component as ENOTDIR).

        Each prefix is examined without following its last component, and only
        after every shorter prefix was found to be a real directory, so no link
        is ever traversed.
        """
        parts = PurePosixPath(rel).parts
        for i in range(1, len(parts) + 1):
            try:
                st = os.stat(str(PurePosixPath(*parts[:i])), dir_fd=home.fd, follow_symlinks=False)
            except OSError:
                return False
            if stat.S_ISLNK(st.st_mode):
                return True
            if not stat.S_ISDIR(st.st_mode):
                return False
        return False

    def _list(
        self, home: _Home, rel: str, ignore_links: frozenset[str] = frozenset()
    ) -> list[tuple[str, str]] | None:
        """``(name, kind)`` entries of a directory, kind ``dir``, ``file`` or ``other``; links are skipped.

        A skipped link is a coverage gap unless its name is in ``ignore_links``:
        links an application keeps for itself that hold no inventory data.
        """
        fd = self._open_dir(home, rel)
        if fd is None:
            return None
        out: list[tuple[str, str]] = []
        links = 0
        try:
            with os.scandir(fd) as it:
                for entry in it:
                    if home.entries >= self.max_entries:
                        home.exhausted = True
                        break
                    home.entries += 1
                    self.ctx.examined()
                    if entry.is_symlink():
                        links += entry.name not in ignore_links
                        continue
                    kind = (
                        "dir"
                        if entry.is_dir(follow_symlinks=False)
                        else ("file" if entry.is_file(follow_symlinks=False) else "other")
                    )
                    out.append((entry.name, kind))
        except OSError as exc:
            self._gap(home, rel, _reason(exc))
            return None
        finally:
            os.close(fd)
        if links:
            self._gap(home, rel, f"{links} symbolic link(s) not followed")
        return sorted(out)

    def _read(self, home: _Home, rel: str, limit: int, *, tail: bool = False) -> str | None:
        """Text of a regular file below the home; None when it does not exist."""
        try:
            with open_confined_file(PurePosixPath(rel), label="endpoint file", dir_fd=home.fd) as (
                stream,
                st,
            ):
                if st.st_size > limit and not tail:
                    raise _Gap(f"larger than {limit:,} bytes")
                if st.st_size > limit:
                    stream.seek(st.st_size - limit)
                data = stream.read(limit + 1)
        except FileNotFoundError:
            return None
        except NotRegularFileError:
            self._gap(home, rel, "not a regular file")
            return None
        except _Gap as exc:
            self._gap(home, rel, str(exc))
            return None
        except (OSError, ValueError) as exc:
            not_dir = isinstance(exc, OSError) and exc.errno == errno.ENOTDIR
            if not_dir and not self._link_in_path(home, rel):
                return None
            self._gap(home, rel, "symbolic link not followed" if not_dir else _reason(exc))
            return None
        self.ctx.examined()
        if tail and st.st_size > limit:
            # Tools used only in the older part of the history are not counted.
            self._gap(home, rel, f"only the last {limit:,} bytes read")
        return data[:limit].decode("utf-8", errors="replace")

    # -------------------------------------------------------- config locations
    def _config_record(self, home: _Home, loc: ConfigLocation) -> dict[str, Any] | None:
        record: dict[str, Any] = {
            "record_type": "agent_config",
            "client": loc.client,
            "product": loc.product,
            "signature": loc.signature,
            "location": f"~/{loc.path}",
        }
        if loc.directory:
            entries = self._list(home, loc.path)
            if not entries:
                return None
            record["entry_count"] = len(entries)
            return record
        limit = MAX_CLAUDE_STATE_BYTES if loc.path == ".claude.json" else MAX_CONFIG_BYTES
        text = self._read(home, loc.path, limit)
        if text is None:
            return None
        # A settings file that does not parse cannot show its posture or approval settings.
        parsed = posture_parseable(loc.path, text)
        if loc.mcp:
            errors: list[str] = []
            record["mcp_servers"] = _mcp_servers(loc, text, errors)
            if errors:
                # A problem with one server entry does not make the file's settings unreadable.
                self._gap(home, loc.path, f"MCP configuration problem: {errors[0]}", unread=not parsed)
            elif not parsed:
                self._gap(home, loc.path, "invalid configuration syntax")
        elif not parsed:
            self._gap(home, loc.path, "invalid configuration syntax")
        issues = assess_posture(loc.path, text)
        if issues:
            record["posture"] = [{**issue.as_dict(), "file": f"~/{loc.path}"} for issue in issues]
        approvals = approval_settings(loc.path, text)
        if approvals:
            record["approval"] = [{**setting.as_dict(), "file": f"~/{loc.path}"} for setting in approvals]
        return record

    # ---------------------------------------------------------- IDE extensions
    def _ide_extensions(self, home: _Home) -> Iterator[dict[str, Any]]:
        for rel, editor in IDE_EXTENSION_DIRS.items():
            for name, kind in self._list(home, rel) or []:
                if kind != "dir":
                    continue
                match = _EXTENSION_VERSION.match(name.lower())
                if not match or match.group("id") not in IDE_EXTENSIONS:
                    continue
                yield {
                    "record_type": "ide_extension",
                    "editor": editor,
                    "extension_id": match.group("id"),
                    "version": match.group("version"),
                    "location": f"~/{rel}/{name}",
                }

    # ------------------------------------------------------ browser extensions
    def _browser_extensions(self, home: _Home) -> Iterator[dict[str, Any]]:
        for user_data, browser in CHROMIUM_USER_DATA.items():
            for profile, kind in self._list(home, user_data, _CHROMIUM_OWN_LINKS) or []:
                if kind != "dir":
                    continue
                ext_root = f"{user_data}/{profile}/Extensions"
                for ext_id, ext_kind in self._list(home, ext_root) or []:
                    if ext_kind != "dir":
                        continue
                    versions = [v for v, k in self._list(home, f"{ext_root}/{ext_id}") or [] if k == "dir"]
                    if not versions:
                        continue
                    version_dir = f"{ext_root}/{ext_id}/{max(versions, key=_version_key)}"
                    name = self._chromium_name(home, version_dir)
                    if name and AI_EXTENSION_NAME.search(name):
                        yield {
                            "record_type": "browser_extension",
                            "browser": browser,
                            "profile": profile,
                            "extension_id": ext_id,
                            "name": name,
                            "version": version_dir.rsplit("/", 1)[-1].split("_", 1)[0],
                        }
        for profiles_dir in FIREFOX_PROFILE_DIRS:
            for profile, kind in self._list(home, profiles_dir) or []:
                if kind != "dir":
                    continue
                text = self._read(home, f"{profiles_dir}/{profile}/extensions.json", MAX_FIREFOX_ADDONS_BYTES)
                for addon in _firefox_addons(text):
                    yield {**addon, "browser": "Firefox", "profile": profile}

    def _chromium_name(self, home: _Home, version_dir: str) -> str | None:
        manifest = _json_object(self._read(home, f"{version_dir}/manifest.json", MAX_MANIFEST_BYTES))
        if manifest is None:
            return None
        name = manifest.get("name")
        if not isinstance(name, str):
            return None
        message = re.fullmatch(r"__MSG_(\w+)__", name.strip())
        if message is None:
            return name.strip()[:200]
        locale = manifest.get("default_locale") if isinstance(manifest.get("default_locale"), str) else "en"
        messages = _json_object(
            self._read(home, f"{version_dir}/_locales/{locale}/messages.json", MAX_MANIFEST_BYTES)
        )
        if messages is None:
            return None
        key = message.group(1).lower()
        for msg_key, value in messages.items():
            if (
                str(msg_key).lower() == key
                and isinstance(value, dict)
                and isinstance(value.get("message"), str)
            ):
                return str(value["message"]).strip()[:200]
        return None

    # ------------------------------------------------------------ model stores
    def _model_store(self, home: _Home, store: ModelStore) -> dict[str, Any] | None:
        if not self._open_dir_exists(home, store.path):
            return None
        if store.layout == "ollama":
            models = self._ollama_models(home, store.path)
        elif store.layout == "hf-hub":
            models = [
                name[len("models--") :].replace("--", "/", 1)
                for name, kind in self._list(home, store.path) or []
                if kind == "dir" and name.startswith("models--")
            ]
        else:
            models = self._model_files(home, store.path, depth=4)
        if not models:
            return None
        return {
            "record_type": "local_model",
            "runtime": store.runtime,
            "product": store.product,
            "provider": store.provider,
            "location": f"~/{store.path}",
            "model_count": len(models),
            "models": sorted(models)[:MAX_LISTED_MODELS],
        }

    def _open_dir_exists(self, home: _Home, rel: str) -> bool:
        fd = self._open_dir(home, rel)
        if fd is None:
            return False
        os.close(fd)
        return True

    def _ollama_models(self, home: _Home, root: str) -> list[str]:
        models: list[str] = []
        for registry, k1 in self._list(home, root) or []:
            if k1 != "dir":
                continue
            for namespace, k2 in self._list(home, f"{root}/{registry}") or []:
                if k2 != "dir":
                    continue
                for model, k3 in self._list(home, f"{root}/{registry}/{namespace}") or []:
                    if k3 != "dir":
                        continue
                    prefix = model if namespace == "library" else f"{namespace}/{model}"
                    for tag, k4 in self._list(home, f"{root}/{registry}/{namespace}/{model}") or []:
                        if k4 == "file":
                            models.append(f"{prefix}:{tag}")
        return models

    def _model_files(self, home: _Home, rel: str, depth: int) -> list[str]:
        found: list[str] = []
        for name, kind in self._list(home, rel) or []:
            if kind == "file" and name.lower().endswith(MODEL_FILE_SUFFIXES):
                found.append(name)
            elif kind == "dir" and depth > 1 and not name.startswith("."):
                found += self._model_files(home, f"{rel}/{name}", depth - 1)
        return found

    # ------------------------------------------------------------ shell history
    def _shell_history(self, home: _Home) -> Iterator[dict[str, Any]]:
        for rel, shell in SHELL_HISTORY_FILES.items():
            text = self._read(home, rel, MAX_HISTORY_BYTES, tail=True)
            if text is None:
                continue
            counts: dict[str, int] = {}
            for line in text.splitlines():
                tool = _history_tool(line, shell)
                if tool is not None:
                    counts[tool] = counts.get(tool, 0) + 1
            for tool, count in sorted(counts.items()):
                yield {"record_type": "shell_history", "shell": shell, "tool": tool, "count": count}

    # ------------------------------------------------------------------ analyze
    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        groups: dict[tuple[str, ...], _Group] = {}
        history: list[dict[str, Any]] = []
        unknown = 0
        # (device, home, client) groups that lost a whole malformed agent_config record; None
        # stands for a record whose group could not be read, which leaves every group partial.
        lost_gates: set[tuple[str, str, str] | None] = set()
        for raw in records:
            self.ctx.examined()
            rec = self._normalize(raw)
            if rec is None:
                unknown += 1
                continue
            if rec.get("ignored"):
                if rec.get("malformed") and rec.get("record_type") == "agent_config":
                    lost_gates.add(rec.get("gate_group"))
                continue  # a malformed record, or an inventory row for a product that is not an AI tool
            kind = rec["record_type"]
            if kind == "shell_history":
                history.append(rec)
                continue
            if kind == "agent_config":
                key: tuple[str, ...] = (kind, rec["device"], rec["home"], str(rec.get("client")))
            elif kind == "ide_extension":
                key = (kind, rec["device"], rec["home"], str(rec.get("extension_id")))
            elif kind == "browser_extension":
                key = (
                    kind,
                    rec["device"],
                    rec["home"],
                    str(rec.get("browser")),
                    str(rec.get("extension_id")),
                )
            else:
                key = (kind, rec["device"], rec["home"], str(rec.get("runtime")))
            groups.setdefault(key, _Group()).records.append(rec)
        if unknown:
            self.ctx.warn(
                f"endpoint.inventory: skipped {unknown} record(s) that are neither endpoint records nor "
                "osquery vscode_extensions, chrome_extensions or firefox_addons rows"
            )
        findings: list[Finding] = []
        for key, group in groups.items():
            kind = key[0]
            if kind == "agent_config":
                lost = None in lost_gates or (key[1], key[2], key[3]) in lost_gates
                findings += self._client_findings(group.records, gate_complete=not lost)
            elif kind == "ide_extension":
                findings.append(self._extension_finding(group.records))
            elif kind == "browser_extension":
                findings.append(self._browser_finding(group.records))
            else:
                findings.append(self._model_finding(group.records))
        findings += self._history_findings(history, findings)
        yield from findings

    def _normalize(self, raw: dict[str, Any]) -> dict[str, Any] | None:
        """Our own records pass through; osquery rows become records; anything else is None."""
        # Type checks come first: an unhashable value from an export must not raise.
        if isinstance(raw.get("record_type"), str) and raw["record_type"] in _RECORD_TYPES:
            if not self._record_fields_valid(
                raw,
                strings=_OWN_STRINGS,
                arrays=("mcp_servers", "posture", "approval", "models"),
                required=_OWN_REQUIRED[str(raw["record_type"])],
            ) or not all(isinstance(raw.get(k, 0), int) for k in ("count", "model_count", "entry_count")):
                self.ctx.warn("endpoint.inventory: skipped a malformed endpoint record")
                skipped = {"record_type": raw["record_type"], "ignored": True, "malformed": True}
                if raw["record_type"] == "agent_config":
                    # The skipped settings file could have loosened its client's approval gate.
                    who = (raw.get("device", self.label), raw.get("home", "unknown"), raw.get("client"))
                    skipped["gate_group"] = who if all(isinstance(v, str) for v in who) else None
                return skipped
            rec = dict(raw)
            rec.setdefault("device", self.label)
            rec.setdefault("home", "unknown")
            servers = list(rec.get("mcp_servers") or [])
            posture = list(rec.get("posture") or [])
            approvals = list(rec.get("approval") or [])
            models = list(rec.get("models") or [])
            rec["mcp_servers"] = [s for s in servers if _valid_server(s)]
            rec["posture"] = [
                p
                for p in posture
                if isinstance(p, dict)
                and isinstance(p.get("id"), str)
                and p["id"] in POSTURE_DESCRIPTIONS
                and all(isinstance(p.get(k), str) for k in ("client", "setting", "value"))
            ]
            # An approval entry this scanner would not have written for this record's settings
            # file is dropped (and reported): it can never gate an action.
            rec["approval"] = [
                a for a in approvals if valid_approval(a, client=rec.get("client"), file=rec.get("location"))
            ]
            rec["models"] = [m for m in models if isinstance(m, str)]
            dropped = (
                len(servers)
                - len(rec["mcp_servers"])
                + len(posture)
                - len(rec["posture"])
                + len(approvals)
                - len(rec["approval"])
                + len(models)
                - len(rec["models"])
            )
            if dropped:
                self.ctx.warn(
                    f"endpoint.inventory: dropped {dropped} malformed server, posture, approval or model "
                    f"entr{'y' if dropped == 1 else 'ies'} from a {rec['record_type']} record"
                )
            # A dropped approval or posture entry could have loosened the gate, so what is left
            # cannot show that every action is approved.
            rec[_GATE_INCOMPLETE] = len(posture) != len(rec["posture"]) or len(approvals) != len(
                rec["approval"]
            )
            return rec
        nested = raw.get("columns")
        columns: dict[str, Any] = nested if isinstance(nested, dict) else raw
        device = str(raw.get("hostIdentifier") or raw.get("host_identifier") or self.label)
        path = str(columns.get("path") or "")
        username = columns.get("username")
        home = (
            (username.strip() if isinstance(username, str) else "")
            or _home_from_path(path)
            or (f"uid-{columns['uid']}" if columns.get("uid") not in (None, "") else "unknown")
        )
        base = {"device": device, "home": home}
        if "browser_type" in columns and "identifier" in columns:
            name = str(columns.get("name") or "")
            if not AI_EXTENSION_NAME.search(name):
                return {**base, "record_type": "browser_extension", "ignored": True}
            return {
                **base,
                "record_type": "browser_extension",
                "browser": str(columns.get("browser_type")).title(),
                "profile": str(columns.get("profile") or ""),
                "extension_id": str(columns.get("identifier")),
                "name": name[:200],
                "version": str(columns.get("version") or ""),
            }
        if "identifier" in columns and "creator" in columns:  # firefox_addons
            name = str(columns.get("name") or "")
            if str(columns.get("type") or "extension") != "extension" or not AI_EXTENSION_NAME.search(name):
                return {**base, "record_type": "browser_extension", "ignored": True}
            return {
                **base,
                "record_type": "browser_extension",
                "browser": "Firefox",
                "profile": "",
                "extension_id": str(columns.get("identifier")),
                "name": name[:200],
                "version": str(columns.get("version") or ""),
            }
        if "publisher" in columns and ("uuid" in columns or "vscode_edition" in columns):
            ext_id = _osquery_extension_id(columns)
            if ext_id not in IDE_EXTENSIONS:
                return {**base, "record_type": "ide_extension", "ignored": True}
            return {
                **base,
                "record_type": "ide_extension",
                "editor": str(columns.get("vscode_edition") or "VS Code"),
                "extension_id": ext_id,
                "version": str(columns.get("version") or ""),
                "location": path,
            }
        return None

    # --------------------------------------------------------------- findings
    def _finding(self, kind: Kind, rec: dict[str, Any], category: str, key: str, title: str) -> Finding:
        return Finding(
            surface=Surface.ENDPOINT,
            connector=self.name,
            kind=kind,
            title=f"{title} on {rec['device']} (~{rec['home']})",
            resource=f"endpoint:{rec['device']}:{rec['home']}:{category}:{key}",
            resource_type=category,
            provider="endpoint",
            account=str(rec["device"]),
            owner=str(rec["home"]),
        )

    def _signature_capabilities(self, f: Finding, signature: str | None) -> None:
        if not signature:
            return
        sig = self.index.get(signature)
        if sig is None:
            return
        f.add_framework(signature)
        for capability in sig.capabilities:
            f.add_capability(capability)

    def _client_findings(self, records: list[dict[str, Any]], *, gate_complete: bool = True) -> list[Finding]:
        first = records[0]
        client, product = str(first.get("client")), str(first.get("product") or first.get("client"))
        signature = next((r.get("signature") for r in records if r.get("signature")), None)
        locations = sorted({str(r.get("location")) for r in records})
        out: list[Finding] = []
        kind = Kind.AGENT_CONFIG if signature else Kind.AI_APP
        f = self._finding(kind, first, "agent-config", client, f"{product} configured")
        self._signature_capabilities(f, signature)
        f.metadata.update({"client": product, "files": locations})
        for loc in locations:
            f.add_evidence(
                Evidence(
                    signal=f"endpoint:config:{client}",
                    description=f"{product} configuration at {loc}",
                    location=loc,
                    weight=0.9,
                    signature=signature,
                )
            )
        posture = [p for r in records for p in r.get("posture") or [] if isinstance(p, dict)]
        if posture:
            record_posture(f, posture)
        record_approval(
            f,
            [a for r in records for a in r.get("approval") or [] if isinstance(a, dict)],
            complete=gate_complete and not any(r.get(_GATE_INCOMPLETE) for r in records),
        )
        f.kind = kind
        out.append(finalize(f, self.index))
        # Each server keeps the file it came from, so its risks cite that file.
        servers = [
            {**s, "location": str(s.get("location") or r.get("location") or "")}
            for r in records
            for s in r.get("mcp_servers") or []
            if isinstance(s, dict)
        ]
        if servers:
            out.append(self._mcp_finding(first, client, product, servers, locations))
        return out

    def _mcp_finding(
        self,
        rec: dict[str, Any],
        client: str,
        product: str,
        servers: list[dict[str, Any]],
        locations: list[str],
    ) -> Finding:
        f = self._finding(Kind.MCP_SERVER, rec, "mcp-config", client, f"MCP servers configured for {product}")
        f.add_framework("protocol.mcp")
        f.add_capability("tool-use")
        # The file that holds the servers, not the client's first location (an instructions file).
        location = next((str(s["location"]) for s in servers if s.get("location")), locations[0])
        f.add_evidence(
            Evidence(
                signal="endpoint:mcp-config",
                description=f"{len(servers)} MCP server(s) configured for {product}",
                location=location,
                weight=0.95,
                signature="protocol.mcp",
            )
        )
        remote: list[str] = []
        for server in servers:
            record_server_risks(f, server, str(server.get("location") or location))
            urls = server.get("urls") if isinstance(server.get("urls"), list) else []
            for url in urls or ([server["url"]] if isinstance(server.get("url"), str) else []):
                if isinstance(url, str) and url not in remote:
                    remote.append(url)
        enabled = [s for s in servers if not s.get("disabled")]
        f.metadata.update(
            {
                "client": product,
                "servers": servers,
                "server_count": len(enabled),
                "disabled_server_count": len(servers) - len(enabled),
                "remote_urls": remote,
                "files": locations,
            }
        )
        if not enabled:
            f.add_tag("declared-disabled")
            f.metadata["disabled"] = True
        f.kind = Kind.MCP_SERVER
        return finalize(f, self.index)

    def _extension_finding(self, records: list[dict[str, Any]]) -> Finding:
        first = records[0]
        ext_id = str(first.get("extension_id"))
        product = IDE_EXTENSIONS.get(ext_id)
        name = product.product if product else ext_id
        kind = Kind.AGENT_CONFIG if product and product.agentic else Kind.AI_APP
        f = self._finding(kind, first, "ide-extension", ext_id, f"AI editor extension installed: {name}")
        if product:
            self._signature_capabilities(f, product.signature)
            if product.agentic:
                f.add_capability("tool-use")
        editors = sorted({str(r.get("editor")) for r in records if r.get("editor")})
        f.metadata.update(
            {
                "extension_id": ext_id,
                "product": name,
                "editors": editors,
                "versions": sorted({str(r.get("version")) for r in records if r.get("version")}),
            }
        )
        for r in records:
            f.add_evidence(
                Evidence(
                    signal=f"endpoint:ide-extension:{ext_id}",
                    description=f"{name} extension ({ext_id} {r.get('version') or ''}) in {r.get('editor')}",
                    location=str(r.get("location") or ""),
                    weight=0.9,
                    signature=product.signature if product else None,
                )
            )
        f.kind = kind
        return finalize(f, self.index)

    def _browser_finding(self, records: list[dict[str, Any]]) -> Finding:
        first = records[0]
        name = str(first.get("name") or first.get("extension_id"))
        f = self._finding(
            Kind.AI_APP,
            first,
            "browser-extension",
            f"{str(first.get('browser')).lower()}:{first.get('extension_id')}",
            f"AI browser extension installed: {name} ({first.get('browser')})",
        )
        f.metadata.update(
            {
                "browser": first.get("browser"),
                "extension_id": first.get("extension_id"),
                "extension_name": name,
                "profiles": sorted({str(r.get("profile")) for r in records if r.get("profile")}),
                "versions": sorted({str(r.get("version")) for r in records if r.get("version")}),
            }
        )
        f.add_evidence(
            Evidence(
                signal="endpoint:browser-extension:ai-name",
                description=f"browser extension name matches an AI product: {name}",
                location=str(first.get("extension_id")),
                weight=0.7,
            )
        )
        f.add_capability("browsing")
        f.kind = Kind.AI_APP
        return finalize(f, self.index)

    def _model_finding(self, records: list[dict[str, Any]]) -> Finding:
        first = records[0]
        runtime = str(first.get("runtime"))
        product = str(first.get("product") or runtime)
        models = sorted({str(m) for r in records for m in r.get("models") or []})
        count = sum(int(r.get("model_count") or 0) for r in records)
        f = self._finding(
            Kind.LOCAL_MODEL, first, "local-model", runtime, f"Local models stored for {product}"
        )
        provider = first.get("provider")
        if isinstance(provider, str) and self.index.get(provider) is not None:
            f.add_model_provider(provider)
        for model in models[:20]:
            f.models.append(model)
        f.metadata.update(
            {
                "runtime": product,
                "model_count": count,
                "models": models[:MAX_LISTED_MODELS],
                "locations": sorted({str(r.get("location")) for r in records}),
            }
        )
        f.add_evidence(
            Evidence(
                signal=f"endpoint:local-model:{runtime}",
                description=f"{count} model(s) in the {product} store",
                location=str(first.get("location")),
                weight=0.85,
                signature=provider if isinstance(provider, str) else None,
            )
        )
        f.kind = Kind.LOCAL_MODEL
        return finalize(f, self.index)

    def _history_findings(self, history: list[dict[str, Any]], findings: list[Finding]) -> list[Finding]:
        by_owner_sig: dict[tuple[str | None, str | None, str], Finding] = {}
        for f in findings:
            # Only a command-line client's own configuration absorbs its history;
            # an editor extension sharing the signature is a different product.
            if f.resource_type != "agent-config":
                continue
            for sig in f.frameworks:
                by_owner_sig[(f.account, f.owner, sig)] = f
        totals: dict[tuple[str, str, str], int] = {}
        for rec in history:
            tool = str(rec.get("tool"))
            if tool not in SHELL_TOOLS:
                continue
            key = (str(rec["device"]), str(rec["home"]), tool)
            totals[key] = totals.get(key, 0) + int(rec.get("count") or 0)
        out: list[Finding] = []
        for (device, home, tool), count in sorted(totals.items()):
            product, signature = SHELL_TOOLS[tool]
            evidence = Evidence(
                signal=f"endpoint:shell-history:{tool}",
                description=f"`{tool}` run {count} time(s) according to shell history",
                location="shell history",
                weight=0.6,
                signature=signature,
            )
            existing = by_owner_sig.get((device, home, signature)) if signature else None
            if existing is not None:
                existing.add_evidence(evidence)
                existing.metadata["shell_history_count"] = count
                finalize(existing, self.index)
                continue
            rec = {"device": device, "home": home}
            f = self._finding(Kind.AI_APP, rec, "cli-usage", tool, f"AI command-line tool used: {product}")
            self._signature_capabilities(f, signature)
            f.metadata.update({"tool": tool, "product": product, "shell_history_count": count})
            f.add_evidence(evidence)
            f.kind = Kind.AI_APP
            out.append(finalize(f, self.index))
        return out


# ----------------------------------------------------------------------- helpers


def _reason(exc: BaseException) -> str:
    if isinstance(exc, OSError) and exc.errno == errno.ELOOP:
        return "symbolic link not followed"
    if isinstance(exc, PermissionError):
        return "permission denied"
    if isinstance(exc, OSError) and exc.errno is not None:
        return os.strerror(exc.errno).lower()
    return type(exc).__name__


def _json_object(text: str | None) -> dict[str, Any] | None:
    if text is None:
        return None
    try:
        data = load_json_lenient(text.lstrip("﻿"))
    except (ValueError, RecursionError):
        return None
    return data if isinstance(data, dict) else None


_SERVER_STRINGS = ("name", "transport", "command", "url", "location")
_SERVER_STRING_LISTS = ("args", "urls", "env_names", "headers", "risks", "secret_locations")


def _valid_server(server: Any) -> bool:
    """A replayed MCP server record has the field types the parser produces."""
    if not isinstance(server, dict) or not isinstance(server.get("name"), str):
        return False
    if any(server.get(k) is not None and not isinstance(server[k], str) for k in _SERVER_STRINGS):
        return False
    if any(
        server.get(k) is not None
        and not (isinstance(server[k], list) and all(isinstance(v, str) for v in server[k]))
        for k in _SERVER_STRING_LISTS
    ):
        return False
    return all(server.get(k) is None or isinstance(server[k], bool) for k in ("disabled", "secrets_inline"))


def _mcp_servers(loc: ConfigLocation, text: str, errors: list[str]) -> list[dict[str, Any]]:
    """Parse a client configuration's MCP servers into the code connector's sanitized records."""
    if loc.path == ".claude.json":
        data = _json_object(text)
        if data is None:
            errors.append("invalid Claude Code state file")
            return []
        merged: dict[str, Any] = {}
        tables = [data.get("mcpServers")]
        projects = data.get("projects")
        if isinstance(projects, dict):
            tables += [p.get("mcpServers") for p in projects.values() if isinstance(p, dict)]
        for table in tables:
            if isinstance(table, dict):
                for name, cfg in table.items():
                    # A project-scoped server that reuses a user-scope name is a
                    # separate configuration; keep it under a numbered name.
                    key, n = str(name), 1
                    while key in merged and merged[key] != cfg:
                        n += 1
                        key = f"{name}#{n}"
                    merged.setdefault(key, cfg)
        return _parse_mcp_servers("claude.json", json.dumps({"mcpServers": merged}), errors) if merged else []
    if loc.client == "goose":
        return _goose_servers(text, errors)
    return _parse_mcp_servers(loc.path, text, errors)


def _goose_servers(text: str, errors: list[str]) -> list[dict[str, Any]]:
    """Goose extensions of type stdio, sse or streamable_http are MCP servers."""
    try:
        data = strict_bounded_safe_load(text)
    except (ValueError, RecursionError, yaml.YAMLError):
        errors.append("invalid Goose configuration syntax")
        return []
    extensions = data.get("extensions") if isinstance(data, dict) else None
    if not isinstance(extensions, dict):
        return []
    servers: dict[str, Any] = {}
    for name, ext in extensions.items():
        if not isinstance(ext, dict) or ext.get("type") not in {"stdio", "sse", "streamable_http"}:
            continue
        entry: dict[str, Any] = {"disabled": ext.get("enabled") is False}
        if isinstance(ext.get("cmd"), str):
            entry["command"] = ext["cmd"]
            entry["args"] = [a for a in ext.get("args") or [] if isinstance(a, str)]
        if isinstance(ext.get("uri"), str):
            entry["url"] = ext["uri"]
        if isinstance(ext.get("envs"), dict):
            entry["env"] = ext["envs"]
        servers[str(name)] = entry
    return _parse_mcp_servers("goose.json", json.dumps({"mcpServers": servers}), errors) if servers else []


def _firefox_addons(text: str | None) -> Iterator[dict[str, Any]]:
    data = _json_object(text)
    addons = data.get("addons") if data else None
    if not isinstance(addons, list):
        return
    for addon in addons:
        if not isinstance(addon, dict) or addon.get("type") != "extension":
            continue
        default_locale = addon.get("defaultLocale")
        locale: dict[str, Any] = default_locale if isinstance(default_locale, dict) else {}
        name = locale.get("name")
        if isinstance(name, str) and AI_EXTENSION_NAME.search(name):
            yield {
                "record_type": "browser_extension",
                "extension_id": str(addon.get("id") or name),
                "name": name.strip()[:200],
                "version": str(addon.get("version") or ""),
            }


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", version)[:6])


def _history_tool(line: str, shell: str) -> str | None:
    """The AI tool a history line runs, from its first command word only."""
    text = line.strip()
    if shell == "zsh" and text.startswith(":") and ";" in text:
        text = text.split(";", 1)[1]
    elif shell == "fish":
        if not text.startswith("- cmd:"):
            return None
        text = text[len("- cmd:") :]
    words = text.split()
    while words and (
        words[0] in {"sudo", "env", "command", "exec", "nohup", "time"} or _ENV_ASSIGNMENT.match(words[0])
    ):
        words = words[1:]
    if not words:
        return None
    word = re.split(r"[\\/]", words[0])[-1].lower()
    if word.endswith(".exe"):
        word = word[:-4]
    if word == "gh" and len(words) > 1 and words[1] == "copilot":
        return "copilot"
    return word if word in SHELL_TOOLS else None


def _home_from_path(path: str) -> str | None:
    match = re.match(r"^(?:/home/|/Users/|[A-Za-z]:[\\/]Users[\\/])([^\\/]+)", path)
    return match.group(1) if match else None


def _osquery_extension_id(columns: dict[str, Any]) -> str:
    base = re.split(r"[\\/]", str(columns.get("path") or "").rstrip("\\/"))[-1].lower()
    match = _EXTENSION_VERSION.match(base)
    if match:
        return match.group("id")
    return f"{columns.get('publisher')}.{columns.get('name')}".lower()
