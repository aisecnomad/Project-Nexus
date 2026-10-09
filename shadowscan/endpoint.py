"""Well-known locations of AI coding-agent and MCP client configuration on a workstation.

``shadowscan endpoint`` scans these instead of a whole home directory: the
client configuration files, user-level skills, sub-agent and instruction
files that establish which agents a person has wired into their editor and
terminal. Every location is a path below the profile's home directory, the
Windows ones below its own ``AppData`` (never the scanning process's
``%APPDATA%``, which describes another profile). Every location is checked
for existence only; the files are then read by the ``code.filesystem``
connector under its usual limits. Symbolic links are never followed, in line
with the inventory and signature policy.
"""

from __future__ import annotations

import os
import re
import socket
import stat
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from shadowscan.connectors.endpoint.catalog import CONFIG_LOCATIONS


@dataclass(frozen=True)
class EndpointLocation:
    client: str
    relative: str  # path below the home directory, written with ``/``


_MAC_VSCODE = "Library/Application Support/Code/User"
_MAC_INSIDERS = "Library/Application Support/Code - Insiders/User"
_LINUX_VSCODE = ".config/Code/User"
_LINUX_INSIDERS = ".config/Code - Insiders/User"
_WIN_VSCODE = "AppData/Roaming/Code/User"
_WIN_INSIDERS = "AppData/Roaming/Code - Insiders/User"
_CLINE = "globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"
_ROO = "globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json"


def _vscode_family(client: str, tail: str) -> list[EndpointLocation]:
    bases = (_LINUX_VSCODE, _LINUX_INSIDERS, _MAC_VSCODE, _MAC_INSIDERS, _WIN_VSCODE, _WIN_INSIDERS)
    return [EndpointLocation(client, f"{base}/{tail}") for base in bases]


# Directories whose existence the endpoint.inventory connector records. They
# hold session logs, caches and agent memory rather than configuration, so they
# are not walked; their configuration files (.copilot/mcp-config.json,
# .kiro/settings/mcp.json, .openclaw/openclaw.json) are listed individually.
CLIENT_DIRECTORIES: frozenset[str] = frozenset({".copilot", ".kiro", ".openclaw/workspace"})


def _unique(locations: Iterable[EndpointLocation]) -> tuple[EndpointLocation, ...]:
    """The locations in order, each path once (the first entry names its client)."""
    out: dict[str, EndpointLocation] = {}
    for location in locations:
        out.setdefault(location.relative, location)
    return tuple(out.values())


LOCATIONS: tuple[EndpointLocation, ...] = _unique(
    (
        EndpointLocation("claude-desktop", "Library/Application Support/Claude/claude_desktop_config.json"),
        EndpointLocation("claude-desktop", ".config/Claude/claude_desktop_config.json"),
        EndpointLocation("claude-desktop", "AppData/Roaming/Claude/claude_desktop_config.json"),
        EndpointLocation("claude-code", ".claude.json"),
        EndpointLocation("claude-code", ".claude/settings.json"),
        EndpointLocation("claude-code", ".claude/settings.local.json"),
        EndpointLocation("claude-code", ".claude/CLAUDE.md"),
        EndpointLocation("claude-code", ".claude/skills"),
        EndpointLocation("claude-code", ".claude/agents"),
        EndpointLocation("claude-code", ".claude/commands"),
        EndpointLocation("claude-code", ".claude/hooks"),
        EndpointLocation("cursor", ".cursor/mcp.json"),
        EndpointLocation("cursor", ".cursor/rules"),
        EndpointLocation("windsurf", ".codeium/windsurf/mcp_config.json"),
        EndpointLocation("windsurf", ".codeium/windsurf/memories/global_rules.md"),
        *_vscode_family("vscode", "mcp.json"),
        *_vscode_family("vscode", "settings.json"),
        *_vscode_family("cline", _CLINE),
        *_vscode_family("roo-code", _ROO),
        EndpointLocation("gemini-cli", ".gemini/settings.json"),
        EndpointLocation("gemini-cli", ".gemini/GEMINI.md"),
        EndpointLocation("codex-cli", ".codex/config.toml"),
        EndpointLocation("codex-cli", ".codex/AGENTS.md"),
        EndpointLocation("kiro", ".kiro/settings/mcp.json"),
        EndpointLocation("amazon-q", ".aws/amazonq/mcp.json"),
        EndpointLocation("github-copilot-cli", ".copilot/mcp-config.json"),
        EndpointLocation("zed", ".config/zed/settings.json"),
        EndpointLocation("continue", ".continue/config.yaml"),
        EndpointLocation("continue", ".continue/config.json"),
        EndpointLocation("goose", ".config/goose/config.yaml"),
        EndpointLocation("opencode", ".config/opencode/opencode.json"),
        EndpointLocation("mcp", ".mcp.json"),
        # Every other location the endpoint.inventory catalog knows (LM Studio,
        # Aider, OpenClaw, Goose on Windows, Cline and Roo inside Cursor), so both
        # commands look at the same configuration files.
        *(
            EndpointLocation(location.client, location.path)
            for location in CONFIG_LOCATIONS
            if location.path not in CLIENT_DIRECTORIES
        ),
    )
)

CLIENTS: tuple[str, ...] = tuple(dict.fromkeys(location.client for location in LOCATIONS))


def endpoint_paths(home: Path, *, errors: list[str] | None = None) -> list[tuple[str, Path]]:
    """Existing well-known files and directories for ``home``: (client, path) pairs in a stable order.

    A location that is a symbolic link, or whose parent chain holds one, is
    left out and reported in ``errors``: the scan root policy never follows
    links, and a link here could point the scan outside the profile it claims
    to describe.
    """
    found: list[tuple[str, Path]] = []
    for location in LOCATIONS:
        candidate = home / location.relative
        try:
            if not _exists_without_links(candidate, home):
                continue
        except OSError:
            if errors is not None:
                errors.append(
                    f"{location.client}: {location.relative}: known configuration location could not be "
                    "inspected safely"
                )
            continue
        found.append((location.client, candidate))
    return found


def _exists_without_links(path: Path, home: Path) -> bool:
    """Whether ``path`` exists as a regular file or directory with no link between it and ``home``."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(info.st_mode):
        raise OSError("configuration location is a symbolic link")
    if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
        raise OSError("configuration location is not a regular file or directory")
    # The components between the profile root and the location must not be links either.
    current = path.parent
    while current != home and home in current.parents:
        if stat.S_ISLNK(os.lstat(current).st_mode):
            raise OSError("configuration parent is a symbolic link")
        current = current.parent
    return True


def endpoint_include() -> list[str]:
    """The ``code.filesystem`` include list of a profile scan: every known location.

    The list does not depend on which locations exist, so a profile without
    any is scanned (and its collection scope fingerprinted) like any other,
    and a client configured or removed later is a new or resolved finding in
    ``shadowscan diff``, not a change of collection scope.
    """
    return [location.relative for location in LOCATIONS]


def default_label(hostname: str | None = None) -> str:
    """``endpoint:<hostname>`` with the host name reduced to a safe resource prefix."""
    name = hostname if hostname is not None else socket.gethostname()
    safe = re.sub(r"[^A-Za-z0-9.-]+", "-", name).strip("-.")[:64] or "host"
    return f"endpoint:{safe}"


def describe(found: Iterable[tuple[str, Path]], home: Path) -> list[str]:
    """One line per location, with the path shown relative to the profile when possible."""
    lines = []
    for client, path in found:
        shown = str(path.relative_to(home)) if path.is_relative_to(home) else str(path)
        lines.append(f"{client:20} {shown}")
    return lines
