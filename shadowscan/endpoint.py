"""Well-known locations of AI coding-agent and MCP client configuration on a workstation.

``shadowscan endpoint`` scans these instead of a whole home directory: the
client configuration files, user-level skills, sub-agent and instruction
files that establish which agents a person has wired into their editor and
terminal. Every location is checked for existence only; the files are then
read by the ``code.filesystem`` connector under its usual limits. Symbolic
links are never followed, in line with the inventory and signature policy.
"""

from __future__ import annotations

import os
import re
import socket
import stat
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class EndpointLocation:
    client: str
    relative: str  # path below the home directory, or below ``base`` when set
    base: str | None = None  # environment variable naming the base directory (Windows)


_MAC_VSCODE = "Library/Application Support/Code/User"
_MAC_INSIDERS = "Library/Application Support/Code - Insiders/User"
_LINUX_VSCODE = ".config/Code/User"
_LINUX_INSIDERS = ".config/Code - Insiders/User"
_WIN_VSCODE = "Code/User"
_WIN_INSIDERS = "Code - Insiders/User"
_CLINE = "globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"
_ROO = "globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json"


def _vscode_family(client: str, tail: str) -> list[EndpointLocation]:
    return [
        EndpointLocation(client, f"{_LINUX_VSCODE}/{tail}"),
        EndpointLocation(client, f"{_LINUX_INSIDERS}/{tail}"),
        EndpointLocation(client, f"{_MAC_VSCODE}/{tail}"),
        EndpointLocation(client, f"{_MAC_INSIDERS}/{tail}"),
        EndpointLocation(client, f"{_WIN_VSCODE}/{tail}", "APPDATA"),
        EndpointLocation(client, f"{_WIN_INSIDERS}/{tail}", "APPDATA"),
    ]


LOCATIONS: tuple[EndpointLocation, ...] = (
    EndpointLocation("claude-desktop", "Library/Application Support/Claude/claude_desktop_config.json"),
    EndpointLocation("claude-desktop", ".config/Claude/claude_desktop_config.json"),
    EndpointLocation("claude-desktop", "Claude/claude_desktop_config.json", "APPDATA"),
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
)

CLIENTS: tuple[str, ...] = tuple(dict.fromkeys(location.client for location in LOCATIONS))


def _candidate(location: EndpointLocation, home: Path, env: Mapping[str, str]) -> Path | None:
    if location.base is None:
        return home / location.relative
    base = env.get(location.base)
    if not base:
        return None
    return Path(base) / location.relative


def endpoint_paths(
    home: Path, env: Mapping[str, str] | None = None, *, errors: list[str] | None = None
) -> list[tuple[str, Path]]:
    """Existing well-known files and directories for ``home``: (client, path) pairs in a stable order.

    A location that is a symbolic link, or whose parent chain holds one, is
    left out: the scan root policy never follows links, and a link here could
    point the scan outside the profile it claims to describe.
    """
    env = os.environ if env is None else env
    found: list[tuple[str, Path]] = []
    seen: set[Path] = set()
    for location in LOCATIONS:
        candidate = _candidate(location, home, env)
        if candidate is None or candidate in seen:
            continue
        try:
            if not _exists_without_links(candidate, home):
                continue
        except OSError:
            if errors is not None:
                errors.append(
                    f"{location.client}: known configuration location could not be inspected safely"
                )
            continue
        seen.add(candidate)
        found.append((location.client, candidate))
    return found


def _exists_without_links(path: Path, home: Path) -> bool:
    """Whether ``path`` exists as a regular file or directory with no link below ``home`` (or its base)."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(info.st_mode):
        raise OSError("configuration location is a symbolic link")
    if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
        raise OSError("configuration location is not a regular file or directory")
    # The components between the profile root and the location must not be links either.
    root = home if path.is_relative_to(home) else path.parents[len(path.parents) - 1]
    current = path.parent
    while current != root and root in current.parents:
        if stat.S_ISLNK(os.lstat(current).st_mode):
            raise OSError("configuration parent is a symbolic link")
        current = current.parent
    return True


def endpoint_roots(found: Iterable[tuple[str, Path]], home: Path) -> tuple[list[Path], list[str]]:
    """Scan roots and the include paths below them for the located files and directories.

    The home directory is one root; a Windows base directory (APPDATA) that
    holds a location is another. Include paths are relative to their root and
    apply to every root: a path absent under one root is simply not found there.
    """
    roots: list[Path] = []
    include: list[str] = []
    for _, path in found:
        root = home if path.is_relative_to(home) else path.parents[len(path.parents) - 1]
        for base in (home, *_bases(path, home)):
            if path.is_relative_to(base):
                root = base
                break
        if root not in roots:
            roots.append(root)
        relative = path.relative_to(root).as_posix()
        if relative not in include:
            include.append(relative)
    return roots, include


def _bases(path: Path, home: Path) -> list[Path]:
    """Known base directories a located path may sit under, longest first."""
    bases = []
    for location in LOCATIONS:
        if location.base is None:
            continue
        tail = Path(location.relative)
        if path.name == tail.name and path.as_posix().endswith(tail.as_posix()):
            depth = len(tail.parts)
            bases.append(Path(*path.parts[: len(path.parts) - depth]))
    return sorted(set(bases), key=lambda b: -len(b.parts))


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
