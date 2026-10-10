"""Tool adapters: how to run each discovery tool and read its output as facts.

An adapter never interprets a tool's findings beyond mapping the names, paths
and package identifiers it reports onto the shared taxonomy. Output outside
the taxonomy is ignored rather than penalized.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from tools.discovery_benchmark import taxonomy

MAX_OUTPUT_BYTES = 200_000_000


@dataclass(frozen=True)
class Command:
    """One process invocation. ``cwd`` is ``"out"`` (default) or ``"repo"``."""

    argv: tuple[str, ...]
    cwd: str = "out"
    ok_exit_codes: frozenset[int] = frozenset({0})
    env: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolSpec:
    id: str
    name: str
    vendor: str
    categories: frozenset[str]
    notes: str = ""


@dataclass
class Normalized:
    facts: set[str] = field(default_factory=set)
    raw_count: int = 0
    detail: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


class ToolConfig:
    """Paths for the installed tools, read from a JSON file."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data

    def tool(self, tool_id: str) -> dict[str, Any]:
        value = self.data.get("tools", {}).get(tool_id)
        return value if isinstance(value, dict) else {}

    def binary(self, tool_id: str) -> str | None:
        value = self.tool(tool_id).get("bin")
        return value if isinstance(value, str) and value else None

    def setting(self, key: str, default: str = "") -> str:
        value = self.data.get(key, default)
        return value if isinstance(value, str) else default

    @classmethod
    def load(cls, path: Path) -> ToolConfig:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError(f"{path}: tool configuration must be an object")
        return cls(data)


class Adapter(Protocol):
    spec: ToolSpec

    def unavailable_reason(self, cfg: ToolConfig) -> str | None: ...

    def version(self, cfg: ToolConfig) -> str: ...

    def commands(self, cfg: ToolConfig, repo_dir: Path, out_dir: Path) -> list[Command]: ...

    def normalize(self, out_dir: Path) -> Normalized: ...


def run_version(argv: list[str], *, pattern: str | None = None) -> str:
    """Run ``argv`` and return its first non-empty output line (or a regex match)."""
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"unknown ({type(exc).__name__})"
    text = re.sub(r"\x1b\[[0-9;]*m", "", (result.stdout or "") + (result.stderr or ""))
    if pattern:
        match = re.search(pattern, text)
        if match:
            return match.group(1)
    for line in text.splitlines():
        if line.strip():
            return line.strip()[:120]
    return "unknown"


def python_package_version(python: str, dist: str) -> str:
    return run_version(
        [python, "-c", f"import importlib.metadata as m; print(m.version({dist!r}))"],
    )


def load_json(path: Path) -> Any:
    """Load a JSON file produced by a tool; ``None`` when missing or malformed."""
    try:
        if path.stat().st_size > MAX_OUTPUT_BYTES:
            return None
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def facts_from_purl(purl: str) -> frozenset[str]:
    """Map a package URL onto facts using the ecosystem alias tables."""
    if not purl.startswith("pkg:"):
        return frozenset()
    body = purl[4:].split("?", 1)[0]
    kind, _, rest = body.partition("/")
    rest = rest.split("@", 1)[0]
    if kind == "pypi":
        return taxonomy.facts_for("pypi", rest)
    if kind == "npm":
        return taxonomy.facts_for("npm", rest)
    if kind in {"golang", "go"}:
        return taxonomy.facts_for("golang", rest)
    if kind == "maven":
        group, _, artifact = rest.rpartition("/")
        return taxonomy.facts_for("maven", f"{group}:{artifact}") if group else frozenset()
    if kind == "nuget":
        return taxonomy.facts_for("nuget", rest)
    if kind == "cargo":
        return taxonomy.facts_for("cargo", rest)
    return frozenset()


def dedupe(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def property_map(component: dict[str, Any]) -> dict[str, str]:
    props: dict[str, str] = {}
    for prop in component.get("properties") or []:
        if isinstance(prop, dict) and isinstance(prop.get("name"), str):
            props[prop["name"]] = str(prop.get("value", ""))
    return props
