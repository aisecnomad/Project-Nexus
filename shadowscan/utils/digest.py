"""Content digests of the scanner's own source tree.

Collection-scope fingerprints and incremental cache keys both attest which
scanner code produced a result. They share one digest so a report comparison
and a cache lookup agree on what "same scanner" means.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

from shadowscan.utils.git import metadata_git_env

_SEMANTIC_DISTRIBUTIONS = ("PyYAML", "regex")


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False, ensure_ascii=True
    ).encode()


def runtime_semantics() -> dict[str, Any]:
    """Describe installed components that can change parsing or matching.

    Source-identical installations are not necessarily semantically identical:
    Python's parsers, the third-party YAML/regex engines, and Git metadata reads
    can change across runtime versions. Keep this deliberately small and free of
    host identifiers so exported comparison fingerprints remain non-sensitive.
    """
    distributions: dict[str, str | None] = {}
    for name in _SEMANTIC_DISTRIBUTIONS:
        try:
            distributions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            distributions[name] = None

    git_version: str | None = None
    env = metadata_git_env()
    env["LC_ALL"] = "C"
    try:
        result = subprocess.run(
            ["git", "--version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            timeout=2,
            check=False,
        )
        if result.returncode == 0:
            value = result.stdout.strip()
            if value.startswith("git version ") and len(value) <= 128:
                git_version = value.removeprefix("git version ")
    except (OSError, subprocess.SubprocessError, ValueError):
        pass

    implementation_version = sys.implementation.version
    return {
        "python": {
            "implementation": sys.implementation.name,
            "implementation_version": [
                implementation_version.major,
                implementation_version.minor,
                implementation_version.micro,
                implementation_version.releaselevel,
                implementation_version.serial,
            ],
            "version": list(sys.version_info[:5]),
            "cache_tag": sys.implementation.cache_tag,
        },
        "platform": {
            "os_name": os.name,
            "sys_platform": sys.platform,
            "machine": platform.machine().lower(),
            "byteorder": sys.byteorder,
        },
        "dependencies": distributions,
        "git": git_version,
    }


def scanner_source_digest(package: Path | None = None) -> str:
    """Return a SHA-256 over scanner source and relevant runtime semantics.

    File contents and package-relative paths capture implementation changes.
    Runtime semantics prevent reuse across Python, platform, Git, parser or
    matcher versions whose behavior can differ despite identical source.
    Read errors propagate as ``OSError`` so callers fail closed.
    """
    root = package if package is not None else Path(__file__).parent.parent
    entries = [
        [path.relative_to(root).as_posix(), hashlib.sha256(path.read_bytes()).hexdigest()]
        for path in sorted(root.rglob("*.py"))
        if path.is_file()
    ]
    return hashlib.sha256(_canonical({"sources": entries, "runtime": runtime_semantics()})).hexdigest()
