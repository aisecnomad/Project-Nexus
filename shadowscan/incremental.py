"""Conservative, content-addressed reuse of completed static connector results.

Only local checkouts and exported cloud inventories are eligible. A live API's
configuration cannot establish that its remote inventory is unchanged. Findings
are stored before reconciliation/scoring/correlation and those stages always run
again. Cache state is local to the scanning user and must stay outside all inputs.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import logging
import os
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from shadowscan import __version__
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors import _BUILTIN
from shadowscan.connectors.code.filesystem import DEFAULT_EXCLUDES
from shadowscan.models import Finding, ScanStats, now_iso
from shadowscan.signatures import SignatureIndex
from shadowscan.utils.git import metadata_git_argv_prefix, metadata_git_env
from shadowscan.utils.redaction import sanitize

log = logging.getLogger("shadowscan.incremental")
_FORMAT = 3  # v2 finding identities: older entries require a full rescan
_MAX_CACHE_BYTES = 64 * 1024 * 1024
_MAX_HASH_FILE_BYTES = 64 * 1024 * 1024
_MAX_HASH_BYTES = 512 * 1024 * 1024
_MAX_HASH_ENTRIES = 200_000
_MAX_HASH_SECONDS = 30.0
_CLOUD_EXPORTS = {"cloud.aws", "cloud.azure", "cloud.gcp", "cloud.oci"}
_CODE = {"code.filesystem", "code.github", "code.gitlab"}
# These directories can be read by the filesystem connector's ownership lookup
# even when the ordinary source walk excludes them.
_OWNERSHIP_DIRECTORIES = {".github", ".gitlab", "docs"}


def _json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _paths(spec: ConnectorSpec) -> list[Path]:
    # Filesystem offline input takes precedence, as it does in BaseConnector.run.
    if spec.config.get("input"):
        raw = [spec.config["input"]]
    elif spec.name == "code.filesystem":
        raw = spec.config.get("paths") or [spec.config.get("path")]
    else:
        return []
    if not isinstance(raw, list) or not all(isinstance(p, str) and p for p in raw):
        return []
    roots = [Path(p).expanduser().absolute() for p in raw]
    if any(part.is_symlink() for root in roots for part in (root, *root.parents)):
        raise ValueError("symlink in static input root path")
    return [root.resolve() for root in roots]


def _literal_excluded_directories(spec: ConnectorSpec) -> frozenset[str]:
    """Use only directory exclusions with exactly the walker's literal semantics.

    Glob patterns and other connector types retain the conservative full-tree
    fingerprint. CODEOWNERS in the three special directories must remain part
    of the fingerprint because ownership lookup reads those files directly.
    """
    if spec.name != "code.filesystem":
        return frozenset()
    raw = spec.config.get("exclude", []) or []
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        return frozenset()
    return frozenset(
        name for name in raw
        if name not in _OWNERSHIP_DIRECTORIES and "*" not in name and "/" not in name
    )


def _eligible(spec: ConnectorSpec) -> bool:
    return spec.name == "code.filesystem" or (
        spec.name in (_CODE | _CLOUD_EXPORTS) and bool(spec.config.get("input"))
    )


@dataclass
class _HashBudget:
    bytes_left: int = field(default_factory=lambda: _MAX_HASH_BYTES)
    entries_left: int = field(default_factory=lambda: _MAX_HASH_ENTRIES)
    deadline: float = field(default_factory=lambda: time.monotonic() + _MAX_HASH_SECONDS)

    def check(self, *, entries: int = 0, size: int = 0) -> None:
        self.entries_left -= entries
        self.bytes_left -= size
        if self.entries_left < 0 or self.bytes_left < 0 or time.monotonic() > self.deadline:
            raise ValueError("static fingerprint budget exceeded")


def _file_digest(path: Path, *, max_bytes: int = _MAX_HASH_FILE_BYTES, budget: _HashBudget | None = None) -> str:
    """Hash regular files only; fail rather than trust a moving or special input."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("non-regular input")
        if before.st_size > max_bytes or (budget and before.st_size > budget.bytes_left):
            raise ValueError("fingerprint input exceeds byte limit")
        digest = hashlib.sha256()
        consumed = 0
        while chunk := stream.read(1024 * 1024):
            consumed += len(chunk)
            if consumed > max_bytes:
                raise ValueError("fingerprint input exceeds byte limit")
            if budget:
                budget.check(size=len(chunk))
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    current = path.stat()
    attrs = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, a) != getattr(after, a) or getattr(after, a) != getattr(current, a) for a in attrs):
        raise ValueError("input changed while hashing")
    # Change time and inode identity catch ordinary replace/restore changes.
    # These checks are not an atomic snapshot or a defense against an adversary
    # concurrently changing inputs. Incremental scans require immutable inputs.
    digest.update(_json([getattr(after, attr) for attr in attrs]))
    return digest.hexdigest()


def _git_state(root: Path, budget: _HashBudget) -> str | None:
    marker = root / ".git"
    if marker.is_symlink():
        raise ValueError("symlink git metadata")
    if not marker.exists():
        return None
    if os.environ.get("GIT_REPLACE_REF_BASE") or os.environ.get("GIT_SHALLOW_FILE"):
        raise ValueError("external git history override")

    def git(*args: str) -> bytes:
        budget.check()
        result = subprocess.run(
            [*metadata_git_argv_prefix(), "-C", str(root), *args], check=False, capture_output=True, timeout=10,
            env=metadata_git_env(),
        )
        budget.check(size=len(result.stdout))
        if result.returncode:
            raise ValueError("cannot resolve checkout metadata")
        return result.stdout

    # Author enrichment depends on effective history, not merely HEAD: replacement
    # refs and shallow boundaries can change git log output without moving HEAD.
    head = git("rev-parse", "--verify", "HEAD")
    if git("for-each-ref", "--format=%(refname)", "refs/replace").strip():
        raise ValueError("git history has replacement refs")
    history_paths = git("rev-parse", "--path-format=absolute", "--git-path", "shallow", "--git-path", "info/grafts").decode().splitlines()
    if len(history_paths) != 2:
        raise ValueError("cannot resolve git history paths")
    shallow, grafts = [Path(p) for p in history_paths]
    if grafts.exists():
        raise ValueError("git history has grafts")
    shallow_digest = _file_digest(shallow, budget=budget) if shallow.exists() else None
    return hashlib.sha256(_json([head.decode(), shallow_digest])).hexdigest()


def _tree_digest(
    root: Path, *, code: bool, use_git: bool, budget: _HashBudget, max_file_bytes: int,
    excluded_dir_names: frozenset[str] = frozenset(),
) -> str:
    digest = hashlib.sha256()
    budget.check(entries=1)
    if root.is_file():
        return _file_digest(root, max_bytes=max_file_bytes, budget=budget)
    if not root.is_dir():
        raise ValueError("input missing or not a regular file/directory")

    def failed(error: OSError) -> None:
        raise error

    for base, dirs, files in os.walk(root, followlinks=False, onerror=failed):
        budget.check(entries=1)
        basepath = Path(base)
        rel = basepath.relative_to(root).as_posix()
        digest.update(_json(["directory", rel]))
        before = basepath.stat(follow_symlinks=False)
        attrs = ("st_dev", "st_ino", "st_mode", "st_mtime_ns", "st_ctime_ns")
        digest.update(_json([getattr(before, attr) for attr in attrs]))
        if code and use_git and ".git" in dirs + files:
            digest.update(_json(["git", rel, _git_state(basepath, budget)]))
        kept = []
        for name in sorted(dirs):
            budget.check(entries=1)
            path = basepath / name
            if code and (name in DEFAULT_EXCLUDES or name in excluded_dir_names):
                continue
            if path.is_symlink():
                # Ancillary readers such as CODEOWNERS can inspect descendants
                # of a symlink even though the source walk skips traversal. A
                # target change outside this tree must not hide a new error.
                raise ValueError("symlink in static input")
            kept.append(name)
        dirs[:] = kept
        for name in sorted(files):
            budget.check(entries=1)
            path = basepath / name
            if code and name == ".git":
                # A worktree's gitdir pointer also affects its metadata.
                digest.update(_json(["git-marker", rel, _file_digest(path, max_bytes=max_file_bytes, budget=budget)]))
                continue
            if path.is_symlink():
                raise ValueError("symlink in static input")
            if not stat.S_ISREG(path.stat().st_mode):
                raise ValueError("special file in input")
            digest.update(_json(["file", path.relative_to(root).as_posix(), _file_digest(path, max_bytes=max_file_bytes, budget=budget)]))
        after = basepath.stat(follow_symlinks=False)
        if any(getattr(before, attr) != getattr(after, attr) for attr in attrs):
            raise ValueError("input directory changed while hashing")
    return digest.hexdigest()


def _checkout_container_digest(root: Path, *, use_git: bool, budget: _HashBudget, max_file_bytes: int) -> str:
    """Offline provider inputs contain repositories; their names are not exclusions."""
    if not root.is_dir():
        raise ValueError("checkout container must be a directory")
    digest = hashlib.sha256()
    before = root.stat(follow_symlinks=False)
    attrs = ("st_dev", "st_ino", "st_mode", "st_mtime_ns", "st_ctime_ns")
    digest.update(_json([getattr(before, attr) for attr in attrs]))
    for child in sorted(root.iterdir()):
        budget.check(entries=1)
        if child.is_symlink():
            raise ValueError("symlink in checkout container")
        if child.is_dir():
            digest.update(_json([child.name, _tree_digest(
                child, code=True, use_git=use_git, budget=budget, max_file_bytes=max_file_bytes,
            )]))
    after = root.stat(follow_symlinks=False)
    if any(getattr(before, attr) != getattr(after, attr) for attr in attrs):
        raise ValueError("checkout container changed while hashing")
    return digest.hexdigest()


@dataclass(frozen=True)
class Snapshot:
    slot: str
    fingerprint: str


class IncrementalCache:
    def __init__(self, config: ScanConfig, index: SignatureIndex):
        self.config = config
        self.index = index
        default = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local" / "state"))) / "shadowscan"
        self.directory = Path(config.state_dir).expanduser() if config.state_dir else default
        self.directory = self.directory.absolute()
        self.enabled = config.incremental and not config.dump_records
        self.scanner_digest = ""
        if not self.enabled:
            return
        try:
            # Reject state in any configured input, including another connector's.
            for spec in config.enabled_connectors():
                for root in _paths(spec):
                    if self.directory.resolve().is_relative_to(root):
                        raise ValueError("state directory overlaps a scan input")
            self._secure_directory()
            package = Path(__file__).parent
            self.scanner_digest = hashlib.sha256(_json([
                [p.relative_to(package).as_posix(), _file_digest(p)]
                for p in sorted(package.rglob("*.py"))
            ])).hexdigest()
        except (OSError, ValueError):
            self.enabled = False
            log.warning("incremental state is unavailable or unsafe; running full scans")

    def _secure_directory(self) -> None:
        if any(p.is_symlink() for p in (self.directory, *self.directory.parents)):
            raise ValueError("symlink in state directory path")
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.directory.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077:
            raise ValueError("state directory must be private (0700)")
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise ValueError("state directory must belong to the current user")

    @staticmethod
    def supports_connector(spec: ConnectorSpec, connector_class: type) -> bool:
        """Plugin overrides may collect additional inputs unknown to this cache."""
        if not _eligible(spec):
            return False
        module, _, name = _BUILTIN[spec.name].partition(":")
        return connector_class is getattr(importlib.import_module(module), name)

    def snapshot(self, spec: ConnectorSpec) -> Snapshot | None:
        if not self.enabled or not _eligible(spec):
            return None
        try:
            roots = _paths(spec)
            if not roots:
                return None
            code = spec.name in _CODE
            use_git = bool(spec.config.get("use_git", False))
            budget = _HashBudget()
            excluded_dir_names = _literal_excluded_directories(spec)
            max_bytes = min(int(spec.config.get("max_file_size", 1_000_000)), _MAX_HASH_FILE_BYTES) if code else _MAX_HASH_FILE_BYTES
            inputs = []
            for root in roots:
                if spec.name in {"code.github", "code.gitlab"}:
                    digest = _checkout_container_digest(root, use_git=use_git, budget=budget, max_file_bytes=max_bytes)
                else:
                    digest = _tree_digest(
                        root, code=code, use_git=use_git, budget=budget,
                        max_file_bytes=max_bytes, excluded_dir_names=excluded_dir_names,
                    )
                inputs.append([str(root), digest])
            fingerprint = hashlib.sha256(_json({
                "format": _FORMAT,
                "version": __version__,
                "scanner": self.scanner_digest,
                "signatures": self.index.fingerprint(),
                "connector": spec.name,
                "id": spec.id,
                "config": spec.config,
                "inputs": inputs,
            })).hexdigest()
            slot = hashlib.sha256(_json([spec.name, spec.id, [str(p) for p in roots]])).hexdigest()
            return Snapshot(slot, fingerprint)
        except (OSError, ValueError, TypeError, subprocess.SubprocessError):
            log.warning("could not fingerprint static input for %s; running a full scan", spec.id)
            return None

    def load(self, spec: ConnectorSpec, snapshot: Snapshot) -> tuple[list[Finding], ScanStats] | None:
        path = self.directory / f"{snapshot.slot}.json"
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > _MAX_CACHE_BYTES:
                    return None
                if hasattr(os, "getuid") and info.st_uid != os.getuid():
                    return None
                data = json.loads(stream.read(_MAX_CACHE_BYTES + 1))
            if data["format"] != _FORMAT or data["fingerprint"] != snapshot.fingerprint:
                return None
            payload = data["payload"]
            if hashlib.sha256(_json(payload)).hexdigest() != data["payload_sha256"]:
                return None
            if not isinstance(payload["findings"], list) or not isinstance(payload["warnings"], list):
                return None
            findings = [Finding.from_dict(d) for d in payload["findings"]]
            for finding in findings:
                finding.sanitize()
            stats = ScanStats(
                connector=spec.id, started_at=now_iso(), finished_at=now_iso(),
                findings=len(findings), objects_examined=0,
                warnings=sanitize(payload["warnings"]), cached=True, cache_key=snapshot.fingerprint,
            )
            return findings, stats
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            return None

    def save(self, snapshot: Snapshot, findings: list[Finding], stats: ScanStats) -> None:
        if stats.incomplete or stats.errors or stats.skipped:
            return
        temp: str | None = None
        try:
            self._secure_directory()
            for finding in findings:
                finding.sanitize()
            payload = {"findings": [f.to_dict() for f in findings], "warnings": sanitize(stats.warnings)}
            data = _json({
                "format": _FORMAT, "fingerprint": snapshot.fingerprint,
                "payload": payload, "payload_sha256": hashlib.sha256(_json(payload)).hexdigest(),
            })
            if len(data) > _MAX_CACHE_BYTES:
                return
            fd, temp = tempfile.mkstemp(prefix=".pending-", dir=self.directory)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, self.directory / f"{snapshot.slot}.json")
            temp = None
        except (OSError, ValueError, TypeError):
            log.warning("could not save incremental state; next scan will run in full")
        finally:
            if temp:
                try:
                    os.unlink(temp)
                except OSError:
                    pass
