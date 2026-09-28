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
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any

from shadowscan import __version__
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors import _BUILTIN
from shadowscan.connectors.code.filesystem import DEFAULT_EXCLUDES
from shadowscan.models import Finding, ScanStats, now_iso
from shadowscan.signatures import SignatureIndex
from shadowscan.utils.digest import scanner_source_digest
from shadowscan.utils.git import metadata_git_argv_prefix, metadata_git_env
from shadowscan.utils.redaction import sanitize
from shadowscan.utils.safe_json import strict_json_loads

fcntl: ModuleType | None
try:
    import fcntl as _fcntl

    fcntl = _fcntl
except (
    ImportError
):  # pragma: no cover - fcntl is absent only on platforms the confined reader already refuses
    fcntl = None


log = logging.getLogger("shadowscan.incremental")
_FORMAT = 3  # v2 finding identities: older entries require a full rescan
_MAX_CACHE_BYTES = 64 * 1024 * 1024
_MAX_CACHE_TOTAL_BYTES = 512 * 1024 * 1024
_MAX_CACHE_ENTRIES = 256
_MAX_CACHE_DIRECTORY_ENTRIES = 4096
_MAX_CACHE_SCAN_ENTRIES = 64 * 1024
_MAX_CACHE_MAINTENANCE_SECONDS = 2.0
_CACHE_TTL_SECONDS = 30 * 24 * 60 * 60
_PENDING_TTL_SECONDS = 60 * 60
_MAX_HASH_FILE_BYTES = 64 * 1024 * 1024
_MAX_HASH_BYTES = 512 * 1024 * 1024
_MAX_HASH_ENTRIES = 200_000
_MAX_HASH_DEPTH = 128
_MAX_HASH_SECONDS = 30.0
# Metadata tracked for every file, hashed or not: a fresh checkout at a new
# inode, a touched file or a chmod all miss the cache.
_FILE_STAT_ATTRS = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
_CLOUD_EXPORTS = {"cloud.aws", "cloud.azure", "cloud.gcp", "cloud.oci"}
_CODE = {"code.filesystem", "code.github", "code.gitlab"}
# These directories can be read by the filesystem connector's ownership lookup
# even when the ordinary source walk excludes them.
_OWNERSHIP_DIRECTORIES = {".github", ".gitlab", "docs"}


class _CacheMaintenanceDeadlineExceeded(RuntimeError):
    """Raised when startup cache housekeeping exceeds its fixed budget."""


def _json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False, ensure_ascii=True
    ).encode()


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
        name for name in raw if name not in _OWNERSHIP_DIRECTORIES and "*" not in name and "/" not in name
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
    check_cancelled: Callable[[], None] | None = None

    def __post_init__(self) -> None:
        self.deadline = min(self.deadline, time.monotonic() + _MAX_HASH_SECONDS)

    def check(self, *, entries: int = 0, size: int = 0) -> None:
        if self.check_cancelled is not None:
            self.check_cancelled()
        self.entries_left -= entries
        self.bytes_left -= size
        if self.entries_left < 0 or self.bytes_left < 0 or time.monotonic() > self.deadline:
            raise ValueError("static fingerprint budget exceeded")

    def timeout(self, maximum: float) -> float:
        """Return a subprocess timeout bounded by the fingerprint/deadline budget."""
        self.check()
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            self.check()
            raise ValueError("static fingerprint budget exceeded")
        return min(maximum, remaining)


def _file_digest(
    path: Path, *, max_bytes: int = _MAX_HASH_FILE_BYTES, budget: _HashBudget | None = None
) -> str:
    """Hash regular files only; fail rather than trust a moving or special input."""
    if budget:
        budget.check()
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("non-regular input")
        if before.st_size > max_bytes or (budget and before.st_size > budget.bytes_left):
            raise ValueError("fingerprint input exceeds byte limit")
        digest = hashlib.sha256()
        consumed = 0
        while True:
            if budget:
                budget.check()
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > max_bytes:
                raise ValueError("fingerprint input exceeds byte limit")
            if budget:
                budget.check(size=len(chunk))
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    if budget:
        budget.check()
    current = path.stat()
    attrs = _FILE_STAT_ATTRS
    if any(
        getattr(before, a) != getattr(after, a) or getattr(after, a) != getattr(current, a) for a in attrs
    ):
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
    # Match the filesystem connector's trust boundary. A worktree/submodule
    # gitfile can redirect metadata reads outside the requested scan root.
    if not marker.is_dir():
        raise ValueError("git metadata must be a local .git directory")
    if os.environ.get("GIT_REPLACE_REF_BASE") or os.environ.get("GIT_SHALLOW_FILE"):
        raise ValueError("external git history override")

    def git(*args: str) -> bytes:
        budget.check()
        try:
            result = subprocess.run(
                [*metadata_git_argv_prefix(), "-C", str(root), *args],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=budget.timeout(10),
                env=metadata_git_env(),
            )
        except subprocess.TimeoutExpired:
            # A connector cancellation/deadline must propagate instead of
            # degrading into an uncached scan that continues doing work.
            budget.check()
            raise
        budget.check(size=len(result.stdout))
        if result.returncode:
            raise ValueError("cannot resolve checkout metadata")
        return result.stdout

    # Author enrichment depends on effective history, not merely HEAD: replacement
    # refs and shallow boundaries can change git log output without moving HEAD.
    head = git("rev-parse", "--verify", "HEAD")
    if git("for-each-ref", "--count=1", "--format=%(refname)", "refs/replace").strip():
        raise ValueError("git history has replacement refs")
    history_paths = (
        git("rev-parse", "--path-format=absolute", "--git-path", "shallow", "--git-path", "info/grafts")
        .decode()
        .splitlines()
    )
    if len(history_paths) != 2:
        raise ValueError("cannot resolve git history paths")
    shallow, grafts = [Path(p) for p in history_paths]
    git_directory = marker.resolve()
    if any(not path.resolve().is_relative_to(git_directory) for path in (shallow, grafts)):
        raise ValueError("git history path escapes local metadata directory")
    if grafts.exists():
        raise ValueError("git history has grafts")
    shallow_digest = _file_digest(shallow, budget=budget) if shallow.exists() else None
    return hashlib.sha256(_json([head.decode(), shallow_digest])).hexdigest()


def _tree_digest(
    root: Path,
    *,
    code: bool,
    use_git: bool,
    budget: _HashBudget,
    max_file_bytes: int,
    excluded_dir_names: frozenset[str] = frozenset(),
    unread_above: int | None = None,
) -> str:
    """Digest a tree's content and metadata.

    Every directory and file contributes its size, mode, times, device and
    inode; readable files also contribute their content. A file larger than
    ``unread_above`` (the scanner's own ``max_file_size``) is never opened by
    the scanner, so only its metadata is tracked instead of aborting the
    fingerprint, which kept every tree with one oversize file out of the cache.
    """
    digest = hashlib.sha256()
    if root.is_file():
        budget.check(entries=1)
        return _file_digest(root, max_bytes=max_file_bytes, budget=budget)
    if not root.is_dir():
        raise ValueError("input missing or not a regular file/directory")

    def visit(basepath: Path, depth: int) -> None:
        if depth > _MAX_HASH_DEPTH:
            raise ValueError("static fingerprint depth limit exceeded")
        budget.check(entries=1)
        rel = basepath.relative_to(root).as_posix()
        digest.update(_json(["directory", rel]))
        before = basepath.stat(follow_symlinks=False)
        attrs = ("st_dev", "st_ino", "st_mode", "st_mtime_ns", "st_ctime_ns")
        digest.update(_json([getattr(before, attr) for attr in attrs]))

        directories: list[str] = []
        files: list[str] = []
        marker_present = False
        # os.walk allocates every name in a directory before the caller can
        # enforce a budget. Count entries while scanning, then sort only the
        # already-bounded names needed for a deterministic digest.
        with os.scandir(basepath) as entries:
            for entry in entries:
                budget.check(entries=1)
                marker_present = marker_present or entry.name == ".git"
                if entry.is_dir(follow_symlinks=False):
                    directories.append(entry.name)
                else:
                    files.append(entry.name)

        if code and use_git and marker_present:
            digest.update(_json(["git", rel, _git_state(basepath, budget)]))

        kept: list[Path] = []
        for name in sorted(directories):
            path = basepath / name
            if code and (name in DEFAULT_EXCLUDES or name in excluded_dir_names):
                continue
            if path.is_symlink():
                # Ancillary readers such as CODEOWNERS can inspect descendants
                # of a symlink even though the source walk skips traversal. A
                # target change outside this tree must not hide a new error.
                raise ValueError("symlink in static input")
            kept.append(path)
        for name in sorted(files):
            path = basepath / name
            if code and name == ".git":
                # A worktree's gitdir pointer also affects its metadata.
                digest.update(
                    _json(["git-marker", rel, _file_digest(path, max_bytes=max_file_bytes, budget=budget)])
                )
                continue
            if path.is_symlink():
                raise ValueError("symlink in static input")
            info = path.stat()
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("special file in input")
            relative = path.relative_to(root).as_posix()
            if unread_above is not None and info.st_size > unread_above:
                digest.update(
                    _json(["oversize", relative, [getattr(info, attr) for attr in _FILE_STAT_ATTRS]])
                )
                continue
            digest.update(
                _json(["file", relative, _file_digest(path, max_bytes=max_file_bytes, budget=budget)])
            )
        after = basepath.stat(follow_symlinks=False)
        if any(getattr(before, attr) != getattr(after, attr) for attr in attrs):
            raise ValueError("input directory changed while hashing")
        for directory in kept:
            visit(directory, depth + 1)

    visit(root, 0)
    return digest.hexdigest()


def _checkout_container_digest(
    root: Path,
    *,
    use_git: bool,
    budget: _HashBudget,
    max_file_bytes: int,
    unread_above: int | None = None,
) -> str:
    """Offline provider inputs contain repositories; their names are not exclusions."""
    budget.check(entries=1)
    if not root.is_dir():
        raise ValueError("checkout container must be a directory")
    digest = hashlib.sha256()
    before = root.stat(follow_symlinks=False)
    attrs = ("st_dev", "st_ino", "st_mode", "st_mtime_ns", "st_ctime_ns")
    digest.update(_json([getattr(before, attr) for attr in attrs]))
    children: list[Path] = []
    with os.scandir(root) as entries:
        for entry in entries:
            budget.check(entries=1)
            children.append(root / entry.name)
    for child in sorted(children):
        if child.is_symlink():
            raise ValueError("symlink in checkout container")
        if child.is_dir():
            digest.update(
                _json(
                    [
                        child.name,
                        _tree_digest(
                            child,
                            code=True,
                            use_git=use_git,
                            budget=budget,
                            max_file_bytes=max_file_bytes,
                            unread_above=unread_above,
                        ),
                    ]
                )
            )
    after = root.stat(follow_symlinks=False)
    if any(getattr(before, attr) != getattr(after, attr) for attr in attrs):
        raise ValueError("checkout container changed while hashing")
    return digest.hexdigest()


@dataclass(frozen=True)
class Snapshot:
    slot: str
    fingerprint: str


@dataclass(frozen=True)
class _CacheEntry:
    slot: str
    path: Path
    size: int
    mtime_ns: int
    device: int
    inode: int


def _valid_slot(value: str) -> bool:
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value)


class IncrementalCache:
    def __init__(self, config: ScanConfig, index: SignatureIndex):
        self.config = config
        self.index = index
        default = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local" / "state"))) / "shadowscan"
        self.directory = Path(config.state_dir).expanduser() if config.state_dir else default
        self.directory = self.directory.absolute()
        self.enabled = config.incremental and not config.dump_records
        self.scanner_digest = ""
        self.signature_digest = ""
        if not self.enabled:
            return
        try:
            if fcntl is None:
                raise ValueError("incremental locking requires POSIX flock")
            # Reject state in any configured input, including another connector's.
            for spec in config.enabled_connectors():
                for root in _paths(spec):
                    if self.directory.resolve().is_relative_to(root):
                        raise ValueError("state directory overlaps a scan input")
            self._secure_directory()
            self.scanner_digest = scanner_source_digest()
            # The signature index is stable for this scan. Its semantic digest
            # need not be serialized again for every pre/post input snapshot.
            self.signature_digest = index.fingerprint()
            maintenance_deadline = time.monotonic() + _MAX_CACHE_MAINTENANCE_SECONDS

            def check_maintenance_deadline() -> None:
                if time.monotonic() >= maintenance_deadline:
                    raise _CacheMaintenanceDeadlineExceeded(
                        "incremental cache startup maintenance deadline exceeded"
                    )

            self._maintain_cache(check_deadline=check_maintenance_deadline)
        except (OSError, ValueError, TypeError, _CacheMaintenanceDeadlineExceeded):
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
    def _same_file(path: Path, expected: os.stat_result) -> bool:
        try:
            current = path.stat(follow_symlinks=False)
        except OSError:
            return False
        return (
            stat.S_ISREG(current.st_mode)
            and current.st_dev == expected.st_dev
            and current.st_ino == expected.st_ino
        )

    def _remove_orphan_lock(self, slot: str, *, check_deadline: Callable[[], None] | None = None) -> bool:
        """Remove an unused slot lock without ever replacing an active inode.

        Cache operations take non-blocking locks, so a process that opened the
        old inode but has not locked it either wins first or fails without
        publishing. Rechecking the paired JSON and pathname inode while the
        exclusive lock is held prevents deleting a live slot or a replacement.
        """
        lock_path = self.directory / f"{slot}.lock"
        entry_path = self.directory / f"{slot}.json"
        if check_deadline is not None:
            check_deadline()
        try:
            with self._slot_lock(Snapshot(slot, ""), exclusive=True) as fd:
                if check_deadline is not None:
                    check_deadline()
                try:
                    entry_path.stat(follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    return False
                held = os.fstat(fd)
                current = lock_path.stat(follow_symlinks=False)
                if (
                    not stat.S_ISREG(current.st_mode)
                    or current.st_dev != held.st_dev
                    or current.st_ino != held.st_ino
                ):
                    return False
                if check_deadline is not None:
                    check_deadline()
                lock_path.unlink()
                if check_deadline is not None:
                    check_deadline()
                return True
        except FileNotFoundError:
            return True
        except (OSError, ValueError):
            return False

    def _cache_inventory(self, *, check_deadline: Callable[[], None] | None = None) -> list[_CacheEntry]:
        """Bound directory enumeration and reclaim abandoned state artifacts."""
        if check_deadline is not None:
            check_deadline()
        now_ns = time.time_ns()
        entries: list[_CacheEntry] = []
        scanned = 0
        retained = 0
        with os.scandir(self.directory) as children:
            for child in children:
                if check_deadline is not None:
                    check_deadline()
                scanned += 1
                if scanned > _MAX_CACHE_SCAN_ENTRIES:
                    raise ValueError("incremental state directory scan limit exceeded")
                try:
                    info = child.stat(follow_symlinks=False)
                except OSError:
                    continue
                if check_deadline is not None:
                    check_deadline()
                path = self.directory / child.name
                owned = not hasattr(os, "getuid") or info.st_uid == os.getuid()
                if child.name.startswith(".pending-"):
                    age_ns = max(0, now_ns - info.st_mtime_ns)
                    if (
                        owned
                        and stat.S_ISREG(info.st_mode)
                        and age_ns > int(_PENDING_TTL_SECONDS * 1_000_000_000)
                        and self._same_file(path, info)
                    ):
                        if check_deadline is not None:
                            check_deadline()
                        try:
                            path.unlink()
                        except OSError:
                            pass
                        else:
                            if check_deadline is not None:
                                check_deadline()
                            continue
                elif child.name.endswith(".lock"):
                    slot = child.name.removesuffix(".lock")
                    if _valid_slot(slot) and owned and stat.S_ISREG(info.st_mode):
                        if self._remove_orphan_lock(slot, check_deadline=check_deadline):
                            continue
                retained += 1
                if retained > _MAX_CACHE_DIRECTORY_ENTRIES:
                    raise ValueError("incremental state directory entry limit exceeded")
                if not child.name.endswith(".json"):
                    continue
                slot = child.name.removesuffix(".json")
                if not _valid_slot(slot) or not owned or not stat.S_ISREG(info.st_mode):
                    continue
                entries.append(
                    _CacheEntry(
                        slot=slot,
                        path=path,
                        size=info.st_size,
                        mtime_ns=info.st_mtime_ns,
                        device=info.st_dev,
                        inode=info.st_ino,
                    )
                )
        return entries

    def _remove_entry(self, entry: _CacheEntry, *, check_deadline: Callable[[], None] | None = None) -> bool:
        """Remove an unchanged cache entry only while holding its slot lock."""
        snapshot = Snapshot(entry.slot, "")
        if check_deadline is not None:
            check_deadline()
        try:
            with self._slot_lock(snapshot, exclusive=True):
                if check_deadline is not None:
                    check_deadline()
                try:
                    current = entry.path.stat(follow_symlinks=False)
                except OSError:
                    return True
                if (
                    not stat.S_ISREG(current.st_mode)
                    or current.st_dev != entry.device
                    or current.st_ino != entry.inode
                ):
                    return False
                if check_deadline is not None:
                    check_deadline()
                entry.path.unlink()
                if check_deadline is not None:
                    check_deadline()
                return True
        except (OSError, ValueError):
            return False

    def _maintain_cache(
        self,
        *,
        protected_slots: frozenset[str] = frozenset(),
        check_deadline: Callable[[], None] | None = None,
    ) -> bool:
        """Apply TTL plus deterministic oldest-first entry and byte limits."""
        if check_deadline is not None:
            check_deadline()
        self._secure_directory()
        if check_deadline is not None:
            check_deadline()
        entries = self._cache_inventory(check_deadline=check_deadline)
        total_bytes = 0
        for entry in entries:
            if check_deadline is not None:
                check_deadline()
            total_bytes += entry.size
        total_entries = len(entries)
        cutoff_ns = time.time_ns() - int(_CACHE_TTL_SECONDS * 1_000_000_000)
        for entry in sorted(entries, key=lambda item: (item.mtime_ns, item.slot)):
            if check_deadline is not None:
                check_deadline()
            expired = entry.mtime_ns < cutoff_ns
            over_limit = total_entries > _MAX_CACHE_ENTRIES or total_bytes > _MAX_CACHE_TOTAL_BYTES
            if not expired and not over_limit:
                continue
            if entry.slot in protected_slots or not self._remove_entry(entry, check_deadline=check_deadline):
                continue
            total_entries -= 1
            total_bytes -= entry.size
        if check_deadline is not None:
            check_deadline()
        return total_entries <= _MAX_CACHE_ENTRIES and total_bytes <= _MAX_CACHE_TOTAL_BYTES

    @staticmethod
    def supports_connector(spec: ConnectorSpec, connector_class: type) -> bool:
        """Plugin overrides may collect additional inputs unknown to this cache."""
        if not _eligible(spec):
            return False
        module, _, name = _BUILTIN[spec.name].partition(":")
        return connector_class is getattr(importlib.import_module(module), name)

    def snapshot(
        self,
        spec: ConnectorSpec,
        *,
        check_deadline: Callable[[], None] | None = None,
        deadline: float | None = None,
    ) -> Snapshot | None:
        if not self.enabled or not _eligible(spec):
            return None
        try:
            if check_deadline is not None:
                check_deadline()
            roots = _paths(spec)
            if not roots:
                return None
            code = spec.name in _CODE
            use_git = bool(spec.config.get("use_git", False))
            budget = _HashBudget(check_cancelled=check_deadline)
            if deadline is not None:
                budget.deadline = min(budget.deadline, deadline)
            excluded_dir_names = _literal_excluded_directories(spec)
            # The code scanners never open a file over their max_file_size, so
            # such files are tracked by metadata; a hashed file stays capped.
            unread_above = int(spec.config.get("max_file_size", 1_000_000)) if code else None
            max_bytes = (
                min(unread_above, _MAX_HASH_FILE_BYTES) if unread_above is not None else _MAX_HASH_FILE_BYTES
            )
            inputs = []
            for root in roots:
                if spec.name in {"code.github", "code.gitlab"}:
                    digest = _checkout_container_digest(
                        root,
                        use_git=use_git,
                        budget=budget,
                        max_file_bytes=max_bytes,
                        unread_above=unread_above,
                    )
                else:
                    digest = _tree_digest(
                        root,
                        code=code,
                        use_git=use_git,
                        budget=budget,
                        max_file_bytes=max_bytes,
                        excluded_dir_names=excluded_dir_names,
                        unread_above=unread_above,
                    )
                inputs.append([str(root), digest])
            fingerprint = hashlib.sha256(
                _json(
                    {
                        "format": _FORMAT,
                        "version": __version__,
                        "scanner": self.scanner_digest,
                        "signatures": self.signature_digest,
                        "connector": spec.name,
                        "id": spec.id,
                        "config": spec.config,
                        "inputs": inputs,
                    }
                )
            ).hexdigest()
            slot = hashlib.sha256(_json([spec.name, spec.id, [str(p) for p in roots]])).hexdigest()
            budget.check()
            return Snapshot(slot, fingerprint)
        except (OSError, ValueError, TypeError, subprocess.SubprocessError):
            log.warning("could not fingerprint static input for %s; running a full scan", spec.id)
            return None

    @contextmanager
    def _slot_lock(self, snapshot: Snapshot, *, exclusive: bool) -> Iterator[int]:
        """Use a stable per-slot inode; contention degrades to a full scan."""
        if fcntl is None or not _valid_slot(snapshot.slot):
            raise ValueError("invalid or unsupported incremental lock")
        self._secure_directory()
        lock_path = self.directory / f"{snapshot.slot}.lock"
        fd = os.open(
            lock_path,
            os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
            0o600,
        )
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                raise ValueError("incremental lock must be a private regular file")
            if hasattr(os, "getuid") and info.st_uid != os.getuid():
                raise ValueError("incremental lock must belong to the current user")
            fcntl.flock(fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
            try:
                # An orphan-lock cleaner can unlink this inode after we open
                # it but before flock. Refuse a stale inode so two processes
                # cannot lock different files for the same slot pathname.
                current = lock_path.stat(follow_symlinks=False)
                if current.st_dev != info.st_dev or current.st_ino != info.st_ino:
                    raise ValueError("incremental lock pathname changed before acquisition")
                yield fd
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def load(
        self,
        spec: ConnectorSpec,
        snapshot: Snapshot,
        *,
        check_deadline: Callable[[], None] | None = None,
    ) -> tuple[list[Finding], ScanStats] | None:
        try:
            if check_deadline is not None:
                check_deadline()
            with self._slot_lock(snapshot, exclusive=False):
                return self._load_unlocked(spec, snapshot, check_deadline=check_deadline)
        except (OSError, ValueError):
            return None

    def _load_unlocked(
        self,
        spec: ConnectorSpec,
        snapshot: Snapshot,
        *,
        check_deadline: Callable[[], None] | None = None,
    ) -> tuple[list[Finding], ScanStats] | None:
        path = self.directory / f"{snapshot.slot}.json"
        try:
            if check_deadline is not None:
                check_deadline()
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > _MAX_CACHE_BYTES:
                    return None
                if hasattr(os, "getuid") and info.st_uid != os.getuid():
                    return None
                encoded = bytearray()
                while len(encoded) <= info.st_size:
                    if check_deadline is not None:
                        check_deadline()
                    chunk = stream.read(min(1024 * 1024, info.st_size + 1 - len(encoded)))
                    if not chunk:
                        break
                    encoded.extend(chunk)
                after = os.fstat(stream.fileno())
                if len(encoded) != info.st_size or any(
                    getattr(info, field) != getattr(after, field)
                    for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
                ):
                    return None
                if check_deadline is not None:
                    check_deadline()
                data = strict_json_loads(encoded)
                if check_deadline is not None:
                    check_deadline()
            if data["format"] != _FORMAT or data["fingerprint"] != snapshot.fingerprint:
                return None
            payload = data["payload"]
            if hashlib.sha256(_json(payload)).hexdigest() != data["payload_sha256"]:
                return None
            if not isinstance(payload["findings"], list) or not isinstance(payload["warnings"], list):
                return None
            findings = []
            for record in payload["findings"]:
                if check_deadline is not None:
                    check_deadline()
                finding = Finding.from_dict(record)
                finding.sanitize()
                findings.append(finding)
            if check_deadline is not None:
                check_deadline()
            stats = ScanStats(
                connector=spec.id,
                started_at=now_iso(),
                finished_at=now_iso(),
                findings=len(findings),
                objects_examined=0,
                warnings=sanitize(payload["warnings"]),
                cached=True,
            )
            try:
                os.utime(path, follow_symlinks=False)
            except OSError:
                pass
            return findings, stats
        except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
            return None

    def save(
        self,
        snapshot: Snapshot,
        findings: list[Finding],
        stats: ScanStats,
        *,
        check_deadline: Callable[[], None] | None = None,
        publish_replace: Callable[[str | Path, str | Path], None] | None = None,
    ) -> None:
        if stats.incomplete or stats.errors or stats.skipped:
            return
        try:
            with self._slot_lock(snapshot, exclusive=True):
                self._save_unlocked(
                    snapshot, findings, stats, check_deadline=check_deadline, publish_replace=publish_replace
                )
        except (OSError, ValueError):
            log.warning("incremental state is locked or unavailable; next scan will run in full")

    def _save_unlocked(
        self,
        snapshot: Snapshot,
        findings: list[Finding],
        stats: ScanStats,
        *,
        check_deadline: Callable[[], None] | None = None,
        publish_replace: Callable[[str | Path, str | Path], None] | None = None,
    ) -> None:
        if stats.incomplete or stats.errors or stats.skipped:
            return
        temp: str | None = None
        try:
            self._secure_directory()
            for finding in findings:
                if check_deadline is not None:
                    check_deadline()
                finding.sanitize()
            if check_deadline is not None:
                check_deadline()
            payload = {"findings": [f.to_dict() for f in findings], "warnings": sanitize(stats.warnings)}
            data = _json(
                {
                    "format": _FORMAT,
                    "fingerprint": snapshot.fingerprint,
                    "payload": payload,
                    "payload_sha256": hashlib.sha256(_json(payload)).hexdigest(),
                }
            )
            if len(data) > min(_MAX_CACHE_BYTES, _MAX_CACHE_TOTAL_BYTES):
                return
            if check_deadline is not None:
                check_deadline()
            fd, temp = tempfile.mkstemp(prefix=".pending-", dir=self.directory)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            target = self.directory / f"{snapshot.slot}.json"
            if publish_replace is not None:
                publish_replace(temp, target)
            else:
                if check_deadline is not None:
                    check_deadline()
                os.replace(temp, target)
            temp = None
            if not self._maintain_cache(
                protected_slots=frozenset({snapshot.slot}), check_deadline=check_deadline
            ):
                # Never let a new entry make an already constrained cache
                # exceed its aggregate byte or entry quota.
                target.unlink(missing_ok=True)
        except (OSError, ValueError, TypeError):
            log.warning("could not save incremental state; next scan will run in full")
        finally:
            if temp:
                try:
                    os.unlink(temp)
                except OSError:
                    pass
