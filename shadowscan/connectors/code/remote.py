"""Shared plumbing for the hosted Git provider connectors (GitHub, GitLab).

Both providers enumerate repositories through a REST API, obtain content by a
bounded shallow ``git clone`` or a sampled API snapshot, and delegate matching
to the filesystem scanner. The provider modules supply what genuinely differs:
API paths, authentication, record fields, tree enumeration and pagination, and
snapshot identity. The controls both depend on live here once: offline input
confinement, clone origin pinning and git subprocess hardening, tree path
confinement, blob object ID validation and verification of downloaded bytes
against that ID.

Configuration is read by the provider classes, never here, so every key a
connector reads stays visible in its own ``config_keys`` listing.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import tempfile
import time
from abc import abstractmethod
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path, PurePosixPath
from typing import Any, ClassVar

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.connectors.code.manifests import is_manifest_name
from shadowscan.models import Finding
from shadowscan.utils.git import (
    CloneTimeoutError,
    clone_environment,
    exceeds_clone_size,
    git_argv_prefix,
    has_clone_size_estimate,
    read_git_snapshot,
    run_bounded_clone,
    validate_git_ref,
)
from shadowscan.utils.http import HttpClient, HttpError, validate_url

INTERESTING_DIRS = (
    ".github/", ".claude/", ".cursor/", ".vscode/", ".windsurf/", ".codex/", ".gemini/", ".kiro/",
    ".amazonq/", ".continue/", ".roo/", ".well-known/", "config/", "infra/", "terraform/", "deploy/",
    "k8s/", "helm/", "flows/", "workflows/", "agents/", "prompts/",
)
API_MODE_MAX_FILES = 400
SOURCE_SAMPLE = 150
# Largest file API mode downloads; bigger blobs are skipped as partial coverage.
API_MAX_BLOB_BYTES = 512_000

# Agent instruction and tool manifests that API mode always fetches.
_AGENT_FILE_NAMES = frozenset({
    "claude.md", "agents.md", "gemini.md", "codex.md", "warp.md", ".cursorrules", ".windsurfrules",
    ".clinerules", ".mcp.json", "mcp.json", "langgraph.json", "agent.json", "agent-card.json",
    "declarativeagent.json", "modelfile",
})
_CONFIG_SUFFIXES = (".tf", ".bicep", ".yml", ".yaml", ".ipynb")
_SOURCE_SUFFIXES = (".py", ".ts", ".tsx", ".js", ".mjs", ".go", ".rs", ".java", ".kt", ".cs", ".rb", ".php")


class OfflineRepository(dict[str, Any]):
    """Local scan authority created only by the directory input loader.

    The path is an attribute, never a JSON control field: neither a remote API
    response nor an exported/reloaded dictionary can impersonate this record.
    """

    def __init__(self, data: dict[str, Any], local_path: str) -> None:
        super().__init__(data)
        self.local_path = local_path


def remote_record(data: dict[str, Any]) -> dict[str, Any]:
    """Discard private dispatch fields before accepting provider JSON."""
    return {key: value for key, value in data.items() if not key.startswith("_")}


class UnusualRepositoryPath(ConnectorError):
    """A legal Git path this scanner does not materialise (backslash, drive-like prefix)."""


def repository_target(root: str, path: str) -> Path:
    """Validate API tree paths before fetching or writing outside the checkout.

    Traversal and absolute paths are hostile and abort the repository fetch
    before any request. Paths that Git permits but that are ambiguous on a
    local filesystem raise :class:`UnusualRepositoryPath` so callers can skip
    that one file with partial-coverage reporting.
    """
    rel = PurePosixPath(path)
    if not rel.parts or rel.is_absolute() or ".." in rel.parts or "\x00" in path:
        raise ConnectorError("Refusing unsafe repository tree path")
    if "\\" in path or ":" in rel.parts[0]:
        raise UnusualRepositoryPath("Refusing unsafe repository tree path")
    target = (Path(root) / path).resolve()
    if not target.is_relative_to(Path(root).resolve()) or target == Path(root).resolve():
        raise ConnectorError("Repository tree path escapes checkout")
    return target


def repository_blob_id(value: Any) -> str:
    """Accept only immutable Git object IDs before interpolating API paths."""
    if not isinstance(value, str) or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value):
        raise ConnectorError("Repository tree contains an invalid blob object ID")
    return value


def repository_blob_matches(value: str, content: bytes) -> bool:
    """Verify fetched bytes against the immutable Git blob object ID."""
    try:
        object_id = repository_blob_id(value)
        algorithm = "sha1" if len(object_id) == 40 else "sha256"
        header = f"blob {len(content)}\0".encode("ascii")
        digest = hashlib.new(algorithm, header + content, usedforsecurity=False).hexdigest()
    except (ConnectorError, TypeError, ValueError):
        return False
    return digest == object_id


def _always_fetched(path: str, name: str) -> bool:
    """Manifests, agent instructions and infrastructure configuration."""
    return (
        is_manifest_name(name)
        or path.startswith(INTERESTING_DIRS)
        or any(f"/{d}" in path for d in INTERESTING_DIRS)
        or name.lower() in _AGENT_FILE_NAMES
        or name.endswith(_CONFIG_SUFFIXES)
    )


def select_api_paths(paths: list[str]) -> list[str]:
    """Choose the bounded API-mode sample: every high-signal file, then shallow sources."""
    must: list[str] = []
    sample: list[str] = []
    for p in paths:
        name = p.rsplit("/", 1)[-1]
        if _always_fetched(p, name):
            must.append(p)
        elif p.count("/") <= 3 and name.endswith(_SOURCE_SUFFIXES):
            sample.append(p)
    sample.sort(key=lambda x: (x.count("/"), len(x)))
    return must[:API_MODE_MAX_FILES] + sample[: max(0, min(SOURCE_SAMPLE, API_MODE_MAX_FILES - len(must)))]


class RemoteRepositoryConnector(BaseConnector):
    """Clone-or-API repository scanning shared by the hosted Git providers.

    A provider's ``__init__`` reads its configuration and sets the instance
    attributes declared below. The class attributes and the abstract hooks
    name what differs between providers; everything else is common, including
    the failure isolation that keeps one broken repository from hiding the
    rest of the scan.
    """

    # Record field holding the repository path ("owner/name").
    name_field: ClassVar[str]
    # Configuration key capping how many repositories one scan covers.
    limit_key: ClassVar[str]
    # Prefix of the per-repository temporary checkout directory.
    temp_prefix: ClassVar[str]
    # What one scanned record is called in debug logs.
    record_noun: ClassVar[str]
    # Bytes per unit of the provider's repository size estimate.
    size_unit: ClassVar[int]
    # HTTP Basic user name paired with the token for git over HTTPS.
    clone_username: ClassVar[str]
    # Tree entry field holding the blob object ID.
    blob_id_field: ClassVar[str]

    api_url: str
    token: str | None
    mode: str
    max_records: int
    depth: int
    clone_max_bytes: int
    clone_timeout_seconds: float
    http: HttpClient

    # -------------------------------------------------------------- settings
    def _clone_mode(self, value: Any) -> str:
        mode = str(value)
        if mode not in {"clone", "api"}:
            raise ConnectorError(f"{self.name}: mode must be 'clone' or 'api'")
        return mode

    def _record_cap(self, value: Any) -> int:
        cap = int(value)
        if cap < 1:
            raise ConnectorError(f"{self.name}: {self.limit_key} must be positive")
        return cap

    def _api_client(self, headers: dict[str, str]) -> HttpClient:
        # Denied or unavailable optional endpoints mark coverage incomplete.
        return HttpClient(
            self.api_url, headers=headers, on_warning=lambda msg: self.ctx.warn(msg, incomplete=True),
        )

    def _cap_reached(self) -> None:
        self.ctx.warn(f"{self.name}: {self.limit_key} ({self.max_records}) reached", incomplete=True)

    # --------------------------------------------------------------- offline
    @abstractmethod
    def _offline_record(self, name: str) -> dict[str, Any]:
        """Provider record describing the offline clone directory *name*."""

    def load_offline(self, path: str) -> Iterator[dict[str, Any]]:
        p = Path(path).expanduser().absolute()
        if any(part.is_symlink() for part in (p, *p.parents)) or not p.is_dir():
            raise ConnectorError(f"{self.name}: offline input must be a directory of clones: {path}")
        root = p.resolve()
        count = 0
        try:
            for child in sorted(root.iterdir()):
                if child.is_symlink():
                    self.ctx.warn(f"{self.name}: offline clone symlinks are skipped")
                    continue
                if not child.is_dir():
                    continue
                if count >= self.max_records:
                    self._cap_reached()
                    return
                try:
                    child.resolve().relative_to(root)
                except (OSError, ValueError):
                    self.ctx.warn(f"{self.name}: offline clone path escaped its input directory")
                    continue
                count += 1
                yield OfflineRepository(self._offline_record(child.name), str(child))
        except OSError:
            self.ctx.warn(f"{self.name}: could not enumerate offline clones")
            return
        if count == 0:
            self.ctx.warn(f"{self.name}: offline input contains no clone directories")

    # --------------------------------------------------------------- analyze
    def _analyze_repository(
        self,
        repo: dict[str, Any],
        fetch: Callable[[dict[str, Any], str], str | None],
        remote_findings: Callable[[dict[str, Any]], Iterable[Finding]],
    ) -> Iterator[Finding]:
        """Fetch (live records only) and scan one repository.

        *fetch* writes the content under a temporary directory and returns
        the checkout path (or None when there is nothing to scan);
        *remote_findings* reports provider-side metadata for live records. A
        failure is recorded against this repository alone, and the temporary
        checkout is always removed.
        """
        full = repo.get(self.name_field) or repo.get("name")
        self.ctx.examined()
        offline = isinstance(repo, OfflineRepository)
        local = repo.local_path if isinstance(repo, OfflineRepository) else None
        tmp: str | None = None
        try:
            if not local:
                # The scan root check rejects symlinked ancestors; the
                # default temp directory has one on macOS (/var -> /private/var).
                tmp = os.path.realpath(tempfile.mkdtemp(prefix=self.temp_prefix, dir=self.ctx.workdir))
                local = fetch(repo, tmp)
                if not local:
                    return
            yield from self._scan_local(repo, local)
            if not offline:
                yield from remote_findings(repo)
        except HttpError as exc:
            self.ctx.warn(f"{self.name}: {full}: {exc}", incomplete=True)
        except Exception as exc:  # noqa: BLE001
            self.ctx.error(f"{self.name}: {full}: {type(exc).__name__}: {exc}")
            self.log.debug("%s failure (%s)", self.record_noun, type(exc).__name__)
        finally:
            if tmp:
                shutil.rmtree(tmp, ignore_errors=True)

    @abstractmethod
    def _filesystem_options(self) -> dict[str, Any]:
        """Configured scanner options forwarded to the nested filesystem connector."""

    @abstractmethod
    def _checkout_account(self, repo: dict[str, Any], full: str) -> Any:
        """Account (owner or namespace) that findings in this repository belong to."""

    @abstractmethod
    def _checkout_metadata(self, repo: dict[str, Any], full: str) -> dict[str, Any]:
        """Provider repository metadata attached to every finding."""

    @abstractmethod
    def _stamp_activity(self, finding: Finding, repo: dict[str, Any]) -> None:
        """Copy the provider's repository timestamps onto one finding."""

    def _scan_local(self, repo: dict[str, Any], local: str) -> Iterator[Finding]:
        full = repo.get(self.name_field) or Path(local).name
        snapshot = repo.get("source_snapshot")
        cfg = {
            **self._filesystem_options(),
            "path": local,
            "label": f"{self.provider}:{full}",
            "account": self._checkout_account(repo, full),
            "provider": self.provider,
            "metadata": {
                **self._checkout_metadata(repo, full),
                **({"source_snapshot": snapshot} if isinstance(snapshot, dict) else {}),
            },
        }
        fs = FilesystemConnector(ConnectorContext(
            config=cfg, index=self.index, logger=self.log, workdir=self.ctx.workdir,
            deadline=self.ctx.deadline, cancelled=self.ctx.cancelled,
            publication_lock=self.ctx.publication_lock,
        ))
        fs.ctx.stats = self.ctx.stats
        # Share the diagnostic budget so repositories cannot each fill 1000 entries.
        fs.ctx._diagnostic_counts = self.ctx._diagnostic_counts
        for f in fs.analyze([{"path": local}]):
            f.connector = self.name
            f.provider = self.provider
            # The filesystem connector created the finding under its own name.
            # Identity v2 includes connector and provider, so finalize it after
            # projecting the observation onto the provider surface.
            f.id = f.compute_id()
            self._stamp_activity(f, repo)
            yield f

    # -------------------------------------------------------------- fetching
    @abstractmethod
    def _clone_size(self, repo: dict[str, Any]) -> Any:
        """Repository size estimate in ``size_unit`` units; None or malformed when unknown."""

    @abstractmethod
    def _clone_target(self, repo: dict[str, Any]) -> tuple[str, Any] | None:
        """Credential origin and unvalidated clone URL, or None when there is no URL to clone."""

    @abstractmethod
    def _fetch_via_api(self, repo: dict[str, Any], tmp: str) -> str | None:
        """Write a sampled, verified API snapshot under *tmp* and return its checkout path."""

    def _fetch(self, repo: dict[str, Any], tmp: str) -> str | None:
        """Obtain the repository's content: a bounded clone, else sampled API mode."""
        full = repo.get(self.name_field)
        # Provenance is derived from the bytes actually selected for scanning;
        # provider JSON must not supply it.
        repo.pop("source_snapshot", None)
        if self.mode == "clone" and shutil.which("git"):
            dest = os.path.join(tmp, "repo")
            size = self._clone_size(repo)
            if exceeds_clone_size(size, self.size_unit, self.clone_max_bytes):
                self.ctx.warn(
                    f"{self.name}: repository {full} exceeds clone_max_bytes; using sampled API mode",
                    incomplete=True,
                )
            elif not has_clone_size_estimate(size):
                self.ctx.warn(
                    f"{self.name}: size metadata unavailable for {full}; using sampled API mode",
                    incomplete=True,
                )
            else:
                if self._clone(repo, dest):
                    self._set_clone_snapshot(repo, dest)
                    return dest
                self.ctx.warn(
                    f"{self.name}: clone failed for {full}; using sampled API mode", incomplete=True,
                )
                # Never mix bytes from a partial clone into the API checkout.
                if os.path.lexists(dest):
                    if os.path.islink(dest):
                        raise ConnectorError(f"{self.name}: partial clone destination is a symlink")
                    shutil.rmtree(dest)
        elif self.mode == "clone":
            self.ctx.warn(
                f"{self.name}: git is unavailable for {full}; using sampled API mode", incomplete=True,
            )
        self.ctx.check_deadline()
        return self._fetch_via_api(repo, tmp)

    def _set_clone_snapshot(self, repo: dict[str, Any], local: str) -> None:
        remaining = max(0.001, self.ctx.deadline - time.monotonic()) if self.ctx.deadline else 10.0
        snapshot = read_git_snapshot(local, timeout=min(10.0, remaining))
        if snapshot is None:
            self.ctx.warn(
                f"{self.name}: could not record immutable clone revision for {repo.get(self.name_field)}; "
                "source provenance unknown",
                incomplete=True,
            )
            return
        repo["source_snapshot"] = {
            "provider": self.provider,
            "capture_method": "git-clone",
            "ref": validate_git_ref(repo.get("default_branch")),
            **snapshot,
        }

    def _clone(self, repo: dict[str, Any], dest: str) -> bool:
        target = self._clone_target(repo)
        if target is None:
            return False
        origin, candidate = target
        # The token is scoped to the API origin: a clone URL from provider JSON
        # must stay on it, and git may not follow redirects away from it.
        url = validate_url(candidate, origin)
        env = clone_environment(origin, self.token, self.clone_username)
        cmd = [
            *git_argv_prefix(), "clone", "--quiet", "--depth", str(self.depth),
            "--no-tags", "--single-branch",
        ]
        branch = validate_git_ref(repo.get("default_branch"))
        if branch:
            cmd += ["--branch", branch]
        elif repo.get("default_branch"):
            self.ctx.warn(
                f"{self.name}: unsupported default branch; cloned remote HEAD, "
                "requested branch coverage unknown",
                incomplete=True,
            )
        cmd += ["--", url, dest]
        try:
            return run_bounded_clone(cmd, env, self.ctx, self.clone_timeout_seconds)
        except (OSError, CloneTimeoutError) as exc:
            self.log.debug("git clone failed: %s", type(exc).__name__)
            return False

    # ------------------------------------------------------------- API mode
    def _api_ref(self, repo: dict[str, Any]) -> str | None:
        """The branch API mode snapshots; never silently another one."""
        ref = validate_git_ref(repo.get("default_branch") or "main")
        if ref is None:
            self.ctx.warn(
                f"{self.name}: unsupported default branch; repository content skipped", incomplete=True,
            )
        return ref

    @abstractmethod
    def _download_blob(self, repo: dict[str, Any], blob_id: str) -> bytes | None:
        """Download one blob by object ID; None (after a warning) when unavailable or invalid."""

    def _write_api_snapshot(
        self,
        repo: dict[str, Any],
        blobs: dict[str, dict[str, Any]],
        selected: list[str],
        tmp: str,
        where: str = "",
    ) -> tuple[str, int]:
        """Download the selected tree entries and write only verified bytes.

        Returns the checkout directory and the number of files written.
        *where* qualifies per-file warnings (for example ``" in owner/name"``).
        """
        dest = os.path.join(tmp, "repo")
        os.makedirs(dest, exist_ok=True)
        written = 0
        for p in selected:
            try:
                target = repository_target(dest, p)
            except UnusualRepositoryPath:
                # Traversal still aborts the repository; an unusual but legal
                # path only costs that file.
                self.ctx.warn(
                    f"{self.name}: unusual repository tree path skipped; source coverage partial",
                    incomplete=True,
                )
                continue
            try:
                blob_id = repository_blob_id(blobs[p].get(self.blob_id_field))
            except ConnectorError:
                self.ctx.warn(f"{self.name}: invalid blob object ID{where}; content skipped", incomplete=True)
                continue
            # A branch can advance after enumeration. Download the enumerated
            # object directly so findings always describe that tree's bytes.
            content = self._download_blob(repo, blob_id)
            if content is None:
                continue
            if not repository_blob_matches(blob_id, content):
                self.ctx.warn(
                    f"{self.name}: API content does not match its immutable blob ID{where}; content skipped",
                    incomplete=True,
                )
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            written += 1
        return dest, written
