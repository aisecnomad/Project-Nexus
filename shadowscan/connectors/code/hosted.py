"""Shared scanning flow for hosted Git repository providers (GitHub, GitLab).

Provider subclasses enumerate repositories through their REST API. This base
obtains each repository's content by shallow ``git clone`` (default, most
complete) or, when cloning is unavailable or fails, through the provider's
content API (manifests, configs, workflows and a bounded sample of source
files), records the immutable source snapshot, then delegates the checkout to
the filesystem scanner.

Offline mode: ``input`` pointing at a directory of already-cloned repositories
(one sub-directory per repository).
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
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
from shadowscan.utils.git import clone_environment, git_argv_prefix, validate_git_ref
from shadowscan.utils.http import HttpClient, HttpError

INTERESTING_DIRS = (".github/", ".claude/", ".cursor/", ".vscode/", ".windsurf/", ".codex/", ".gemini/", ".kiro/", ".amazonq/", ".continue/", ".roo/", ".well-known/", "config/", "infra/", "terraform/", "deploy/", "k8s/", "helm/", "flows/", "workflows/", "agents/", "prompts/")
API_MODE_MAX_FILES = 400
SOURCE_SAMPLE = 150
# Connector options forwarded to the filesystem scan of each checkout.
_CHECKOUT_SCAN_KEYS = frozenset({"exclude", "max_file_size", "max_files", "scan_timeout", "scan_secrets", "use_git"})


class _OfflineRepository(dict[str, Any]):
    """Local scan authority created only by the directory input loader.

    The path is an attribute, never a JSON control field: neither a remote API
    response nor an exported/reloaded dictionary can impersonate this record.
    """

    def __init__(self, data: dict[str, Any], local_path: str):
        super().__init__(data)
        self.local_path = local_path


def _remote_record(data: dict[str, Any]) -> dict[str, Any]:
    """Discard private dispatch fields before accepting provider JSON."""
    return {key: value for key, value in data.items() if not key.startswith("_")}


def repository_target(root: str, path: str) -> Path:
    """Validate API tree paths before fetching or writing outside the checkout."""
    rel = PurePosixPath(path)
    if not rel.parts or rel.is_absolute() or ".." in rel.parts or "\\" in path or "\x00" in path or ":" in rel.parts[0]:
        raise ConnectorError("Refusing unsafe repository tree path")
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


class HostedRepositoryConnector(BaseConnector):
    """Scan the repositories of a hosted Git provider from clones or its content API.

    Subclasses enumerate repositories (``collect``) and supply the provider
    parts: clone source and credentials, API tree and blob download, record
    shapes and repository-level findings. Diagnostics are prefixed with the
    provider class's ``diagnostic_prefix``.
    """

    # Fixed per provider class, and deliberately not the overridable connector
    # ``name``/``provider``: a plugin subclass (``code.ghe``) keeps the
    # diagnostics, finding provider and therefore finding IDs it had before.
    diagnostic_prefix: ClassVar[str]
    source_provider: ClassVar[str]
    # Record field naming a repository ("full_name", "path_with_namespace").
    repository_field: ClassVar[str]
    # Config key, and connector attribute, holding the cap on repositories.
    limit_key: ClassVar[str]
    # API tree entry field holding a blob's object ID.
    blob_id_field: ClassVar[str]
    # Prefix of the temporary directory a live repository is fetched into.
    temp_prefix: ClassVar[str]
    # Word for a repository in debug logs ("repo", "project").
    record_label: ClassVar[str]

    # Set by the provider constructor.
    api_url: str
    token: Any
    mode: str
    http: HttpClient

    def _limit_reached(self, count: int) -> bool:
        """Report partial coverage once ``count`` repositories reach the configured cap."""
        limit = getattr(self, self.limit_key)
        if count >= limit:
            self.ctx.warn(f"{self.diagnostic_prefix}: {self.limit_key} ({limit}) reached", incomplete=True)
            return True
        return False

    # --------------------------------------------------------------- offline
    def load_offline(self, path: str) -> Iterator[dict[str, Any]]:
        p = Path(path).expanduser().absolute()
        if any(part.is_symlink() for part in (p, *p.parents)) or not p.is_dir():
            raise ConnectorError(f"{self.diagnostic_prefix}: offline input must be a directory of clones: {path}")
        root = p.resolve()
        count = 0
        try:
            for child in sorted(root.iterdir()):
                if child.is_symlink():
                    self.ctx.warn(f"{self.diagnostic_prefix}: offline clone symlinks are skipped")
                    continue
                if not child.is_dir():
                    continue
                if self._limit_reached(count):
                    return
                try:
                    child.resolve().relative_to(root)
                except (OSError, ValueError):
                    self.ctx.warn(f"{self.diagnostic_prefix}: offline clone path escaped its input directory")
                    continue
                count += 1
                yield _OfflineRepository(self._offline_record(child.name), str(child))
        except OSError:
            self.ctx.warn(f"{self.diagnostic_prefix}: could not enumerate offline clones")

    @abstractmethod
    def _offline_record(self, name: str) -> dict[str, Any]:
        """Provider-shaped record for the offline clone directory ``name``."""

    # --------------------------------------------------------------- analyze
    def _scan_repository(
        self,
        repo: dict[str, Any],
        fetch: Callable[[dict[str, Any], str], str | None],
        repository_findings: Callable[[dict[str, Any]], Iterable[Finding]],
    ) -> Iterator[Finding]:
        """Fetch (unless offline) and scan one repository; a failure costs only that repository.

        ``fetch`` and ``repository_findings`` are the provider's own methods
        (for example ``_fetch_repo`` and ``_repo_level_findings``).
        """
        full = repo.get(self.repository_field) or repo.get("name")
        self.ctx.examined()
        offline = isinstance(repo, _OfflineRepository)
        local = repo.local_path if isinstance(repo, _OfflineRepository) else None
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
                yield from repository_findings(repo)
        except HttpError as exc:
            self.ctx.warn(f"{self.diagnostic_prefix}: {full}: {exc}", incomplete=True)
        except Exception as exc:  # noqa: BLE001
            self.ctx.error(f"{self.diagnostic_prefix}: {full}: {type(exc).__name__}: {exc}")
            self.log.debug(f"{self.record_label} failure", exc_info=True)
        finally:
            if tmp:
                shutil.rmtree(tmp, ignore_errors=True)

    @abstractmethod
    def _scan_local(self, repo: dict[str, Any], local: str) -> Iterable[Finding]:
        """Scan the checkout at ``local`` with provider metadata (see ``_scan_checkout``)."""

    def _scan_checkout(
        self, scanner: type[FilesystemConnector], repo: dict[str, Any], local: str,
        label: str, account: Any, metadata: dict[str, Any],
    ) -> Iterator[Finding]:
        """Scan a checkout with ``scanner`` and project its findings onto this provider.

        The provider module passes ``scanner`` (``FilesystemConnector``), so the
        scanner class is looked up, and can be substituted, in that module.
        """
        cfg = {
            **{k: v for k, v in self.ctx.config.items() if k in _CHECKOUT_SCAN_KEYS},
            "path": local,
            "label": label,
            "account": account,
            "provider": self.source_provider,
            "metadata": {
                **metadata,
                **({"source_snapshot": repo["source_snapshot"]} if isinstance(repo.get("source_snapshot"), dict) else {}),
            },
        }
        fs = scanner(ConnectorContext(
            config=cfg, index=self.index, logger=self.log, workdir=self.ctx.workdir,
            deadline=self.ctx.deadline, cancelled=self.ctx.cancelled,
            publication_lock=self.ctx.publication_lock,
        ))
        fs.ctx.stats = self.ctx.stats
        for f in fs.analyze([{"path": local}]):
            f.connector = self.name
            f.provider = self.source_provider
            # The filesystem connector created the finding under its own name.
            # Identity v2 includes connector and provider, so finalize it after
            # projecting the observation onto the provider surface.
            f.id = f.compute_id()
            yield f

    # -------------------------------------------------------------- fetching
    def _fetch_checkout(self, repo: dict[str, Any], tmp: str, name: Any) -> str | None:
        """Clone into ``tmp``, falling back to API mode; ``name`` labels a failed clone."""
        # This field is generated only from the bytes actually selected for
        # scanning; provider JSON must not supply scan provenance.
        repo.pop("source_snapshot", None)
        if self.mode == "clone" and shutil.which("git"):
            dest = os.path.join(tmp, "repo")
            if self._clone(repo, dest):
                self._set_clone_snapshot(repo, dest)
                return dest
            # A timed-out git is killed before its cleanup runs. API mode must
            # not scan a partial checkout (or its .git) as if it were API bytes.
            shutil.rmtree(dest, ignore_errors=True)
            self.ctx.warn(f"{self.diagnostic_prefix}: clone failed for {name}; falling back to API mode")
        self.ctx.check_deadline()
        return self._fetch_via_api(repo, tmp)

    @abstractmethod
    def _clone(self, repo: dict[str, Any], dest: str) -> bool:
        """Clone the repository into ``dest``; False when it could not be cloned."""

    def _git_clone(
        self, repo: dict[str, Any], url: str, dest: str, *, origin: str, username: str, depth: int,
    ) -> subprocess.CompletedProcess[str]:
        """Run a shallow single-branch ``git clone`` within the connector deadline.

        Credentials are scoped to ``origin``. Raises OSError or SubprocessError
        when git cannot run; a nonzero status is left to the caller.
        """
        env = clone_environment(origin, self.token, username)
        cmd = [*git_argv_prefix(), "clone", "--quiet", "--depth", str(depth), "--no-tags", "--single-branch"]
        branch = validate_git_ref(repo.get("default_branch"))
        if branch:
            cmd += ["--branch", branch]
        elif repo.get("default_branch"):
            self.ctx.warn(f"{self.diagnostic_prefix}: unsupported default branch; cloned remote HEAD, requested branch coverage unknown", incomplete=True)
        cmd += ["--", url, dest]
        self.ctx.check_deadline()
        timeout = min(600.0, max(0.001, self.ctx.deadline - time.monotonic())) if self.ctx.deadline else 600.0
        res = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=timeout, check=False)
        self.ctx.check_deadline()
        return res

    def _set_clone_snapshot(self, repo: dict[str, Any], local: str) -> None:
        remaining = max(0.001, self.ctx.deadline - time.monotonic()) if self.ctx.deadline else 10.0
        snapshot = self._read_git_snapshot(local, timeout=min(10.0, remaining))
        if snapshot is None:
            self.ctx.warn(
                f"{self.diagnostic_prefix}: could not record immutable clone revision for {repo.get(self.repository_field)}; source provenance unknown",
                incomplete=True,
            )
            return
        repo["source_snapshot"] = {
            "provider": self.source_provider,
            "capture_method": "git-clone",
            "ref": validate_git_ref(repo.get("default_branch")),
            **snapshot,
        }

    @abstractmethod
    def _read_git_snapshot(self, local: str, timeout: float) -> dict[str, str] | None:
        """Immutable commit and tree IDs of the clone at ``local`` (``read_git_snapshot``)."""

    @abstractmethod
    def _fetch_via_api(self, repo: dict[str, Any], tmp: str) -> str | None:
        """Download a bounded sample of the default branch through the provider API."""

    def _api_branch(self, repo: dict[str, Any]) -> str | None:
        """Default branch for API mode; None, reported, when it is unsupported."""
        ref = validate_git_ref(repo.get("default_branch") or "main")
        if ref is None:
            self.ctx.warn(f"{self.diagnostic_prefix}: unsupported default branch; repository content skipped", incomplete=True)
        return ref

    def _write_api_blobs(
        self, repo: dict[str, Any], dest: str, blobs: dict[str, dict[str, Any]], selected: list[str], where: str = "",
    ) -> int:
        """Download the selected tree entries into ``dest`` and return how many were written.

        Each blob is requested by its enumerated object ID and written only
        when its bytes hash to that ID. ``where`` names the repository in
        diagnostics when the provider does so.
        """
        written = 0
        for p in selected:
            target = repository_target(dest, p)
            try:
                blob_id = repository_blob_id(blobs[p].get(self.blob_id_field))
            except ConnectorError:
                self.ctx.warn(f"{self.diagnostic_prefix}: invalid blob object ID{where}; content skipped", incomplete=True)
                continue
            content = self._download_blob(repo, blob_id)
            if content is None:
                continue
            if not repository_blob_matches(blob_id, content):
                self.ctx.warn(f"{self.diagnostic_prefix}: API content does not match its immutable blob ID{where}; content skipped", incomplete=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            written += 1
        return written

    @abstractmethod
    def _download_blob(self, repo: dict[str, Any], blob_id: str) -> bytes | None:
        """Content of one blob by object ID; None, reported, when it cannot be read."""

    @staticmethod
    def _select_paths(paths: list[str]) -> list[str]:
        must: list[str] = []
        sample: list[str] = []
        for p in paths:
            name = p.rsplit("/", 1)[-1]
            depth = p.count("/")
            if is_manifest_name(name) or p.startswith(INTERESTING_DIRS) or any(f"/{d}" in p for d in INTERESTING_DIRS) or name.lower() in {"claude.md", "agents.md", "gemini.md", "codex.md", "warp.md", ".cursorrules", ".windsurfrules", ".clinerules", ".mcp.json", "mcp.json", "langgraph.json", "agent.json", "agent-card.json", "declarativeagent.json", "modelfile"} or name.endswith((".tf", ".bicep", ".yml", ".yaml", ".ipynb")):
                must.append(p)
            elif depth <= 3 and name.endswith((".py", ".ts", ".tsx", ".js", ".mjs", ".go", ".rs", ".java", ".kt", ".cs", ".rb", ".php")):
                sample.append(p)
        sample.sort(key=lambda x: (x.count("/"), len(x)))
        return must[:API_MODE_MAX_FILES] + sample[: max(0, min(SOURCE_SAMPLE, API_MODE_MAX_FILES - len(must)))]
