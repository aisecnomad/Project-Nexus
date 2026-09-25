"""GitHub organisation / repository scanner.

Enumerates repositories (org, user or explicit list), obtains their content
either by shallow ``git clone`` (default, most complete) or through the REST
contents API (``mode: api`` – fetches manifests, configs, workflows and a
bounded sample of source files), then delegates to the filesystem scanner.

Additional repository-level signals: Actions secret / variable *names*
(never values), Dependabot/Copilot settings, default branch protection.

Offline mode: ``input`` pointing at a directory of already-cloned repositories
(one sub-directory per repository).
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import shutil
import tempfile
import time
from collections.abc import Iterable, Iterator
from pathlib import Path, PurePosixPath
from typing import Any, ClassVar
from urllib.parse import quote, urlsplit

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.connectors.code.manifests import is_manifest_name
from shadowscan.connectors.common import apply_matches, finalize
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.utils.git import (
    CloneTimeoutError,
    clone_environment,
    clone_limits,
    exceeds_clone_size,
    git_argv_prefix,
    has_clone_size_estimate,
    read_git_snapshot,
    run_bounded_clone,
    validate_git_ref,
)
from shadowscan.utils.http import HttpClient, HttpError, validate_url

INTERESTING_DIRS = (".github/", ".claude/", ".cursor/", ".vscode/", ".windsurf/", ".codex/", ".gemini/", ".kiro/", ".amazonq/", ".continue/", ".roo/", ".well-known/", "config/", "infra/", "terraform/", "deploy/", "k8s/", "helm/", "flows/", "workflows/", "agents/", "prompts/")
API_MODE_MAX_FILES = 400
SOURCE_SAMPLE = 150


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


class GitHubConnector(BaseConnector):
    name: ClassVar[str] = "code.github"
    surface: ClassVar[Surface] = Surface.CODE
    provider: ClassVar[str | None] = "github"
    description: ClassVar[str] = "Enumerate GitHub org/user repositories and scan their contents (clone or API mode)."
    config_keys: ClassVar[dict[str, str]] = {
        "org": "organisation login to enumerate (env GITHUB_ORG); or `user`, or `repos`",
        "user": "user login to enumerate instead of `org`",
        "repos": "explicit list of owner/name repositories to scan",
        "token": "PAT / app token (env GITHUB_TOKEN); needs repo read, org read",
        "github_token": "fallback token key (env GH_TOKEN) used when `token` is unset",
        "api_url": "API base URL (default https://api.github.com, env GITHUB_API_URL; GHES: https://ghe.example.com/api/v3)",
        "mode": "clone | api (default clone when git is available)",
        "include_archived": "scan archived repositories (default false)",
        "include_forks": "scan forks (default false)",
        "max_repos": "cap on repositories (default 500)",
        "scan_timeout": "matching budget in seconds per file (default 2)",
        "strict_coverage": "see code.filesystem (default false)",
        "include_tests": "see code.filesystem (default false)",
        "use_git": "opt in to offline git author/date enrichment for trusted metadata; requires Git 2.45+ (default false)",
        "exclude": "forwarded to the filesystem scanner (see code.filesystem)",
        "max_file_size": "forwarded to the filesystem scanner (see code.filesystem)",
        "max_files": "forwarded to the filesystem scanner (see code.filesystem)",
        "scan_secrets": "forwarded to the filesystem scanner (see code.filesystem)",
        "clone_depth": "git clone depth (default 1)",
        "clone_max_bytes": "preflight repository size cap (default 268435456); requires a disk quota for hard limits",
        "clone_timeout_seconds": "per-repository git clone deadline (default 120)",
        "topics": "only repositories with any of these topics",
        "input": "offline: directory containing cloned repositories",
    }
    shared_config_keys: ClassVar[dict[str, str]] = {}  # clones are bounded by max_repos, not export limits
    offline_formats: ClassVar[str] = "directory of cloned repositories"

    def __init__(self, ctx: ConnectorContext):
        super().__init__(ctx)
        self.api_url = str(ctx.get("api_url", "https://api.github.com", env="GITHUB_API_URL")).rstrip("/")
        self.token = ctx.get("token", env="GITHUB_TOKEN") or ctx.get("github_token", env="GH_TOKEN")
        self.mode = str(ctx.get("mode", "clone" if shutil.which("git") else "api"))
        if self.mode not in {"clone", "api"}:
            raise ConnectorError("code.github: mode must be 'clone' or 'api'")
        self.max_repos = int(ctx.get("max_repos", 500))
        if self.max_repos < 1:
            raise ConnectorError("code.github: max_repos must be positive")
        self.depth = int(ctx.get("clone_depth", 1))
        self.clone_max_bytes, self.clone_timeout_seconds = clone_limits(
            ctx.get("clone_max_bytes", 256 * 1024 * 1024), ctx.get("clone_timeout_seconds", 120),
        )
        self.include_archived = bool(ctx.get("include_archived", False))
        self.include_forks = bool(ctx.get("include_forks", False))
        self.topics = set(ctx.get("topics", []) or [])
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        self.http = HttpClient(self.api_url, headers=headers, on_warning=lambda msg: self.ctx.warn(msg, incomplete=True))

    # --------------------------------------------------------------- collect
    def collect(self) -> Iterable[dict[str, Any]]:
        org = self.ctx.get("org", env="GITHUB_ORG")
        user = self.ctx.get("user")
        repos = self.ctx.get("repos") or []
        if not (org or user or repos):
            raise ConnectorError("code.github: set 'org', 'user' or 'repos'")
        seen: set[str] = set()
        if repos:
            for full in repos:
                if full in seen:
                    continue
                if len(seen) >= self.max_repos:
                    self.ctx.warn(f"code.github: max_repos ({self.max_repos}) reached", incomplete=True)
                    return
                data = self.http.try_get_json(f"/repos/{full}")
                if data:
                    if data["full_name"] not in seen:
                        seen.add(data["full_name"])
                        yield _remote_record(data)
                else:
                    self.ctx.warn(f"code.github: cannot access {full}", incomplete=True)
        if org:
            for r in self.http.paginate_link(f"/orgs/{org}/repos", params={"per_page": 100, "type": "all", "sort": "pushed"}):
                if r["full_name"] not in seen and self._wanted(r):
                    if len(seen) >= self.max_repos:
                        self.ctx.warn(f"code.github: max_repos ({self.max_repos}) reached", incomplete=True)
                        return
                    seen.add(r["full_name"])
                    yield _remote_record(r)
        if user:
            for r in self.http.paginate_link(f"/users/{user}/repos", params={"per_page": 100, "sort": "pushed"}):
                if r["full_name"] not in seen and self._wanted(r):
                    if len(seen) >= self.max_repos:
                        self.ctx.warn(f"code.github: max_repos ({self.max_repos}) reached", incomplete=True)
                        return
                    seen.add(r["full_name"])
                    yield _remote_record(r)

    def _wanted(self, r: dict[str, Any]) -> bool:
        if r.get("archived") and not self.include_archived:
            return False
        if r.get("fork") and not self.include_forks:
            return False
        if self.topics and not (self.topics & set(r.get("topics") or [])):
            return False
        return True

    def load_offline(self, path: str) -> Iterator[dict[str, Any]]:
        p = Path(path).expanduser().absolute()
        if any(part.is_symlink() for part in (p, *p.parents)) or not p.is_dir():
            raise ConnectorError(f"code.github: offline input must be a directory of clones: {path}")
        root = p.resolve()
        count = 0
        try:
            for child in sorted(root.iterdir()):
                if child.is_symlink():
                    self.ctx.warn("code.github: offline clone symlinks are skipped")
                    continue
                if not child.is_dir():
                    continue
                if count >= self.max_repos:
                    self.ctx.warn(f"code.github: max_repos ({self.max_repos}) reached", incomplete=True)
                    return
                try:
                    child.resolve().relative_to(root)
                except (OSError, ValueError):
                    self.ctx.warn("code.github: offline clone path escaped its input directory")
                    continue
                count += 1
                yield _OfflineRepository({"full_name": child.name, "owner": {"login": child.name.split("__")[0] if "__" in child.name else child.name}}, str(child))
        except OSError:
            self.ctx.warn("code.github: could not enumerate offline clones")

    # --------------------------------------------------------------- analyze
    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        for repo in records:
            full = repo.get("full_name") or repo.get("name")
            self.ctx.examined()
            offline = isinstance(repo, _OfflineRepository)
            local = repo.local_path if isinstance(repo, _OfflineRepository) else None
            tmp: str | None = None
            try:
                if not local:
                    # The scan root check rejects symlinked ancestors; the
                    # default temp directory has one on macOS (/var -> /private/var).
                    tmp = os.path.realpath(tempfile.mkdtemp(prefix="shadowscan-gh-", dir=self.ctx.workdir))
                    local = self._fetch_repo(repo, tmp)
                    if not local:
                        continue
                yield from self._scan_local(repo, local)
                if not offline:
                    yield from self._repo_level_findings(repo)
            except HttpError as exc:
                self.ctx.warn(f"code.github: {full}: {exc}", incomplete=True)
            except Exception as exc:  # noqa: BLE001
                self.ctx.error(f"code.github: {full}: {type(exc).__name__}: {exc}")
                self.log.debug("repo failure (%s)", type(exc).__name__)
            finally:
                if tmp:
                    shutil.rmtree(tmp, ignore_errors=True)

    def _scan_local(self, repo: dict[str, Any], local: str) -> Iterable[Finding]:
        full = repo.get("full_name") or Path(local).name
        owner_login = (repo.get("owner") or {}).get("login")
        cfg = {
            **{k: v for k, v in self.ctx.config.items() if k in {"exclude", "max_file_size", "max_files", "scan_timeout", "scan_secrets", "use_git", "strict_coverage", "include_tests"}},
            "path": local,
            "label": f"github:{full}",
            "account": owner_login,
            "provider": "github",
            "metadata": {
                "repository": full,
                "html_url": repo.get("html_url"),
                "default_branch": repo.get("default_branch"),
                "visibility": repo.get("visibility") or ("private" if repo.get("private") else "public"),
                "archived": repo.get("archived"),
                "pushed_at": repo.get("pushed_at"),
                "language": repo.get("language"),
                "topics": repo.get("topics"),
                **({"source_snapshot": repo["source_snapshot"]} if isinstance(repo.get("source_snapshot"), dict) else {}),
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
            f.provider = "github"
            # The filesystem connector created the finding under its own name.
            # Identity v2 includes connector and provider, so finalize it after
            # projecting the observation onto the GitHub surface.
            f.id = f.compute_id()
            if repo.get("pushed_at"):
                f.last_seen = f.last_seen or repo["pushed_at"]
            if repo.get("created_at"):
                f.first_seen = repo["created_at"]
            yield f

    # ------------------------------------------------------------- fetching
    def _fetch_repo(self, repo: dict[str, Any], tmp: str) -> str | None:
        full = repo["full_name"]
        # This field is generated only from the bytes actually selected for
        # scanning; provider JSON must not supply scan provenance.
        repo.pop("source_snapshot", None)
        if self.mode == "clone" and shutil.which("git"):
            dest = os.path.join(tmp, "repo")
            size = repo.get("size")
            if exceeds_clone_size(size, 1024, self.clone_max_bytes):
                self.ctx.warn(f"code.github: repository {full} exceeds clone_max_bytes; using sampled API mode", incomplete=True)
            elif not has_clone_size_estimate(size):
                self.ctx.warn(
                    f"code.github: size metadata unavailable for {full}; using sampled API mode",
                    incomplete=True,
                )
            else:
                if self._clone(repo, dest):
                    self._set_clone_snapshot(repo, dest)
                    return dest
                self.ctx.warn(f"code.github: clone failed for {full}; using sampled API mode", incomplete=True)
                # Never mix bytes from a partial clone into the API checkout.
                if os.path.lexists(dest):
                    if os.path.islink(dest):
                        raise ConnectorError("code.github: partial clone destination is a symlink")
                    shutil.rmtree(dest)
        elif self.mode == "clone":
            self.ctx.warn(f"code.github: git is unavailable for {full}; using sampled API mode", incomplete=True)
        self.ctx.check_deadline()
        return self._fetch_via_api(repo, tmp)

    def _set_clone_snapshot(self, repo: dict[str, Any], local: str) -> None:
        remaining = max(0.001, self.ctx.deadline - time.monotonic()) if self.ctx.deadline else 10.0
        snapshot = read_git_snapshot(local, timeout=min(10.0, remaining))
        if snapshot is None:
            self.ctx.warn(
                f"code.github: could not record immutable clone revision for {repo.get('full_name')}; source provenance unknown",
                incomplete=True,
            )
            return
        repo["source_snapshot"] = {
            "provider": "github",
            "capture_method": "git-clone",
            "ref": validate_git_ref(repo.get("default_branch")),
            **snapshot,
        }

    def _clone(self, repo: dict[str, Any], dest: str) -> bool:
        api = urlsplit(validate_url(self.api_url))
        origin = "https://github.com" if api.hostname == "api.github.com" else f"{api.scheme}://{api.netloc}"
        url = validate_url(repo.get("clone_url") or f"{origin}/{repo['full_name']}.git", origin)
        env = clone_environment(origin, self.token, "x-access-token")
        cmd = [*git_argv_prefix(), "clone", "--quiet", "--depth", str(self.depth), "--no-tags", "--single-branch"]
        branch = validate_git_ref(repo.get("default_branch"))
        if branch:
            cmd += ["--branch", branch]
        elif repo.get("default_branch"):
            self.ctx.warn("code.github: unsupported default branch; cloned remote HEAD, requested branch coverage unknown", incomplete=True)
        cmd += ["--", url, dest]
        try:
            return run_bounded_clone(cmd, env, self.ctx, self.clone_timeout_seconds)
        except (OSError, CloneTimeoutError) as exc:
            self.log.debug("git clone failed: %s", type(exc).__name__)
            return False

    def _fetch_via_api(self, repo: dict[str, Any], tmp: str) -> str | None:
        full = repo["full_name"]
        repo.pop("source_snapshot", None)
        branch = validate_git_ref(repo.get("default_branch") or "main")
        if branch is None:
            self.ctx.warn("code.github: unsupported default branch; repository content skipped", incomplete=True)
            return None
        tree = self.http.try_get_json(f"/repos/{full}/git/trees/{quote(branch, safe='')}", params={"recursive": "1"})
        if not isinstance(tree, dict) or not isinstance(tree.get("tree"), list):
            self.ctx.warn(f"code.github: cannot read tree of {full}", incomplete=True)
            return None
        try:
            tree_sha = repository_blob_id(tree.get("sha"))
        except ConnectorError:
            self.ctx.warn(f"code.github: cannot identify immutable tree snapshot for {full}; source provenance unknown", incomplete=True)
        else:
            repo["source_snapshot"] = {
                "provider": "github",
                "capture_method": "github-api",
                "ref": branch,
                "tree_sha": tree_sha,
            }
        if tree.get("truncated"):
            self.ctx.warn(f"code.github: tree of {full} truncated; results partial", incomplete=True)
        # Gitlinks and symlink blobs are not regular source files. In
        # particular the contents endpoint can dereference a symlink; keep the
        # same confinement and partial-coverage behavior as a local checkout.
        entries = [t for t in tree["tree"] if isinstance(t, dict) and isinstance(t.get("path"), str)]
        if len(entries) != len(tree["tree"]):
            self.ctx.warn(f"code.github: malformed tree entries in {full}; source coverage partial", incomplete=True)
        if any(t.get("type") == "commit" or t.get("mode") in {"120000", "160000"} for t in entries):
            self.ctx.warn(f"code.github: symbolic links or submodules in {full} skipped; source coverage partial", incomplete=True)
        blobs = {
            t["path"]: t for t in entries
            if t.get("type") == "blob" and t.get("mode") not in {"120000", "160000"}
            and isinstance(t.get("size", 0), int) and 0 <= t.get("size", 0) <= 512_000
        }
        if any(t.get("type") == "blob" and (not isinstance(t.get("size", 0), int) or t.get("size", 0) < 0) for t in entries):
            self.ctx.warn(f"code.github: invalid blob size metadata in {full}; source coverage partial", incomplete=True)
        paths = list(blobs)
        selected = self._select_paths(paths)
        if len(selected) < sum(t.get("type") == "blob" for t in entries):
            self.ctx.warn(f"code.github: API mode samples repository {full}; source coverage partial", incomplete=True)
        dest = os.path.join(tmp, "repo")
        os.makedirs(dest, exist_ok=True)
        fetched = 0
        for p in selected:
            try:
                target = repository_target(dest, p)
            except UnusualRepositoryPath:
                # Traversal still aborts the repository; an unusual but legal
                # path only costs that file.
                self.ctx.warn("code.github: unusual repository tree path skipped; source coverage partial", incomplete=True)
                continue
            try:
                blob_id = repository_blob_id(blobs[p].get("sha"))
            except ConnectorError:
                self.ctx.warn(f"code.github: invalid blob object ID in {full}; content skipped", incomplete=True)
                continue
            # A branch can advance after enumeration. Download the enumerated
            # object directly so findings always describe that tree's bytes.
            data = self.http.try_get_json(f"/repos/{full}/git/blobs/{blob_id}")
            if not isinstance(data, dict) or data.get("encoding") != "base64":
                self.ctx.warn(f"code.github: cannot read content in {full}", incomplete=True)
                continue
            try:
                encoded = data.get("content")
                if not isinstance(encoded, str):
                    raise ValueError("missing or invalid encoded content")
                # GitHub wraps base64 with newlines; reject all other invalid
                # characters instead of silently decoding corruption as empty.
                content = base64.b64decode(encoded.replace("\r", "").replace("\n", ""), validate=True)
            except (ValueError, TypeError):
                self.ctx.warn(f"code.github: invalid encoded content in {full}", incomplete=True)
                continue
            if len(content) > 512_000:
                self.ctx.warn(f"code.github: oversized API content in {full}", incomplete=True)
                continue
            if not repository_blob_matches(blob_id, content):
                self.ctx.warn(f"code.github: API content does not match its immutable blob ID in {full}; content skipped", incomplete=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            fetched += 1
        self.log.info("code.github: %s fetched %d/%d files via API", full, fetched, len(paths))
        return dest

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

    # ------------------------------------------------------ repo-level extra
    def _repo_level_findings(self, repo: dict[str, Any]) -> Iterable[Finding]:
        full = repo["full_name"]
        names: list[str] = []
        for path in (f"/repos/{full}/actions/secrets", f"/repos/{full}/actions/variables", f"/repos/{full}/codespaces/secrets", f"/repos/{full}/dependabot/secrets"):
            try:
                for item in self.http.paginate_link(path, params={"per_page": 100}, item_key="variables" if path.endswith("variables") else "secrets"):
                    if item.get("name"):
                        names.append(item["name"])
            except HttpError as exc:
                self.ctx.warn(f"code.github: repository metadata HTTP {exc.status}; coverage unknown", incomplete=True)
        if not names:
            return
        matches = []
        for n in names:
            matches.extend(self.index.match_env(n))
        if not matches:
            return
        f = Finding(
            surface=Surface.CODE,
            connector=self.name,
            kind=Kind.SECRET,
            title=f"CI secrets for LLM providers configured in {full}",
            resource=f"github:{full}/actions-secrets",
            resource_type="ci-secrets",
            provider="github",
            account=(repo.get("owner") or {}).get("login"),
        )
        f.add_evidence(Evidence(signal="ci:secret-names", description=f"Actions/Codespaces/Dependabot secret or variable names: {', '.join(sorted(set(names)))[:400]}", location=f"{repo.get('html_url')}/settings/secrets/actions", weight=0.3))
        apply_matches(f, matches, location=f"{full} (repository secrets)", weight_scale=0.8)
        f.metadata["secret_names"] = sorted(set(names))
        f.add_tag("ci-credentials")
        finalize(f, self.index)
        f.kind = Kind.SECRET
        yield f
