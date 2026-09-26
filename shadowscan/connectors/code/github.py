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
import os
import shutil
import subprocess
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import quote, urlsplit

from shadowscan.connectors.base import ConnectorContext, ConnectorError
from shadowscan.connectors.code.filesystem import FilesystemConnector

# Shared helpers now live in ``hosted``; the ``X as X`` imports keep them
# importable from this module.
# Re-exported for compatibility. The shared base reads the hosted.py values, so
# patching these names here has no effect.
from shadowscan.connectors.code.hosted import API_MODE_MAX_FILES as API_MODE_MAX_FILES
from shadowscan.connectors.code.hosted import INTERESTING_DIRS as INTERESTING_DIRS
from shadowscan.connectors.code.hosted import SOURCE_SAMPLE as SOURCE_SAMPLE
from shadowscan.connectors.code.hosted import HostedRepositoryConnector, _remote_record, repository_blob_id
from shadowscan.connectors.code.hosted import _OfflineRepository as _OfflineRepository
from shadowscan.connectors.code.hosted import repository_blob_matches as repository_blob_matches
from shadowscan.connectors.code.hosted import repository_target as repository_target
from shadowscan.connectors.code.manifests import is_manifest_name as is_manifest_name
from shadowscan.connectors.common import apply_matches, finalize
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.utils.git import clone_environment as clone_environment
from shadowscan.utils.git import git_argv_prefix as git_argv_prefix
from shadowscan.utils.git import read_git_snapshot
from shadowscan.utils.git import validate_git_ref as validate_git_ref
from shadowscan.utils.http import HttpClient, HttpError, validate_url


def _named_repository(record: Any) -> bool:
    return isinstance(record, dict) and isinstance(record.get("full_name"), str) and bool(record["full_name"])


class GitHubConnector(HostedRepositoryConnector):
    name: ClassVar[str] = "code.github"
    diagnostic_prefix: ClassVar[str] = "code.github"
    source_provider: ClassVar[str] = "github"
    surface: ClassVar[Surface] = Surface.CODE
    provider: ClassVar[str | None] = "github"
    description: ClassVar[str] = "Enumerate GitHub org/user repositories and scan their contents (clone or API mode)."
    config_keys: ClassVar[dict[str, str]] = {
        "org": "organisation login to enumerate (or `user`, or `repos: [owner/name, ...]`)",
        "token": "PAT / app token (env GITHUB_TOKEN); needs repo read, org read",
        "api_url": "API base URL (default https://api.github.com; GHES: https://ghe.example.com/api/v3)",
        "mode": "clone | api (default clone when git is available)",
        "include_archived": "scan archived repositories (default false)",
        "include_forks": "scan forks (default false)",
        "max_repos": "cap on repositories (default 500)",
        "scan_timeout": "matching budget in seconds per file (default 2)",
        "use_git": "opt in to offline git author/date enrichment for trusted metadata; requires Git 2.45+ (default false)",
        "clone_depth": "git clone depth (default 1)",
        "topics": "only repositories with any of these topics",
        "input": "offline: directory containing cloned repositories",
    }
    offline_formats: ClassVar[str] = "directory of cloned repositories"
    repository_field: ClassVar[str] = "full_name"
    limit_key: ClassVar[str] = "max_repos"
    blob_id_field: ClassVar[str] = "sha"
    temp_prefix: ClassVar[str] = "shadowscan-gh-"
    record_label: ClassVar[str] = "repo"

    def __init__(self, ctx: ConnectorContext):
        super().__init__(ctx)
        self.api_url = str(ctx.get("api_url", "https://api.github.com", env="GITHUB_API_URL")).rstrip("/")
        self.token = ctx.get("token", env="GITHUB_TOKEN") or ctx.get("github_token", env="GH_TOKEN")
        self.mode = str(ctx.get("mode", "clone" if shutil.which("git") else "api"))
        self.max_repos = int(ctx.get("max_repos", 500))
        if self.max_repos < 1:
            raise ConnectorError("code.github: max_repos must be positive")
        self.depth = int(ctx.get("clone_depth", 1))
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
                if self._limit_reached(len(seen)):
                    return
                data = self.http.try_get_json(f"/repos/{full}")
                if data and not _named_repository(data):
                    self.ctx.warn(f"code.github: malformed repository record for {full}; skipped", incomplete=True)
                elif data:
                    if data["full_name"] not in seen:
                        seen.add(data["full_name"])
                        yield _remote_record(data)
                else:
                    self.ctx.warn(f"code.github: cannot access {full}", incomplete=True)
        if org:
            for r in self._named_listing(self.http.paginate_link(f"/orgs/{org}/repos", params={"per_page": 100, "type": "all", "sort": "pushed"})):
                if r["full_name"] not in seen and self._wanted(r):
                    if self._limit_reached(len(seen)):
                        return
                    seen.add(r["full_name"])
                    yield _remote_record(r)
        if user:
            for r in self._named_listing(self.http.paginate_link(f"/users/{user}/repos", params={"per_page": 100, "sort": "pushed"})):
                if r["full_name"] not in seen and self._wanted(r):
                    if self._limit_reached(len(seen)):
                        return
                    seen.add(r["full_name"])
                    yield _remote_record(r)

    def _named_listing(self, records: Iterable[Any]) -> Iterator[dict[str, Any]]:
        """Skip malformed listing entries (reported once) instead of stopping the connector."""
        reported = False
        for r in records:
            if _named_repository(r):
                yield r
            elif not reported:
                self.ctx.warn("code.github: malformed repository record in listing; skipped", incomplete=True)
                reported = True

    def _wanted(self, r: dict[str, Any]) -> bool:
        if r.get("archived") and not self.include_archived:
            return False
        if r.get("fork") and not self.include_forks:
            return False
        if self.topics and not (self.topics & set(r.get("topics") or [])):
            return False
        return True

    def _offline_record(self, name: str) -> dict[str, Any]:
        return {"full_name": name, "owner": {"login": name.split("__")[0] if "__" in name else name}}

    # --------------------------------------------------------------- analyze
    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        for repo in records:
            yield from self._scan_repository(repo, self._fetch_repo, self._repo_level_findings)

    def _scan_local(self, repo: dict[str, Any], local: str) -> Iterable[Finding]:
        full = repo.get("full_name") or Path(local).name
        owner_login = (repo.get("owner") or {}).get("login")
        metadata = {
            "repository": full,
            "html_url": repo.get("html_url"),
            "default_branch": repo.get("default_branch"),
            "visibility": repo.get("visibility") or ("private" if repo.get("private") else "public"),
            "archived": repo.get("archived"),
            "pushed_at": repo.get("pushed_at"),
            "language": repo.get("language"),
            "topics": repo.get("topics"),
        }
        for f in self._scan_checkout(FilesystemConnector, repo, local, f"github:{full}", owner_login, metadata):
            if repo.get("pushed_at"):
                f.last_seen = f.last_seen or repo["pushed_at"]
            if repo.get("created_at"):
                f.first_seen = repo["created_at"]
            yield f

    # ------------------------------------------------------------- fetching
    def _fetch_repo(self, repo: dict[str, Any], tmp: str) -> str | None:
        return self._fetch_checkout(repo, tmp, repo["full_name"])

    def _clone(self, repo: dict[str, Any], dest: str) -> bool:
        api = urlsplit(validate_url(self.api_url))
        origin = "https://github.com" if api.hostname == "api.github.com" else f"{api.scheme}://{api.netloc}"
        url = validate_url(repo.get("clone_url") or f"{origin}/{repo['full_name']}.git", origin)
        try:
            res = self._git_clone(repo, url, dest, origin=origin, username="x-access-token", depth=self.depth)
        except (OSError, subprocess.SubprocessError) as exc:
            self.log.debug("git clone error: %s", exc)
            return False
        if res.returncode != 0:
            self.log.debug("git clone failed with status %s", res.returncode)
            return False
        return True

    def _read_git_snapshot(self, local: str, timeout: float) -> dict[str, str] | None:
        # Looked up in this module, where callers substitute the reader.
        return read_git_snapshot(local, timeout=timeout)

    def _fetch_via_api(self, repo: dict[str, Any], tmp: str) -> str | None:
        full = repo["full_name"]
        repo.pop("source_snapshot", None)
        branch = self._api_branch(repo)
        if branch is None:
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
        fetched = self._write_api_blobs(repo, dest, blobs, selected, where=f" in {full}")
        self.log.info("code.github: %s fetched %d/%d files via API", full, fetched, len(paths))
        return dest

    def _download_blob(self, repo: dict[str, Any], blob_id: str) -> bytes | None:
        full = repo["full_name"]
        # A branch can advance after enumeration. Download the enumerated
        # object directly so findings always describe that tree's bytes.
        data = self.http.try_get_json(f"/repos/{full}/git/blobs/{blob_id}")
        if not isinstance(data, dict) or data.get("encoding") != "base64":
            self.ctx.warn(f"code.github: cannot read content in {full}", incomplete=True)
            return None
        try:
            encoded = data.get("content")
            if not isinstance(encoded, str):
                raise ValueError("missing or invalid encoded content")
            # GitHub wraps base64 with newlines; reject all other invalid
            # characters instead of silently decoding corruption as empty.
            content = base64.b64decode(encoded.replace("\r", "").replace("\n", ""), validate=True)
        except (ValueError, TypeError):
            self.ctx.warn(f"code.github: invalid encoded content in {full}", incomplete=True)
            return None
        if len(content) > 512_000:
            self.ctx.warn(f"code.github: oversized API content in {full}", incomplete=True)
            return None
        return content

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
