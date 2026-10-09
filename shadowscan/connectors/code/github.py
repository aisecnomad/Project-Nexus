"""GitHub organisation / repository scanner.

Enumerates repositories (org, user or explicit list), obtains their content
either by shallow ``git clone`` (default, most complete) or through the REST
contents API (``mode: api`` – fetches manifests, configs, workflows and a
bounded sample of source files), then delegates to the filesystem scanner.
Clone, API snapshot and offline plumbing shared with GitLab lives in
:mod:`shadowscan.connectors.code.remote`.

Additional repository-level signals: Actions secret / variable *names*
(never values), Dependabot/Copilot settings, default branch protection.

Offline mode: ``input`` pointing at a directory of already-cloned repositories
(one sub-directory per repository).
"""

from __future__ import annotations

import base64
import re
import shutil
from collections.abc import Iterable, Iterator
from typing import Any, ClassVar, TypeGuard
from urllib.parse import quote, urlsplit

from shadowscan.connectors.base import ConnectorContext, ConnectorError
from shadowscan.connectors.code.remote import (  # noqa: F401 - re-exported for callers and tests
    API_MAX_BLOB_BYTES,
    API_MODE_MAX_FILES,
    INTERESTING_DIRS,
    SOURCE_SAMPLE,
    RemoteRepositoryConnector,
    UnusualRepositoryPath,
    config_integer,
    config_string_list,
    config_text,
    remote_record,
    repository_blob_id,
    repository_blob_matches,
    repository_target,
    select_api_paths,
)
from shadowscan.connectors.common import apply_matches, config_boolean, finalize
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.utils.git import clone_limits
from shadowscan.utils.http import HttpError, validate_url

# Repository-level endpoints listing credential *names* (never values).
_SECRET_NAME_ENDPOINTS = ("actions/secrets", "actions/variables", "codespaces/secrets", "dependabot/secrets")
# One part of ``owner/name``: the characters GitHub allows in logins (EMU
# logins add an underscore suffix) and repository names, never a separator,
# query, fragment or percent-escape.
_FULL_NAME_PART = re.compile(r"[A-Za-z0-9_.-]{1,100}")


def _is_full_name(value: Any) -> TypeGuard[str]:
    if not isinstance(value, str) or value.count("/") != 1:
        return False
    return all(_FULL_NAME_PART.fullmatch(part) and part not in {".", ".."} for part in value.split("/"))


def repository_full_name(value: Any) -> str:
    """Return a repository ``full_name`` as the ``owner/name`` segments of an API path.

    The value comes from provider JSON and is interpolated into every request
    about the repository and into the fallback clone URL. Anything but two
    plain path segments (``..``, extra separators, a query or an escape) could
    address a different endpoint, so it is refused before any request is built.
    """
    if not _is_full_name(value):
        raise ConnectorError(
            "GitHub repository full_name is not a plain owner/name; repository requests refused"
        )
    return value


class GitHubConnector(RemoteRepositoryConnector):
    name: ClassVar[str] = "code.github"
    surface: ClassVar[Surface] = Surface.CODE
    provider: ClassVar[str | None] = "github"
    description: ClassVar[str] = (
        "Enumerate GitHub org/user repositories and scan their contents (clone or API mode)."
    )
    config_keys: ClassVar[dict[str, str]] = {
        "org": "organisation login to enumerate (env GITHUB_ORG); or `user`, or `repos`",
        "user": "user login to enumerate instead of `org`",
        "repos": "explicit list of owner/name repositories to scan",
        "token": "PAT / app token (env GITHUB_TOKEN); needs repo read, org read",
        "github_token": "fallback token key (env GH_TOKEN) used when `token` is unset",
        "api_url": (
            "API base URL (default https://api.github.com, env GITHUB_API_URL; "
            "GHES: https://ghe.example.com/api/v3)"
        ),
        "mode": "clone | api (default clone when git is available)",
        "include_archived": "scan archived repositories (default false)",
        "include_forks": "scan forks (default false)",
        "max_repos": "cap on repositories (default 500)",
        "scan_timeout": "matching budget in seconds per file (default 2)",
        "default_excludes": "see code.filesystem (default true)",
        "strict_coverage": "see code.filesystem (default false)",
        "include_tests": "see code.filesystem (default false)",
        "agent_granularity": "project (default) | source; see code.filesystem",
        "use_git": (
            "opt in to offline git author/date enrichment for trusted metadata; requires Git 2.45+ "
            "(default false)"
        ),
        "exclude": "forwarded to the filesystem scanner (see code.filesystem)",
        "max_file_size": "forwarded to the filesystem scanner (see code.filesystem)",
        "max_files": "forwarded to the filesystem scanner (see code.filesystem)",
        "max_entries": "forwarded to the filesystem scanner (see code.filesystem)",
        "scan_secrets": "forwarded to the filesystem scanner (see code.filesystem)",
        "clone_depth": "git clone depth (default 1)",
        "clone_max_bytes": (
            "provider size preflight and observed checkout size cap (default 268435456); "
            "strict disk limits require an OS quota"
        ),
        "clone_timeout_seconds": "per-repository git clone deadline (default 120)",
        "topics": "only repositories with any of these topics",
        "input": "offline: directory containing cloned repositories",
    }
    shared_config_keys: ClassVar[dict[str, str]] = {}  # clones are bounded by max_repos, not export limits
    offline_formats: ClassVar[str] = "directory of cloned repositories"

    name_field: ClassVar[str] = "full_name"
    limit_key: ClassVar[str] = "max_repos"
    temp_prefix: ClassVar[str] = "shadowscan-gh-"
    record_noun: ClassVar[str] = "repo"
    size_unit: ClassVar[int] = 1024  # the REST API reports repository size in KiB
    clone_username: ClassVar[str] = "x-access-token"
    blob_id_field: ClassVar[str] = "sha"

    def __init__(self, ctx: ConnectorContext) -> None:
        super().__init__(ctx)
        self.api_url = str(ctx.get("api_url", "https://api.github.com", env="GITHUB_API_URL")).rstrip("/")
        self.token = ctx.get("token", env="GITHUB_TOKEN") or ctx.get("github_token", env="GH_TOKEN")
        self.mode = self._clone_mode(ctx.get("mode", "clone" if shutil.which("git") else "api"))
        self.max_records = self._record_cap(ctx.get("max_repos", 500))
        self.depth = config_integer(ctx.get("clone_depth", 1), "clone_depth")
        if self.depth < 1:
            raise ConnectorError("code.github: clone_depth must be positive")
        self.clone_max_bytes, self.clone_timeout_seconds = clone_limits(
            ctx.get("clone_max_bytes", 256 * 1024 * 1024),
            ctx.get("clone_timeout_seconds", 120),
        )
        self.include_archived = config_boolean(ctx.get("include_archived", False), "include_archived")
        self.include_forks = config_boolean(ctx.get("include_forks", False), "include_forks")
        self.topics = set(config_string_list(ctx.get("topics"), "topics"))
        self.org = config_text(ctx.get("org", env="GITHUB_ORG"), "org")
        self.user = config_text(ctx.get("user"), "user")
        self.repos = config_string_list(ctx.get("repos"), "repos")
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        self.http = self._api_client(headers)

    # --------------------------------------------------------------- collect
    def collect(self) -> Iterable[dict[str, Any]]:
        return self._complete_listing(self._enumerate())

    def _enumerate(self) -> Iterator[dict[str, Any]]:
        org, user, repos = self.org, self.user, self.repos
        if not (org or user or repos):
            raise ConnectorError("code.github: set 'org', 'user' or 'repos'")
        seen: set[str] = set()
        for full in repos:
            if full in seen:
                continue
            if len(seen) >= self.max_records:
                self._cap_reached()
                return
            data = self.http.try_get_json(f"/repos/{full}")
            if not data:
                self.ctx.warn(f"code.github: cannot access {full}", incomplete=True)
                continue
            name = data.get("full_name") if isinstance(data, dict) else None
            if not _is_full_name(name) or name.casefold() != str(full).casefold():
                returned = name if isinstance(name, str) and len(name) <= 200 else "an invalid name"
                self.ctx.warn(
                    f"code.github: explicit repository response ({returned}) does not match the "
                    "requested name; the repository may have been renamed; coverage unknown"
                )
                continue
            if name not in seen:
                seen.add(name)
                yield remote_record(data)
        # Ordered by a key a push cannot change, so that offset paging stays stable.
        order = {"sort": "full_name", "direction": "asc"}
        listings: list[tuple[str, dict[str, Any]]] = []
        if org:
            listings.append((f"/orgs/{org}/repos", {"per_page": 100, "type": "all", **order}))
        if user:
            listings.append((f"/users/{user}/repos", {"per_page": 100, **order}))
        for path, params in listings:
            for r in self._paginate_listing(path, params):
                name = r.get("full_name") if isinstance(r, dict) else None
                if not _is_full_name(name):
                    # The name addresses every later request about the repository
                    # and its clone URL; skip the entry rather than send it elsewhere.
                    self.ctx.error(
                        "code.github: repository listing entry has no valid owner/name; repository skipped"
                    )
                    continue
                if name not in seen and self._wanted(r):
                    if len(seen) >= self.max_records:
                        self._cap_reached()
                        return
                    seen.add(name)
                    yield remote_record(r)

    def _wanted(self, r: dict[str, Any]) -> bool:
        if r.get("archived") and not self.include_archived:
            return False
        if r.get("fork") and not self.include_forks:
            return False
        if self.topics and not (self.topics & set(r.get("topics") or [])):
            return False
        return True

    def _offline_record(self, name: str) -> dict[str, Any]:
        # Offline clone directories are conventionally named owner__repository.
        return {"full_name": name, "owner": {"login": name.split("__", 1)[0]}}

    # --------------------------------------------------------------- analyze
    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        for repo in records:
            yield from self._analyze_repository(repo, self._fetch_repo, self._repo_level_findings)

    def _filesystem_options(self) -> dict[str, Any]:
        return {
            k: v
            for k, v in self.ctx.config.items()
            if k
            in {
                "exclude",
                "default_excludes",
                "max_file_size",
                "max_files",
                "max_entries",
                "scan_timeout",
                "scan_secrets",
                "use_git",
                "strict_coverage",
                "include_tests",
                "agent_granularity",
            }
        }

    def _checkout_account(self, repo: dict[str, Any], full: str) -> Any:
        return (repo.get("owner") or {}).get("login")

    def _checkout_metadata(self, repo: dict[str, Any], full: str) -> dict[str, Any]:
        return {
            "repository": full,
            "html_url": repo.get("html_url"),
            "default_branch": repo.get("default_branch"),
            "visibility": repo.get("visibility") or ("private" if repo.get("private") else "public"),
            "archived": repo.get("archived"),
            "pushed_at": repo.get("pushed_at"),
            "language": repo.get("language"),
            "topics": repo.get("topics"),
        }

    def _stamp_activity(self, finding: Finding, repo: dict[str, Any]) -> None:
        if repo.get("pushed_at"):
            finding.last_seen = finding.last_seen or repo["pushed_at"]
        if repo.get("created_at"):
            finding.first_seen = repo["created_at"]

    # ------------------------------------------------------------- fetching
    # GitHub's name for the shared clone-or-API fetch.
    _fetch_repo = RemoteRepositoryConnector._fetch

    def _clone_size(self, repo: dict[str, Any]) -> Any:
        return repo.get("size")

    def _clone_target(self, repo: dict[str, Any]) -> tuple[str, Any]:
        api = urlsplit(validate_url(self.api_url))
        # github.com serves its API from a separate host; GHES serves both from one origin.
        origin = "https://github.com" if api.hostname == "api.github.com" else f"{api.scheme}://{api.netloc}"
        full = repository_full_name(repo.get("full_name"))
        return origin, repo.get("clone_url") or f"{origin}/{full}.git"

    def _fetch_via_api(self, repo: dict[str, Any], tmp: str) -> str | None:
        full = repository_full_name(repo.get("full_name"))
        repo.pop("source_snapshot", None)
        branch = self._api_ref(repo)
        if branch is None:
            return None
        tree = self.http.try_get_json(
            f"/repos/{full}/git/trees/{quote(branch, safe='')}",
            params={"recursive": "1"},
        )
        if not isinstance(tree, dict) or not isinstance(tree.get("tree"), list):
            self.ctx.warn(f"code.github: cannot read tree of {full}", incomplete=True)
            return None
        try:
            tree_sha = repository_blob_id(tree.get("sha"))
        except ConnectorError:
            self.ctx.warn(
                f"code.github: cannot identify immutable tree snapshot for {full}; source provenance unknown",
                incomplete=True,
            )
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
            self.ctx.warn(
                f"code.github: malformed tree entries in {full}; source coverage partial",
                incomplete=True,
            )
        if any(t.get("type") == "commit" or t.get("mode") in {"120000", "160000"} for t in entries):
            self.ctx.warn(
                f"code.github: symbolic links or submodules in {full} skipped; source coverage partial",
                incomplete=True,
            )
        blobs = {
            t["path"]: t
            for t in entries
            if t.get("type") == "blob"
            and t.get("mode") not in {"120000", "160000"}
            and isinstance(t.get("size", 0), int)
            and 0 <= t.get("size", 0) <= API_MAX_BLOB_BYTES
        }
        if any(
            t.get("type") == "blob" and (not isinstance(t.get("size", 0), int) or t.get("size", 0) < 0)
            for t in entries
        ):
            self.ctx.warn(
                f"code.github: invalid blob size metadata in {full}; source coverage partial",
                incomplete=True,
            )
        paths = list(blobs)
        selected = select_api_paths(paths)
        if len(selected) < sum(t.get("type") == "blob" for t in entries):
            self.ctx.warn(
                f"code.github: API mode samples repository {full}; source coverage partial",
                incomplete=True,
            )
        dest, fetched = self._write_api_snapshot(repo, blobs, selected, tmp, f" in {full}")
        self.log.info("code.github: %s fetched %d/%d files via API", full, fetched, len(paths))
        return dest

    def _download_blob(self, repo: dict[str, Any], blob_id: str) -> bytes | None:
        full = repository_full_name(repo.get("full_name"))
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
        if len(content) > API_MAX_BLOB_BYTES:
            self.ctx.warn(f"code.github: oversized API content in {full}", incomplete=True)
            return None
        return content

    # ------------------------------------------------------ repo-level extra
    def _repo_level_findings(self, repo: dict[str, Any]) -> Iterable[Finding]:
        full = repository_full_name(repo.get("full_name"))
        names: list[str] = []
        for endpoint in _SECRET_NAME_ENDPOINTS:
            path = f"/repos/{full}/{endpoint}"
            item_key = "variables" if path.endswith("variables") else "secrets"
            try:
                for item in self.http.paginate_link(path, params={"per_page": 100}, item_key=item_key):
                    if item.get("name"):
                        names.append(item["name"])
            except HttpError as exc:
                self.ctx.warn(
                    f"code.github: repository metadata HTTP {exc.status}; coverage unknown",
                    incomplete=True,
                )
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
        f.add_evidence(
            Evidence(
                signal="ci:secret-names",
                description=(
                    "Actions/Codespaces/Dependabot secret or variable names: "
                    f"{', '.join(sorted(set(names)))[:400]}"
                ),
                location=f"{repo.get('html_url')}/settings/secrets/actions",
                weight=0.3,
            )
        )
        apply_matches(f, matches, location=f"{full} (repository secrets)", weight_scale=0.8)
        f.metadata["secret_names"] = sorted(set(names))
        f.add_tag("ci-credentials")
        finalize(f, self.index)
        f.kind = Kind.SECRET
        yield f
