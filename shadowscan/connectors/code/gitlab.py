"""GitLab group / project scanner (gitlab.com or self-managed).

Enumerates projects of a group (including subgroups) or an explicit list,
fetches content by shallow clone or the repository files API, then delegates
to the filesystem scanner. Clone, API snapshot and offline plumbing shared
with GitHub lives in :mod:`shadowscan.connectors.code.remote`. Also reports:

* CI/CD variable *names* matching LLM providers (values are never read);
* group service accounts, project bots and access tokens (machine identities);
* GitLab Duo enablement at the group level.

Offline mode: ``input`` pointing at a directory of already-cloned projects.
"""

from __future__ import annotations

import shutil
from collections.abc import Iterable, Iterator
from typing import Any, ClassVar
from urllib.parse import quote, urlsplit

from shadowscan.connectors.base import ConnectorContext, ConnectorError
from shadowscan.connectors.code.remote import (
    API_MAX_BLOB_BYTES,
    RemoteRepositoryConnector,
    config_string_list,
    config_text,
    remote_record,
    repository_blob_id,
    select_api_paths,
)
from shadowscan.connectors.common import apply_matches, config_boolean, finalize, name_matches
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.utils.git import clone_limits, has_clone_size_estimate
from shadowscan.utils.http import HttpError, validate_url


def _is_project_id(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


def project_path_id(value: Any) -> str:
    """Return a GitLab project ``id`` as the ``:id`` segment of an API path.

    The value comes from provider JSON and is interpolated into every request
    about the project. GitLab's project ``id`` is a positive integer; anything
    else (a string, path, bool or nested object) could address a different
    endpoint, so it is refused before any request is built.
    """
    if not _is_project_id(value):
        raise ConnectorError("GitLab project id is not a positive integer; project requests refused")
    return str(value)


class _GitLabMetadata(dict[str, Any]):
    """Provider payload with a dispatch kind assigned by the collector."""

    def __init__(self, kind: str, data: dict[str, Any]) -> None:
        super().__init__({**remote_record(data), "_kind": kind})
        self.kind = kind


class GitLabConnector(RemoteRepositoryConnector):
    name: ClassVar[str] = "code.gitlab"
    surface: ClassVar[Surface] = Surface.CODE
    provider: ClassVar[str | None] = "gitlab"
    description: ClassVar[str] = (
        "Enumerate GitLab group projects and scan their contents; report CI variables and bot identities."
    )
    config_keys: ClassVar[dict[str, str]] = {
        "group": "group path or id (env GITLAB_GROUP; subgroups included); or `projects`",
        "projects": "explicit list of path/with/namespace projects to scan",
        "token": "personal / group access token (env GITLAB_TOKEN) with read_api + read_repository",
        "api_url": "API base (default https://gitlab.com/api/v4; env GITLAB_API_URL)",
        "mode": "clone | api",
        "include_archived": "default false",
        "max_projects": "default 500",
        "clone_max_bytes": (
            "provider size preflight and observed checkout size cap (default 268435456); "
            "strict disk limits require an OS quota"
        ),
        "clone_timeout_seconds": "per-repository git clone deadline (default 120)",
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
        "input": "offline: directory of cloned projects",
    }
    shared_config_keys: ClassVar[dict[str, str]] = {}  # clones are bounded by max_projects, not export limits
    offline_formats: ClassVar[str] = "directory of cloned projects"

    name_field: ClassVar[str] = "path_with_namespace"
    limit_key: ClassVar[str] = "max_projects"
    temp_prefix: ClassVar[str] = "shadowscan-gl-"
    record_noun: ClassVar[str] = "project"
    size_unit: ClassVar[int] = 1  # statistics.repository_size is in bytes
    clone_username: ClassVar[str] = "oauth2"
    blob_id_field: ClassVar[str] = "id"

    def __init__(self, ctx: ConnectorContext) -> None:
        super().__init__(ctx)
        self.api_url = str(ctx.get("api_url", "https://gitlab.com/api/v4", env="GITLAB_API_URL")).rstrip("/")
        self.token = ctx.get("token", env="GITLAB_TOKEN")
        self.mode = self._clone_mode(ctx.get("mode", "clone" if shutil.which("git") else "api"))
        self.max_records = self._record_cap(ctx.get("max_projects", 500))
        self.depth = 1
        self.clone_max_bytes, self.clone_timeout_seconds = clone_limits(
            ctx.get("clone_max_bytes", 256 * 1024 * 1024),
            ctx.get("clone_timeout_seconds", 120),
        )
        self.include_archived = config_boolean(ctx.get("include_archived", False), "include_archived")
        group = ctx.get("group", env="GITLAB_GROUP")
        # A group may be named by its numeric id.
        self.group = config_text(str(group) if _is_project_id(group) else group, "group")
        self.projects = config_string_list(ctx.get("projects"), "projects", allow_int=True)
        self.http = self._api_client({"PRIVATE-TOKEN": self.token} if self.token else {})

    def collect(self) -> Iterable[dict[str, Any]]:
        return self._complete_listing(self._enumerate())

    def _enumerate(self) -> Iterator[dict[str, Any]]:
        group, projects = self.group, self.projects
        if not (group or projects):
            raise ConnectorError("code.gitlab: set 'group' or 'projects'")
        seen: set[int] = set()
        requested: set[str] = set()
        for project in projects:
            if project in requested:
                continue
            requested.add(project)
            if len(seen) >= self.max_records:
                self._cap_reached()
                return
            data = self.http.try_get_json(f"/projects/{quote(project, safe='')}")
            if (
                not isinstance(data, dict)
                or not _is_project_id(data.get("id"))
                or not isinstance(data.get("path_with_namespace"), str)
                or not data["path_with_namespace"].strip()
            ):
                self.ctx.warn(
                    "code.gitlab: explicit project response is missing a valid id or path; coverage unknown"
                )
                continue
            # A successful HTTP response does not prove that it describes the
            # requested project. GitLab may resolve an old path after a rename;
            # require the caller to use the canonical path instead of silently
            # claiming coverage of a different project.
            canonical = data["path_with_namespace"]
            numeric_id = project.isascii() and project.isdecimal() and project.lstrip("0") == str(data["id"])
            if not (numeric_id or project.casefold() == canonical.casefold()):
                self.ctx.warn(
                    "code.gitlab: explicit project response does not match the requested path or id; "
                    "project may have moved; coverage unknown"
                )
                continue
            if data["id"] not in seen:
                seen.add(data["id"])
                yield remote_record(data)
        if group:
            gid = quote(str(group), safe="")
            yield from self._group_identities(str(group), gid)
            params = {
                "per_page": 100,
                "include_subgroups": "true",
                "archived": "false" if not self.include_archived else None,
                # Ordered by a key a push cannot change, so that offset paging stays stable.
                "order_by": "id",
                "sort": "asc",
                "simple": "false",
            }
            params = {k: v for k, v in params.items() if v is not None}
            for p in self._paginate_listing(f"/groups/{gid}/projects", params):
                if not _is_project_id(p.get("id")):
                    # The id addresses every later request about this project;
                    # skip the entry rather than send it to another endpoint.
                    self.ctx.error(
                        "code.gitlab: group project listing entry has no valid numeric id; project skipped"
                    )
                    continue
                if p["id"] in seen:
                    continue
                if len(seen) >= self.max_records:
                    self._cap_reached()
                    return
                seen.add(p["id"])
                yield remote_record(p)

    def _group_identities(self, group: str, gid: str | None = None) -> Iterator[dict[str, Any]]:
        # ``gid`` is the URL-encoded path used in requests; records and the
        # finding identities derived from them carry the plain group path.
        gid = gid if gid is not None else quote(group, safe="")
        for sa in self._optional_list(f"/groups/{gid}/service_accounts"):
            yield _GitLabMetadata("service_account", {**sa, "group": group})
        for tok in self._optional_list(f"/groups/{gid}/access_tokens"):
            yield _GitLabMetadata("group_access_token", {**tok, "group": group})
        variables = [
            {k: v for k, v in var.items() if k != "value"}
            for var in self._optional_list(f"/groups/{gid}/variables")
        ]
        if variables:
            yield _GitLabMetadata("group_variables", {"group": group, "variables": variables})
        group_details = self.http.try_get_json(f"/groups/{gid}")
        if isinstance(group_details, dict) and (group_details.get("duo_features_enabled") is not None):
            yield _GitLabMetadata(
                "duo",
                {
                    "group": group_details.get("full_path"),
                    "duo_features_enabled": group_details.get("duo_features_enabled"),
                    "lock_duo_features_enabled": group_details.get("lock_duo_features_enabled"),
                },
            )

    def _optional_list(self, path: str) -> Iterator[dict[str, Any]]:
        try:
            yield from self.http.paginate_link(path, params={"per_page": 100})
        except HttpError as exc:
            self.ctx.warn(
                f"code.gitlab: metadata HTTP {exc.status} for {path}; coverage unknown",
                incomplete=True,
            )

    def _offline_record(self, name: str) -> dict[str, Any]:
        return {"path_with_namespace": name}

    # --------------------------------------------------------------- analyze
    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        group_variables: dict[str, list[dict[str, Any]]] = {}
        for rec in records:
            kind = rec.kind if isinstance(rec, _GitLabMetadata) else None
            if kind == "service_account" or kind == "group_access_token":
                yield self._identity_finding(rec)
                continue
            if kind == "group_variable":
                group_variables.setdefault(str(rec.get("group")), []).append(rec)
                continue
            if kind == "group_variables":
                group_variables.setdefault(str(rec.get("group")), []).extend(rec.get("variables") or [])
                continue
            if kind == "duo":
                if rec.get("duo_features_enabled"):
                    yield self._duo_finding(rec)
                continue
            yield from self._analyze_repository(rec, self._fetch, self._project_level)
        for group, variables in group_variables.items():
            f = self._variables_finding(group, variables, scope="group")
            if f:
                yield f

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

    def _checkout_account(self, proj: dict[str, Any], full: str) -> Any:
        return (proj.get("namespace") or {}).get("full_path") or full.rsplit("/", 1)[0]

    def _checkout_metadata(self, proj: dict[str, Any], full: str) -> dict[str, Any]:
        return {
            "project": full,
            "web_url": proj.get("web_url"),
            "default_branch": proj.get("default_branch"),
            "visibility": proj.get("visibility"),
            "archived": proj.get("archived"),
            "last_activity_at": proj.get("last_activity_at"),
            "topics": proj.get("topics"),
        }

    def _stamp_activity(self, finding: Finding, proj: dict[str, Any]) -> None:
        finding.last_seen = finding.last_seen or proj.get("last_activity_at")
        finding.first_seen = proj.get("created_at")

    # -------------------------------------------------------------- fetching
    def _clone_size(self, proj: dict[str, Any]) -> Any:
        stats = proj.get("statistics")
        size = stats.get("repository_size") if isinstance(stats, dict) else None
        # GitLab group listings generally omit statistics. Request the
        # project detail when the caller's token can see its size.
        if not has_clone_size_estimate(size) and proj.get("id") is not None:
            detail = self.http.try_get_json(
                f"/projects/{project_path_id(proj['id'])}",
                params={"statistics": "true"},
            )
            detail_stats = detail.get("statistics") if isinstance(detail, dict) else None
            if isinstance(detail_stats, dict):
                size = detail_stats.get("repository_size")
        return size

    def _clone_target(self, proj: dict[str, Any]) -> tuple[str, Any] | None:
        url = proj.get("http_url_to_repo")
        if not url:
            return None
        api = urlsplit(validate_url(self.api_url))
        return f"{api.scheme}://{api.netloc}", url

    def _fetch_via_api(self, proj: dict[str, Any], tmp: str) -> str | None:
        pid = project_path_id(proj.get("id"))
        proj.pop("source_snapshot", None)
        ref = self._api_ref(proj)
        if ref is None:
            return None
        # Tree pages must describe one snapshot. Pin the branch before the
        # first page; pinning only blobs cannot prevent drift between pages.
        commit = self.http.try_get_json(
            f"/projects/{pid}/repository/commits/{quote(ref, safe='')}",
            params={"stats": "false"},
        )
        try:
            if not isinstance(commit, dict) or self._is_error_record(commit):
                raise ConnectorError("invalid commit response")
            snapshot = repository_blob_id(commit.get("id"))
        except ConnectorError:
            self.ctx.warn(
                "code.gitlab: cannot resolve immutable commit; repository content skipped",
                incomplete=True,
            )
            return None
        proj["source_snapshot"] = {
            "provider": "gitlab",
            "capture_method": "gitlab-api",
            "ref": ref,
            "commit_sha": snapshot,
        }
        blobs: dict[str, dict[str, Any]] = {}
        skipped_links = False
        tree_params = {"recursive": "true", "per_page": 100, "ref": snapshot}
        for item in self.http.paginate_link(f"/projects/{pid}/repository/tree", params=tree_params):
            if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                self.ctx.warn("code.gitlab: malformed tree entry; source coverage partial", incomplete=True)
                continue
            if item.get("type") == "commit" or item.get("mode") in {"120000", "160000"}:
                if not skipped_links:
                    self.ctx.warn(
                        "code.gitlab: symbolic links or submodules skipped; source coverage partial",
                        incomplete=True,
                    )
                    skipped_links = True
                continue
            if item.get("type") == "blob":
                blobs[item["path"]] = item
        paths = list(blobs)
        selected = select_api_paths(paths)
        if len(selected) < len(paths):
            self.ctx.warn(
                "code.gitlab: API mode samples repository; source coverage partial",
                incomplete=True,
            )
        dest, _ = self._write_api_snapshot(proj, blobs, selected, tmp)
        return dest

    def _download_blob(self, proj: dict[str, Any], blob_id: str) -> bytes | None:
        pid = project_path_id(proj.get("id"))
        try:
            resp = self.http.get(f"/projects/{pid}/repository/blobs/{blob_id}/raw", stream=True)
            return self.http.read_response_bytes(resp, max_bytes=API_MAX_BLOB_BYTES)
        except HttpError as exc:
            self.ctx.warn(
                f"code.gitlab: repository content HTTP {exc.status}; coverage partial",
                incomplete=True,
            )
        except ValueError:
            self.ctx.warn("code.gitlab: oversized or invalid API content skipped", incomplete=True)
        return None

    # --------------------------------------------------- project-level extra
    def _project_level(self, proj: dict[str, Any]) -> Iterable[Finding]:
        pid = project_path_id(proj.get("id"))
        full = proj.get("path_with_namespace", pid)
        variables = list(self._optional_list(f"/projects/{pid}/variables"))
        f = self._variables_finding(
            full,
            [{k: v for k, v in var.items() if k != "value"} for var in variables],
            scope="project",
        )
        if f:
            yield f
        for tok in self._optional_list(f"/projects/{pid}/access_tokens"):
            yield self._identity_finding(_GitLabMetadata("project_access_token", {**tok, "project": full}))
        for member in self._optional_list(f"/projects/{pid}/members"):
            username = str(member.get("username", ""))
            if member.get("bot") or (username.startswith(("project_", "group_")) and "_bot" in username):
                yield self._identity_finding(_GitLabMetadata("project_bot", {**member, "project": full}))

    def _variables_finding(
        self,
        scope_name: str,
        variables: list[dict[str, Any]],
        scope: str,
    ) -> Finding | None:
        names = [name for v in variables if isinstance(name := v.get("key"), str) and name]
        matches = []
        for n in names:
            matches.extend(self.index.match_env(n))
        if not matches:
            return None
        f = Finding(
            surface=Surface.CODE,
            connector=self.name,
            kind=Kind.SECRET,
            title=f"CI/CD variables for LLM providers in {scope} {scope_name}",
            resource=f"gitlab:{scope_name}/ci-variables",
            resource_type="ci-variables",
            provider="gitlab",
            account=scope_name.split("/")[0],
        )
        matched_names = {m.value for m in matches}
        unmasked = [
            name
            for v in variables
            if isinstance(name := v.get("key"), str) and name in matched_names and not v.get("masked")
        ]
        f.add_evidence(
            Evidence(
                signal="ci:variable-names",
                description=f"CI/CD variable names: {', '.join(sorted(set(names)))[:400]}",
                weight=0.3,
            )
        )
        apply_matches(f, matches, location=f"{scope_name} ({scope} CI/CD variables)", weight_scale=0.8)
        if unmasked:
            f.add_tag("unmasked-ci-variable")
            f.add_evidence(
                Evidence(
                    signal="ci:unmasked",
                    description=f"Provider credentials stored unmasked: {', '.join(unmasked)}",
                    weight=0.4,
                )
            )
        f.metadata["variable_names"] = sorted(set(names))
        f.add_tag("ci-credentials")
        finalize(f, self.index)
        f.kind = Kind.SECRET
        return f

    def _identity_finding(self, rec: dict[str, Any]) -> Finding:
        kind = rec.get("_kind", "identity")
        name = rec.get("name") or rec.get("username") or str(rec.get("id"))
        scope_name = rec.get("project") or rec.get("group") or ""
        f = Finding(
            surface=Surface.CODE,
            connector=self.name,
            kind=Kind.SERVICE_IDENTITY,
            title=f"GitLab {kind.replace('_', ' ')}: {name}",
            resource=f"gitlab:{kind}:{rec.get('id', name)}",
            resource_type=kind,
            provider="gitlab",
            account=str(scope_name).split("/")[0] if scope_name else None,
            owner=rec.get("created_by") or None,
        )
        f.add_evidence(
            Evidence(
                signal=f"gitlab:{kind}",
                description=f"Machine identity in {scope_name or 'group'}",
                weight=0.3,
            )
        )
        scopes = rec.get("scopes") or []
        if scopes:
            f.permissions.extend(scopes)
            apply_matches(f, [m for s in scopes for m in self.index.match_scope(s)], weight_scale=0.5)
        apply_matches(f, name_matches(self.index, name, rec.get("username")), weight_scale=0.8)
        f.metadata.update(
            {
                k: v
                for k, v in rec.items()
                if k
                in {"username", "access_level", "expires_at", "last_used_at", "active", "revoked", "state"}
            }
        )
        f.last_seen = rec.get("last_used_at") or rec.get("last_activity_on")
        f.first_seen = rec.get("created_at")
        finalize(f, self.index)
        f.kind = Kind.SERVICE_IDENTITY
        return f

    def _duo_finding(self, rec: dict[str, Any]) -> Finding:
        f = Finding(
            surface=Surface.CODE,
            connector=self.name,
            kind=Kind.AGENT_CONFIG,
            title=f"GitLab Duo enabled for group {rec.get('group')}",
            resource=f"gitlab:{rec.get('group')}/duo",
            resource_type="platform-setting",
            provider="gitlab",
            account=str(rec.get("group", "")).split("/")[0],
        )
        f.add_framework("identity-app.coding-assistants-saas")
        f.add_evidence(
            Evidence(
                signal="gitlab:duo",
                description=(
                    "GitLab Duo (AI code suggestions / agentic chat / Duo Agent Platform) features enabled"
                ),
                weight=0.8,
            )
        )
        f.add_capability("code-exec")
        f.metadata.update(rec)
        finalize(f, self.index)
        f.kind = Kind.AGENT_CONFIG
        return f
