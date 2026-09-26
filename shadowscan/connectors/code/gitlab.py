"""GitLab group / project scanner (gitlab.com or self-managed).

Enumerates projects of a group (including subgroups) or an explicit list,
fetches content by shallow clone or the repository files API, then delegates
to the filesystem scanner. Also reports:

* CI/CD variable *names* matching LLM providers (values are never read);
* group service accounts, project bots and access tokens (machine identities);
* GitLab Duo enablement at the group level.

Offline mode: ``input`` pointing at a directory of already-cloned projects.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import quote, urlsplit

from shadowscan.connectors.base import ConnectorContext, ConnectorError
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.connectors.code.hosted import HostedRepositoryConnector, _remote_record, repository_blob_id
from shadowscan.connectors.common import apply_matches, finalize, name_matches
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.utils.git import read_git_snapshot
from shadowscan.utils.http import HttpClient, HttpError, validate_url


class _GitLabMetadata(dict[str, Any]):
    """Provider payload with a dispatch kind assigned by the collector."""

    def __init__(self, kind: str, data: dict[str, Any]):
        super().__init__({**_remote_record(data), "_kind": kind})
        self.kind = kind


def _identified_project(record: Any) -> bool:
    return isinstance(record, dict) and type(record.get("id")) is int


class GitLabConnector(HostedRepositoryConnector):
    name: ClassVar[str] = "code.gitlab"
    surface: ClassVar[Surface] = Surface.CODE
    provider: ClassVar[str | None] = "gitlab"
    description: ClassVar[str] = "Enumerate GitLab group projects and scan their contents; report CI variables and bot identities."
    config_keys: ClassVar[dict[str, str]] = {
        "group": "group path or id (subgroups included); or `projects: [path/with/namespace, ...]`",
        "token": "personal / group access token (env GITLAB_TOKEN) with read_api + read_repository",
        "api_url": "API base (default https://gitlab.com/api/v4)",
        "mode": "clone | api",
        "include_archived": "default false",
        "max_projects": "default 500",
        "scan_timeout": "matching budget in seconds per file (default 2)",
        "use_git": "opt in to offline git author/date enrichment for trusted metadata; requires Git 2.45+ (default false)",
        "input": "offline: directory of cloned projects",
    }
    offline_formats: ClassVar[str] = "directory of cloned projects"
    repository_field: ClassVar[str] = "path_with_namespace"
    limit_key: ClassVar[str] = "max_projects"
    blob_id_field: ClassVar[str] = "id"
    temp_prefix: ClassVar[str] = "shadowscan-gl-"
    record_label: ClassVar[str] = "project"

    def __init__(self, ctx: ConnectorContext):
        super().__init__(ctx)
        self.api_url = str(ctx.get("api_url", "https://gitlab.com/api/v4", env="GITLAB_API_URL")).rstrip("/")
        self.token = ctx.get("token", env="GITLAB_TOKEN")
        self.mode = str(ctx.get("mode", "clone" if shutil.which("git") else "api"))
        self.max_projects = int(ctx.get("max_projects", 500))
        if self.max_projects < 1:
            raise ConnectorError("code.gitlab: max_projects must be positive")
        self.include_archived = bool(ctx.get("include_archived", False))
        headers = {"PRIVATE-TOKEN": self.token} if self.token else {}
        self.http = HttpClient(self.api_url, headers=headers, on_warning=lambda msg: self.ctx.warn(msg, incomplete=True))

    def collect(self) -> Iterable[dict[str, Any]]:
        group = self.ctx.get("group", env="GITLAB_GROUP")
        projects = self.ctx.get("projects") or []
        if not (group or projects):
            raise ConnectorError("code.gitlab: set 'group' or 'projects'")
        seen: set[int] = set()
        requested: set[str] = set()
        for p in projects:
            if str(p) in requested:
                continue
            requested.add(str(p))
            if self._limit_reached(len(seen)):
                return
            data = self.http.try_get_json(f"/projects/{quote(str(p), safe='')}")
            if data and not _identified_project(data):
                self.ctx.warn("code.gitlab: malformed project record skipped; coverage partial", incomplete=True)
            elif data and data["id"] not in seen:
                seen.add(data["id"])
                yield _remote_record(data)
        if group:
            gid = quote(str(group), safe="")
            yield from self._group_identities(str(group), gid)
            params = {"per_page": 100, "include_subgroups": "true", "archived": "false" if not self.include_archived else None, "order_by": "last_activity_at", "simple": "false"}
            params = {k: v for k, v in params.items() if v is not None}
            reported = False
            for p in self.http.paginate_link(f"/groups/{gid}/projects", params=params):
                if not _identified_project(p):
                    if not reported:
                        self.ctx.warn("code.gitlab: malformed project record skipped; coverage partial", incomplete=True)
                        reported = True
                    continue
                if p["id"] in seen:
                    continue
                if self._limit_reached(len(seen)):
                    return
                seen.add(p["id"])
                yield _remote_record(p)

    def _group_identities(self, group: str, gid: str | None = None) -> Iterator[dict[str, Any]]:
        # ``gid`` is the URL-encoded path used in requests; records and the
        # finding identities derived from them carry the plain group path.
        gid = gid if gid is not None else quote(group, safe="")
        for sa in self._optional_list(f"/groups/{gid}/service_accounts"):
            yield _GitLabMetadata("service_account", {**sa, "group": group})
        for tok in self._optional_list(f"/groups/{gid}/access_tokens"):
            yield _GitLabMetadata("group_access_token", {**tok, "group": group})
        variables = [{k: v for k, v in var.items() if k != "value"} for var in self._optional_list(f"/groups/{gid}/variables")]
        if variables:
            yield _GitLabMetadata("group_variables", {"group": group, "variables": variables})
        group = self.http.try_get_json(f"/groups/{gid}")
        if isinstance(group, dict) and (group.get("duo_features_enabled") is not None):
            yield _GitLabMetadata("duo", {"group": group.get("full_path"), "duo_features_enabled": group.get("duo_features_enabled"), "lock_duo_features_enabled": group.get("lock_duo_features_enabled")})

    def _optional_list(self, path: str) -> Iterator[dict[str, Any]]:
        reported = False
        try:
            for item in self.http.paginate_link(path, params={"per_page": 100}):
                if isinstance(item, dict):
                    yield item
                elif not reported:
                    self.ctx.warn(f"code.gitlab: malformed metadata record for {path}; coverage partial", incomplete=True)
                    reported = True
        except HttpError as exc:
            self.ctx.warn(f"code.gitlab: metadata HTTP {exc.status} for {path}; coverage unknown", incomplete=True)

    def _offline_record(self, name: str) -> dict[str, Any]:
        return {"path_with_namespace": name}

    # --------------------------------------------------------------- analyze
    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        # Group CI variables are reported after the stream ends. If collection
        # fails partway, still report the variables already seen (an unmasked
        # provider key must not vanish with a later listing error).
        group_variables: dict[str, list[dict[str, Any]]] = {}
        try:
            yield from self._analyze_records(records, group_variables)
        except Exception:
            yield from self._group_variable_findings(group_variables)
            raise
        yield from self._group_variable_findings(group_variables)

    def _group_variable_findings(self, group_variables: dict[str, list[dict[str, Any]]]) -> Iterator[Finding]:
        for group, variables in group_variables.items():
            f = self._variables_finding(group, variables, scope="group")
            if f:
                yield f
        group_variables.clear()

    def _analyze_records(self, records: Iterable[dict[str, Any]], group_variables: dict[str, list[dict[str, Any]]]) -> Iterator[Finding]:
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
            yield from self._scan_repository(rec, self._fetch, self._project_level)

    def _scan_local(self, proj: dict[str, Any], local: str) -> Iterable[Finding]:
        full = proj.get("path_with_namespace") or Path(local).name
        ns = (proj.get("namespace") or {}).get("full_path") or full.rsplit("/", 1)[0]
        metadata = {
            "project": full,
            "web_url": proj.get("web_url"),
            "default_branch": proj.get("default_branch"),
            "visibility": proj.get("visibility"),
            "archived": proj.get("archived"),
            "last_activity_at": proj.get("last_activity_at"),
            "topics": proj.get("topics"),
        }
        for f in self._scan_checkout(FilesystemConnector, proj, local, f"gitlab:{full}", ns, metadata):
            f.last_seen = f.last_seen or proj.get("last_activity_at")
            f.first_seen = proj.get("created_at")
            yield f

    # -------------------------------------------------------------- fetching
    def _fetch(self, proj: dict[str, Any], tmp: str) -> str | None:
        return self._fetch_checkout(proj, tmp, proj.get("path_with_namespace"))

    def _clone(self, proj: dict[str, Any], dest: str) -> bool:
        url = proj.get("http_url_to_repo")
        if not url:
            return False
        api = urlsplit(validate_url(self.api_url))
        origin = f"{api.scheme}://{api.netloc}"
        url = validate_url(url, origin)
        try:
            res = self._git_clone(proj, url, dest, origin=origin, username="oauth2", depth=1)
        except (OSError, subprocess.SubprocessError):
            return False
        return res.returncode == 0

    def _read_git_snapshot(self, local: str, timeout: float) -> dict[str, str] | None:
        # Looked up in this module, where callers substitute the reader.
        return read_git_snapshot(local, timeout=timeout)

    def _fetch_via_api(self, proj: dict[str, Any], tmp: str) -> str | None:
        pid = proj["id"]
        proj.pop("source_snapshot", None)
        ref = self._api_branch(proj)
        if ref is None:
            return None
        # Tree pages must describe one snapshot. Pin the branch before the
        # first page; pinning only blobs cannot prevent drift between pages.
        commit = self.http.try_get_json(
            f"/projects/{pid}/repository/commits/{quote(ref, safe='')}", params={"stats": "false"},
        )
        try:
            if not isinstance(commit, dict) or self._is_error_record(commit):
                raise ConnectorError("invalid commit response")
            snapshot = repository_blob_id(commit.get("id"))
        except ConnectorError:
            self.ctx.warn("code.gitlab: cannot resolve immutable commit; repository content skipped", incomplete=True)
            return None
        proj["source_snapshot"] = {
            "provider": "gitlab",
            "capture_method": "gitlab-api",
            "ref": ref,
            "commit_sha": snapshot,
        }
        blobs: dict[str, dict[str, Any]] = {}
        skipped_links = malformed = False
        for item in self.http.paginate_link(f"/projects/{pid}/repository/tree", params={"recursive": "true", "per_page": 100, "ref": snapshot}):
            if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                # Once per repository: a broken tree must not exhaust the
                # connector's diagnostic budget for every other project.
                if not malformed:
                    self.ctx.warn("code.gitlab: malformed tree entry; source coverage partial", incomplete=True)
                    malformed = True
                continue
            if item.get("type") == "commit" or item.get("mode") in {"120000", "160000"}:
                if not skipped_links:
                    self.ctx.warn("code.gitlab: symbolic links or submodules skipped; source coverage partial", incomplete=True)
                    skipped_links = True
                continue
            if item.get("type") == "blob":
                blobs[item["path"]] = item
        paths = list(blobs)
        selected = self._select_paths(paths)
        if len(selected) < len(paths):
            self.ctx.warn("code.gitlab: API mode samples repository; source coverage partial", incomplete=True)
        dest = os.path.join(tmp, "repo")
        os.makedirs(dest, exist_ok=True)
        self._write_api_blobs(proj, dest, blobs, selected)
        return dest

    def _download_blob(self, proj: dict[str, Any], blob_id: str) -> bytes | None:
        pid = proj["id"]
        try:
            # Fetch the exact enumerated object, even if its branch has
            # advanced between listing the tree and downloading content.
            resp = self.http.get(
                f"/projects/{pid}/repository/blobs/{blob_id}/raw",
                stream=True,
            )
            content = self.http.read_response_bytes(resp, max_bytes=512_000)
        except HttpError as exc:
            self.ctx.warn(f"code.gitlab: repository content HTTP {exc.status}; coverage partial", incomplete=True)
            return None
        except ValueError:
            self.ctx.warn("code.gitlab: oversized or invalid API content skipped", incomplete=True)
            return None
        return content

    # --------------------------------------------------- project-level extra
    def _project_level(self, proj: dict[str, Any]) -> Iterable[Finding]:
        pid = proj["id"]
        full = proj.get("path_with_namespace", str(pid))
        variables = list(self._optional_list(f"/projects/{pid}/variables"))
        f = self._variables_finding(full, [{k: v for k, v in var.items() if k != "value"} for var in variables], scope="project")
        if f:
            yield f
        for tok in self._optional_list(f"/projects/{pid}/access_tokens"):
            yield self._identity_finding(_GitLabMetadata("project_access_token", {**tok, "project": full}))
        for member in self._optional_list(f"/projects/{pid}/members"):
            if member.get("bot") or str(member.get("username", "")).startswith(("project_", "group_")) and "_bot" in str(member.get("username", "")):
                yield self._identity_finding(_GitLabMetadata("project_bot", {**member, "project": full}))

    def _variables_finding(self, scope_name: str, variables: list[dict[str, Any]], scope: str) -> Finding | None:
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
            name for v in variables
            if isinstance(name := v.get("key"), str) and name in matched_names and not v.get("masked")
        ]
        f.add_evidence(Evidence(signal="ci:variable-names", description=f"CI/CD variable names: {', '.join(sorted(set(names)))[:400]}", weight=0.3))
        apply_matches(f, matches, location=f"{scope_name} ({scope} CI/CD variables)", weight_scale=0.8)
        if unmasked:
            f.add_tag("unmasked-ci-variable")
            f.add_evidence(Evidence(signal="ci:unmasked", description=f"Provider credentials stored unmasked: {', '.join(unmasked)}", weight=0.4))
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
        f.add_evidence(Evidence(signal=f"gitlab:{kind}", description=f"Machine identity in {scope_name or 'group'}", weight=0.3))
        scopes = rec.get("scopes") or []
        if scopes:
            f.permissions.extend(scopes)
            apply_matches(f, [m for s in scopes for m in self.index.match_scope(s)], weight_scale=0.5)
        apply_matches(f, name_matches(self.index, name, rec.get("username")), weight_scale=0.8)
        f.metadata.update({k: v for k, v in rec.items() if k in {"username", "access_level", "expires_at", "last_used_at", "active", "revoked", "state"}})
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
        f.add_evidence(Evidence(signal="gitlab:duo", description="GitLab Duo (AI code suggestions / agentic chat / Duo Agent Platform) features enabled", weight=0.8))
        f.add_capability("code-exec")
        f.metadata.update(rec)
        finalize(f, self.index)
        f.kind = Kind.AGENT_CONFIG
        return f
