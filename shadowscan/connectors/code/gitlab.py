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
import tempfile
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import quote, urlsplit

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.connectors.code.github import (
    GitHubConnector,
    _OfflineRepository,
    _remote_record,
    repository_blob_id,
    repository_target,
)
from shadowscan.connectors.common import apply_matches, finalize, name_matches
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.utils.git import clone_environment, git_argv_prefix, validate_git_ref
from shadowscan.utils.http import HttpClient, HttpError, validate_url


class _GitLabMetadata(dict[str, Any]):
    """Provider payload with a dispatch kind assigned by the collector."""

    def __init__(self, kind: str, data: dict[str, Any]):
        super().__init__({**_remote_record(data), "_kind": kind})
        self.kind = kind


class GitLabConnector(BaseConnector):
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
            if len(seen) >= self.max_projects:
                self.ctx.warn(f"code.gitlab: max_projects ({self.max_projects}) reached", incomplete=True)
                return
            data = self.http.try_get_json(f"/projects/{quote(str(p), safe='')}")
            if data and data["id"] not in seen:
                seen.add(data["id"])
                yield _remote_record(data)
        if group:
            gid = quote(str(group), safe="")
            yield from self._group_identities(gid)
            params = {"per_page": 100, "include_subgroups": "true", "archived": "false" if not self.include_archived else None, "order_by": "last_activity_at", "simple": "false"}
            params = {k: v for k, v in params.items() if v is not None}
            for p in self.http.paginate_link(f"/groups/{gid}/projects", params=params):
                if p["id"] in seen:
                    continue
                if len(seen) >= self.max_projects:
                    self.ctx.warn(f"code.gitlab: max_projects ({self.max_projects}) reached", incomplete=True)
                    return
                seen.add(p["id"])
                yield _remote_record(p)

    def _group_identities(self, gid: str) -> Iterator[dict[str, Any]]:
        for sa in self._optional_list(f"/groups/{gid}/service_accounts"):
            yield _GitLabMetadata("service_account", {**sa, "group": gid})
        for tok in self._optional_list(f"/groups/{gid}/access_tokens"):
            yield _GitLabMetadata("group_access_token", {**tok, "group": gid})
        variables = [{k: v for k, v in var.items() if k != "value"} for var in self._optional_list(f"/groups/{gid}/variables")]
        if variables:
            yield _GitLabMetadata("group_variables", {"group": gid, "variables": variables})
        group = self.http.try_get_json(f"/groups/{gid}")
        if isinstance(group, dict) and (group.get("duo_features_enabled") is not None):
            yield _GitLabMetadata("duo", {"group": group.get("full_path"), "duo_features_enabled": group.get("duo_features_enabled"), "lock_duo_features_enabled": group.get("lock_duo_features_enabled")})

    def _optional_list(self, path: str) -> Iterator[dict[str, Any]]:
        try:
            yield from self.http.paginate_link(path, params={"per_page": 100})
        except HttpError as exc:
            self.ctx.warn(f"code.gitlab: metadata HTTP {exc.status} for {path}; coverage unknown", incomplete=True)

    def load_offline(self, path: str) -> Iterator[dict[str, Any]]:
        p = Path(path).expanduser().absolute()
        if any(part.is_symlink() for part in (p, *p.parents)) or not p.is_dir():
            raise ConnectorError(f"code.gitlab: offline input must be a directory of clones: {path}")
        root = p.resolve()
        count = 0
        try:
            for child in sorted(root.iterdir()):
                if child.is_symlink():
                    self.ctx.warn("code.gitlab: offline clone symlinks are skipped")
                    continue
                if not child.is_dir():
                    continue
                if count >= self.max_projects:
                    self.ctx.warn(f"code.gitlab: max_projects ({self.max_projects}) reached", incomplete=True)
                    return
                try:
                    child.resolve().relative_to(root)
                except (OSError, ValueError):
                    self.ctx.warn("code.gitlab: offline clone path escaped its input directory")
                    continue
                count += 1
                yield _OfflineRepository({"path_with_namespace": child.name}, str(child))
        except OSError:
            self.ctx.warn("code.gitlab: could not enumerate offline clones")

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
            full = rec.get("path_with_namespace") or rec.get("name")
            self.ctx.examined()
            offline = isinstance(rec, _OfflineRepository)
            local = rec.local_path if isinstance(rec, _OfflineRepository) else None
            tmp: str | None = None
            try:
                if not local:
                    tmp = tempfile.mkdtemp(prefix="shadowscan-gl-", dir=self.ctx.workdir)
                    local = self._fetch(rec, tmp)
                    if not local:
                        continue
                yield from self._scan_local(rec, local)
                if not offline:
                    yield from self._project_level(rec)
            except HttpError as exc:
                self.ctx.warn(f"code.gitlab: {full}: {exc}", incomplete=True)
            except Exception as exc:  # noqa: BLE001
                self.ctx.error(f"code.gitlab: {full}: {type(exc).__name__}: {exc}")
                self.log.debug("project failure", exc_info=True)
            finally:
                if tmp:
                    shutil.rmtree(tmp, ignore_errors=True)
        for group, variables in group_variables.items():
            f = self._variables_finding(group, variables, scope="group")
            if f:
                yield f

    def _scan_local(self, proj: dict[str, Any], local: str) -> Iterable[Finding]:
        full = proj.get("path_with_namespace") or Path(local).name
        ns = (proj.get("namespace") or {}).get("full_path") or full.rsplit("/", 1)[0]
        cfg = {
            **{k: v for k, v in self.ctx.config.items() if k in {"exclude", "max_file_size", "max_files", "scan_timeout", "scan_secrets", "use_git"}},
            "path": local,
            "label": f"gitlab:{full}",
            "account": ns,
            "provider": "gitlab",
            "metadata": {
                "project": full,
                "web_url": proj.get("web_url"),
                "default_branch": proj.get("default_branch"),
                "visibility": proj.get("visibility"),
                "archived": proj.get("archived"),
                "last_activity_at": proj.get("last_activity_at"),
                "topics": proj.get("topics"),
            },
        }
        fs = FilesystemConnector(ConnectorContext(config=cfg, index=self.index, logger=self.log))
        fs.ctx.stats = self.ctx.stats
        for f in fs.analyze([{"path": local}]):
            f.connector = self.name
            f.provider = "gitlab"
            # The filesystem connector created the finding under its own name.
            # Identity v2 includes connector and provider, so finalize it after
            # projecting the observation onto the GitLab surface.
            f.id = f.compute_id()
            f.last_seen = f.last_seen or proj.get("last_activity_at")
            f.first_seen = proj.get("created_at")
            yield f

    # -------------------------------------------------------------- fetching
    def _fetch(self, proj: dict[str, Any], tmp: str) -> str | None:
        if self.mode == "clone" and shutil.which("git"):
            dest = os.path.join(tmp, "repo")
            if self._clone(proj, dest):
                return dest
            self.ctx.warn(f"code.gitlab: clone failed for {proj.get('path_with_namespace')}; falling back to API mode")
        return self._fetch_via_api(proj, tmp)

    def _clone(self, proj: dict[str, Any], dest: str) -> bool:
        url = proj.get("http_url_to_repo")
        if not url:
            return False
        api = urlsplit(validate_url(self.api_url))
        origin = f"{api.scheme}://{api.netloc}"
        url = validate_url(url, origin)
        env = clone_environment(origin, self.token, "oauth2")
        cmd = [*git_argv_prefix(), "clone", "--quiet", "--depth", "1", "--no-tags", "--single-branch"]
        branch = validate_git_ref(proj.get("default_branch"))
        if branch:
            cmd += ["--branch", branch]
        elif proj.get("default_branch"):
            self.ctx.warn("code.gitlab: unsupported default branch; cloned remote HEAD, requested branch coverage unknown", incomplete=True)
        cmd += ["--", url, dest]
        try:
            res = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=600, check=False)
        except (OSError, subprocess.SubprocessError):
            return False
        return res.returncode == 0

    def _fetch_via_api(self, proj: dict[str, Any], tmp: str) -> str | None:
        pid = proj["id"]
        ref = validate_git_ref(proj.get("default_branch") or "main")
        if ref is None:
            self.ctx.warn("code.gitlab: unsupported default branch; repository content skipped", incomplete=True)
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
        blobs: dict[str, dict[str, Any]] = {}
        skipped_links = False
        for item in self.http.paginate_link(f"/projects/{pid}/repository/tree", params={"recursive": "true", "per_page": 100, "ref": snapshot}):
            if item.get("type") == "commit" or item.get("mode") in {"120000", "160000"}:
                if not skipped_links:
                    self.ctx.warn("code.gitlab: symbolic links or submodules skipped; source coverage partial", incomplete=True)
                    skipped_links = True
                continue
            if item.get("type") == "blob":
                blobs[item["path"]] = item
        paths = list(blobs)
        selected = GitHubConnector._select_paths(paths)
        if len(selected) < len(paths):
            self.ctx.warn("code.gitlab: API mode samples repository; source coverage partial", incomplete=True)
        dest = os.path.join(tmp, "repo")
        os.makedirs(dest, exist_ok=True)
        for p in selected:
            target = repository_target(dest, p)
            try:
                blob_id = repository_blob_id(blobs[p].get("id"))
            except ConnectorError:
                self.ctx.warn("code.gitlab: invalid blob object ID; content skipped", incomplete=True)
                continue
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
                continue
            except ValueError:
                self.ctx.warn("code.gitlab: oversized or invalid API content skipped", incomplete=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        return dest

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
