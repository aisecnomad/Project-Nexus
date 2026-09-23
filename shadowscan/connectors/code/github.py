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
import tempfile
from collections.abc import Iterable, Iterator
from pathlib import Path, PurePosixPath
from typing import Any, ClassVar
from urllib.parse import quote, urlsplit

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.connectors.code.manifests import is_manifest_name
from shadowscan.connectors.common import apply_matches, finalize
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.utils.http import HttpClient, HttpError, validate_url

INTERESTING_DIRS = (".github/", ".claude/", ".cursor/", ".vscode/", ".windsurf/", ".codex/", ".gemini/", ".kiro/", ".amazonq/", ".continue/", ".roo/", ".well-known/", "config/", "infra/", "terraform/", "deploy/", "k8s/", "helm/", "flows/", "workflows/", "agents/", "prompts/")
API_MODE_MAX_FILES = 400
SOURCE_SAMPLE = 150


def repository_target(root: str, path: str) -> Path:
    """Validate API tree paths before fetching or writing outside the checkout."""
    rel = PurePosixPath(path)
    if not rel.parts or rel.is_absolute() or ".." in rel.parts or "\\" in path or "\x00" in path or ":" in rel.parts[0]:
        raise ConnectorError("Refusing unsafe repository tree path")
    target = (Path(root) / path).resolve()
    if not target.is_relative_to(Path(root).resolve()) or target == Path(root).resolve():
        raise ConnectorError("Repository tree path escapes checkout")
    return target


def clone_environment(origin: str, token: str | None, username: str) -> dict[str, str]:
    """Scope authentication to a verified HTTPS origin and disable redirects."""
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    config = [("http.followRedirects", "false"), ("credential.helper", ""), ("protocol.allow", "never"), ("protocol.https.allow", "always")]
    if token:
        basic = base64.b64encode(f"{username}:{token}".encode()).decode()
        config.append((f"http.{origin.rstrip('/')}/.extraheader", f"Authorization: Basic {basic}"))
    env["GIT_CONFIG_COUNT"] = str(len(config))
    for i, (key, value) in enumerate(config):
        env[f"GIT_CONFIG_KEY_{i}"] = key
        env[f"GIT_CONFIG_VALUE_{i}"] = value
    return env


class GitHubConnector(BaseConnector):
    name: ClassVar[str] = "code.github"
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
        "clone_depth": "git clone depth (default 1)",
        "topics": "only repositories with any of these topics",
        "input": "offline: directory containing cloned repositories",
    }
    offline_formats: ClassVar[str] = "directory of cloned repositories"

    def __init__(self, ctx: ConnectorContext):
        super().__init__(ctx)
        self.api_url = str(ctx.get("api_url", "https://api.github.com", env="GITHUB_API_URL")).rstrip("/")
        self.token = ctx.get("token", env="GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
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
                if len(seen) >= self.max_repos:
                    self.ctx.warn(f"code.github: max_repos ({self.max_repos}) reached", incomplete=True)
                    return
                data = self.http.try_get_json(f"/repos/{full}")
                if data:
                    if data["full_name"] not in seen:
                        seen.add(data["full_name"])
                        yield data
                else:
                    self.ctx.warn(f"code.github: cannot access {full}", incomplete=True)
        if org:
            for r in self.http.paginate_link(f"/orgs/{org}/repos", params={"per_page": 100, "type": "all", "sort": "pushed"}):
                if r["full_name"] not in seen and self._wanted(r):
                    if len(seen) >= self.max_repos:
                        self.ctx.warn(f"code.github: max_repos ({self.max_repos}) reached", incomplete=True)
                        return
                    seen.add(r["full_name"])
                    yield r
        if user:
            for r in self.http.paginate_link(f"/users/{user}/repos", params={"per_page": 100, "sort": "pushed"}):
                if r["full_name"] not in seen and self._wanted(r):
                    if len(seen) >= self.max_repos:
                        self.ctx.warn(f"code.github: max_repos ({self.max_repos}) reached", incomplete=True)
                        return
                    seen.add(r["full_name"])
                    yield r

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
                yield {"full_name": child.name, "_local_path": str(child), "owner": {"login": child.name.split("__")[0] if "__" in child.name else child.name}}
        except OSError:
            self.ctx.warn("code.github: could not enumerate offline clones")

    # --------------------------------------------------------------- analyze
    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        for repo in records:
            full = repo.get("full_name") or repo.get("name")
            self.ctx.examined()
            local = repo.get("_local_path")
            tmp: str | None = None
            try:
                if not local:
                    tmp = tempfile.mkdtemp(prefix="shadowscan-gh-", dir=self.ctx.workdir)
                    local = self._fetch_repo(repo, tmp)
                    if not local:
                        continue
                yield from self._scan_local(repo, local)
                if not repo.get("_local_path"):
                    yield from self._repo_level_findings(repo)
            except HttpError as exc:
                self.ctx.warn(f"code.github: {full}: {exc}", incomplete=True)
            except Exception as exc:  # noqa: BLE001
                self.ctx.error(f"code.github: {full}: {type(exc).__name__}: {exc}")
                self.log.debug("repo failure", exc_info=True)
            finally:
                if tmp:
                    shutil.rmtree(tmp, ignore_errors=True)

    def _scan_local(self, repo: dict[str, Any], local: str) -> Iterable[Finding]:
        full = repo.get("full_name") or Path(local).name
        owner_login = (repo.get("owner") or {}).get("login")
        cfg = {
            **{k: v for k, v in self.ctx.config.items() if k in {"exclude", "max_file_size", "max_files", "scan_timeout", "scan_secrets", "use_git"}},
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
            },
        }
        fs = FilesystemConnector(ConnectorContext(config=cfg, index=self.index, logger=self.log))
        fs.ctx.stats = self.ctx.stats
        for f in fs.analyze([{"path": local}]):
            f.connector = self.name
            f.provider = "github"
            if repo.get("pushed_at"):
                f.last_seen = f.last_seen or repo["pushed_at"]
            if repo.get("created_at"):
                f.first_seen = repo["created_at"]
            yield f

    # ------------------------------------------------------------- fetching
    def _fetch_repo(self, repo: dict[str, Any], tmp: str) -> str | None:
        full = repo["full_name"]
        if self.mode == "clone" and shutil.which("git"):
            dest = os.path.join(tmp, "repo")
            if self._clone(repo, dest):
                return dest
            self.ctx.warn(f"code.github: clone failed for {full}; falling back to API mode")
        return self._fetch_via_api(repo, tmp)

    def _clone(self, repo: dict[str, Any], dest: str) -> bool:
        api = urlsplit(validate_url(self.api_url))
        origin = "https://github.com" if api.hostname == "api.github.com" else f"{api.scheme}://{api.netloc}"
        url = validate_url(repo.get("clone_url") or f"{origin}/{repo['full_name']}.git", origin)
        env = clone_environment(origin, self.token, "x-access-token")
        cmd = ["git", "clone", "--quiet", "--depth", str(self.depth), "--no-tags", "--single-branch"]
        if repo.get("default_branch"):
            cmd += ["--branch", repo["default_branch"]]
        cmd += ["--", url, dest]
        try:
            res = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=600, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            self.log.debug("git clone error: %s", exc)
            return False
        if res.returncode != 0:
            self.log.debug("git clone failed with status %s", res.returncode)
            return False
        return True

    def _fetch_via_api(self, repo: dict[str, Any], tmp: str) -> str | None:
        full = repo["full_name"]
        branch = repo.get("default_branch") or "main"
        tree = self.http.try_get_json(f"/repos/{full}/git/trees/{branch}", params={"recursive": "1"})
        if not tree or "tree" not in tree:
            self.ctx.warn(f"code.github: cannot read tree of {full}", incomplete=True)
            return None
        if tree.get("truncated"):
            self.ctx.warn(f"code.github: tree of {full} truncated; results partial", incomplete=True)
        paths = [t["path"] for t in tree["tree"] if t.get("type") == "blob" and int(t.get("size") or 0) <= 512_000]
        selected = self._select_paths(paths)
        if len(selected) < sum(t.get("type") == "blob" for t in tree["tree"]):
            self.ctx.warn(f"code.github: API mode samples repository {full}; source coverage partial", incomplete=True)
        dest = os.path.join(tmp, "repo")
        os.makedirs(dest, exist_ok=True)
        fetched = 0
        for p in selected:
            target = repository_target(dest, p)
            data = self.http.try_get_json(f"/repos/{full}/contents/{quote(p, safe='/')}", params={"ref": branch})
            if not data or data.get("encoding") != "base64":
                self.ctx.warn(f"code.github: cannot read content in {full}", incomplete=True)
                continue
            try:
                content = base64.b64decode(data.get("content") or "")
            except ValueError:
                self.ctx.warn(f"code.github: invalid encoded content in {full}", incomplete=True)
                continue
            if len(content) > 512_000:
                self.ctx.warn(f"code.github: oversized API content in {full}", incomplete=True)
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
