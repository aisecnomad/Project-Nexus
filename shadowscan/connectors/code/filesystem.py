"""Scan a local directory tree (a checked-out repository, a monorepo, a laptop).

Produces:

* one ``agent`` / ``framework-usage`` finding per project (nearest manifest
  root) summarising frameworks, model providers, capabilities and evidence;
* one ``mcp-server`` finding per MCP client/server configuration file;
* one ``agent-config`` finding per coding-agent product per project
  (Claude Code, Copilot, Cursor, Codex... including sub-agent definitions);
* one ``agent`` finding per A2A agent card / declarative agent manifest;
* one ``workflow`` finding per exported low-code flow (n8n, Flowise, Langflow, Dify, Make, Power Automate, Logic Apps);
* one ``infra`` finding per IaC / container file provisioning agent platforms;
* one ``secret`` finding per file containing LLM-provider credentials (redacted).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tomllib
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, ClassVar

import yaml

from shadowscan.connectors.base import BaseConnector, ConnectorError
from shadowscan.connectors.code.manifests import Artifact, Dep, is_manifest_name, parse_manifest
from shadowscan.connectors.common import apply_matches, finalize, looks_like_placeholder
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.signatures import Match
from shadowscan.signatures.matcher import SOURCE_EXTENSIONS, language_for_path
from shadowscan.utils.text import excerpt_line, notebook_to_source, read_text, redact, truncate

DEFAULT_EXCLUDES = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "bower_components",
    ".venv",
    "venv",
    ".virtualenv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
    "site-packages",
    "dist",
    "build",
    "out",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".turbo",
    ".parcel-cache",
    "target",
    "vendor",
    ".terraform",
    ".serverless",
    ".gradle",
    ".idea",
    ".vs",
    "bin",
    "obj",
    "Pods",
    ".dart_tool",
    "coverage",
    ".coverage",
    ".cache",
    ".yarn",
    ".pnpm-store",
    "third_party",
    "thirdparty",
    "external",
}

LOCK_FILES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "uv.lock",
    "pdm.lock",
    "Pipfile.lock",
    "Cargo.lock",
    "go.sum",
    "composer.lock",
    "Gemfile.lock",
    "packages.lock.json",
    "flake.lock",
    "bun.lockb",
    "bun.lock",
}

PROJECT_ROOT_MARKERS = {
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "setup.py",
    "Pipfile",
    "go.mod",
    "Cargo.toml",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "Gemfile",
    "composer.json",
    "environment.yml",
}

TEXT_CONFIG_EXTENSIONS = {
    ".json",
    ".jsonc",
    ".json5",
    ".yaml",
    ".yml",
    ".toml",
    ".md",
    ".mdc",
    ".mdx",
    ".txt",
    ".xml",
    ".cfg",
    ".ini",
    ".conf",
    ".env",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".bat",
    ".cmd",
    ".tf",
    ".tfvars",
    ".hcl",
    ".bicep",
    ".prompty",
    ".prompt",
    ".sql",
    ".graphql",
    ".proto",
    ".html",
    ".vue",
    ".svelte",
    ".astro",
    ".lua",
    ".pl",
    ".r",
    ".jl",
    ".ex",
    ".exs",
    ".clj",
    ".groovy",
    ".gradle",
    ".properties",
    ".plist",
    ".nix",
    ".dockerfile",
    ".csv",
}

MCP_CONFIG_NAMES = {
    ".mcp.json",
    "mcp.json",
    "mcp-config.json",
    "mcp_config.json",
    "mcp-servers.json",
    "claude_desktop_config.json",
    "cline_mcp_settings.json",
    "mcp_settings.json",
    "config.toml",  # codex, only when it has [mcp_servers.*]
    "settings.json",  # .gemini / .vscode when it has mcpServers / servers
    "config.yaml",  # continue
    "config.json",  # continue
    "opencode.json",
    "server.json",  # MCP registry manifest
    "smithery.yaml",
}

_FRONTMATTER = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.S)


@dataclass
class _Project:
    root: str  # relative posix path ("." for scan root)
    files: int = 0
    matches: list[tuple[Match, str, str | None]] = field(default_factory=list)  # match, relpath, snippet
    deps: list[Dep] = field(default_factory=list)
    languages: set[str] = field(default_factory=set)
    coding_agent_files: dict[str, list[str]] = field(default_factory=dict)  # sig id -> files
    coding_agent_matches: dict[str, list[tuple[Match, str, str | None]]] = field(default_factory=dict)
    agent_defs: list[dict[str, Any]] = field(default_factory=list)


class FilesystemConnector(BaseConnector):
    name: ClassVar[str] = "code.filesystem"
    surface: ClassVar[Surface] = Surface.CODE
    provider: ClassVar[str | None] = "filesystem"
    description: ClassVar[str] = "Scan a local directory / repository checkout for agent frameworks, MCP, coding agents, IaC and secrets."
    config_keys: ClassVar[dict[str, str]] = {
        "path": "directory to scan (or `paths`: list)",
        "exclude": "extra directory names / glob patterns to skip",
        "max_file_size": "bytes; larger files are skipped (default 1 MiB)",
        "max_files": "stop after this many files (default 100000)",
        "scan_secrets": "detect provider credentials (default true)",
        "use_git": "enrich with git last-commit author/date (default true)",
        "label": "prefix for resource ids (e.g. 'github:org/repo'); defaults to the path",
    }
    offline_formats: ClassVar[str] = "n/a (path is the input)"

    def __init__(self, ctx):
        super().__init__(ctx)
        self.max_file_size = int(ctx.get("max_file_size", 1_000_000))
        self.max_files = int(ctx.get("max_files", 100_000))
        self.scan_secrets = bool(ctx.get("scan_secrets", True))
        self.use_git = bool(ctx.get("use_git", True))
        extra = ctx.get("exclude", []) or []
        self.exclude_names = set(DEFAULT_EXCLUDES) | {e for e in extra if "*" not in e and "/" not in e}
        self.exclude_globs = [e for e in extra if "*" in e or "/" in e]
        self.label: str | None = ctx.get("label")
        self.account: str | None = ctx.get("account")
        self.owner: str | None = ctx.get("owner")
        self.provider_override: str | None = ctx.get("provider")
        self.extra_metadata: dict[str, Any] = dict(ctx.get("metadata", {}) or {})

    # ----------------------------------------------------------------- input
    def _paths(self) -> list[Path]:
        paths = self.ctx.get("paths") or ([self.ctx.get("path")] if self.ctx.get("path") else None)
        if not paths and self.ctx.input_path:
            paths = [self.ctx.input_path]
        if not paths:
            raise ConnectorError("code.filesystem: 'path' is required")
        out = []
        for p in paths:
            pp = Path(p).expanduser()
            if not pp.exists():
                raise ConnectorError(f"code.filesystem: path not found: {p}")
            out.append(pp)
        return out

    def collect(self) -> Iterable[dict[str, Any]]:
        for root in self._paths():
            yield {"path": str(root)}

    def load_offline(self, path: str) -> Iterator[dict[str, Any]]:
        yield {"path": path}

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        for rec in records:
            root = Path(rec["path"]).expanduser().resolve()
            yield from self.scan_tree(root)

    # ------------------------------------------------------------------ walk
    def _excluded(self, rel: str, name: str) -> bool:
        if name in self.exclude_names:
            return True
        for g in self.exclude_globs:
            if PurePosixPath(rel).match(g) or PurePosixPath(rel).match(g.rstrip("/") + "/*"):
                return True
        return False

    def _iter_files(self, root: Path) -> Iterator[tuple[str, Path, str]]:
        """Yield (relpath, path, project_root_rel) top-down with project root tracking."""
        roots: list[str] = ["."]
        count = 0
        if root.is_file():
            yield root.name, root, "."
            return
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
            rel_dir = "." if rel_dir == "." else rel_dir
            dirnames[:] = sorted(d for d in dirnames if not self._excluded(f"{rel_dir}/{d}".lstrip("./"), d))
            if rel_dir != "." and any(f in PROJECT_ROOT_MARKERS for f in filenames):
                roots.append(rel_dir)
            proj = _nearest_root(rel_dir, roots)
            for fn in sorted(filenames):
                if fn in LOCK_FILES or fn.endswith((".min.js", ".min.css", ".map", ".pyc", ".lock")):
                    continue
                rel = fn if rel_dir == "." else f"{rel_dir}/{fn}"
                if self.exclude_globs and self._excluded(rel, fn):
                    continue
                p = Path(dirpath) / fn
                try:
                    if p.is_symlink() or not p.is_file():
                        continue
                except OSError:
                    continue
                count += 1
                if count > self.max_files:
                    self.ctx.warn(f"code.filesystem: max_files ({self.max_files}) reached under {root}")
                    return
                yield rel, p, proj

    # ------------------------------------------------------------------ scan
    def scan_tree(self, root: Path) -> Iterator[Finding]:
        label = self.label or str(root)
        projects: dict[str, _Project] = {".": _Project(".")}
        secret_hits: dict[str, list[tuple[Match, str]]] = {}  # relpath -> matches
        mcp_files: list[tuple[str, str]] = []  # relpath, text
        card_files: list[tuple[str, str, str]] = []  # relpath, text, kind
        workflow_files: dict[str, list[tuple[Match, str]]] = {}
        infra_files: dict[str, list[tuple[Match, str, str]]] = {}  # relpath -> (match, value, snippet)
        infra_names: dict[str, list[str]] = {}  # relpath -> display / resource names
        for rel, path, proj_root in self._iter_files(root):
            proj = projects.setdefault(proj_root, _Project(proj_root))
            proj.files += 1
            self.ctx.examined()
            name = path.name
            lower = name.lower()
            ext = path.suffix.lower()
            lang = language_for_path(rel)
            if lang:
                proj.languages.add(lang)

            # 1. file-name signals (config files of agents / MCP / A2A ...)
            file_matches = self.index.match_file(rel)
            for m in file_matches:
                self._record(proj, m, rel, None)

            is_source = ext in SOURCE_EXTENSIONS
            is_text_cfg = ext in TEXT_CONFIG_EXTENSIONS or lower.startswith(".env") or is_manifest_name(name) or "." not in name
            if not (is_source or is_text_cfg or file_matches):
                continue
            text = read_text(path, self.max_file_size)
            if text is None:
                continue
            if ext == ".ipynb":
                text = notebook_to_source(text)
                lang = "python"

            # 2. manifests (dependencies, images, env names, IaC types)
            manifest = parse_manifest(rel, text) if (is_manifest_name(name) or ext in {".tf", ".bicep", ".yml", ".yaml", ".json", ".hcl"} or ".github/workflows" in rel) else None
            if manifest:
                for dep in manifest.deps:
                    proj.deps.append(dep)
                    for m in self.index.match_dependency(dep.ecosystem, dep.name):
                        m.line = dep.line
                        self._record(proj, m, rel, f"{dep.ecosystem}: {dep.name} {dep.spec or ''}".strip())
                for art in manifest.artifacts:
                    self._handle_artifact(proj, art, rel, text, infra_files, secret_hits, infra_names)

            # 3. source & config content
            is_mcp = self._looks_like_mcp_config(rel, name, text)
            if is_source:
                for m in self.index.match_imports(text, lang):
                    self._record(proj, m, rel, excerpt_line(text, m.line or 1))
                for m in self.index.match_code(text, lang):
                    self._record(proj, m, rel, excerpt_line(text, m.line or 1))
            else:
                for m in self.index.match_code(text, None):
                    self._record(proj, m, rel, excerpt_line(text, m.line or 1))
                    if m.signature.category in {"platform", "cloud-service"} and m.agent_indicator and ext in {".json", ".yaml", ".yml"} and not is_mcp:
                        workflow_files.setdefault(rel, []).append((m, excerpt_line(text, m.line or 1)))
            for m in self.index.match_envs_in_text(text):
                self._record(proj, m, rel, excerpt_line(text, m.line or 1))
            for m in self.index.match_domains_in_text(text):
                self._record(proj, m, rel, excerpt_line(text, m.line or 1))
            if self.scan_secrets:
                for m in self.index.match_secrets(text):
                    if looks_like_placeholder(m.value):
                        continue
                    secret_hits.setdefault(rel, []).append((m, excerpt_line(text, m.line or 1).replace(m.value, redact(m.value))))
                    self._record(proj, m, rel, None)

            # 4. special files
            if is_mcp:
                mcp_files.append((rel, text))
            if lower in {"agent.json", "agent-card.json", "agent_card.json"} and ".well-known" in rel or lower in {"agent-card.json", "agent_card.json"}:
                card_files.append((rel, text, "a2a"))
            elif lower.startswith("declarativeagent") and ext == ".json":
                card_files.append((rel, text, "m365"))
            elif lower == "langgraph.json":
                card_files.append((rel, text, "langgraph"))
            elif lower == "agents.yaml" and "config" in rel:
                card_files.append((rel, text, "crewai"))
            if ext in {".md", ".mdc"} and (".claude/agents/" in rel or ".github/agents/" in rel or ".cursor/rules/" in rel or ".windsurf/rules/" in rel):
                proj.agent_defs.append(self._parse_agent_definition(rel, text))

        # ------------------------------------------------------------ emit
        for proj in projects.values():
            yield from self._emit_project(label, root, proj)
        for rel, text in mcp_files:
            f = self._mcp_finding(label, root, rel, text)
            if f:
                yield f
        for rel, text, kind in card_files:
            f = self._card_finding(label, root, rel, text, kind)
            if f:
                yield f
        for rel, hits in workflow_files.items():
            yield self._workflow_finding(label, root, rel, hits)
        for rel, hits in infra_files.items():
            yield self._infra_finding(label, root, rel, hits, infra_names.get(rel, []))
        for rel, hits in secret_hits.items():
            yield self._secret_finding(label, root, rel, hits)

    # --------------------------------------------------------------- helpers
    def _record(self, proj: _Project, m: Match, rel: str, snippet: str | None) -> None:
        if m.signature.category == "identity-app":
            return  # identity-app signatures describe OAuth/SaaS apps, not code
        if m.signature.category == "coding-agent":
            proj.coding_agent_files.setdefault(m.signature_id, [])
            if rel not in proj.coding_agent_files[m.signature_id]:
                proj.coding_agent_files[m.signature_id].append(rel)
            proj.coding_agent_matches.setdefault(m.signature_id, []).append((m, rel, snippet))
            return
        proj.matches.append((m, rel, snippet))

    def _handle_artifact(
        self,
        proj: _Project,
        art: Artifact,
        rel: str,
        text: str,
        infra_files: dict[str, list[tuple[Match, str, str]]],
        secret_hits: dict[str, list[tuple[Match, str]]],
        infra_names: dict[str, list[str]] | None = None,
    ) -> None:
        infra_names = infra_names if infra_names is not None else {}
        if art.kind == "image":
            for m in self.index.match_image(art.value):
                m.line = art.line
                self._record(proj, m, rel, f"image: {art.value}")
                infra_files.setdefault(rel, []).append((m, art.value, f"image: {art.value}"))
        elif art.kind in {"env", "secret_ref"}:
            for m in self.index.match_env(art.value):
                m.line = art.line
                self._record(proj, m, rel, f"{art.kind}: {art.value}")
            val = art.extra.get("value") if art.extra else None
            if val and self.scan_secrets and not looks_like_placeholder(val):
                for m in self.index.match_secrets(val):
                    m.line = art.line
                    secret_hits.setdefault(rel, []).append((m, f"{art.value}={redact(m.value)}"))
                    self._record(proj, m, rel, None)
        elif art.kind == "iac":
            for m in self.index.match_iac(art.value):
                m.line = art.line
                self._record(proj, m, rel, f"resource: {art.value}")
                label = f"resource {art.value} {art.extra.get('name', '')}".strip()
                if art.extra.get("display_name"):
                    label += f" ({art.extra['display_name']})"
                infra_files.setdefault(rel, []).append((m, art.value, label))
                names = infra_names.setdefault(rel, [])
                for n in (art.extra.get("display_name"), art.extra.get("name")):
                    if n and n not in names:
                        names.append(n)
        elif art.kind == "model":
            for m in self.index.match_model(art.value):
                m.line = art.line
                self._record(proj, m, rel, f"model: {art.value}")
        elif art.kind == "action":
            for m in self.index.match_code(f"uses: {art.value}"):
                m.line = art.line
                self._record(proj, m, rel, f"uses: {art.value}")
        elif art.kind == "module":
            for m in self.index.match_domains_in_text(art.value):
                m.line = art.line
                self._record(proj, m, rel, f"module: {art.value}")

    @staticmethod
    def _looks_like_mcp_config(rel: str, name: str, text: str) -> bool:
        lower = name.lower()
        if lower in {".mcp.json", "mcp.json", "mcp-config.json", "mcp_config.json", "mcp-servers.json", "claude_desktop_config.json", "cline_mcp_settings.json", "mcp_settings.json", "smithery.yaml"}:
            return True
        if lower in MCP_CONFIG_NAMES or rel.endswith((".json", ".toml", ".yaml", ".yml")):
            head = text[:200_000]
            return bool(re.search(r'"mcpServers"\s*:|^\s*mcpServers\s*:|\[mcp_servers\.[A-Za-z0-9_-]+\]|"mcp"\s*:\s*\{\s*"servers"|^\s*mcp:\s*\n\s+servers:|"servers"\s*:\s*\{[^}]*"(?:command|url)"', head, re.M))
        return False

    def _git_info(self, root: Path, rel_root: str) -> dict[str, Any]:
        if not self.use_git or not (root / ".git").exists():
            return {}
        target = "." if rel_root == "." else rel_root
        try:
            out = subprocess.run(
                ["git", "-C", str(root), "log", "-1", "--format=%an|%ae|%cI", "--", target],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            if out.returncode == 0 and out.stdout.strip():
                an, ae, ci = (out.stdout.strip().split("|") + ["", "", ""])[:3]
                return {"last_author": an, "last_author_email": ae, "last_commit": ci}
        except (OSError, subprocess.SubprocessError):
            pass
        return {}

    def _codeowners(self, root: Path) -> list[tuple[str, list[str]]]:
        if hasattr(self, "_codeowners_cache"):
            return self._codeowners_cache  # type: ignore[attr-defined]
        rules: list[tuple[str, list[str]]] = []
        for cand in (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS", ".gitlab/CODEOWNERS"):
            p = root / cand
            if p.is_file():
                try:
                    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                        line = line.split("#", 1)[0].strip()
                        if not line:
                            continue
                        parts = line.split()
                        if len(parts) >= 2:
                            rules.append((parts[0], parts[1:]))
                except OSError:
                    pass
                break
        self._codeowners_cache = rules  # type: ignore[attr-defined]
        return rules

    def _owner_for(self, root: Path, rel_root: str) -> str | None:
        if self.owner:
            return self.owner
        rules = self._codeowners(root)
        best: list[str] | None = None
        for pattern, owners in rules:
            pat = pattern.strip("/")
            if pattern == "*" or pat == "" or rel_root == pat or rel_root.startswith(pat + "/") or (rel_root == "." and pattern == "*"):
                best = owners
        return ", ".join(best) if best else None

    # ----------------------------------------------------------------- emits
    def _base(self, label: str, root: Path, rel: str, kind: Kind, title: str, resource_type: str) -> Finding:
        f = Finding(
            surface=Surface.CODE,
            connector=self.name,
            kind=kind,
            title=title,
            resource=f"{label}/{rel}" if rel != "." else label,
            resource_type=resource_type,
            provider=self.provider_override or self.provider,
            account=self.account,
            owner=self.owner,
        )
        f.metadata.update(self.extra_metadata)
        f.metadata["path"] = rel
        f.metadata["scan_root"] = str(root)
        return f

    def _emit_project(self, label: str, root: Path, proj: _Project) -> Iterator[Finding]:
        tech_matches = [(m, rel, snip) for (m, rel, snip) in proj.matches if m.signature.category not in {"policy"}]
        if tech_matches:
            f = self._base(label, root, proj.root, Kind.FRAMEWORK_USAGE, "", "project")
            for m, rel, snip in tech_matches:
                apply_matches(f, [m], location=rel, snippet=snip)
            git = self._git_info(root, proj.root)
            f.metadata.update(git)
            if git.get("last_commit"):
                f.last_seen = git["last_commit"]
            f.owner = self._owner_for(root, proj.root) or git.get("last_author_email") or f.owner
            f.metadata["files_scanned"] = proj.files
            f.metadata["languages"] = sorted(proj.languages)
            f.metadata["dependencies_matched"] = sorted({f"{m.signal.ecosystem or 'any'}:{m.value}" for m, _, _ in tech_matches if m.signal.type == "dependency"})
            f.metadata["models"] = sorted({m.value for m, _, _ in tech_matches if m.signal.type == "model"})
            f.models = f.metadata["models"]
            if proj.agent_defs:
                f.metadata["agent_definitions"] = proj.agent_defs
            finalize(f, self.index)
            f.title = self._project_title(f, proj)
            yield f
        for sig_id, files in proj.coding_agent_files.items():
            sig = self.index.get(sig_id)
            f = self._base(label, root, proj.root, Kind.AGENT_CONFIG, f"{sig.name if sig else sig_id} configured in {proj.root if proj.root != '.' else 'repository root'}", "coding-agent-config")
            for m, rel, snip in proj.coding_agent_matches.get(sig_id, []):
                apply_matches(f, [m], location=rel, snippet=snip)
            f.metadata["files"] = sorted(files)
            defs = [d for d in proj.agent_defs if any(d["file"] == x for x in files)]
            if defs:
                f.metadata["agent_definitions"] = defs
                f.add_capability("multi-agent")
            f.kind = Kind.AGENT_CONFIG
            f.owner = self._owner_for(root, proj.root) or f.owner
            finalize(f, self.index)
            f.kind = Kind.AGENT_CONFIG
            yield f

    def _project_title(self, f: Finding, proj: _Project) -> str:
        order = {"framework": 0, "cloud-service": 1, "platform": 2, "protocol": 3}
        ranked = sorted(
            (sig for sid in f.frameworks if (sig := self.index.get(sid)) and sig.category in order),
            key=lambda s: order[s.category],
        )
        names = [s.name for s in ranked[:4]]
        provs = [self.index.get(sid).name for sid in f.model_providers[:3] if self.index.get(sid)]  # type: ignore[union-attr]
        where = "repository root" if proj.root == "." else proj.root
        what = "Agent" if f.kind == Kind.AGENT else "LLM usage"
        detail = ", ".join(names) or ", ".join(provs) or "LLM SDK"
        return f"{what} in {where}: {detail}"

    def _mcp_finding(self, label: str, root: Path, rel: str, text: str) -> Finding | None:
        servers = _parse_mcp_servers(rel, text)
        f = self._base(label, root, rel, Kind.MCP_SERVER, f"MCP configuration: {rel}", "mcp-config")
        sig = self.index.get("protocol.mcp")
        f.add_framework("protocol.mcp")
        f.add_capability("tool-use")
        f.add_evidence(Evidence(signal="file:protocol.mcp", description=f"MCP client/server configuration file {rel}", location=rel, weight=0.95, signature="protocol.mcp"))
        remote_hosts: list[str] = []
        for s in servers:
            if s.get("url"):
                for m in self.index.match_domains_in_text(s["url"]):
                    if m.signature.category != "identity-app":
                        apply_matches(f, [m], location=rel)
                remote_hosts.append(s["url"])
            for env_name in s.get("env", []):
                for m in self.index.match_env(env_name):
                    apply_matches(f, [m], location=rel, weight_scale=0.5)
            if s.get("secrets_inline"):
                f.add_tag("inline-secrets")
                f.add_evidence(Evidence(signal="secret:inline", description=f"MCP server '{s['name']}' has credential-looking values in its env block", location=rel, weight=0.3))
            cmd = " ".join([str(s.get("command") or "")] + [str(a) for a in s.get("args", [])]).lower()
            if any(k in cmd for k in ("filesystem", "shell", "bash", "terminal", "exec", "docker", "kubectl", "ssh", "sqlite", "postgres", "mysql", "mongodb", "github", "gitlab", "slack", "gmail", "google-drive", "aws", "gcloud", "azure", "puppeteer", "playwright", "browser")):
                f.add_capability("code-exec" if any(k in cmd for k in ("shell", "bash", "terminal", "exec", "docker", "kubectl", "ssh")) else "saas-actions")
        f.metadata["servers"] = servers
        f.metadata["server_count"] = len(servers)
        f.metadata["remote_urls"] = remote_hosts
        f.metadata["client"] = _mcp_client_for(rel)
        if not servers and "mcpServers" not in text and "mcp_servers" not in text and "servers" not in text:
            return None
        f.owner = self._owner_for(root, PurePosixPath(rel).parent.as_posix()) or f.owner
        finalize(f, self.index)
        f.kind = Kind.MCP_SERVER
        if sig:
            f.metadata["risk_notes"] = sig.risk_notes
        return f

    def _card_finding(self, label: str, root: Path, rel: str, text: str, kind: str) -> Finding | None:
        data: Any = None
        try:
            data = yaml.safe_load(text) if rel.endswith((".yaml", ".yml")) else json.loads(text)
        except (ValueError, yaml.YAMLError):
            return None
        if not isinstance(data, dict):
            return None
        f = self._base(label, root, rel, Kind.AGENT, "", "agent-manifest")
        if kind == "a2a":
            f.title = f"A2A agent card: {data.get('name') or rel}"
            f.add_framework("protocol.a2a")
            f.add_capability("multi-agent")
            f.add_evidence(Evidence(signal="file:protocol.a2a", description="A2A Agent Card", location=rel, weight=0.95, signature="protocol.a2a"))
            f.metadata["agent_card"] = {
                "name": data.get("name"),
                "description": truncate(str(data.get("description", "")), 300),
                "url": data.get("url"),
                "version": data.get("version"),
                "protocol_version": data.get("protocolVersion"),
                "skills": [s.get("name") or s.get("id") for s in data.get("skills", []) or [] if isinstance(s, dict)],
                "capabilities": data.get("capabilities"),
                "security_schemes": list((data.get("securitySchemes") or {}).keys()) if isinstance(data.get("securitySchemes"), dict) else data.get("authentication"),
            }
            if data.get("url"):
                apply_matches(f, self.index.match_domains_in_text(str(data["url"])), location=rel)
            if not data.get("securitySchemes") and not data.get("authentication"):
                f.add_tag("no-auth-declared")
        elif kind == "m365":
            f.title = f"M365 Copilot declarative agent: {data.get('name') or rel}"
            f.add_framework("platform.m365-declarative-agent")
            f.add_evidence(Evidence(signal="file:platform.m365-declarative-agent", description="Microsoft 365 declarative agent manifest", location=rel, weight=0.95, signature="platform.m365-declarative-agent"))
            f.metadata["declarative_agent"] = {
                "name": data.get("name"),
                "description": truncate(str(data.get("description", "")), 300),
                "instructions": truncate(str(data.get("instructions", "")), 300),
                "capabilities": [c.get("name") for c in data.get("capabilities", []) or [] if isinstance(c, dict)],
                "actions": [a.get("id") or a.get("file") for a in data.get("actions", []) or [] if isinstance(a, dict)],
                "conversation_starters": len(data.get("conversation_starters", []) or []),
            }
            if data.get("actions"):
                f.add_capability("tool-use")
        elif kind == "langgraph":
            f.title = f"LangGraph deployment manifest: {rel}"
            f.add_framework("framework.langgraph")
            f.add_evidence(Evidence(signal="file:framework.langgraph", description="langgraph.json deployment manifest", location=rel, weight=0.95, signature="framework.langgraph"))
            graphs = data.get("graphs", {}) or {}
            f.metadata["graphs"] = list(graphs.keys()) if isinstance(graphs, dict) else graphs
            f.metadata["dependencies"] = data.get("dependencies")
            f.metadata["env"] = data.get("env")
            f.add_capability("tool-use")
        elif kind == "crewai":
            f.title = f"CrewAI agent definitions: {rel}"
            f.add_framework("framework.crewai")
            f.add_capability("multi-agent")
            f.add_evidence(Evidence(signal="file:framework.crewai", description="CrewAI agents.yaml", location=rel, weight=0.9, signature="framework.crewai"))
            f.metadata["agents"] = [
                {"name": k, "role": truncate(str((v or {}).get("role", "")), 120), "llm": (v or {}).get("llm")} for k, v in data.items() if isinstance(v, dict)
            ]
            for v in data.values():
                if isinstance(v, dict) and v.get("llm"):
                    apply_matches(f, self.index.match_model(str(v["llm"]).split("/")[-1]), location=rel, weight_scale=0.6)
        f.owner = self._owner_for(root, PurePosixPath(rel).parent.as_posix()) or f.owner
        finalize(f, self.index)
        f.kind = Kind.AGENT
        return f

    def _workflow_finding(self, label: str, root: Path, rel: str, hits: list[tuple[Match, str]]) -> Finding:
        f = self._base(label, root, rel, Kind.WORKFLOW, "", "workflow-export")
        for m, snip in hits:
            apply_matches(f, [m], location=rel, snippet=snip)
        names = {self.index.get(m.signature_id).name for m, _ in hits if self.index.get(m.signature_id)}  # type: ignore[union-attr]
        f.title = f"Exported AI workflow ({', '.join(sorted(names))}): {rel}"
        f.owner = self._owner_for(root, PurePosixPath(rel).parent.as_posix()) or f.owner
        finalize(f, self.index)
        f.kind = Kind.WORKFLOW
        return f

    def _infra_finding(self, label: str, root: Path, rel: str, hits: list[tuple[Match, str, str]], names_found: list[str] | None = None) -> Finding:
        f = self._base(label, root, rel, Kind.INFRA, "", "iac")
        for m, value, snip in hits:
            apply_matches(f, [m], location=rel, snippet=snip)
        names = {self.index.get(m.signature_id).name for m, _, _ in hits if self.index.get(m.signature_id)}  # type: ignore[union-attr]
        resources = sorted({v for _, v, _ in hits})
        f.title = f"Infrastructure provisions {', '.join(sorted(names))}: {rel}"
        f.metadata["resources"] = resources
        if names_found:
            f.metadata["names"] = names_found
        f.owner = self._owner_for(root, PurePosixPath(rel).parent.as_posix()) or f.owner
        finalize(f, self.index)
        f.kind = Kind.INFRA
        return f

    def _secret_finding(self, label: str, root: Path, rel: str, hits: list[tuple[Match, str]]) -> Finding:
        f = self._base(label, root, rel, Kind.SECRET, f"LLM provider credential in {rel}", "file")
        for m, snip in hits:
            apply_matches(f, [m], location=rel, snippet=snip)
        f.add_tag("hardcoded-credential")
        f.metadata["providers"] = sorted({m.signature_id for m, _ in hits})
        f.metadata["count"] = len(hits)
        f.owner = self._owner_for(root, PurePosixPath(rel).parent.as_posix()) or f.owner
        finalize(f, self.index)
        f.kind = Kind.SECRET
        return f

    @staticmethod
    def _parse_agent_definition(rel: str, text: str) -> dict[str, Any]:
        info: dict[str, Any] = {"file": rel, "name": PurePosixPath(rel).stem}
        m = _FRONTMATTER.match(text)
        if m:
            try:
                fm = yaml.safe_load(m.group(1)) or {}
            except yaml.YAMLError:
                fm = {}
            if isinstance(fm, dict):
                for k in ("name", "description", "tools", "model", "permissionMode", "mode", "globs", "alwaysApply"):
                    if k in fm:
                        v = fm[k]
                        info[k] = truncate(str(v), 200) if isinstance(v, str) else v
        return info


def _nearest_root(rel_dir: str, roots: list[str]) -> str:
    if rel_dir == ".":
        return "."
    best = "."
    for r in roots:
        if r == "." or rel_dir == r or rel_dir.startswith(r + "/"):
            if len(r) > len(best) or best == ".":
                best = r if r != "." else best
    return best


def _mcp_client_for(rel: str) -> str:
    r = rel.lower()
    if "claude_desktop_config" in r:
        return "Claude Desktop"
    if ".mcp.json" in r or "/.claude/" in r:
        return "Claude Code"
    if ".cursor/" in r:
        return "Cursor"
    if ".vscode/" in r:
        return "VS Code / Copilot"
    if ".windsurf" in r or "codeium" in r:
        return "Windsurf"
    if "cline" in r:
        return "Cline"
    if ".roo/" in r:
        return "Roo Code"
    if ".codex/" in r:
        return "OpenAI Codex"
    if ".gemini/" in r:
        return "Gemini CLI"
    if ".kiro/" in r or ".amazonq/" in r:
        return "Amazon Q / Kiro"
    if ".continue/" in r:
        return "Continue"
    if "opencode" in r:
        return "OpenCode"
    if "smithery" in r or r.endswith("server.json"):
        return "MCP server manifest"
    return "generic"


_SECRETISH = re.compile(r"(?i)(key|token|secret|password|passwd|credential|auth)")


def _parse_mcp_servers(rel: str, text: str) -> list[dict[str, Any]]:
    servers: dict[str, Any] = {}
    try:
        if rel.endswith(".toml"):
            data = tomllib.loads(text)
            servers = data.get("mcp_servers", {}) or (data.get("mcp", {}) or {}).get("servers", {}) or {}
        elif rel.endswith((".yaml", ".yml")):
            data = yaml.safe_load(text) or {}
            raw = data.get("mcpServers") or (data.get("mcp", {}) or {}).get("servers") or data.get("servers") or {}
            if isinstance(raw, list):  # continue.dev style list
                servers = {str(s.get("name", i)): s for i, s in enumerate(raw) if isinstance(s, dict)}
            else:
                servers = raw
        else:
            data = json.loads(_strip_json_comments(text))
            servers = data.get("mcpServers") or (data.get("mcp", {}) or {}).get("servers") or data.get("servers") or {}
            if not servers and data.get("name") and (data.get("packages") or data.get("remotes")):
                servers = {data["name"]: data}
    except (ValueError, tomllib.TOMLDecodeError, yaml.YAMLError, AttributeError):
        return []
    out: list[dict[str, Any]] = []
    if not isinstance(servers, dict):
        return out
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        env = cfg.get("env") or cfg.get("environment") or {}
        headers = cfg.get("headers") or {}
        url = cfg.get("url") or cfg.get("serverUrl") or cfg.get("endpoint")
        if not url and isinstance(cfg.get("remotes"), list) and cfg["remotes"]:
            url = cfg["remotes"][0].get("url")
        inline = False
        for k, v in list(env.items()) + list(headers.items()):
            if isinstance(v, str) and v and not v.startswith("${") and not looks_like_placeholder(v) and _SECRETISH.search(str(k)) and len(v) >= 12:
                inline = True
        transport = cfg.get("type") or cfg.get("transport") or ("stdio" if cfg.get("command") else ("http" if url else "unknown"))
        out.append(
            {
                "name": str(name),
                "transport": transport,
                "command": cfg.get("command"),
                "args": [str(a) for a in (cfg.get("args") or [])][:12],
                "url": url,
                "env": sorted(env.keys()) if isinstance(env, dict) else [],
                "headers": sorted(headers.keys()) if isinstance(headers, dict) else [],
                "secrets_inline": inline,
                "disabled": bool(cfg.get("disabled", False)),
                "auto_approve": cfg.get("autoApprove") or cfg.get("alwaysAllow"),
            }
        )
    return out


def _strip_json_comments(text: str) -> str:
    text = re.sub(r"^\s*//.*$", "", text, flags=re.M)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r",(\s*[}\]])", r"\1", text)
    return text
