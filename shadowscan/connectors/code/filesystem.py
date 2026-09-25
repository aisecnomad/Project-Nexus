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

Precision safeguards
--------------------
* A credential whose value looks like a documentation placeholder (see
  ``shadowscan.connectors.common.placeholder_reason``) never becomes a
  ``secret`` finding. It is attached to the project finding as low-weight
  ``example-credential`` evidence (tag ``example-credential``) so analysts
  still see that a sample key exists, without a high-risk alert.
* A credential alone does not establish LLM usage: secret matches only join
  the project finding when the project has another technology observation.
* Vendor-neutral heuristics (agent loops, autonomy flags, shell execution)
  only count when the project also matches a framework, provider, platform,
  protocol or cloud-service signature; on their own they describe ordinary
  automation code and are dropped.
* When every technology observation other than those heuristics is an
  environment-variable or display-name reference, the heuristics are dropped
  and the finding is built from the name references alone: evidence weights
  are halved, the finding is tagged ``env-names-only`` and confidence is
  capped below the ``confirmed`` band.
"""

from __future__ import annotations

import errno
import fnmatch
import hashlib
import json
import os
import re
import stat
import subprocess
import time
import tomllib
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, ClassVar

import yaml

from shadowscan.connectors.base import BaseConnector, ConnectorError
from shadowscan.connectors.code.import_provenance import local_module_conflict
from shadowscan.connectors.code.manifests import Artifact, Dep, is_manifest_name, parse_manifest
from shadowscan.connectors.code.ownership import (
    MAX_OWNERSHIP_STEPS,
    MAX_PATTERN_LENGTH,
    MAX_RULES,
    OwnershipBudget,
    OwnershipLimitError,
)
from shadowscan.connectors.code.ownership import (
    codeowners_match as _codeowners_match,
)
from shadowscan.connectors.code.semantic_config import (
    agent_manifest_kind,
    parse_agent_manifest,
    structured_code_matches,
)
from shadowscan.connectors.code.source_ranges import noncode_ranges
from shadowscan.connectors.code.source_semantics import bound_source_matches
from shadowscan.connectors.common import (
    apply_matches,
    cap_confidence,
    finalize,
    looks_like_placeholder,
    placeholder_reason,
)
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.signatures import Match
from shadowscan.signatures.matcher import SOURCE_EXTENSIONS, MatchTimeoutError, language_for_path
from shadowscan.utils.git import metadata_git_argv_prefix, metadata_git_env
from shadowscan.utils.redaction import SanitizationLimitError, sanitize, sanitize_text
from shadowscan.utils.safe_yaml import YAMLResourceLimitError, bounded_safe_load
from shadowscan.utils.text import notebook_to_source, parse_timestamp, read_text, redact, truncate

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

# A file over max_file_size that the scanner would read is an error: unread
# content could hide agent configuration. Names matching these globs hold
# generated, locked or binary content that never carries such evidence, so
# skipping them is a warning and the scan stays complete. The connector's
# `oversize_skip_globs` replaces the list; see docs/scanning.md.
DEFAULT_OVERSIZE_SKIP_GLOBS: tuple[str, ...] = (
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Pipfile.lock",
    "Cargo.lock",
    "Gemfile.lock",
    "composer.lock",
    "go.sum",
    "*.min.js",
    "*.min.css",
    "*.map",
    "*.svg",
    "*.csv",
    "*.parquet",
    "*.wasm",
    "*.so",
    "*.dylib",
    "*.dll",
    "*.pdf",
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.gif",
    "*.woff",
    "*.woff2",
    "*.ttf",
    "*.zip",
    "*.gz",
    "*.tar",
    "*.jar",
    "*.pyc",
    "*.class",
)
# Path.is_file() treats these as "not a file"; keep that for a vanished entry.
_IGNORED_STAT_ERRNOS = frozenset({errno.ENOENT, errno.ENOTDIR, errno.EBADF, errno.ELOOP})
# Per-file matching budget: `scan_timeout` covers the first 256 KiB and one
# more budget is added per further 256 KiB, capped so a hostile file still
# fails fast. A 971 KB JSON index gets four default budgets (8 s).
SCAN_TIMEOUT_STEP_BYTES = 256 * 1024
SCAN_TIMEOUT_CAP_SECONDS = 10.0
# Stop the walk this far before the connector deadline so the findings
# collected so far are emitted, sanitized and accepted by the engine, which
# discards a result that arrives after the deadline.
DEADLINE_MARGIN_FRACTION = 0.05
DEADLINE_MARGIN_MIN_SECONDS = 0.25

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
# Files whose parsed structure supplies credential context for excerpt
# redaction (see _structured_context).
_JSON_SUFFIXES = (".json", ".jsonc", ".json5")
_YAML_SUFFIXES = (".yaml", ".yml")

# Documentation placeholders are informational: enough to be listed, never
# enough to establish a technology or raise risk.
EXAMPLE_CREDENTIAL_WEIGHT = 0.1
MAX_EXAMPLE_CREDENTIAL_EVIDENCE = 20
# Environment-variable names alone are a weak signal (see module docstring):
# weights are halved and confidence stays inside the "likely" band.
ENV_ONLY_WEIGHT_SCALE = 0.5
ENV_ONLY_MAX_CONFIDENCE = 0.8
# Capability implied by an MCP server's launch command; the first matching
# group wins, so a database server launched through docker keeps code-exec.
_MCP_CAPABILITY_KEYWORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("code-exec", ("shell", "bash", "terminal", "exec", "docker", "kubectl", "ssh")),
    ("data-access", ("filesystem", "sqlite", "postgres", "mysql", "mongodb")),
    ("browsing", ("puppeteer", "playwright", "browser")),
    ("saas-actions", ("github", "gitlab", "slack", "gmail", "google-drive", "aws", "gcloud", "azure")),
)


@dataclass
class _Project:
    root: str  # relative posix path ("." for scan root)
    files: int = 0
    matches: list[tuple[Match, str, str | None]] = field(default_factory=list)  # match, relpath, snippet
    example_credentials: list[tuple[Match, str, str]] = field(default_factory=list)  # match, relpath, reason
    deps: list[Dep] = field(default_factory=list)
    languages: set[str] = field(default_factory=set)
    coding_agent_files: dict[str, list[str]] = field(default_factory=dict)  # sig id -> files
    coding_agent_matches: dict[str, list[tuple[Match, str, str | None]]] = field(default_factory=dict)
    agent_defs: list[dict[str, Any]] = field(default_factory=list)
    seen: set[tuple[str, int, str, str, int | None]] = field(default_factory=set)


_ROOT_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}\Z")

# Test suites routinely construct agents to exercise a library. Evidence found
# only there describes the library's tests, not a deployed agent, so it cannot
# establish an agent on its own unless ``include_tests`` is set.
_TEST_DIR_NAMES = frozenset({
    "test", "tests", "__tests__", "spec", "specs", "testing", "fixtures", "__fixtures__",
    "__mocks__", "cassettes", "testdata", "test_data", "test-data", "e2e",
})
_TEST_FILE_RE = re.compile(
    r"(?:^|/)(?:test_[^/]*\.py|[^/]*_test\.(?:py|go)|conftest\.py|[^/]*\.(?:test|spec)\.[cm]?[jt]sx?)$",
    re.IGNORECASE,
)
# Categories whose evidence shows that a file itself talks to a model.
_LLM_CATEGORIES = frozenset({"provider", "framework", "protocol", "platform", "cloud-service"})
# Signatures that are only meaningful when the same file also invokes an LLM.
_COLOCATED_SIGNATURES = frozenset({"heuristic.llm-command-execution"})
# IAM statements granting every action (Terraform, CloudFormation, ARM/Bicep JSON).
_IAM_WILDCARD_RE = re.compile(
    r"""(?i)["']?\bActions?["']?\s*[:=]\s*\[?\s*["']\*["']|["'](?:bedrock|iam|sts|lambda|s3|secretsmanager|kms):\*["']"""
)
_IAC_MODEL_RE = re.compile(
    r"""(?i)\b(?:foundation_?model(?:_?(?:id|arn))?|model_?id|model_?name|model)\b["']?\s*[:=]\s*["']([A-Za-z0-9][A-Za-z0-9._:/@-]{2,199})["']"""
)
_IAC_EXTENSIONS = frozenset({".tf", ".hcl", ".bicep", ".json", ".yaml", ".yml"})


def _is_test_path(rel: str) -> bool:
    parts = rel.lower().split("/")
    return any(part in _TEST_DIR_NAMES for part in parts[:-1]) or bool(_TEST_FILE_RE.search(rel))


def _link_target_inside(link: Path, resolved_root: Path) -> bool:
    """True when a (never followed) link resolves inside the scan root."""
    try:
        target = Path(os.path.realpath(link))
    except (OSError, ValueError, RuntimeError):
        return False
    return target == resolved_root or resolved_root in target.parents
MAX_ROOT_OWNERSHIP_STEPS = 20_000_000


def scan_timeout_for_size(base: float, size: int) -> float:
    """Return the matching budget in seconds for one file of ``size`` bytes.

    ``base`` is the configured ``scan_timeout``. Each further 256 KiB adds
    one more ``base`` so ordinary large text files finish on an idle core;
    the result is capped at 10 seconds, or at ``base`` when that is higher.
    """
    steps = max(size, 0) // SCAN_TIMEOUT_STEP_BYTES
    return min(base * (1 + steps), max(base, SCAN_TIMEOUT_CAP_SECONDS))


def deadline_margin(remaining: float) -> float:
    """Return the safety margin kept before a connector deadline.

    Five percent of the budget that remained when the walk started, and at
    least 250 ms, covers emitting the collected project findings and the
    engine's own sanitization before it compares completion to the deadline.
    """
    return max(DEADLINE_MARGIN_MIN_SECONDS, DEADLINE_MARGIN_FRACTION * remaining)


def _validated_globs(value: Any) -> list[str]:
    if not isinstance(value, (list, tuple)) or not all(isinstance(g, str) and g.strip() for g in value):
        raise ConnectorError("code.filesystem: oversize_skip_globs must be a list of file name globs")
    return [g.strip().lower() for g in value]


def _checked_scan_root(path: str | Path) -> Path:
    """Reject symlinked roots and ancestors before resolving a scan input.

    Keep ``..`` components while checking so ``link/..`` cannot conceal a
    symlink in the path supplied by the caller. The scan itself assumes an
    immutable checkout; an adversary concurrently replacing directories still
    needs isolation at the filesystem/container boundary.
    """
    try:
        raw = Path(path).expanduser().absolute()
        if any(part.is_symlink() for part in (raw, *raw.parents)):
            raise ConnectorError("code.filesystem: scan root must not traverse a symbolic link")
        root = raw.resolve()
        if root != Path(os.path.abspath(raw)):
            raise ConnectorError("code.filesystem: scan root changed while being validated")
        return root
    except ConnectorError:
        raise
    except (OSError, RuntimeError) as exc:
        raise ConnectorError("code.filesystem: scan root could not be safely resolved") from exc


def validate_distinct_paths(paths: Any) -> list[Path]:
    """Reject aliases that resolve to the same repository under one label."""
    if not isinstance(paths, list) or not paths or not all(isinstance(p, str) and p for p in paths):
        raise ConnectorError("code.filesystem: paths must be a nonempty list of paths")
    canonical = [_checked_scan_root(path) for path in paths]
    if len(set(canonical)) != len(canonical):
        raise ConnectorError("code.filesystem: labeled paths must resolve to distinct scan roots")
    return canonical


def validate_root_ids(paths: Any, root_ids: Any) -> list[str]:
    """Validate positional, stable IDs for a labeled ``paths`` connector."""
    validate_distinct_paths(paths)
    if not isinstance(root_ids, list) or len(root_ids) != len(paths):
        raise ConnectorError("code.filesystem: root_ids must contain exactly one ID per path")
    if not all(isinstance(root_id, str) and _ROOT_ID_RE.fullmatch(root_id) for root_id in root_ids):
        raise ConnectorError("code.filesystem: root_ids must be 1-80 characters of letters, digits, '.', '_' or '-'")
    if len(set(root_ids)) != len(root_ids):
        raise ConnectorError("code.filesystem: root_ids must be unique within paths")
    return root_ids


class FilesystemConnector(BaseConnector):
    name: ClassVar[str] = "code.filesystem"
    surface: ClassVar[Surface] = Surface.CODE
    provider: ClassVar[str | None] = "filesystem"
    description: ClassVar[str] = "Scan a local directory / repository checkout for agent frameworks, MCP, coding agents, IaC and secrets."
    config_keys: ClassVar[dict[str, str]] = {
        "path": "directory to scan (or `paths`: list)",
        "paths": "list of directories to scan instead of `path`; each root keeps its own identity",
        "exclude": "extra directory names / glob patterns to skip",
        "max_file_size": "bytes; a larger file is not analyzed: skipped with a warning, or an error under strict_coverage unless oversize_skip_globs matches it (default 1 MiB)",
        "oversize_skip_globs": "case-insensitive file name globs; a file over max_file_size matching one is skipped with a warning even under strict_coverage (default: lockfiles, minified bundles, source maps, images, fonts, archives and compiled artifacts)",
        "max_files": "stop after this many files (default 100000)",
        "scan_timeout": "matching budget in seconds per file up to 256 KiB (default 2); one more budget per further 256 KiB, capped at 10 seconds or scan_timeout when higher",
        "scan_secrets": "detect provider credentials (default true)",
        "use_git": "opt in to offline git author/date enrichment for trusted metadata; requires Git 2.45+ (default false)",
        "strict_coverage": "treat oversize files and symbolic links leaving the scan root as incomplete coverage (default false: skipped with a warning)",
        "include_tests": "let test and fixture code establish agents at full weight (default false)",
        "label": "prefix for resource ids (e.g. 'github:org/repo'); defaults to the path",
        "root_ids": "unique stable IDs aligned with paths, for resource identity across checkout moves",
        "account": "account label recorded on every finding (default none)",
        "owner": "owner recorded on every finding; overrides CODEOWNERS and inventory attribution (default: CODEOWNERS, then git author when use_git, then inventory)",
        "provider": "provider label recorded on findings (default filesystem)",
        "metadata": "mapping merged into every finding's metadata",
    }
    shared_config_keys: ClassVar[dict[str, str]] = {}  # scans a checkout, not an export file
    offline_formats: ClassVar[str] = "n/a (path is the input)"

    def __init__(self, ctx):
        super().__init__(ctx)
        self.max_file_size = int(ctx.get("max_file_size", 1_000_000))
        self.max_files = int(ctx.get("max_files", 100_000))
        self.scan_timeout = float(ctx.get("scan_timeout", 2.0))
        if self.max_file_size < 1 or self.max_files < 1 or not 0 < self.scan_timeout <= 60:
            raise ConnectorError("code.filesystem: limits must be positive; scan_timeout must be at most 60 seconds")
        self.oversize_skip_globs = _validated_globs(ctx.get("oversize_skip_globs", list(DEFAULT_OVERSIZE_SKIP_GLOBS)))
        self.scan_secrets = bool(ctx.get("scan_secrets", True))
        self.use_git = ctx.get("use_git", False)
        if not isinstance(self.use_git, bool):
            raise ConnectorError("code.filesystem: use_git must be a boolean")
        self.strict_coverage = ctx.get("strict_coverage", False)
        self.include_tests = ctx.get("include_tests", False)
        for key, value in (("strict_coverage", self.strict_coverage), ("include_tests", self.include_tests)):
            if not isinstance(value, bool):
                raise ConnectorError(f"code.filesystem: {key} must be a boolean")
        extra = ctx.get("exclude", []) or []
        self.exclude_names = set(DEFAULT_EXCLUDES) | {e for e in extra if "*" not in e and "/" not in e}
        self.exclude_globs = [e for e in extra if "*" in e or "/" in e]
        self.label: str | None = ctx.get("label")
        # Every labeled `paths` root has its own identity, even if the list
        # shrinks to one. The engine marks a child split for incremental reuse.
        paths = ctx.get("paths")
        self._shared_label_roots = isinstance(paths, list) or ctx.get("_shared_label_roots") is True
        if self.label and isinstance(paths, list):
            validate_distinct_paths(paths)
        self._root_ids: dict[Path, str] = {}
        root_ids = ctx.get("root_ids")
        split_root_id = ctx.get("_root_id")
        if root_ids is not None:
            if not self.label or ctx.input_path:
                raise ConnectorError("code.filesystem: root_ids requires a label and paths, without input")
            validated = validate_root_ids(paths, root_ids)
            self._root_ids = {
                Path(path).expanduser().resolve(): root_id
                for path, root_id in zip(paths, validated, strict=True)
            }
        elif split_root_id is not None:
            path = ctx.get("path")
            if not self.label or not isinstance(path, str) or not isinstance(split_root_id, str) or not _ROOT_ID_RE.fullmatch(split_root_id):
                raise ConnectorError("code.filesystem: invalid split root identity")
            self._root_ids[Path(path).expanduser().resolve()] = split_root_id
        self.account: str | None = ctx.get("account")
        self.owner: str | None = ctx.get("owner")
        self.provider_override: str | None = ctx.get("provider")
        self.extra_metadata: dict[str, Any] = dict(ctx.get("metadata", {}) or {})
        self._codeowners_cache: dict[Path, list[tuple[str, list[str]]]] = {}
        self._ownership_exhausted: set[Path] = set()
        self._ownership_steps_remaining: dict[Path, int] = {}
        self._owner_cache: dict[tuple[Path, str], str | None] = {}
        self._symlink_warnings: set[Path] = set()

    # ----------------------------------------------------------------- input
    def _paths(self) -> list[Path]:
        paths = self.ctx.get("paths") or ([self.ctx.get("path")] if self.ctx.get("path") else None)
        if not paths and self.ctx.input_path:
            paths = [self.ctx.input_path]
        if not paths:
            raise ConnectorError("code.filesystem: 'path' is required")
        out = []
        for p in paths:
            pp = _checked_scan_root(p)
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
            try:
                root = _checked_scan_root(rec["path"])
            except ConnectorError as exc:
                self.ctx.error(str(exc))
                continue
            if not root.exists():
                self.ctx.error(f"code.filesystem: path not found: {root}")
                continue
            yield from self.scan_tree(root)

    # ------------------------------------------------------------------ walk
    def _excluded(self, rel: str, name: str) -> bool:
        """Directory exclusion: configured names and globs."""
        return name in self.exclude_names or self._excluded_file(rel)

    def _excluded_file(self, rel: str) -> bool:
        """File exclusion: globs only, so a file named like an excluded directory is still scanned."""
        for g in self.exclude_globs:
            if PurePosixPath(rel).match(g) or PurePosixPath(rel).match(g.rstrip("/") + "/*"):
                return True
        return False

    def _oversize_skippable(self, rel: str, name: str) -> bool:
        """Whether an oversize file is generated, locked or binary content per ``oversize_skip_globs``."""
        lower = name.lower()
        for pattern in self.oversize_skip_globs:
            if "/" in pattern:
                if PurePosixPath(rel.lower()).match(pattern):
                    return True
            elif fnmatch.fnmatchcase(lower, pattern):
                return True
        return False

    def _skip_oversize(self, rel: str, size: int) -> None:
        self.ctx.warn(
            f"code.filesystem: {rel}: skipped {size} byte file over max_file_size ({self.max_file_size}); "
            "generated or binary content is never analyzed",
            incomplete=False,
        )

    def _iter_files(self, root: Path) -> Iterator[tuple[str, Path, str]]:
        """Yield (relpath, path, project_root_rel) top-down with project root tracking."""
        for rel, path, proj, _ in self._iter_entries(root):
            yield rel, path, proj

    def _iter_entries(self, root: Path) -> Iterator[tuple[str, Path, str, int]]:
        """Yield (relpath, path, project_root_rel, size) for every regular file to analyze.

        A file over ``max_file_size`` whose name matches ``oversize_skip_globs``
        is reported as a warning and never yielded; the scan stays complete
        because such content is never analyzed. Every other oversize file is
        yielded so the reader records the existing error, or skips it silently
        when its type is never read.
        """
        # os.walk visits descendants before siblings. Keep only active project
        # ancestors, so assigning a project is amortized constant time even in
        # monorepos with thousands of sibling projects.
        roots: list[str] = ["."]
        count = 0

        resolved_root = Path(os.path.realpath(root))

        def skipped_link(rel: str, link: Path) -> None:
            # Links are never followed. A link that resolves inside the scan
            # root loses no coverage: its target is scanned at its real path.
            if _link_target_inside(link, resolved_root):
                return
            # A single representative diagnostic per root keeps hostile trees
            # from filling the report with thousands of link names.
            if root not in self._symlink_warnings:
                self._symlink_warnings.add(root)
                message = f"code.filesystem: skipped symbolic link {rel} whose target is outside the scan root"
                if self.strict_coverage:
                    self.ctx.error(f"{message}; coverage incomplete")
                else:
                    self.ctx.warn(f"{message}; enable strict_coverage to treat this as incomplete", incomplete=False)

        if root.is_file():
            try:
                size = root.stat().st_size
            except OSError:
                self.ctx.error(f"code.filesystem: could not inspect {root.name}")
                return
            if size > self.max_file_size and self._oversize_skippable(root.name, root.name):
                self._skip_oversize(root.name, size)
                return
            yield root.name, root, ".", size
            return
        def walk_error(exc: OSError) -> None:
            self.ctx.error(f"code.filesystem: could not enumerate a directory under {root}")

        for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=walk_error):
            rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
            rel_dir = "." if rel_dir == "." else rel_dir
            kept = []
            for name in sorted(dirnames):
                rel = name if rel_dir == "." else f"{rel_dir}/{name}"
                if self._excluded(rel, name):
                    continue
                path = Path(dirpath) / name
                try:
                    if path.is_symlink():
                        skipped_link(rel, path)
                        continue
                except OSError:
                    self.ctx.error(f"code.filesystem: could not inspect {rel}")
                    continue
                kept.append(name)
            dirnames[:] = kept
            proj = _nearest_root(rel_dir, roots)
            if rel_dir != "." and any(f in PROJECT_ROOT_MARKERS for f in filenames):
                roots.append(rel_dir)
                proj = rel_dir
            for fn in sorted(filenames):
                rel = fn if rel_dir == "." else f"{rel_dir}/{fn}"
                if self._excluded_file(rel):
                    continue
                p = Path(dirpath) / fn
                try:
                    if p.is_symlink():
                        skipped_link(rel, p)
                        continue
                    info = p.stat()
                except OSError as exc:
                    if exc.errno in _IGNORED_STAT_ERRNOS:
                        continue
                    self.ctx.error(f"code.filesystem: could not inspect {rel}")
                    continue
                if not stat.S_ISREG(info.st_mode):
                    continue
                if info.st_size > self.max_file_size and self._oversize_skippable(rel, fn):
                    self._skip_oversize(rel, info.st_size)
                    continue
                if fn in LOCK_FILES or fn.endswith((".min.js", ".min.css", ".map", ".pyc", ".lock")):
                    continue
                count += 1
                if count > self.max_files:
                    self.ctx.error(f"code.filesystem: max_files ({self.max_files}) reached under {root}")
                    return
                yield rel, p, proj, info.st_size

    def _reserved_budget(self, rel: str, path: Path, size: int, budget: float) -> float:
        """Return the share of ``budget`` a file must have left before the walk may start it.

        Files the reader never opens (over ``max_file_size``, which only
        records an error, or neither source, configuration nor a file-name
        signal) reserve nothing, so they cannot end the walk under a short
        deadline.
        """
        if size > self.max_file_size:
            return 0.0
        name = path.name
        ext = path.suffix.lower()
        will_read = (
            ext in SOURCE_EXTENSIONS or ext in TEXT_CONFIG_EXTENSIONS or name.lower().startswith(".env")
            or is_manifest_name(name) or "." not in name or bool(self.index.match_file(rel))
        )
        return budget if will_read else 0.0

    def _stop_at_deadline(
        self, root: Path, examined: int, entries: Iterator[tuple[str, Path, str, int]], deadline: float, margin: float,
    ) -> None:
        """Record one error naming how much of the tree the connector deadline left unread.

        The remaining entries are only counted (a stat each, never a read).
        Counting stops at half the margin or just before the ``max_files``
        cap, so the findings already collected are still emitted in time.
        """
        remaining = 1  # the entry that could not start
        truncated = False
        count_until = deadline - margin / 2
        for _ in entries:
            remaining += 1
            if examined + remaining >= self.max_files or (not (remaining & 63) and time.monotonic() >= count_until):
                truncated = True
                break
        total = f"at least {examined + remaining}" if truncated else str(examined + remaining)
        self.ctx.error(
            f"code.filesystem: connector deadline reached after {examined} of {total} files under {root}; "
            "results incomplete",
        )

    # ------------------------------------------------------------------ scan
    def scan_tree(self, root: Path) -> Iterator[Finding]:
        label = self.label or str(root)
        if self.label and self._shared_label_roots:
            # Explicit IDs survive checkout relocation; absent them, hash the
            # resolved root to avoid exposing local directory names.
            root_id = self._root_ids.get(root)
            label = (
                f"{label}/root-id-{root_id}" if root_id is not None
                else f"{label}/root-{hashlib.sha256(os.fsencode(root)).hexdigest()}"
            )
        projects: dict[str, _Project] = {".": _Project(".")}
        secret_hits: dict[str, list[tuple[Match, str]]] = {}  # relpath -> matches
        mcp_files: list[tuple[str, list[dict[str, Any]]]] = []  # relpath, parsed servers
        card_files: list[tuple[str, str, str]] = []  # relpath, text, kind
        workflow_files: dict[str, list[tuple[Match, str]]] = {}
        infra_files: dict[str, list[tuple[Match, str, str]]] = {}  # relpath -> (match, value, snippet)
        infra_names: dict[str, list[str]] = {}  # relpath -> display / resource names
        infra_project: dict[str, str] = {}  # relpath -> project root
        workflow_providers: dict[str, list[tuple[Match, str]]] = {}  # relpath -> model nodes in exported workflows
        infra_models: dict[str, list[Match]] = {}  # relpath -> model ids declared in IaC
        iam_wildcards: dict[str, list[tuple[str, int, str]]] = {}  # project root -> (relpath, line, excerpt)
        deadline = self.ctx.deadline
        margin = deadline_margin(deadline - time.monotonic()) if deadline is not None else 0.0
        entries = self._iter_entries(root)
        examined = 0
        for rel, path, proj_root, size in entries:
            budget = scan_timeout_for_size(self.scan_timeout, size)
            reserve = self._reserved_budget(rel, path, size, budget)
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining < reserve + margin:
                    if remaining > margin + self.scan_timeout:
                        # Only this file's size-scaled budget does not fit; the
                        # walk can still cover ordinary files, so record the
                        # gap for this file alone and keep going.
                        self.ctx.error(
                            f"code.filesystem: {rel}: skipped; the remaining connector deadline cannot cover "
                            f"its {reserve:.0f}s matching budget",
                        )
                        continue
                    # Cooperative deadline: never start a file whose budget
                    # could run into the margin. Findings collected so far are
                    # returned and the engine keeps them; only a result that
                    # arrives after the deadline is discarded.
                    self._stop_at_deadline(root, examined, entries, deadline, margin)
                    break
            examined += 1
            try:
                with self.index.scan_budget(seconds=budget):
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

                    is_source = ext in SOURCE_EXTENSIONS
                    is_text_cfg = ext in TEXT_CONFIG_EXTENSIONS or lower.startswith(".env") or is_manifest_name(name) or "." not in name
                    if not (is_source or is_text_cfg or file_matches):
                        continue
                    read_errors: list[str] = []
                    text = read_text(path, self.max_file_size, read_errors)
                    for issue in read_errors:
                        if issue == "file exceeds max_file_size" and not self.strict_coverage:
                            self.ctx.warn(f"code.filesystem: {rel}: skipped, {issue}; enable strict_coverage to treat this as incomplete", incomplete=False)
                        else:
                            self.ctx.error(f"code.filesystem: {rel}: {issue}")
                    if text is None:
                        continue
                    raw_notebook: str | None = None
                    if ext == ".ipynb":
                        notebook_errors: list[str] = []
                        raw_notebook = text
                        text = notebook_to_source(text, notebook_errors)
                        for issue in dict.fromkeys(notebook_errors):
                            self.ctx.error(f"code.filesystem: {rel}: {issue}")
                        lang = "python"
                    # Structured files are parsed now so a resource-limit
                    # failure reaches the per-file boundary. Redacting the
                    # text for excerpts waits until a match needs one, which
                    # most files never do.
                    try:
                        structure = _structured_context(rel, text)
                    except (YAMLResourceLimitError, SanitizationLimitError) as exc:
                        # Detection still runs, but without an established
                        # structured context none of this file's excerpts can
                        # safely be emitted.
                        self.ctx.error(f"code.filesystem: {rel}: structured sanitization incomplete ({type(exc).__name__}); excerpts withheld")
                        structure = None
                    source: str = text
                    safe_lines: list[str] | None = [] if structure is None else None

                    card_kind = agent_manifest_kind(rel)
                    card_valid = False
                    if card_kind:
                        validation = parse_agent_manifest(rel, text, card_kind)
                        for issue in validation.errors:
                            self.ctx.error(f"code.filesystem: {rel}: {issue}")
                        card_valid = validation.valid
                    for m in file_matches:
                        if m.signature_id == "protocol.mcp":
                            continue
                        # A suggestive filename establishes neither a valid
                        # manifest nor an agent. Keep coding-agent file evidence
                        # and validated product schemas; do not invent agents.
                        if card_kind and not card_valid:
                            continue
                        m.extra["verified_agent"] = card_valid
                        self._record(proj, m, rel, None)

                    def redacted_lines() -> list[str]:
                        nonlocal safe_lines, structure
                        if structure is None:
                            return []
                        if safe_lines is None:
                            try:
                                safe_lines = _redacted_source(source, structure).splitlines()
                            except (YAMLResourceLimitError, SanitizationLimitError) as exc:
                                self.ctx.error(f"code.filesystem: {rel}: structured sanitization incomplete ({type(exc).__name__}); excerpts withheld")
                                structure = None
                                safe_lines = []
                        return safe_lines

                    def excerpt(line_number: int | None, secret: str | None = None) -> str:
                        return _excerpt(redacted_lines(), line_number or 1, secret)

                    # Credential detection runs first and in its own isolation so a
                    # slow or over-budget content pass cannot hide a real key. Notebook
                    # outputs and markdown cells are scanned from the raw document.
                    if self.scan_secrets:
                        try:
                            seen_secrets: set[tuple[str, str, int | None]] = set()
                            for raw in (text, raw_notebook):
                                if raw is None or (raw == text and seen_secrets):
                                    continue
                                raw_lines: list[str] | None = None
                                if raw is raw_notebook and raw_notebook != text and structure is not None:
                                    try:
                                        raw_lines = sanitize_text(raw).splitlines()
                                    except SanitizationLimitError:
                                        self.ctx.error(f"code.filesystem: {rel}: notebook excerpt sanitization incomplete; excerpts withheld")
                                for m in self.index.match_secrets(raw):
                                    key = (m.signature_id, m.value, m.line)
                                    if key in seen_secrets:
                                        continue
                                    seen_secrets.add(key)
                                    reason = placeholder_reason(m.value)
                                    if reason:
                                        self._record_example_credential(proj, m, rel, reason)
                                        continue
                                    if raw is raw_notebook and raw_notebook != text:
                                        snippet = _excerpt(raw_lines, m.line or 1, m.value) if raw_lines is not None else ""
                                    else:
                                        snippet = excerpt(m.line, m.value)
                                    secret_hits.setdefault(rel, []).append((m, snippet))
                                    self._record(proj, m, rel, None)
                        except ConnectorError:
                            raise
                        except Exception as exc:  # noqa: BLE001 - keep the content passes and other files
                            self.ctx.error(f"code.filesystem: {rel}: credential detection incomplete ({type(exc).__name__})")

                    is_mcp = self._looks_like_mcp_config(rel, name, text) or (
                        lower == "server.json" and '"mcpServers"' in text
                    )
                    mcp_servers: list[dict[str, Any]] = []
                    if is_mcp:
                        mcp_errors: list[str] = []
                        mcp_servers = _parse_mcp_servers(rel, text, mcp_errors)
                        for issue in dict.fromkeys(mcp_errors):
                            self.ctx.error(f"code.filesystem: {rel}: {issue}")
                    active_mcp = [server for server in mcp_servers if not server["disabled"]]
                    for m in file_matches:
                        if m.signature_id == "protocol.mcp" and active_mcp:
                            self._record(proj, m, rel, None)

                    def record_content_match(m: Match, snippet: str | None) -> None:
                        # A bare key or matching filename is not evidence of a
                        # configured server when all entries are empty/disabled.
                        if m.signature_id != "protocol.mcp" or not is_mcp or active_mcp:
                            self._record(proj, m, rel, snippet)

                    # 2. manifests (dependencies, images, env names, IaC types)
                    manifest = parse_manifest(rel, text) if (is_manifest_name(name) or ext in {".tf", ".bicep", ".yml", ".yaml", ".json", ".hcl"} or ".github/workflows" in rel) else None
                    if manifest:
                        for issue in dict.fromkeys(manifest.errors):
                            self.ctx.error(f"code.filesystem: {rel}: {issue}")
                        for dep in manifest.deps:
                            proj.deps.append(dep)
                            for m in self.index.match_dependency(dep.ecosystem, dep.name):
                                m.line = dep.line
                                self._record(proj, m, rel, f"{dep.ecosystem}: {dep.name} {dep.spec or ''}".strip())
                        for art in manifest.artifacts:
                            self._handle_artifact(proj, art, rel, text, infra_files, secret_hits, infra_names)
                    if ext in _IAC_EXTENSIONS and not is_mcp:
                        # Excerpts come from the redacted source, which is only
                        # produced for files that actually contain a wildcard.
                        if _IAM_WILDCARD_RE.search(text):
                            for number, line_text in enumerate(redacted_lines(), start=1):
                                if _IAM_WILDCARD_RE.search(line_text):
                                    wildcard_hits = iam_wildcards.setdefault(proj_root, [])
                                    if len(wildcard_hits) < 20:
                                        wildcard_hits.append((rel, number, truncate(line_text.strip(), 160) or ""))
                        if rel in infra_files:
                            infra_project[rel] = proj_root
                            for model in _IAC_MODEL_RE.finditer(text):
                                for mm in self.index.match_model(model.group(1)):
                                    mm.line = text.count("\n", 0, model.start()) + 1
                                    infra_models.setdefault(rel, []).append(mm)

                    # 3. source & config content
                    # Match prose documentation by its dedicated filenames only.
                    # Invocations in a README, even in fenced examples, do not
                    # establish executable agent code in this repository.
                    is_documentation = ext in {".md", ".mdc", ".mdx", ".txt"} and not is_manifest_name(name)
                    # Maven's XML parser above extracts dependency declarations.
                    # Generic regex matching over the raw POM would promote
                    # examples in descriptions or CDATA to executable agents.
                    is_nonexecutable = is_documentation or lower == "pom.xml"
                    # XML comments are examples/disabled declarations. Preserve
                    # offsets for match line numbers and the original redacted
                    # excerpts; the manifest parser handles active XML itself.
                    content_text = _without_xml_comments(text) if ext in {".xml", ".props", ".targets", ".csproj", ".fsproj", ".vbproj"} else text
                    if is_source:
                        local_modules: dict[str, bool] = {}

                        def is_local_module(module: str) -> bool:
                            # Resolve only within the supplied directory scope.
                            # A standalone file has no sibling/module inventory.
                            if root.is_file():
                                return False
                            name = module.split(".", 1)[0]
                            if name not in local_modules:
                                local_modules[name] = local_module_conflict(
                                    module, scan_root=root, source_path=path,
                                    project_root=root if proj_root == "." else root / proj_root,
                                )
                            return local_modules[name]

                        # Malformed trailing literals are masked through EOF;
                        # preceding valid imports/code remain inspectable.
                        ignored, ambiguous = noncode_ranges(
                            content_text, lang, ext, jsx=ext in {".jsx", ".tsx"},
                        )
                        if ambiguous:
                            self.ctx.error(f"code.filesystem: {rel}: incomplete source lexical analysis")
                        imports = (
                            self.index.match_imports(content_text, lang, ignore_spans=ignored)
                            if ignored else self.index.match_imports(content_text, lang)
                        )
                        for m in imports:
                            if lang == "python":
                                imported = re.match(r"\s*(?:from|import)\s+([A-Za-z_]\w*(?:\.\w+)*)", m.value)
                                if imported and is_local_module(imported.group(1)):
                                    continue
                            record_content_match(m, excerpt(m.line))
                        code_matches = (
                            self.index.match_code(content_text, lang, ignore_spans=ignored)
                            if ignored else self.index.match_code(content_text, lang)
                        )
                        bound = (
                            bound_source_matches(
                                self.index, content_text, lang, ignored,
                                is_local_module=is_local_module if lang == "python" else None,
                            )
                            if lang in {"python", "javascript"} else []
                        )
                        # Execution sinks describe a model-driven capability only
                        # when this same file invokes a model, framework or
                        # tool-calling protocol; elsewhere they are build tooling.
                        file_uses_llm = any(
                            m.signature.category in _LLM_CATEGORIES for m in (*imports, *code_matches, *bound)
                        )
                        for m in code_matches:
                            if m.signature_id in _COLOCATED_SIGNATURES and not file_uses_llm:
                                continue
                            if lang in {"python", "javascript"}:
                                if m.signature.category == "framework":
                                    continue  # bound calls below establish the library
                                m.extra["verified_agent"] = False
                            else:
                                # Other languages have lexical filtering but
                                # no import binder. Their code signatures need
                                # corroborating library evidence at emit time.
                                m.extra["lexical_source"] = lang
                            record_content_match(m, excerpt(m.line))
                        for m in bound:
                            record_content_match(m, excerpt(m.line))
                    elif not is_nonexecutable:
                        config_errors: list[str] = []
                        structured = [] if is_mcp else structured_code_matches(self.index, rel, content_text, errors=config_errors)
                        for issue in config_errors:
                            self.ctx.error(f"code.filesystem: {rel}: {issue}")
                        for m in structured:
                            # MCP configs are structured data. A disabled server
                            # may contain sample commands that look like agent
                            # code; only the parsed protocol marker is relevant.
                            if is_mcp and m.signature_id != "protocol.mcp":
                                continue
                            record_content_match(m, None)
                            if m.signature.category in {"platform", "cloud-service"} and m.agent_indicator and ext in {".json", ".yaml", ".yml"} and not is_mcp:
                                workflow_files.setdefault(rel, []).append((m, ""))
                            elif m.signature.category == "provider" and m.extra.get("structured_config") and not is_mcp:
                                workflow_providers.setdefault(rel, []).append((m, ""))
                    if not is_nonexecutable and not is_mcp:
                        for m in self.index.match_envs_in_text(content_text):
                            record_content_match(m, excerpt(m.line))
                        for m in self.index.match_domains_in_text(content_text):
                            record_content_match(m, excerpt(m.line))
                    # 4. special files
                    if active_mcp:
                        mcp_files.append((rel, mcp_servers))
                    if card_kind and card_valid:
                        if len(card_files) >= _MAX_CARD_FILES:
                            self.ctx.error(f"code.filesystem: {rel}: agent manifest limit ({_MAX_CARD_FILES}) reached; manifest skipped")
                        else:
                            card_files.append((rel, text, card_kind))
                    if ext in {".md", ".mdc"} and (".claude/agents/" in rel or ".github/agents/" in rel or ".cursor/rules/" in rel or ".windsurf/rules/" in rel):
                        if len(proj.agent_defs) >= _MAX_AGENT_DEFINITIONS:
                            self.ctx.error(f"code.filesystem: {rel}: agent definition limit ({_MAX_AGENT_DEFINITIONS}) reached; definition skipped")
                        else:
                            proj.agent_defs.append(self._parse_agent_definition(rel, text))
            except ConnectorError:
                # Cancellation or an exhausted deadline ends the walk; it must
                # not become one "file analysis incomplete" error per file.
                raise
            except Exception as exc:  # noqa: BLE001 - isolate hostile files and retain other findings
                # Only the scanner's own limit messages are static text; never
                # echo exception text that could be derived from hostile input.
                reason = f"{type(exc).__name__}: {exc}" if isinstance(exc, MatchTimeoutError) else type(exc).__name__
                self.ctx.error(f"code.filesystem: {rel}: file analysis incomplete ({sanitize_text(reason)[:200]})")

        # ------------------------------------------------------------ emit
        # MCP configs, agent manifests, exported workflows and IaC produce their
        # own findings; a project finding built only from them is a duplicate.
        covered_files = frozenset(
            {rel for rel, _ in mcp_files} | {rel for rel, _, _ in card_files} | set(workflow_files) | set(infra_files)
        )
        for proj in projects.values():
            try:
                yield from self._emit_project(label, root, proj, covered_files)
            except Exception as exc:  # noqa: BLE001 - retain findings from other projects
                self.ctx.error(f"code.filesystem: {proj.root}: project analysis incomplete ({type(exc).__name__})")
        for rel, servers in mcp_files:
            try:
                with self.index.scan_budget(seconds=self.scan_timeout):
                    yield self._mcp_finding(label, root, rel, servers)
            except ConnectorError:
                raise
            except Exception as exc:  # noqa: BLE001 - retain findings from other configurations
                self.ctx.error(f"code.filesystem: {rel}: MCP analysis incomplete ({type(exc).__name__})")
        for rel, text, kind in card_files:
            try:
                with self.index.scan_budget(seconds=self.scan_timeout):
                    f = self._card_finding(label, root, rel, text, kind)
                    if f:
                        yield f
            except ConnectorError:
                raise
            except Exception as exc:  # noqa: BLE001 - retain findings from other manifests
                self.ctx.error(f"code.filesystem: {rel}: agent manifest analysis incomplete ({type(exc).__name__})")
        for rel, hits in workflow_files.items():
            try:
                yield self._workflow_finding(label, root, rel, [*hits, *workflow_providers.get(rel, [])])
            except Exception as exc:  # noqa: BLE001 - retain findings from other files
                self.ctx.error(f"code.filesystem: {rel}: workflow analysis incomplete ({type(exc).__name__})")
        for rel, infra_hits in infra_files.items():
            try:
                yield self._infra_finding(
                    label, root, rel, infra_hits, infra_names.get(rel, []),
                    wildcards=iam_wildcards.get(infra_project.get(rel, ""), []), models=infra_models.get(rel, []),
                )
            except Exception as exc:  # noqa: BLE001 - retain findings from other files
                self.ctx.error(f"code.filesystem: {rel}: infrastructure analysis incomplete ({type(exc).__name__})")
        for rel, hits in secret_hits.items():
            try:
                f = self._secret_finding(label, root, rel, hits)
                if f:
                    yield f
            except Exception as exc:  # noqa: BLE001 - retain findings from other files
                self.ctx.error(f"code.filesystem: {rel}: credential analysis incomplete ({type(exc).__name__})")

    # --------------------------------------------------------------- helpers
    def _record_example_credential(self, proj: _Project, m: Match, rel: str, reason: str) -> None:
        """Remember a placeholder credential for informational project evidence."""
        key = (m.signature_id, id(m.signal), m.value, rel, m.line)
        if key in proj.seen:
            return
        proj.seen.add(key)
        proj.example_credentials.append((m, rel, reason))

    def _record(self, proj: _Project, m: Match, rel: str, snippet: str | None) -> None:
        snippet = sanitize_text(snippet) if snippet is not None else None
        if m.signature.category == "identity-app":
            return  # identity-app signatures describe OAuth/SaaS apps, not code
        # A manifest artifact and the generic text pass can observe the same
        # token on the same line. Confidence combines evidence as independent
        # signals, so a duplicate observation must not count twice.
        # Distinct signals may attach different authority/capabilities to the
        # same text. Deduplicate repeated passes of the same signal only.
        key = (m.signature_id, id(m.signal), m.value, rel, m.line)
        if key in proj.seen:
            return
        proj.seen.add(key)
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
            if val and self.scan_secrets:
                for m in self.index.match_secrets(val):
                    m.line = art.line
                    # Judge the matched credential, not the whole assignment:
                    # a trailing comment must not hide a real key.
                    reason = placeholder_reason(m.value)
                    if reason:
                        self._record_example_credential(proj, m, rel, reason)
                        continue
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
        if lower == "server.json":
            # A generic service can use this filename. The MCP registry format
            # has a name and structured package or remote transport records.
            try:
                data = _load_json_lenient(text)
            except (ValueError, RecursionError):
                return False
            if not isinstance(data, dict):
                return False
            explicit = data.get("mcpServers", data.get("mcp_servers"))
            if isinstance(explicit, dict) and bool(explicit):
                return True
            if not isinstance(data.get("name"), str) or not data["name"].strip():
                return False
            packages = data.get("packages")
            remotes = data.get("remotes")
            return (
                isinstance(packages, list) and any(
                    isinstance(p, dict) and isinstance(p.get("registryType"), str)
                    and isinstance(p.get("identifier"), str) and p["identifier"].strip()
                    for p in packages
                ) or isinstance(remotes, list) and any(
                    isinstance(r, dict) and isinstance(r.get("url"), str)
                    and r["url"].startswith(("https://", "http://"))
                    and r.get("type") in {"streamable-http", "sse"}
                    for r in remotes
                )
            )
        if lower in {".mcp.json", "mcp.json", "mcp-config.json", "mcp_config.json", "mcp-servers.json", "claude_desktop_config.json", "cline_mcp_settings.json", "mcp_settings.json", "smithery.yaml"}:
            return True
        if lower in MCP_CONFIG_NAMES or rel.endswith((".json", ".toml", ".yaml", ".yml")):
            head = text[:200_000]
            return (
                '"mcpServers"' in head or '"mcp_servers"' in head
                or "mcpServers:" in head or "mcp_servers:" in head
                or "[mcp_servers." in head
                or re.search(r"(?m)^[ \t]*\[mcp_servers\][ \t]*(?:#.*)?$", head) is not None
                or re.search(r"(?m)^[ \t]*mcp_servers\.[A-Za-z0-9_-]+[ \t]*=", head) is not None
                or ('"mcp"' in head and '"servers"' in head)
                or ("mcp:" in head and "servers:" in head)
            )
        return False

    def _git_info(self, root: Path, rel_root: str) -> dict[str, Any]:
        if not self.use_git:
            return {}
        marker = root / ".git"
        # Worktree gitfiles and symlinks can redirect Git outside the requested
        # checkout. Optional enrichment supports self-contained checkouts only.
        if marker.is_symlink() or (marker.exists() and not marker.is_dir()):
            self.ctx.warn("code.filesystem: git metadata must be a local .git directory; enrichment skipped")
            return {}
        if not marker.exists():
            return {}
        target = "." if rel_root == "." else rel_root
        try:
            out = subprocess.run(
                [*metadata_git_argv_prefix(), "-C", str(root), "log", "--no-show-signature", "--no-ext-diff", "--no-textconv", "-1", "--format=%an%x00%ae%x00%cI", "--", target],
                capture_output=True,
                # Author bytes follow the repository's i18n.logOutputEncoding;
                # a strict decode would abort the whole project's findings.
                encoding="utf-8",
                errors="replace",
                env=metadata_git_env(),
                timeout=20,
                check=False,
            )
            if out.returncode == 0 and out.stdout.strip():
                # NUL separators: an author name may itself contain "|".
                an, ae, ci = (out.stdout.strip("\r\n").split("\x00") + ["", "", ""])[:3]
                if parse_timestamp(ci) is None:
                    self.ctx.warn("code.filesystem: git metadata has an unparseable commit timestamp; enrichment skipped")
                    return {}
                return {"last_author": an, "last_author_email": ae, "last_commit": ci}
            if out.returncode == 0:
                return {}
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
        self.ctx.warn("code.filesystem: offline git enrichment failed; Git 2.45+ and locally available history are required")
        return {}

    def _codeowners(self, root: Path) -> list[tuple[str, list[str]]]:
        root = root.resolve()
        if root in self._codeowners_cache:
            return self._codeowners_cache[root]
        rules: list[tuple[str, list[str]]] = []
        for cand in (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS", ".gitlab/CODEOWNERS"):
            p = root / cand
            if p.exists() or p.is_symlink():
                try:
                    if not p.resolve().is_relative_to(root) or any(
                        part.is_symlink() for part in [p, *p.parents] if part != root and root in part.parents
                    ):
                        self.ctx.error(f"code.filesystem: ignored unsafe CODEOWNERS path {cand}")
                        break
                    errors: list[str] = []
                    content = read_text(p, self.max_file_size, errors)
                    for issue in errors:
                        self.ctx.error(f"code.filesystem: {cand}: {issue}")
                    for line in (content or "").splitlines():
                        line = line.split("#", 1)[0].strip()
                        if not line:
                            continue
                        parts = line.split()
                        if parts:
                            if len(rules) >= MAX_RULES or len(parts[0]) > MAX_PATTERN_LENGTH:
                                self.ctx.error("code.filesystem: CODEOWNERS rule limit exceeded; ownership incomplete")
                                rules = []
                                self._ownership_exhausted.add(root)
                                break
                            rules.append((parts[0], parts[1:]))
                except (OSError, RuntimeError):
                    self.ctx.error(f"code.filesystem: could not read {cand}")
                break
        self._codeowners_cache[root] = rules
        return rules

    def _owner_for(self, root: Path, rel_root: str) -> str | None:
        if self.owner:
            return self.owner
        root = root.resolve()
        rules = self._codeowners(root)
        if root in self._ownership_exhausted:
            return None
        key = (root, rel_root)
        if key in self._owner_cache:
            return self._owner_cache[key]
        # Preserve the per-lookup cap and limit aggregate work across many
        # unique paths. Cache hits consume no steps. Exhaustion is reported as
        # incomplete ownership rather than assigning a potentially wrong owner.
        root_remaining = self._ownership_steps_remaining.get(root, MAX_ROOT_OWNERSHIP_STEPS)
        budget = OwnershipBudget(min(MAX_OWNERSHIP_STEPS, root_remaining))
        initial = budget.remaining
        try:
            # Last matching rule wins, including ownerless exclusions. Stop at
            # that rule instead of repeatedly re-evaluating overridden rules.
            for pattern, owners in reversed(rules):
                if _codeowners_match(pattern, rel_root, budget):
                    self._owner_cache[key] = ", ".join(owners) if owners else None
                    return self._owner_cache[key]
        except OwnershipLimitError:
            self._ownership_exhausted.add(root)
            self.ctx.error("code.filesystem: CODEOWNERS processing budget exceeded; ownership incomplete")
        finally:
            remaining = max(0, root_remaining - (initial - budget.remaining))
            self._ownership_steps_remaining[root] = remaining
            if remaining == 0 and root not in self._ownership_exhausted:
                self._ownership_exhausted.add(root)
                self.ctx.error("code.filesystem: CODEOWNERS aggregate processing budget exceeded; ownership incomplete")
        self._owner_cache[key] = None
        return None

    def _owners_for_files(self, root: Path, files: Iterable[str]) -> tuple[str | None, dict[str, str]]:
        paths = sorted(set(files))
        by_file = {rel: owner for rel in paths if (owner := self._owner_for(root, rel))}
        owners = set(by_file.values())
        if len(owners) == 1 and len(by_file) == len(paths):
            return owners.pop(), by_file
        # A project finding summarizes many files. Do not name one file's owner
        # as the owner of unrelated files if CODEOWNERS has differing rules.
        return None, by_file

    # ----------------------------------------------------------------- emits
    def _base(
        self, label: str, root: Path, rel: str, kind: Kind, title: str,
        resource_type: str, *, identity_discriminator: str = "",
    ) -> Finding:
        f = Finding(
            surface=Surface.CODE,
            connector=self.name,
            kind=kind,
            title=title,
            resource=f"{label}/{rel}" if rel != "." else label,
            resource_type=resource_type,
            identity_discriminator=identity_discriminator,
            provider=self.provider_override or self.provider,
            account=self.account,
            owner=self.owner,
        )
        f.metadata.update(self.extra_metadata)
        f.metadata["path"] = rel
        f.metadata["scan_root"] = str(root)
        return f

    def _emit_project(
        self, label: str, root: Path, proj: _Project, covered_files: frozenset[str] = frozenset(),
    ) -> Iterator[Finding]:
        observations = [(m, rel, snip) for (m, rel, snip) in proj.matches if m.signature.category not in {"policy"}]
        discount_tests = not self.include_tests

        def in_tests(rel: str) -> bool:
            return discount_tests and _is_test_path(rel)

        def covered(m: Match, rel: str) -> bool:
            # Credential and artifact findings already report this evidence.
            return rel in covered_files or m.signal.type == "secret"

        # Anchors establish LLM / agent technology on their own. A credential
        # alone is already a SECRET finding, evidence that an MCP, manifest,
        # workflow or IaC finding already reports is not a project anchor, and
        # a vendor-neutral heuristic alone (a retry loop, subprocess.run)
        # describes ordinary automation.
        anchors = [t for t in observations if t[0].signature.category != "heuristic" and not covered(t[0], t[1])]
        tech_matches = observations if anchors else []
        if tech_matches:
            # Environment-variable and display-name references are weak
            # anchors, so they are judged before heuristics join: an agent
            # loop or subprocess.run next to a .env.example must not promote
            # the project to a confirmed agent with autonomous or code-exec
            # capabilities. Such a finding is built from the name references
            # alone. A live credential is not a name: it keeps full weights
            # and lets the heuristics count. Every anchor is non-heuristic,
            # so the judgement below is never vacuous.
            env_only = all(
                m.signal.type in {"env", "name"}
                for m, _, _ in tech_matches if m.signature.category != "heuristic"
            )
            if env_only:
                tech_matches = [t for t in tech_matches if t[0].signal.type in {"env", "name"}]
            library_evidence = {m.signature_id for m, _, _ in tech_matches if m.signal.type in {"import", "dependency"}}

            def verified_indicator(match: Match) -> bool:
                if match.signature.category == "heuristic" or match.signature_id == "protocol.mcp":
                    return False
                if "verified_agent" in match.extra:
                    return bool(match.extra["verified_agent"])
                if match.extra.get("lexical_source") and match.signature.category == "framework":
                    return match.agent_indicator and match.signature_id in library_evidence
                return match.agent_indicator

            f = self._base(label, root, proj.root, Kind.FRAMEWORK_USAGE, "", "project")
            uncorroborated = {m.signature_id for m, _, _ in tech_matches
                              if m.extra.get("lexical_source") and m.signature.category == "framework"
                              and m.signature_id not in library_evidence}
            # Decisive evidence must survive the per-signature report quota.
            for m, rel, snip in sorted(tech_matches, key=lambda item: not verified_indicator(item[0])):
                if m.extra.get("lexical_source") and m.signature.category == "framework" and m.signature_id not in library_evidence:
                    m.weight = min(m.weight, 0.6)
                apply_matches(f, [m], location=rel, snippet=snip, weight_scale=(ENV_ONLY_WEIGHT_SCALE if env_only else 1.0) * (0.5 if in_tests(rel) else 1.0))
            # Repeated observations of one technology are correlated evidence.
            # Generic idioms share a single supporting group; loops in several
            # worker files must never accumulate into a confirmed AI agent.
            for evidence in f.evidence:
                category = evidence.attributes.get("category")
                evidence.attributes["confidence_group"] = (
                    "heuristic-support" if category == "heuristic" else
                    "uncorroborated-lexical" if evidence.signature in uncorroborated else
                    evidence.signature or evidence.signal
                )
            if env_only:
                f.add_tag("env-names-only")
            self._attach_example_credentials(f, proj)
            git = self._git_info(root, proj.root)
            f.metadata.update(git)
            if git.get("last_commit"):
                f.last_seen = git["last_commit"]
            f.owner, by_file = self._owners_for_files(root, (rel for _, rel, _ in tech_matches))
            f.owner = f.owner or (git.get("last_author_email") if not by_file else None) or self.owner
            if by_file:
                f.metadata["codeowners_by_file"] = by_file
            f.metadata["files_scanned"] = proj.files
            f.metadata["languages"] = sorted(proj.languages)
            f.metadata["dependencies_matched"] = sorted({f"{m.signal.ecosystem or 'any'}:{m.value}" for m, _, _ in tech_matches if m.signal.type == "dependency"})
            f.metadata["models"] = sorted({m.value for m, _, _ in tech_matches if m.signal.type == "model"})
            f.models = f.metadata["models"]
            if proj.agent_defs:
                f.metadata["agent_definitions"] = proj.agent_defs
            # Installed SDKs, imports and endpoint strings establish framework
            # use. MCP code/config alone establishes a tool server/client, not
            # an agent capable of choosing actions or planning.
            f.metadata["agent_indicators"] = sum(
                verified_indicator(m) and m.signal.type in {"code", "file"} and not in_tests(rel)
                for m, rel, _ in tech_matches
            )
            if discount_tests and all(_is_test_path(rel) for _, rel, _ in tech_matches):
                f.add_tag("test-code-only")
            finalize(f, self.index)
            if env_only:
                cap_confidence(f, ENV_ONLY_MAX_CONFIDENCE)
                f.metadata["confidence_cap"] = {"reason": "env-names-only", "maximum": ENV_ONLY_MAX_CONFIDENCE}
            f.title = self._project_title(f, proj)
            yield f
        for sig_id, files in proj.coding_agent_files.items():
            sig = self.index.get(sig_id)
            f = self._base(
                label, root, proj.root, Kind.AGENT_CONFIG,
                f"{sig.name if sig else sig_id} configured in {proj.root if proj.root != '.' else 'repository root'}",
                "coding-agent-config", identity_discriminator=f"coding-agent-config:{sig_id}",
            )
            for m, rel, snip in proj.coding_agent_matches.get(sig_id, []):
                apply_matches(f, [m], location=rel, snippet=snip)
            f.metadata["files"] = sorted(files)
            defs = [d for d in proj.agent_defs if any(d["file"] == x for x in files)]
            if defs:
                f.metadata["agent_definitions"] = defs
                f.add_capability("multi-agent")
            f.kind = Kind.AGENT_CONFIG
            f.owner, by_file = self._owners_for_files(root, files)
            f.owner = f.owner or self.owner
            if by_file:
                f.metadata["codeowners_by_file"] = by_file
            finalize(f, self.index)
            f.kind = Kind.AGENT_CONFIG
            yield f

    @staticmethod
    def _attach_example_credentials(f: Finding, proj: _Project) -> None:
        """Attach placeholder credentials as informational evidence (see module docstring)."""
        if not proj.example_credentials:
            return
        f.add_tag("example-credential")
        files: list[str] = []
        for i, (m, rel, reason) in enumerate(proj.example_credentials):
            if rel not in files:
                files.append(rel)
            if i >= MAX_EXAMPLE_CREDENTIAL_EVIDENCE:
                continue
            what = m.signal.description or m.signature.name
            f.add_evidence(
                Evidence(
                    signal=f"example-credential:{m.signature_id}",
                    description=f"placeholder {what} ({reason}) in {rel}: {redact(m.value)}",
                    location=f"{rel}:{m.line}" if m.line else rel,
                    weight=EXAMPLE_CREDENTIAL_WEIGHT,
                    signature=m.signature_id,
                    attributes={"category": m.signature.category, "value": redact(m.value), "placeholder": reason},
                )
            )
        # The key name must not read as a credential field, or the report
        # sanitizer withholds the file list itself.
        f.metadata["placeholder_samples"] = {"count": len(proj.example_credentials), "files": sorted(files)[:MAX_EXAMPLE_CREDENTIAL_EVIDENCE]}

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

    def _mcp_finding(self, label: str, root: Path, rel: str, servers: list[dict[str, Any]]) -> Finding:
        enabled = [server for server in servers if not server["disabled"]]
        f = self._base(label, root, rel, Kind.MCP_SERVER, f"MCP configuration: {rel}", "mcp-config")
        sig = self.index.get("protocol.mcp")
        f.add_framework("protocol.mcp")
        f.add_capability("tool-use")
        f.add_evidence(Evidence(signal="file:protocol.mcp", description=f"MCP client/server configuration file {rel}", location=rel, weight=0.95, signature="protocol.mcp"))
        remote_hosts: list[str] = []
        for s in enabled:
            if s.get("url"):
                for m in self.index.match_domains_in_text(s["url"]):
                    if m.signature.category != "identity-app":
                        apply_matches(f, [m], location=rel)
                remote_hosts.append(s["url"])
            for env_name in s.get("env_names", []):
                for m in self.index.match_env(env_name):
                    apply_matches(f, [m], location=rel, weight_scale=0.5)
            if s.get("secrets_inline"):
                f.add_tag("inline-secrets")
                f.add_evidence(Evidence(signal="secret:inline", description=f"MCP server '{s['name']}' has credential-looking values inline ({', '.join(s.get('secret_locations') or ['configuration'])})", location=rel, weight=0.3))
            cmd = " ".join([str(s.get("command") or "")] + [str(a) for a in s.get("args", [])]).lower()
            for capability, keywords in _MCP_CAPABILITY_KEYWORDS:
                if any(k in cmd for k in keywords):
                    f.add_capability(capability)
                    break
        f.metadata["servers"] = enabled
        f.metadata["server_count"] = len(enabled)
        f.metadata["disabled_server_count"] = len(servers) - len(enabled)
        f.metadata["remote_urls"] = remote_hosts
        f.metadata["client"] = _mcp_client_for(rel)
        f.owner = self._owner_for(root, rel) or f.owner
        finalize(f, self.index)
        f.kind = Kind.MCP_SERVER
        if sig:
            f.metadata["risk_notes"] = sig.risk_notes
        return f

    def _card_finding(self, label: str, root: Path, rel: str, text: str, kind: str) -> Finding | None:
        validation = parse_agent_manifest(rel, text, kind)
        if not validation.valid:
            for issue in validation.errors:
                self.ctx.error(f"code.filesystem: {rel}: {issue}")
            return None
        data = validation.data
        # Retain sibling credential context before projecting descriptive fields.
        # An opaque secret may also appear in a description, URL or dependency.
        data = sanitize(data)
        f = self._base(label, root, rel, Kind.AGENT, "", "agent-manifest")
        if kind == "a2a":
            f.title = f"A2A agent card: {data.get('name') or rel}"
            f.add_framework("protocol.a2a")
            f.add_capability("multi-agent")
            f.add_evidence(Evidence(signal="file:protocol.a2a", description="A2A Agent Card", location=rel, weight=0.95, signature="protocol.a2a"))
            f.metadata["agent_card"] = {
                "name": data.get("name"),
                "description": truncate(sanitize_text(str(data.get("description", ""))), 300),
                "url": data.get("url"),
                "version": data.get("version"),
                "protocol_version": data.get("protocolVersion"),
                "skills": [s.get("name") or s.get("id") for s in data.get("skills", []) or [] if isinstance(s, dict)],
                "capabilities": _clip(data.get("capabilities")),
                "security_schemes": _clip(list((data.get("securitySchemes") or {}).keys()) if isinstance(data.get("securitySchemes"), dict) else data.get("authentication")),
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
                "description": truncate(sanitize_text(str(data.get("description", ""))), 300),
                "instructions": truncate(sanitize_text(str(data.get("instructions", ""))), 300),
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
            f.metadata["graphs"] = _clip(list(graphs.keys()) if isinstance(graphs, dict) else graphs)
            f.metadata["dependencies"] = _clip(data.get("dependencies"))
            env = data.get("env")
            f.metadata["env_names"] = sorted(env) if isinstance(env, dict) else []
            if isinstance(env, str):
                f.metadata["env_file"] = sanitize_text(env)
            f.add_capability("tool-use")
        elif kind == "crewai":
            f.title = f"CrewAI agent definitions: {rel}"
            f.add_framework("framework.crewai")
            f.add_capability("multi-agent")
            f.add_evidence(Evidence(signal="file:framework.crewai", description="CrewAI agents.yaml", location=rel, weight=0.9, signature="framework.crewai"))
            f.metadata["agents"] = [
                {"name": k, "role": truncate(sanitize_text(str((v or {}).get("role", ""))), 120), "llm": (v or {}).get("llm")} for k, v in data.items() if isinstance(v, dict)
            ]
            for v in data.values():
                if isinstance(v, dict) and v.get("llm"):
                    apply_matches(f, self.index.match_model(str(v["llm"]).split("/")[-1]), location=rel, weight_scale=0.6)
        f.owner = self._owner_for(root, rel) or f.owner
        finalize(f, self.index)
        f.kind = Kind.AGENT
        return f

    def _workflow_finding(self, label: str, root: Path, rel: str, hits: list[tuple[Match, str]]) -> Finding:
        f = self._base(label, root, rel, Kind.WORKFLOW, "", "workflow-export")
        for m, snip in hits:
            apply_matches(f, [m], location=rel, snippet=snip)
        names = {self.index.get(m.signature_id).name for m, _ in hits if m.signature.category != "provider" and self.index.get(m.signature_id)}  # type: ignore[union-attr]
        f.title = f"Exported AI workflow ({', '.join(sorted(names))}): {rel}"
        f.owner = self._owner_for(root, rel) or f.owner
        finalize(f, self.index)
        f.kind = Kind.WORKFLOW
        return f

    def _infra_finding(
        self, label: str, root: Path, rel: str, hits: list[tuple[Match, str, str]], names_found: list[str] | None = None,
        *, wildcards: list[tuple[str, int, str]] | None = None, models: list[Match] | None = None,
    ) -> Finding:
        f = self._base(label, root, rel, Kind.INFRA, "", "iac")
        for m, value, snip in hits:
            apply_matches(f, [m], location=rel, snippet=snip)
        for m in models or []:
            apply_matches(f, [m], location=rel)
            if m.value not in f.models:
                f.models.append(m.value)
        for source, line, snip in (wildcards or [])[:5]:
            f.add_tag("wildcard-permissions")
            f.add_evidence(Evidence(
                signal="iac:iam-wildcard", description="IAM statement in the same project grants wildcard actions",
                location=f"{source}:{line}", snippet=snip, weight=0.5,
            ))
        names = {self.index.get(m.signature_id).name for m, _, _ in hits if self.index.get(m.signature_id)}  # type: ignore[union-attr]
        resources = sorted({v for _, v, _ in hits})
        f.title = f"Infrastructure provisions {', '.join(sorted(names))}: {rel}"
        f.metadata["resources"] = resources
        if names_found:
            f.metadata["names"] = names_found
        f.owner = self._owner_for(root, rel) or f.owner
        finalize(f, self.index)
        f.kind = Kind.INFRA
        return f

    def _secret_finding(self, label: str, root: Path, rel: str, hits: list[tuple[Match, str]]) -> Finding | None:
        # A structured value (e.g. a .env assignment) and the raw text pass can
        # both observe the same credential on the same line; count it once.
        # Placeholders are filtered again here so every caller shares the rule.
        unique: dict[tuple[str, str, int | None], tuple[Match, str]] = {}
        for m, snip in hits:
            if not looks_like_placeholder(m.value):
                unique.setdefault((m.signature_id, m.value, m.line), (m, snip))
        hits = list(unique.values())
        if not hits:
            return None
        f = self._base(label, root, rel, Kind.SECRET, f"LLM provider credential in {rel}", "file")
        for m, snip in hits:
            apply_matches(f, [m], location=rel, snippet=snip)
        f.add_tag("hardcoded-credential")
        f.metadata["providers"] = sorted({m.signature_id for m, _ in hits})
        f.metadata["count"] = len(hits)
        f.owner = self._owner_for(root, rel) or f.owner
        finalize(f, self.index)
        f.kind = Kind.SECRET
        return f

    def _parse_agent_definition(self, rel: str, text: str) -> dict[str, Any]:
        info: dict[str, Any] = {"file": rel, "name": PurePosixPath(rel).stem}
        m = _FRONTMATTER.match(text)
        if m:
            try:
                fm = bounded_safe_load(m.group(1)) or {}
            except yaml.YAMLError:
                self.ctx.error(f"code.filesystem: {rel}: invalid agent definition YAML")
                fm = {}
            if isinstance(fm, dict):
                fm = sanitize(fm)
                for k in ("name", "description", "tools", "model", "permissionMode", "mode", "globs", "alwaysApply"):
                    if k in fm:
                        v = fm[k]
                        info[k] = truncate(sanitize_text(v), 200) if isinstance(v, str) else _clip(sanitize(v))
        return info


_MAX_CARD_FILES = 200
_MAX_AGENT_DEFINITIONS = 50
_CLIP_ITEMS = 50
_CLIP_CHARS = 200


def _clip(value: Any, depth: int = 0) -> Any:
    """Bound a projected metadata value so aggregates stay within the sanitizer budget."""
    if isinstance(value, str):
        return truncate(value, _CLIP_CHARS)
    if depth >= 4:
        return None if isinstance(value, (dict, list, tuple)) else value
    if isinstance(value, dict):
        return {str(k)[:_CLIP_CHARS]: _clip(v, depth + 1) for k, v in list(value.items())[:_CLIP_ITEMS]}
    if isinstance(value, (list, tuple)):
        return [_clip(v, depth + 1) for v in value[:_CLIP_ITEMS]]
    return value


def _excerpt(lines: list[str], line: int, secret: str | None = None, width: int = 160) -> str:
    """Return one trimmed source line; a matched credential is redacted before truncation.

    Truncating first can leave a recognisable prefix of a long credential in
    the snippet when the full value no longer appears in the shortened text.
    """
    try:
        text = lines[line - 1]
    except IndexError:
        return ""
    text = text.strip()
    if secret:
        text = text.replace(secret, redact(secret))
    return text if len(text) <= width else text[: width - 1] + "…"


def _load_json_lenient(text: str) -> Any:
    """Parse JSON, tolerating JSONC comments and trailing commas only when needed.

    Stripping comments is a pure-Python character loop; ordinary JSON must not
    pay for it on every file.
    """
    try:
        return json.loads(text)
    except ValueError:
        return json.loads(_strip_json_comments(text))


def _nearest_root(rel_dir: str, roots: list[str]) -> str:
    """Discard completed branches from the active root stack during the walk."""
    while len(roots) > 1 and rel_dir != roots[-1] and not rel_dir.startswith(roots[-1] + "/"):
        roots.pop()
    return roots[-1]


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


def _without_xml_comments(text: str) -> str:
    """Mask XML comments while preserving character offsets and source lines."""
    return re.sub(r"<!--.*?(?:-->|$)", lambda match: re.sub(r"[^\n]", " ", match.group()), text, flags=re.S)


_NO_STRUCTURE = object()


def _structured_context(rel: str, text: str) -> Any:
    """Parse the structure that supplies credential context for excerpt redaction.

    Returns ``_NO_STRUCTURE`` for plain text and for structured files whose
    syntax or shape the dedicated parser rejects; lexical redaction then
    applies. Resource-limit failures propagate: they must reach the per-file
    isolation boundary even when nothing is excerpted, since lexical fallback
    would otherwise disguise an incomplete analysis.
    """
    try:
        if rel.endswith(_JSON_SUFFIXES):
            return _load_json_lenient(text)
        if rel.endswith(".toml"):
            return tomllib.loads(text)
        if rel.endswith(_YAML_SUFFIXES):
            return bounded_safe_load(text)
    except (YAMLResourceLimitError, SanitizationLimitError):
        raise
    except (ValueError, RecursionError, yaml.YAMLError):
        return _NO_STRUCTURE
    return _NO_STRUCTURE


def _redacted_source(text: str, structure: Any) -> str:
    """Redact ``text`` with the structured context from ``_structured_context``, keeping line positions.

    An opaque argv value is identifiable only alongside its flag, and environment
    values must not reappear in source snippets after being removed from metadata.
    """
    if structure is _NO_STRUCTURE:
        return sanitize_text(text)
    try:
        return sanitize((structure, text))[1]
    except (YAMLResourceLimitError, SanitizationLimitError):
        raise
    except (ValueError, RecursionError, yaml.YAMLError):
        return sanitize_text(text)


def _safe_source_text(rel: str, text: str) -> str:
    """Use structured credential context while retaining source line positions."""
    return _redacted_source(text, _structured_context(rel, text))


def _parse_mcp_servers(rel: str, text: str, errors: list[str] | None = None) -> list[dict[str, Any]]:
    errors = errors if errors is not None else []
    try:
        if rel.endswith(".toml"):
            data = tomllib.loads(text)
        elif rel.endswith((".yaml", ".yml")):
            data = bounded_safe_load(text)
        else:
            data = _load_json_lenient(text)
    except (ValueError, RecursionError, yaml.YAMLError):
        errors.append("invalid MCP configuration syntax")
        return []
    if not isinstance(data, dict):
        errors.append("MCP configuration must be an object")
        return []
    mcp = data.get("mcp", {})
    if not isinstance(mcp, dict):
        errors.append("MCP mcp field must be an object")
        mcp = {}
    servers: Any = next((value for value in (
        data.get("mcp_servers"), data.get("mcpServers"), mcp.get("servers"), data.get("servers"),
    ) if value is not None), {})
    if isinstance(servers, list):
        if any(not isinstance(server, dict) for server in servers):
            errors.append("MCP server entries must be objects")
        servers = {str(server.get("name", i)): server for i, server in enumerate(servers) if isinstance(server, dict)}
    if not servers and isinstance(data.get("name"), str) and (data.get("packages") or data.get("remotes")):
        servers = {data["name"]: data}
    if not isinstance(servers, dict):
        errors.append("MCP servers must be an object or array")
        return []
    out: list[dict[str, Any]] = []
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            errors.append("MCP server entry must be an object")
            continue
        env = cfg.get("env", cfg.get("environment", {}))
        headers = cfg.get("headers", {})
        env = {} if env is None else env
        headers = {} if headers is None else headers
        if not isinstance(env, dict):
            errors.append("MCP env must be an object")
            env = {}
        if not isinstance(headers, dict):
            errors.append("MCP headers must be an object")
            headers = {}
        url = cfg.get("url") or cfg.get("serverUrl") or cfg.get("endpoint")
        remotes = cfg.get("remotes")
        if not url and isinstance(remotes, list) and remotes:
            if isinstance(remotes[0], dict):
                url = remotes[0].get("url")
            else:
                errors.append("MCP remote entry must be an object")
        if url is not None and not isinstance(url, str):
            errors.append("MCP url must be a string")
            url = None
        command = cfg.get("command")
        if command is not None and not isinstance(command, str):
            errors.append("MCP command must be a string")
            command = None
        packages = cfg.get("packages")
        valid_package = isinstance(packages, list) and any(
            isinstance(package, dict)
            and isinstance(package.get("registryType"), str)
            and isinstance(package.get("identifier"), str)
            and package["identifier"].strip()
            for package in packages
        )
        if not (command and command.strip()) and not (url and url.strip()) and not valid_package:
            if cfg.get("disabled") is not True and cfg.get("enabled") is not False:
                errors.append("MCP server entry has no command, URL, or valid package")
            continue
        args = cfg.get("args", [])
        args = [] if args is None else args
        if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
            errors.append("MCP args must be an array of strings")
            args = []
        inline_locations = [
            location for location, items in (("env", env.items()), ("headers", headers.items()))
            if any(
                isinstance(value, str) and value and not value.startswith("${")
                and not looks_like_placeholder(value) and _SECRETISH.search(str(key)) and len(value) >= 12
                for key, value in items
            )
        ]
        transport = cfg.get("type") or cfg.get("transport") or ("stdio" if command else ("http" if url else "unknown"))
        if not isinstance(transport, str):
            errors.append("MCP transport must be a string")
            transport = "unknown"
        # Project only after sanitizing with the entire config: a credential in
        # env/headers may be repeated as an otherwise unrecognizable argument.
        field_names = ("name", "transport", "command", "args", "url", "env_names", "headers", "auto_approve")
        clean_values = sanitize((cfg, [
            str(name), transport, command, args, url,
            sorted(str(key) for key in env), sorted(str(key) for key in headers),
            cfg.get("autoApprove") or cfg.get("alwaysAllow"),
        ]))[1]
        safe = dict(zip(field_names, clean_values, strict=True))
        inline_locations += [
            location for location, changed in (
                ("args", safe["args"] != args), ("url", safe["url"] != url), ("command", safe["command"] != command),
            ) if changed
        ]
        inline = bool(inline_locations)
        safe["args"] = safe["args"][:12]
        safe["secrets_inline"] = bool(inline)
        if inline_locations:
            safe["secret_locations"] = inline_locations
        disabled = cfg.get("disabled", False)
        enabled = cfg.get("enabled", True)
        if not isinstance(disabled, bool) or not isinstance(enabled, bool):
            errors.append("MCP enabled/disabled flags must be booleans")
            # Unknown activation state cannot substantiate an active server.
            safe["disabled"] = True
        else:
            safe["disabled"] = disabled or not enabled
        out.append(safe)
    # Each output key is generated by this parser. Preserve its schema while
    # sanitizing all values in the context of the entire source document.
    names = [tuple(server) for server in out]
    cleaned = sanitize((data, [[server[key] for key in keys] for server, keys in zip(out, names, strict=True)]))[1]
    return [dict(zip(keys, values, strict=True)) for keys, values in zip(names, cleaned, strict=True)]


def _strip_json_comments(text: str) -> str:
    """Tolerate JSONC comments and trailing commas without rewriting strings."""
    out: list[str] = []
    i = 0
    in_string = False
    while i < len(text):
        char = text[i]
        if in_string:
            out.append(char)
            if char == "\\" and i + 1 < len(text):
                i += 1
                out.append(text[i])
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
            out.append(char)
        elif text.startswith("//", i):
            end = text.find("\n", i + 2)
            i = len(text) if end == -1 else end
            out.append("\n")
            continue
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end == -1:
                raise ValueError("unterminated JSON comment")
            out.append(" " + "\n" * text.count("\n", i, end + 2))
            i = end + 2
            continue
        else:
            out.append(char)
        i += 1
    stripped = "".join(out)
    out = []
    in_string = False
    i = 0
    while i < len(stripped):
        char = stripped[i]
        if in_string:
            out.append(char)
            if char == "\\" and i + 1 < len(stripped):
                i += 1
                out.append(stripped[i])
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
            out.append(char)
        elif char == ",":
            end = i + 1
            while end < len(stripped) and stripped[end].isspace():
                end += 1
            if end == len(stripped) or stripped[end] not in "}]":
                out.append(char)
        else:
            out.append(char)
        i += 1
    return "".join(out)
