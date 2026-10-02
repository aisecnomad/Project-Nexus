"""Scan a local directory tree (a checked-out repository, a monorepo, a laptop).

Produces:

* one ``agent`` / ``framework-usage`` finding per project (nearest manifest
  root) summarising frameworks, model providers, capabilities and evidence;
* one ``mcp-server`` finding per MCP client/server configuration file;
* one ``agent-config`` finding per coding-agent product per project
  (Claude Code, Copilot, Cursor, Codex... including sub-agent definitions);
* one ``agent`` finding per A2A agent card / declarative agent manifest;
* one ``workflow`` finding per exported low-code flow (n8n, Flowise, Langflow,
  Dify, Make, Power Automate, Logic Apps);
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
import os
import re
import stat
import subprocess
import time
import tomllib
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath
from typing import Any, ClassVar

import yaml

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.connectors.code.import_provenance import local_module_conflict
from shadowscan.connectors.code.java_semantics import spring_tool_registration_matches
from shadowscan.connectors.code.manifests import Artifact, Dep, is_manifest_name, parse_manifest
from shadowscan.connectors.code.mcp_tools import mcp_tool_capabilities, mcp_tool_names
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
    has_template_markers,
    is_agent_config_path,
    parse_agent_manifest,
    structured_code_matches,
)
from shadowscan.connectors.code.source_ranges import noncode_ranges
from shadowscan.connectors.code.source_semantics import SourceBudgetExceeded, bound_source_matches
from shadowscan.connectors.common import (
    apply_matches,
    cap_confidence,
    config_boolean,
    finalize,
    looks_like_placeholder,
    placeholder_reason,
)
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.signatures import Match
from shadowscan.signatures.matcher import SOURCE_EXTENSIONS, MatchTimeoutError, language_for_path
from shadowscan.utils.files import open_confined_directory, open_confined_file, read_policy_text
from shadowscan.utils.git import (
    MAX_GITMODULES_BYTES,
    declared_submodule_paths,
    metadata_git_argv_prefix,
    metadata_git_env,
    read_gitlink_paths,
)
from shadowscan.utils.jsonc import load_json_lenient as _load_json_lenient
from shadowscan.utils.jsonc import strip_json_comments as _strip_json_comments  # noqa: F401 - historical name
from shadowscan.utils.redaction import REDACTED, SanitizationLimitError, sanitize, sanitize_text
from shadowscan.utils.safe_json import JSONIntegrityError
from shadowscan.utils.safe_yaml import (
    YAMLIntegrityError,
    YAMLResourceLimitError,
    strict_bounded_safe_load,
)
from shadowscan.utils.text import notebook_to_source, parse_timestamp, read_text, redact, truncate

# Manifests that configure the code of the project containing them. A2A cards
# and M365 declarative agents declare a separately addressable agent (its own
# name, endpoint and authentication) and stay findings of their own.
_PROJECT_MANIFESTS = frozenset({"crewai", "langgraph"})

# Registered MCP tool names retained per project.
_MAX_MCP_TOOLS = 200

# Signal types that establish a library in a project (see _emit_project).
_LIBRARY_SIGNALS = frozenset({"import", "dependency", "code"})
# Signals that name a product without configuring it.
_MENTION_SIGNALS = frozenset({"env", "name"})

# Saved outputs (plots, tables, logs) routinely push small notebooks past
# max_file_size. Their code cells are still analyzed up to this size.
DEFAULT_MAX_NOTEBOOK_SIZE = 20 * 1024 * 1024

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

# A file over max_file_size that the scanner would read leaves coverage
# incomplete: unread content could hide agent configuration. Names matching
# these globs hold generated, locked or binary content that is explicitly
# outside the scan scope, so skipping them is a warning and the scan stays
# complete. The connector's `oversize_skip_globs` replaces the list.
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
# fails fast. The final 64 KiB of the first band receives the next budget
# early; this avoids a sharp, scheduler-sensitive timeout cliff for the
# mid-sized source files most likely to sit just below the first boundary.
# A 971 KB JSON index still gets four default budgets (8 s).
SCAN_TIMEOUT_STEP_BYTES = 256 * 1024
SCAN_TIMEOUT_BAND_HEADROOM_BYTES = 64 * 1024
SCAN_TIMEOUT_CAP_SECONDS = 10.0
# Stop the walk this far before the connector deadline so the findings
# collected so far are emitted, sanitized and accepted by the engine, which
# discards a result that arrives after the deadline.
DEADLINE_MARGIN_FRACTION = 0.05
DEADLINE_MARGIN_MIN_SECONDS = 0.25

# Generated or locked files the walker never reads at any size.
_NEVER_READ_SUFFIXES = (".min.js", ".min.css", ".map", ".pyc", ".lock")


def _never_read_by_name(name: str) -> bool:
    """Whether the walker skips ``name`` silently because it never carries evidence."""
    return name in LOCK_FILES or name.endswith(_NEVER_READ_SUFFIXES)


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

# `setup.py` is also an ordinary module name (a package's `tracing/setup.py`,
# a web app's `controllers/setup.py`). It marks a project only when it builds
# a package; anything that cannot be read keeps the historical marker.
_SETUP_SCRIPT_MAX_BYTES = 256 * 1024
_PACKAGING_SETUP = re.compile(rb"\b(?:setuptools|distutils|skbuild)\b|(?<!def )(?<![.\w])setup\s*\(")


def _packaging_setup_script(path: Path) -> bool:
    try:
        with open_confined_file(path, label="setup.py") as (stream, _):
            head = stream.read(_SETUP_SCRIPT_MAX_BYTES)
    except (OSError, ValueError):
        return True
    return _PACKAGING_SETUP.search(head) is not None


def _marks_project(directory: Path, names: Iterable[str]) -> bool:
    """True when ``names`` in ``directory`` include a project manifest."""
    return any(
        name in PROJECT_ROOT_MARKERS and (name != "setup.py" or _packaging_setup_script(directory / name))
        for name in names
    )


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


def _analyzed_by_name(name: str) -> bool:
    """Whether the name alone makes a file source or configuration that the walker reads."""
    ext = Path(name).suffix.lower()
    return (
        ext in SOURCE_EXTENSIONS
        or ext in TEXT_CONFIG_EXTENSIONS
        or name.lower().startswith(".env")
        or is_manifest_name(name)
        or "." not in name
    )


# Files that may be manifests whatever their name: IaC, compose, CI and deployment templates.
_MANIFEST_EXTENSIONS = frozenset({".tf", ".bicep", ".yml", ".yaml", ".json", ".hcl"})
# XML-based files whose comments are masked before content matching.
_XML_EXTENSIONS = frozenset({".xml", ".props", ".targets", ".csproj", ".fsproj", ".vbproj"})
# Structured files whose platform matches can describe an exported workflow.
_WORKFLOW_EXTENSIONS = frozenset({".json", ".yaml", ".yml"})
# Coding-agent sub-agent and rule definitions (Markdown with YAML front matter).
_AGENT_DEFINITION_DIRS = (".claude/agents/", ".github/agents/", ".cursor/rules/", ".windsurf/rules/")

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
    mcp_tools: dict[str, str] = field(default_factory=dict)  # registered MCP tool name -> relpath


@dataclass
class _ScanState:
    """What one ``scan_tree`` walk collects for its emit phase."""

    root: Path
    label: str  # resource prefix of every finding
    # Descriptor of the directory files are read relative to, open during the walk.
    root_fd: int = -1
    projects: dict[str, _Project] = field(default_factory=lambda: {".": _Project(".")})
    secret_hits: dict[str, list[tuple[Match, str]]] = field(default_factory=dict)  # relpath -> matches
    # relpath, parsed servers
    mcp_files: list[tuple[str, list[dict[str, Any]]]] = field(default_factory=list)
    # relpath, text, kind, project root
    card_files: list[tuple[str, str, str, str]] = field(default_factory=list)
    workflow_files: dict[str, list[tuple[Match, str]]] = field(default_factory=dict)
    # relpath -> model nodes in exported workflows
    workflow_providers: dict[str, list[tuple[Match, str]]] = field(default_factory=dict)
    # relpath -> (match, value, snippet)
    infra_files: dict[str, list[tuple[Match, str, str]]] = field(default_factory=dict)
    infra_names: dict[str, list[str]] = field(default_factory=dict)  # relpath -> display / resource names
    infra_project: dict[str, str] = field(default_factory=dict)  # relpath -> project root
    infra_models: dict[str, list[Match]] = field(default_factory=dict)  # relpath -> model ids declared in IaC
    # project root -> (relpath, line, excerpt)
    iam_wildcards: dict[str, list[tuple[str, int, str]]] = field(default_factory=dict)

    def covered_files(self) -> frozenset[str]:
        """Files whose own MCP, manifest, workflow or IaC finding reports their evidence."""
        return frozenset(
            {rel for rel, _ in self.mcp_files}
            | {rel for rel, _, _, _ in self.card_files}
            | set(self.workflow_files)
            | set(self.infra_files)
        )


@dataclass
class _SourceFile:
    """One file under analysis and the state its analysis passes share."""

    rel: str
    path: Path
    proj_root: str
    proj: _Project
    text: str  # analyzed text; a notebook's code cells
    lang: str | None
    file_matches: list[Match]
    raw_notebook: str | None = None  # a notebook's raw document, scanned for credentials
    # Credential context for excerpt redaction (see _structured_context).
    # None withholds every excerpt of the file.
    structure: Any = None
    safe_lines: list[str] | None = None  # redacted lines, produced when an excerpt first needs them
    card_kind: str | None = None  # agent manifest kind suggested by the path
    card_valid: bool = False
    is_mcp: bool = False
    mcp_servers: list[dict[str, Any]] = field(default_factory=list)
    mcp_active: bool = False  # at least one configured MCP server is enabled

    @property
    def name(self) -> str:
        return self.path.name

    @property
    def ext(self) -> str:
        return self.path.suffix.lower()


_Observation = tuple[Match, str, str | None]  # match, relpath, snippet


class _ProjectEvidence:
    """How a project's observations count toward its finding (see the module docstring)."""

    def __init__(
        self,
        observations: list[_Observation],
        *,
        discount_tests: bool,
        mcp_tools: dict[str, str],
    ) -> None:
        self.discount_tests = discount_tests
        # Environment-variable and display-name references are weak
        # anchors, so they are judged before heuristics join: an agent
        # loop or subprocess.run next to a .env.example must not promote
        # the project to a confirmed agent with autonomous or code-exec
        # capabilities. Such a finding is built from the name references
        # alone. A live credential is not a name: it keeps full weights
        # and lets the heuristics count. Every anchor is non-heuristic,
        # so the judgement below is never vacuous.
        self.env_only = all(
            m.signal.type in {"env", "name"}
            for m, _, _ in observations
            if m.signature.category != "heuristic"
        )
        self.matches = (
            [t for t in observations if t[0].signal.type in {"env", "name"}]
            if self.env_only
            else observations
        )
        self.library_evidence = {
            m.signature_id for m, _, _ in self.matches if m.signal.type in {"import", "dependency"}
        }
        self.uncorroborated = {
            m.signature_id
            for m, _, _ in self.matches
            if m.extra.get("lexical_source")
            and m.signature.category != "heuristic"
            and m.signature_id not in self.library_evidence
        }
        # Capabilities describe what the deployed code can do. Evidence
        # from tests (unless the project is only tests) and vendor-neutral
        # idioms in an MCP tool server (whose tools are read below) is
        # kept as evidence but implies no capability.
        self.test_only = discount_tests and all(_is_test_path(rel) for _, rel, _ in self.matches)
        java_tool_types = {
            m.extra["java_tool_type"]
            for m, rel, _ in self.matches
            if m.extra.get("java_tool_type") and (self.test_only or not self.in_tests(rel))
        }
        for m, _, _ in self.matches:
            if m.extra.get("java_tool_registration_type"):
                verified = m.extra["java_tool_registration_type"] in java_tool_types
                m.extra["verified_agent"] = verified
                m.extra["source_capabilities"] = ["tool-use"] if verified else []
        # Tools registered only in tests imply nothing, like other test evidence.
        self.server_tools = {
            tool: rel for tool, rel in mcp_tools.items() if self.test_only or not self.in_tests(rel)
        }
        # A tool server's capabilities come from its tools. When none were
        # recognised, its other evidence still implies what the code can do.
        self.mcp_server = bool(self.server_tools) and {
            m.signature_id for m, _, _ in self.matches if m.signature.category != "heuristic"
        } == {"protocol.mcp"}

    def in_tests(self, rel: str) -> bool:
        return self.discount_tests and _is_test_path(rel)

    def verified_indicator(self, match: Match) -> bool:
        if match.signature.category == "heuristic" or match.signature_id == "protocol.mcp":
            return False
        if "verified_agent" in match.extra:
            return bool(match.extra["verified_agent"])
        if match.extra.get("lexical_source"):
            return match.agent_indicator and match.signature_id in self.library_evidence
        return match.agent_indicator

    def implies_capabilities(self, match: Match, rel: str) -> bool:
        if match.signal.type in {"import", "dependency", "env", "name"}:
            return False
        if self.in_tests(rel) and not self.test_only:
            return False
        if (
            match.signature.category == "framework"
            and match.extra.get("lexical_source")
            and match.signature_id not in self.library_evidence
        ):
            return False
        return not (self.mcp_server and match.signature.category == "heuristic")

    def weight_scale(self, rel: str) -> float:
        return (ENV_ONLY_WEIGHT_SCALE if self.env_only else 1.0) * (0.5 if self.in_tests(rel) else 1.0)


_ROOT_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}\Z")

# Test suites routinely construct agents to exercise a library. Evidence found
# only there describes the library's tests, not a deployed agent, so it cannot
# establish an agent on its own unless ``include_tests`` is set.
_TEST_DIR_NAMES = frozenset(
    {
        "test",
        "tests",
        "__tests__",
        "spec",
        "specs",
        "testing",
        "fixtures",
        "__fixtures__",
        "__mocks__",
        "cassettes",
        "testdata",
        "test_data",
        "test-data",
        "e2e",
    }
)
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
    r"""(?i)["']?\bActions?["']?\s*[:=]\s*\[?\s*["']\*["']"""
    r"""|["'](?:bedrock|iam|sts|lambda|s3|secretsmanager|kms):\*["']"""
)
_IAC_MODEL_RE = re.compile(
    r"""(?i)\b(?:foundation_?model(?:_?(?:id|arn))?|model_?id|model_?name|model)\b"""
    r"""["']?\s*[:=]\s*["']([A-Za-z0-9][A-Za-z0-9._:/@-]{2,199})["']"""
)
_IAC_EXTENSIONS = frozenset({".tf", ".hcl", ".bicep", ".json", ".yaml", ".yml"})


def _exception_name(exc: Exception) -> str:
    return type(exc).__name__


def _file_failure_reason(exc: Exception) -> str:
    """Describe why one file's analysis stopped without echoing hostile input.

    Only the scanner's own limit messages are static text; never echo
    exception text that could be derived from hostile input.
    """
    reason = f"{type(exc).__name__}: {exc}" if isinstance(exc, MatchTimeoutError) else type(exc).__name__
    return sanitize_text(reason)[:200]


# A link in the root's path fails its no-follow directory open as ENOTDIR or ELOOP.
_ROOT_OPEN_REASONS = {
    errno.EACCES: "permission denied",
    errno.EPERM: "permission denied",
    errno.ENOENT: "not found",
    errno.ENOTDIR: "a path component is a link or not a directory",
    errno.ELOOP: "a path component is a link or not a directory",
}


def _root_open_failure(exc: OSError | ValueError) -> str:
    """Say why a scan root could not be opened without echoing its path.

    A ``ValueError`` from the confined opener carries only its own fixed text.
    """
    if isinstance(exc, ValueError):
        return str(exc)
    return _ROOT_OPEN_REASONS.get(exc.errno or 0) or errno.errorcode.get(exc.errno or 0, type(exc).__name__)


def _is_test_path(rel: str) -> bool:
    parts = rel.lower().split("/")
    return any(part in _TEST_DIR_NAMES for part in parts[:-1]) or bool(_TEST_FILE_RE.search(rel))


_CODING_AGENT_DOC_NAMES = frozenset(
    {
        "agents.md",
        "agent.md",
        "claude.md",
        "claude.local.md",
        "gemini.md",
        "copilot-instructions.md",
    }
)


def _is_coding_agent_doc(name: str) -> bool:
    return name.lower() in _CODING_AGENT_DOC_NAMES


def _resolved_link_target(link: Path, resolved_root: Path) -> Path | None:
    """Resolve only to classify a link; never open it through the link path."""
    try:
        target = link.resolve(strict=True)
    except (OSError, ValueError, RuntimeError):
        return None
    return target if target == resolved_root or resolved_root in target.parents else None


def _local_module_predicate(root: Path, path: Path, proj_root: str) -> Callable[[str], bool]:
    """Return a cached check whether an import in ``path`` names a module of the scanned tree."""
    local_modules: dict[str, bool] = {}

    def is_local_module(module: str) -> bool:
        # Resolve only within the supplied directory scope.
        # A standalone file has no sibling/module inventory.
        if root.is_file():
            return False
        name = module.split(".", 1)[0]
        if name not in local_modules:
            local_modules[name] = local_module_conflict(
                module,
                scan_root=root,
                source_path=path,
                project_root=root if proj_root == "." else root / proj_root,
            )
        return local_modules[name]

    return is_local_module


MAX_ROOT_OWNERSHIP_STEPS = 20_000_000


def scan_timeout_for_size(base: float, size: int) -> float:
    """Return the matching budget in seconds for one file of ``size`` bytes.

    ``base`` is the configured ``scan_timeout``. Each further 256 KiB adds
    one more ``base`` so ordinary large text files finish on an idle core; the
    final 64 KiB of the first band receives that next slice early. The result
    is capped at 10 seconds, or at ``base`` when that is higher.
    """
    size = max(size, 0)
    steps = size // SCAN_TIMEOUT_STEP_BYTES
    if steps == 0 and size >= SCAN_TIMEOUT_STEP_BYTES - SCAN_TIMEOUT_BAND_HEADROOM_BYTES:
        steps = 1
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
    symlink in the path supplied by the caller. The walk then opens this root
    once and reads every file relative to it without following a link in any
    component (``FilesystemConnector._walk``), so a directory concurrently
    replaced by a link fails its reads instead of redirecting them outside the
    tree. Findings still describe one consistent state only when the checkout
    does not change during the scan.
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
        raise ConnectorError(
            "code.filesystem: root_ids must be 1-80 characters of letters, digits, '.', '_' or '-'"
        )
    if len(set(root_ids)) != len(root_ids):
        raise ConnectorError("code.filesystem: root_ids must be unique within paths")
    return root_ids


class FilesystemConnector(BaseConnector):
    @classmethod
    def cache_roots_separately(cls, roots: list[Any], root_ids: Any, *, labelled: bool) -> bool:
        # Engine hook: each repository root is an independent incremental-cache unit.
        if labelled:
            validate_distinct_paths(roots)
        if root_ids is not None:
            validate_root_ids(roots, root_ids)
        return True

    name: ClassVar[str] = "code.filesystem"
    surface: ClassVar[Surface] = Surface.CODE
    provider: ClassVar[str | None] = "filesystem"
    description: ClassVar[str] = (
        "Scan a local directory / repository checkout for agent frameworks, MCP, coding agents, IaC "
        "and secrets."
    )
    config_keys: ClassVar[dict[str, str]] = {
        "path": "directory to scan (or `paths`: list)",
        "paths": "list of directories to scan instead of `path`; each root keeps its own identity",
        "exclude": "extra directory names / glob patterns to skip",
        "max_file_size": (
            "bytes; an analyzable larger file is skipped with incomplete coverage unless oversize_skip_globs "
            "matches it (default 1,000,000 bytes)"
        ),
        "oversize_skip_globs": (
            "case-insensitive file name globs; a file over max_file_size matching one is skipped with a "
            "warning even under strict_coverage (default: lockfiles, minified bundles, source maps, images, "
            "fonts, archives and compiled artifacts)"
        ),
        "max_files": "stop after this many files (default 100000)",
        "max_notebook_size": (
            "bytes; a Jupyter notebook up to this size is read with its code cells analyzed as source even "
            "when saved outputs make the file larger than max_file_size (default 20 MiB); outputs of such a "
            "notebook are not scanned for credentials"
        ),
        "max_ast_nodes": (
            "Python syntax-tree nodes analyzed per file for import-bound evidence (default 50000); a larger "
            "file keeps its lexical evidence and is reported as partially analyzed: a warning under test "
            "paths, an error elsewhere"
        ),
        "scan_timeout": (
            "matching budget in seconds per file up to 256 KiB (default 2); one more budget per further "
            "256 KiB, capped at 10 seconds or scan_timeout when higher"
        ),
        "scan_secrets": "detect provider credentials (default true)",
        "use_git": (
            "opt in to offline git author/date enrichment for trusted metadata; requires Git 2.45+ "
            "(default false)"
        ),
        "strict_coverage": (
            "report coverage gaps (unread analyzable oversize files, symbolic links whose alias path is not "
            "covered) as errors instead of warnings; either way the scan is incomplete (default false)"
        ),
        "include_tests": (
            "let test and fixture code establish agents and credential findings at full weight "
            "(default false)"
        ),
        "label": "prefix for resource ids (e.g. 'github:org/repo'); defaults to the path",
        "root_ids": "unique stable IDs aligned with paths, for resource identity across checkout moves",
        "account": "account label recorded on every finding (default none)",
        "owner": (
            "owner recorded on every finding; overrides CODEOWNERS and inventory attribution "
            "(default: CODEOWNERS, then git author when use_git, then inventory)"
        ),
        "provider": "provider label recorded on findings (default filesystem)",
        "metadata": "mapping merged into every finding's metadata",
    }
    shared_config_keys: ClassVar[dict[str, str]] = {}  # scans a checkout, not an export file
    offline_formats: ClassVar[str] = "n/a (path is the input)"

    def __init__(self, ctx: ConnectorContext) -> None:
        super().__init__(ctx)
        self.max_file_size = int(ctx.get("max_file_size", 1_000_000))
        self.max_files = int(ctx.get("max_files", 100_000))
        self.scan_timeout = float(ctx.get("scan_timeout", 2.0))
        # max_ast_nodes and max_notebook_size are validated below.
        self.max_ast_nodes: int | None = ctx.get("max_ast_nodes")
        self.max_notebook_size: int = ctx.get("max_notebook_size", DEFAULT_MAX_NOTEBOOK_SIZE)
        if type(self.max_notebook_size) is not int or self.max_notebook_size < 1:
            raise ConnectorError("code.filesystem: max_notebook_size must be a positive integer")
        if self.max_file_size < 1 or self.max_files < 1 or not 0 < self.scan_timeout <= 60:
            raise ConnectorError(
                "code.filesystem: limits must be positive; scan_timeout must be at most 60 seconds"
            )
        if self.max_ast_nodes is not None and (
            type(self.max_ast_nodes) is not int or not 1_000 <= self.max_ast_nodes <= 2_000_000
        ):
            raise ConnectorError("code.filesystem: max_ast_nodes must be an integer between 1000 and 2000000")
        self.oversize_skip_globs = _validated_globs(
            ctx.get("oversize_skip_globs", list(DEFAULT_OVERSIZE_SKIP_GLOBS))
        )
        self.scan_secrets = config_boolean(ctx.get("scan_secrets", True), "scan_secrets")
        self.use_git = config_boolean(ctx.get("use_git", False), "use_git")
        self.strict_coverage = config_boolean(ctx.get("strict_coverage", False), "strict_coverage")
        self.include_tests = config_boolean(ctx.get("include_tests", False), "include_tests")
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
            if (
                not self.label
                or not isinstance(path, str)
                or not isinstance(split_root_id, str)
                or not _ROOT_ID_RE.fullmatch(split_root_id)
            ):
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
        self._checked_submodules: set[tuple[Path, str]] = set()
        self._gitlink_roots: set[Path] = set()

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

    def _size_limit(self, name: str) -> int:
        """Bytes the reader accepts for ``name``: notebooks may carry large saved outputs."""
        if name.lower().endswith(".ipynb"):
            return max(self.max_file_size, self.max_notebook_size)
        return self.max_file_size

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

    def _link_target_is_scanned(self, rel: str, target: Path, root: Path) -> bool:
        """Whether skipping the (never followed) link at ``rel`` loses no coverage.

        Coverage is kept when nothing would ever be read at the alias path, or
        when the real target is walked and analyzed with the same semantics the
        alias path would have had: same project, same test classification, same
        source type and no file-name signal that only the alias name carries.
        Directory links, links into excluded or unread content and config or
        document aliases (whose parsing can depend on their path) are gaps. A
        coding-agent instruction document linked to another one is the exception:
        the target keeps the alias's project and test classification.
        """
        relative = target.relative_to(root)
        target_rel = relative.as_posix()
        if target.is_dir():
            # A directory alias changes every descendant's path. Even an
            # included target cannot prove that path-based signals at the
            # alias were assessed without walking the link (which we forbid).
            return False
        link_name = PurePosixPath(rel).name
        link_ext = Path(link_name).suffix.lower()
        alias_signals = {(m.signature.id, id(m.signal)) for m in self.index.match_file(rel)}
        link_read = bool(alias_signals) or _analyzed_by_name(link_name)
        if _never_read_by_name(link_name) or not link_read:
            # The walker would skip this name silently even as a regular
            # file, whatever it points at: the alias hides nothing.
            return True
        parts = relative.parts
        for depth, name in enumerate(parts[:-1], start=1):
            if self._excluded(PurePosixPath(*parts[:depth]).as_posix(), name):
                return False
        if not target.is_file() or self._excluded_file(target_rel) or _never_read_by_name(target.name):
            return False
        # Coding-agent instruction aliases (CLAUDE.md -> AGENTS.md) are the
        # same document family. The real file is scanned and the alias hides no
        # second agent definition, so the alias-only file-name signal is not a
        # gap. Project ownership and test classification must still match.
        if _is_coding_agent_doc(link_name) and _is_coding_agent_doc(target.name):
            return _project_root(root, rel) == _project_root(root, target_rel) and _is_test_path(
                rel
            ) == _is_test_path(target_rel)
        # Only source aliases are equivalent without opening the link: config
        # and document parsing can depend on the file name and directory.
        if link_ext not in SOURCE_EXTENSIONS or Path(target.name).suffix.lower() != link_ext:
            return False
        # The real path must keep the alias's project ownership and evidence
        # weight; another project or a test directory would change both.
        if _project_root(root, rel) != _project_root(root, target_rel) or _is_test_path(rel) != _is_test_path(
            target_rel
        ):
            return False
        # File-name signatures can apply to the alias but not the real file.
        target_signals = {(m.signature.id, id(m.signal)) for m in self.index.match_file(target_rel)}
        return alias_signals <= target_signals

    def _iter_files(self, root: Path) -> Iterator[tuple[str, Path, str]]:
        """Yield (relpath, path, project_root_rel) top-down with project root tracking."""
        for rel, path, proj, _ in self._iter_entries(root):
            yield rel, path, proj

    def check_gitlink_coverage(self, root: Path) -> None:
        """Check committed gitlinks where Git is authorized: a clone or use_git=True.

        Default local scans never invoke Git, and instead inspect declarations
        as the walk reaches .gitmodules. Gitlinks lacking that declaration
        require clone mode or the existing local metadata opt-in to discover.
        """
        if root in self._gitlink_roots:
            return
        self._gitlink_roots.add(root)
        self.ctx.check_deadline()
        remaining = self.ctx.deadline - time.monotonic() if self.ctx.deadline is not None else 10.0
        paths = read_gitlink_paths(root, timeout=remaining)
        self.ctx.check_deadline()
        if paths is None:
            self._submodule_gap("could not inventory gitlinks safely; submodule coverage unknown")
            return
        self._check_submodule_paths(root, paths)

    def _submodule_gap(self, message: str) -> None:
        if self.strict_coverage:
            self.ctx.error(f"code.filesystem: {message}")
        else:
            self.ctx.warn(f"code.filesystem: {message}")

    def _check_submodule_paths(self, root: Path, paths: Iterable[str]) -> None:
        """Missing/empty modules are gaps; operator-excluded paths remain out of scope.

        Each directory component is opened without following symlinks. We only
        test materialization here; the ordinary bounded walker scans its files.
        A nonempty directory is not proof of a complete or authentic checkout.
        """
        for rel in paths:
            self.ctx.check_deadline()
            parts = PurePosixPath(rel).parts
            if any(
                self._excluded(PurePosixPath(*parts[:depth]).as_posix(), name)
                for depth, name in enumerate(parts, 1)
            ):
                continue
            key = (root, rel)
            if key in self._checked_submodules:
                continue
            self._checked_submodules.add(key)
            materialized = False
            try:
                anchor = open_confined_directory(root / rel)
                try:
                    # The confined anchor may be O_PATH, which cannot enumerate.
                    directory = os.open(".", os.O_RDONLY | os.O_DIRECTORY, dir_fd=anchor)
                finally:
                    os.close(anchor)
                try:
                    with os.scandir(directory) as entries:
                        materialized = any(entry.name != ".git" for entry in entries)
                finally:
                    os.close(directory)
            except (OSError, ValueError):
                pass
            if not materialized:
                self._submodule_gap(
                    f"submodule {rel}: checkout is missing, empty or unsafe; source coverage incomplete"
                )

    def _check_submodule_declarations(self, root: Path, rel_dir: str) -> None:
        rel = ".gitmodules" if rel_dir == "." else f"{rel_dir}/.gitmodules"
        if self._excluded_file(rel):
            return
        try:
            text = read_policy_text(root / rel, MAX_GITMODULES_BYTES)
            paths = declared_submodule_paths(text)
        except (OSError, ValueError, UnicodeError):
            self._submodule_gap(f"{rel}: cannot read submodule declarations safely; coverage unknown")
            return
        self._check_submodule_paths(root, (path if rel_dir == "." else f"{rel_dir}/{path}" for path in paths))

    def _iter_entries(self, root: Path) -> Iterator[tuple[str, Path, str, int]]:
        """Yield (relpath, path, project_root_rel, size) for every regular file to analyze.

        A file over ``max_file_size`` whose name matches ``oversize_skip_globs``
        is reported as a warning and never yielded; the scan stays complete
        because such content is never analyzed. Every other oversize file is
        yielded so the reader records incomplete coverage for analyzable files;
        types that the scanner never reads are still ignored.
        """
        # os.walk visits descendants before siblings. Keep only active project
        # ancestors, so assigning a project is amortized constant time even in
        # monorepos with thousands of sibling projects.
        roots: list[str] = ["."]
        count = 0

        resolved_root = Path(os.path.realpath(root))

        if root.is_file():
            try:
                size = root.stat().st_size
            except OSError:
                self.ctx.error(f"code.filesystem: could not inspect {root.name}")
                return
            if size > self._size_limit(root.name) and self._oversize_skippable(root.name, root.name):
                self._skip_oversize(root.name, size)
                return
            yield root.name, root, ".", size
            return

        def walk_error(exc: OSError) -> None:
            self.ctx.error(f"code.filesystem: could not enumerate a directory under {root}")

        # A gitfile or symlink also signals a checkout, but cannot authorize
        # reading external metadata. The checker reports that unknown coverage
        # even when this source tree produces no findings (and no enrichment).
        if self.use_git and os.path.lexists(root / ".git"):
            self.check_gitlink_coverage(root)
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=walk_error):
            rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
            rel_dir = "." if rel_dir == "." else rel_dir
            if ".gitmodules" in filenames:
                self._check_submodule_declarations(root, rel_dir)
            dirnames[:] = self._walked_directories(root, resolved_root, dirpath, rel_dir, dirnames)
            proj = _nearest_root(rel_dir, roots)
            if rel_dir != "." and _marks_project(Path(dirpath), filenames):
                roots.append(rel_dir)
                proj = rel_dir
            for fn in sorted(filenames):
                rel = fn if rel_dir == "." else f"{rel_dir}/{fn}"
                if self._excluded_file(rel):
                    continue
                p = Path(dirpath) / fn
                try:
                    if p.is_symlink():
                        self._skip_link(root, resolved_root, rel, p)
                        continue
                    info = p.stat()
                except OSError as exc:
                    if exc.errno in _IGNORED_STAT_ERRNOS:
                        continue
                    self.ctx.error(f"code.filesystem: could not inspect {rel}")
                    continue
                if not stat.S_ISREG(info.st_mode):
                    continue
                if info.st_size > self._size_limit(fn) and self._oversize_skippable(rel, fn):
                    self._skip_oversize(rel, info.st_size)
                    continue
                if _never_read_by_name(fn):
                    continue
                count += 1
                if count > self.max_files:
                    self.ctx.error(f"code.filesystem: max_files ({self.max_files}) reached under {root}")
                    return
                yield rel, p, proj, info.st_size

    def _walked_directories(
        self,
        root: Path,
        resolved_root: Path,
        dirpath: str,
        rel_dir: str,
        dirnames: list[str],
    ) -> list[str]:
        """Return the subdirectories of ``dirpath`` the walk descends into, in name order."""
        kept = []
        for name in sorted(dirnames):
            rel = name if rel_dir == "." else f"{rel_dir}/{name}"
            if self._excluded(rel, name):
                continue
            path = Path(dirpath) / name
            try:
                if path.is_symlink():
                    self._skip_link(root, resolved_root, rel, path)
                    continue
            except OSError:
                self.ctx.error(f"code.filesystem: could not inspect {rel}")
                continue
            kept.append(name)
        return kept

    def _skip_link(self, root: Path, resolved_root: Path, rel: str, link: Path) -> None:
        """Record the coverage gap of a symbolic link, which the walk never follows."""
        # A link that resolves inside the scan root loses no coverage only if
        # the target is scanned at its real path.
        target = _resolved_link_target(link, resolved_root)
        if target is not None and self._link_target_is_scanned(rel, target, resolved_root):
            return
        # A single representative diagnostic per root keeps hostile trees
        # from filling the report with thousands of link names.
        if root not in self._symlink_warnings:
            self._symlink_warnings.add(root)
            message = f"code.filesystem: skipped symbolic link {rel} whose target is unavailable or unscanned"
            if self.strict_coverage:
                self.ctx.error(f"{message}; coverage incomplete")
            else:
                self.ctx.warn(f"{message}; coverage incomplete", incomplete=True)

    def _reserved_budget(self, rel: str, path: Path, size: int, budget: float) -> float:
        """Return the share of ``budget`` a file must have left before the walk may start it.

        Files the reader never opens (over ``max_file_size``, which only
        records an error, or neither source, configuration nor a file-name
        signal) reserve nothing, so they cannot end the walk under a short
        deadline.
        """
        if size > self._size_limit(path.name):
            return 0.0
        will_read = _analyzed_by_name(path.name) or bool(self.index.match_file(rel))
        return budget if will_read else 0.0

    def _stop_at_deadline(
        self,
        root: Path,
        examined: int,
        entries: Iterator[tuple[str, Path, str, int]],
        deadline: float,
        margin: float,
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
            if examined + remaining >= self.max_files or (
                not (remaining & 63) and time.monotonic() >= count_until
            ):
                truncated = True
                break
        total = f"at least {examined + remaining}" if truncated else str(examined + remaining)
        self.ctx.error(
            f"code.filesystem: connector deadline reached after {examined} of {total} files under {root}; "
            "results incomplete",
        )

    # ------------------------------------------------------------------ scan
    @contextmanager
    def _isolated(
        self,
        rel: str,
        analysis: str,
        reason: Callable[[Exception], str] = _exception_name,
    ) -> Iterator[None]:
        """Contain a failure while analyzing ``rel`` to one diagnostic so other findings survive.

        A ConnectorError always propagates: cancellation or an exhausted
        deadline ends the walk and must not become one "incomplete" error per
        file, project or finding.
        """
        try:
            yield
        except ConnectorError:
            raise
        except Exception as exc:  # noqa: BLE001 - isolate hostile input and retain other findings
            self.ctx.error(f"code.filesystem: {rel}: {analysis} incomplete ({reason(exc)})")

    def scan_tree(self, root: Path) -> Iterator[Finding]:
        scan = _ScanState(root, self._scan_label(root))
        self._walk(scan)
        yield from self._emit_findings(scan)

    def _scan_label(self, root: Path) -> str:
        """Return the resource prefix of the findings under ``root``."""
        label = self.label or str(root)
        if self.label and self._shared_label_roots:
            # Explicit IDs survive checkout relocation; absent them, hash the
            # resolved root to avoid exposing local directory names.
            root_id = self._root_ids.get(root)
            label = (
                f"{label}/root-id-{root_id}"
                if root_id is not None
                else f"{label}/root-{hashlib.sha256(os.fsencode(root)).hexdigest()}"
            )
        return label

    def _walk(self, scan: _ScanState) -> None:
        """Analyze every file under the scan root, each in its own failure isolation.

        Files are read relative to the root directory opened here, with no
        link followed in any component below it. The listing itself uses
        paths, so a directory replaced by a link after it was listed fails
        that file's read (incomplete coverage) instead of redirecting it.
        """
        # A single-file root is read relative to its (equally checked) parent.
        base = scan.root.parent if scan.root.is_file() else scan.root
        try:
            scan.root_fd = open_confined_directory(base)
        except (OSError, ValueError) as exc:
            # Named by its label, like the findings: a labeled root is not exposed.
            reason = _root_open_failure(exc)
            self.ctx.error(f"code.filesystem: {scan.label}: could not open the scan root safely ({reason})")
            return
        try:
            self._walk_entries(scan)
        finally:
            os.close(scan.root_fd)
            scan.root_fd = -1

    def _walk_entries(self, scan: _ScanState) -> None:
        """Start each file only while its matching budget fits before the connector deadline."""
        deadline = self.ctx.deadline
        margin = deadline_margin(deadline - time.monotonic()) if deadline is not None else 0.0
        entries = self._iter_entries(scan.root)
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
                    self._stop_at_deadline(scan.root, examined, entries, deadline, margin)
                    break
            examined += 1
            with (
                self._isolated(rel, "file analysis", _file_failure_reason),
                self.index.scan_budget(seconds=budget),
            ):
                self._scan_file(scan, rel, path, proj_root)

    def _scan_file(self, scan: _ScanState, rel: str, path: Path, proj_root: str) -> None:
        """Run every analysis pass over one file of the walk."""
        proj = scan.projects.setdefault(proj_root, _Project(proj_root))
        proj.files += 1
        self.ctx.examined()
        lang = language_for_path(rel)
        if lang:
            proj.languages.add(lang)

        # 1. file-name signals (config files of agents / MCP / A2A ...)
        file_matches = self.index.match_file(rel)
        if not (_analyzed_by_name(path.name) or file_matches):
            return
        loaded = self._read_source(rel, path, scan.root_fd)
        if loaded is None:
            return
        text, raw_notebook = loaded
        file = _SourceFile(
            rel=rel,
            path=path,
            proj_root=proj_root,
            proj=proj,
            text=text,
            lang="python" if path.suffix.lower() == ".ipynb" else lang,
            file_matches=file_matches,
            raw_notebook=raw_notebook,
            structure=self._structure_for(rel, text),
        )
        self._record_file_matches(file)
        if self.scan_secrets:
            self._detect_secrets(scan, file)
        self._detect_mcp(file)

        # 2. manifests (dependencies, images, env names, IaC types)
        self._scan_manifest(scan, file)
        if file.ext in _IAC_EXTENSIONS and not file.is_mcp:
            self._scan_iac(scan, file)

        # 3. source & config content
        self._scan_content(scan, file)

        # 4. special files
        self._record_special_files(scan, file)

    def _read_source(self, rel: str, path: Path, root_fd: int) -> tuple[str, str | None] | None:
        """Read a file for analysis: its text and, for a notebook, the raw document.

        ``rel`` is read relative to the open scan root ``root_fd``. A notebook's
        text is its code cells. None means nothing is analyzed; the recorded
        diagnostics say why.
        """
        read_errors: list[str] = []
        text = read_text(PurePosixPath(rel), self._size_limit(path.name), read_errors, dir_fd=root_fd)
        for issue in read_errors:
            if issue == "file exceeds max_file_size" and not self.strict_coverage:
                self.ctx.warn(
                    f"code.filesystem: {rel}: skipped, {issue}; coverage incomplete",
                    incomplete=True,
                )
            else:
                self.ctx.error(f"code.filesystem: {rel}: {issue}")
        if text is None:
            return None
        if path.suffix.lower() != ".ipynb":
            return text, None
        return self._notebook_source(rel, text)

    def _notebook_source(self, rel: str, document: str) -> tuple[str, str | None] | None:
        """Return a notebook's code cells and, when within max_file_size, its raw document."""
        notebook_errors: list[str] = []
        oversized_notebook = len(document) > self.max_file_size
        raw_notebook = None if oversized_notebook else document
        text = notebook_to_source(document, notebook_errors)
        self._file_errors(rel, dict.fromkeys(notebook_errors))
        # Unread analyzable content leaves coverage incomplete, as
        # for any oversize file; strict_coverage only raises the
        # diagnostic from a warning to an error.
        gap: str | None = None
        if len(text) > self.max_file_size:
            gap = f"code.filesystem: {rel}: skipped, notebook code cells exceed max_file_size"
        elif oversized_notebook and self.scan_secrets:
            # Code cells are analyzed as usual. Saved outputs are
            # read only for credentials, and not at this size.
            gap = (
                f"code.filesystem: {rel}: notebook over max_file_size; code cells analyzed, "
                "saved outputs not scanned for credentials"
            )
        if gap is not None:
            if self.strict_coverage:
                self.ctx.error(gap)
            else:
                self.ctx.warn(f"{gap}; coverage incomplete", incomplete=True)
        if len(text) > self.max_file_size:
            return None
        return text, raw_notebook

    def _structure_for(self, rel: str, text: str) -> Any:
        """Parse the credential context of a structured file; None withholds its excerpts.

        Structured files are parsed now so a resource-limit or integrity
        failure (duplicate fields, non-finite numbers) reaches the per-file
        boundary. Redacting the text for excerpts waits until a match needs
        one, which most files never do.
        """
        try:
            return _structured_context(rel, text)
        except (
            JSONIntegrityError,
            YAMLIntegrityError,
            YAMLResourceLimitError,
            SanitizationLimitError,
        ) as exc:
            # Detection still runs, but without an established
            # structured context none of this file's excerpts can
            # safely be emitted.
            self._withhold_excerpts(rel, exc, "parsing")
            return None

    def _withhold_excerpts(self, rel: str, exc: Exception, stage: str = "sanitization") -> None:
        self.ctx.error(
            f"code.filesystem: {rel}: structured {stage} incomplete ({type(exc).__name__}); excerpts withheld"
        )

    def _file_errors(self, rel: str, issues: Iterable[str]) -> None:
        """Record each issue a parser or validator reported for ``rel`` as an error."""
        for issue in issues:
            self.ctx.error(f"code.filesystem: {rel}: {issue}")

    def _redacted_lines(self, file: _SourceFile) -> list[str]:
        """Return the redacted lines excerpts are cut from, redacting on first use."""
        if file.structure is None:
            return []
        if file.safe_lines is None:
            try:
                file.safe_lines = _redacted_source(file.text, file.structure).splitlines()
            except (YAMLResourceLimitError, SanitizationLimitError) as exc:
                self._withhold_excerpts(file.rel, exc)
                file.structure = None
                file.safe_lines = []
        return file.safe_lines

    def _file_excerpt(self, file: _SourceFile, line_number: int | None, secret: str | None = None) -> str:
        return _excerpt(self._redacted_lines(file), line_number or 1, secret)

    def _record_file_matches(self, file: _SourceFile) -> None:
        """Record file-name evidence; MCP file names wait for a parsed configuration."""
        file.card_kind = agent_manifest_kind(file.rel)
        if file.card_kind:
            validation = parse_agent_manifest(file.rel, file.text, file.card_kind)
            self._file_errors(file.rel, validation.errors)
            file.card_valid = validation.valid
        for m in file.file_matches:
            if m.signature_id == "protocol.mcp":
                continue
            # A suggestive filename establishes neither a valid
            # manifest nor an agent. Keep coding-agent file evidence
            # and validated product schemas; do not invent agents.
            if file.card_kind and not file.card_valid:
                continue
            m.extra["verified_agent"] = file.card_valid
            self._record(file.proj, m, file.rel, None)

    def _detect_secrets(self, scan: _ScanState, file: _SourceFile) -> None:
        """Collect provider credentials from the file text and a notebook's raw document.

        Credential detection runs first and in its own isolation so a slow or
        over-budget content pass cannot hide a real key. Notebook outputs and
        markdown cells are scanned from the raw document.
        """
        with self._isolated(file.rel, "credential detection"):
            seen_secrets: set[tuple[str, str, int | None]] = set()
            for raw in (file.text, file.raw_notebook):
                if raw is None or (raw == file.text and seen_secrets):
                    continue
                self._detect_secrets_in(scan, file, raw, seen_secrets)

    def _detect_secrets_in(
        self,
        scan: _ScanState,
        file: _SourceFile,
        raw: str,
        seen_secrets: set[tuple[str, str, int | None]],
    ) -> None:
        # Excerpts of a notebook's raw document come from its own sanitized
        # lines; the redacted source lines describe the code cells only.
        from_raw_notebook = raw is file.raw_notebook and file.raw_notebook != file.text
        raw_lines: list[str] | None = None
        if from_raw_notebook and file.structure is not None:
            try:
                raw_lines = sanitize_text(raw).splitlines()
            except SanitizationLimitError:
                self.ctx.error(
                    f"code.filesystem: {file.rel}: notebook excerpt sanitization incomplete; "
                    "excerpts withheld"
                )
        for m in self.index.match_secrets(raw):
            key = (m.signature_id, m.value, m.line)
            if key in seen_secrets:
                continue
            seen_secrets.add(key)
            reason = placeholder_reason(m.value)
            if reason:
                self._record_example_credential(file.proj, m, file.rel, reason)
                continue
            if from_raw_notebook:
                snippet = _excerpt(raw_lines, m.line or 1, m.value) if raw_lines is not None else ""
            else:
                snippet = self._file_excerpt(file, m.line, m.value)
            scan.secret_hits.setdefault(file.rel, []).append((m, snippet))
            self._record(file.proj, m, file.rel, None)

    def _detect_mcp(self, file: _SourceFile) -> None:
        """Parse an MCP client/server configuration; only an enabled server is MCP evidence."""
        file.is_mcp = self._looks_like_mcp_config(file.rel, file.name, file.text) or (
            file.name.lower() == "server.json" and '"mcpServers"' in file.text
        )
        if file.is_mcp:
            mcp_errors: list[str] = []
            file.mcp_servers = _parse_mcp_servers(file.rel, file.text, mcp_errors)
            self._file_errors(file.rel, dict.fromkeys(mcp_errors))
        file.mcp_active = any(not server["disabled"] for server in file.mcp_servers)
        if file.mcp_active:
            for m in file.file_matches:
                if m.signature_id == "protocol.mcp":
                    self._record(file.proj, m, file.rel, None)

    def _record_content(self, file: _SourceFile, m: Match, snippet: str | None) -> None:
        # A bare key or matching filename is not evidence of a
        # configured server when all entries are empty/disabled.
        if m.signature_id != "protocol.mcp" or not file.is_mcp or file.mcp_active:
            self._record(file.proj, m, file.rel, snippet)

    def _scan_manifest(self, scan: _ScanState, file: _SourceFile) -> None:
        """Match the dependencies and artifacts (images, env names, IaC types) a manifest declares."""
        rel = file.rel
        may_be_manifest = (
            is_manifest_name(file.name) or file.ext in _MANIFEST_EXTENSIONS or ".github/workflows" in rel
        )
        if not may_be_manifest:
            return
        manifest = parse_manifest(rel, file.text)
        if not manifest:
            return
        self._file_errors(rel, dict.fromkeys(manifest.errors))
        for dep in manifest.deps:
            file.proj.deps.append(dep)
            for m in self.index.match_dependency(dep.ecosystem, dep.name):
                m.line = dep.line
                self._record(file.proj, m, rel, f"{dep.ecosystem}: {dep.name} {dep.spec or ''}".strip())
        for art in manifest.artifacts:
            self._handle_artifact(
                file.proj,
                art,
                rel,
                file.text,
                scan.infra_files,
                scan.secret_hits,
                scan.infra_names,
            )

    def _scan_iac(self, scan: _ScanState, file: _SourceFile) -> None:
        """Collect wildcard IAM grants and declared model ids for the infrastructure findings."""
        rel, text = file.rel, file.text
        # Excerpts come from the redacted source, which is only
        # produced for files that actually contain a wildcard.
        if _IAM_WILDCARD_RE.search(text):
            for number, line_text in enumerate(self._redacted_lines(file), start=1):
                if _IAM_WILDCARD_RE.search(line_text):
                    wildcard_hits = scan.iam_wildcards.setdefault(file.proj_root, [])
                    if len(wildcard_hits) < 20:
                        wildcard_hits.append((rel, number, truncate(line_text.strip(), 160) or ""))
        if rel in scan.infra_files:
            scan.infra_project[rel] = file.proj_root
            for model in _IAC_MODEL_RE.finditer(text):
                for mm in self.index.match_model(model.group(1)):
                    mm.line = text.count("\n", 0, model.start()) + 1
                    scan.infra_models.setdefault(rel, []).append(mm)

    def _scan_content(self, scan: _ScanState, file: _SourceFile) -> None:
        """Match source code and configuration content; prose is matched by file name only."""
        # Match prose documentation by its dedicated filenames only.
        # Invocations in a README, even in fenced examples, do not
        # establish executable agent code in this repository.
        is_documentation = file.ext in {".md", ".mdc", ".mdx", ".txt"} and not is_manifest_name(file.name)
        # The manifest pass's Maven XML parser extracts dependency declarations.
        # Generic regex matching over the raw POM would promote
        # examples in descriptions or CDATA to executable agents.
        is_nonexecutable = is_documentation or file.name.lower() == "pom.xml"
        # XML comments are examples/disabled declarations. Preserve
        # offsets for match line numbers and the original redacted
        # excerpts; the manifest parser handles active XML itself.
        content_text = _without_xml_comments(file.text) if file.ext in _XML_EXTENSIONS else file.text
        if file.ext in SOURCE_EXTENSIONS:
            self._scan_source(scan.root, file, content_text)
        elif not is_nonexecutable:
            self._scan_config(scan, file, content_text)
        if not is_nonexecutable and not file.is_mcp:
            for m in self.index.match_envs_in_text(content_text):
                self._record_content(file, m, self._file_excerpt(file, m.line))
            for m in self.index.match_domains_in_text(content_text):
                self._record_content(file, m, self._file_excerpt(file, m.line))

    def _scan_source(self, root: Path, file: _SourceFile, content_text: str) -> None:
        """Match the imports, code patterns and import-bound calls of a source file."""
        lang, ext = file.lang, file.ext
        is_local_module = _local_module_predicate(root, file.path, file.proj_root)
        # Malformed trailing literals are masked through EOF;
        # preceding valid imports/code remain inspectable.
        ignored, ambiguous = noncode_ranges(content_text, lang, ext, jsx=ext in {".jsx", ".tsx"})
        if ambiguous:
            self.ctx.error(f"code.filesystem: {file.rel}: incomplete source lexical analysis")
        imports = (
            self.index.match_imports(content_text, lang, ignore_spans=ignored)
            if ignored
            else self.index.match_imports(content_text, lang)
        )
        for m in imports:
            if lang == "python":
                imported = re.match(r"\s*(?:from|import)\s+([A-Za-z_]\w*(?:\.\w+)*)", m.value)
                if imported and is_local_module(imported.group(1)):
                    continue
            self._record_content(file, m, self._file_excerpt(file, m.line))
        code_matches = (
            self.index.match_code(content_text, lang, ignore_spans=ignored)
            if ignored
            else self.index.match_code(content_text, lang)
        )
        bound = self._bound_matches(file, content_text, ignored, is_local_module)
        # Execution sinks describe a model-driven capability only
        # when this same file invokes a model, framework or
        # tool-calling protocol; elsewhere they are build tooling.
        file_uses_llm = any(
            m.signature.category in _LLM_CATEGORIES for m in (*imports, *code_matches, *bound)
        )
        self._record_code_matches(file, code_matches, file_uses_llm, bound)
        for m in bound:
            self._record_content(file, m, self._file_excerpt(file, m.line))
        if any(m.signature_id == "protocol.mcp" for m in (*imports, *code_matches, *bound)):
            self._register_mcp_tools(file, ignored)

    def _bound_matches(
        self,
        file: _SourceFile,
        content_text: str,
        ignored: list[tuple[int, int]],
        is_local_module: Callable[[str], bool],
    ) -> list[Match]:
        """Return bound evidence, including narrow typed-field registration for Java."""
        lang = file.lang
        if file.ext == ".java":
            return spring_tool_registration_matches(self.index, content_text, ignored)
        if lang not in {"python", "javascript"}:
            return []
        try:
            return bound_source_matches(
                self.index,
                content_text,
                lang,
                ignored,
                is_local_module=is_local_module if lang == "python" else None,
                max_ast_nodes=self.max_ast_nodes,
            )
        except SourceBudgetExceeded as exc:
            # The budget is a property of the file, not of
            # the scan: keep its lexical evidence. Test code
            # is discounted evidence, so it only warns.
            message = (
                f"code.filesystem: {file.rel}: import-bound analysis skipped ({exc}); "
                "lexical evidence retained"
            )
            if not self.include_tests and _is_test_path(file.rel):
                self.ctx.warn(message, incomplete=self.strict_coverage)
            else:
                self.ctx.error(message)
            return []

    def _record_code_matches(
        self, file: _SourceFile, code_matches: list[Match], file_uses_llm: bool, bound: list[Match]
    ) -> None:
        configured_spans = {
            m.extra["configured_call_span"] for m in bound if "configured_call_span" in m.extra
        }
        for m in code_matches:
            if m.signature_id in _COLOCATED_SIGNATURES and not file_uses_llm:
                continue
            if file.lang in {"python", "javascript"}:
                if m.signature.category == "framework":
                    continue  # import-bound calls establish the library
                if (
                    m.signature_id in {"heuristic.tool-use", "heuristic.memory"}
                    and re.match(r"(?:tools|checkpointer)\s*[=:]", m.value)
                    and any(start <= m.extra.get("start", -1) < end for start, end in configured_spans)
                ):
                    # The parsed call owns these option values. A raw keyword
                    # match must not turn empty, disabled or unknown options
                    # into capabilities. Independent tool/memory calls remain.
                    continue
                if m.signature_id == "heuristic.tool-use" and re.fullmatch(
                    r"tools\s*=\s*(?:None|False)\s*", m.value
                ):
                    continue  # explicit disabled options do not register tools
                m.extra["verified_agent"] = False
            else:
                # Other languages have lexical filtering but
                # no import binder. Their code signatures need
                # corroborating library evidence at emit time.
                m.extra["lexical_source"] = file.lang
            self._record_content(file, m, self._file_excerpt(file, m.line))

    @staticmethod
    def _register_mcp_tools(file: _SourceFile, ignored: list[tuple[int, int]]) -> None:
        """Remember the MCP tool names a source file registers, bounded per project."""
        tools = file.proj.mcp_tools
        for tool in mcp_tool_names(file.text, ignore_spans=ignored):
            known = tools.get(tool)
            if known is None:
                if len(tools) < _MAX_MCP_TOOLS:
                    tools[tool] = file.rel
            elif _is_test_path(known) and not _is_test_path(file.rel):
                tools[tool] = file.rel  # prefer where deployed code registers it

    def _scan_config(self, scan: _ScanState, file: _SourceFile, content_text: str) -> None:
        """Match recognized configuration shapes and collect the model nodes of exported workflows."""
        if file.is_mcp:
            # MCP configs are structured data. A disabled server may
            # contain sample commands that look like agent code; only
            # the parsed protocol marker (see _detect_mcp) is relevant.
            return
        rel = file.rel
        config_errors: list[str] = []
        config_limits: list[str] = []
        structured = structured_code_matches(
            self.index,
            rel,
            content_text,
            errors=config_errors,
            limit_errors=config_limits,
        )
        # Unknown content, not a syntax error: fail closed.
        self._file_errors(rel, config_limits)
        for issue in config_errors:
            if is_agent_config_path(rel):
                self.ctx.error(f"code.filesystem: {rel}: {issue}")
            else:
                # Only the structured projection is lost; the
                # lexical env and domain passes still read this text.
                self.ctx.warn(
                    f"code.filesystem: {rel}: {issue}; structured checks skipped",
                    incomplete=self.strict_coverage,
                )
        for m in structured:
            self._record_content(file, m, None)
            category = m.signature.category
            agent_platform = category in {"platform", "cloud-service"} and m.agent_indicator
            if agent_platform and file.ext in _WORKFLOW_EXTENSIONS:
                scan.workflow_files.setdefault(rel, []).append((m, ""))
            elif category == "provider" and m.extra.get("structured_config"):
                scan.workflow_providers.setdefault(rel, []).append((m, ""))

    def _record_special_files(self, scan: _ScanState, file: _SourceFile) -> None:
        """Queue MCP configurations and agent manifests for their findings; keep agent definitions."""
        rel = file.rel
        if file.mcp_active:
            scan.mcp_files.append((rel, file.mcp_servers))
        if file.card_kind and file.card_valid:
            if len(scan.card_files) >= _MAX_CARD_FILES:
                self.ctx.error(
                    f"code.filesystem: {rel}: agent manifest limit ({_MAX_CARD_FILES}) reached; "
                    "manifest skipped"
                )
            else:
                scan.card_files.append((rel, file.text, file.card_kind, file.proj_root))
        if file.ext in {".md", ".mdc"} and any(directory in rel for directory in _AGENT_DEFINITION_DIRS):
            if len(file.proj.agent_defs) >= _MAX_AGENT_DEFINITIONS:
                self.ctx.error(
                    f"code.filesystem: {rel}: agent definition limit ({_MAX_AGENT_DEFINITIONS}) reached; "
                    "definition skipped"
                )
            else:
                file.proj.agent_defs.append(self._parse_agent_definition(rel, file.text))

    # ------------------------------------------------------------------ emit
    def _emit_findings(self, scan: _ScanState) -> Iterator[Finding]:
        """Yield the findings of one walk; a failure is isolated to its own file or project."""
        label, root = scan.label, scan.root
        # Project findings are held back until the manifests are read: a
        # manifest inside a reported project describes that project's agent
        # and is folded into its finding instead of counting it twice.
        project_findings: dict[str, Finding] = {}
        yield from self._emit_projects(scan, project_findings)
        for rel, servers in scan.mcp_files:
            with self._isolated(rel, "MCP analysis"), self.index.scan_budget(seconds=self.scan_timeout):
                yield self._mcp_finding(label, root, rel, servers)
        yield from self._emit_manifests(scan, project_findings)
        yield from project_findings.values()
        for rel, hits in scan.workflow_files.items():
            with self._isolated(rel, "workflow analysis"):
                yield self._workflow_finding(label, root, rel, [*hits, *scan.workflow_providers.get(rel, [])])
        for rel, infra_hits in scan.infra_files.items():
            with self._isolated(rel, "infrastructure analysis"):
                yield self._infra_finding(
                    label,
                    root,
                    rel,
                    infra_hits,
                    scan.infra_names.get(rel, []),
                    wildcards=scan.iam_wildcards.get(scan.infra_project.get(rel, ""), []),
                    models=scan.infra_models.get(rel, []),
                )
        for rel, hits in scan.secret_hits.items():
            with self._isolated(rel, "credential analysis"):
                f = self._secret_finding(label, root, rel, hits)
                if f:
                    yield f

    def _emit_projects(self, scan: _ScanState, project_findings: dict[str, Finding]) -> Iterator[Finding]:
        """Yield coding-agent findings and hold each project finding in ``project_findings``."""
        # MCP configs, agent manifests, exported workflows and IaC produce their
        # own findings; a project finding built only from them is a duplicate.
        covered_files = scan.covered_files()
        for proj in scan.projects.values():
            with self._isolated(proj.root, "project analysis"):
                for finding in self._emit_project(scan.label, scan.root, proj, covered_files):
                    if finding.resource_type == "project":
                        project_findings[proj.root] = finding
                    else:
                        yield finding

    def _emit_manifests(self, scan: _ScanState, project_findings: dict[str, Finding]) -> Iterator[Finding]:
        """Yield agent manifest findings; a project manifest is folded into its project's finding."""
        for rel, text, kind, proj_root in scan.card_files:
            with (
                self._isolated(rel, "agent manifest analysis"),
                self.index.scan_budget(seconds=self.scan_timeout),
            ):
                f = self._card_finding(scan.label, scan.root, rel, text, kind)
                if f is None:
                    continue
                owner = project_findings.get(proj_root) if kind in _PROJECT_MANIFESTS else None
                if owner is None:
                    yield f
                else:
                    self._fold_manifest(owner, f, scan.projects[proj_root])

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
            if (
                not self.include_tests
                and _is_test_path(rel)
                and m.signal.type != "file"
                and not _is_coding_agent_doc(PurePosixPath(rel).name)
            ):
                return
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
        # Cookiecutter template paths and compiled agentic-workflow lock files are
        # not client configuration. Other GitHub Actions workflows are parsed for
        # MCP servers embedded in step inputs (see _embedded_workflow_mcp).
        if "{{" in rel or lower.endswith((".lock.yml", ".lock.yaml")):
            return False
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
                isinstance(packages, list)
                and any(
                    isinstance(p, dict)
                    and isinstance(p.get("registryType"), str)
                    and isinstance(p.get("identifier"), str)
                    and p["identifier"].strip()
                    for p in packages
                )
                or isinstance(remotes, list)
                and any(
                    isinstance(r, dict)
                    and isinstance(r.get("url"), str)
                    and r["url"].startswith(("https://", "http://"))
                    and r.get("type") in {"streamable-http", "sse"}
                    for r in remotes
                )
            )
        if lower in {
            ".mcp.json",
            "mcp.json",
            "mcp-config.json",
            "mcp_config.json",
            "mcp-servers.json",
            "claude_desktop_config.json",
            "cline_mcp_settings.json",
            "mcp_settings.json",
            "smithery.yaml",
        }:
            return True
        if lower in MCP_CONFIG_NAMES or rel.endswith((".json", ".toml", ".yaml", ".yml")):
            head = text[:200_000]
            return (
                '"mcpServers"' in head
                or '"mcp_servers"' in head
                or "mcpServers:" in head
                or "mcp_servers:" in head
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
                [
                    *metadata_git_argv_prefix(),
                    "-C",
                    str(root),
                    "log",
                    "--no-show-signature",
                    "--no-ext-diff",
                    "--no-textconv",
                    "-1",
                    "--format=%an%x00%ae%x00%cI",
                    "--",
                    target,
                ],
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
                    self.ctx.warn(
                        "code.filesystem: git metadata has an unparseable commit timestamp; "
                        "enrichment skipped"
                    )
                    return {}
                return {"last_author": an, "last_author_email": ae, "last_commit": ci}
            if out.returncode == 0:
                return {}
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
        self.ctx.warn(
            "code.filesystem: offline git enrichment failed; Git 2.45+ and locally available history "
            "are required"
        )
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
                    # The check above is for its diagnostic; the read itself
                    # follows no link below the root, whatever changed since.
                    errors: list[str] = []
                    directory = open_confined_directory(root)
                    try:
                        content = read_text(PurePosixPath(cand), self.max_file_size, errors, dir_fd=directory)
                    finally:
                        os.close(directory)
                    for issue in errors:
                        self.ctx.error(f"code.filesystem: {cand}: {issue}")
                    for line in (content or "").splitlines():
                        line = line.split("#", 1)[0].strip()
                        if not line:
                            continue
                        parts = line.split()
                        if parts:
                            if len(rules) >= MAX_RULES or len(parts[0]) > MAX_PATTERN_LENGTH:
                                self.ctx.error(
                                    "code.filesystem: CODEOWNERS rule limit exceeded; ownership incomplete"
                                )
                                rules = []
                                self._ownership_exhausted.add(root)
                                break
                            rules.append((parts[0], parts[1:]))
                except (OSError, RuntimeError, ValueError):
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
                self.ctx.error(
                    "code.filesystem: CODEOWNERS aggregate processing budget exceeded; ownership incomplete"
                )
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
        self,
        label: str,
        root: Path,
        rel: str,
        kind: Kind,
        title: str,
        resource_type: str,
        *,
        identity_discriminator: str = "",
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
        self,
        label: str,
        root: Path,
        proj: _Project,
        covered_files: frozenset[str] = frozenset(),
    ) -> Iterator[Finding]:
        observations = self._project_observations(proj)
        # Anchors establish LLM / agent technology on their own. A credential
        # alone is already a SECRET finding, evidence that an MCP, manifest,
        # workflow or IaC finding already reports is not a project anchor, and
        # a vendor-neutral heuristic alone (a retry loop, subprocess.run)
        # describes ordinary automation.
        if any(
            m.signature.category != "heuristic" and rel not in covered_files and m.signal.type != "secret"
            for m, rel, _ in observations
        ):
            yield self._project_finding(label, root, proj, observations)
        for sig_id, files in proj.coding_agent_files.items():
            # Env-name and display-name mentions (GOOSE_PROVIDER in a detector
            # matrix, "GitHub Copilot" in an SDK adapter) are not configuration.
            # Config files, instruction docs, dependencies and code such as a
            # workflow step or a YOLO-mode flag still establish the agent.
            if not any(
                m.signal.type not in _MENTION_SIGNALS or _is_coding_agent_doc(PurePosixPath(rel).name)
                for m, rel, _ in proj.coding_agent_matches.get(sig_id, [])
            ):
                continue
            yield self._coding_agent_finding(label, root, proj, sig_id, files)

    @staticmethod
    def _project_observations(proj: _Project) -> list[_Observation]:
        """Return a project's technology evidence without policy or uncorroborated ambiguous matches."""
        observations = [
            (m, rel, snip) for (m, rel, snip) in proj.matches if m.signature.category not in {"policy"}
        ]
        # An ambiguous pattern is a common identifier outside the product
        # (aiohttp's ClientSession, a UI component named AgentCard). It counts
        # only when the same signature has library evidence in this project:
        # an import, a dependency or one of its specific code patterns.
        independent = {
            m.signature_id
            for m, _, _ in observations
            if m.signal.type in _LIBRARY_SIGNALS and not m.signal.ambiguous
        }
        return [t for t in observations if not t[0].signal.ambiguous or t[0].signature_id in independent]

    def _project_finding(
        self,
        label: str,
        root: Path,
        proj: _Project,
        observations: list[_Observation],
    ) -> Finding:
        """Build the finding that summarizes a project's frameworks, providers and capabilities."""
        evidence = _ProjectEvidence(
            observations,
            discount_tests=not self.include_tests,
            mcp_tools=proj.mcp_tools,
        )
        f = self._base(label, root, proj.root, Kind.FRAMEWORK_USAGE, "", "project")
        self._apply_project_evidence(f, evidence)
        if evidence.env_only:
            f.add_tag("env-names-only")
        self._attach_example_credentials(f, proj)
        self._attach_project_metadata(f, root, proj, evidence)
        if evidence.test_only:
            f.add_tag("test-code-only")
        finalize(f, self.index)
        if evidence.env_only:
            cap_confidence(f, ENV_ONLY_MAX_CONFIDENCE)
            f.metadata["confidence_cap"] = {"reason": "env-names-only", "maximum": ENV_ONLY_MAX_CONFIDENCE}
        f.title = self._project_title(f, proj)
        return f

    def _apply_project_evidence(self, f: Finding, evidence: _ProjectEvidence) -> None:
        # Decisive evidence must survive the per-signature report quota.
        decisive_first = sorted(evidence.matches, key=lambda item: not evidence.verified_indicator(item[0]))
        for m, rel, snip in decisive_first:
            if m.signature_id in evidence.uncorroborated and m.extra.get("lexical_source"):
                m.weight = min(m.weight, 0.6)
            observed = m.extra.get("source_capabilities")
            applied = (
                replace(m, signal=replace(m.signal, capabilities=observed)) if observed is not None else m
            )
            apply_matches(
                f,
                [applied],
                location=rel,
                snippet=snip,
                weight_scale=evidence.weight_scale(rel),
                capabilities=evidence.implies_capabilities(m, rel),
                signature_capabilities=observed is None
                and (evidence.verified_indicator(m) or m.signature.category != "framework"),
            )
        if "protocol.mcp" in f.frameworks and evidence.server_tools:
            self._apply_mcp_tools(f, evidence.server_tools)
        potential = {cap for m, _, _ in evidence.matches for cap in m.capabilities()} - set(f.capabilities)
        if potential:
            f.metadata["potential_capabilities"] = sorted(potential)
        # Repeated observations of one technology are correlated evidence.
        # Generic idioms share a single supporting group; loops in several
        # worker files must never accumulate into a confirmed AI agent.
        for item in f.evidence:
            category = item.attributes.get("category")
            item.attributes["confidence_group"] = (
                "heuristic-support"
                if category == "heuristic"
                else "uncorroborated-lexical"
                if item.signature in evidence.uncorroborated
                else item.signature or item.signal
            )

    def _attach_project_metadata(
        self,
        f: Finding,
        root: Path,
        proj: _Project,
        evidence: _ProjectEvidence,
    ) -> None:
        """Record a project's owner, history, inventory and agent indicators."""
        matches = evidence.matches
        git = self._git_info(root, proj.root)
        f.metadata.update(git)
        if git.get("last_commit"):
            f.last_seen = git["last_commit"]
        f.owner, by_file = self._owners_for_files(root, (rel for _, rel, _ in matches))
        f.owner = f.owner or (git.get("last_author_email") if not by_file else None) or self.owner
        if by_file:
            f.metadata["codeowners_by_file"] = by_file
        f.metadata["files_scanned"] = proj.files
        f.metadata["languages"] = sorted(proj.languages)
        f.metadata["dependencies_matched"] = sorted(
            {
                f"{m.signal.ecosystem or 'any'}:{m.value}"
                for m, _, _ in matches
                if m.signal.type == "dependency"
            }
        )
        f.metadata["models"] = sorted({m.value for m, _, _ in matches if m.signal.type == "model"})
        f.models = f.metadata["models"]
        if proj.agent_defs:
            f.metadata["agent_definitions"] = proj.agent_defs
        # Installed SDKs, imports and endpoint strings establish framework
        # use. MCP code/config alone establishes a tool server/client, not
        # an agent capable of choosing actions or planning.
        f.metadata["agent_indicators"] = sum(
            evidence.verified_indicator(m)
            and m.signal.type in {"code", "file"}
            and not evidence.in_tests(rel)
            for m, rel, _ in matches
        )
        if any(
            m.extra.get("agent_classification") == "openai-responses-tool-dispatch"
            and evidence.verified_indicator(m)
            and not evidence.in_tests(rel)
            for m, rel, _ in matches
        ):
            f.metadata["agent_classification"] = "openai-responses-tool-dispatch"

    def _coding_agent_finding(
        self,
        label: str,
        root: Path,
        proj: _Project,
        sig_id: str,
        files: list[str],
    ) -> Finding:
        """Build the finding for one coding-agent product configured in a project."""
        sig = self.index.get(sig_id)
        where = proj.root if proj.root != "." else "repository root"
        f = self._base(
            label,
            root,
            proj.root,
            Kind.AGENT_CONFIG,
            f"{sig.name if sig else sig_id} configured in {where}",
            "coding-agent-config",
            identity_discriminator=f"coding-agent-config:{sig_id}",
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
        return f

    @staticmethod
    def _apply_mcp_tools(f: Finding, server_tools: dict[str, str]) -> None:
        """Derive MCP server capabilities from the tool names it registers."""
        tools = sorted(server_tools)
        f.metadata["mcp_tools"] = tools[:50]
        implied: dict[str, list[str]] = {}
        for tool in tools:
            for capability in mcp_tool_capabilities(tool):
                implied.setdefault(capability, []).append(tool)
        for capability, names in sorted(implied.items()):
            f.add_capability(capability)
            f.add_evidence(
                Evidence(
                    signal=f"mcp-tool:{capability}",
                    description=(
                        f"registers MCP tools implying {capability}: "
                        f"{', '.join(names[:5])}{' …' if len(names) > 5 else ''}"
                    ),
                    location=server_tools[names[0]],
                    weight=0.5,
                    signature="protocol.mcp",
                    attributes={"category": "protocol", "value": names[0]},
                )
            )

    def _fold_manifest(self, project: Finding, manifest: Finding, proj: _Project) -> None:
        """Merge a project manifest into the finding of the project that contains it.

        A CrewAI ``agents.yaml`` or a ``langgraph.json`` configures the agent
        implemented by that project's code, so the project is an agent and the
        manifest's evidence, technologies and details move onto it instead of
        counting the same agent twice. The manifest stays visible under
        ``metadata.manifests``.
        """
        for evidence in manifest.evidence:
            project.add_evidence(evidence)
        for sid in manifest.frameworks:
            project.add_framework(sid)
        for pid in manifest.model_providers:
            project.add_model_provider(pid)
        for capability in manifest.capabilities:
            project.add_capability(capability)
        for tag in manifest.tags:
            project.add_tag(tag)
        for model in manifest.models:
            if model not in project.models:
                project.models.append(model)
        details = {
            k: v
            for k, v in manifest.metadata.items()
            if k not in {"path", "scan_root", "technologies", "evidence_counts"}
        }
        project.metadata.setdefault("manifests", []).append(
            {
                "path": manifest.metadata.get("path"),
                "title": manifest.title,
                "resource": manifest.resource,
                **details,
            }
        )
        project.metadata["agent_indicators"] = max(1, int(project.metadata.get("agent_indicators") or 0))
        project.kind = Kind.AGENT
        finalize(project, self.index)
        project.title = self._project_title(project, proj)

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
                    attributes={
                        "category": m.signature.category,
                        "value": redact(m.value),
                        "placeholder": reason,
                    },
                )
            )
        # The key name must not read as a credential field, or the report
        # sanitizer withholds the file list itself.
        f.metadata["placeholder_samples"] = {
            "count": len(proj.example_credentials),
            "files": sorted(files)[:MAX_EXAMPLE_CREDENTIAL_EVIDENCE],
        }

    def _project_title(self, f: Finding, proj: _Project) -> str:
        order = {"framework": 0, "cloud-service": 1, "platform": 2, "protocol": 3}
        ranked = sorted(
            (sig for sid in f.frameworks if (sig := self.index.get(sid)) and sig.category in order),
            key=lambda s: order[s.category],
        )
        names = [s.name for s in ranked[:4]]
        provs = [
            self.index.get(sid).name  # type: ignore[union-attr]
            for sid in f.model_providers[:3]
            if self.index.get(sid)
        ]
        where = "repository root" if proj.root == "." else proj.root
        what = "Agent" if f.kind == Kind.AGENT else "LLM usage"
        detail = ", ".join(names) or ", ".join(provs)
        if not detail:
            # Only supporting technology (a search tool, a vector store,
            # tracing): name it rather than claim an LLM SDK.
            support = [s.name.split(" (", 1)[0] for sid in f.frameworks if (s := self.index.get(sid))]
            detail = ", ".join(support[:3]) or "LLM SDK"
            if support and f.kind != Kind.AGENT:
                what = "AI tooling"
        return f"{what} in {where}: {detail}"

    def _mcp_finding(self, label: str, root: Path, rel: str, servers: list[dict[str, Any]]) -> Finding:
        enabled = [server for server in servers if not server["disabled"]]
        f = self._base(label, root, rel, Kind.MCP_SERVER, f"MCP configuration: {rel}", "mcp-config")
        sig = self.index.get("protocol.mcp")
        f.add_framework("protocol.mcp")
        f.add_capability("tool-use")
        f.add_evidence(
            Evidence(
                signal="file:protocol.mcp",
                description=f"MCP client/server configuration file {rel}",
                location=rel,
                weight=0.95,
                signature="protocol.mcp",
            )
        )
        remote_hosts: list[str] = []
        for s in enabled:
            urls = s.get("urls")
            if not isinstance(urls, list):
                urls = [s["url"]] if s.get("url") else []
            for url in urls:
                if not isinstance(url, str):
                    continue
                for m in self.index.match_domains_in_text(url):
                    if m.signature.category != "identity-app":
                        apply_matches(f, [m], location=rel)
                if url not in remote_hosts:
                    remote_hosts.append(url)
            for env_name in s.get("env_names", []):
                for m in self.index.match_env(env_name):
                    apply_matches(f, [m], location=rel, weight_scale=0.5)
            if s.get("secrets_inline"):
                f.add_tag("inline-secrets")
                f.add_evidence(
                    Evidence(
                        signal="secret:inline",
                        description=(
                            f"MCP server '{s['name']}' has credential-looking values inline "
                            f"({', '.join(s.get('secret_locations') or ['configuration'])})"
                        ),
                        location=rel,
                        weight=0.3,
                    )
                )
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
            self._file_errors(rel, validation.errors)
            return None
        # Retain sibling credential context before projecting descriptive fields.
        # An opaque secret may also appear in a description, URL or dependency.
        data = sanitize(validation.data)
        f = self._base(label, root, rel, Kind.AGENT, "", "agent-manifest")
        if kind == "a2a":
            self._describe_a2a_card(f, rel, data)
        elif kind == "m365":
            self._describe_m365_agent(f, rel, data)
        elif kind == "langgraph":
            self._describe_langgraph_manifest(f, rel, data)
        elif kind == "crewai":
            self._describe_crewai_agents(f, rel, data)
        f.owner = self._owner_for(root, rel) or f.owner
        finalize(f, self.index)
        f.kind = Kind.AGENT
        return f

    def _describe_a2a_card(self, f: Finding, rel: str, data: dict[str, Any]) -> None:
        f.title = f"A2A agent card: {data.get('name') or rel}"
        f.add_framework("protocol.a2a")
        f.add_capability("multi-agent")
        f.add_evidence(
            Evidence(
                signal="file:protocol.a2a",
                description="A2A Agent Card",
                location=rel,
                weight=0.95,
                signature="protocol.a2a",
            )
        )
        f.metadata["agent_card"] = {
            "name": data.get("name"),
            "description": truncate(sanitize_text(str(data.get("description", ""))), 300),
            "url": data.get("url"),
            "version": data.get("version"),
            "protocol_version": data.get("protocolVersion"),
            "skills": [
                s.get("name") or s.get("id") for s in data.get("skills", []) or [] if isinstance(s, dict)
            ],
            "capabilities": _clip(data.get("capabilities")),
            "security_schemes": _clip(
                list((data.get("securitySchemes") or {}).keys())
                if isinstance(data.get("securitySchemes"), dict)
                else data.get("authentication")
            ),
        }
        if data.get("url"):
            apply_matches(f, self.index.match_domains_in_text(str(data["url"])), location=rel)
        if not data.get("securitySchemes") and not data.get("authentication"):
            f.add_tag("no-auth-declared")

    @staticmethod
    def _describe_m365_agent(f: Finding, rel: str, data: dict[str, Any]) -> None:
        f.title = f"M365 Copilot declarative agent: {data.get('name') or rel}"
        f.add_framework("platform.m365-declarative-agent")
        f.add_evidence(
            Evidence(
                signal="file:platform.m365-declarative-agent",
                description="Microsoft 365 declarative agent manifest",
                location=rel,
                weight=0.95,
                signature="platform.m365-declarative-agent",
            )
        )
        f.metadata["declarative_agent"] = {
            "name": data.get("name"),
            "description": truncate(sanitize_text(str(data.get("description", ""))), 300),
            "instructions": truncate(sanitize_text(str(data.get("instructions", ""))), 300),
            "capabilities": [
                c.get("name") for c in data.get("capabilities", []) or [] if isinstance(c, dict)
            ],
            "actions": [
                a.get("id") or a.get("file") for a in data.get("actions", []) or [] if isinstance(a, dict)
            ],
            "conversation_starters": len(data.get("conversation_starters", []) or []),
        }
        if data.get("actions"):
            f.add_capability("tool-use")

    @staticmethod
    def _describe_langgraph_manifest(f: Finding, rel: str, data: dict[str, Any]) -> None:
        f.title = f"LangGraph deployment manifest: {rel}"
        f.add_framework("framework.langgraph")
        f.add_evidence(
            Evidence(
                signal="file:framework.langgraph",
                description="langgraph.json deployment manifest",
                location=rel,
                weight=0.95,
                signature="framework.langgraph",
            )
        )
        graphs = data.get("graphs", {}) or {}
        f.metadata["graphs"] = _clip(list(graphs.keys()) if isinstance(graphs, dict) else graphs)
        f.metadata["dependencies"] = _clip(data.get("dependencies"))
        env = data.get("env")
        f.metadata["env_names"] = sorted(env) if isinstance(env, dict) else []
        if isinstance(env, str):
            f.metadata["env_file"] = sanitize_text(env)
        f.add_capability("tool-use")

    def _describe_crewai_agents(self, f: Finding, rel: str, data: dict[str, Any]) -> None:
        f.title = f"CrewAI agent definitions: {rel}"
        f.add_framework("framework.crewai")
        f.add_capability("multi-agent")
        f.add_evidence(
            Evidence(
                signal="file:framework.crewai",
                description="CrewAI agents.yaml",
                location=rel,
                weight=0.9,
                signature="framework.crewai",
            )
        )
        f.metadata["agents"] = [
            {
                "name": k,
                "role": truncate(sanitize_text(str((v or {}).get("role", ""))), 120),
                "llm": (v or {}).get("llm"),
            }
            for k, v in data.items()
            if isinstance(v, dict)
        ]
        for v in data.values():
            if isinstance(v, dict) and v.get("llm"):
                apply_matches(
                    f,
                    self.index.match_model(str(v["llm"]).split("/")[-1]),
                    location=rel,
                    weight_scale=0.6,
                )

    def _workflow_finding(self, label: str, root: Path, rel: str, hits: list[tuple[Match, str]]) -> Finding:
        f = self._base(label, root, rel, Kind.WORKFLOW, "", "workflow-export")
        # A workflow export kept as a test or fixture input exercises the
        # importer; it is not a deployed workflow. Apply the project policy:
        # half weight and an explicit tag, unless test code is included.
        test_only = not self.include_tests and _is_test_path(rel)
        for m, snip in hits:
            apply_matches(f, [m], location=rel, snippet=snip, weight_scale=0.5 if test_only else 1.0)
        if test_only:
            f.add_tag("test-code-only")
        names = {
            self.index.get(m.signature_id).name  # type: ignore[union-attr]
            for m, _ in hits
            if m.signature.category != "provider" and self.index.get(m.signature_id)
        }
        f.title = f"Exported AI workflow ({', '.join(sorted(names))}): {rel}"
        f.owner = self._owner_for(root, rel) or f.owner
        finalize(f, self.index)
        f.kind = Kind.WORKFLOW
        return f

    def _infra_finding(
        self,
        label: str,
        root: Path,
        rel: str,
        hits: list[tuple[Match, str, str]],
        names_found: list[str] | None = None,
        *,
        wildcards: list[tuple[str, int, str]] | None = None,
        models: list[Match] | None = None,
    ) -> Finding:
        f = self._base(label, root, rel, Kind.INFRA, "", "iac")
        for m, _value, snip in hits:
            apply_matches(f, [m], location=rel, snippet=snip)
        for m in models or []:
            apply_matches(f, [m], location=rel)
            if m.value not in f.models:
                f.models.append(m.value)
        for source, line, snip in (wildcards or [])[:5]:
            f.add_tag("wildcard-permissions")
            f.add_evidence(
                Evidence(
                    signal="iac:iam-wildcard",
                    description="IAM statement in the same project grants wildcard actions",
                    location=f"{source}:{line}",
                    snippet=snip,
                    weight=0.5,
                )
            )
        names = {
            self.index.get(m.signature_id).name  # type: ignore[union-attr]
            for m, _, _ in hits
            if self.index.get(m.signature_id)
        }
        resources = sorted({v for _, v, _ in hits})
        f.title = f"Infrastructure provisions {', '.join(sorted(names))}: {rel}"
        f.metadata["resources"] = resources
        if names_found:
            f.metadata["names"] = names_found
        f.owner = self._owner_for(root, rel) or f.owner
        finalize(f, self.index)
        f.kind = Kind.INFRA
        return f

    def _secret_finding(
        self,
        label: str,
        root: Path,
        rel: str,
        hits: list[tuple[Match, str]],
    ) -> Finding | None:
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
        # Test, fixture and recorded-cassette paths follow the project test-code
        # policy: half weight and an explicit tag unless test code is included.
        # The credential is still reported: cassettes record real traffic, and a
        # key committed under tests/ is as exposed as one anywhere else.
        test_only = not self.include_tests and _is_test_path(rel)
        for m, snip in hits:
            apply_matches(f, [m], location=rel, snippet=snip, weight_scale=0.5 if test_only else 1.0)
        f.add_tag("hardcoded-credential")
        if test_only:
            f.add_tag("test-code-only")
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
                fm = strict_bounded_safe_load(m.group(1)) or {}
            except (ValueError, RecursionError, yaml.YAMLError):
                # Includes resource limits, duplicate fields, non-finite
                # numbers, and SafeLoader's plain ValueError for an
                # impossible date or an over-long integer.
                self.ctx.error(f"code.filesystem: {rel}: invalid agent definition YAML")
                fm = {}
            if isinstance(fm, dict):
                fm = sanitize(fm)
                for k in (
                    "name",
                    "description",
                    "tools",
                    "model",
                    "permissionMode",
                    "mode",
                    "globs",
                    "alwaysApply",
                ):
                    if k in fm:
                        v = fm[k]
                        info[k] = (
                            truncate(sanitize_text(v), 200) if isinstance(v, str) else _clip(sanitize(v))
                        )
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


def _project_root(root: Path, rel: str) -> str:
    """The project a file at ``rel`` belongs to, as ``_iter_entries`` assigns it.

    That is the deepest ancestor directory below the scan root holding a
    project marker, or ``"."``. Used for the rare symlink checks only.
    """
    for parent in PurePosixPath(rel).parents:
        directory = parent.as_posix()
        if directory == ".":
            break
        try:
            names = os.listdir(root / directory)
        except OSError:
            continue
        if _marks_project(root / directory, names):
            return directory
    return "."


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
# Gemini CLI names its Streamable HTTP endpoint `httpUrl` (`url` is SSE).
_MCP_URL_KEYS = ("url", "httpUrl", "serverUrl", "endpoint")
# Spellings of one MCP server field; an entry that sets more than one is ambiguous.
_MCP_FIELD_ALIASES: tuple[tuple[str, ...], ...] = (
    ("env", "environment"),
    _MCP_URL_KEYS,
    ("type", "transport"),
    ("autoApprove", "alwaysAllow"),
)


def _without_xml_comments(text: str) -> str:
    """Mask XML comments while preserving character offsets and source lines."""
    return re.sub(r"<!--.*?(?:-->|$)", lambda match: re.sub(r"[^\n]", " ", match.group()), text, flags=re.S)


_NO_STRUCTURE = object()


def _structured_context(rel: str, text: str) -> Any:
    """Parse the structure that supplies credential context for excerpt redaction.

    Returns ``_NO_STRUCTURE`` for plain text and for structured files whose
    syntax or shape the dedicated parser rejects; lexical redaction then
    applies. Resource-limit and integrity failures (duplicate fields,
    non-finite numbers) propagate: they must reach the per-file isolation
    boundary even when nothing is excerpted, since lexical fallback would
    otherwise disguise an incomplete analysis. An unrendered Helm, Jinja or
    Go template is the exception to the integrity rule: its raw text is not
    YAML, so a placeholder such as ``{{ .Values.image }}`` reads as a mapping
    key and conditional branches repeat fields. It falls back to lexical
    redaction like any other template the parser rejects.
    """
    try:
        if rel.endswith(_JSON_SUFFIXES):
            return _load_json_lenient(text)
        if rel.endswith(".toml"):
            return tomllib.loads(text)
        if rel.endswith(_YAML_SUFFIXES):
            return strict_bounded_safe_load(text, require_string_keys=False)
    except YAMLIntegrityError:
        if has_template_markers(text):
            return _NO_STRUCTURE
        raise
    except (JSONIntegrityError, YAMLResourceLimitError, SanitizationLimitError):
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
        result: str = sanitize((structure, text))[1]
        return result
    except (YAMLResourceLimitError, SanitizationLimitError):
        raise
    except (ValueError, RecursionError, yaml.YAMLError):
        return sanitize_text(text)


def _safe_source_text(rel: str, text: str) -> str:
    """Use structured credential context while retaining source line positions."""
    return _redacted_source(text, _structured_context(rel, text))


# `Bearer $TOKEN`: Gemini CLI expands shell-style variables in env and headers.
_SHELL_ENV_REFERENCE = re.compile(r"(?:[A-Za-z][\w-]*[ \t]+)?\$[A-Z_][A-Z0-9_]*")
# `GOOGLE_APPLICATION_CREDENTIALS=/app/key.json` names a credential file; the
# path is redacted with the rest of the argument but is not an inline secret.
_CREDENTIAL_FILE_ARGUMENT = re.compile(
    r"[A-Z][A-Z0-9_]*(?:CREDENTIALS|_FILE|_PATH)=(?:/|\./|\.\./|~/)[A-Za-z0-9_./@%+-]*"
)


# An environment value under a sensitive key is redacted wherever it repeats.
# When that value is itself a variable reference, its repetition in an
# argument (`-v ${KEY_FILE}:/app/key.json`) does not disclose a secret.
_VARIABLE_REFERENCE = r"(?:\$\{\{[^}\r\n]{1,200}\}\}|\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Z_][A-Z0-9_]*)"


def _only_references_redacted(before: str, after: str) -> bool:
    parts = after.split(REDACTED)
    if len(parts) < 2:
        return False
    pattern = _VARIABLE_REFERENCE.join(re.escape(part) for part in parts)
    return re.fullmatch(pattern, before) is not None


def _args_reveal_secret(args: list[Any], sanitized: Any) -> bool:
    """True when sanitizing changed an argument that could carry a credential value.

    A credential-file path assignment and an argument whose only redacted
    parts are variable references remain redacted, but are not inline secrets.
    """
    if not isinstance(sanitized, list) or len(sanitized) != len(args):
        return bool(sanitized != args)
    return any(
        before != after
        and not (
            isinstance(before, str)
            and isinstance(after, str)
            and (_CREDENTIAL_FILE_ARGUMENT.fullmatch(before) or _only_references_redacted(before, after))
        )
        for before, after in zip(args, sanitized, strict=True)
    )


_WORKFLOW_PATH = re.compile(r"(?:^|/)\.github/workflows/[^/]+\.ya?ml$")
_EMBEDDED_MCP_MARKERS = ('"mcpServers"', '"mcp_servers"')


def _embedded_workflow_mcp(workflow: Any, errors: list[str]) -> dict[str, Any]:
    """Collect MCP servers passed as JSON strings to workflow step inputs.

    Agent actions take their MCP configuration as a step input, for example
    `run-gemini-cli` `settings` or `claude-code-action` `mcp_config`. The
    workflow itself is not an MCP document, so only those embedded objects
    are parsed. Server names repeated across steps keep a numbered suffix.
    """
    servers: dict[str, Any] = {}
    jobs = workflow.get("jobs") if isinstance(workflow, dict) else None
    for job in jobs.values() if isinstance(jobs, dict) else ():
        steps = job.get("steps") if isinstance(job, dict) else None
        for step in steps if isinstance(steps, list) else ():
            inputs = step.get("with") if isinstance(step, dict) else None
            for value in inputs.values() if isinstance(inputs, dict) else ():
                if not (
                    isinstance(value, str)
                    and value.lstrip().startswith("{")
                    and any(marker in value for marker in _EMBEDDED_MCP_MARKERS)
                ):
                    continue
                try:
                    embedded = _load_json_lenient(value)
                except (ValueError, RecursionError):
                    errors.append("invalid embedded MCP configuration syntax")
                    continue
                container = (
                    embedded.get("mcpServers", embedded.get("mcp_servers"))
                    if isinstance(embedded, dict)
                    else None
                )
                if not isinstance(container, dict):
                    errors.append("embedded MCP servers must be an object")
                    continue
                for name, cfg in container.items():
                    key, suffix = str(name), 2
                    while key in servers:
                        key, suffix = f"{name}#{suffix}", suffix + 1
                    servers[key] = cfg
    return {"mcpServers": servers} if servers else {}


def _parse_mcp_servers(rel: str, text: str, errors: list[str] | None = None) -> list[dict[str, Any]]:
    errors = errors if errors is not None else []
    data = _load_mcp_document(rel, text, errors)
    if data is None:
        return []
    servers = _mcp_server_entries(data, errors)
    if servers is None:
        return []
    out: list[dict[str, Any]] = []
    for name, cfg in servers.items():
        server = _mcp_server_record(name, cfg, errors)
        if server is not None:
            out.append(server)
    # Each output key is generated by this parser. Preserve its schema while
    # sanitizing all values in the context of the entire source document.
    names = [tuple(server) for server in out]
    projected = [[server[key] for key in keys] for server, keys in zip(out, names, strict=True)]
    cleaned = sanitize((data, projected))[1]
    return [dict(zip(keys, values, strict=True)) for keys, values in zip(names, cleaned, strict=True)]


def _load_mcp_document(rel: str, text: str, errors: list[str]) -> dict[str, Any] | None:
    data: Any  # untrusted repository content; every shape is checked below
    try:
        if rel.endswith(".toml"):
            data = tomllib.loads(text)
        elif _WORKFLOW_PATH.search(rel):
            # GitHub's `on:` key is a YAML 1.1 boolean, so a workflow needs the
            # configuration loader that permits non-string mapping keys.
            data = _embedded_workflow_mcp(strict_bounded_safe_load(text, require_string_keys=False), errors)
        elif rel.endswith((".yaml", ".yml")):
            data = strict_bounded_safe_load(text)
        else:
            data = _load_json_lenient(text)
    except (ValueError, RecursionError, yaml.YAMLError):
        errors.append("invalid MCP configuration syntax")
        return None
    if not isinstance(data, dict):
        errors.append("MCP configuration must be an object")
        return None
    return data


def _mcp_server_entries(data: dict[str, Any], errors: list[str]) -> dict[Any, Any] | None:
    """Return the server table of a client configuration or registry manifest, keyed by name."""
    mcp = data.get("mcp", {})
    if not isinstance(mcp, dict):
        errors.append("MCP mcp field must be an object")
        mcp = {}
    containers: list[Any] = []
    for key in ("mcp_servers", "mcpServers", "servers"):
        if key in data:
            containers.append(data[key])
    if "servers" in mcp:
        containers.append(mcp["servers"])
    if len(containers) > 1:
        errors.append("multiple MCP server containers are ambiguous")
        return None
    servers: Any = containers[0] if containers else {}
    if servers is None:
        servers = {}
    if isinstance(servers, list):
        if any(not isinstance(server, dict) for server in servers):
            errors.append("MCP server entries must be objects")
        named_servers: dict[str, dict[str, Any]] = {}
        for i, server in enumerate(servers):
            if not isinstance(server, dict):
                continue
            name = str(server.get("name", i))
            if name in named_servers:
                errors.append("duplicate MCP server names are ambiguous")
                return None
            named_servers[name] = server
        servers = named_servers
    if not servers and isinstance(data.get("name"), str) and (data.get("packages") or data.get("remotes")):
        servers = {data["name"]: data}
    if not isinstance(servers, dict):
        errors.append("MCP servers must be an object or array")
        return None
    return servers


def _mcp_server_record(name: Any, cfg: Any, errors: list[str]) -> dict[str, Any] | None:
    """Project one configured server to its reported fields; None when it is not a usable entry."""
    if not isinstance(cfg, dict):
        errors.append("MCP server entry must be an object")
        return None
    if any(sum(alias in cfg for alias in aliases) > 1 for aliases in _MCP_FIELD_ALIASES):
        # Which spelling a client honors is not knowable here; picking one
        # could hide the credentials or endpoint the other one configures.
        errors.append("MCP server entry contains ambiguous field aliases")
        return None
    env = _mcp_mapping(_mcp_alias(cfg, ("env", "environment"), {}), "env", errors)
    headers = _mcp_mapping(cfg.get("headers", {}), "headers", errors)
    urls = _mcp_urls(cfg, errors)
    url = urls[0] if urls else None
    command = cfg.get("command")
    if command is not None and not isinstance(command, str):
        errors.append("MCP command must be a string")
        command = None
    if not (command and command.strip()) and not (url and url.strip()) and not _has_mcp_package(cfg):
        if cfg.get("disabled") is not True and cfg.get("enabled") is not False:
            errors.append("MCP server entry has no command, URL, or valid package")
        return None
    args = cfg.get("args", [])
    args = [] if args is None else args
    if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
        errors.append("MCP args must be an array of strings")
        args = []
    inline_locations = _inline_secret_locations(env, headers)
    transport = _mcp_alias(cfg, ("type", "transport"), "stdio" if command else ("http" if url else "unknown"))
    if not isinstance(transport, str):
        errors.append("MCP transport must be a string")
        transport = "unknown"
    # Project only after sanitizing with the entire config: a credential in
    # env/headers may be repeated as an otherwise unrecognizable argument.
    field_names = (
        "name",
        "transport",
        "command",
        "args",
        "url",
        "urls",
        "env_names",
        "headers",
        "auto_approve",
    )
    clean_values = sanitize(
        (
            cfg,
            [
                str(name),
                transport,
                command,
                args,
                url,
                urls,
                sorted(str(key) for key in env),
                sorted(str(key) for key in headers),
                _mcp_alias(cfg, ("autoApprove", "alwaysAllow"), None),
            ],
        )
    )[1]
    safe = dict(zip(field_names, clean_values, strict=True))
    inline_locations += [
        location
        for location, changed in (
            ("args", _args_reveal_secret(args, safe["args"])),
            ("url", safe["url"] != url or safe["urls"] != urls),
            ("command", safe["command"] != command),
        )
        if changed
    ]
    safe["args"] = safe["args"][:12]
    safe["secrets_inline"] = bool(inline_locations)
    if inline_locations:
        safe["secret_locations"] = inline_locations
    safe["disabled"] = _mcp_disabled(cfg, errors)
    return safe


def _mcp_mapping(value: Any, section: str, errors: list[str]) -> dict[Any, Any]:
    """Return an ``env``/``headers`` table; an absent one is empty and a malformed one is reported."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        errors.append(f"MCP {section} must be an object")
        return {}
    return value


def _mcp_alias(cfg: dict[str, Any], aliases: tuple[str, ...], default: Any) -> Any:
    """Return the value of the one alias present in ``cfg`` (callers reject several), else ``default``.

    Presence, not truthiness, selects the field: an empty or false value must
    not let a lower-precedence spelling supply a different one.
    """
    return next((cfg[key] for key in aliases if key in cfg), default)


def _mcp_urls(cfg: dict[str, Any], errors: list[str]) -> list[str]:
    """Return every endpoint of a server: its own URL field, then each registry remote.

    Every remote is kept so detection and risk see all of them, not only the
    first one listed.
    """
    urls: list[str] = []
    direct_url = _mcp_alias(cfg, _MCP_URL_KEYS, None)
    if direct_url is not None:
        if not isinstance(direct_url, str):
            errors.append("MCP url must be a string")
        elif direct_url.strip():
            urls.append(direct_url)
    remotes = cfg.get("remotes")
    if remotes is not None:
        if not isinstance(remotes, list):
            errors.append("MCP remotes must be an array")
        else:
            for remote in remotes:
                if not isinstance(remote, dict):
                    errors.append("MCP remote entry must be an object")
                    continue
                remote_url = remote.get("url")
                if remote_url is not None and not isinstance(remote_url, str):
                    errors.append("MCP remote url must be a string")
                elif isinstance(remote_url, str) and remote_url.strip():
                    urls.append(remote_url)
    return list(dict.fromkeys(urls))


def _has_mcp_package(cfg: dict[str, Any]) -> bool:
    """Whether a registry entry names at least one installable package."""
    packages = cfg.get("packages")
    return isinstance(packages, list) and any(
        isinstance(package, dict)
        and isinstance(package.get("registryType"), str)
        and isinstance(package.get("identifier"), str)
        and package["identifier"].strip()
        for package in packages
    )


def _inline_secret_locations(env: dict[Any, Any], headers: dict[Any, Any]) -> list[str]:
    """Name the tables that hold a credential-looking literal rather than a reference."""
    return [
        location
        for location, items in (("env", env.items()), ("headers", headers.items()))
        if any(
            isinstance(value, str)
            and value
            and not value.startswith("${")
            and not _SHELL_ENV_REFERENCE.fullmatch(value)
            and not looks_like_placeholder(value)
            and _SECRETISH.search(str(key))
            and len(value) >= 12
            for key, value in items
        )
    ]


def _mcp_disabled(cfg: dict[str, Any], errors: list[str]) -> bool:
    """Whether a server is switched off; malformed activation flags count as disabled."""
    disabled = cfg.get("disabled", False)
    enabled = cfg.get("enabled", True)
    if not isinstance(disabled, bool) or not isinstance(enabled, bool):
        errors.append("MCP enabled/disabled flags must be booleans")
        # Unknown activation state cannot substantiate an active server.
        return True
    return disabled or not enabled
