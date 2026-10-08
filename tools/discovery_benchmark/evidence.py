"""Independent evidence extraction used to label ground truth.

This module is deliberately simpler than any tool under test: it reads
dependency manifests, lock files, import statements, well-known configuration
paths, a few code constructs, infrastructure-as-code resources and service
hostnames, and maps each onto the shared taxonomy with file:line pointers. It
never executes repository content. Facts seen only in lock files or indirect
Go requirements are reported separately as *tolerated*: a tool may claim them
without penalty, but they are not required.
"""

from __future__ import annotations

import json
import os
import re
import tomllib
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from tools.discovery_benchmark import taxonomy

SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "vendor",
        "dist",
        "build",
        ".venv",
        "venv",
        "__pycache__",
        "site-packages",
        "third_party",
        "thirdparty",
        "target",
        ".next",
        ".turbo",
        ".cache",
        "bower_components",
        ".tox",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        ".gradle",
    }
)
MAX_FILE_BYTES = 2_000_000
MAX_NOTEBOOK_BYTES = 20_000_000
MAX_FILES = 80_000
MAX_HITS_PER_FACT = 6
MAX_IMPORTS_PER_FILE = 3000

DOC_SUFFIXES = frozenset({".md", ".mdx", ".rst", ".txt", ".html", ".htm", ".adoc", ".pdf", ".svg"})
BINARY_SUFFIXES = frozenset(
    {
        ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".otf", ".eot",
        ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".jar", ".war", ".class", ".so", ".dylib",
        ".dll", ".exe", ".bin", ".pyc", ".whl", ".parquet", ".npy", ".npz", ".pt", ".pth", ".onnx",
        ".gguf", ".safetensors", ".mp3", ".mp4", ".wav", ".mov", ".avi", ".pdf", ".lock",
    }
)  # fmt: skip
PY_IMPORT = re.compile(r"^\s*(?:from\s+([\w.]+)\s+import\b|import\s+([\w.]+(?:\s*,\s*[\w.]+)*))", re.M)
PY_AGENTS_IMPORT = re.compile(r"^\s*from\s+agents\s+import\s+\(?([^\n)]+)", re.M)
OPENAI_AGENTS_NAMES = frozenset(
    {"Agent", "Runner", "function_tool", "handoff", "RunConfig", "ModelSettings", "WebSearchTool", "trace",
     "AgentHooks", "RunContextWrapper", "ItemHelpers", "set_default_openai_key", "FileSearchTool",
     "ComputerTool", "InputGuardrail", "OutputGuardrail", "GuardrailFunctionOutput", "SQLiteSession"}
)  # fmt: skip
NB_PIP = re.compile(r"^\s*[!%]\s*(?:pip3?|uv pip)\s+install\s+(.+)$", re.M)
JS_IMPORT = re.compile(
    r"""(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\s*\(\s*)['"]([^'"\n]+)['"]""",
)
GO_IMPORT_BLOCK = re.compile(r"^import\s*\((.*?)^\)", re.M | re.S)
GO_IMPORT_ONE = re.compile(r'^import\s+(?:\w+\s+)?"([^"]+)"', re.M)
GO_QUOTED = re.compile(r'"([^"]+)"')
JAVA_IMPORT = re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+)", re.M)
CS_USING = re.compile(r"^\s*(?:global\s+)?using\s+(?:static\s+)?([\w.]+)\s*;", re.M)
RS_USE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?use\s+([\w:]+)|^\s*extern\s+crate\s+(\w+)", re.M)
REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
EGG = re.compile(r"#egg=([A-Za-z0-9._-]+)")
POM_DEP = re.compile(r"<dependency>(.*?)</dependency>", re.S)
POM_GROUP = re.compile(r"<groupId>\s*([^<\s]+)\s*</groupId>")
POM_ARTIFACT = re.compile(r"<artifactId>\s*([^<\s]+)\s*</artifactId>")
GRADLE_COORD = re.compile(r"""['"]([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+)(?::[^'"]*)?['"]""")
GRADLE_GROUP_NAME = re.compile(r"""group\s*[:=]\s*['"]([^'"]+)['"]\s*,\s*name\s*[:=]\s*['"]([^'"]+)['"]""")
NUGET_REF = re.compile(r"""<(?:PackageReference|PackageVersion)\s+[^>]*Include=["']([^"']+)["']""")
NUGET_CONFIG = re.compile(r"""<package\s+id=["']([^"']+)["']""")
CSPROJ_SUFFIXES = frozenset({".csproj", ".fsproj", ".vbproj", ".props", ".targets"})
SETUP_REQ = re.compile(r"(?:install_requires|extras_require)\s*=\s*([\[{].*?[\]}])", re.S)
QUOTED = re.compile(r"""['"]([A-Za-z0-9][A-Za-z0-9._\[\]-]*)[^'"]*['"]""")
PNPM_PKG = re.compile(r"^\s+/?(@?[a-z0-9][^@\s'\"]*)@[0-9]", re.M)
YARN_PKG = re.compile(r'^"?(@?[^@"\s,]+)@', re.M)
GRADLE_LOCK = re.compile(r"^([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):", re.M)

CODE_SUFFIXES = frozenset(
    {".py", ".pyi", ".ipynb", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts", ".vue",
     ".svelte", ".go", ".java", ".kt", ".kts", ".scala", ".groovy", ".cs", ".fs", ".rs", ".rb", ".php",
     ".swift", ".dart", ".sh", ".bash", ".ps1", ".tf", ".bicep", ".json", ".yaml", ".yml", ".toml",
     ".ini", ".cfg", ".conf", ".properties", ".xml", ".env", ".hcl", ".sql", ".proto", ".graphql"}
)  # fmt: skip
TEXT_BASENAMES = frozenset({"dockerfile", "makefile", "justfile", "procfile", "modelfile", "pipfile", ".env"})

_CONFIG_PATHS = taxonomy.config_rules()

TF_RULES: tuple[tuple[str, str], ...] = (
    (r'(resource|data)\s+"aws_bedrock', "iac:bedrock"),
    (r'source\s*=\s*"(aws-ia/bedrock/aws|[^"]*terraform-aws-bedrock)', "iac:bedrock"),
    (r'resource\s+"azurerm_cognitive_deployment"', "iac:azure-openai"),
    (r'resource\s+"google_vertex_ai_', "iac:vertex-ai"),
    (r'resource\s+"google_discovery_engine_', "iac:vertex-ai"),
    (r'resource\s+"google_dialogflow_cx_agent"', "iac:dialogflow"),
)
_TF_RULES = [(re.compile(p, re.I), fact) for p, fact in TF_RULES]
AZURE_OPENAI_ACCOUNT = re.compile(r'resource\s+"azurerm_cognitive_account"', re.I)
AZURE_OPENAI_KIND = re.compile(r'kind\s*=\s*"OpenAI"', re.I)
COGNITIVE_TYPE = re.compile(r"Microsoft\.CognitiveServices/accounts", re.I)
CFN_BEDROCK = re.compile(r"AWS::Bedrock::")
CDK_BEDROCK = re.compile(
    r"aws_cdk\.aws_bedrock|aws-cdk-lib/aws-bedrock|@aws-cdk/aws-bedrock-alpha|"
    r"@cdklabs/generative-ai-cdk-constructs|cdklabs\.generative_ai_cdk_constructs|"
    r"pulumi_aws\.bedrock|@pulumi/aws/bedrock|aws\.bedrock\.Agent\(",
)

MCP_SERVER_PY = re.compile(r"\bFastMCP\(|\bServer\(\s*[\"'\w]")
MCP_SERVER_JS = re.compile(r"\bnew\s+(McpServer|Server)\s*\(")
MCP_SERVER_GO = re.compile(r"\bserver\.NewMCPServer\(|\bmcp\.NewServer\(")
MCP_SERVER_JAVA = re.compile(r"\bMcpServer\.(sync|async)\(")
MCP_SERVER_CS = re.compile(r"\.AddMcpServer\(|\[McpServerTool")
MCP_SERVER_RS = re.compile(r"\bServerHandler\b")


TEST_PATH = re.compile(
    r"(^|/)(tests?|testdata|test_data|fixtures?|__fixtures__|cassettes|__snapshots__|snapshots|__tests__|__mocks__|mocks|e2e|spec)/"
    r"|(^|/)(test_[^/]*\.py|[^/]*_tests?\.(py|go|rs|java|kt)|tests?\.rs|[^/]*\.(test|spec)\.[cm]?[jt]sx?|conftest\.py)$",
)


DOC_PATH = re.compile(r"(^|/)(docs?|website|site|_data|_posts|_includes|blog|changelogs?)/", re.I)


def is_test_path(location: str) -> bool:
    """Whether a hit location lies in test or fixture data."""
    return bool(TEST_PATH.search(location.split(":", 1)[0]))


def is_doc_path(location: str) -> bool:
    """Whether a hit location lies under a documentation site tree (data files included)."""
    return bool(DOC_PATH.search(location.split(":", 1)[0]))


@dataclass(frozen=True)
class Hit:
    kind: str  # manifest | lock | import | config | code | host | notebook | iac | lowcode
    location: str  # posix relative path, optionally :line
    detail: str = ""


@dataclass
class Evidence:
    """Facts with supporting hits, split into required and tolerated."""

    facts: dict[str, list[Hit]] = field(default_factory=lambda: defaultdict(list))
    tolerated: dict[str, list[Hit]] = field(default_factory=lambda: defaultdict(list))
    test_only: dict[str, list[Hit]] = field(default_factory=lambda: defaultdict(list))
    languages: Counter[str] = field(default_factory=Counter)
    files: int = 0
    skipped_large: int = 0
    truncated: bool = False

    def add(self, fact: str, hit: Hit, *, tolerated: bool = False) -> None:
        """Record a hit. Test and fixture paths are kept apart until ``finish``."""
        if not tolerated and (
            is_test_path(hit.location) or (hit.kind != "config" and is_doc_path(hit.location))
        ):
            tolerated = True
            bucket = self.test_only
        else:
            bucket = self.tolerated if tolerated else self.facts
        hits = bucket[fact]
        if len(hits) < MAX_HITS_PER_FACT and hit not in hits:
            hits.append(hit)

    def finish(self) -> None:
        """Facts seen only in test data, documentation trees or lock files are tolerated, not required."""
        for fact, hits in self.test_only.items():
            if fact not in self.facts:
                for hit in hits:
                    if len(self.tolerated[fact]) < MAX_HITS_PER_FACT:
                        self.tolerated[fact].append(hit)
        self.test_only.clear()
        for fact in list(self.tolerated):
            if fact in self.facts:
                del self.tolerated[fact]

    def to_dict(self) -> dict[str, Any]:
        return {
            "facts": {
                f: [{"kind": h.kind, "location": h.location, "detail": h.detail} for h in hits]
                for f, hits in sorted(self.facts.items())
            },
            "tolerated": {
                f: [{"kind": h.kind, "location": h.location, "detail": h.detail} for h in hits]
                for f, hits in sorted(self.tolerated.items())
            },
            "languages": dict(self.languages.most_common(6)),
            "files": self.files,
            "skipped_large": self.skipped_large,
            "truncated": self.truncated,
        }


LANGUAGE_BY_SUFFIX = {
    ".py": "python", ".ipynb": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".cjs": "javascript", ".ts": "typescript", ".tsx": "typescript", ".go": "go", ".java": "java",
    ".kt": "kotlin", ".kts": "kotlin", ".cs": "csharp", ".rs": "rust", ".rb": "ruby", ".php": "php",
    ".tf": "terraform", ".bicep": "bicep", ".swift": "swift", ".dart": "dart", ".scala": "scala",
    ".cpp": "cpp", ".c": "c", ".h": "c", ".hpp": "cpp", ".sh": "shell", ".ps1": "powershell",
}  # fmt: skip


def _read_text(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:4096]:
        return None
    return data.decode("utf-8", errors="replace")


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


class _Lines:
    """Line numbers for increasing offsets in one text, in linear total time."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.index = 0
        self.line = 1

    def at(self, index: int) -> int:
        if index < self.index:
            return _line_of(self.text, index)
        self.line += self.text.count("\n", self.index, index)
        self.index = index
        return self.line


def _req_names(spec_lines: list[str]) -> list[str]:
    names: list[str] = []
    for raw in spec_lines:
        line = raw.split("#", 1)[0].strip() if not raw.lstrip().startswith("-e") else raw.strip()
        if not line:
            continue
        if line.startswith(("-e", "--editable")) or "#egg=" in line:
            egg = EGG.search(raw)
            if egg:
                names.append(egg.group(1))
            continue
        if line.startswith("-") or line.startswith(("http://", "https://", "git+", "file:")):
            continue
        match = REQ_NAME.match(line)
        if match:
            names.append(match.group(1))
    return names


def _spec_name(spec: str) -> str | None:
    match = REQ_NAME.match(spec.strip())
    return match.group(1) if match else None


def _pyproject_names(text: str) -> list[str]:
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return []
    names: list[str] = []

    def take_specs(items: Any) -> None:
        if isinstance(items, list):
            for item in items:
                if isinstance(item, str):
                    name = _spec_name(item)
                    if name:
                        names.append(name)

    def take_keys(table: Any) -> None:
        if isinstance(table, dict):
            for key, value in table.items():
                if key == "python":
                    continue
                if isinstance(value, dict) and isinstance(value.get("package"), str):
                    names.append(value["package"])
                names.append(key)

    project = data.get("project") or {}
    take_specs(project.get("dependencies"))
    for extra in (project.get("optional-dependencies") or {}).values():
        take_specs(extra)
    for group in (data.get("dependency-groups") or {}).values():
        take_specs(group)
    tool = data.get("tool") or {}
    poetry = tool.get("poetry") or {}
    take_keys(poetry.get("dependencies"))
    take_keys(poetry.get("dev-dependencies"))
    for group in (poetry.get("group") or {}).values():
        if isinstance(group, dict):
            take_keys(group.get("dependencies"))
    for group in ((tool.get("pdm") or {}).get("dev-dependencies") or {}).values():
        take_specs(group)
    take_specs((tool.get("uv") or {}).get("dev-dependencies"))
    return names


def _cargo_names(text: str) -> list[str]:
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return []
    names: list[str] = []

    def take(table: Any) -> None:
        if isinstance(table, dict):
            for key, value in table.items():
                if isinstance(value, dict) and isinstance(value.get("package"), str):
                    names.append(value["package"])
                names.append(key)

    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        take(data.get(section))
    take((data.get("workspace") or {}).get("dependencies"))
    for target in (data.get("target") or {}).values():
        if isinstance(target, dict):
            for section in ("dependencies", "dev-dependencies", "build-dependencies"):
                take(target.get(section))
    return names


def _package_json_names(text: str) -> list[str]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    names: list[str] = []
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        table = data.get(section)
        if isinstance(table, dict):
            for key, spec in table.items():
                if not isinstance(key, str):
                    continue
                names.append(key)
                # "alias": "npm:@scope/real-name@^1" installs real-name under another key.
                if isinstance(spec, str) and spec.startswith("npm:"):
                    real = spec[4:]
                    cut = real.rfind("@")
                    if cut > 0:
                        real = real[:cut]
                    if real:
                        names.append(real)
    return names


def _go_mod(text: str) -> list[tuple[str, bool]]:
    modules: list[tuple[str, bool]] = []
    in_block = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line.startswith(")"):
            in_block = False
            continue
        if in_block or line.startswith("require "):
            body = line[len("require ") :] if line.startswith("require ") else line
            parts = body.split()
            if parts and "/" in parts[0]:
                modules.append((parts[0], "// indirect" in line))
    return modules


def _maven_coords(text: str) -> list[str]:
    coords: list[str] = []
    for block in POM_DEP.finditer(text):
        group = POM_GROUP.search(block.group(1))
        artifact = POM_ARTIFACT.search(block.group(1))
        if group and artifact and "${" not in group.group(1):
            coords.append(f"{group.group(1)}:{artifact.group(1)}")
    return coords


def _gradle_coords(text: str) -> list[str]:
    coords = [f"{g}:{a}" for g, a in GRADLE_COORD.findall(text)]
    coords.extend(f"{g}:{a}" for g, a in GRADLE_GROUP_NAME.findall(text))
    return coords


def _versions_catalog(text: str) -> list[str]:
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return []
    coords: list[str] = []
    for value in (data.get("libraries") or {}).values():
        if isinstance(value, str) and ":" in value:
            coords.append(":".join(value.split(":")[:2]))
        elif isinstance(value, dict):
            module = value.get("module")
            if isinstance(module, str):
                coords.append(module)
            elif isinstance(value.get("group"), str) and isinstance(value.get("name"), str):
                coords.append(f"{value['group']}:{value['name']}")
    return coords


def _setup_names(text: str) -> list[str]:
    names: list[str] = []
    for block in SETUP_REQ.finditer(text):
        for quoted in QUOTED.findall(block.group(1)):
            name = _spec_name(quoted)
            if name:
                names.append(name)
    return names


def _setup_cfg_names(text: str) -> list[str]:
    names: list[str] = []
    capture = False
    for raw in text.splitlines():
        if re.match(r"^\s*(install_requires|[a-z_]+)\s*=", raw):
            capture = bool(re.match(r"^\s*install_requires\s*=", raw))
            rest = raw.split("=", 1)[1].strip()
            if capture and rest:
                names.extend(_req_names([rest]))
            continue
        if raw.startswith("["):
            capture = raw.strip() == "[options.extras_require]"
            continue
        if capture and raw.startswith((" ", "\t")):
            names.extend(_req_names([raw.strip().split("=", 1)[-1]]))
    return names


def _conda_names(text: str) -> list[str]:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return []
    names: list[str] = []
    if not isinstance(data, dict):
        return names
    for item in data.get("dependencies") or []:
        if isinstance(item, str):
            name = _spec_name(item.split("=", 1)[0])
            if name:
                names.append(name)
        elif isinstance(item, dict):
            names.extend(_req_names([s for s in item.get("pip") or [] if isinstance(s, str)]))
    return names


def _lock_names(name: str, text: str) -> list[tuple[str, str]]:
    """Return (ecosystem, package) pairs from a lock file."""
    pairs: list[tuple[str, str]] = []
    if name in {"poetry.lock", "uv.lock", "cargo.lock"}:
        try:
            data = tomllib.loads(text)
        except (tomllib.TOMLDecodeError, ValueError):
            return pairs
        eco = "cargo" if name == "cargo.lock" else "pypi"
        for pkg in data.get("package") or []:
            if isinstance(pkg, dict) and isinstance(pkg.get("name"), str):
                pairs.append((eco, pkg["name"]))
    elif name == "pipfile.lock":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return pairs
        for section in ("default", "develop"):
            table = data.get(section) if isinstance(data, dict) else None
            if isinstance(table, dict):
                pairs.extend(("pypi", k) for k in table)
    elif name == "package-lock.json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return pairs
        packages = data.get("packages") if isinstance(data, dict) else None
        if isinstance(packages, dict):
            for key in packages:
                if "node_modules/" in key:
                    pairs.append(("npm", key.rsplit("node_modules/", 1)[1]))
        deps = data.get("dependencies") if isinstance(data, dict) else None
        if isinstance(deps, dict):
            pairs.extend(("npm", k) for k in deps)
    elif name == "pnpm-lock.yaml":
        pairs.extend(("npm", m) for m in PNPM_PKG.findall(text))
    elif name == "yarn.lock":
        pairs.extend(("npm", m) for m in YARN_PKG.findall(text))
    elif name == "go.sum":
        pairs.extend(("golang", line.split()[0]) for line in text.splitlines() if line.strip())
    elif name == "packages.lock.json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return pairs
        deps = data.get("dependencies") if isinstance(data, dict) else None
        if isinstance(deps, dict):
            for table in deps.values():
                if isinstance(table, dict):
                    pairs.extend(("nuget", k) for k in table)
    elif name == "gradle.lockfile":
        pairs.extend(("maven", f"{g}:{a}") for g, a in GRADLE_LOCK.findall(text))
    return pairs


LOCK_NAMES = frozenset(
    {
        "poetry.lock", "uv.lock", "cargo.lock", "pipfile.lock", "package-lock.json", "pnpm-lock.yaml",
        "yarn.lock", "go.sum", "packages.lock.json", "gradle.lockfile",
    }
)  # fmt: skip
REQ_FILE = re.compile(r"^(requirements|constraints)[\w.-]*\.(txt|in)$", re.I)


def _manifest_pairs(rel: PurePosixPath, text: str) -> list[tuple[str, str, bool]]:
    """Return (ecosystem, name, indirect) for a dependency manifest, else []."""
    name = rel.name
    lower = name.lower()
    pairs: list[tuple[str, str, bool]] = []
    if REQ_FILE.match(name) or (
        rel.parent.name.lower() == "requirements" and lower.endswith((".txt", ".in"))
    ):
        pairs.extend(("pypi", n, False) for n in _req_names(text.splitlines()))
    elif lower == "pyproject.toml":
        pairs.extend(("pypi", n, False) for n in _pyproject_names(text))
    elif lower == "setup.py":
        pairs.extend(("pypi", n, False) for n in _setup_names(text))
    elif lower == "setup.cfg":
        pairs.extend(("pypi", n, False) for n in _setup_cfg_names(text))
    elif lower == "pipfile":
        try:
            data = tomllib.loads(text)
        except (tomllib.TOMLDecodeError, ValueError):
            data = {}
        for section in ("packages", "dev-packages"):
            table = data.get(section)
            if isinstance(table, dict):
                pairs.extend(("pypi", k, False) for k in table)
    elif lower in {"environment.yml", "environment.yaml"} or lower.startswith("conda"):
        if lower.endswith((".yml", ".yaml")):
            pairs.extend(("pypi", n, False) for n in _conda_names(text))
    elif lower == "package.json":
        pairs.extend(("npm", n, False) for n in _package_json_names(text))
    elif lower == "go.mod":
        pairs.extend(("golang", m, indirect) for m, indirect in _go_mod(text))
    elif lower == "pom.xml":
        pairs.extend(("maven", c, False) for c in _maven_coords(text))
    elif lower in {"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"}:
        pairs.extend(("maven", c, False) for c in _gradle_coords(text))
    elif lower == "libs.versions.toml":
        pairs.extend(("maven", c, False) for c in _versions_catalog(text))
    elif rel.suffix.lower() in CSPROJ_SUFFIXES:
        pairs.extend(("nuget", n, False) for n in NUGET_REF.findall(text))
    elif lower == "packages.config":
        pairs.extend(("nuget", n, False) for n in NUGET_CONFIG.findall(text))
    elif lower == "cargo.toml":
        pairs.extend(("cargo", n, False) for n in _cargo_names(text))
    return pairs


def _import_pairs(rel: PurePosixPath, text: str) -> list[tuple[str, str, int]]:
    """Return (ecosystem, import path, line) pairs for a source file."""
    suffix = rel.suffix.lower()
    pairs: list[tuple[str, str, int]] = []
    lines = _Lines(text)
    if suffix in {".py", ".pyi"}:
        for match in PY_AGENTS_IMPORT.finditer(text):
            names = {part.strip().split(" as ")[0] for part in match.group(1).split(",")}
            if names & OPENAI_AGENTS_NAMES:
                pairs.append(("pyimport", "openai_agents_sdk_marker", lines.at(match.start())))
                break
        for match in PY_IMPORT.finditer(text):
            line = lines.at(match.start())
            if match.group(1):
                pairs.append(("pyimport", match.group(1), line))
            else:
                pairs.extend(("pyimport", part.strip(), line) for part in match.group(2).split(","))
            if len(pairs) >= MAX_IMPORTS_PER_FILE:
                break
    elif suffix in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte"}:
        for match in JS_IMPORT.finditer(text):
            spec = match.group(1)
            if spec.startswith((".", "/", "node:", "#", "~")):
                continue
            pairs.append(("jsimport", spec, lines.at(match.start())))
            if len(pairs) >= MAX_IMPORTS_PER_FILE:
                break
    elif suffix == ".go":
        for block in GO_IMPORT_BLOCK.finditer(text):
            base = lines.at(block.start())
            pairs.extend(("goimport", path, base) for path in GO_QUOTED.findall(block.group(1)))
        for match in GO_IMPORT_ONE.finditer(text):
            pairs.append(("goimport", match.group(1), _line_of(text, match.start())))
    elif suffix in {".java", ".kt", ".kts", ".scala", ".groovy"}:
        for match in JAVA_IMPORT.finditer(text):
            pairs.append(("javaimport", match.group(1), lines.at(match.start())))
            if len(pairs) >= MAX_IMPORTS_PER_FILE:
                break
    elif suffix == ".cs":
        for match in CS_USING.finditer(text):
            pairs.append(("csimport", match.group(1), lines.at(match.start())))
            if len(pairs) >= MAX_IMPORTS_PER_FILE:
                break
    elif suffix == ".rs":
        for match in RS_USE.finditer(text):
            name = match.group(1) or match.group(2)
            if name.split("::", 1)[0] in {"crate", "self", "super", "std", "core", "alloc"}:
                continue
            pairs.append(("rsimport", name, lines.at(match.start())))
            if len(pairs) >= MAX_IMPORTS_PER_FILE:
                break
    return pairs


def _notebook_sources(text: str) -> tuple[str, list[str]]:
    """Return code-cell source joined, and pip install package specs."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return "", []
    cells = data.get("cells") if isinstance(data, dict) else None
    if not isinstance(cells, list):
        return "", []
    parts: list[str] = []
    for cell in cells:
        if isinstance(cell, dict) and cell.get("cell_type") == "code":
            source = cell.get("source")
            if isinstance(source, list):
                parts.append("".join(s for s in source if isinstance(s, str)))
            elif isinstance(source, str):
                parts.append(source)
    code = "\n".join(parts)
    specs: list[str] = []
    for match in NB_PIP.finditer(code):
        for token in match.group(1).replace("\\", " ").split():
            if token.startswith("-") or token.startswith(("http", "git+")):
                continue
            specs.append(token.strip("'\""))
    return code, specs


def _content_check(check: str | None, text: str) -> bool:
    if check is None:
        return True
    if check == "codex_mcp":
        return "mcp_servers" in text
    if check == "vscode_settings_mcp":
        return bool(re.search(r'"mcp"\s*:\s*\{', text))
    if check == "zed_context_servers":
        return "context_servers" in text
    if check == "continue_mcp":
        return "mcpServers" in text
    if check == "opencode_mcp":
        return bool(re.search(r'"mcp"\s*:\s*\{', text))
    if check == "mcp_servers":
        return "mcpServers" in text or "mcp_servers" in text
    if check == "mcp_servers_or_servers":
        return "mcpServers" in text or bool(re.search(r'"servers"\s*:\s*\{', text))
    return False


def _json_doc(text: str) -> Any:
    if len(text) > MAX_FILE_BYTES or not text.lstrip().startswith(("{", "[")):
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _lowcode_and_cards(rel: PurePosixPath, text: str, ev: Evidence) -> None:
    suffix = rel.suffix.lower()
    loc = rel.as_posix()
    if suffix == ".json":
        doc = _json_doc(text)
        if not isinstance(doc, dict):
            return
        nodes = doc.get("nodes")
        if isinstance(nodes, list) and nodes:
            types = [n.get("type") for n in nodes if isinstance(n, dict)]
            if any(isinstance(t, str) and t.startswith("@n8n/n8n-nodes-langchain") for t in types):
                ev.add("lowcode:n8n", Hit("lowcode", loc, "n8n workflow with LangChain/AI nodes"))
            elif all(isinstance(n, dict) and isinstance(n.get("data"), dict) for n in nodes[:3]):
                data0 = nodes[0]["data"]
                if "baseClasses" in data0 and "category" in data0:
                    ev.add("lowcode:flowise", Hit("lowcode", loc, "Flowise chatflow export"))
        inner = doc.get("data")
        if (
            isinstance(inner, dict)
            and isinstance(inner.get("nodes"), list)
            and isinstance(inner.get("edges"), list)
        ):
            first = inner["nodes"][0] if inner["nodes"] else None
            if isinstance(first, dict) and isinstance(first.get("data"), dict) and "type" in first["data"]:
                ev.add("lowcode:langflow", Hit("lowcode", loc, "Langflow flow export"))
        if {"name", "skills"} <= set(doc) and (
            "capabilities" in doc or "defaultInputModes" in doc or "url" in doc
        ):
            if isinstance(doc.get("skills"), list):
                ev.add("a2a:agent-card", Hit("config", loc, "A2A agent card"))
    elif suffix in {".yml", ".yaml"} and len(text) < MAX_FILE_BYTES:
        head = text[:4000]
        if re.search(r"^app:\s*$", head, re.M) and re.search(
            r"^\s+mode:\s*(workflow|advanced-chat|agent-chat|chat|completion)", head, re.M
        ):
            ev.add("lowcode:dify", Hit("lowcode", loc, "Dify DSL export"))


def _iac(rel: PurePosixPath, text: str, ev: Evidence) -> None:
    suffix = rel.suffix.lower()
    loc = rel.as_posix()
    if suffix == ".tf":
        for pattern, fact in _TF_RULES:
            match = pattern.search(text)
            if match:
                ev.add(fact, Hit("iac", f"{loc}:{_line_of(text, match.start())}", match.group(0)[:60]))
        account = AZURE_OPENAI_ACCOUNT.search(text)
        if account and AZURE_OPENAI_KIND.search(text):
            ev.add(
                "iac:azure-openai",
                Hit(
                    "iac",
                    f"{loc}:{_line_of(text, account.start())}",
                    'azurerm_cognitive_account kind "OpenAI"',
                ),
            )
    elif suffix in {".bicep", ".json", ".yaml", ".yml", ".template"}:
        match = COGNITIVE_TYPE.search(text)
        if match and ("OpenAI" in text or "openai" in text.lower()):
            ev.add("iac:azure-openai", Hit("iac", f"{loc}:{_line_of(text, match.start())}", match.group(0)))
        match = CFN_BEDROCK.search(text)
        if match:
            ev.add("iac:bedrock", Hit("iac", f"{loc}:{_line_of(text, match.start())}", match.group(0)))
    if suffix in {".py", ".ts", ".js", ".mjs", ".go", ".java", ".cs"}:
        match = CDK_BEDROCK.search(text)
        if match:
            ev.add("iac:bedrock", Hit("iac", f"{loc}:{_line_of(text, match.start())}", match.group(0)))


def _mcp_server(rel: PurePosixPath, text: str, imports: list[tuple[str, str, int]], ev: Evidence) -> None:
    suffix = rel.suffix.lower()
    loc = rel.as_posix()
    paths = {name.lower() for _, name, _ in imports}

    def has(prefix: str) -> bool:
        return any(p == prefix or p.startswith(prefix + "/") or p.startswith(prefix + ".") for p in paths)

    pattern: re.Pattern[str] | None = None
    if suffix in {".py", ".ipynb"} and (
        has("mcp.server") or has("fastmcp") or any(p.startswith("mcp.server") for p in paths)
    ):
        pattern = MCP_SERVER_PY
    elif suffix in {".ts", ".js", ".mjs", ".cjs", ".mts", ".tsx"} and has("@modelcontextprotocol/sdk"):
        pattern = MCP_SERVER_JS
    elif suffix == ".go" and (
        has("github.com/mark3labs/mcp-go") or has("github.com/modelcontextprotocol/go-sdk")
    ):
        pattern = MCP_SERVER_GO
    elif suffix in {".java", ".kt"} and has("io.modelcontextprotocol"):
        pattern = MCP_SERVER_JAVA
    elif suffix == ".cs" and has("modelcontextprotocol"):
        pattern = MCP_SERVER_CS
    elif suffix == ".rs" and has("rmcp"):
        pattern = MCP_SERVER_RS
    if pattern is None:
        return
    match = pattern.search(text)
    if match:
        ev.add("mcp:server", Hit("code", f"{loc}:{_line_of(text, match.start())}", match.group(0)[:40]))


def _hosts_and_idioms(rel: PurePosixPath, text: str, ev: Evidence) -> None:
    loc = rel.as_posix()
    for ecosystem in ("host", "idiom"):
        for fact, match in taxonomy.text_matches(ecosystem, text):
            ev.add(fact, Hit(ecosystem, f"{loc}:{_line_of(text, match.start())}", match.group(0)[:60]))


def _walk(root: Path) -> list[Path]:
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.is_symlink():
                continue
            files.append(path)
            if len(files) >= MAX_FILES:
                return files
    return files


def extract(root: Path) -> Evidence:
    """Extract labeling evidence from a checkout at ``root``."""
    ev = Evidence()
    files = _walk(root)
    ev.truncated = len(files) >= MAX_FILES
    for path in files:
        rel = PurePosixPath(path.relative_to(root).as_posix())
        suffix = rel.suffix.lower()
        lower = rel.name.lower()
        ev.files += 1
        if suffix in LANGUAGE_BY_SUFFIX:
            ev.languages[LANGUAGE_BY_SUFFIX[suffix]] += 1
        config_facts: set[str] = set()
        for pattern, fact, check in _CONFIG_PATHS:
            if pattern.search(rel.as_posix()):
                text = _read_text(path) if check else ""
                if text is not None and _content_check(check, text):
                    config_facts.add(fact)
        if len([f for f in config_facts if f.startswith("mcp-client-config:")]) > 1:
            config_facts.discard("mcp-client-config:generic")
        for fact in sorted(config_facts):
            ev.add(fact, Hit("config", rel.as_posix(), rel.name))
        if suffix in BINARY_SUFFIXES and lower not in LOCK_NAMES:
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        limit = MAX_NOTEBOOK_BYTES if suffix == ".ipynb" or lower in LOCK_NAMES else MAX_FILE_BYTES
        if size > limit:
            ev.skipped_large += 1
            continue
        text = _read_text(path)
        if text is None:
            continue
        if lower in LOCK_NAMES:
            for ecosystem, name in _lock_names(lower, text):
                for fact in taxonomy.facts_for(ecosystem, name):
                    ev.add(fact, Hit("lock", rel.as_posix(), name), tolerated=True)
            continue
        for ecosystem, name, indirect in _manifest_pairs(rel, text):
            for fact in taxonomy.facts_for(ecosystem, name):
                ev.add(fact, Hit("manifest", rel.as_posix(), name), tolerated=indirect)
        imports: list[tuple[str, str, int]] = []
        if suffix == ".ipynb":
            code, specs = _notebook_sources(text)
            for spec in specs:
                for fact in taxonomy.facts_for("pypi", spec):
                    ev.add(fact, Hit("notebook", rel.as_posix(), f"pip install {spec}"))
            imports = _import_pairs(PurePosixPath(rel.as_posix() + ".py"), code)
            text = code
        else:
            imports = _import_pairs(rel, text)
        for ecosystem, name, line in imports:
            for fact in taxonomy.facts_for(ecosystem, name):
                ev.add(fact, Hit("import", f"{rel.as_posix()}:{line}", name))
        if imports:
            _mcp_server(rel, text, imports, ev)
        if suffix in DOC_SUFFIXES:
            continue
        if (
            suffix in CODE_SUFFIXES
            or lower in TEXT_BASENAMES
            or lower.startswith(".env")
            or "dockerfile" in lower
            or "compose" in lower
        ):
            _hosts_and_idioms(rel, text, ev)
            _iac(rel, text, ev)
            _lowcode_and_cards(rel, text, ev)
    ev.finish()
    return ev


def extract_to_file(root: Path, out: Path) -> Evidence:
    ev = extract(root)
    out.write_text(json.dumps(ev.to_dict(), indent=1) + "\n", encoding="utf-8")
    return ev
