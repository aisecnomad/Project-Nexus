"""Tool-independent labelling oracle for the real-world benchmark.

The oracle reads a repository snapshot as *data* (it never executes, imports or
builds anything in it) and decides from manifests, parsed import statements,
well-known configuration paths and a few content markers whether the repository
integrates an LLM, an AI agent framework, an MCP server or client, or a
coding-agent configuration. Its knowledge lives in ``registry/ai_registry.json``.

This file imports nothing from ShadowScan or from any tool under test
(``tests/test_benchmark_realworld.py`` enforces both) and uses only the standard
library, so it can run isolated and outside the corpus directory::

    python -I oracle.py --registry registry/ai_registry.json \\
        --manifest manifest.jsonl --corpus /path/to/corpus --out labels.jsonl

Label states (see PROTOCOL.md):

* ``positive``  strong AI evidence outside tests and documentation
* ``negative``  no strong, weak or adjacent evidence anywhere (ML frameworks allowed)
* ``ambiguous`` everything else (evidence only in tests/docs, weak-only, adjacent-only)
"""

from __future__ import annotations

import argparse
import ast
import configparser
import json
import os
import re
import sys
import tomllib
import warnings
from collections import Counter
from collections.abc import Iterable, Iterator
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ORACLE_VERSION = "2"
MAX_TEXT_BYTES = 1_000_000
MAX_DATA_BYTES = 5_000_000
MAX_WEAK_BYTES = 512_000
MAX_FILES = 60_000
MAX_EVIDENCE_PER_KEY = 4

STRICT_CTX = frozenset({"src", "config", "example", "notebook"})
CORE_CTX = frozenset({"src", "config"})

EXT_LANG = {
    ".py": "python", ".ipynb": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".cjs": "javascript", ".vue": "javascript", ".svelte": "javascript", ".ts": "typescript",
    ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript", ".go": "go", ".rs": "rust",
    ".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".scala": "scala", ".groovy": "groovy",
    ".cs": "csharp", ".rb": "ruby", ".php": "php", ".swift": "swift", ".dart": "dart",
    ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp", ".lua": "lua", ".sh": "shell",
    ".ex": "elixir", ".exs": "elixir", ".zig": "zig", ".r": "r", ".jl": "julia",
}  # fmt: skip
JS_EXTS = frozenset({".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte", ".ts", ".tsx", ".mts", ".cts"})
JAVA_EXTS = frozenset({".java", ".kt", ".kts", ".scala", ".groovy"})
WEAK_EXTS = frozenset(
    {".py", ".ipynb", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".go", ".rs", ".java", ".kt", ".cs",
     ".rb", ".php", ".swift", ".dart", ".yml", ".yaml", ".json", ".toml", ".cfg", ".ini", ".sh", ".tf",
     ".properties", ".env", ".example", ".sample", ".template", ".conf", ".vue", ".svelte"}
)  # fmt: skip
MANIFEST_NAMES = frozenset(
    {"package.json", "pyproject.toml", "setup.py", "setup.cfg", "pipfile", "go.mod", "cargo.toml", "pom.xml",
     "build.gradle", "build.gradle.kts", "composer.json", "pubspec.yaml", "gemfile",
     "directory.packages.props", "directory.build.props", "packages.config"}
)  # fmt: skip
MANIFEST_SUFFIXES = (".csproj", ".fsproj", ".vbproj", ".gemspec", ".versions.toml")
DEV_NAME = re.compile(r"(^|[-_./])(dev|test|tests|lint|docs|ci|typing|develop|development)([-_./]|$)")
REQ_FILE = re.compile(r"^(?:.*[-_.])?(?:requirements|constraints)(?:[-_.].*)?\.(?:txt|in)$", re.IGNORECASE)
REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
REQ_STRING = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*(\[[^\]]*\])?\s*([<>=!~]=?[^;]*)?(;.*)?")
TEST_FILE = re.compile(
    r"(^test_.*\.py$|_test\.(py|go|rb|rs)$|\.(test|spec)\.[cm]?[jt]sx?$|^conftest\.py$|_spec\.rb$"
    r"|(Test|Tests|IT)\.(java|kt|cs)$)"
)
JS_IMPORT = re.compile(r"""(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\s*\(\s*)['"]([^'"\n]+)['"]""")
GO_BLOCK = re.compile(r"(?ms)^\s*import\s*\((.*?)\)")
GO_SINGLE = re.compile(r'(?m)^\s*import\s+(?:[\w.]+\s+)?"([^"]+)"')
QUOTED = re.compile(r'"([^"\n]+)"')
RUST_USE = re.compile(r"(?m)^\s*(?:pub\s+)?(?:use\s+|extern\s+crate\s+)([A-Za-z_][A-Za-z0-9_]*)")
JAVA_IMPORT = re.compile(r"(?m)^\s*import\s+(?:static\s+)?([A-Za-z_][\w.]*)")
CS_USING = re.compile(r"(?m)^\s*(?:global\s+)?using\s+(?:static\s+)?([A-Za-z_][\w.]*)\s*;")
RUBY_REQUIRE = re.compile(r"""(?m)^\s*require\s+['"]([^'"]+)['"]""")
DART_IMPORT = re.compile(r"""(?m)^\s*import\s+['"]package:([a-z0-9_]+)/""")
PY_IMPORT_FALLBACK = re.compile(r"^\s*(?:from\s+([A-Za-z_][\w.]*)\s+import|import\s+([A-Za-z_][\w., ]*))")
PIP_CELL = re.compile(r"^\s*[!%]\s*(?:pip|uv pip)\s+install\s+(.+)$")
MAVEN_DEP = re.compile(
    r"<dependency>\s*<groupId>\s*([^<\s]+)\s*</groupId>\s*<artifactId>\s*([^<\s]+)\s*</artifactId>"
    r"(?:(?!</dependency>).)*?(?:<scope>\s*([^<\s]*)\s*</scope>)?(?:(?!</dependency>).)*?</dependency>",
    re.DOTALL,
)
GRADLE_COORD = re.compile(r"""["']([A-Za-z][\w.\-]*):([A-Za-z][\w.\-]*)(?::[^"'\s]*)?["']""")
NUGET_REF = re.compile(
    r"""<(?:PackageReference|PackageVersion)\s+(?:Include|Update)\s*=\s*"([^"]+)"|<package\s+id\s*=\s*"([^"]+)\""""
)
GEM_REF = re.compile(r"""(?m)^\s*(?:gem|add_(?:runtime_)?dependency)\s*\(?\s*['"]([^'"]+)['"]""")


def norm_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def norm_crate(name: str) -> str:
    return name.strip().lower().replace("-", "_")


@dataclass
class Ev:
    kind: str  # dep | import | path | content | weak
    tech: str
    tier: str
    path: str
    line: int
    ctx: str  # src | config | example | notebook | test | docs | transitive
    detail: str
    needs_dep: bool = False

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind, "tech": self.tech, "tier": self.tier, "path": self.path,
            "line": self.line, "ctx": self.ctx, "detail": self.detail,
        }  # fmt: skip


@dataclass
class Dep:
    eco: str
    name: str
    line: int = 0
    dev: bool = False
    transitive: bool = False


Parsed = tuple[list[Dep], list[tuple[str, str]]]  # dependencies, (ecosystem, own project name)
Marker = tuple[dict[str, Any], "re.Pattern[str] | None", "re.Pattern[str] | None"]


class Index:
    """The registry compiled for matching. The first technology to claim an exact name wins."""

    def __init__(self, registry: dict[str, Any]) -> None:
        self.registry = registry
        self.tier_class = {t: c for c, tiers in registry["classes"].items() for t in tiers}
        self.tier: dict[str, str] = {}
        self.pypi: dict[str, str] = {}
        self.pypi_prefix: list[tuple[str, str]] = []
        self.py_imp: dict[str, tuple[str, bool]] = {}
        self.py_imp_prefix: list[tuple[str, str]] = []
        self.npm: dict[str, str] = {}
        self.npm_prefix: list[tuple[str, str]] = []
        self.npm_import_needs_dep: set[str] = set()
        self.go: list[tuple[str, str]] = []
        self.maven_group: list[tuple[str, str]] = []
        self.maven_coord: dict[str, str] = {}
        self.java_imp: list[tuple[str, str]] = []
        self.nuget: dict[str, str] = {}
        self.nuget_prefix: list[tuple[str, str]] = []
        self.cs_ns: list[tuple[str, str]] = []
        self.crates: dict[str, str] = {}
        self.rs_imp: dict[str, str] = {}
        self.gems: dict[str, str] = {}
        self.composer: dict[str, str] = {}
        self.pub: dict[str, str] = {}
        for tech in registry["technologies"]:
            tid = tech["id"]
            self.tier[tid] = tech["tier"]
            needs = bool(tech.get("py_import_requires_dep"))
            for n in tech.get("pypi", []):
                self.pypi.setdefault(norm_pypi(n), tid)
            self.pypi_prefix += [(norm_pypi(p), tid) for p in tech.get("pypi_prefixes", [])]
            for m in tech.get("py_imports", []):
                self.py_imp.setdefault(m, (tid, needs))
            self.py_imp_prefix += [(p, tid) for p in tech.get("py_import_prefixes", [])]
            for n in tech.get("npm", []):
                self.npm.setdefault(n, tid)
            self.npm_prefix += [(p, tid) for p in tech.get("npm_prefixes", [])]
            self.npm_import_needs_dep.update(tech.get("npm_import_requires_dep", []))
            self.go += [(p, tid) for p in tech.get("go", [])]
            for g in tech.get("maven_groups", []):
                if ":" in g:
                    self.maven_coord.setdefault(g, tid)
                else:
                    self.maven_group.append((g, tid))
            self.java_imp += [(p, tid) for p in tech.get("java_imports", [])]
            for n in tech.get("nuget", []):
                self.nuget.setdefault(n.lower(), tid)
            self.nuget_prefix += [(p.lower(), tid) for p in tech.get("nuget_prefixes", [])]
            self.cs_ns += [(p, tid) for p in tech.get("cs_namespaces", [])]
            for n in tech.get("crates", []):
                self.crates.setdefault(norm_crate(n), tid)
            for n in tech.get("rs_imports", []):
                self.rs_imp.setdefault(norm_crate(n), tid)
            for n in tech.get("gems", []):
                self.gems.setdefault(n, tid)
            for n in tech.get("composer", []):
                self.composer.setdefault(n.lower(), tid)
            for n in tech.get("pub", []):
                self.pub.setdefault(n, tid)
        for lst in (self.pypi_prefix, self.py_imp_prefix, self.npm_prefix, self.go, self.maven_group,
                    self.java_imp, self.nuget_prefix, self.cs_ns):  # fmt: skip
            lst.sort(key=lambda item: -len(item[0]))
        self.path_rules: list[tuple[dict[str, Any], re.Pattern[str], str | None]] = [
            (r, re.compile(r["regex"]), r.get("case_sensitive_name")) for r in registry["path_rules"]
        ]
        self.markers: list[Marker] = [
            (m, re.compile(m["regex"]) if "regex" in m else None,
             re.compile(m["path_regex"]) if "path_regex" in m else None)
            for m in registry["content_markers"]
        ]  # fmt: skip
        ctx = registry["context"]
        self.ignore_dirs = frozenset(registry["ignore_dirs"])
        self.test_dirs = frozenset(ctx["test_dirs"])
        self.docs_dirs = frozenset(ctx["docs_dirs"])
        self.example_dirs = frozenset(ctx["example_dirs"])
        self.docs_exts = frozenset(ctx["docs_exts"])
        self.weak_hosts = [h.lower() for h in registry["weak"]["hosts"]]
        self.weak_env = list(registry["weak"]["env_vars"])
        self.dev_config_ids = frozenset(registry.get("dev_config_ids", []))

    def pypi_dist(self, name: str) -> str | None:
        n = norm_pypi(name)
        if n in self.pypi:
            return self.pypi[n]
        return next((t for p, t in self.pypi_prefix if n.startswith(p)), None)

    def py_import(self, module: str) -> tuple[str, bool] | None:
        parts = module.split(".")
        for i in range(len(parts), 0, -1):
            hit = self.py_imp.get(".".join(parts[:i]))
            if hit:
                return hit
        return next(((t, False) for p, t in self.py_imp_prefix if parts[0].startswith(p)), None)

    def npm_pkg(self, name: str) -> str | None:
        if name in self.npm:
            return self.npm[name]
        return next((t for p, t in self.npm_prefix if name.startswith(p)), None)

    def go_mod(self, path: str) -> str | None:
        return next((t for p, t in self.go if path == p or path.startswith(p + "/")), None)

    def maven(self, group: str, artifact: str) -> str | None:
        hit = self.maven_coord.get(f"{group}:{artifact}")
        if hit:
            return hit
        return next((t for g, t in self.maven_group if group == g or group.startswith(g + ".")), None)

    def java_import(self, name: str) -> str | None:
        return next((t for p, t in self.java_imp if name == p or name.startswith(p + ".")), None)

    def nuget_pkg(self, name: str) -> str | None:
        n = name.lower()
        if n in self.nuget:
            return self.nuget[n]
        return next((t for p, t in self.nuget_prefix if n.startswith(p)), None)

    def cs_using(self, ns: str) -> str | None:
        return next((t for p, t in self.cs_ns if ns == p or ns.startswith(p + ".")), None)

    def match_dep(self, dep: Dep) -> str | None:
        if dep.eco == "pypi":
            return self.pypi_dist(dep.name)
        if dep.eco == "npm":
            return self.npm_pkg(dep.name)
        if dep.eco == "go":
            return self.go_mod(dep.name)
        if dep.eco == "maven":
            group, _, artifact = dep.name.partition(":")
            return self.maven(group, artifact)
        if dep.eco == "nuget":
            return self.nuget_pkg(dep.name)
        if dep.eco == "crates":
            return self.crates.get(norm_crate(dep.name))
        if dep.eco == "gems":
            return self.gems.get(dep.name)
        if dep.eco == "composer":
            return self.composer.get(dep.name.lower())
        if dep.eco == "pub":
            return self.pub.get(dep.name)
        return None


def load_index(path: Path) -> Index:
    return Index(json.loads(path.read_text(encoding="utf-8")))


# ---------------------------------------------------------------------------
# File walking and context


def walk(root: Path, index: Index) -> Iterator[tuple[str, Path, bool]]:
    """Yield (posix relative path, absolute path, is_symlink) without following symlinks."""
    prefix = len(str(root)) + 1
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_symlink():
                    yield entry.path[prefix:], Path(entry.path), True
                elif entry.is_dir(follow_symlinks=False):
                    if entry.name not in index.ignore_dirs:
                        stack.append(Path(entry.path))
                elif entry.is_file(follow_symlinks=False):
                    yield entry.path[prefix:], Path(entry.path), False
            except OSError:
                continue


def dir_context(rel: str, index: Index) -> str:
    dirs = [d.lower() for d in rel.split("/")[:-1]]
    if any(d in index.test_dirs for d in dirs):
        return "test"
    if any(d in index.docs_dirs for d in dirs):
        return "docs"
    if any(d in index.example_dirs for d in dirs):
        return "example"
    return "src"


def file_context(rel: str, index: Index) -> str:
    base = dir_context(rel, index)
    name = rel.rsplit("/", 1)[-1]
    if base in {"test", "docs"}:
        return base
    if TEST_FILE.search(name):
        return "test"
    if os.path.splitext(name)[1].lower() in index.docs_exts:
        return "docs"
    if base == "example":
        return "example"
    return "notebook" if name.endswith(".ipynb") else "src"


def read_text(path: Path, limit: int) -> str | None:
    try:
        if path.stat().st_size > limit:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:8000]:
        return None
    return data.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Source import extraction


def py_modules(text: str) -> list[tuple[str, int]]:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # legacy escapes in third-party code are not our business
            tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError, OverflowError):
        out: list[tuple[str, int]] = []
        for i, line in enumerate(text.splitlines(), 1):
            m = PY_IMPORT_FALLBACK.match(line)
            if m:
                names = [m.group(1)] if m.group(1) else [n.strip() for n in m.group(2).split(",")]
                out += [(n.split(" as ")[0].strip(), i) for n in names if n]
        return out
    found: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found += [(a.name, node.lineno) for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            found.append((node.module, node.lineno))
            found += [(f"{node.module}.{a.name}", node.lineno) for a in node.names if a.name != "*"]
    return found


def notebook_code(text: str) -> str:
    try:
        doc = json.loads(text)
    except (ValueError, RecursionError):
        return ""
    cells = doc.get("cells", []) if isinstance(doc, dict) else []
    chunks = []
    for cell in cells:
        if isinstance(cell, dict) and cell.get("cell_type") == "code":
            src = cell.get("source", "")
            chunks.append("".join(src) if isinstance(src, list) else str(src))
    return "\n".join(chunks)


def strip_magics(code: str) -> tuple[str, list[str]]:
    pips: list[str] = []
    kept: list[str] = []
    for line in code.splitlines():
        m = PIP_CELL.match(line)
        if m:
            pips.append(m.group(1))
        kept.append("" if line.lstrip().startswith(("%", "!")) else line)
    return "\n".join(kept), pips


def js_modules(text: str) -> list[tuple[str, int]]:
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith(("//", "*", "/*", "#")) or len(line) > 2000:
            continue
        for m in JS_IMPORT.finditer(line):
            spec = m.group(1)
            if spec.startswith((".", "/", "node:", "http:", "https:", "~", "@/")):
                continue
            parts = spec.split("/")
            out.append(("/".join(parts[:2]) if spec.startswith("@") and len(parts) > 1 else parts[0], i))
    return out


def go_modules(text: str) -> list[tuple[str, int]]:
    out = []
    for m in GO_BLOCK.finditer(text):
        base = text.count("\n", 0, m.start())
        for j, line in enumerate(m.group(1).splitlines()):
            q = QUOTED.search(line.split("//")[0])
            if q:
                out.append((q.group(1), base + j + 1))
    for m in GO_SINGLE.finditer(text):
        out.append((m.group(1), text.count("\n", 0, m.start()) + 1))
    return out


def regex_modules(rx: re.Pattern[str], text: str) -> list[tuple[str, int]]:
    return [(m.group(1), text.count("\n", 0, m.start()) + 1) for m in rx.finditer(text)]


# ---------------------------------------------------------------------------
# Manifest parsing


def _pep508(eco_items: Iterable[Any], dev: bool = False) -> list[Dep]:
    out = []
    for item in eco_items:
        m = REQ_NAME.match(item) if isinstance(item, str) else None
        if m:
            out.append(Dep("pypi", m.group(1), 0, dev))
    return out


def parse_requirements(text: str, dev: bool) -> Parsed:
    out = []
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.split(" #")[0].split("\t#")[0].strip()
        if not line or line.startswith(("#", "-r", "-c", "--")):
            continue
        egg = re.search(r"[#&]egg=([A-Za-z0-9._-]+)", line)
        if line.startswith("-e") or egg:
            if egg:
                out.append(Dep("pypi", egg.group(1), i, dev))
            continue
        m = REQ_NAME.match(line)
        if m:
            out.append(Dep("pypi", m.group(1), i, dev))
    return out, []


def parse_pyproject(text: str) -> Parsed:
    try:
        doc = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError, RecursionError):
        return [], []
    deps: list[Dep] = []
    names: list[tuple[str, str]] = []
    project = doc.get("project", {})
    if isinstance(project, dict):
        if isinstance(project.get("name"), str):
            names.append(("pypi", project["name"]))
        deps += _pep508(project.get("dependencies", []))
        opt = project.get("optional-dependencies", {})
        if isinstance(opt, dict):
            for group, items in opt.items():
                deps += _pep508(
                    items if isinstance(items, list) else [], bool(DEV_NAME.search(str(group).lower()))
                )
    groups = doc.get("dependency-groups", {})
    if isinstance(groups, dict):
        for items in groups.values():
            deps += _pep508(items if isinstance(items, list) else [], True)
    tool = doc.get("tool", {})
    poetry = tool.get("poetry", {}) if isinstance(tool, dict) else {}
    if isinstance(poetry, dict):
        if isinstance(poetry.get("name"), str):
            names.append(("pypi", poetry["name"]))
        for key, dev in (("dependencies", False), ("dev-dependencies", True)):
            table = poetry.get(key, {})
            if isinstance(table, dict):
                deps += [Dep("pypi", n, 0, dev) for n in table if n.lower() != "python"]
        pgroups = poetry.get("group", {})
        if isinstance(pgroups, dict):
            for gname, body in pgroups.items():
                table = body.get("dependencies", {}) if isinstance(body, dict) else {}
                if isinstance(table, dict):
                    deps += [Dep("pypi", n, 0, gname != "main") for n in table if n.lower() != "python"]
    for tool_name in ("uv", "pdm"):
        section = tool.get(tool_name, {}) if isinstance(tool, dict) else {}
        dev_deps = section.get("dev-dependencies") if isinstance(section, dict) else None
        if isinstance(dev_deps, list):
            deps += _pep508(dev_deps, True)
        elif isinstance(dev_deps, dict):
            for items in dev_deps.values():
                deps += _pep508(items if isinstance(items, list) else [], True)
    return deps, names


def parse_setup_py(text: str) -> Parsed:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError, OverflowError):
        return [], []
    deps: list[Dep] = []
    names: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and len(node.value) < 120:
            m = REQ_NAME.match(node.value)
            if m and REQ_STRING.fullmatch(node.value):
                deps.append(Dep("pypi", m.group(1), node.lineno))
        elif (
            isinstance(node, ast.Call) and getattr(node.func, "id", getattr(node.func, "attr", "")) == "setup"
        ):
            for kw in node.keywords:
                if (
                    kw.arg == "name"
                    and isinstance(kw.value, ast.Constant)
                    and isinstance(kw.value.value, str)
                ):
                    names.append(("pypi", kw.value.value))
    return deps, names


def parse_setup_cfg(text: str) -> Parsed:
    cp = configparser.ConfigParser(strict=False, interpolation=None)
    try:
        cp.read_string(text)
    except configparser.Error:
        return [], []
    names = [("pypi", cp.get("metadata", "name"))] if cp.has_option("metadata", "name") else []
    deps: list[Dep] = []
    if cp.has_option("options", "install_requires"):
        deps += _pep508(cp.get("options", "install_requires").splitlines())
    if cp.has_section("options.extras_require"):
        for key, val in cp.items("options.extras_require"):
            deps += _pep508(val.splitlines(), bool(DEV_NAME.search(key.lower())))
    return deps, names


def parse_pipfile(text: str) -> Parsed:
    try:
        doc = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError, RecursionError):
        return [], []
    deps = [Dep("pypi", n) for n in (doc.get("packages") or {})]
    return deps + [Dep("pypi", n, 0, True) for n in (doc.get("dev-packages") or {})], []


def parse_package_json(text: str) -> Parsed:
    try:
        doc = json.loads(text)
    except (ValueError, RecursionError):
        return [], []
    if not isinstance(doc, dict):
        return [], []
    deps: list[Dep] = []
    for key, dev in (("dependencies", False), ("peerDependencies", False), ("optionalDependencies", False),
                     ("devDependencies", True)):  # fmt: skip
        table = doc.get(key)
        if isinstance(table, dict):
            deps += [Dep("npm", n, 0, dev) for n in table]
    return deps, [("npm", doc["name"])] if isinstance(doc.get("name"), str) else []


def parse_go_mod(text: str) -> Parsed:
    deps: list[Dep] = []
    names = [("go", m.group(1)) for m in re.finditer(r"(?m)^\s*module\s+(\S+)", text)]
    in_block = False
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        body = line[len("require ") :] if line.startswith("require ") else (line if in_block else "")
        m = re.match(r"(\S+)\s+v\S+", body)
        if m:
            deps.append(Dep("go", m.group(1), i, False, "// indirect" in raw))
    return deps, names


def parse_cargo(text: str) -> Parsed:
    try:
        doc = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError, RecursionError):
        return [], []
    deps: list[Dep] = []

    def table(tbl: Any, dev: bool) -> None:
        if isinstance(tbl, dict):
            for name, spec in tbl.items():
                real = spec.get("package", name) if isinstance(spec, dict) else name
                deps.append(Dep("crates", str(real), 0, dev))

    for key, dev in (("dependencies", False), ("dev-dependencies", True), ("build-dependencies", False)):
        table(doc.get(key), dev)
    ws = doc.get("workspace", {})
    if isinstance(ws, dict):
        table(ws.get("dependencies"), False)
    targets = doc.get("target", {})
    if isinstance(targets, dict):
        for body in targets.values():
            if isinstance(body, dict):
                table(body.get("dependencies"), False)
                table(body.get("dev-dependencies"), True)
    pkg = doc.get("package", {})
    return deps, [("crates", pkg["name"])] if isinstance(pkg, dict) and isinstance(
        pkg.get("name"), str
    ) else []


def parse_pom(text: str) -> Parsed:
    deps = [
        Dep("maven", f"{m.group(1)}:{m.group(2)}", 0, (m.group(3) or "") in {"test", "provided"})
        for m in MAVEN_DEP.finditer(text)
    ]
    head = re.sub(r"(?s)<parent>.*?</parent>", "", text.split("<dependencies>", 1)[0])
    group = re.search(r"<groupId>\s*([^<\s]+)\s*</groupId>", head)
    artifact = re.search(r"<artifactId>\s*([^<\s]+)\s*</artifactId>", head)
    return deps, [("maven", f"{group.group(1)}:{artifact.group(1)}")] if group and artifact else []


def parse_gradle(text: str) -> Parsed:
    deps = []
    for i, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith(("//", "*", "/*")):
            continue
        for m in GRADLE_COORD.finditer(line):
            dev = line.lstrip().lower().startswith(("test", "androidtest", "kapt"))
            deps.append(Dep("maven", f"{m.group(1)}:{m.group(2)}", i, dev))
    return deps, []


def parse_version_catalog(text: str) -> Parsed:
    try:
        doc = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError, RecursionError):
        return [], []
    libs = doc.get("libraries", {})
    deps: list[Dep] = []
    if isinstance(libs, dict):
        for spec in libs.values():
            coord: list[str] | None = None
            if isinstance(spec, str):
                coord = spec.split(":")[:2]
            elif isinstance(spec, dict):
                if isinstance(spec.get("module"), str):
                    coord = spec["module"].split(":")[:2]
                elif "group" in spec and "name" in spec:
                    coord = [str(spec["group"]), str(spec["name"])]
            if coord and len(coord) == 2:
                deps.append(Dep("maven", f"{coord[0]}:{coord[1]}"))
    return deps, []


def parse_nuget(text: str) -> Parsed:
    deps = [Dep("nuget", m.group(1) or m.group(2)) for m in NUGET_REF.finditer(text)]
    names = [
        ("nuget", m.group(1)) for m in re.finditer(r"<(?:PackageId|AssemblyName)>\s*([^<\s]+)\s*<", text)
    ]
    return deps, names


def parse_gemfile(text: str) -> Parsed:
    return [Dep("gems", m.group(1)) for m in GEM_REF.finditer(text)], []


def parse_composer(text: str) -> Parsed:
    try:
        doc = json.loads(text)
    except (ValueError, RecursionError):
        return [], []
    if not isinstance(doc, dict):
        return [], []
    deps: list[Dep] = []
    for key, dev in (("require", False), ("require-dev", True)):
        table = doc.get(key)
        if isinstance(table, dict):
            deps += [Dep("composer", n, 0, dev) for n in table]
    return deps, [("composer", doc["name"])] if isinstance(doc.get("name"), str) else []


def parse_pubspec(text: str) -> Parsed:
    deps = []
    section = ""
    for raw in text.splitlines():
        if raw and not raw[0].isspace():
            section = raw.split(":")[0].strip()
            continue
        m = re.match(r"^  ([a-z0-9_]+):", raw)
        if m and section in {"dependencies", "dev_dependencies"}:
            deps.append(Dep("pub", m.group(1), 0, section == "dev_dependencies"))
    name = re.search(r"(?m)^name:\s*([a-z0-9_]+)", text)
    return deps, [("pub", name.group(1))] if name else []


def is_manifest(name: str, rel: str) -> bool:
    lower = name.lower()
    directory = "/" + rel.lower().rsplit("/", 1)[0] + "/" if "/" in rel else "/"
    return (
        lower in MANIFEST_NAMES
        or lower.endswith(MANIFEST_SUFFIXES)
        or bool(REQ_FILE.match(name))
        or (lower.endswith((".txt", ".in")) and "/requirements/" in directory)
    )


def parse_manifest(name: str, rel: str, text: str) -> Parsed:
    lower = name.lower()
    simple = {
        "package.json": parse_package_json, "pyproject.toml": parse_pyproject, "setup.py": parse_setup_py,
        "setup.cfg": parse_setup_cfg, "pipfile": parse_pipfile, "go.mod": parse_go_mod,
        "cargo.toml": parse_cargo, "pom.xml": parse_pom, "build.gradle": parse_gradle,
        "build.gradle.kts": parse_gradle, "composer.json": parse_composer, "pubspec.yaml": parse_pubspec,
        "gemfile": parse_gemfile, "directory.packages.props": parse_nuget,
        "directory.build.props": parse_nuget, "packages.config": parse_nuget,
    }  # fmt: skip
    if lower in simple:
        return simple[lower](text)
    if lower.endswith(".versions.toml"):
        return parse_version_catalog(text)
    if lower.endswith((".csproj", ".fsproj", ".vbproj")):
        return parse_nuget(text)
    if lower.endswith(".gemspec"):
        return parse_gemfile(text)
    directory = rel.lower().rsplit("/", 1)[0] if "/" in rel else ""
    return parse_requirements(text, bool(DEV_NAME.search(lower)) or bool(DEV_NAME.search(directory + "/")))


# ---------------------------------------------------------------------------
# Labelling


class Collector:
    def __init__(self, index: Index) -> None:
        self.index = index
        self.evidence: list[Ev] = []
        self._seen: set[tuple[str, str, str, str]] = set()
        self._counts: Counter[tuple[str, str, str]] = Counter()

    def add(self, ev: Ev) -> None:
        key = (ev.kind, ev.tech, ev.path, ev.detail)
        if key in self._seen or self._counts[(ev.kind, ev.tech, ev.ctx)] >= MAX_EVIDENCE_PER_KEY:
            return
        self._seen.add(key)
        self._counts[(ev.kind, ev.tech, ev.ctx)] += 1
        self.evidence.append(ev)


def scan_repo(root: Path, index: Index) -> dict[str, Any]:
    col = Collector(index)
    inv: Counter[str] = Counter()
    lang: Counter[str] = Counter()
    self_names: list[tuple[str, str]] = []
    truncated = False
    for count, (rel, path, is_link) in enumerate(walk(root, index), 1):
        if count > MAX_FILES:
            truncated = True
            break
        name = rel.rsplit("/", 1)[-1]
        ext = os.path.splitext(name)[1].lower()
        inv["files"] += 1
        low = rel.lower()
        dctx = dir_context(rel, index)
        # Path rules look at the name only, so they also cover symlinks such as CLAUDE.md -> AGENTS.md.
        for rule, rx, exact in index.path_rules:
            if rx.search(low) and (exact is None or name == exact):
                col.add(
                    Ev(
                        "path",
                        rule["id"],
                        rule["tier"],
                        rel,
                        0,
                        "config" if dctx == "src" else dctx,
                        rule["id"],
                    )
                )
        if is_link:
            inv["symlinks"] += 1
            continue
        if ext in EXT_LANG:
            lang[EXT_LANG[ext]] += 1
        ctx = file_context(rel, index)
        if is_manifest(name, rel):
            text = read_text(path, MAX_DATA_BYTES)
            if text is None:
                inv["skipped_large"] += 1
                continue
            inv["manifests"] += 1
            deps, names = parse_manifest(name, rel, text)
            self_names += names
            for dep in deps:
                tid = index.match_dep(dep)
                if tid:
                    kind_ctx = "transitive" if dep.transitive else ("test" if dep.dev else dctx)
                    col.add(Ev("dep", tid, index.tier[tid], rel, dep.line, kind_ctx, f"{dep.eco}:{dep.name}"))
            continue
        if ext in EXT_LANG:
            scan_source(path, rel, ext, ctx, index, col, inv)
        scan_markers(path, rel, ext, ctx, index, col)
        scan_weak(path, name, rel, ext, ctx, index, col)
    return finalize(col, self_names, lang, inv, truncated, index)


def scan_source(
    path: Path, rel: str, ext: str, ctx: str, index: Index, col: Collector, inv: Counter[str]
) -> None:
    text = read_text(path, MAX_DATA_BYTES if ext == ".ipynb" else MAX_TEXT_BYTES)
    if text is None:
        inv["skipped_large"] += 1
        return
    if ext == ".ipynb":
        text, pips = strip_magics(notebook_code(text))
        for spec in pips:
            for token in spec.replace(",", " ").split():
                m = None if token.startswith("-") else REQ_NAME.match(token)
                tid = index.pypi_dist(m.group(1)) if m else None
                if m and tid:
                    col.add(Ev("dep", tid, index.tier[tid], rel, 0, "notebook", f"pypi:{m.group(1)}"))
    if ext in {".py", ".ipynb"}:
        for module, line in py_modules(text):
            hit = index.py_import(module)
            if hit:
                col.add(
                    Ev("import", hit[0], index.tier[hit[0]], rel, line, ctx, f"py:{module}", needs_dep=hit[1])
                )
    elif ext in JS_EXTS:
        for module, line in js_modules(text):
            tid = index.npm_pkg(module)
            if tid:
                needs = module in index.npm_import_needs_dep
                col.add(Ev("import", tid, index.tier[tid], rel, line, ctx, f"js:{module}", needs_dep=needs))
    elif ext == ".go":
        for module, line in go_modules(text):
            tid = index.go_mod(module)
            if tid:
                col.add(Ev("import", tid, index.tier[tid], rel, line, ctx, f"go:{module}"))
    elif ext == ".rs":
        for module, line in regex_modules(RUST_USE, text):
            tid = index.rs_imp.get(norm_crate(module))
            if tid:
                col.add(Ev("import", tid, index.tier[tid], rel, line, ctx, f"rs:{module}", needs_dep=True))
    elif ext in JAVA_EXTS:
        for module, line in regex_modules(JAVA_IMPORT, text):
            tid = index.java_import(module)
            if tid:
                col.add(Ev("import", tid, index.tier[tid], rel, line, ctx, f"java:{module}"))
    elif ext == ".cs":
        for module, line in regex_modules(CS_USING, text):
            tid = index.cs_using(module)
            if tid:
                col.add(Ev("import", tid, index.tier[tid], rel, line, ctx, f"cs:{module}"))
    elif ext == ".rb":
        for module, line in regex_modules(RUBY_REQUIRE, text):
            tid = index.gems.get(module.split("/")[0])
            if tid:
                col.add(Ev("import", tid, index.tier[tid], rel, line, ctx, f"rb:{module}", needs_dep=True))
    elif ext == ".dart":
        for module, line in regex_modules(DART_IMPORT, text):
            tid = index.pub.get(module)
            if tid:
                col.add(Ev("import", tid, index.tier[tid], rel, line, ctx, f"dart:{module}", needs_dep=True))


def scan_markers(path: Path, rel: str, ext: str, ctx: str, index: Index, col: Collector) -> None:
    low = rel.lower()
    applicable = [
        (m, rx) for m, rx, path_rx in index.markers
        if (m.get("exts") is None or ext in m["exts"]) and (path_rx is None or path_rx.search(low))
        and (m.get("exts") is not None or path_rx is not None)
    ]  # fmt: skip
    if not applicable:
        return
    text = read_text(path, MAX_DATA_BYTES)
    if text is None:
        return
    for marker, rx in applicable:
        if any(s in text for s in marker.get("contains", [])) or (rx is not None and rx.search(text)):
            col.add(
                Ev(
                    "content",
                    marker["id"],
                    marker["tier"],
                    rel,
                    0,
                    "config" if ctx == "src" else ctx,
                    marker["id"],
                )
            )


def scan_weak(path: Path, name: str, rel: str, ext: str, ctx: str, index: Index, col: Collector) -> None:
    lower = name.lower()
    if ctx == "docs" or not (
        ext in WEAK_EXTS or lower.startswith((".env", "env.", "dockerfile", "docker-compose"))
    ):
        return
    text = read_text(path, MAX_WEAK_BYTES)
    if text is None:
        return
    low = text.lower()
    for host in index.weak_hosts:
        if host in low:
            col.add(Ev("weak", "host", "weak", rel, 0, ctx, host))
    for var in index.weak_env:
        if var in text:
            col.add(Ev("weak", "env", "weak", rel, 0, ctx, var))


def finalize(
    col: Collector,
    self_names: list[tuple[str, str]],
    lang: Counter[str],
    inv: Counter[str],
    truncated: bool,
    index: Index,
) -> dict[str, Any]:
    dep_techs = {e.tech for e in col.evidence if e.kind == "dep"}
    evidence = [
        e for e in col.evidence if not (e.kind == "import" and e.needs_dep and e.tech not in dep_techs)
    ]
    cls = index.tier_class
    strong = [e for e in evidence if e.kind != "weak" and cls.get(e.tier) in {"agent", "llm"}]
    weak = [e for e in evidence if e.kind == "weak"]
    adjacent = [e for e in evidence if cls.get(e.tier) == "adjacent"]
    strict_items = [e for e in strong if e.ctx in STRICT_CTX]
    app_items = [e for e in strict_items if e.tech not in index.dev_config_ids]

    def has(ctxs: frozenset[str], klass: str | None = None) -> bool:
        return any(e.ctx in ctxs and (klass is None or cls.get(e.tier) == klass) for e in strong)

    library_of = sorted({t for eco, n in self_names if (t := self_tech(index, eco, n)) is not None})
    if strict_items:
        state = "positive"
    elif not strong and not weak and not adjacent:
        state = "negative"
    else:
        state = "ambiguous"
    labels = {
        "state": state,
        "ai_strict": bool(strict_items),
        "app_strict": bool(app_items),
        "devcfg_only": bool(strict_items) and not app_items,
        "ai_core": has(CORE_CTX),
        "ai_loose": bool(strong),
        "agent_strict": has(STRICT_CTX, "agent"),
        "agent_core": has(CORE_CTX, "agent"),
        "agent_loose": any(cls.get(e.tier) == "agent" for e in strong),
        "llm_strict": has(STRICT_CTX, "llm"),
        "dep_only": bool(strict_items) and all(e.kind == "dep" for e in strict_items),
        "weak_only": not strong and bool(weak),
        "adjacent_only": not strong and not weak and bool(adjacent),
        "ml_present": any(cls.get(e.tier) == "ml" for e in evidence),
        "role": "ai-library" if library_of else "consumer",
        "library_of": library_of,
    }
    top = lang.most_common(1)
    return {
        "oracle_version": ORACLE_VERSION,
        "labels": labels,
        "techs": sorted({e.tech for e in strict_items}),
        "evidence": [e.to_json() for e in sorted(evidence, key=lambda e: (e.kind, e.tech, e.path, e.line))],
        "inventory": {
            "files": inv["files"], "symlinks": inv["symlinks"], "manifests": inv["manifests"],
            "languages": dict(lang.most_common(8)), "primary_language": top[0][0] if top else "none",
            "skipped_large": inv["skipped_large"], "truncated": truncated,
        },
    }  # fmt: skip


def self_tech(index: Index, eco: str, name: str) -> str | None:
    """A project whose own name is a registry package (an AI library or SDK) is not a consumer."""
    tid = index.match_dep(Dep(eco, name))
    if tid and index.tier_class.get(index.tier[tid]) in {"agent", "llm"}:
        return tid
    return None


def label_repo(root: Path, index: Index) -> dict[str, Any]:
    return scan_repo(Path(str(root).rstrip("/")), index)


# ---------------------------------------------------------------------------
# CLI

_STATE: dict[str, Index] = {}


def _init_worker(registry: str) -> None:
    _STATE["index"] = load_index(Path(registry))


def _label(args: tuple[str, str]) -> dict[str, Any]:
    repo_id, directory = args
    try:
        result = label_repo(Path(directory), _STATE["index"])
    except (OSError, RecursionError, MemoryError) as exc:
        return {"id": repo_id, "error": f"{type(exc).__name__}: {exc}"[:200]}
    return {"id": repo_id, **result}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument(
        "--manifest", type=Path, required=True, help="JSONL with id and dir (relative to --corpus)"
    )
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args(argv)
    rows = [
        json.loads(line) for line in args.manifest.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    jobs = [(r["id"], str(args.corpus / r["dir"])) for r in rows]
    with ProcessPoolExecutor(
        max_workers=args.workers, initializer=_init_worker, initargs=(str(args.registry),)
    ) as pool:
        results = sorted(pool.map(_label, jobs, chunksize=2), key=lambda r: r["id"])
    with open(args.out, "w", encoding="utf-8") as fh:
        for row in results:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
    states = Counter(r.get("labels", {}).get("state", "error") for r in results)
    print(json.dumps(dict(sorted(states.items()))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
