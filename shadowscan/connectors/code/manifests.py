"""Dependency manifest, container, IaC and CI file parsers for the code scanner.

Each parser returns lightweight :class:`Dep` / :class:`Artifact` records that
the filesystem connector matches against signatures. Parsers are tolerant:
they never raise on malformed input, they just return what they can.
"""

from __future__ import annotations

import json
import tomllib
import xml.etree.ElementTree as ET
from bisect import bisect_left, bisect_right
from collections.abc import Iterator
from dataclasses import dataclass, field
from functools import partial
from pathlib import PurePosixPath
from time import monotonic
from typing import Any

import regex as re
import yaml

from shadowscan.signatures.matcher import _run_regex, pattern_timeout
from shadowscan.utils.safe_json import strict_json_loads
from shadowscan.utils.safe_yaml import YAMLResourceLimitError, strict_bounded_safe_load

# Regex execution here runs outside the signature matcher. A per-pattern
# ceiling well above the matcher's 100 ms keeps ordinary large manifests from
# timing out under GIL contention between parallel connectors, while the
# filesystem connector's per-file scan budget still caps the total.
MANIFEST_PATTERN_SECONDS = 1.0


def _pattern_timeout() -> float:
    return pattern_timeout(MANIFEST_PATTERN_SECONDS)


# Keep bounded regex calls on their calling thread. Releasing/reacquiring the
# GIL for each tiny match can spend a 100ms wall deadline waiting behind other
# connector threads. ``concurrent=False`` retains regex-engine preemption for
# hostile patterns while avoiding that scheduling overhead.


@dataclass(slots=True)
class Dep:
    ecosystem: str  # pypi | npm | go | cargo | maven | nuget | rubygems | composer | conda
    name: str
    spec: str | None = None
    line: int | None = None
    dev: bool = False


@dataclass(slots=True)
class Artifact:
    """Non-dependency signal extracted from a manifest."""

    kind: str  # image | env | iac | action | secret_ref
    value: str
    line: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ManifestResult:
    deps: list[Dep] = field(default_factory=list)
    artifacts: list[Artifact] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _mapping(value: Any, result: ManifestResult, section: str) -> dict[str, Any]:
    if value is None and section != "document":
        return {}
    if isinstance(value, dict):
        return value
    result.errors.append(f"{section} must be an object")
    return {}


def _sequence(value: Any, result: ManifestResult, section: str) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    result.errors.append(f"{section} must be an array")
    return []


MANIFEST_FILENAMES = {
    "requirements.txt",
    "requirements-dev.txt",
    "requirements_dev.txt",
    "requirements-test.txt",
    "dev-requirements.txt",
    "constraints.txt",
    "pyproject.toml",
    "Pipfile",
    "setup.py",
    "setup.cfg",
    "environment.yml",
    "environment.yaml",
    "package.json",
    "go.mod",
    "Cargo.toml",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "packages.config",
    "Directory.Packages.props",
    "Gemfile",
    "composer.json",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
    "values.yaml",
    "Chart.yaml",
    "serverless.yml",
    "serverless.yaml",
    "template.yaml",
    "template.yml",
    "template.json",
    "samconfig.toml",
    "wrangler.toml",
    "wrangler.json",
    "wrangler.jsonc",
    "vercel.json",
    "fly.toml",
    "app.yaml",
    "Procfile",
    ".env",
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.local",
    ".env.development",
    ".env.production",
    "cloudbuild.yaml",
    "skaffold.yaml",
    "Modelfile",
}

_REQ_LINE = re.compile(r"^[ \t]*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*([<>=!~;@ ].*)?$")
_REQ_DIRECT_REF = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\]\s*)?@\s*\S")
_GIT_URL = re.compile(
    r"(?:git\+)?(?:https?|ssh|git)://[^\s#]+?/([A-Za-z0-9_.-]+?)(?:\.git)?(?:@[^\s#]+)?(?:#.*)?$"
)


def parse_requirements(text: str) -> ManifestResult:
    res = ManifestResult()
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if line.startswith(("-e ", "--editable ")):
            line = line.split(None, 1)[1].strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # A PEP 508 direct reference declares its distribution name before
        # the URL. Prefer that name over a URL basename or legacy #egg hint,
        # and preserve fragments, extras and environment markers in the spec.
        direct = _REQ_DIRECT_REF.match(line, timeout=_pattern_timeout(), concurrent=False)
        if direct:
            res.deps.append(Dep("pypi", direct.group(1), line, i))
            continue
        if line.startswith(("http://", "https://", "git+", "ssh://", "git://")) or "://" in line:
            # The fragment is part of a VCS requirement, not a comment.
            egg = re.search(
                r"(?:#|&)egg=([A-Za-z0-9_.-]+)",
                line,
                timeout=_pattern_timeout(),
                concurrent=False,
            )
            if egg:
                res.deps.append(Dep("pypi", egg.group(1), line, i))
                continue
            m = _GIT_URL.search(line.split("#", 1)[0], timeout=_pattern_timeout(), concurrent=False)
            if m:
                res.deps.append(Dep("pypi", m.group(1), line, i))
            continue
        line = line.split("#", 1)[0].strip()
        m = _REQ_LINE.match(line, timeout=_pattern_timeout(), concurrent=False)
        if m:
            res.deps.append(Dep("pypi", m.group(1), (m.group(3) or "").strip() or None, i))
    return res


def _pep508_name(spec: str) -> str | None:
    spec = spec.strip()
    m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", spec, timeout=_pattern_timeout(), concurrent=False)
    return m.group(1) if m else None


def parse_pyproject(text: str) -> ManifestResult:
    res = ManifestResult()
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        res.errors.append("invalid TOML")
        return res
    project = _mapping(data.get("project"), res, "project")
    for spec in _sequence(project.get("dependencies"), res, "project.dependencies"):
        if isinstance(spec, str) and (n := _pep508_name(spec)):
            res.deps.append(Dep("pypi", n, spec))
    for group, specs in _mapping(
        project.get("optional-dependencies"),
        res,
        "project.optional-dependencies",
    ).items():
        for spec in _sequence(specs, res, "project.optional-dependencies group"):
            if isinstance(spec, str) and (n := _pep508_name(spec)):
                res.deps.append(Dep("pypi", n, spec, dev=group in {"dev", "test", "tests", "lint"}))
    for specs in _mapping(data.get("dependency-groups"), res, "dependency-groups").values():
        for spec in _sequence(specs, res, "dependency-groups group"):
            if isinstance(spec, str) and (n := _pep508_name(spec)):
                res.deps.append(Dep("pypi", n, spec, dev=True))
    tool = _mapping(data.get("tool"), res, "tool")
    poetry = _mapping(tool.get("poetry"), res, "tool.poetry")
    for name, spec in _mapping(poetry.get("dependencies"), res, "tool.poetry.dependencies").items():
        if name.lower() != "python":
            res.deps.append(Dep("pypi", name, json.dumps(spec) if not isinstance(spec, str) else spec))
    for group in _mapping(poetry.get("group"), res, "tool.poetry.group").values():
        for name, spec in _mapping(
            _mapping(group, res, "tool.poetry.group entry").get("dependencies"),
            res,
            "group.dependencies",
        ).items():
            res.deps.append(Dep("pypi", name, str(spec), dev=True))
    for name, spec in _mapping(poetry.get("dev-dependencies"), res, "tool.poetry.dev-dependencies").items():
        res.deps.append(Dep("pypi", name, str(spec), dev=True))
    uv = _mapping(tool.get("uv"), res, "tool.uv")
    for spec in _sequence(uv.get("dev-dependencies"), res, "tool.uv.dev-dependencies"):
        if isinstance(spec, str) and (n := _pep508_name(spec)):
            res.deps.append(Dep("pypi", n, spec, dev=True))
    # image / env style hints sometimes live in pyproject (e.g. tool.langgraph)
    return res


def parse_pipfile(text: str) -> ManifestResult:
    res = ManifestResult()
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        res.errors.append("invalid TOML")
        return res
    for section, dev in (("packages", False), ("dev-packages", True)):
        for name, spec in _mapping(data.get(section), res, section).items():
            res.deps.append(Dep("pypi", name, str(spec), dev=dev))
    return res


_SETUP_REQ = re.compile(
    r"(?:install_requires|extras_require|tests_require|setup_requires)\s*=\s*(\[[^\]]*\]|\{[^}]*\})",
    re.S,
)
_STR = re.compile(r"""["']([^"']+)["']""")


def parse_setup_py(text: str) -> ManifestResult:
    res = ManifestResult()
    for m in _SETUP_REQ.finditer(text, timeout=_pattern_timeout(), concurrent=False):
        for s in _STR.findall(m.group(1), timeout=_pattern_timeout(), concurrent=False):
            n = _pep508_name(s)
            if n:
                res.deps.append(Dep("pypi", n, s))
    return res


def parse_setup_cfg(text: str) -> ManifestResult:
    res = ManifestResult()
    in_reqs = False
    for line in text.splitlines():
        if re.match(
            r"^[ \t]*(install_requires|tests_require)\s*=",
            line,
            timeout=_pattern_timeout(),
            concurrent=False,
        ):
            in_reqs = True
            rest = line.split("=", 1)[1].strip()
            if rest and (n := _pep508_name(rest)):
                res.deps.append(Dep("pypi", n, rest))
            continue
        if in_reqs:
            if line.startswith((" ", "\t")) and line.strip():
                n = _pep508_name(line.strip())
                if n:
                    res.deps.append(Dep("pypi", n, line.strip()))
            else:
                in_reqs = False
    return res


def parse_conda_env(text: str) -> ManifestResult:
    res = ManifestResult()
    try:
        data = strict_bounded_safe_load(text)
    except YAMLResourceLimitError:
        res.errors.append("YAML safety limit exceeded")
        return res
    except (ValueError, RecursionError, yaml.YAMLError):
        # SafeLoader raises a plain ValueError for an impossible date or an
        # integer beyond Python's digit limit: the document is malformed.
        res.errors.append("invalid YAML")
        return res
    data = _mapping(data, res, "document")
    for item in _sequence(data.get("dependencies"), res, "dependencies"):
        if isinstance(item, str):
            name = re.split(r"[=<>!~ ]", item, 1)[0]
            if "::" in name:
                name = name.split("::", 1)[1]
            res.deps.append(Dep("conda", name, item))
        elif isinstance(item, dict) and "pip" in item:
            for spec in _sequence(item["pip"], res, "dependencies.pip"):
                if isinstance(spec, str) and (n := _pep508_name(spec)):
                    res.deps.append(Dep("pypi", n, spec))
    return res


# An npm alias installs the registry package named after ``npm:``. The map
# key is only its local import name; attributing that key can both miss a
# framework and invent one when a known name aliases an unrelated package.
# Keep the version/range opaque, like ordinary dependency versions. Registry
# names include legacy URL-safe punctuation and scoped names can begin with
# underscore/hyphen; current publishing rules are stricter than installation.
_NPM_ALIAS = re.compile(r"(?i:npm:)((?:@[A-Za-z0-9._~!'()*-]+/)?[A-Za-z0-9._~!'()*-]+)(?:@.*)?")


def parse_package_json(text: str) -> ManifestResult:
    res = ManifestResult()
    try:
        data = strict_json_loads(text)
    except ValueError:
        res.errors.append("invalid JSON")
        return res
    data = _mapping(data, res, "document")
    for section, dev in (
        ("dependencies", False),
        ("devDependencies", True),
        ("peerDependencies", False),
        ("optionalDependencies", False),
    ):
        for name, spec in _mapping(data.get(section), res, section).items():
            if not isinstance(spec, str):
                res.errors.append(f"{section} dependency version must be a string")
                continue
            if spec[:4].lower() == "npm:":
                alias = _NPM_ALIAS.fullmatch(spec, timeout=_pattern_timeout(), concurrent=False)
                if (
                    alias is None
                    or alias.group(1).startswith((".", "_", "-"))
                    or alias.group(1).rsplit("/", 1)[-1].startswith(".")
                ):
                    res.errors.append(f"{section} dependency has an invalid npm alias target")
                    continue
                name = alias.group(1)
            res.deps.append(Dep("npm", name, spec, dev=dev))
    scripts = _mapping(data.get("scripts"), res, "scripts")
    for _, cmd in scripts.items():
        if isinstance(cmd, str):
            for pkg in re.findall(
                r"npx\s+(?:-y\s+)?(@?[A-Za-z0-9_./-]+)",
                cmd,
                timeout=_pattern_timeout(),
                concurrent=False,
            ):
                res.deps.append(
                    Dep(
                        "npm",
                        pkg.split("@", 1)[0] if not pkg.startswith("@") else "@" + pkg[1:].split("@", 1)[0],
                        cmd,
                    )
                )
    return res


_GO_REQUIRE_BLOCK = re.compile(r"require\s*\((.*?)\)", re.S)
_GO_REQUIRE_LINE = re.compile(r"^[ \t]*require\s+(\S+)\s+(\S+)", re.M)
_GO_MOD_LINE = re.compile(r"^[ \t]*(\S+)\s+(v\S+)", re.M)


def parse_go_mod(text: str) -> ManifestResult:
    res = ManifestResult()
    for block in _GO_REQUIRE_BLOCK.findall(text, timeout=_pattern_timeout(), concurrent=False):
        for m in _GO_MOD_LINE.finditer(block, timeout=_pattern_timeout(), concurrent=False):
            res.deps.append(Dep("go", m.group(1), m.group(2)))
    for m in _GO_REQUIRE_LINE.finditer(text, timeout=_pattern_timeout(), concurrent=False):
        res.deps.append(Dep("go", m.group(1), m.group(2)))
    return res


def parse_cargo_toml(text: str) -> ManifestResult:
    res = ManifestResult()
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        res.errors.append("invalid TOML")
        return res
    workspace = _mapping(data.get("workspace"), res, "workspace")
    sections = [
        (_mapping(data.get("dependencies"), res, "dependencies"), False),
        (_mapping(data.get("dev-dependencies"), res, "dev-dependencies"), True),
        (_mapping(data.get("build-dependencies"), res, "build-dependencies"), True),
        (_mapping(workspace.get("dependencies"), res, "workspace.dependencies"), False),
    ]
    for target in _mapping(data.get("target"), res, "target").values():
        if isinstance(target, dict):
            sections.append((_mapping(target.get("dependencies"), res, "target dependencies"), False))
        else:
            res.errors.append("target entry must be an object")
    for section, dev in sections:
        for name, spec in section.items():
            real = spec.get("package", name) if isinstance(spec, dict) else name
            if not isinstance(real, str):
                res.errors.append("dependency package name must be a string")
                continue
            res.deps.append(Dep("cargo", real, str(spec), dev=dev))
    return res


def parse_pom(text: str) -> ManifestResult:
    res = ManifestResult()
    # XML comments often contain sample dependencies. Parse the document rather
    # than extracting <dependency> tags with a regex, which treats comments as
    # active configuration. Maven POMs also commonly use a default namespace.
    # No DTD is needed for dependency extraction; reject entities to keep
    # parsing an untrusted repository bounded even with older Expat versions.
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        res.errors.append("POM DTD/entity declarations are unsupported")
        return res
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        res.errors.append("invalid POM XML")
        return res

    for dependency in root.iter():
        if dependency.tag.rsplit("}", 1)[-1] != "dependency":
            continue
        tags: dict[str, str] = {}
        ambiguous = False
        for child in dependency:
            tag = child.tag.rsplit("}", 1)[-1]
            if tag in {"groupId", "artifactId", "version", "scope"} and tag in tags:
                ambiguous = True
            tags[tag] = (child.text or "").strip()
        if ambiguous:
            res.errors.append("POM dependency contains a duplicate meaningful field")
            continue
        g, a = tags.get("groupId"), tags.get("artifactId")
        if g and a:
            res.deps.append(Dep("maven", f"{g}:{a}", tags.get("version"), dev=tags.get("scope") == "test"))
    return res


_GRADLE_DEP = re.compile(
    r"""\b(implementation|api|compile|compileOnly|runtimeOnly|testImplementation|testCompile|kapt"""
    r"""|annotationProcessor|developmentOnly)\s*\(?\s*["']([^"':]+):([^"':]+)(?::([^"']+))?["']"""
)
_GRADLE_PLATFORM = re.compile(
    r"""(?:platform|enforcedPlatform)\s*\(\s*["']([^"':]+):([^"':]+)(?::([^"']+))?["']"""
)


def _gradle_slashy_start(text: str, position: int) -> bool:
    """Recognize a Groovy slashy literal where an expression can begin."""
    before = position - 1
    while before >= 0 and text[before].isspace():
        before -= 1
    if before < 0 or text[before] in "=([{,:!~?":
        return True
    end = before + 1
    while before >= 0 and (text[before].isalnum() or text[before] == "_"):
        before -= 1
    return text[before + 1 : end] in {"return", "case", "assert"}


def _mask_manifest_comments(
    text: str, *, shell: bool = False, kotlin: bool = False
) -> tuple[str, list[tuple[int, int]], bool]:
    """Mask comments without moving offsets or interpreting quoted markers.

    Gradle accepts Java-style comments and quoted/triple-quoted strings. Kotlin
    additionally permits nested block comments. Docker shell comments begin at
    a word boundary; URL fragments and quoted/escaped hashes stay literal.
    The returned inert spans also keep Gradle example strings from becoming
    dependency declarations. This is a bounded lexical filter, not execution.
    """
    masked = list(text)
    ignored: list[tuple[int, int]] = []
    incomplete = False
    i, size, next_check = 0, len(text), 0

    def check_budget(position: int) -> None:
        nonlocal next_check
        if position >= next_check:
            _pattern_timeout()
            next_check = position + 4096

    def mask(start: int, end: int) -> None:
        ignored.append((start, end))
        for position in range(start, end):
            if text[position] not in "\r\n":
                masked[position] = " "

    while i < size:
        check_budget(i)
        start = i
        char = text[i]
        if shell and char == "\\":
            i += 2
        elif (
            not shell
            and not kotlin
            and char == "/"
            and not text.startswith(("//", "/*"), i)
            and _gradle_slashy_start(text, i)
        ):
            i += 1
            while i < size and text[i] != "/":
                check_budget(i)
                i += 2 if text.startswith("\\/", i) else 1
            closed = i < size
            i = min(size, i + 1) if closed else size
            ignored.append((start, i))
            incomplete = incomplete or not closed
        elif not shell and text.startswith("$/", i):
            # Groovy dollar-slashy strings use '$' to escape '$' and '/'.
            i += 2
            while i < size and not text.startswith("/$", i):
                check_budget(i)
                i += 2 if text[i] == "$" and text[i + 1 : i + 2] in {"$", "/"} else 1
            closed = i < size
            i = min(size, i + 2) if closed else size
            ignored.append((start, i))
            incomplete = incomplete or not closed
        elif char in "\"'":
            delimiter = char * 3 if not shell and text.startswith(char * 3, i) else char
            escaped = not (shell and char == "'" or kotlin and delimiter == '"""')
            i += len(delimiter)
            while i < size and not text.startswith(delimiter, i):
                check_budget(i)
                i += 2 if text[i] == "\\" and escaped else 1
            closed = i < size
            i = min(size, i + len(delimiter)) if closed else size
            ignored.append((start, i))
            incomplete = incomplete or not closed
        elif (not shell and text.startswith("//", i)) or (
            shell and char == "#" and (not i or text[i - 1].isspace() or text[i - 1] in ";|&()")
        ):
            end = text.find("\n", i)
            i = size if end < 0 else end
            mask(start, i)
        elif not shell and text.startswith("/*", i):
            depth = 1
            i += 2
            while i < size and depth:
                check_budget(i)
                if kotlin and text.startswith("/*", i):
                    depth += 1
                    i += 2
                elif text.startswith("*/", i):
                    depth -= 1
                    i += 2
                else:
                    i += 1
            incomplete = incomplete or bool(depth)
            mask(start, i)
        else:
            i += 1
    return "".join(masked), ignored, incomplete


def manifest_comment_projection(relpath: str, text: str) -> str:
    """Share comment filtering with generic code detection; keep all line offsets.

    This projection must not replace the original input to credential scanning:
    credentials can remain sensitive even inside a comment.
    """
    lower = PurePosixPath(relpath.replace("\\", "/")).name.lower()
    if (
        lower == "dockerfile"
        or lower.startswith("dockerfile.")
        or lower.endswith(".dockerfile")
        or lower == "containerfile"
    ):
        return _docker_comment_projection(text)
    if lower.endswith((".gradle", ".gradle.kts")):
        return _mask_manifest_comments(text, kotlin=lower.endswith(".kts"))[0]
    return text


def parse_gradle(text: str, *, kotlin: bool = False) -> ManifestResult:
    res = ManifestResult()
    masked, ignored, incomplete = _mask_manifest_comments(text, kotlin=kotlin)
    if incomplete:
        res.errors.append("unterminated Gradle comment or string")
    starts = [start for start, _ in ignored]
    lines = _LineIndex(text)
    for pattern, offset in ((_GRADLE_DEP, 1), (_GRADLE_PLATFORM, 0)):
        for m in pattern.finditer(masked, timeout=_pattern_timeout(), concurrent=False):
            preceding = bisect_right(starts, m.start()) - 1
            if preceding >= 0 and m.start() < ignored[preceding][1]:
                continue
            res.deps.append(
                Dep(
                    "maven",
                    f"{m.group(1 + offset)}:{m.group(2 + offset)}",
                    m.group(3 + offset),
                    lines.at(m.start()),
                    dev=bool(offset and m.group(1).startswith("test")),
                )
            )
    return res


def parse_nuget(text: str) -> ManifestResult:
    res = ManifestResult()
    # Package manifests never need document types or entities. Reject them
    # before parsing so comments stay inert and Expat cannot expand attacker-
    # controlled declarations on runtimes with weaker amplification limits.
    upper = text.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        res.errors.append("NuGet DTD/entity declarations are unsupported")
        return res
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        res.errors.append("invalid NuGet XML")
        return res

    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1].lower() not in {
            "packagereference",
            "packageversion",
            "package",
        }:
            continue
        identities: list[str] = []
        versions: list[str] = []
        for attribute, value in element.attrib.items():
            key = attribute.rsplit("}", 1)[-1].lower()
            if key in {"include", "id"}:
                identities.append(value.strip())
            elif key == "version":
                versions.append(value.strip())
        if len(identities) > 1 or len(versions) > 1:
            res.errors.append("NuGet dependency contains ambiguous attributes")
            continue
        if identities and identities[0]:
            res.deps.append(Dep("nuget", identities[0], versions[0] if versions else None))
    return res


_GEM = re.compile(r"""^[ \t]*gem\s+["']([^"']+)["'](?:\s*,\s*["']([^"']+)["'])?""", re.M)


def parse_gemfile(text: str) -> ManifestResult:
    res = ManifestResult()
    for m in _GEM.finditer(text, timeout=_pattern_timeout(), concurrent=False):
        res.deps.append(Dep("rubygems", m.group(1), m.group(2)))
    return res


def parse_composer(text: str) -> ManifestResult:
    res = ManifestResult()
    try:
        data = strict_json_loads(text)
    except ValueError:
        res.errors.append("invalid JSON")
        return res
    data = _mapping(data, res, "document")
    for section, dev in (("require", False), ("require-dev", True)):
        for name, spec in _mapping(data.get(section), res, section).items():
            if "/" in name:
                res.deps.append(Dep("composer", name, str(spec), dev=dev))
    return res


_DOCKER_FROM = re.compile(r"^[ \t]*FROM\s+(?:--platform=\S+\s+)?(\S+)", re.I | re.M)
_DOCKER_ENV = re.compile(r"^[ \t]*(?:ENV|ARG)\s+([A-Z][A-Z0-9_]+)", re.I | re.M)
_DOCKER_ENV_MULTI = re.compile(r"^[ \t]*ENV\s+(.+)$", re.I | re.M)
_DOCKER_PIP = re.compile(r"pip3?\s+install\s+([^&|;\n\\]+)", re.I)
_DOCKER_NPM = re.compile(
    r"(?:npm\s+(?:install|i|add)|yarn\s+add|pnpm\s+(?:add|install))\s+([^&|;\n\\]+)",
    re.I,
)
_DOCKER_UV = re.compile(r"uv\s+(?:pip\s+install|add)\s+([^&|;\n\\]+)", re.I)


class _LineIndex:
    """Map match offsets to line numbers with one newline scan per input.

    Counting newlines from the start of the text for every match is quadratic
    and, because the regex iterator timeout also charges caller work, made
    ordinary large manifests trip the 0.1 s per-pattern limit.
    """

    __slots__ = ("_offsets", "_text")

    def __init__(self, text: str) -> None:
        self._text = text
        self._offsets: list[int] | None = None

    def at(self, position: int) -> int:
        if self._offsets is None:
            self._offsets = [match.start() for match in re.finditer("\n", self._text)]
        return bisect_left(self._offsets, position) + 1


def _unique_artifacts(artifacts: list[Artifact]) -> list[Artifact]:
    """Drop repeated observations of one value on one line (e.g. ``ENV A=`` matched twice)."""
    seen: set[tuple[str, str, int | None, str]] = set()
    unique: list[Artifact] = []
    for artifact in artifacts:
        key = (artifact.kind, artifact.value, artifact.line, repr(artifact.extra))
        if key in seen:
            continue
        seen.add(key)
        unique.append(artifact)
    return unique


# A parser directive: "#", a name, "=" and a value, blanks allowed around each.
# Possessive, so a long run of blanks costs one pass.
_DOCKER_DIRECTIVE = re.compile(r"#[\t\f\r ]*+([A-Za-z][A-Za-z0-9]*+)[\t\f\r ]*+=")
_DOCKER_DIRECTIVES = frozenset({"syntax", "escape", "check"})


def _docker_escape(text: str) -> str:
    """Read the optional escape parser directive the way BuildKit does.

    Directives are read from the leading lines only: the first line that is not
    a known directive (a comment, a blank line, an unknown directive or an
    instruction) ends them, and a later ``# escape=`` is an ordinary comment.
    Honouring it there let a trailing backtick join the next instruction into a
    shell comment that Docker never sees.
    """
    escape = "\\"
    for raw in text.split("\n"):
        line = raw.rstrip("\r").lstrip()
        directive = _DOCKER_DIRECTIVE.match(line, timeout=_pattern_timeout(), concurrent=False)
        value = line[directive.end() :].strip(" \t\f\r") if directive is not None else ""
        if directive is None or not value or directive[1].lower() not in _DOCKER_DIRECTIVES:
            break
        if directive[1].lower() == "escape" and value in {"\\", "`"}:
            escape = value
    return escape


def _docker_continues(body: str, escape: str) -> bool:
    trimmed = body.rstrip()
    return bool((len(trimmed) - len(trimmed.rstrip(escape))) % 2)


_DOCKER_COMMAND = re.compile(r"^[ \t]*(?:RUN|CMD|ENTRYPOINT)[ \t]+(?:--\S+[ \t]+)*(.*)$", re.I)


def _docker_comment_projection(text: str) -> str:
    """Mask Docker comments, with inline shell comments limited to shell form.

    Docker's ENV/ARG/LABEL/COPY arguments and JSON-form instructions treat '#'
    as literal data. Only shell-form RUN/CMD/ENTRYPOINT interpret an unquoted
    word-boundary hash as an inline comment. Keep quoted strings and all source
    offsets intact; this does not interpret scripts embedded in JSON strings.
    """
    escape = _docker_escape(text)
    projected: list[str] = []
    pending: list[str] = []
    shell_form = False

    def flush() -> None:
        instruction = "".join(pending)
        if shell_form:
            # Docker removes escaped newlines before the shell sees '#'. A
            # comment can therefore consume several physical source lines.
            # Resolve spans on the joined instruction, then mask those same
            # offsets in the original so generic detection retains line IDs.
            logical = _docker_join_continuations(instruction, escape)
            _, ignored, _ = _mask_manifest_comments(logical, shell=True)
            masked = list(instruction)
            for start, end in ignored:
                if logical[start] == "#":
                    for position in range(start, end):
                        if instruction[position] not in "\r\n":
                            masked[position] = " "
            instruction = "".join(masked)
        projected.append(instruction)
        pending.clear()

    for line in text.splitlines(keepends=True):
        if line.lstrip(" \t").startswith("#"):
            line = "".join(char if char in "\r\n" else " " for char in line)
        body = line.rstrip("\r\n")
        if not pending and not body.strip():
            projected.append(line)
            continue
        if not pending:
            command = _DOCKER_COMMAND.match(body, timeout=_pattern_timeout(), concurrent=False)
            shell_form = bool(
                command and command.group(1).strip() and not command.group(1).lstrip().startswith("[")
            )
        pending.append(line)
        # Docker ignores blank/comment-only lines inside a continuation.
        if body.strip() and not _docker_continues(body, escape):
            flush()
    if pending:
        flush()
    return "".join(projected)


def _docker_join_continuations(text: str, escape: str) -> str:
    """Join escaped lines and intervening empty/comment lines without moving offsets."""
    projected: list[str] = []
    continued = False
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        if continued and not body.strip():
            projected.append(" " * len(line))
            continue
        trimmed = body.rstrip()
        continued = _docker_continues(body, escape)
        if continued:
            marker = len(trimmed) - 1
            projected.append(line[:marker] + " " * (len(line) - marker))
        else:
            projected.append(line)
    return "".join(projected)


def _docker_command_text(text: str) -> str:
    """Project Docker comments and continuations without moving token offsets."""
    return _docker_join_continuations(_docker_comment_projection(text), _docker_escape(text))


def parse_dockerfile(text: str) -> ManifestResult:
    res = ManifestResult()
    lines = _LineIndex(text)
    text = _docker_command_text(text)
    for m in _DOCKER_FROM.finditer(text, timeout=_pattern_timeout(), concurrent=False):
        img = m.group(1)
        if img.lower() != "scratch" and "$" not in img:
            res.artifacts.append(Artifact("image", img, lines.at(m.start())))
    for m in _DOCKER_ENV_MULTI.finditer(text, timeout=_pattern_timeout(), concurrent=False):
        for name in re.findall(
            r"([A-Z][A-Z0-9_]+)\s*=",
            m.group(1),
            timeout=_pattern_timeout(),
            concurrent=False,
        ):
            res.artifacts.append(Artifact("env", name, lines.at(m.start())))
    for m in _DOCKER_ENV.finditer(text, timeout=_pattern_timeout(), concurrent=False):
        res.artifacts.append(Artifact("env", m.group(1), lines.at(m.start())))
    for rx in (_DOCKER_PIP, _DOCKER_UV):
        for m in rx.finditer(text, timeout=_pattern_timeout(), concurrent=False):
            for tok in m.group(1).split():
                if (
                    tok.startswith("-")
                    or tok in {"install", "."}
                    or "=" in tok
                    and not re.match(
                        r"^[A-Za-z0-9_.-]+==",
                        tok,
                        timeout=_pattern_timeout(),
                        concurrent=False,
                    )
                ):
                    continue
                n = _pep508_name(tok)
                if n and n.lower() not in {"pip", "setuptools", "wheel", "poetry", "uv", "pipenv", "r"}:
                    res.deps.append(Dep("pypi", n, tok, lines.at(m.start())))
    for m in _DOCKER_NPM.finditer(text, timeout=_pattern_timeout(), concurrent=False):
        for tok in m.group(1).split():
            if tok.startswith("-") or tok in {"install", "add"}:
                continue
            name = tok if tok.startswith("@") else tok.split("@", 1)[0]
            if name.startswith("@"):
                name = "@" + name[1:].split("@", 1)[0]
            res.deps.append(Dep("npm", name, tok, lines.at(m.start())))
    return res


_YAML_IMAGE = re.compile(r"^[ \t]*(?:-[ \t]*)?image[ \t]*:[ \t]*['\"]?([^'\"\s#]+)", re.M)
_YAML_REPO = re.compile(r"^[ \t]*repository[ \t]*:[ \t]*['\"]?([^'\"\s#]+)", re.M)
_YAML_ENV_KEY = re.compile(
    r"^[ \t]*+-?[ \t]*+(?:name[ \t]*+:[ \t]*+)?['\"]?([A-Z][A-Z0-9_]{2,})['\"]?[ \t]*+[:=]",
    re.M,
)
_YAML_USES = re.compile(r"^[ \t]*+-?[ \t]*+uses[ \t]*+:[ \t]*+['\"]?([^'\"\s#]+)", re.M)
_SECRETS_REF = re.compile(r"\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}")
_GITLAB_IMAGE = re.compile(r"^[ \t]*image\s*:\s*(?:name\s*:\s*)?['\"]?([^'\"\s#]+)", re.M)


def _chunk_matches(
    pattern: re.Pattern[str],
    text: str,
    start: int,
    end: int,
    ceiling: float,
    timeout: float,
) -> list[re.Match[str]]:
    """Return every match in ``text[start:end]``, each attempt bounded by ``timeout`` and ``ceiling``."""
    return list(pattern.finditer(text, start, end, timeout=min(timeout, ceiling), concurrent=False))


def _yaml_line_matches(pattern: re.Pattern[str], text: str, deadline: float) -> Iterator[re.Match[str]]:
    """Keep each regex deadline short without charging a whole file's matches to it.

    The patterns passed here are line-bound. An exceptionally long single line
    remains intact and still has the regex timeout; it cannot evade the limit.
    The shared deadline also bounds the total cost of all ordinary chunks.
    """
    start = 0
    while start < len(text):
        end = min(start + 4096, len(text))
        if end < len(text):
            newline = text.rfind("\n", start, end)
            if newline < start:
                newline = text.find("\n", end)
            end = len(text) if newline < 0 else newline + 1
        remaining = min(deadline - monotonic(), _pattern_timeout())
        if remaining <= 0:
            raise TimeoutError("YAML manifest matching exceeded its time budget")
        # Materialize only this bounded line chunk before caller processing;
        # regex iterators otherwise charge artifact construction and unrelated
        # worker CPU to matching. Reuse the matcher contention retry budget.
        matches = _run_regex(
            partial(_chunk_matches, pattern, text, start, end, remaining),
            "YAML manifest",
            max_seconds=remaining,
        )
        if monotonic() > deadline:
            raise TimeoutError("YAML manifest matching exceeded its time budget")
        yield from matches
        start = end


def parse_compose_or_k8s(text: str) -> ManifestResult:
    """docker-compose, Kubernetes manifests, Helm values, CI configs: images + env keys."""
    res = ManifestResult()
    deadline = monotonic() + _pattern_timeout()
    lines = _LineIndex(text)
    for m in _yaml_line_matches(_YAML_IMAGE, text, deadline):
        res.artifacts.append(Artifact("image", m.group(1), lines.at(m.start())))
    for m in _yaml_line_matches(_YAML_REPO, text, deadline):
        val = m.group(1)
        if "/" in val and not val.startswith(("http", "git@")):
            res.artifacts.append(Artifact("image", val, lines.at(m.start())))
    for m in _yaml_line_matches(_YAML_ENV_KEY, text, deadline):
        res.artifacts.append(Artifact("env", m.group(1), lines.at(m.start())))
    for m in _yaml_line_matches(_YAML_USES, text, deadline):
        res.artifacts.append(Artifact("action", m.group(1), lines.at(m.start())))
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise TimeoutError("YAML manifest matching exceeded its time budget")
    # Secret references can span lines; scan these with the same shared budget.
    for m in _SECRETS_REF.finditer(text, timeout=min(0.1, remaining, _pattern_timeout()), concurrent=False):
        res.artifacts.append(Artifact("secret_ref", m.group(1), lines.at(m.start())))
    return res


_TF_RESOURCE = re.compile(r"""^[ \t]*(?:resource|data)\s+["']([A-Za-z0-9_]+)["']\s+["']([^"']+)["']""", re.M)
_TF_MODULE_SOURCE = re.compile(r"""^[ \t]*source\s*=\s*["']([^"']+)["']""", re.M)
_CFN_TYPE = re.compile(r"""^[ \t]*(?:"Type"|Type)\s*:\s*['"]?((?:AWS|Alexa|Custom)::[A-Za-z0-9:]+)""", re.M)
_ARM_TYPE = re.compile(r"""["']type["']\s*:\s*["']((?:Microsoft|Oracle|Google)\.[A-Za-z0-9./]+)["']""", re.I)
_BICEP_RESOURCE = re.compile(r"""^[ \t]*resource\s+\w+\s+['"]([A-Za-z0-9./]+)@[^'"]+['"]""", re.M)
_PULUMI_TYPE = re.compile(r"""\b(?:aws|gcp|azure|azure_native|azurerm|oci)[.:][a-z_]+[.:][A-Z][A-Za-z]+""")
_CDK_IMPORT = re.compile(
    r"""(?:from\s+aws_cdk\s+import\s+([^\n]+)|aws-cdk-lib/([a-z_-]+)|@aws-cdk/([a-z_-]+)"""
    r"""|aws_cdk\.([a-z_]+))"""
)


_TF_DISPLAY = re.compile(
    r"""^[ \t]*(?:agent_name|display_name|function_name|name|bot_name|app_name|workflow_name)"""
    r"""\s*=\s*["']([^"'$]+)["']""",
    re.M,
)


def parse_terraform(text: str) -> ManifestResult:
    res = ManifestResult()
    lines = _LineIndex(text)
    starts = [
        (m.start(), m) for m in _TF_RESOURCE.finditer(text, timeout=_pattern_timeout(), concurrent=False)
    ]
    for i, (pos, m) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else len(text)
        block = text[pos:end]
        dm = _TF_DISPLAY.search(block, timeout=_pattern_timeout(), concurrent=False)
        extra = {"name": m.group(2)}
        if dm:
            extra["display_name"] = dm.group(1)
        res.artifacts.append(Artifact("iac", m.group(1), lines.at(m.start()), extra))
    for m in _TF_MODULE_SOURCE.finditer(text, timeout=_pattern_timeout(), concurrent=False):
        res.artifacts.append(Artifact("module", m.group(1), lines.at(m.start())))
    for m in re.finditer(
        r"image\s*=\s*['\"]([^'\"$]+)['\"]",
        text,
        timeout=_pattern_timeout(),
        concurrent=False,
    ):
        res.artifacts.append(Artifact("image", m.group(1), lines.at(m.start())))
    for m in re.finditer(
        r"['\"]([A-Z][A-Z0-9_]{2,})['\"]\s*[=:]",
        text,
        timeout=_pattern_timeout(),
        concurrent=False,
    ):
        res.artifacts.append(Artifact("env", m.group(1), lines.at(m.start())))
    for m in re.finditer(
        r"^[ \t]*([A-Z][A-Z0-9_]{2,})\s*=\s*",
        text,
        re.M,
        timeout=_pattern_timeout(),
        concurrent=False,
    ):
        res.artifacts.append(Artifact("env", m.group(1), lines.at(m.start())))
    return res


def parse_cloudformation(text: str) -> ManifestResult:
    res = ManifestResult()
    lines = _LineIndex(text)
    for m in _CFN_TYPE.finditer(text, timeout=_pattern_timeout(), concurrent=False):
        res.artifacts.append(Artifact("iac", m.group(1), lines.at(m.start())))
    res.artifacts.extend(parse_compose_or_k8s(text).artifacts)
    return res


def parse_arm_or_bicep(text: str) -> ManifestResult:
    res = ManifestResult()
    lines = _LineIndex(text)
    for m in _ARM_TYPE.finditer(text, timeout=_pattern_timeout(), concurrent=False):
        res.artifacts.append(Artifact("iac", m.group(1), lines.at(m.start())))
    for m in _BICEP_RESOURCE.finditer(text, timeout=_pattern_timeout(), concurrent=False):
        res.artifacts.append(Artifact("iac", m.group(1), lines.at(m.start())))
    return res


_ENV_FILE_LINE = re.compile(r"^[ \t]*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


def parse_env_file(text: str) -> ManifestResult:
    res = ManifestResult()
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _ENV_FILE_LINE.match(line, timeout=_pattern_timeout(), concurrent=False)
        if m:
            val = m.group(2).strip().strip("'\"")
            res.artifacts.append(Artifact("env", m.group(1), i, {"has_value": bool(val), "value": val}))
    return res


def parse_wrangler(text: str) -> ManifestResult:
    res = ManifestResult()
    lines = _LineIndex(text)
    if re.search(r"^[ \t]*\[ai\]", text, re.M, timeout=_pattern_timeout(), concurrent=False) or re.search(
        r'"ai"\s*:\s*\{', text, timeout=_pattern_timeout(), concurrent=False
    ):
        res.artifacts.append(Artifact("iac", "cloudflare_workers_ai_binding", None))
    for m in re.finditer(
        r"^[ \t]*([A-Z][A-Z0-9_]{2,})\s*=",
        text,
        re.M,
        timeout=_pattern_timeout(),
        concurrent=False,
    ):
        res.artifacts.append(Artifact("env", m.group(1), lines.at(m.start())))
    return res


def parse_modelfile(text: str) -> ManifestResult:
    res = ManifestResult()
    lines = _LineIndex(text)
    for m in re.finditer(
        r"^[ \t]*FROM\s+(\S+)",
        text,
        re.M | re.I,
        timeout=_pattern_timeout(),
        concurrent=False,
    ):
        res.artifacts.append(Artifact("model", m.group(1), lines.at(m.start())))
    return res


def parse_manifest(relpath: str, text: str) -> ManifestResult | None:
    """Parse untrusted input, reporting malformed input without losing the scan."""
    try:
        result = _parse_manifest(relpath, text)
    except (ValueError, TypeError, AttributeError, RecursionError, yaml.YAMLError) as exc:
        return ManifestResult(errors=[f"manifest parsing failed ({type(exc).__name__})"])
    if result is not None:
        result.artifacts = _unique_artifacts(result.artifacts)
    return result


def _parse_manifest(relpath: str, text: str) -> ManifestResult | None:
    """Dispatch on file name / extension. Returns None when the file is not a manifest."""
    p = PurePosixPath(relpath.replace("\\", "/"))
    name = p.name
    lower = name.lower()
    parts = [x.lower() for x in p.parts]
    if (
        lower.startswith("requirements")
        and lower.endswith((".txt", ".in"))
        or lower in {"constraints.txt", "dev-requirements.txt"}
    ):
        return parse_requirements(text)
    if lower == "pyproject.toml":
        return parse_pyproject(text)
    if lower == "pipfile":
        return parse_pipfile(text)
    if lower == "setup.py":
        return parse_setup_py(text)
    if lower == "setup.cfg":
        return parse_setup_cfg(text)
    if lower in {"environment.yml", "environment.yaml", "conda.yaml", "conda.yml"}:
        return parse_conda_env(text)
    if lower == "package.json":
        return parse_package_json(text)
    if lower == "go.mod":
        return parse_go_mod(text)
    if lower == "cargo.toml":
        return parse_cargo_toml(text)
    if lower == "pom.xml":
        return parse_pom(text)
    if lower in {
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "settings.gradle.kts",
    } or lower.endswith(".gradle"):
        return parse_gradle(text, kotlin=lower.endswith(".kts"))
    if lower.endswith((".csproj", ".fsproj", ".vbproj", ".props", ".targets")) or lower == "packages.config":
        return parse_nuget(text)
    if lower == "gemfile":
        return parse_gemfile(text)
    if lower == "composer.json":
        return parse_composer(text)
    if (
        lower == "dockerfile"
        or lower.startswith("dockerfile.")
        or lower.endswith(".dockerfile")
        or lower == "containerfile"
    ):
        return parse_dockerfile(text)
    if lower == "modelfile":
        return parse_modelfile(text)
    if lower.endswith(".tf") or lower.endswith(".hcl"):
        return parse_terraform(text)
    if lower.endswith(".bicep"):
        return parse_arm_or_bicep(text)
    if lower.startswith("wrangler."):
        return parse_wrangler(text)
    if lower.startswith(".env") and not lower.endswith((".py", ".js", ".ts")):
        return parse_env_file(text)
    if lower.endswith((".yml", ".yaml")):
        if re.search(
            r"^[ \t]*AWSTemplateFormatVersion|^[ \t]*Transform\s*:\s*['\"]?AWS::Serverless",
            text,
            re.M,
            timeout=_pattern_timeout(),
            concurrent=False,
        ):
            return parse_cloudformation(text)
        return parse_compose_or_k8s(text)
    if lower.endswith(".json") and (
        "azuredeploy" in lower or '"$schema"' in text[:2000] and "deploymenttemplate" in text[:2000].lower()
    ):
        return parse_arm_or_bicep(text)
    if lower.endswith(".json") and re.search(
        r'"AWSTemplateFormatVersion"|"Transform"\s*:\s*"AWS::Serverless',
        text[:4000],
        timeout=_pattern_timeout(),
        concurrent=False,
    ):
        return parse_cloudformation(text)
    if ".github" in parts and "workflows" in parts:
        return parse_compose_or_k8s(text)
    return None


_MANIFEST_FILENAMES_LOWER = frozenset(n.lower() for n in MANIFEST_FILENAMES)


def is_manifest_name(name: str) -> bool:
    lower = name.lower()
    if name in MANIFEST_FILENAMES or lower in _MANIFEST_FILENAMES_LOWER:
        return True
    return (
        (lower.startswith("requirements") and lower.endswith((".txt", ".in")))
        # MSBuild imports carry PackageReference items too (Directory.Build.props,
        # Directory.Build.targets, shared eng/*.props): parse_manifest routes them to NuGet.
        or lower.endswith((".csproj", ".fsproj", ".vbproj", ".props", ".targets", ".tf", ".bicep", ".gradle"))
        or lower.startswith("dockerfile")
        or lower.endswith(".dockerfile")
        or lower == "containerfile"
        or lower.startswith(".env")
        or lower.startswith("wrangler.")
    )
