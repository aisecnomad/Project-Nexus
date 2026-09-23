"""Dependency manifest, container, IaC and CI file parsers for the code scanner.

Each parser returns lightweight :class:`Dep` / :class:`Artifact` records that
the filesystem connector matches against signatures. Parsers are tolerant:
they never raise on malformed input, they just return what they can.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

import yaml


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

_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*([<>=!~;@ ].*)?$")
_GIT_URL = re.compile(r"(?:git\+)?(?:https?|ssh|git)://[^\s#]+?/([A-Za-z0-9_.-]+?)(?:\.git)?(?:@[^\s#]+)?(?:#.*)?$")


def parse_requirements(text: str) -> ManifestResult:
    res = ManifestResult()
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "--")):
            continue
        if line.startswith(("http://", "https://", "git+", "ssh://", "git://")) or "://" in line:
            egg = re.search(r"#egg=([A-Za-z0-9_.-]+)", line)
            if egg:
                res.deps.append(Dep("pypi", egg.group(1), line, i))
                continue
            m = _GIT_URL.search(line)
            if m:
                res.deps.append(Dep("pypi", m.group(1), line, i))
            continue
        if "@" in line and not line.startswith("-e"):
            # PEP 508 direct reference: name @ url
            name = line.split("@", 1)[0].strip()
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*(\[[^\]]*\])?", name):
                res.deps.append(Dep("pypi", name.split("[", 1)[0], line, i))
                continue
        m = _REQ_LINE.match(line)
        if m:
            res.deps.append(Dep("pypi", m.group(1), (m.group(3) or "").strip() or None, i))
    return res


def _pep508_name(spec: str) -> str | None:
    spec = spec.strip()
    m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", spec)
    return m.group(1) if m else None


def parse_pyproject(text: str) -> ManifestResult:
    res = ManifestResult()
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return parse_requirements(text)
    project = data.get("project", {}) or {}
    for spec in project.get("dependencies", []) or []:
        if isinstance(spec, str) and (n := _pep508_name(spec)):
            res.deps.append(Dep("pypi", n, spec))
    for group, specs in (project.get("optional-dependencies", {}) or {}).items():
        for spec in specs or []:
            if isinstance(spec, str) and (n := _pep508_name(spec)):
                res.deps.append(Dep("pypi", n, spec, dev=group in {"dev", "test", "tests", "lint"}))
    for group, specs in (data.get("dependency-groups", {}) or {}).items():
        for spec in specs or []:
            if isinstance(spec, str) and (n := _pep508_name(spec)):
                res.deps.append(Dep("pypi", n, spec, dev=True))
    poetry = (data.get("tool", {}) or {}).get("poetry", {}) or {}
    for name, spec in (poetry.get("dependencies", {}) or {}).items():
        if name.lower() != "python":
            res.deps.append(Dep("pypi", name, json.dumps(spec) if not isinstance(spec, str) else spec))
    for gname, group in (poetry.get("group", {}) or {}).items():
        for name, spec in (group.get("dependencies", {}) or {}).items():
            res.deps.append(Dep("pypi", name, str(spec), dev=True))
    for name, spec in (poetry.get("dev-dependencies", {}) or {}).items():
        res.deps.append(Dep("pypi", name, str(spec), dev=True))
    uv = (data.get("tool", {}) or {}).get("uv", {}) or {}
    for spec in uv.get("dev-dependencies", []) or []:
        if isinstance(spec, str) and (n := _pep508_name(spec)):
            res.deps.append(Dep("pypi", n, spec, dev=True))
    # image / env style hints sometimes live in pyproject (e.g. tool.langgraph)
    return res


def parse_pipfile(text: str) -> ManifestResult:
    res = ManifestResult()
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return res
    for section, dev in (("packages", False), ("dev-packages", True)):
        for name, spec in (data.get(section, {}) or {}).items():
            res.deps.append(Dep("pypi", name, str(spec), dev=dev))
    return res


_SETUP_REQ = re.compile(r"(?:install_requires|extras_require|tests_require|setup_requires)\s*=\s*(\[[^\]]*\]|\{[^}]*\})", re.S)
_STR = re.compile(r"""["']([^"']+)["']""")


def parse_setup_py(text: str) -> ManifestResult:
    res = ManifestResult()
    for m in _SETUP_REQ.finditer(text):
        for s in _STR.findall(m.group(1)):
            n = _pep508_name(s)
            if n:
                res.deps.append(Dep("pypi", n, s))
    return res


def parse_setup_cfg(text: str) -> ManifestResult:
    res = ManifestResult()
    in_reqs = False
    for line in text.splitlines():
        if re.match(r"^\s*(install_requires|tests_require)\s*=", line):
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
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError:
        return res
    for item in data.get("dependencies", []) or []:
        if isinstance(item, str):
            name = re.split(r"[=<>!~ ]", item, 1)[0]
            if "::" in name:
                name = name.split("::", 1)[1]
            res.deps.append(Dep("conda", name, item))
        elif isinstance(item, dict) and "pip" in item:
            for spec in item["pip"] or []:
                if isinstance(spec, str) and (n := _pep508_name(spec)):
                    res.deps.append(Dep("pypi", n, spec))
    return res


def parse_package_json(text: str) -> ManifestResult:
    res = ManifestResult()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return res
    if not isinstance(data, dict):
        return res
    for section, dev in (
        ("dependencies", False),
        ("devDependencies", True),
        ("peerDependencies", False),
        ("optionalDependencies", False),
    ):
        for name, spec in (data.get(section, {}) or {}).items():
            res.deps.append(Dep("npm", name, str(spec), dev=dev))
    scripts = data.get("scripts", {}) or {}
    for _, cmd in scripts.items():
        if isinstance(cmd, str):
            for pkg in re.findall(r"npx\s+(?:-y\s+)?(@?[A-Za-z0-9_./-]+)", cmd):
                res.deps.append(Dep("npm", pkg.split("@", 1)[0] if not pkg.startswith("@") else "@" + pkg[1:].split("@", 1)[0], cmd))
    return res


_GO_REQUIRE_BLOCK = re.compile(r"require\s*\((.*?)\)", re.S)
_GO_REQUIRE_LINE = re.compile(r"^\s*require\s+(\S+)\s+(\S+)", re.M)
_GO_MOD_LINE = re.compile(r"^\s*(\S+)\s+(v\S+)", re.M)


def parse_go_mod(text: str) -> ManifestResult:
    res = ManifestResult()
    for block in _GO_REQUIRE_BLOCK.findall(text):
        for m in _GO_MOD_LINE.finditer(block):
            res.deps.append(Dep("go", m.group(1), m.group(2)))
    for m in _GO_REQUIRE_LINE.finditer(text):
        res.deps.append(Dep("go", m.group(1), m.group(2)))
    return res


def parse_cargo_toml(text: str) -> ManifestResult:
    res = ManifestResult()
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return res
    sections = [
        (data.get("dependencies", {}) or {}, False),
        (data.get("dev-dependencies", {}) or {}, True),
        (data.get("build-dependencies", {}) or {}, True),
        ((data.get("workspace", {}) or {}).get("dependencies", {}) or {}, False),
    ]
    for target in (data.get("target", {}) or {}).values():
        if isinstance(target, dict):
            sections.append((target.get("dependencies", {}) or {}, False))
    for section, dev in sections:
        for name, spec in section.items():
            real = spec.get("package", name) if isinstance(spec, dict) else name
            res.deps.append(Dep("cargo", real, str(spec), dev=dev))
    return res


_POM_DEP = re.compile(r"<dependency>\s*(.*?)\s*</dependency>", re.S)
_POM_TAG = re.compile(r"<(groupId|artifactId|version|scope)>\s*([^<]+?)\s*</\1>")


def parse_pom(text: str) -> ManifestResult:
    res = ManifestResult()
    for m in _POM_DEP.finditer(text):
        tags = dict(_POM_TAG.findall(m.group(1)))
        g, a = tags.get("groupId"), tags.get("artifactId")
        if g and a:
            res.deps.append(Dep("maven", f"{g}:{a}", tags.get("version"), dev=tags.get("scope") == "test"))
    for m in re.finditer(r"<(?:artifactId)>\s*([^<]+?)\s*</artifactId>", text):
        pass
    return res


_GRADLE_DEP = re.compile(
    r"""\b(implementation|api|compile|compileOnly|runtimeOnly|testImplementation|testCompile|kapt|annotationProcessor|developmentOnly)\s*\(?\s*["']([^"':]+):([^"':]+)(?::([^"']+))?["']"""
)
_GRADLE_PLATFORM = re.compile(r"""(?:platform|enforcedPlatform)\s*\(\s*["']([^"':]+):([^"':]+)(?::([^"']+))?["']""")


def parse_gradle(text: str) -> ManifestResult:
    res = ManifestResult()
    for m in _GRADLE_DEP.finditer(text):
        res.deps.append(Dep("maven", f"{m.group(2)}:{m.group(3)}", m.group(4), dev=m.group(1).startswith("test")))
    for m in _GRADLE_PLATFORM.finditer(text):
        res.deps.append(Dep("maven", f"{m.group(1)}:{m.group(2)}", m.group(3)))
    return res


_NUGET_REF = re.compile(r"""<(?:PackageReference|PackageVersion|package)\s+[^>]*?(?:Include|id)\s*=\s*["']([^"']+)["'][^>]*?(?:Version|version)\s*=\s*["']([^"']*)["']""", re.I)
_NUGET_REF_NOVER = re.compile(r"""<(?:PackageReference|PackageVersion)\s+[^>]*?Include\s*=\s*["']([^"']+)["']""", re.I)


def parse_nuget(text: str) -> ManifestResult:
    res = ManifestResult()
    seen: set[str] = set()
    for m in _NUGET_REF.finditer(text):
        seen.add(m.group(1))
        res.deps.append(Dep("nuget", m.group(1), m.group(2)))
    for m in _NUGET_REF_NOVER.finditer(text):
        if m.group(1) not in seen:
            res.deps.append(Dep("nuget", m.group(1)))
    return res


_GEM = re.compile(r"""^\s*gem\s+["']([^"']+)["'](?:\s*,\s*["']([^"']+)["'])?""", re.M)


def parse_gemfile(text: str) -> ManifestResult:
    res = ManifestResult()
    for m in _GEM.finditer(text):
        res.deps.append(Dep("rubygems", m.group(1), m.group(2)))
    return res


def parse_composer(text: str) -> ManifestResult:
    res = ManifestResult()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return res
    for section, dev in (("require", False), ("require-dev", True)):
        for name, spec in (data.get(section, {}) or {}).items():
            if "/" in name:
                res.deps.append(Dep("composer", name, str(spec), dev=dev))
    return res


_DOCKER_FROM = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", re.I | re.M)
_DOCKER_ENV = re.compile(r"^\s*(?:ENV|ARG)\s+([A-Z][A-Z0-9_]+)", re.I | re.M)
_DOCKER_ENV_MULTI = re.compile(r"^\s*ENV\s+(.+)$", re.I | re.M)
_DOCKER_PIP = re.compile(r"pip3?\s+install\s+([^&|;\n\\]+)", re.I)
_DOCKER_NPM = re.compile(r"(?:npm\s+(?:install|i|add)|yarn\s+add|pnpm\s+(?:add|install))\s+([^&|;\n\\]+)", re.I)
_DOCKER_UV = re.compile(r"uv\s+(?:pip\s+install|add)\s+([^&|;\n\\]+)", re.I)


def parse_dockerfile(text: str) -> ManifestResult:
    res = ManifestResult()
    for m in _DOCKER_FROM.finditer(text):
        img = m.group(1)
        if img.lower() != "scratch" and "$" not in img:
            res.artifacts.append(Artifact("image", img, text.count("\n", 0, m.start()) + 1))
    for m in _DOCKER_ENV_MULTI.finditer(text):
        for name in re.findall(r"([A-Z][A-Z0-9_]+)\s*=", m.group(1)):
            res.artifacts.append(Artifact("env", name, text.count("\n", 0, m.start()) + 1))
    for m in _DOCKER_ENV.finditer(text):
        res.artifacts.append(Artifact("env", m.group(1), text.count("\n", 0, m.start()) + 1))
    for rx in (_DOCKER_PIP, _DOCKER_UV):
        for m in rx.finditer(text):
            for tok in m.group(1).split():
                if tok.startswith("-") or tok in {"install", "."} or "=" in tok and not re.match(r"^[A-Za-z0-9_.-]+==", tok):
                    continue
                n = _pep508_name(tok)
                if n and n.lower() not in {"pip", "setuptools", "wheel", "poetry", "uv", "pipenv", "r"}:
                    res.deps.append(Dep("pypi", n, tok, text.count("\n", 0, m.start()) + 1))
    for m in _DOCKER_NPM.finditer(text):
        for tok in m.group(1).split():
            if tok.startswith("-") or tok in {"install", "add"}:
                continue
            name = tok if tok.startswith("@") else tok.split("@", 1)[0]
            if name.startswith("@"):
                name = "@" + name[1:].split("@", 1)[0]
            res.deps.append(Dep("npm", name, tok, text.count("\n", 0, m.start()) + 1))
    return res


_YAML_IMAGE = re.compile(r"^\s*(?:-\s*)?image\s*:\s*['\"]?([^'\"\s#]+)", re.M)
_YAML_REPO = re.compile(r"^\s*repository\s*:\s*['\"]?([^'\"\s#]+)", re.M)
_YAML_ENV_KEY = re.compile(r"^\s*-?\s*(?:name\s*:\s*)?['\"]?([A-Z][A-Z0-9_]{2,})['\"]?\s*[:=]", re.M)
_YAML_USES = re.compile(r"^\s*-?\s*uses\s*:\s*['\"]?([^'\"\s#]+)", re.M)
_SECRETS_REF = re.compile(r"\$\{\{\s*secrets\.([A-Za-z0-9_]+)\s*\}\}")
_GITLAB_IMAGE = re.compile(r"^\s*image\s*:\s*(?:name\s*:\s*)?['\"]?([^'\"\s#]+)", re.M)


def parse_compose_or_k8s(text: str) -> ManifestResult:
    """docker-compose, Kubernetes manifests, Helm values, CI configs: images + env keys."""
    res = ManifestResult()
    for m in _YAML_IMAGE.finditer(text):
        res.artifacts.append(Artifact("image", m.group(1), text.count("\n", 0, m.start()) + 1))
    for m in _YAML_REPO.finditer(text):
        val = m.group(1)
        if "/" in val and not val.startswith(("http", "git@")):
            res.artifacts.append(Artifact("image", val, text.count("\n", 0, m.start()) + 1))
    for m in _YAML_ENV_KEY.finditer(text):
        res.artifacts.append(Artifact("env", m.group(1), text.count("\n", 0, m.start()) + 1))
    for m in _YAML_USES.finditer(text):
        res.artifacts.append(Artifact("action", m.group(1), text.count("\n", 0, m.start()) + 1))
    for m in _SECRETS_REF.finditer(text):
        res.artifacts.append(Artifact("secret_ref", m.group(1), text.count("\n", 0, m.start()) + 1))
    return res


_TF_RESOURCE = re.compile(r"""^\s*(?:resource|data)\s+["']([A-Za-z0-9_]+)["']\s+["']([^"']+)["']""", re.M)
_TF_MODULE_SOURCE = re.compile(r"""^\s*source\s*=\s*["']([^"']+)["']""", re.M)
_CFN_TYPE = re.compile(r"""^\s*(?:"Type"|Type)\s*:\s*['"]?((?:AWS|Alexa|Custom)::[A-Za-z0-9:]+)""", re.M)
_ARM_TYPE = re.compile(r"""["']type["']\s*:\s*["']((?:Microsoft|Oracle|Google)\.[A-Za-z0-9./]+)["']""", re.I)
_BICEP_RESOURCE = re.compile(r"""^\s*resource\s+\w+\s+['"]([A-Za-z0-9./]+)@[^'"]+['"]""", re.M)
_PULUMI_TYPE = re.compile(r"""\b(?:aws|gcp|azure|azure_native|azurerm|oci)[.:][a-z_]+[.:][A-Z][A-Za-z]+""")
_CDK_IMPORT = re.compile(r"""(?:from\s+aws_cdk\s+import\s+([^\n]+)|aws-cdk-lib/([a-z_-]+)|@aws-cdk/([a-z_-]+)|aws_cdk\.([a-z_]+))""")


_TF_DISPLAY = re.compile(r"""^\s*(?:agent_name|display_name|function_name|name|bot_name|app_name|workflow_name)\s*=\s*["']([^"'$]+)["']""", re.M)


def parse_terraform(text: str) -> ManifestResult:
    res = ManifestResult()
    starts = [(m.start(), m) for m in _TF_RESOURCE.finditer(text)]
    for i, (pos, m) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else len(text)
        block = text[pos:end]
        dm = _TF_DISPLAY.search(block)
        extra = {"name": m.group(2)}
        if dm:
            extra["display_name"] = dm.group(1)
        res.artifacts.append(Artifact("iac", m.group(1), text.count("\n", 0, m.start()) + 1, extra))
    for m in _TF_MODULE_SOURCE.finditer(text):
        res.artifacts.append(Artifact("module", m.group(1), text.count("\n", 0, m.start()) + 1))
    for m in re.finditer(r"image\s*=\s*['\"]([^'\"$]+)['\"]", text):
        res.artifacts.append(Artifact("image", m.group(1), text.count("\n", 0, m.start()) + 1))
    for m in re.finditer(r"['\"]([A-Z][A-Z0-9_]{2,})['\"]\s*[=:]", text):
        res.artifacts.append(Artifact("env", m.group(1), text.count("\n", 0, m.start()) + 1))
    for m in re.finditer(r"^\s*([A-Z][A-Z0-9_]{2,})\s*=\s*", text, re.M):
        res.artifacts.append(Artifact("env", m.group(1), text.count("\n", 0, m.start()) + 1))
    return res


def parse_cloudformation(text: str) -> ManifestResult:
    res = ManifestResult()
    for m in _CFN_TYPE.finditer(text):
        res.artifacts.append(Artifact("iac", m.group(1), text.count("\n", 0, m.start()) + 1))
    res.artifacts.extend(parse_compose_or_k8s(text).artifacts)
    return res


def parse_arm_or_bicep(text: str) -> ManifestResult:
    res = ManifestResult()
    for m in _ARM_TYPE.finditer(text):
        res.artifacts.append(Artifact("iac", m.group(1), text.count("\n", 0, m.start()) + 1))
    for m in _BICEP_RESOURCE.finditer(text):
        res.artifacts.append(Artifact("iac", m.group(1), text.count("\n", 0, m.start()) + 1))
    return res


_ENV_FILE_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


def parse_env_file(text: str) -> ManifestResult:
    res = ManifestResult()
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _ENV_FILE_LINE.match(line)
        if m:
            val = m.group(2).strip().strip("'\"")
            res.artifacts.append(Artifact("env", m.group(1), i, {"has_value": bool(val), "value": val}))
    return res


def parse_wrangler(text: str) -> ManifestResult:
    res = ManifestResult()
    if re.search(r"^\s*\[ai\]", text, re.M) or re.search(r'"ai"\s*:\s*\{', text):
        res.artifacts.append(Artifact("iac", "cloudflare_workers_ai_binding", None))
    for m in re.finditer(r"^\s*([A-Z][A-Z0-9_]{2,})\s*=", text, re.M):
        res.artifacts.append(Artifact("env", m.group(1), text.count("\n", 0, m.start()) + 1))
    return res


def parse_modelfile(text: str) -> ManifestResult:
    res = ManifestResult()
    for m in re.finditer(r"^\s*FROM\s+(\S+)", text, re.M | re.I):
        res.artifacts.append(Artifact("model", m.group(1), text.count("\n", 0, m.start()) + 1))
    return res


def parse_manifest(relpath: str, text: str) -> ManifestResult | None:
    """Dispatch on file name / extension. Returns None when the file is not a manifest."""
    p = PurePosixPath(relpath.replace("\\", "/"))
    name = p.name
    lower = name.lower()
    parts = [x.lower() for x in p.parts]
    if lower.startswith("requirements") and lower.endswith((".txt", ".in")) or lower in {"constraints.txt", "dev-requirements.txt"}:
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
    if lower in {"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"} or lower.endswith(".gradle"):
        return parse_gradle(text)
    if lower.endswith((".csproj", ".fsproj", ".vbproj", ".props", ".targets")) or lower == "packages.config":
        return parse_nuget(text)
    if lower == "gemfile":
        return parse_gemfile(text)
    if lower == "composer.json":
        return parse_composer(text)
    if lower == "dockerfile" or lower.startswith("dockerfile.") or lower.endswith(".dockerfile") or lower == "containerfile":
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
        if re.search(r"^\s*AWSTemplateFormatVersion|^\s*Transform\s*:\s*['\"]?AWS::Serverless", text, re.M):
            return parse_cloudformation(text)
        return parse_compose_or_k8s(text)
    if lower.endswith(".json") and ("azuredeploy" in lower or '"$schema"' in text[:2000] and "deploymenttemplate" in text[:2000].lower()):
        return parse_arm_or_bicep(text)
    if lower.endswith(".json") and re.search(r'"AWSTemplateFormatVersion"|"Transform"\s*:\s*"AWS::Serverless', text[:4000]):
        return parse_cloudformation(text)
    if ".github" in parts and "workflows" in parts:
        return parse_compose_or_k8s(text)
    return None


def is_manifest_name(name: str) -> bool:
    lower = name.lower()
    if name in MANIFEST_FILENAMES or lower in {n.lower() for n in MANIFEST_FILENAMES}:
        return True
    return (
        (lower.startswith("requirements") and lower.endswith((".txt", ".in")))
        or lower.endswith((".csproj", ".fsproj", ".vbproj", ".tf", ".bicep", ".gradle"))
        or lower.startswith("dockerfile")
        or lower.endswith(".dockerfile")
        or lower.startswith(".env")
        or lower.startswith("wrangler.")
    )
