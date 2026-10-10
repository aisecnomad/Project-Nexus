"""Static risk checks for configured MCP servers.

An MCP client configuration says how each server is started or reached. Some
of those choices widen what the server can do or who controls its code:

* ``mcp-unpinned-package``: ``npx``, ``bunx``, ``pnpm dlx``, ``yarn dlx``,
  ``uvx``, ``uv tool run``, ``pipx run`` or ``docker run`` fetches a package
  or image without an exact version (or by a moving tag such as ``latest``),
  so the next launch runs whatever the registry serves then.
* ``mcp-insecure-transport``: a remote server is reached over plaintext
  ``http://`` on a non-loopback host.
* ``mcp-auto-approve``: the client runs some or all of the server's tools
  without asking (``autoApprove`` / ``alwaysAllow``).
* ``mcp-broad-filesystem``: a filesystem server is rooted at ``/``, a drive
  root or a home directory.
* ``mcp-shell-command``: the server is started through a shell command line
  (``sh -c``, ``cmd /c``, ``powershell -Command``), so the configuration can
  run arbitrary commands.

The checks read only the sanitized server record the configuration parser
produced; they never start a server or contact a registry. A digest-pinned
image or an exact package version is treated as pinned even though a
registry can still be compromised.

:func:`server_package` reads the same launch to name the package a server is
fetched from (registry type, normalized identifier and exact version), which
MCP registry snapshots are matched against; :func:`registry_package`
normalizes a registry's own package listing the same way.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from shadowscan.models import Evidence, Finding

RISK_DESCRIPTIONS: dict[str, str] = {
    "mcp-unpinned-package": "fetches its package or image without an exact version",
    "mcp-insecure-transport": "is reached over plaintext HTTP",
    "mcp-auto-approve": "runs tools without asking for approval",
    "mcp-broad-filesystem": "is given the whole filesystem or a home directory",
    "mcp-shell-command": "is started through a shell command line",
}

_EXACT_SEMVER = re.compile(r"^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$")
_PY_EXACT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^\]]*\])?(?:==|===)\s*[0-9][^,;\s]*$")
_PY_AT_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[^\]]*\])?@v?\d+(?:\.\d+)*$")
_SHELLS = {
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
}
_SHELL_FLAGS = {"-c", "/c", "/k", "-command", "-encodedcommand", "-enc"}
# npx / bunx / dlx options that consume the next argument.
_NODE_VALUE_FLAGS = {"-p", "--package", "--registry", "--cache", "--userconfig", "-c", "--call"}
_UV_VALUE_FLAGS = {"--from", "--with", "-w", "--python", "-p", "--index", "--index-url", "--extra-index-url"}
_PIPX_VALUE_FLAGS = {"--spec", "--python", "--pip-args", "--index-url"}
_DOCKER_VALUE_FLAGS = {
    "-e", "--env", "--env-file", "-v", "--volume", "--mount", "--name", "-p", "--publish", "--network",
    "--net", "-w", "--workdir", "-u", "--user", "--entrypoint", "--platform", "-l", "--label", "--cpus",
    "-m", "--memory", "--add-host", "--cap-add", "--cap-drop", "--device", "--pull", "--restart",
    "--hostname", "-h", "--dns", "--ipc", "--pid", "--runtime", "--security-opt", "--tmpfs", "--ulimit",
}  # fmt: skip
_BROAD_ROOTS = {"/", "~", "~/", "$HOME", "${HOME}", "%USERPROFILE%", "/home", "/Users", "/root"}
_DRIVE_ROOT = re.compile(r"^[A-Za-z]:[\\/]?$")
_HOME_DIR = re.compile(r"^(?:/home/[^/]+|/Users/[^/]+|[A-Za-z]:[\\/]Users[\\/][^\\/]+)[\\/]?$")
_MOVING_TAGS = frozenset({"latest", "main", "master", "edge", "nightly"})
# A spec that names a path, a URL, a Git source or an npm alias is not a registry package.
_NOT_REGISTRY = (".", "/", "~", "file:", "git+", "git:", "github:", "npm:", "http:", "https:")
_NPM_NAME = re.compile(r"(?:@[a-z0-9._~-]+/)?[a-z0-9._~-]+\Z")
_PY_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_PY_SEPARATORS = re.compile(r"[-_.]+")
_DOCKER_HUB_HOSTS = frozenset({"docker.io", "index.docker.io", "registry-1.docker.io"})


@dataclass(frozen=True, slots=True)
class PackageRef:
    """The package an MCP server is fetched from.

    ``identifier`` is normalized per registry type: npm names lowercased, PyPI names
    normalized as PEP 503 does, OCI images as ``host/path`` with Docker Hub spelled
    ``docker.io`` and no tag or digest. ``version`` is the exact version or image tag,
    or None when the launch does not pin one.
    """

    registry_type: str
    identifier: str
    version: str | None


@dataclass(frozen=True, slots=True)
class McpRisk:
    """One risky choice in a configured server; ``detail`` never holds a credential."""

    id: str
    detail: str

    @property
    def description(self) -> str:
        return RISK_DESCRIPTIONS[self.id]


def assess_server(server: dict[str, Any]) -> list[McpRisk]:
    """Return the risks of one parsed server record (``_mcp_server_record`` output)."""
    risks: list[McpRisk] = []
    argv = _argv(server)
    if argv is not None:
        risks += _launcher_risks(argv)
    raw_urls = server.get("urls")
    urls = [u for u in raw_urls if isinstance(u, str)] if isinstance(raw_urls, list) else []
    if not urls and isinstance(server.get("url"), str):
        urls = [server["url"]]
    for url in urls:
        if isinstance(url, str) and _plaintext_remote(url):
            risks.append(McpRisk("mcp-insecure-transport", _host(url)))
            break
    approve = server.get("auto_approve")
    if approve is True or (isinstance(approve, list) and approve):
        detail = "all tools" if approve is True or "*" in approve else f"{len(approve)} tool(s)"
        risks.append(McpRisk("mcp-auto-approve", detail))
    return _unique(risks)


def record_server_risks(finding: Finding, server: dict[str, Any], location: str) -> None:
    """Assess one server record and record its risks on ``finding``.

    Sets ``server["risks"]`` to the risk ids, adds each id as a tag, and adds
    zero-weight evidence, so risk changes but confidence does not. A server
    that declares itself disabled is not assessed.
    """
    risks = [] if server.get("disabled") else assess_server(server)
    server["risks"] = [risk.id for risk in risks]
    for risk in risks:
        finding.add_tag(risk.id)
        finding.add_evidence(
            Evidence(
                signal=f"mcp-risk:{risk.id}",
                description=f"MCP server '{server.get('name')}' {risk.description} ({risk.detail})",
                location=location,
                weight=0.0,
            )
        )


def server_package(server: dict[str, Any]) -> PackageRef | None:
    """The registry package a parsed server record launches, or None when it launches none.

    Only the launchers :func:`assess_server` recognizes count. A shell command line, a
    local path, a URL or Git source, an npm alias and a GitHub shorthand name no package.
    """
    argv = _argv(server)
    if argv is None or (_basename(argv[0]) in _SHELLS and any(a.lower() in _SHELL_FLAGS for a in argv[1:])):
        return None
    registry, spec, _ = _launch(argv)
    if registry is None or not spec:
        return None
    if registry == "npm":
        parsed = _npm_ref(spec)
    elif registry == "pypi":
        parsed = _pypi_ref(spec)
    else:
        parsed = _oci_ref(spec)
    return PackageRef(registry, parsed[0], parsed[1]) if parsed is not None else None


def registry_package(registry_type: str, identifier: str, version: str | None = None) -> PackageRef | None:
    """Normalize a package as an MCP registry lists it, comparably with :func:`server_package`.

    An OCI identifier carries its tag, which is the version unless ``version`` is given.
    Other registry types keep their lowercased identifier. None when the identifier does
    not name a registry package.
    """
    kind = registry_type.strip().lower()
    name = identifier.strip()
    if not kind or not name:
        return None
    if kind == "oci":
        parsed = _oci_ref(name)
        return PackageRef(kind, parsed[0], version or parsed[1]) if parsed is not None else None
    if kind == "npm":
        npm = _npm_ref(name)
        return PackageRef(kind, npm[0], version) if npm is not None else None
    if kind == "pypi":
        pypi = _pypi_ref(name)
        return PackageRef(kind, pypi[0], version) if pypi is not None else None
    return PackageRef(kind, name.lower(), version)


def _argv(server: dict[str, Any]) -> list[str] | None:
    """The command line a server record starts, or None when it starts no command."""
    command = server.get("command")
    if not isinstance(command, str) or not command.strip():
        return None
    raw_args = server.get("args")
    args = [a for a in raw_args if isinstance(a, str)] if isinstance(raw_args, list) else []
    return command.split() + args if " " in command.strip() and not args else [command, *args]


def _npm_ref(spec: str) -> tuple[str, str | None] | None:
    if spec.startswith(_NOT_REGISTRY):
        return None
    name = _package_name(spec).lower()
    if not _NPM_NAME.match(name):
        return None
    body = spec[1:] if spec.startswith("@") else spec
    version = body.rsplit("@", 1)[1] if "@" in body else ""
    return name, version.removeprefix("v") if _EXACT_SEMVER.match(version) else None


def _pypi_ref(spec: str) -> tuple[str, str | None] | None:
    if spec.startswith(_NOT_REGISTRY) or "://" in spec:
        return None
    match = _PY_NAME.match(spec)
    if match is None:
        return None
    name = _PY_SEPARATORS.sub("-", match.group(0)).lower()
    version = None
    if _PY_EXACT.match(spec):
        version = spec.split("==", 1)[1].lstrip("=").strip()
    elif _PY_AT_VERSION.match(spec):
        version = spec.rsplit("@", 1)[1].removeprefix("v")
    return name, version


def _oci_ref(image: str) -> tuple[str, str | None] | None:
    reference = image.strip().partition("@")[0]
    if not reference or reference.startswith(("-", "/", ".")) or "://" in reference:
        return None
    head, _, last = reference.rpartition("/")
    last, _, tag = last.partition(":")
    parts = [*head.split("/"), last] if head else [last]
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        host, path = parts[0].lower(), parts[1:]
    else:
        host, path = "docker.io", parts
    if host in _DOCKER_HUB_HOSTS:
        host = "docker.io"
        if len(path) == 1:
            path = ["library", *path]
    if not all(path):
        return None
    return "/".join([host, *path]).lower(), tag if tag and tag not in _MOVING_TAGS else None


def _launch(argv: list[str]) -> tuple[str | None, str | None, list[str]]:
    """The registry a launcher fetches from, the package or image it names, and the arguments after it.

    The registry is ``npm``, ``pypi`` or ``oci``, or None when ``argv`` does not start a
    package launcher; the arguments are then everything after the executable.
    """
    exe = _basename(argv[0])
    rest = argv[1:]
    if (
        exe in {"npx", "bunx"}
        or (exe in {"pnpm", "yarn"} and rest[:1] == ["dlx"])
        or (exe == "bun" and rest[:1] == ["x"])
    ):
        tail = rest[1:] if exe in {"pnpm", "yarn", "bun"} else rest
        package, positional = _node_package(tail)
        return "npm", package, positional
    if exe == "uvx" or (exe == "uv" and rest[:2] == ["tool", "run"]):
        tail = rest[2:] if exe == "uv" else rest
        package, positional = _python_package(tail, _UV_VALUE_FLAGS, "--from")
        return "pypi", package, positional
    if exe == "pipx" and rest[:1] == ["run"]:
        package, positional = _python_package(rest[1:], _PIPX_VALUE_FLAGS, "--spec")
        return "pypi", package, positional
    if exe in {"docker", "podman"} and rest[:1] == ["run"]:
        image, positional = _docker_image(rest[1:])
        return "oci", image, positional
    return None, None, rest


def _launcher_risks(argv: list[str]) -> list[McpRisk]:
    exe = _basename(argv[0])
    if exe in _SHELLS and any(a.lower() in _SHELL_FLAGS for a in argv[1:]):
        return [McpRisk("mcp-shell-command", exe)]
    registry, package, rest = _launch(argv)
    risks: list[McpRisk] = []
    if registry == "oci":
        if package is not None and _image_unpinned(package):
            risks.append(McpRisk("mcp-unpinned-package", package.split("@", 1)[0]))
        return risks
    if package is None:
        return risks
    if not (_npm_pinned(package) if registry == "npm" else _python_pinned(package)):
        risks.append(McpRisk("mcp-unpinned-package", _package_name(package)))
    if "server-filesystem" in package.lower() and any(_broad_root(a) for a in rest):
        risks.append(McpRisk("mcp-broad-filesystem", _package_name(package)))
    return risks


def _node_package(args: list[str]) -> tuple[str | None, list[str]]:
    package = None
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in {"-p", "--package"} and i + 1 < len(args):
            package = args[i + 1]
            i += 2
            continue
        if arg.startswith("--package="):
            package = arg.split("=", 1)[1]
        elif arg in _NODE_VALUE_FLAGS:
            i += 2
            continue
        elif not arg.startswith("-"):
            return package or arg, args[i + 1 :]
        i += 1
    return package, []


def _python_package(args: list[str], value_flags: set[str], spec_flag: str) -> tuple[str | None, list[str]]:
    spec = None
    i = 0
    while i < len(args):
        arg = args[i]
        if arg == spec_flag and i + 1 < len(args):
            spec = args[i + 1]
            i += 2
            continue
        if arg.startswith(spec_flag + "="):
            spec = arg.split("=", 1)[1]
        elif arg in value_flags:
            i += 2
            continue
        elif not arg.startswith("-"):
            return spec or arg, args[i + 1 :]
        i += 1
    return spec, []


def _docker_image(args: list[str]) -> tuple[str | None, list[str]]:
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in _DOCKER_VALUE_FLAGS:
            i += 2
            continue
        if not arg.startswith("-"):
            return arg, args[i + 1 :]
        i += 1
    return None, []


def _npm_pinned(spec: str) -> bool:
    if spec.startswith((".", "/", "file:", "git+", "http:", "https:")):
        return True  # a local path or explicit URL is not a registry lookup
    body = spec[1:] if spec.startswith("@") else spec
    if "@" not in body:
        return False
    version = body.rsplit("@", 1)[1]
    return bool(_EXACT_SEMVER.match(version))


def _python_pinned(spec: str) -> bool:
    if spec.startswith((".", "/", "git+", "http:", "https:", "file:")):
        return True
    return bool(_PY_EXACT.match(spec) or _PY_AT_VERSION.match(spec))


def _image_unpinned(image: str) -> bool:
    if "@sha256:" in image:
        return False
    last = image.rsplit("/", 1)[-1]
    if ":" not in last:
        return True
    return last.rsplit(":", 1)[1] in {"latest", "main", "master", "edge", "nightly"}


def _package_name(spec: str) -> str:
    if spec.startswith("@"):
        scope, _, rest = spec.partition("/")
        return f"{scope}/{rest.split('@', 1)[0]}"
    return re.split(r"[@=<>~!\[]", spec, maxsplit=1)[0]


def _broad_root(arg: str) -> bool:
    value = arg.strip().strip("'\"")
    return value in _BROAD_ROOTS or bool(_DRIVE_ROOT.match(value)) or bool(_HOME_DIR.match(value))


def _plaintext_remote(url: str) -> bool:
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return False
    if parts.scheme.lower() not in {"http", "ws"}:
        return False
    host = (parts.hostname or "").lower()
    if not host or host == "localhost" or host.endswith(".localhost"):
        return False
    try:
        return not ipaddress.ip_address(host).is_loopback
    except ValueError:
        return True


def _host(url: str) -> str:
    try:
        return urlsplit(url.strip()).hostname or "remote server"
    except ValueError:
        return "remote server"


def _basename(command: str) -> str:
    return re.split(r"[\\/]", command.strip())[-1].lower()


def _unique(risks: list[McpRisk]) -> list[McpRisk]:
    seen: set[str] = set()
    out: list[McpRisk] = []
    for risk in risks:
        if risk.id not in seen:
            seen.add(risk.id)
            out.append(risk)
    return out
