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
normalizes a registry's own package listing the same way. A launch names a
package only when nothing in it can change what is fetched or run: a launcher
run from a relative path, another registry, index, configuration file, cache
or container host (as an option or an environment variable), an environment
variable that changes how a launcher or interpreter starts or where it finds
programs and files, a working directory or environment file, a container
mount, working directory or execution-affecting variable, an extra package, a
command line or entrypoint, an option the parser does not know, or a Git, URL,
path or alias source.
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
_NODE_VALUE_FLAGS = {"-p", "--package", "--registry", "--cache", "--userconfig", "-c", "--call", "--loglevel"}
_UV_VALUE_FLAGS = {
    "--from", "--with", "-w", "--with-editable", "--with-requirements", "--python", "-p", "--index",
    "--index-url", "-i", "--default-index", "--extra-index-url", "--find-links", "-f", "--cache-dir",
    "--config-file", "--constraints", "-c", "--overrides",
}  # fmt: skip
_PIPX_VALUE_FLAGS = {"--spec", "--python", "--pip-args", "--index-url", "-i"}
# Options that leave which package a launch fetches, and from where, as written; any other
# option before the package (another registry or index, a configuration file or cache, an
# extra package, a command line) can change what runs, so the launch names no package.
_NODE_PLAIN_FLAGS = frozenset({
    "-y", "--yes", "-q", "--quiet", "-s", "--silent", "--prefer-online", "--ignore-existing", "--bun",
    "--loglevel",
})  # fmt: skip
_UV_PLAIN_FLAGS = frozenset(
    {"-q", "--quiet", "-v", "--verbose", "--isolated", "-n", "--no-cache", "--no-progress"}
)
_PIPX_PLAIN_FLAGS = frozenset({"-q", "--quiet", "-v", "--verbose", "--no-cache"})
# An interpreter request such as 3.12 or cpython@3.12; a path would run that file.
_PYTHON_FLAGS = frozenset({"--python", "-p"})
_PYTHON_REQUEST = re.compile(r"[A-Za-z0-9.+@=<>~_-]+\Z")
_DOCKER_VALUE_FLAGS = {
    "-e", "--env", "--env-file", "-v", "--volume", "--mount", "--name", "-p", "--publish", "--network",
    "--net", "-w", "--workdir", "-u", "--user", "--entrypoint", "--platform", "-l", "--label", "--cpus",
    "-m", "--memory", "--add-host", "--cap-add", "--cap-drop", "--device", "--pull", "--restart",
    "--hostname", "-h", "--dns", "--ipc", "--pid", "--runtime", "--security-opt", "--tmpfs", "--ulimit",
    "--gpus", "-a", "--attach", "--log-driver", "--log-opt", "--shm-size", "--group-add", "--stop-signal",
    "--stop-timeout", "--health-cmd", "--health-interval", "--health-retries", "--health-start-period",
    "--health-timeout", "--cgroupns", "--cgroup-parent", "--isolation", "--expose", "--label-file",
    "--mac-address", "--ip", "--ip6", "--userns", "--uts", "--annotation", "--blkio-weight", "--cidfile",
    "--cpu-period", "--cpu-quota", "-c", "--cpu-shares", "--cpuset-cpus", "--cpuset-mems",
    "--device-cgroup-rule", "--dns-option", "--dns-search", "--domainname", "--link", "--memory-reservation",
    "--memory-swap", "--memory-swappiness", "--network-alias", "--net-alias", "--oom-score-adj",
    "--pids-limit", "--storage-opt", "--sysctl", "--volume-driver", "--volumes-from", "--detach-keys",
    "--secret", "--pod", "--arch", "--os", "--variant", "--tz", "--umask", "--unsetenv", "--authfile",
    "--creds", "--uidmap", "--gidmap", "--requires",
}  # fmt: skip
# docker / podman run options that take no value.
_DOCKER_FLAGS = frozenset({
    "-i", "--interactive", "-t", "--tty", "-d", "--detach", "--rm", "--init", "--privileged", "-P",
    "--publish-all", "--read-only", "--no-healthcheck", "--oom-kill-disable", "--disable-content-trust",
    "-q", "--quiet", "--sig-proxy", "--replace", "--env-host", "--http-proxy", "--read-only-tmpfs",
    "--no-hosts", "--rmi", "--tls-verify",
})  # fmt: skip
_DOCKER_FLAG_CLUSTER = re.compile(r"-[itdPq]{2,}\Z")
# docker / podman run options that replace the image's entrypoint or put other files, another
# working directory or another environment into the container, so the image may not run what
# it was published with.
_DOCKER_CONTEXT_FLAGS = frozenset(
    {"-v", "--volume", "--mount", "--volumes-from", "-w", "--workdir", "--env-file", "--entrypoint"}
)
_DOCKER_ENV_FLAGS = frozenset({"-e", "--env"})
# Environment variables that can change what a launch fetches or runs, matched by namespace:
# launcher, package manager, interpreter and container settings (another registry, index,
# configuration, cache, container host or startup option), the program search path, loader
# preloads, the home, configuration and temporary directories launchers read files from, the
# shell a launcher runs commands with, and TLS trust.
_SOURCE_ENV = re.compile(
    r"(?i)(?:npm|node|bun|yarn|pnpm|corepack|uv|pipx?|docker|containers?|podman|registr(?:y|ies))_\w*"
    r"|python\w*|ld_\w+|dyld_\w+|xdg_\w+|path|pathext|home|homedrive|homepath|userprofile"
    r"|(?:local)?appdata|programdata|tmp|temp|tmpdir|comspec|shell|bash_env|env"
    r"|ssl_\w+|(?:requests|curl)_ca_bundle"
)
# Variables in those namespaces that change neither the package nor what it runs.
_HARMLESS_ENV = re.compile(r"(?i)node_env|python(?:unbuffered|ioencoding|dontwritebytecode|utf8)")
# cmd.exe switches that change nothing about the command it runs, and the characters that make
# its command line more than one plain command: operators, quoting, and %VAR% and !VAR!
# expansion, which happens before operators are read, so a variable can hold an operator.
_CMD_SWITCHES = frozenset({"/d", "/s", "/q"})
_CMD_METACHARACTERS = re.compile(r'[&|<>^()"%!]')
# A Windows absolute path (C:\ or C:/); a relative path resolves against the server's working
# directory, which is usually the scanned repository.
_WINDOWS_ABSOLUTE = re.compile(r"[A-Za-z]:[\\/]")
_BROAD_ROOTS = {"/", "~", "~/", "$HOME", "${HOME}", "%USERPROFILE%", "/home", "/Users", "/root"}
_DRIVE_ROOT = re.compile(r"^[A-Za-z]:[\\/]?$")
_HOME_DIR = re.compile(r"^(?:/home/[^/]+|/Users/[^/]+|[A-Za-z]:[\\/]Users[\\/][^\\/]+)[\\/]?$")
_MOVING_TAGS = frozenset({"latest", "main", "master", "edge", "nightly"})
# A spec that names a path, a URL, a Git source or an npm alias is not a registry package.
_NOT_REGISTRY = (".", "/", "~", "file:", "git+", "git:", "github:", "npm:", "http:", "https:")
_NPM_NAME = re.compile(r"(?:@[a-z0-9._~-]+/)?[a-z0-9._~-]+\Z")
# What may follow 'name@' for a registry lookup: a version, range or dist-tag. An alias
# ('npm:other@1.0.0'), a Git, GitHub, URL or file source fetches something else under the name.
_NPM_SELECTOR = re.compile(r"[A-Za-z0-9.^~<>=|*+ _-]*\Z")
# The public registry each package type's launchers fetch from when nothing names another.
_DEFAULT_REGISTRIES = {
    "npm": frozenset({"https://registry.npmjs.org"}),
    "pypi": frozenset({"https://pypi.org", "https://pypi.org/simple"}),
}
_DOCKER_HUB_ORIGINS = frozenset(
    {
        "https://docker.io",
        "https://index.docker.io",
        "https://registry-1.docker.io",
        "https://registry.hub.docker.com",
    }
)
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

    Only the launchers :func:`assess_server` recognizes count, also as ``npx.cmd`` or
    ``uvx.exe`` and inside ``cmd /c``, and only by a bare program name or an absolute path:
    ``./npx`` or ``tools/uvx`` runs a file of the server's working directory, usually the
    scanned repository. A shell command line, a local path, a URL or Git source, an npm alias,
    a GitHub shorthand, a working directory or environment file (``launch_context``), and a
    launch with an option or environment variable that can change what is fetched or run name
    no package.
    """
    argv = _argv(server)
    if argv is None or not _found_program(argv[0]) or server.get("launch_context"):
        return None
    argv = _cmd_wrapped(argv)
    if (
        argv is None
        or not _found_program(argv[0])
        or _shell_command(argv)
        or _env_changes_source(server.get("env_names"))
    ):
        return None
    registry, spec, _, plain = _launch(argv)
    if registry is None or not spec or not plain:
        return None
    if registry == "npm":
        parsed = _npm_ref(spec)
    elif registry == "pypi":
        parsed = _pypi_ref(spec)
    else:
        parsed = _oci_ref(spec)
    return PackageRef(registry, parsed[0], parsed[1]) if parsed is not None else None


def registry_package(
    registry_type: str, identifier: str, version: str | None = None, registry_base_url: str | None = None
) -> PackageRef | None:
    """Normalize a package as an MCP registry lists it, comparably with :func:`server_package`.

    An OCI identifier carries its tag, which is the version unless ``version`` is given.
    Other registry types keep their lowercased identifier. None when the identifier does
    not name a registry package, or when ``registry_base_url`` names a registry other than
    the public one a launch fetches from by default (for OCI, the image's own host): a
    launch cannot show that it fetches from there.
    """
    kind = registry_type.strip().lower()
    name = identifier.strip()
    if not kind or not name:
        return None
    if kind == "oci":
        parsed = _oci_ref(name)
        ref = PackageRef(kind, parsed[0], version or parsed[1]) if parsed is not None else None
    elif kind == "npm":
        npm = _npm_ref(name)
        ref = PackageRef(kind, npm[0], version) if npm is not None else None
    elif kind == "pypi":
        pypi = _pypi_ref(name)
        ref = PackageRef(kind, pypi[0], version) if pypi is not None else None
    else:
        ref = PackageRef(kind, name.lower(), version)
    if ref is None or registry_base_url is None:
        return ref
    origin = registry_base_url.strip().rstrip("/").lower()
    if kind == "oci":
        host = ref.identifier.split("/", 1)[0]
        default = _DOCKER_HUB_ORIGINS if host == "docker.io" else frozenset({f"https://{host}"})
    else:
        default = _DEFAULT_REGISTRIES.get(kind, frozenset({origin}))
    return ref if origin in default else None


def _argv(server: dict[str, Any]) -> list[str] | None:
    """The command line a server record starts, or None when it starts no command."""
    command = server.get("command")
    if not isinstance(command, str) or not command.strip():
        return None
    raw_args = server.get("args")
    args = [a for a in raw_args if isinstance(a, str)] if isinstance(raw_args, list) else []
    return command.split() + args if " " in command.strip() and not args else [command, *args]


def _cmd_wrapped(argv: list[str]) -> list[str] | None:
    """The command ``cmd /c`` runs, or ``argv`` itself; None when cmd runs more than one plain command.

    Windows runs a batch file (``npx.cmd``) through cmd.exe as well, which reads the same
    operators and variable references in its arguments.
    """
    if argv[0].strip().lower().endswith((".cmd", ".bat")) and any(
        _CMD_METACHARACTERS.search(arg) for arg in argv[1:]
    ):
        return None
    if _basename(argv[0]) != "cmd":
        return argv
    i = 1
    while i < len(argv) and argv[i].lower() in _CMD_SWITCHES:
        i += 1
    if i >= len(argv) or argv[i].lower() not in {"/c", "/k"}:
        return argv
    inner = argv[i + 1 :]
    if len(inner) == 1 and " " in inner[0].strip():
        inner = inner[0].split()
    if not inner or any(_CMD_METACHARACTERS.search(arg) for arg in inner):
        return None
    return inner


def _shell_command(argv: list[str]) -> bool:
    return _basename(argv[0]) in _SHELLS and any(a.lower() in _SHELL_FLAGS for a in argv[1:])


def _env_changes_source(names: Any) -> bool:
    return isinstance(names, list) and any(
        isinstance(name, str) and _SOURCE_ENV.fullmatch(name) and not _HARMLESS_ENV.fullmatch(name)
        for name in names
    )


def _found_program(command: str) -> bool:
    """Whether ``command`` is a bare program name, found on the PATH, or an absolute path.

    A relative path such as ``./npx`` or ``tools\\uvx.cmd`` resolves against the working
    directory; a UNC path names a file on another host.
    """
    name = command.strip()
    if "/" not in name and "\\" not in name:
        return bool(name)
    if name.startswith(("//", "\\\\")):
        return False
    return name.startswith("/") or bool(_WINDOWS_ABSOLUTE.match(name))


def _npm_split(spec: str) -> tuple[str, str]:
    """A spec's package name and what follows its ``@`` (empty when nothing does)."""
    at = spec.find("@", 1)  # past a scope's leading '@'
    return (spec, "") if at < 0 else (spec[:at], spec[at + 1 :])


def _npm_ref(spec: str) -> tuple[str, str | None] | None:
    if spec.startswith(_NOT_REGISTRY):
        return None
    name, selector = _npm_split(spec)
    name = name.lower()
    if not _NPM_NAME.match(name) or not _NPM_SELECTOR.match(selector):
        return None
    return name, selector.removeprefix("v") if _EXACT_SEMVER.match(selector) else None


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


def _launch(argv: list[str]) -> tuple[str | None, str | None, list[str], bool]:
    """The registry a launcher fetches from, the package or image it names, the arguments after
    it, and whether the launch is plain: no option before the package can change what is fetched
    or run.

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
        package, positional, plain = _node_package(tail)
        return "npm", package, positional, plain
    if exe == "uvx" or (exe == "uv" and rest[:2] == ["tool", "run"]):
        tail = rest[2:] if exe == "uv" else rest
        package, positional, plain = _python_package(tail, _UV_VALUE_FLAGS, "--from", _UV_PLAIN_FLAGS)
        return "pypi", package, positional, plain
    if exe == "pipx" and rest[:1] == ["run"]:
        package, positional, plain = _python_package(rest[1:], _PIPX_VALUE_FLAGS, "--spec", _PIPX_PLAIN_FLAGS)
        return "pypi", package, positional, plain
    if exe in {"docker", "podman"} and rest[:1] == ["run"]:
        image, positional, plain = _docker_image(rest[1:])
        return "oci", image, positional, plain
    return None, None, rest, False


def _launcher_risks(argv: list[str]) -> list[McpRisk]:
    if _shell_command(argv):
        return [McpRisk("mcp-shell-command", re.split(r"[\\/]", argv[0].strip())[-1].lower())]
    registry, package, rest, _ = _launch(argv)
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


def _node_package(args: list[str]) -> tuple[str | None, list[str], bool]:
    """The package an npm launcher fetches, the arguments after its command, and whether it is plain.

    With ``-p``/``--package`` the command is looked up among that package's programs and then
    on the PATH, so the launch is plain only for one package whose own name is the command.
    """
    package = None
    packages = 0
    plain = True
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in {"-p", "--package"} and i + 1 < len(args):
            package = args[i + 1]
            packages += 1
            i += 2
            continue
        if arg.startswith("--package="):
            package = arg.split("=", 1)[1]
            packages += 1
        elif arg in _NODE_VALUE_FLAGS:
            plain = plain and arg in _NODE_PLAIN_FLAGS
            i += 2
            continue
        elif not arg.startswith("-"):
            if package is None:
                return arg, args[i + 1 :], plain
            command = _npm_split(package)[0].rsplit("/", 1)[-1]
            return package, args[i + 1 :], plain and packages == 1 and arg == command
        else:
            plain = plain and arg.partition("=")[0] in _NODE_PLAIN_FLAGS
        i += 1
    return package, [], False


def _python_package(
    args: list[str], value_flags: set[str], spec_flag: str, plain_flags: frozenset[str]
) -> tuple[str | None, list[str], bool]:
    spec = None
    plain = True
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
            value = args[i + 1] if i + 1 < len(args) else ""
            plain = plain and arg in _PYTHON_FLAGS and bool(_PYTHON_REQUEST.match(value))
            i += 2
            continue
        elif not arg.startswith("-"):
            return spec or arg, args[i + 1 :], plain
        else:
            flag, equals, value = arg.partition("=")
            plain = plain and (
                (flag in plain_flags and not equals)
                or (flag in _PYTHON_FLAGS and bool(equals) and bool(_PYTHON_REQUEST.match(value)))
            )
        i += 1
    return spec, [], plain


def _docker_image(args: list[str]) -> tuple[str | None, list[str], bool]:
    """The image ``docker run`` starts, the arguments after it, and whether the launch is plain.

    An option this parser does not know may take a value, which would then be read as the
    image, so it leaves the launch not plain; so do ``--entrypoint``, which replaces what the
    image runs, a mount, a working directory, an environment file, and an environment variable
    that can change what runs (``-e NODE_OPTIONS=...``).
    """
    plain = True
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in _DOCKER_VALUE_FLAGS:
            plain = plain and _docker_plain_value(arg, args[i + 1] if i + 1 < len(args) else "")
            i += 2
            continue
        if not arg.startswith("-"):
            return arg, args[i + 1 :], plain
        flag, equals, value = arg.partition("=")
        if equals and flag.startswith("--"):
            known = flag in _DOCKER_VALUE_FLAGS or flag in _DOCKER_FLAGS
        elif not arg.startswith("--") and len(arg) > 2 and arg[:2] in _DOCKER_VALUE_FLAGS:
            # An attached short option value, -eNAME=x or -e=NAME=x.
            flag, value = arg[:2], arg[2:].removeprefix("=")
            known = True
        else:
            known = arg in _DOCKER_FLAGS or bool(_DOCKER_FLAG_CLUSTER.match(arg))
        plain = plain and known and _docker_plain_value(flag, value)
        i += 1
    return None, [], plain


def _docker_plain_value(flag: str, value: str) -> bool:
    """Whether a ``docker run`` option with this value leaves what the image runs as published."""
    if flag in _DOCKER_CONTEXT_FLAGS:
        return False
    return flag not in _DOCKER_ENV_FLAGS or not _env_changes_source([value.partition("=")[0]])


def _npm_pinned(spec: str) -> bool:
    while True:
        if spec.startswith((".", "/", "file:", "git+", "http:", "https:")):
            return True  # a local path or explicit URL is not a registry lookup
        if spec.startswith("npm:"):
            spec = spec[4:]  # an alias is as pinned as the package it names
            continue
        selector = _npm_split(spec)[1]
        if selector.startswith("npm:"):
            spec = selector[4:]
            continue
        return bool(_EXACT_SEMVER.match(selector))


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
    """Whether ``url`` is plaintext HTTP or WebSocket to a host that is not known to be loopback."""
    text = url.strip()
    scheme, separator, rest = text.partition("://")
    if separator and scheme.lower() in {"http", "ws"} and _hidden_host(rest):
        return True
    try:
        parts = urlsplit(text)
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


def _hidden_host(rest: str) -> bool:
    """Whether the host of a URL (``rest`` follows its ``://``) cannot be told from its authority.

    An HTTP client ends the host at a backslash, which :func:`urlsplit` does not
    (``http://remote.example\\@localhost/`` reaches remote.example), and parsed configuration
    redacts user information, which may have held such a backslash.
    """
    authority = re.split(r"[/?#]", rest, maxsplit=1)[0]
    return "\\" in authority or "@" in authority


def _host(url: str) -> str:
    text = url.strip()
    if _hidden_host(text.partition("://")[2]):
        return "remote server"
    try:
        return urlsplit(text).hostname or "remote server"
    except ValueError:
        return "remote server"


def _basename(command: str) -> str:
    """The program a command names, lowercased and without a Windows ``.exe``/``.cmd``/``.bat`` suffix."""
    name = re.split(r"[\\/]", command.strip())[-1].lower()
    stem, dot, suffix = name.rpartition(".")
    return stem if dot and stem and suffix in {"exe", "cmd", "bat"} else name


def _unique(risks: list[McpRisk]) -> list[McpRisk]:
    seen: set[str] = set()
    out: list[McpRisk] = []
    for risk in risks:
        if risk.id not in seen:
            seen.add(risk.id)
            out.append(risk)
    return out
