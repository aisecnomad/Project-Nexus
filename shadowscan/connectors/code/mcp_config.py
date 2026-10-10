"""MCP client/server configuration parsing for the code scanner.

Parses MCP server declarations from client configuration documents
(JSON/JSONC, TOML, YAML and MCP configuration embedded in workflow step
inputs) into redacted server records. Entries keep structure (name,
transport, command, args, url) while credential values are sanitized before
any record leaves this module.
"""

from __future__ import annotations

import re
import tomllib
from typing import Any

import yaml

from shadowscan.connectors.common import looks_like_placeholder
from shadowscan.utils.jsonc import load_json_lenient as _load_json_lenient
from shadowscan.utils.redaction import REDACTED, sanitize
from shadowscan.utils.safe_yaml import strict_bounded_safe_load


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


def _parse_mcp_servers(
    rel: str, text: str, errors: list[str] | None = None, document: Any = None
) -> list[dict[str, Any]]:
    """Return the servers an MCP configuration declares; ``document`` is its parse if already held.

    Only a JSON or TOML document is taken over: YAML configurations are
    loaded here with string keys required, which the shared parse does not.
    """
    errors = errors if errors is not None else []
    data = _load_mcp_document(rel, text, errors, document)
    if data is None:
        return []
    servers = _mcp_server_entries(data, errors)
    if servers is None:
        return []
    # A registry manifest (server.json) is the document itself, not an entry of a server table.
    manifest = len(servers) == 1 and next(iter(servers.values())) is data
    out: list[dict[str, Any]] = []
    for name, cfg in servers.items():
        server = _mcp_server_record(name, cfg, errors, manifest=manifest)
        if server is not None:
            out.append(server)
    # Each output key is generated by this parser. Preserve its schema while
    # sanitizing all values in the context of the entire source document.
    names = [tuple(server) for server in out]
    projected = [[server[key] for key in keys] for server, keys in zip(out, names, strict=True)]
    cleaned = sanitize((data, projected))[1]
    return [dict(zip(keys, values, strict=True)) for keys, values in zip(names, cleaned, strict=True)]


def _load_mcp_document(rel: str, text: str, errors: list[str], document: Any = None) -> dict[str, Any] | None:
    data: Any  # untrusted repository content; every shape is checked below
    try:
        if document is not None and not rel.endswith((".yaml", ".yml")):
            data = document
        elif rel.endswith(".toml"):
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


# Server fields that set the working directory a command starts in or load its environment from
# a file (`cwd`, `envFile`, `env_file`, `workingDirectory`): either can change what a launcher
# fetches or runs, which the record cannot show.
_LAUNCH_CONTEXT_KEY = re.compile(r"(?i)cwd|work(?:ing)?[_-]?dir(?:ectory)?|env[_-]?files?")


def _mcp_server_record(
    name: Any, cfg: Any, errors: list[str], *, manifest: bool = False
) -> dict[str, Any] | None:
    """Project one configured server to its reported fields; None when it is not a usable entry.

    Only a registry manifest's record has ``packages``: each package it declares (registry
    type, identifier, version and registry base URL), which MCP registry matching compares.
    Only a server that sets a working directory or an environment file has ``launch_context``:
    the names of those fields, whose values are not kept.
    """
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
    launch_context = sorted(str(key) for key in cfg if _LAUNCH_CONTEXT_KEY.fullmatch(str(key)))
    if launch_context:
        safe["launch_context"] = launch_context[:8]
    safe["disabled"] = _mcp_disabled(cfg, errors)
    if manifest:
        safe["packages"] = _manifest_packages(cfg.get("packages"), errors)
    return safe


# A manifest package as a record keeps it; an unreadable one keeps no value, so it matches nothing.
_MANIFEST_PACKAGE_FIELDS = ("registry_type", "identifier", "version", "registry_base_url")
_MANIFEST_SOURCE_FIELDS = ("registryType", "identifier", "version", "registryBaseUrl")
_MAX_MANIFEST_PACKAGES = 16


def _manifest_packages(packages: Any, errors: list[str]) -> list[dict[str, str | None]]:
    """The packages a registry manifest declares; one that cannot be read is kept without values."""
    if packages is None:
        return []
    unreadable = dict.fromkeys(_MANIFEST_PACKAGE_FIELDS)
    if not isinstance(packages, list):
        errors.append("MCP server manifest packages must be an array")
        return [unreadable]
    out: list[dict[str, str | None]] = []
    for package in packages[:_MAX_MANIFEST_PACKAGES]:
        values = [package.get(key) for key in _MANIFEST_SOURCE_FIELDS] if isinstance(package, dict) else []
        if (
            values
            and isinstance(values[0], str)
            and isinstance(values[1], str)
            and all(value is None or isinstance(value, str) for value in values[2:])
        ):
            out.append(dict(zip(_MANIFEST_PACKAGE_FIELDS, values, strict=True)))
        else:
            errors.append("MCP server manifest package needs a string registryType and identifier")
            out.append(dict(unreadable))
    if len(packages) > _MAX_MANIFEST_PACKAGES:
        errors.append(f"MCP server manifest lists more than {_MAX_MANIFEST_PACKAGES} packages")
        out.append(dict(unreadable))
    return out


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
