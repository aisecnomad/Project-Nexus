"""Security posture of AI coding and personal agents, read from their settings files.

An agent's own configuration says how much it may do without a person in the
loop. These checks read the documented settings of each client and report the
choices that remove a safeguard:

* ``posture-permissions-bypassed``: tool calls run without approval
  (Claude Code ``permissions.defaultMode: bypassPermissions``, Codex
  ``approval_policy = "never"``, Goose ``GOOSE_MODE: auto``).
* ``posture-unrestricted-shell``: any shell command is allowed (a bare
  ``Bash`` or ``Bash(*)`` Claude Code allow rule, OpenClaw
  ``capabilities.shell_access``).
* ``posture-unsandboxed``: the agent runs outside its sandbox (Codex
  ``sandbox_mode = "danger-full-access"``).
* ``posture-exposed-gateway``: a local agent gateway listens beyond loopback
  (OpenClaw ``gateway.bind: lan``, or ``custom`` with ``0.0.0.0``).
* ``posture-unauthenticated-gateway``: that exposed gateway has no auth token.

Only enumerated setting names and their documented values are reported, never
a token, URL or other free-form value. A file that does not parse yields no
issues; the caller reports the parse failure as it does for any other file.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

import yaml

from shadowscan.models import Evidence, Finding
from shadowscan.utils.jsonc import load_json_lenient
from shadowscan.utils.safe_yaml import strict_bounded_safe_load

POSTURE_DESCRIPTIONS: dict[str, str] = {
    "posture-permissions-bypassed": "runs tool calls without asking for approval",
    "posture-unrestricted-shell": "may run any shell command",
    "posture-unsandboxed": "runs outside its sandbox",
    "posture-exposed-gateway": "exposes its local gateway beyond loopback",
    "posture-unauthenticated-gateway": "exposes its gateway without an auth token",
}

# Signature that owns each client's configuration files.
CLIENT_SIGNATURES: dict[str, str] = {
    "claude-code": "coding-agent.claude-code",
    "codex": "coding-agent.openai-codex",
    "goose": "coding-agent.goose",
    "openclaw": "coding-agent.openclaw",
}

_UNRESTRICTED_BASH = re.compile(r"^Bash(?:\((?:\*|\*:\*|:\*)\))?$")


@dataclass(frozen=True, slots=True)
class PostureIssue:
    id: str
    client: str
    setting: str
    value: str

    @property
    def description(self) -> str:
        return POSTURE_DESCRIPTIONS[self.id]

    def as_dict(self) -> dict[str, str]:
        return {"id": self.id, "client": self.client, "setting": self.setting, "value": self.value}


def record_posture(finding: Finding, posture: list[dict[str, str]]) -> None:
    """Record posture issues (``PostureIssue.as_dict()`` plus ``file``) on ``finding``.

    Each issue becomes a tag and zero-weight evidence; bypassed approval also
    adds the ``autonomous`` capability. ``metadata.posture`` keeps the list.
    """
    finding.metadata["posture"] = posture
    for issue in posture:
        finding.add_tag(issue["id"])
        if issue["id"] == "posture-permissions-bypassed":
            finding.add_capability("autonomous")
        finding.add_evidence(
            Evidence(
                signal=f"posture:{issue['id']}",
                description=(
                    f"{issue['client']} {POSTURE_DESCRIPTIONS[issue['id']]} "
                    f"({issue['setting']} = {issue['value']})"
                ),
                location=issue.get("file"),
                weight=0.0,
            )
        )


def posture_client(rel: str) -> str | None:
    """The client whose settings file ``rel`` is, or None."""
    parts = PurePosixPath(rel.replace("\\", "/")).parts
    name = parts[-1] if parts else ""
    parent = parts[-2] if len(parts) >= 2 else ""
    if parent == ".claude" and name in {"settings.json", "settings.local.json"}:
        return "claude-code"
    if parent == ".codex" and name == "config.toml":
        return "codex"
    if name == "config.yaml" and (
        tuple(parts[-3:-1]) == (".config", "goose") or tuple(parts[-4:-1]) == ("Block", "goose", "config")
    ):
        return "goose"
    if (parent, name) in {(".openclaw", "openclaw.json"), (".clawdbot", "clawdbot.json")}:
        return "openclaw"
    return None


def assess(rel: str, text: str) -> list[PostureIssue] | None:
    """Posture issues in one settings file; None when ``rel`` is not a known settings file."""
    client = posture_client(rel)
    if client is None:
        return None
    try:
        data = _load(client, text)
    except (ValueError, RecursionError, yaml.YAMLError, tomllib.TOMLDecodeError):
        return []
    if not isinstance(data, dict):
        return []
    return _CHECKS[client](data)


def parseable(rel: str, text: str) -> bool:
    """Whether a known settings file parses to a mapping; True for files posture does not read."""
    client = posture_client(rel)
    if client is None:
        return True
    try:
        return isinstance(_load(client, text), dict)
    except (ValueError, RecursionError, yaml.YAMLError, tomllib.TOMLDecodeError):
        return False


def _load(client: str, text: str) -> Any:
    if client == "codex":
        return tomllib.loads(text)
    if client == "goose":
        return strict_bounded_safe_load(text)
    return load_json_lenient(text)


def _claude_code(data: dict[str, Any]) -> list[PostureIssue]:
    issues: list[PostureIssue] = []
    permissions = data.get("permissions")
    if not isinstance(permissions, dict):
        return issues
    if permissions.get("defaultMode") == "bypassPermissions":
        issues.append(
            PostureIssue(
                "posture-permissions-bypassed", "claude-code", "permissions.defaultMode", "bypassPermissions"
            )
        )
    allow = permissions.get("allow")
    if isinstance(allow, list):
        rule = next((r for r in allow if isinstance(r, str) and _UNRESTRICTED_BASH.match(r.strip())), None)
        if rule is not None:
            issues.append(
                PostureIssue("posture-unrestricted-shell", "claude-code", "permissions.allow", rule.strip())
            )
    return issues


def _codex(data: dict[str, Any]) -> list[PostureIssue]:
    issues: list[PostureIssue] = []
    scopes: list[tuple[str, dict[str, Any]]] = [("", data)]
    profiles = data.get("profiles")
    if isinstance(profiles, dict):
        scopes += [(f"profiles.{name}.", p) for name, p in profiles.items() if isinstance(p, dict)]
    for prefix, scope in scopes:
        if scope.get("approval_policy") == "never":
            issues.append(
                PostureIssue("posture-permissions-bypassed", "codex", f"{prefix}approval_policy", "never")
            )
        if scope.get("sandbox_mode") == "danger-full-access":
            issues.append(
                PostureIssue("posture-unsandboxed", "codex", f"{prefix}sandbox_mode", "danger-full-access")
            )
    return issues


def _goose(data: dict[str, Any]) -> list[PostureIssue]:
    mode = data.get("GOOSE_MODE")
    if isinstance(mode, str) and mode.strip().lower() == "auto":
        return [PostureIssue("posture-permissions-bypassed", "goose", "GOOSE_MODE", "auto")]
    return []


def _openclaw(data: dict[str, Any]) -> list[PostureIssue]:
    issues: list[PostureIssue] = []
    gateway = _mapping(data.get("gateway"))
    bind = gateway.get("bind", "loopback")
    custom = gateway.get("customBindHost")
    exposed = bind == "lan" or (bind == "custom" and custom in {"0.0.0.0", "::"})
    if exposed:
        value = "lan" if bind == "lan" else f"custom {custom}"
        issues.append(PostureIssue("posture-exposed-gateway", "openclaw", "gateway.bind", value))
        token = _mapping(gateway.get("auth")).get("token")
        if not (isinstance(token, str) and token.strip()):
            issues.append(
                PostureIssue("posture-unauthenticated-gateway", "openclaw", "gateway.auth.token", "unset")
            )
    capabilities = _mapping(data.get("capabilities"))
    if capabilities.get("shell_access") is True or capabilities.get("shellAccess") is True:
        issues.append(
            PostureIssue("posture-unrestricted-shell", "openclaw", "capabilities.shell_access", "true")
        )
    return issues


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


_CHECKS = {"claude-code": _claude_code, "codex": _codex, "goose": _goose, "openclaw": _openclaw}
