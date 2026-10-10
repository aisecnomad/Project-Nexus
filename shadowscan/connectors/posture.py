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

:func:`approval_settings` reports the opposite: settings that make a person
approve actions. ``every-action`` means each side-effecting action waits for a
person (Claude Code ``defaultMode`` ``default`` or ``plan`` with no allow
rules, Codex ``approval_policy = "untrusted"``, Goose ``GOOSE_MODE: approve``);
``some-actions`` means only some do (Claude Code ``acceptEdits`` or allow
rules, Codex ``on-request`` or ``on-failure``, Goose ``smart_approve``).
:func:`record_approval` stores them as ``metadata.approval_gate``, which the
autonomy classification reads. A settings file says how the agent is
configured, not how a given run was started: command-line flags and other
settings scopes can still override it.

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


APPROVAL_SCOPES = ("every-action", "some-actions")
# Issues that let some action run without approval, whatever else the settings gate.
_UNGATED_ISSUES = frozenset({"posture-permissions-bypassed", "posture-unrestricted-shell"})
MAX_APPROVAL_SETTINGS = 20


@dataclass(frozen=True, slots=True)
class ApprovalSetting:
    """A setting under which a person approves every (or only some) side-effecting action."""

    client: str
    setting: str
    value: str
    scope: str

    def as_dict(self) -> dict[str, str]:
        return {"client": self.client, "setting": self.setting, "value": self.value, "scope": self.scope}


def record_posture(finding: Finding, posture: list[dict[str, str]]) -> None:
    """Record posture issues (``PostureIssue.as_dict()`` plus ``file``) on ``finding``.

    Each issue becomes a tag and zero-weight evidence; bypassed approval also
    adds the ``autonomous`` capability. ``metadata.posture`` keeps the list.
    """
    finding.metadata["posture"] = posture
    for issue in posture:
        finding.add_tag(issue["id"])
        if issue["id"] == "posture-permissions-bypassed":
            # Autonomy: approval-bypass evidence (tool calls run without a person approving them).
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


def record_approval(finding: Finding, approvals: list[dict[str, str]]) -> None:
    """Record approval settings (``ApprovalSetting.as_dict()`` plus ``file``) as ``metadata.approval_gate``.

    Call after :func:`record_posture`. The gate covers every action only when every recorded
    setting does and no posture issue lets an action run unapproved; otherwise it covers some.
    Nothing is recorded without a setting: absent configuration is not evidence of approval.
    """
    if not approvals:
        return
    every = all(item.get("scope") == "every-action" for item in approvals) and not (
        _UNGATED_ISSUES & set(finding.tags)
    )
    finding.metadata["approval_gate"] = {
        "scope": "every-action" if every else "some-actions",
        "settings": approvals[:MAX_APPROVAL_SETTINGS],
    }


def valid_approval(item: Any) -> bool:
    """Whether ``item`` is an approval setting record, as replayed from an export."""
    return (
        isinstance(item, dict)
        and all(isinstance(item.get(key), str) for key in ("client", "setting", "value"))
        and item.get("scope") in APPROVAL_SCOPES
    )


def approval_settings(rel: str, text: str) -> list[ApprovalSetting] | None:
    """Approval settings in one settings file; None when ``rel`` is not a known settings file."""
    client = posture_client(rel)
    if client is None:
        return None
    try:
        data = _load(client, text)
    except (ValueError, RecursionError, yaml.YAMLError, tomllib.TOMLDecodeError):
        return []
    if not isinstance(data, dict):
        return []
    reader = _APPROVALS.get(client)
    return reader(data) if reader else []


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


def _claude_code_approval(data: dict[str, Any]) -> list[ApprovalSetting]:
    permissions = data.get("permissions")
    if not isinstance(permissions, dict):
        return []
    mode = permissions.get("defaultMode")
    if mode in {"default", "plan"}:
        # An allow rule (or an allow value this reader cannot interpret) pre-approves some tools.
        allow = permissions.get("allow")
        scope = "every-action" if allow is None or allow == [] else "some-actions"
        return [ApprovalSetting("claude-code", "permissions.defaultMode", mode, scope)]
    if mode == "acceptEdits":
        return [ApprovalSetting("claude-code", "permissions.defaultMode", mode, "some-actions")]
    return []


def _codex_approval(data: dict[str, Any]) -> list[ApprovalSetting]:
    settings: list[ApprovalSetting] = []
    scopes: list[tuple[str, dict[str, Any]]] = [("", data)]
    profiles = data.get("profiles")
    if isinstance(profiles, dict):
        scopes += [(f"profiles.{name}.", p) for name, p in profiles.items() if isinstance(p, dict)]
    for prefix, scope in scopes:
        policy = scope.get("approval_policy")
        # "untrusted" asks before any command outside a fixed read-only set. "on-request" lets
        # the model decide when to ask and "on-failure" asks only to escalate a failed command.
        if policy == "untrusted":
            gate = "every-action"
        elif policy in {"on-request", "on-failure"}:
            gate = "some-actions"
        else:
            continue
        # A profile cannot gate a default run that it does not configure.
        if prefix and data.get("approval_policy") != "untrusted":
            gate = "some-actions"
        settings.append(ApprovalSetting("codex", f"{prefix}approval_policy", policy, gate))
    return settings


def _goose_approval(data: dict[str, Any]) -> list[ApprovalSetting]:
    mode = data.get("GOOSE_MODE")
    value = mode.strip().lower() if isinstance(mode, str) else None
    if value == "approve":
        return [ApprovalSetting("goose", "GOOSE_MODE", "approve", "every-action")]
    if value == "smart_approve":
        return [ApprovalSetting("goose", "GOOSE_MODE", "smart_approve", "some-actions")]
    return []


_CHECKS = {"claude-code": _claude_code, "codex": _codex, "goose": _goose, "openclaw": _openclaw}
_APPROVALS = {"claude-code": _claude_code_approval, "codex": _codex_approval, "goose": _goose_approval}
