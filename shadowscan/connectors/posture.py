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
person (Claude Code ``defaultMode`` ``default`` or ``plan``, Codex
``approval_policy = "untrusted"``, Goose ``GOOSE_MODE: approve``);
``some-actions`` means only some do (Claude Code ``acceptEdits`` or allow
rules, Codex ``on-request`` or ``on-failure``, Goose ``smart_approve``). Claude
Code settings that let actions run without a prompt but configure no approval
themselves (a sandbox that auto-allows Bash, ``PreToolUse`` and
``PermissionRequest`` hooks, which can allow a call) are reported as
``some-actions`` too; they make a gate partial but never record one alone.
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

_EVERY = frozenset({"every-action"})
_SOME = frozenset({"some-actions"})
_UNREADABLE = {"unreadable": _SOME}
# Every (client, setting) an approval reader reports, each value it reports for it and the scopes
# that value can carry. Replayed exports are held to it (:func:`valid_approval`).
UNREADABLE_SETTINGS = "settings-file"
_APPROVAL_VALUES: dict[tuple[str, str], dict[str, frozenset[str]]] = {
    ("claude-code", "permissions.defaultMode"): {"default": _EVERY, "plan": _EVERY, "acceptEdits": _SOME},
    ("claude-code", "permissions.allow"): {"rules": _SOME, **_UNREADABLE},
    ("claude-code", "permissions"): _UNREADABLE,
    ("claude-code", "sandbox.autoAllowBashIfSandboxed"): {"true": _SOME},
    ("claude-code", "sandbox"): _UNREADABLE,
    ("claude-code", "hooks.PreToolUse"): {"configured": _SOME},
    ("claude-code", "hooks.PermissionRequest"): {"configured": _SOME},
    ("claude-code", "hooks"): _UNREADABLE,
    ("codex", "approval_policy"): {"untrusted": _EVERY, "on-request": _SOME, "on-failure": _SOME},
    # A profile is every-action only when the top level is untrusted too.
    ("codex", "profiles.*.approval_policy"): {
        "untrusted": _EVERY | _SOME,
        "on-request": _SOME,
        "on-failure": _SOME,
    },
    ("goose", "GOOSE_MODE"): {"approve": _EVERY, "smart_approve": _SOME},
    # A settings file of the client that could not be read (invalid syntax, a symbolic link,
    # over the size limit): whatever it sets is unknown, so it may loosen the gate.
    **{(client, UNREADABLE_SETTINGS): _UNREADABLE for client in ("claude-code", "codex", "goose")},
}
# Settings that let some actions run without a prompt but do not themselves configure approval:
# they make a gate partial and never record one on their own.
_LOOSENING = frozenset(
    {
        ("claude-code", setting)
        for setting in (
            "permissions",
            "sandbox.autoAllowBashIfSandboxed",
            "sandbox",
            "hooks.PreToolUse",
            "hooks.PermissionRequest",
            "hooks",
        )
    }
    | {(client, UNREADABLE_SETTINGS) for client in ("claude-code", "codex", "goose")}
)
# Claude Code hook events whose hooks can allow a tool call without a prompt.
_ALLOWING_HOOKS = ("PreToolUse", "PermissionRequest")
_CODEX_PROFILE_POLICY = re.compile(r"profiles\..*\.approval_policy", re.DOTALL)


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


def record_approval(finding: Finding, approvals: list[dict[str, str]], *, complete: bool = True) -> None:
    """Record approval settings (``ApprovalSetting.as_dict()`` plus ``file``) as ``metadata.approval_gate``.

    Call after :func:`record_posture`. The gate covers every action only when every recorded
    setting does, no posture issue lets an action run unapproved and ``complete`` is true;
    otherwise it covers some. Pass ``complete=False`` when approval or posture entries were
    dropped (for example malformed entries in a replayed export): a setting that was lost could
    have loosened the gate. Nothing is recorded without a setting that configures approval:
    absent configuration is not evidence of approval, and a setting that only lets actions run
    unprompted is not either.
    """
    if not any((item.get("client"), item.get("setting")) not in _LOOSENING for item in approvals):
        return
    every = (
        complete
        and all(item.get("scope") == "every-action" for item in approvals)
        and not (_UNGATED_ISSUES & set(finding.tags))
    )
    finding.metadata["approval_gate"] = {
        "scope": "every-action" if every else "some-actions",
        "settings": approvals[:MAX_APPROVAL_SETTINGS],
    }


def approval_scopes(client: str, setting: str, value: str) -> frozenset[str]:
    """The scopes an approval reader can report for ``setting = value``; empty when it reports none."""
    key = (
        "profiles.*.approval_policy"
        if client == "codex" and _CODEX_PROFILE_POLICY.fullmatch(setting)
        else setting
    )
    return _APPROVAL_VALUES.get((client, key), {}).get(value, frozenset())


def valid_approval(item: Any, *, client: Any, file: Any) -> bool:
    """Whether ``item`` is an approval setting a reader reports, as replayed from an export.

    It must hold exactly ``client``, ``setting``, ``value``, ``scope`` and ``file``, as
    :func:`approval_settings` and its callers write them: a combination of setting, value and
    scope a reader can produce, the given ``client`` and ``file`` of the record it came with, and
    a ``file`` that is a settings file of that client. An :func:`unreadable_settings` entry names
    the unread file, which may be another settings file of the same client.
    """
    if not isinstance(item, dict) or set(item) != {"client", "setting", "value", "scope", "file"}:
        return False
    if not all(isinstance(value, str) for value in item.values()):
        return False
    return (
        item["client"] == client
        and (item["file"] == file or item["setting"] == UNREADABLE_SETTINGS)
        and posture_client(item["file"]) == client
        and item["scope"] in approval_scopes(client, item["setting"], item["value"])
    )


def unreadable_settings(client: str) -> ApprovalSetting:
    """The approval entry for a settings file of ``client`` that could not be read.

    It never records a gate on its own (see :func:`record_approval`), and next to a readable
    setting it keeps the gate at ``some-actions``: the unread file could loosen it.
    """
    return ApprovalSetting(client, UNREADABLE_SETTINGS, "unreadable", "some-actions")


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
    # Values come from an untrusted file: a list or object must not reach a set lookup.
    exposed = bind == "lan" or (bind == "custom" and isinstance(custom, str) and custom in {"0.0.0.0", "::"})
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
    settings: list[ApprovalSetting] = []
    permissions = data.get("permissions")
    if isinstance(permissions, dict):
        mode = permissions.get("defaultMode")
        if not isinstance(mode, str):
            mode = None  # an unreadable mode configures no approval
        if mode in {"default", "plan"}:
            settings.append(ApprovalSetting("claude-code", "permissions.defaultMode", mode, "every-action"))
        elif mode == "acceptEdits":
            settings.append(ApprovalSetting("claude-code", "permissions.defaultMode", mode, "some-actions"))
        # An allow rule (or an allow value this reader cannot interpret) pre-approves some tools,
        # whichever settings file sets the mode.
        allow = permissions.get("allow")
        if allow is not None and allow != []:
            value = "rules" if isinstance(allow, list) else "unreadable"
            settings.append(ApprovalSetting("claude-code", "permissions.allow", value, "some-actions"))
    elif permissions is not None:
        settings.append(ApprovalSetting("claude-code", "permissions", "unreadable", "some-actions"))
    # A sandbox runs Bash commands without a prompt unless autoAllowBashIfSandboxed is false.
    sandbox = data.get("sandbox")
    if isinstance(sandbox, dict):
        enabled = sandbox.get("enabled")
        if (
            enabled is not None
            and enabled is not False
            and sandbox.get("autoAllowBashIfSandboxed") is not False
        ):
            settings.append(
                ApprovalSetting("claude-code", "sandbox.autoAllowBashIfSandboxed", "true", "some-actions")
            )
    elif sandbox is not None:
        settings.append(ApprovalSetting("claude-code", "sandbox", "unreadable", "some-actions"))
    # A PreToolUse or PermissionRequest hook can allow a call without asking anyone.
    hooks = data.get("hooks")
    if isinstance(hooks, dict):
        for event in _ALLOWING_HOOKS:
            if hooks.get(event) not in (None, [], {}):
                settings.append(
                    ApprovalSetting("claude-code", f"hooks.{event}", "configured", "some-actions")
                )
    elif hooks is not None:
        settings.append(ApprovalSetting("claude-code", "hooks", "unreadable", "some-actions"))
    return settings


def _codex_approval(data: dict[str, Any]) -> list[ApprovalSetting]:
    settings: list[ApprovalSetting] = []
    scopes: list[tuple[str, dict[str, Any]]] = [("", data)]
    profiles = data.get("profiles")
    if isinstance(profiles, dict):
        scopes += [(f"profiles.{name}.", p) for name, p in profiles.items() if isinstance(p, dict)]
    for prefix, scope in scopes:
        policy = scope.get("approval_policy")
        if not isinstance(policy, str):
            continue  # an unreadable policy configures no approval
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
