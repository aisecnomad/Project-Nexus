"""Autonomy evidence recorded by connectors: approval gates, triggers and their classification."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shadowscan.autonomy import classify
from shadowscan.connectors.cloud.aws import _bedrock_approval_gate
from shadowscan.connectors.posture import (
    ApprovalSetting,
    approval_scopes,
    approval_settings,
    record_approval,
    record_posture,
    valid_approval,
)
from shadowscan.models import Finding, Kind, Surface


def write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def scopes(rel: str, text: str) -> list[tuple[str, str, str]]:
    settings = approval_settings(rel, text)
    assert settings is not None
    return [(s.setting, s.value, s.scope) for s in settings]


def interval(f: Finding) -> tuple[int, int, str, str]:
    autonomy = classify(f)
    assert autonomy is not None
    return autonomy["floor"], autonomy["ceiling"], autonomy["oversight"], autonomy["initiation"]


# ----------------------------------------------------------- posture readers

CLAUDE = ".claude/settings.json"


@pytest.mark.parametrize(
    ("permissions", "expected"),
    [
        ({"defaultMode": "default"}, [("permissions.defaultMode", "default", "every-action")]),
        ({"defaultMode": "plan", "allow": []}, [("permissions.defaultMode", "plan", "every-action")]),
        (
            {"defaultMode": "default", "allow": ["Bash(npm test:*)"]},
            [
                ("permissions.defaultMode", "default", "every-action"),
                ("permissions.allow", "rules", "some-actions"),
            ],
        ),
        (
            {"defaultMode": "default", "allow": "Bash"},
            [
                ("permissions.defaultMode", "default", "every-action"),
                ("permissions.allow", "unreadable", "some-actions"),
            ],
        ),
        ({"defaultMode": "acceptEdits"}, [("permissions.defaultMode", "acceptEdits", "some-actions")]),
        ({"defaultMode": "bypassPermissions"}, []),
        # The default mode applies when nothing is set, but an unset mode is not evidence.
        ({"allow": []}, []),
        ({"defaultMode": 3}, []),
        # Allow rules pre-approve tools whichever file sets the mode (regression: a file without
        # defaultMode, such as settings.local.json, reported nothing).
        ({"allow": ["Bash(git push:*)", "Edit"]}, [("permissions.allow", "rules", "some-actions")]),
        ({"allow": {"Bash": True}}, [("permissions.allow", "unreadable", "some-actions")]),
    ],
)
def test_claude_code_approval_settings(permissions, expected):
    assert scopes(CLAUDE, json.dumps({"permissions": permissions})) == expected


HOOK = [{"matcher": "Bash", "hooks": [{"type": "command", "command": "./allow.sh"}]}]


@pytest.mark.parametrize(
    ("settings", "expected"),
    [
        # A sandbox runs Bash without a prompt unless autoAllowBashIfSandboxed is false (default true).
        ({"sandbox": {"enabled": True}}, [("sandbox.autoAllowBashIfSandboxed", "true", "some-actions")]),
        (
            {"sandbox": {"enabled": True, "autoAllowBashIfSandboxed": True}},
            [("sandbox.autoAllowBashIfSandboxed", "true", "some-actions")],
        ),
        (
            {"sandbox": {"enabled": "yes"}},
            [("sandbox.autoAllowBashIfSandboxed", "true", "some-actions")],
        ),
        ({"sandbox": {"enabled": True, "autoAllowBashIfSandboxed": False}}, []),
        ({"sandbox": {"enabled": False}}, []),
        ({"sandbox": {}}, []),
        ({"sandbox": "on"}, [("sandbox", "unreadable", "some-actions")]),
        # A PreToolUse or PermissionRequest hook can allow a call without a prompt.
        ({"hooks": {"PreToolUse": HOOK}}, [("hooks.PreToolUse", "configured", "some-actions")]),
        ({"hooks": {"PermissionRequest": HOOK}}, [("hooks.PermissionRequest", "configured", "some-actions")]),
        ({"hooks": {"PostToolUse": HOOK, "PreToolUse": []}}, []),
        ({"hooks": {"PreToolUse": "x"}}, [("hooks.PreToolUse", "configured", "some-actions")]),
        ({"hooks": ["PreToolUse"]}, [("hooks", "unreadable", "some-actions")]),
        ({"permissions": ["allow"]}, [("permissions", "unreadable", "some-actions")]),
        (
            {
                "permissions": {"defaultMode": "default"},
                "sandbox": {"enabled": True},
                "hooks": {"PreToolUse": HOOK},
            },
            [
                ("permissions.defaultMode", "default", "every-action"),
                ("sandbox.autoAllowBashIfSandboxed", "true", "some-actions"),
                ("hooks.PreToolUse", "configured", "some-actions"),
            ],
        ),
    ],
)
def test_claude_code_settings_that_run_actions_without_a_prompt(settings, expected):
    assert scopes(CLAUDE, json.dumps(settings)) == expected


@pytest.mark.parametrize(
    ("rel", "text"),
    [
        (
            CLAUDE,
            json.dumps(
                {"permissions": {"defaultMode": "default", "allow": ["Edit"]}, "sandbox": {"enabled": True}}
            ),
        ),
        (
            ".codex/config.toml",
            'approval_policy = "untrusted"\n[profiles.ci]\napproval_policy = "on-request"\n',
        ),
        (".codex/config.toml", '[profiles."a.b"]\napproval_policy = "untrusted"\n'),
        (".config/goose/config.yaml", "GOOSE_MODE: approve\n"),
    ],
)
def test_every_reported_setting_is_one_a_replay_accepts(rel, text):
    settings = approval_settings(rel, text)
    assert settings
    for setting in settings:
        item = {**setting.as_dict(), "file": rel}
        assert setting.scope in approval_scopes(setting.client, setting.setting, setting.value)
        assert valid_approval(item, client=setting.client, file=rel)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('approval_policy = "untrusted"\n', [("approval_policy", "untrusted", "every-action")]),
        (
            'approval_policy = "on-request"\nsandbox_mode = "read-only"\n',
            [("approval_policy", "on-request", "some-actions")],
        ),
        ('approval_policy = "on-failure"\n', [("approval_policy", "on-failure", "some-actions")]),
        ('approval_policy = "never"\n', []),
        (
            'approval_policy = "untrusted"\n[profiles.ci]\napproval_policy = "untrusted"\n',
            [
                ("approval_policy", "untrusted", "every-action"),
                ("profiles.ci.approval_policy", "untrusted", "every-action"),
            ],
        ),
        # A profile cannot gate the default run it does not configure.
        (
            '[profiles.safe]\napproval_policy = "untrusted"\n',
            [("profiles.safe.approval_policy", "untrusted", "some-actions")],
        ),
        ('model = "x"\nprofiles = 3\n', []),
    ],
)
def test_codex_approval_settings(text, expected):
    assert scopes(".codex/config.toml", text) == expected


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        ("approve", [("GOOSE_MODE", "approve", "every-action")]),
        (" Approve ", [("GOOSE_MODE", "approve", "every-action")]),
        ("smart_approve", [("GOOSE_MODE", "smart_approve", "some-actions")]),
        ("auto", []),
        (3, []),
    ],
)
def test_goose_approval_settings(mode, expected):
    assert scopes(".config/goose/config.yaml", f"GOOSE_MODE: {json.dumps(mode)}\n") == expected


@pytest.mark.parametrize(
    ("rel", "text", "expected"),
    [
        ("README.md", "{}", None),
        (CLAUDE, "{not json", []),
        (CLAUDE, "[1]", []),
        (".openclaw/openclaw.json", json.dumps({"gateway": {"bind": "lan"}}), []),
    ],
)
def test_approval_settings_of_unknown_or_unreadable_files(rel, text, expected):
    assert approval_settings(rel, text) == expected


def _config_finding() -> Finding:
    return Finding(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.AGENT_CONFIG,
        title="Claude Code configured",
        resource="repo",
        resource_type="coding-agent-config",
        capabilities=["code-exec", "tool-use"],
    )


def test_record_approval_needs_every_setting_and_no_ungated_posture():
    every = ApprovalSetting("claude-code", "permissions.defaultMode", "default", "every-action").as_dict()
    some = ApprovalSetting("claude-code", "permissions.defaultMode", "acceptEdits", "some-actions").as_dict()
    f = _config_finding()
    record_approval(f, [])
    assert "approval_gate" not in f.metadata
    record_approval(f, [every])
    assert f.metadata["approval_gate"] == {"scope": "every-action", "settings": [every]}
    assert interval(f) == (2, 2, "gated", "unknown")
    record_approval(f, [every, some])
    assert f.metadata["approval_gate"]["scope"] == "some-actions"
    shell = _config_finding()
    record_posture(
        shell,
        [
            {
                "id": "posture-unrestricted-shell",
                "client": "claude-code",
                "setting": "permissions.allow",
                "value": "Bash",
            }
        ],
    )
    record_approval(shell, [every])
    assert shell.metadata["approval_gate"]["scope"] == "some-actions"
    assert interval(shell) == (4, 5, "bypassed", "unknown")
    many = _config_finding()
    record_approval(many, [every] * 30)
    assert len(many.metadata["approval_gate"]["settings"]) == 20


def test_settings_that_only_skip_prompts_record_no_gate_alone_but_make_one_partial():
    every = ApprovalSetting("claude-code", "permissions.defaultMode", "default", "every-action").as_dict()
    sandbox = ApprovalSetting(
        "claude-code", "sandbox.autoAllowBashIfSandboxed", "true", "some-actions"
    ).as_dict()
    hook = ApprovalSetting("claude-code", "hooks.PreToolUse", "configured", "some-actions").as_dict()
    allow = ApprovalSetting("claude-code", "permissions.allow", "rules", "some-actions").as_dict()
    alone = _config_finding()
    record_approval(alone, [sandbox, hook])
    assert "approval_gate" not in alone.metadata
    assert interval(alone) == (2, 5, "unknown", "unknown")
    partial = _config_finding()
    record_approval(partial, [every, sandbox])
    assert partial.metadata["approval_gate"] == {"scope": "some-actions", "settings": [every, sandbox]}
    assert interval(partial) == (2, 5, "gated", "unknown")
    # Allow rules configure approval: the tools they do not name still ask.
    rules = _config_finding()
    record_approval(rules, [allow])
    assert rules.metadata["approval_gate"]["scope"] == "some-actions"


SETTINGS = "~/.claude/settings.json"
ENTRY = {
    "client": "claude-code",
    "setting": "permissions.defaultMode",
    "value": "default",
    "scope": "every-action",
    "file": SETTINGS,
}


@pytest.mark.parametrize(
    ("item", "client", "file", "valid"),
    [
        (ENTRY, "claude-code", SETTINGS, True),
        ({**ENTRY, "value": "plan"}, "claude-code", SETTINGS, True),
        ({**ENTRY, "value": "acceptEdits", "scope": "some-actions"}, "claude-code", SETTINGS, True),
        (
            {**ENTRY, "setting": "permissions.allow", "value": "rules", "scope": "some-actions"},
            "claude-code",
            SETTINGS,
            True,
        ),
        (
            {
                "client": "codex",
                "setting": "approval_policy",
                "value": "untrusted",
                "scope": "every-action",
                "file": "~/.codex/config.toml",
            },
            "codex",
            "~/.codex/config.toml",
            True,
        ),
        (
            {
                "client": "codex",
                "setting": "profiles.ci.approval_policy",
                "value": "untrusted",
                "scope": "some-actions",
                "file": "~/.codex/config.toml",
            },
            "codex",
            "~/.codex/config.toml",
            True,
        ),
        (
            {
                "client": "goose",
                "setting": "GOOSE_MODE",
                "value": "approve",
                "scope": "every-action",
                "file": "~/.config/goose/config.yaml",
            },
            "goose",
            "~/.config/goose/config.yaml",
            True,
        ),
        # A scope the reader never reports for that value.
        ({**ENTRY, "value": "acceptEdits"}, "claude-code", SETTINGS, False),
        ({**ENTRY, "setting": "permissions.allow", "value": "rules"}, "claude-code", SETTINGS, False),
        ({**ENTRY, "scope": "all"}, "claude-code", SETTINGS, False),
        # A setting or value the reader never reports.
        ({**ENTRY, "setting": "anything"}, "claude-code", SETTINGS, False),
        ({**ENTRY, "value": "bypassPermissions"}, "claude-code", SETTINGS, False),
        # A client whose approvals the scanner does not read (regression: a Cursor record gated).
        (
            {
                "client": "cursor",
                "setting": "anything",
                "value": "x",
                "scope": "every-action",
                "file": "~/.cursor/mcp.json",
            },
            "cursor",
            "~/.cursor/mcp.json",
            False,
        ),
        # Bound to the record it came with, and to a settings file of its client.
        (ENTRY, "codex", SETTINGS, False),
        (ENTRY, "claude-code", "~/.claude/settings.local.json", False),
        ({**ENTRY, "file": "~/.cursor/mcp.json"}, "claude-code", "~/.cursor/mcp.json", False),
        ({k: v for k, v in ENTRY.items() if k != "file"}, "claude-code", None, False),
        ({**ENTRY, "extra": "x"}, "claude-code", SETTINGS, False),
        ({**ENTRY, "setting": 1}, "claude-code", SETTINGS, False),
        ("every-action", "claude-code", SETTINGS, False),
    ],
)
def test_valid_approval(item, client, file, valid):
    assert valid_approval(item, client=client, file=file) is valid


# ----------------------------------------------------------- code connector


def test_code_connector_records_gated_and_partial_coding_agent_settings(run_connector, tmp_path):
    write(tmp_path, ".claude/settings.json", json.dumps({"permissions": {"defaultMode": "default"}}))
    write(tmp_path, ".codex/config.toml", 'approval_policy = "on-failure"\n')
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), label="home", use_git=False)
    assert not ctx.stats.errors
    configs = {f.frameworks[0]: f for f in findings if f.kind == Kind.AGENT_CONFIG}
    claude = configs["coding-agent.claude-code"]
    assert claude.metadata["approval_gate"] == {
        "scope": "every-action",
        "settings": [
            {
                "client": "claude-code",
                "setting": "permissions.defaultMode",
                "value": "default",
                "scope": "every-action",
                "file": ".claude/settings.json",
            }
        ],
    }
    assert classify(claude)["ceiling"] == 2 and classify(claude)["oversight"] == "gated"
    codex = configs["coding-agent.openai-codex"]
    assert codex.metadata["approval_gate"]["scope"] == "some-actions"
    assert classify(codex)["ceiling"] == 5


DEFAULT_MODE = json.dumps({"permissions": {"defaultMode": "default"}})


@pytest.mark.parametrize(
    ("files", "settings"),
    [
        # Allow rules in settings.local.json, which sets no mode.
        (
            {
                ".claude/settings.local.json": {
                    "permissions": {"allow": ["Bash(git push:*)", "Edit", "Write", "Bash(rm:*)"]}
                }
            },
            [("permissions.allow", "rules", ".claude/settings.local.json")],
        ),
        # A sandbox that auto-allows Bash, in the file that sets the mode.
        (
            {
                ".claude/settings.json": {
                    "permissions": {"defaultMode": "default"},
                    "sandbox": {"enabled": True, "autoAllowBashIfSandboxed": True},
                }
            },
            [("sandbox.autoAllowBashIfSandboxed", "true", ".claude/settings.json")],
        ),
        # A PreToolUse hook that can answer permissionDecision allow.
        (
            {
                ".claude/settings.json": {
                    "permissions": {"defaultMode": "default"},
                    "hooks": {"PreToolUse": HOOK},
                }
            },
            [("hooks.PreToolUse", "configured", ".claude/settings.json")],
        ),
    ],
)
def test_code_connector_settings_that_skip_prompts_make_a_default_mode_gate_partial(
    run_connector, tmp_path, files, settings
):
    # Regression: each of these was recorded as every-action, capping the interval at L2.
    write(tmp_path, ".claude/settings.json", DEFAULT_MODE)
    for rel, payload in files.items():
        write(tmp_path, rel, json.dumps(payload))
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), label="home", use_git=False)
    assert not ctx.stats.errors
    [claude] = [f for f in findings if f.kind == Kind.AGENT_CONFIG]
    gate = claude.metadata["approval_gate"]
    assert gate["scope"] == "some-actions"
    recorded = {(s["setting"], s["value"], s["file"]) for s in gate["settings"]}
    assert ("permissions.defaultMode", "default", ".claude/settings.json") in recorded
    assert set(settings) <= recorded
    autonomy = classify(claude)
    assert (autonomy["ceiling"], autonomy["oversight"]) == (5, "gated")
    assert "per-action-approval" not in {item["rule"] for item in autonomy["basis"]}
    agent = Finding(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.AGENT,
        title="agent",
        resource="repo",
        resource_type="agent",
        capabilities=["tool-use", "code-exec"],
        metadata={"approval_gate": gate},
    )
    # The model-loop floor is suppressed only when every action is approved.
    assert interval(agent)[:2] == (3, 5)


def test_code_connector_sandbox_without_a_mode_records_no_gate(run_connector, tmp_path):
    write(tmp_path, ".claude/settings.json", json.dumps({"sandbox": {"enabled": True}}))
    findings, _ = run_connector("code.filesystem", path=str(tmp_path), label="home", use_git=False)
    [claude] = [f for f in findings if f.kind == Kind.AGENT_CONFIG]
    assert "approval_gate" not in claude.metadata
    assert classify(claude)["oversight"] == "unknown"


def test_code_connector_local_settings_that_bypass_approval_win(run_connector, tmp_path):
    write(tmp_path, ".claude/settings.json", json.dumps({"permissions": {"defaultMode": "default"}}))
    write(
        tmp_path,
        ".claude/settings.local.json",
        json.dumps({"permissions": {"defaultMode": "bypassPermissions"}}),
    )
    findings, _ = run_connector("code.filesystem", path=str(tmp_path), label="home", use_git=False)
    [claude] = [f for f in findings if f.kind == Kind.AGENT_CONFIG]
    assert claude.metadata["approval_gate"]["scope"] == "some-actions"
    autonomy = classify(claude)
    assert autonomy["oversight"] == "bypassed" and autonomy["ceiling"] == 5


# ------------------------------------------------------- endpoint connector


def test_endpoint_inventory_records_approval_and_replays_it(run_connector, tmp_path):
    home = tmp_path / "dana"
    write(home, ".claude/settings.json", json.dumps({"permissions": {"defaultMode": "plan"}}))
    write(home, ".config/goose/config.yaml", "GOOSE_MODE: smart_approve\n")
    target = tmp_path / "export.jsonl"
    findings, ctx = run_connector(
        "endpoint.inventory", path=str(home), label="laptop", _dump_path=str(target)
    )
    assert not ctx.stats.incomplete
    live = {f.title.split(" on laptop")[0]: f for f in findings}
    claude = live["Claude Code configured"]
    assert claude.metadata["approval_gate"]["scope"] == "every-action"
    assert claude.metadata["approval_gate"]["settings"][0]["file"] == "~/.claude/settings.json"
    assert interval(claude)[1:3] == (2, "gated")
    assert live["Goose configured"].metadata["approval_gate"]["scope"] == "some-actions"
    replayed, replay_ctx = run_connector("endpoint.inventory", input=str(target), label="laptop")
    assert not replay_ctx.stats.incomplete
    again = {f.title.split(" on laptop")[0]: f for f in replayed}
    assert {k: f.metadata.get("approval_gate") for k, f in again.items()} == {
        k: f.metadata.get("approval_gate") for k, f in live.items()
    }


def _replay(run_connector, tmp_path, record):
    target = tmp_path / "export.jsonl"
    target.write_text(json.dumps(record) + "\n")
    return run_connector("endpoint.inventory", input=str(target), label="lap")


CURSOR_RECORD = {
    "device": "lap",
    "home": "dana",
    "record_type": "agent_config",
    "client": "cursor",
    "product": "Cursor",
    "signature": "coding-agent.cursor",
    "location": "~/.cursor/mcp.json",
}


@pytest.mark.parametrize(
    "approval",
    [
        # Regression: an export gated a client whose approvals the scanner never reads.
        {"client": "cursor", "setting": "anything", "value": "x", "scope": "every-action"},
        {
            "client": "cursor",
            "setting": "anything",
            "value": "x",
            "scope": "every-action",
            "file": "~/.cursor/mcp.json",
        },
        # A real Claude Code setting does not belong to a Cursor record or its file.
        {
            "client": "claude-code",
            "setting": "permissions.defaultMode",
            "value": "default",
            "scope": "every-action",
            "file": "~/.claude/settings.json",
        },
    ],
)
def test_endpoint_replay_drops_approval_entries_the_reader_cannot_produce(run_connector, tmp_path, approval):
    findings, ctx = _replay(run_connector, tmp_path, {**CURSOR_RECORD, "approval": [approval]})
    assert ctx.stats.incomplete
    assert any("dropped 1 malformed" in warning for warning in ctx.stats.warnings)
    [cursor] = [f for f in findings if f.kind == Kind.AGENT_CONFIG]
    assert "approval_gate" not in cursor.metadata
    assert interval(cursor)[1:3] == (5, "unknown")


def test_endpoint_replay_drops_a_claude_code_scope_the_setting_cannot_have(run_connector, tmp_path):
    record = {
        **CURSOR_RECORD,
        "client": "claude-code",
        "product": "Claude Code",
        "signature": "coding-agent.claude-code",
        "location": "~/.claude/settings.json",
        "approval": [
            {
                "client": "claude-code",
                "setting": "permissions.defaultMode",
                "value": "acceptEdits",
                "scope": "every-action",
                "file": "~/.claude/settings.json",
            }
        ],
    }
    findings, ctx = _replay(run_connector, tmp_path, record)
    assert ctx.stats.incomplete
    [claude] = [f for f in findings if f.kind == Kind.AGENT_CONFIG]
    assert "approval_gate" not in claude.metadata


def test_endpoint_interactive_extensions_are_person_started(run_connector, tmp_path):
    home = tmp_path / "dana"
    write(home, ".vscode/extensions/github.copilot-1.388.0/package.json", "{}")
    findings, _ = run_connector("endpoint.inventory", path=str(home), label="laptop")
    [extension] = [f for f in findings if f.resource_type == "ide-extension"]
    assert classify(extension)["initiation"] == "human"


# ------------------------------------------------------------------- AWS


def _group(state="ENABLED", parent=None, functions=None, schema=True):
    group = {"actionGroupName": "g", "actionGroupState": state}
    if parent:
        group["parentActionSignature"] = parent
    if schema:
        group["functionSchema"] = {"functions": functions or []}
    return group


ENABLED = {"name": "a", "requireConfirmation": "ENABLED"}
DISABLED = {"name": "b", "requireConfirmation": "DISABLED"}


@pytest.mark.parametrize(
    ("groups", "scope"),
    [
        ([_group(functions=[ENABLED, ENABLED])], "every-action"),
        # The user-input group acts on nothing and a disabled group cannot run.
        ([_group(functions=[ENABLED]), _group(parent="AMAZON.UserInput", schema=False)], "every-action"),
        ([_group(functions=[ENABLED]), _group(state="DISABLED", functions=[DISABLED])], "every-action"),
        ([_group(functions=[ENABLED, DISABLED])], "some-actions"),
        (
            [_group(functions=[ENABLED]), _group(parent="AMAZON.CodeInterpreter", schema=False)],
            "some-actions",
        ),
        ([_group(functions=[ENABLED]), _group(schema=False)], "some-actions"),
        ([_group(functions=[ENABLED]), _group(functions=["x", 3])], "some-actions"),
        ([_group(functions=[DISABLED])], None),
        ([_group(schema=False), "junk"], None),
        ([], None),
    ],
)
def test_bedrock_approval_gate(groups, scope):
    gate = _bedrock_approval_gate(groups)
    assert (gate and gate["scope"]) == scope


def test_bedrock_agent_with_every_function_confirmed_is_supervised(run_connector, tmp_path):
    source = tmp_path / "aws.jsonl"
    record = {
        "_kind": "bedrock-agent",
        "_region": "us-east-1",
        "agentId": "AGENTX",
        "agentArn": "arn:aws:bedrock:us-east-1:111111111111:agent/AGENTX",
        "agentName": "refunds",
        "agentStatus": "PREPARED",
        "_action_groups": [
            {
                "actionGroupName": "refund",
                "actionGroupState": "ENABLED",
                "actionGroupExecutor": {"lambda": "arn:aws:lambda:us-east-1:111111111111:function:refund"},
                "functionSchema": {"functions": [ENABLED]},
            }
        ],
    }
    source.write_text(json.dumps(record) + "\n")
    [agent], ctx = run_connector("cloud.aws", input=str(source))
    assert not ctx.stats.incomplete
    assert agent.metadata["approval_gate"]["settings"] == [
        {"setting": "functionSchema.functions.requireConfirmation", "value": "ENABLED for 1 of 1 function(s)"}
    ]
    assert interval(agent) == (2, 2, "gated", "unknown")


# ---------------------------------------------- triggers recorded by connectors


def test_cloud_and_lowcode_triggers_classify_initiation(run_connector, fixtures):
    findings, _ = run_connector("cloud.azure", input=str(fixtures / "cloud" / "azure_records.jsonl"))
    logic = next(f for f in findings if f.resource_type == "logic-app")
    assert logic.metadata["trigger_types"] == ["Recurrence"]
    assert interval(logic) == (3, 5, "unknown", "schedule")

    findings, _ = run_connector("cloud.gcp", input=str(fixtures / "cloud" / "gcp_extended_records.jsonl"))
    function = next(f for f in findings if f.resource_type == "cloud-function")
    assert "autonomous" in function.capabilities and interval(function)[2:] == ("unknown", "event")

    findings, _ = run_connector(
        "lowcode.salesforce",
        input=str(fixtures / "lowcode" / "salesforce.json"),
        instance_url="https://acme.my.salesforce.com",
    )
    flow = next(f for f in findings if f.resource_type == "flow")
    assert interval(flow)[0] == 3 and interval(flow)[3] == "event"

    findings, _ = run_connector(
        "lowcode.power-platform", input=str(fixtures / "lowcode" / "power_platform.json")
    )
    workflow = next(f for f in findings if f.kind == Kind.WORKFLOW)
    assert "scheduled" in workflow.tags and interval(workflow)[3] == "schedule"


def test_logic_app_trigger_types_ignore_malformed_trigger_entries(run_connector, tmp_path):
    record = {
        "_kind": "logicapp-definition",
        "id": "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Logic/workflows/x",
        "name": "x",
        "definition": {
            "triggers": {
                "When_a_message_arrives": {"type": "ApiConnectionWebhook"},
                "Odd": {"type": 7},
                "Bad": {},
            },
            "actions": {
                "Ask_GPT": {
                    "type": "ApiConnection",
                    "inputs": {
                        "host": {
                            "connection": {
                                "name": "@parameters('$connections')['azureopenai']['connectionId']"
                            }
                        }
                    },
                }
            },
        },
        "connections": {
            "azureopenai": {
                "id": "/subscriptions/s1/providers/Microsoft.Web/locations/eastus/managedApis/azureopenai"
            }
        },
    }
    source = tmp_path / "azure.jsonl"
    source.write_text(json.dumps(record) + "\n")
    findings, _ = run_connector("cloud.azure", input=str(source))
    [logic] = [f for f in findings if f.resource_type == "logic-app"]
    assert logic.metadata["trigger_types"] == ["ApiConnectionWebhook"]
    assert "autonomous" not in logic.capabilities and interval(logic)[3] == "event"
