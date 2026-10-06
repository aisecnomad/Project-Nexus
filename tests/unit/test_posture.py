"""Agent settings posture checks (shadowscan.connectors.posture)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shadowscan.connectors.posture import POSTURE_DESCRIPTIONS, PostureIssue, assess, posture_client
from shadowscan.models import Kind


def ids(rel: str, text: str) -> list[str]:
    issues = assess(rel, text)
    assert issues is not None
    return [i.id for i in issues]


@pytest.mark.parametrize(
    ("rel", "client"),
    [
        (".claude/settings.json", "claude-code"),
        ("proj/.claude/settings.local.json", "claude-code"),
        (".codex/config.toml", "codex"),
        (".config/goose/config.yaml", "goose"),
        ("AppData/Roaming/Block/goose/config/config.yaml", "goose"),
        (".openclaw/openclaw.json", "openclaw"),
        (".clawdbot/clawdbot.json", "openclaw"),
        (".claude/agents/x.md", None),
        ("config.yaml", None),
        ("", None),
    ],
)
def test_posture_client(rel, client):
    assert posture_client(rel) == client


def test_unknown_file_is_not_assessed():
    assert assess("README.md", "{}") is None


def test_claude_code_bypass_and_unrestricted_bash():
    text = json.dumps({"permissions": {"defaultMode": "bypassPermissions", "allow": ["Read", " Bash(*) "]}})
    issues = assess(".claude/settings.json", text)
    assert issues == [
        PostureIssue(
            "posture-permissions-bypassed", "claude-code", "permissions.defaultMode", "bypassPermissions"
        ),
        PostureIssue("posture-unrestricted-shell", "claude-code", "permissions.allow", "Bash(*)"),
    ]
    assert issues[0].description == POSTURE_DESCRIPTIONS["posture-permissions-bypassed"]
    assert issues[0].as_dict()["setting"] == "permissions.defaultMode"


@pytest.mark.parametrize("rule", ["Bash", "Bash(*)", "Bash(*:*)", "Bash(:*)"])
def test_claude_code_unrestricted_bash_rules(rule):
    assert ids(".claude/settings.json", json.dumps({"permissions": {"allow": [rule]}})) == [
        "posture-unrestricted-shell"
    ]


@pytest.mark.parametrize(
    "settings",
    [
        {"permissions": {"defaultMode": "acceptEdits", "allow": ["Bash(npm test:*)", "Read", 7]}},
        {"permissions": "nope"},
        {"model": "sonnet"},
        {"permissions": {"allow": "Bash"}},
    ],
)
def test_claude_code_scoped_settings_are_fine(settings):
    assert ids(".claude/settings.json", json.dumps(settings)) == []


def test_claude_code_settings_allow_comments():
    assert ids(".claude/settings.json", '{"permissions": {"defaultMode": "bypassPermissions"}} // x') == [
        "posture-permissions-bypassed"
    ]


def test_codex_top_level_and_profiles():
    text = (
        'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n'
        '[profiles.safe]\napproval_policy = "on-request"\n'
        '[profiles.yolo]\nsandbox_mode = "danger-full-access"\n'
    )
    issues = assess(".codex/config.toml", text)
    assert issues is not None
    assert [(i.id, i.setting) for i in issues] == [
        ("posture-permissions-bypassed", "approval_policy"),
        ("posture-unsandboxed", "sandbox_mode"),
        ("posture-unsandboxed", "profiles.yolo.sandbox_mode"),
    ]


def test_codex_defaults_are_fine():
    assert ids(".codex/config.toml", 'model = "gpt-5"\napproval_policy = "on-request"\nprofiles = 3\n') == []


@pytest.mark.parametrize(
    ("mode", "flagged"), [("auto", True), (" AUTO ", True), ("approve", False), (3, False)]
)
def test_goose_mode(mode, flagged):
    text = f"GOOSE_MODE: {json.dumps(mode)}\n"
    assert (ids(".config/goose/config.yaml", text) == ["posture-permissions-bypassed"]) is flagged


@pytest.mark.parametrize(
    ("gateway", "expected"),
    [
        ({"bind": "lan"}, ["posture-exposed-gateway", "posture-unauthenticated-gateway"]),
        ({"bind": "lan", "auth": {"token": "x" * 24}}, ["posture-exposed-gateway"]),
        ({"bind": "custom", "customBindHost": "0.0.0.0", "auth": {"token": " "}},
         ["posture-exposed-gateway", "posture-unauthenticated-gateway"]),
        ({"bind": "custom", "customBindHost": "127.0.0.1"}, []),
        ({"bind": "loopback"}, []),
        ({}, []),
    ],
)  # fmt: skip
def test_openclaw_gateway(gateway, expected):
    assert ids(".openclaw/openclaw.json", json.dumps({"gateway": gateway})) == expected


def test_openclaw_never_reports_the_token_and_flags_shell_access():
    text = json.dumps({"gateway": {"bind": "lan", "auth": "bad"}, "capabilities": {"shellAccess": True}})
    issues = assess(".openclaw/openclaw.json", text)
    assert issues is not None
    assert [(i.id, i.value) for i in issues] == [
        ("posture-exposed-gateway", "lan"),
        ("posture-unauthenticated-gateway", "unset"),
        ("posture-unrestricted-shell", "true"),
    ]


@pytest.mark.parametrize(
    ("rel", "text"),
    [
        (".claude/settings.json", "{not json"),
        (".claude/settings.json", "[1, 2]"),
        (".codex/config.toml", "approval_policy = "),
        (".config/goose/config.yaml", "a: [unclosed"),
        (".openclaw/openclaw.json", '{"a": 1, "a": 2}'),
    ],
)
def test_unparseable_or_non_object_settings_have_no_issues(rel, text):
    assert assess(rel, text) == []


def write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_code_connector_reports_posture_on_the_agent_config(run_connector, tmp_path):
    write(
        tmp_path, ".claude/settings.json", json.dumps({"permissions": {"defaultMode": "bypassPermissions"}})
    )
    write(tmp_path, ".codex/config.toml", 'sandbox_mode = "danger-full-access"\n')
    write(tmp_path, ".openclaw/openclaw.json", json.dumps({"gateway": {"bind": "lan"}}))
    write(tmp_path, ".config/goose/config.yaml", "GOOSE_MODE: approve\n")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), label="home", use_git=False)
    assert not ctx.stats.errors
    configs = {f.frameworks[0]: f for f in findings if f.kind == Kind.AGENT_CONFIG}
    claude = configs["coding-agent.claude-code"]
    assert "posture-permissions-bypassed" in claude.tags and "autonomous" in claude.capabilities
    assert claude.metadata["posture"][0]["file"] == ".claude/settings.json"
    assert "posture-unsandboxed" in configs["coding-agent.openai-codex"].tags
    assert {"posture-exposed-gateway", "posture-unauthenticated-gateway"} <= set(
        configs["coding-agent.openclaw"].tags
    )
    assert "posture" not in configs["coding-agent.goose"].metadata
    evidence = [e for e in claude.evidence if e.signal.startswith("posture:")]
    assert evidence and evidence[0].weight == 0.0
