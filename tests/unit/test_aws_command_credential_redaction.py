"""AWS configure-set values stay private through source evidence and cache replay."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.utils import redaction
from shadowscan.utils.redaction import REDACTED, SanitizationLimitError, sanitize, sanitize_text

# No real credential or vendor-token literal is committed or used by these tests.
SECRET = "Zx9qOpaque" + "Value7731"
SETTINGS = ("aws_secret_access_key", "aws_session_token", "aws_security_token", "aws_access_key_id")


@pytest.mark.parametrize("setting", SETTINGS)
@pytest.mark.parametrize(
    "command",
    [
        "aws configure set {setting} {secret}",
        "aws configure set '{setting}' '{secret}' --profile audit",
        'aws --profile audit configure set "{setting}" "{secret}"',
        "aws configure --profile=audit set default.{setting} {secret}",
        "aws configure set profile.audit.{setting} --profile audit {secret}",
        "aws --debug --region eu-west-1 configure set profile.team-a.{setting} {secret}",
        "aws \\\n  configure \\\n  set {setting} \\\n  {secret}",
        'subprocess.run(["aws", "configure", "set", "{setting}", "{secret}"])',
        "subprocess.run(['aws', '--profile', 'audit', 'configure', 'set', '{setting}', '{secret}'])",
        'run([\n  "aws",\n  "configure",\n  "set",\n  "{setting}",\n  "{secret}"\n])',
        'os.system("aws configure set {setting} {secret}")',
        '/usr/local/bin/aws configure set {setting} "{secret}"',
        '"/opt/aws" configure set {setting} "{secret}"',
        'aws.exe configure set {setting} "{secret}"',
    ],
)
def test_aws_positional_credentials_are_redacted(command, setting):
    source = command.format(setting=setting, secret=SECRET)
    safe = sanitize_text(source)
    assert SECRET not in safe and REDACTED in safe
    assert safe.count("\n") == source.count("\n")
    assert sanitize_text(safe) == safe
    assert "configure" in safe and "set" in safe


@pytest.mark.parametrize("setting", SETTINGS)
@pytest.mark.parametrize("container", [list, tuple])
@pytest.mark.parametrize("byte_values", [False, True])
def test_native_argv_credentials_and_sibling_copies_are_withheld(setting, container, byte_values):
    argv = ["aws", "--profile", "audit", "configure", "set", f"profile.audit.{setting}", SECRET]
    if byte_values:
        argv = [item.encode() for item in argv]
    source = {"args": container(argv), "note": f"copied {SECRET}", "model": "gpt-4o"}
    safe = sanitize(source)
    assert SECRET not in repr(safe)
    assert safe["model"] == "gpt-4o"
    assert sanitize(safe) == safe


@pytest.mark.parametrize(
    "value",
    [
        "$AWS_SECRET_ACCESS_KEY",
        "${AWS_SESSION_TOKEN}",
        "${{ secrets.AWS_ACCESS_KEY_ID }}",
        "%AWS_SESSION_TOKEN%",
        "<your-key>",
        "YOUR_SECRET_KEY",
        "example-secret-value",
        "xxxx",
        REDACTED,
    ],
)
def test_aws_reference_and_placeholder_policy_is_preserved(value):
    command = f'aws configure set aws_secret_access_key "{value}"'
    assert sanitize_text(command) == command
    argv = ["aws", "configure", "set", "aws_secret_access_key", value]
    assert sanitize(argv) == argv


@pytest.mark.parametrize(
    "source",
    [
        "myaws configure set aws_secret_access_key ordinary-value",
        "not-aws configure set aws_secret_access_key ordinary-value",
        "aws-tool configure set aws_secret_access_key ordinary-value",
        "aws.configure set aws_secret_access_key ordinary-value",
        "aws configure get aws_secret_access_key ordinary-value",
        "aws configure set region eu-west-1",
        "aws configure set source_profile audit",
        "aws configure set profile.audit.region eu-west-1",
        "aws configure set aws_secret_access_key_suffix ordinary-value",
        "aws configure set telemetry.aws_secret_access_key ordinary-value",
        "aws\nconfigure set aws_secret_access_key ordinary-value",
        "aws configure; set aws_secret_access_key ordinary-value",
        "aws configure set aws_secret_access_key",
        '["aws", "configure", "set", "aws_secret_access_key", key_lookup()]',
        '["aws", "configure", "set", "aws_secret_access_key", config["ordinary-value"]]',
    ],
)
def test_unrelated_or_computed_commands_are_preserved(source):
    assert sanitize_text(source) == source


def test_native_unrelated_commands_are_preserved():
    for argv in (
        ["not-aws", "configure", "set", "aws_secret_access_key", "ordinary-value"],
        ["aws", "configure", "set", "region", "eu-west-1"],
        ["aws", "configure", "get", "aws_secret_access_key"],
        ["aws", "configure", "set", "aws_secret_access_key", None],
    ):
        assert sanitize(argv) == argv


@pytest.mark.parametrize("depth", [1, 2, 3, 4])
@pytest.mark.parametrize("argv", [False, True])
def test_json_escaped_command_quotes_are_redacted(depth, argv):
    source = (
        json.dumps(["aws", "configure", "set", "aws_secret_access_key", SECRET])
        if argv
        else f'aws configure set aws_secret_access_key "{SECRET}"'
    )
    for _ in range(depth):
        source = json.dumps(source)
    safe = sanitize_text(source)
    assert SECRET not in safe and REDACTED in safe
    assert sanitize_text(safe) == safe


def test_json_escaped_quotes_inside_the_value_do_not_leave_a_tail():
    value = SECRET + '"private-tail'
    command = f'aws configure set aws_secret_access_key "{value.replace(chr(34), chr(92) + chr(34))}"'
    source = json.dumps(command)
    safe = sanitize_text(source)
    assert SECRET not in safe and "private-tail" not in safe
    assert sanitize_text(safe) == safe


@pytest.mark.parametrize("setting", SETTINGS)
@pytest.mark.parametrize(
    "argument",
    [
        '"{prefix}""{suffix}"',
        '"{prefix}"{suffix}',
        '{prefix}"{suffix}"',
        '{prefix}";{suffix}"',
        '{prefix}" {suffix}"',
        "{prefix}\\{suffix}",
        "{prefix}\\\n{suffix}",
    ],
)
def test_shell_credential_argument_fragments_are_withheld_together(setting, argument):
    prefix, suffix = SECRET[:8], SECRET[8:]
    source = f"aws configure set {setting} " + argument.format(prefix=prefix, suffix=suffix)
    safe = sanitize_text(source)
    assert prefix not in safe and suffix not in safe
    assert safe.count("\n") == source.count("\n")
    assert sanitize_text(safe) == safe


@pytest.mark.parametrize("depth", [1, 2, 3])
def test_json_escaped_shell_argument_tail_is_withheld_whole(depth):
    prefix, suffix = SECRET[:8], SECRET[8:]
    source = f'aws configure set aws_secret_access_key {prefix}";{suffix}"'
    for _ in range(depth):
        source = json.dumps(source)
    safe = sanitize_text(source)
    assert prefix not in safe and suffix not in safe
    assert sanitize_text(safe) == safe


@pytest.mark.parametrize("setting", SETTINGS)
@pytest.mark.parametrize("operator", [" ", " + ", " + lookup() + "])
def test_source_argv_credential_literal_expression_is_withheld_whole(setting, operator):
    prefix, suffix = SECRET[:8], SECRET[8:]
    value = f'"{prefix}"{operator}"{suffix}"'
    source = f'subprocess.run(["aws", "configure", "set", "{setting}", {value}])'
    safe = sanitize_text(source)
    assert prefix not in safe and suffix not in safe
    assert sanitize_text(safe) == safe


def test_aws_redaction_keeps_other_credentials_withheld():
    source = f'aws configure set aws_secret_access_key {SECRET}#password="another-private-value"; --token Another9OpaqueValue'
    safe = sanitize_text(source)
    assert not any(value in safe for value in (SECRET, "another-private-value", "Another9OpaqueValue"))
    assert sanitize_text(safe) == safe


@pytest.mark.parametrize("native", [False, True])
def test_aws_argument_limit_fails_closed(native, monkeypatch):
    monkeypatch.setattr(redaction, "_AWS_MAX_ARGUMENTS", 5)
    argv = [
        "aws",
        "--profile",
        "audit",
        "--region",
        "eu-west-1",
        "configure",
        "set",
        "aws_secret_access_key",
        SECRET,
    ]
    with pytest.raises(SanitizationLimitError, match="AWS command argument limit"):
        sanitize(argv) if native else sanitize_text(" ".join(argv))


@pytest.mark.parametrize("native", [False, True])
def test_aws_character_limit_fails_closed(native, monkeypatch):
    monkeypatch.setattr(redaction, "_AWS_MAX_COMMAND_CHARS", 40)
    argv = ["aws", "configure", "set", "aws_secret_access_key", SECRET * 20]
    with pytest.raises(SanitizationLimitError, match="AWS command character limit"):
        sanitize(argv) if native else sanitize_text(" ".join(argv))


def test_aws_repeated_candidate_work_remains_bounded():
    # A process deadline makes an accidental quadratic scan observable without
    # requiring sub-second timings from shared CI runners.
    program = """
from shadowscan.utils.redaction import sanitize, sanitize_text
prefix = "aws " * 100_000
assert sanitize_text(prefix) == prefix
argv = ["aws"] * 10_000
assert sanitize(argv) == argv
"""
    subprocess.run(
        [sys.executable, "-c", program], cwd=Path(__file__).resolve().parents[2], timeout=15, check=True
    )


@pytest.mark.parametrize("setting", SETTINGS)
def test_finding_serialization_withholds_aws_command_values(setting):
    finding = Finding(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.FRAMEWORK_USAGE,
        title="LLM bootstrap",
        resource="repo:bootstrap",
        resource_type="project",
        evidence=[
            Evidence(
                signal="import", description="OpenAI import", snippet=f"aws configure set {setting} {SECRET}"
            )
        ],
    )
    assert SECRET not in json.dumps(finding.to_dict())


@pytest.mark.parametrize("setting", SETTINGS)
@pytest.mark.parametrize("json_config", [False, True])
def test_engine_reports_and_cache_replay_withhold_aws_command_values(tmp_path, index, setting, json_config):
    repo = tmp_path / "repo"
    repo.mkdir()
    if json_config:
        (repo / "config.json").write_text(
            json.dumps(
                {
                    "base_url": "https://api.openai.com/v1",
                    "bootstrap": f'aws configure set {setting} "{SECRET}"',
                }
            ),
            encoding="utf-8",
        )
    else:
        (repo / "bootstrap.py").write_text(
            f'import openai,os;os.system("aws configure set {setting} {SECRET}")\n', encoding="utf-8"
        )
    state = tmp_path / "state"
    config = ScanConfig(
        connectors=[ConnectorSpec("code.filesystem", {"path": str(repo), "use_git": False})],
        incremental=True,
        state_dir=str(state),
        parallel=1,
    )
    first = Engine(config, index).run()
    assert first.complete and first.findings
    report_path = tmp_path / "report.json"
    report_path.write_text(first.to_json(), encoding="utf-8")
    assert SECRET not in report_path.read_text() and REDACTED in report_path.read_text()
    assert any(
        evidence.snippet and REDACTED in evidence.snippet
        for finding in first.findings
        for evidence in finding.evidence
    )
    entries = list(state.glob("*.json"))
    assert entries and all(SECRET not in entry.read_text() for entry in entries)
    replay = Engine(config, index).run()
    assert replay.complete and any(stats.cached for stats in replay.stats)
    assert SECRET not in replay.to_json()


def test_source_exceeding_aws_command_limit_is_incomplete_and_withheld(tmp_path, run_connector, monkeypatch):
    monkeypatch.setattr(redaction, "_AWS_MAX_COMMAND_CHARS", 40)
    source = tmp_path / "bootstrap.py"
    source.write_text(
        f'import openai,os;os.system("aws configure set aws_secret_access_key {SECRET * 20}")\n',
        encoding="utf-8",
    )
    findings, context = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert context.stats.incomplete
    assert any("excerpts withheld" in error for error in context.stats.errors)
    assert SECRET not in json.dumps([finding.to_dict() for finding in findings])


@pytest.mark.parametrize("setting", SETTINGS)
@pytest.mark.parametrize(
    "command",
    [
        # Global options the CLI accepts before the subcommand, known or not.
        "aws --no-paginate configure set {setting} {secret}",
        "aws --cli-binary-format raw-in-base64-out configure set {setting} {secret}",
        "aws --future-flag configure set {setting} {secret}",
        "aws --future-option value configure set {setting} {secret}",
        "aws configure set {setting} --future-flag {secret}",
        # Names and executables in other cases.
        "aws configure set {upper} {secret}",
        "AWS configure set {setting} {secret}",
        "Aws.EXE configure set {setting} {secret}",
        "aws.cmd configure set {setting} {secret}",
        "aws configure set default.{upper} {secret}",
        # Comments between source argv elements and Python string prefixes.
        '["aws", "configure", "set",  # store\n "{setting}", "{secret}"]',
        '["aws",  # cli\n "configure", "set", "{setting}",\n  # value\n  "{secret}"]',
        '["aws", "configure", "set", "{setting}",  // value\n "{secret}"]',
        '["aws", "configure", "set", "{setting}", r"{secret}"]',
        '[b"aws", b"configure", b"set", b"{setting}", b"{secret}"]',
        '["aws", "configure", "set", u"{setting}", f"{secret}"]',
        '["aws", "configure", "set", "{setting}", Rb"{secret}"]',
        # PowerShell backtick and cmd caret continuations.
        "aws configure set {setting} `\n  {secret}",
        "aws configure `\r\n  set {setting} `\r\n  {secret}",
        "aws configure set {setting} ^\n  {secret}",
        "aws ^\r\n  configure set {setting} ^\r\n  {secret}",
        # The executable split from its argv list.
        'spawnSync("aws", ["configure", "set", "{setting}", "{secret}"])',
        "spawn('aws', [\n  'configure',\n  'set',\n  '{setting}',\n  '{secret}',\n])",
        'execFile("/usr/local/bin/aws", ["--profile", "audit", "configure", "set", "{setting}", "{secret}"])',
        'subprocess.run("aws", ["configure", "set", "{setting}", "{secret}"])',
    ],
)
def test_aws_command_variants_are_redacted(command, setting):
    source = command.format(setting=setting, upper=setting.upper(), secret=SECRET)
    safe = sanitize_text(source)
    assert SECRET not in safe and REDACTED in safe
    assert safe.count("\n") == source.count("\n")
    assert sanitize_text(safe) == safe


@pytest.mark.parametrize(
    "argv",
    [
        ["aws", "--no-paginate", "configure", "set", "aws_session_token", SECRET],
        [
            "aws",
            "--cli-binary-format",
            "raw-in-base64-out",
            "configure",
            "set",
            "aws_secret_access_key",
            SECRET,
        ],
        ["aws", "--future-option", "value", "configure", "set", "aws_secret_access_key", SECRET],
        ["AWS", "configure", "set", "AWS_SECRET_ACCESS_KEY", SECRET],
        ["C:\\Program Files\\Amazon\\AWSCLIV2\\AWS.EXE", "configure", "set", "aws_access_key_id", SECRET],
        ["aws.cmd", "configure", "set", "aws_session_token", SECRET],
    ],
)
def test_native_argv_variants_and_sibling_copies_are_withheld(argv):
    safe = sanitize({"args": argv, "note": f"copied {SECRET}"})
    assert SECRET not in repr(safe)
    assert sanitize(safe) == safe


def test_end_to_end_report_withholds_a_global_option_variant(tmp_path, index):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "tools.py").write_text(
        "import subprocess\nfrom agents import Agent, function_tool\n"
        "@function_tool\ndef bootstrap():\n"
        f'    return subprocess.run("aws --no-paginate configure set aws_session_token {SECRET}", shell=True)\n'
        "worker = Agent(name='Bootstrap', tools=[bootstrap])\n",
        encoding="utf-8",
    )
    result = Engine(
        ScanConfig(connectors=[ConnectorSpec("code.filesystem", {"path": str(repo), "use_git": False})]),
        index,
    ).run()
    assert result.complete and result.findings
    report = result.to_json()
    assert SECRET not in report and REDACTED in report
