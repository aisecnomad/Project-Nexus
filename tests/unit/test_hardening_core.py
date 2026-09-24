"""Regressions for the production-review round: core model, engine, CLI, config and utilities."""

from __future__ import annotations

import json
import os
import threading
import time
from collections import Counter

import pytest
from click.testing import CliRunner

from shadowscan import cli as cli_module
from shadowscan.cli import main
from shadowscan.config import ConfigValidationError, ConnectorSpec, ScanConfig, validate_connector_timeout
from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.common import classify_permissions
from shadowscan.engine import Engine
from shadowscan.models import Evidence, Finding, Kind, ScanResult, ScanStats, Surface, now_iso
from shadowscan.registry import Inventory
from shadowscan.reporters.html import render_html
from shadowscan.signatures import SignatureIndex
from shadowscan.signatures.matcher import _SCAN_DEADLINE, MatchTimeoutError, pattern_timeout
from shadowscan.utils import redaction
from shadowscan.utils.http import HttpClient
from shadowscan.utils.text import parse_timestamp


def _finding(**kw) -> Finding:
    base = dict(
        surface=Surface.CLOUD, connector="cloud.aws", kind=Kind.AGENT, title="Bedrock Agent: ops",
        resource="arn:aws:bedrock:us-east-1:123456789012:agent/A1", resource_type="bedrock-agent",
    )
    base.update(kw)
    return Finding(**base)


# ------------------------------------------------------------------ models


def test_sanitize_skips_unchanged_state_but_catches_every_later_mutation():
    finding = _finding(evidence=[Evidence("signal", "clean", snippet="nothing here", weight=0.5)])
    digest = finding._clean_digest
    assert digest is not None
    finding.sanitize()
    assert finding._clean_digest == digest  # unchanged state is not re-sanitized
    finding.title = "leaked sk-proj-" + "a" * 40
    finding.evidence[0].snippet = "AKIA" + "A" * 16
    finding.metadata["note"] = "Authorization: Bearer abcdefghijklmnop"
    finding.sanitize()
    assert "sk-proj" not in finding.title and redaction.REDACTED in finding.title
    assert "AKIA" not in (finding.evidence[0].snippet or "")
    assert "abcdefghijklmnop" not in finding.metadata["note"]
    assert finding._clean_digest != digest


def test_report_serialization_hides_private_state_and_tolerates_newer_fields():
    finding = _finding(evidence=[Evidence("signal", "clean")])
    data = finding.to_dict()
    assert "_clean_digest" not in data
    assert "_clean_digest" not in json.dumps(ScanResult(findings=[finding]).to_dict())
    data["future_field"] = {"anything": 1}
    data["evidence"][0]["future_attribute"] = 2
    data["risk"]["factors"] = [{"id": "x", "description": "y", "weight": 1, "novel": True}]
    restored = Finding.from_dict(data)
    assert restored.id == finding.id and restored.risk.factors[0].id == "x"
    with pytest.raises(TypeError):
        Finding.from_dict("not an object")  # type: ignore[arg-type]


# --------------------------------------------------------------- redaction


def test_text_sanitizer_cache_is_transparent():
    assert redaction.sanitize_text("token=abcdefghijklmnop") == "token=" + redaction.REDACTED
    assert redaction.sanitize_text("token=abcdefghijklmnop") == "token=" + redaction.REDACTED
    assert redaction.sanitize_text("token=zzzzzzzzzzzzzzzz") == "token=" + redaction.REDACTED
    long_text = "x" * 2000 + " api_key=abcdefghijklmnop"
    assert redaction.sanitize_text(long_text).endswith("api_key=" + redaction.REDACTED)
    assert redaction._sensitive_key("API_KEY") and not redaction._sensitive_key("region")


def test_ssws_scheme_and_repr_escaped_values_are_redacted():
    assert "00abcdefghijklmnop" not in redaction.sanitize_text("Authorization: SSWS 00abcdefghijklmnop")
    secret = "00SuperSecretOktaApiToken123456\n"
    ctx = ConnectorContext(config={"token": secret})
    message = ctx.sanitize_message(f"InvalidHeader: Invalid leading whitespace in header value: {secret!r}")
    assert "SuperSecretOktaApiToken" not in message


@pytest.mark.parametrize("secret", [
    "pplx-" + "a" * 45, "gsk_" + "A" * 45, "xai-" + "b" * 64, "nvapi-" + "c" * 64, "r8_" + "d" * 32,
    "csk-" + "e" * 32, "tgp_v1_" + "f" * 32, "e2b_" + "0" * 40, "lsv2_pt_" + "a" * 32 + "_" + "b" * 10,
    "tvly-dev-" + "g" * 24, "pcsk_" + "h" * 24, "fc-" + "1" * 32, "app-" + "A" * 24, "sk-lf-" + "0" * 36,
])
def test_every_detectable_credential_format_is_redacted_by_the_text_sanitizer(secret):
    assert secret not in redaction.sanitize_text(f"value {secret} trailing")


def test_http_client_rejects_control_characters_in_headers_without_echoing_them():
    with pytest.raises(ValueError) as failure:
        HttpClient("https://example.com", headers={"Authorization": "SSWS 00SuperSecret\n"})
    assert "SuperSecret" not in str(failure.value)


# ------------------------------------------------------------------ config


def test_connector_timeout_validation():
    assert validate_connector_timeout(5) == 5.0
    for invalid in (0, -1, True, None, "fast", float("inf"), float("nan")):
        with pytest.raises(ConfigValidationError):
            validate_connector_timeout(invalid)
    assert ScanConfig.from_dict({"options": {"connector_timeout_seconds": 2}}).connector_timeout_seconds == 2.0
    with pytest.raises(ConfigValidationError):
        ScanConfig.from_dict({"options": {"connector_timeout_seconds": -1}})
    with pytest.raises(ConfigValidationError):
        ScanConfig.from_dict({"options": {"connector_deadline": 2}})


# ------------------------------------------------------------------ engine


@pytest.mark.parametrize("parallel", [1, 2])
def test_engine_abandons_a_connector_that_exceeds_its_deadline(monkeypatch, parallel):
    release = threading.Event()

    class Blocking:
        def __init__(self, ctx):
            self.ctx = ctx

        def run(self):
            release.wait(30)
            self.ctx.stats = ScanStats(connector="cloud.aws", started_at=now_iso(), finished_at=now_iso())
            return []

    class Quick:
        def __init__(self, ctx):
            self.ctx = ctx

        def run(self):
            self.ctx.stats = ScanStats(connector="code.filesystem", started_at=now_iso(), finished_at=now_iso())
            return [_finding(surface=Surface.CODE, connector="code.filesystem", kind=Kind.FRAMEWORK_USAGE,
                             resource="repo", resource_type="project")]

    monkeypatch.setattr("shadowscan.engine.get_connector_class", lambda name: {"cloud.aws": Blocking, "identity.okta": Quick}[name])
    cfg = ScanConfig(connectors=[ConnectorSpec("cloud.aws", label="slow"), ConnectorSpec("identity.okta", label="fast")],
                     parallel=parallel, connector_timeout_seconds=0.5)
    engine = Engine(cfg, SignatureIndex([]))
    try:
        started = time.monotonic()
        result = engine.run()
        assert time.monotonic() - started < 10
        # The blocked worker is reported so the CLI can exit without joining it.
        assert engine.abandoned_workers == ["slow"]
        by_connector = {s.connector: s for s in result.stats}
        assert by_connector["slow"].incomplete and "deadline exceeded" in by_connector["slow"].errors[0]
        fast = by_connector["fast"]
        if parallel == 2:
            assert fast.findings == 1 and len(result.findings) == 1
        else:
            # The only worker slot is still held by the timed-out call.
            assert fast.skipped and "no worker capacity" in (fast.skip_reason or "") and result.findings == []
        assert not result.complete
    finally:
        release.set()


def test_engine_loads_the_signature_index_once_for_the_first_run(monkeypatch):
    calls = []

    def counting_get_index(**kwargs):
        calls.append(kwargs)
        return SignatureIndex([])

    monkeypatch.setattr("shadowscan.engine.get_index", counting_get_index)
    engine = Engine(ScanConfig(connectors=[]))
    engine.run()
    assert len(calls) == 1
    engine.run()
    assert len(calls) == 2  # a reused Engine still notices pack edits between runs


# --------------------------------------------------------------------- cli


def test_cli_validates_connector_timeout_and_rejects_malformed_reports(tmp_path):
    runner = CliRunner()
    result = runner.invoke(main, ["run", "identity.jwt", "--connector-timeout-seconds", "0", "--set", "tokens=a.b.c"])
    assert result.exit_code == 2 and "connector_timeout_seconds" in result.output
    broken = tmp_path / "report.json"
    broken.write_text("{not json")
    out = tmp_path / "stubs"
    result = runner.invoke(main, ["inventory", "stubs", str(broken), "-o", str(out)])
    assert result.exit_code == 1 and "invalid inventory input" in result.output and "Traceback" not in result.output
    broken.write_text(json.dumps({"findings": [{"surface": "cloud"}]}))
    result = runner.invoke(main, ["inventory", "stubs", str(broken), "-o", str(out)])
    assert result.exit_code == 1 and "invalid inventory input" in result.output
    result = runner.invoke(main, ["diff", str(broken), str(broken)])
    assert result.exit_code == 1 and "Traceback" not in result.output


def test_cli_exits_without_joining_abandoned_workers(monkeypatch, tmp_path):
    exits = []

    class FakeEngine:
        def __init__(self, cfg, progress=None):
            self.abandoned_workers = ["slow"]

        def run(self, only=None):
            return ScanResult(stats=[ScanStats(connector="slow", started_at=now_iso(), finished_at=now_iso(),
                                               skipped=True, incomplete=True, errors=["timed out"])])

    def fake_exit(code):
        exits.append(code)
        raise SystemExit(code)

    monkeypatch.setattr(cli_module, "Engine", FakeEngine)
    monkeypatch.setattr(os, "_exit", fake_exit)
    result = CliRunner().invoke(main, ["run", "identity.jwt", "--set", "tokens=a.b.c", "--format", "json"])
    assert exits == [3] and result.exit_code == 3


# ----------------------------------------------------------------- matcher


def test_pattern_timeout_and_input_budget_respect_an_open_deadline(index):
    assert pattern_timeout(1.0) == 1.0
    with index.scan_budget(seconds=30):
        deadline = _SCAN_DEADLINE.get()
        assert 0.9 < pattern_timeout(1.0) <= 1.0
        with index._input_budget():
            assert _SCAN_DEADLINE.get() == deadline  # the default budget no longer shortens an explicit one
    token = _SCAN_DEADLINE.set(time.monotonic() - 1)
    try:
        with pytest.raises(MatchTimeoutError):
            pattern_timeout(1.0)
    finally:
        _SCAN_DEADLINE.reset(token)


def test_matcher_reports_line_numbers_from_the_newline_index(index):
    text = "\n".join(["x = 1"] * 50 + ["from langchain.agents import AgentExecutor"])
    assert any(m.line == 51 for m in index.match_imports(text, "python"))


def test_classify_permissions_orders_set_input_deterministically(index):
    finding = _finding()
    classify_permissions(index, finding, {"Mail.Read", "User.Read", "Calendars.Read", "offline_access"})
    assert finding.permissions == sorted(finding.permissions)


def test_inventory_name_patterns_are_compiled_once(tmp_path):
    (tmp_path / "agents.yaml").write_text("agents:\n  - id: reviewer\n    names: [coderabbitai]\n    resources: ['x:*']\n")
    inventory = Inventory.load([str(tmp_path)])
    for _ in range(3):
        assert inventory.suggest(_finding(title="Slack app: CodeRabbitAI", resource="slack:app:1"))
    assert set(inventory._name_patterns) == {"reviewer", "coderabbitai"}


def test_html_report_forbids_network_access():
    html = render_html(ScanResult(findings=[_finding()]))
    assert "Content-Security-Policy" in html and "default-src 'none'" in html and "no-referrer" in html


def test_parse_timestamp_numeric_hygiene():
    assert parse_timestamp(10**400) is None
    assert parse_timestamp("1" * 5000) is None
    assert parse_timestamp(True) is None
    assert parse_timestamp(float("nan")) is None
    assert parse_timestamp("1700000000.123").microsecond == 123000
    assert parse_timestamp("1700000000").year == 2023
    assert parse_timestamp(1700000000123).year == 2023


def test_counter_helper_is_importable_for_reports():
    # Guard against the gateway helper drifting into a different module.
    from shadowscan.connectors.gateway.logs import _MAX_DISTINCT_KEYS, _count

    counter: Counter = Counter()
    for i in range(_MAX_DISTINCT_KEYS + 5):
        _count(counter, f"key-{i}", 1)
    assert len(counter) == _MAX_DISTINCT_KEYS + 1 and counter["<other>"] == 5
