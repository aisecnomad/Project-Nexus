"""Opt-in LLM triage (shadowscan.triage): off by default, redacted, advisory."""

from __future__ import annotations

import json

import pytest

from shadowscan.config import ConfigValidationError, ScanConfig
from shadowscan.engine import Engine
from shadowscan.models import Evidence, Finding, Kind, Risk, RiskLevel, Surface
from shadowscan.triage import (
    Triage,
    TriageConfigError,
    TriageSettings,
    finding_summary,
    parse_reply,
    select,
)
from shadowscan.utils.http import HttpError

TOKEN = "sk-ant-api03-" + "B" * 93 + "AA"


def _finding(fid: str, score: int, level: RiskLevel) -> Finding:
    f = Finding(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.AGENT,
        title=f"Agent {fid}",
        resource=f"github:acme/{fid}",
        resource_type="project",
        owner="dana@acme.example",
        account="acme",
        frameworks=["framework.langgraph"],
        capabilities=["tool-use"],
    )
    f.id = fid
    f.risk = Risk(score=score, level=level)
    f.evidence.append(
        Evidence(
            signal="code:framework.langgraph",
            description=f"StateGraph with tools; key {TOKEN}",
            location="src/agent.py:12",
            snippet="graph = StateGraph(State)",
            weight=0.9,
        )
    )
    return f


class FakeClient:
    def __init__(self, replies):
        self.replies = list(replies)
        self.requests = []

    def post_json(self, path, *, json):
        self.requests.append((path, json))
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply


def _anthropic(text: str) -> dict:
    return {"content": [{"type": "text", "text": text}]}


def test_disabled_by_default():
    assert TriageSettings.from_options(None).enabled is False
    assert ScanConfig().llm_triage.enabled is False
    with pytest.raises(TriageConfigError):
        Triage(TriageSettings())


@pytest.mark.parametrize(
    "options",
    [
        "yes",
        {"enabled": "true", "model": "m"},
        {"enabled": True},
        {"enabled": True, "model": "m", "provider": "other"},
        {"enabled": True, "model": "m", "api_key": "secret"},
        {"enabled": True, "model": "m", "base_url": "http://gateway.internal"},
        {"enabled": True, "model": "m", "api_key_env": "BAD NAME"},
        {"enabled": True, "model": "m", "max_findings": 0},
        {"enabled": True, "model": "m", "max_findings": True},
        {"enabled": True, "model": "m", "min_level": "severe"},
        {"enabled": True, "model": "m", "timeout_seconds": 0},
        {"enabled": True, "model": "m", "colour": "blue"},
    ],
)
def test_invalid_settings_are_refused(options):
    with pytest.raises(TriageConfigError):
        TriageSettings.from_options(options)


def test_settings_reach_scan_config(tmp_path):
    path = tmp_path / "scan.yaml"
    path.write_text(
        "options:\n  llm_triage:\n    enabled: true\n    model: some-model\n    provider: openai\n"
    )
    settings = ScanConfig.from_yaml(path).llm_triage
    assert (settings.enabled, settings.provider, settings.api_key_env) == (True, "openai", "OPENAI_API_KEY")
    path.write_text("options:\n  llm_triage:\n    enabled: true\n    model: m\n    api_key: x\n")
    with pytest.raises(ConfigValidationError, match="api_key_env"):
        ScanConfig.from_yaml(path)


def test_summary_is_redacted_and_omits_identifiers(index):
    summary = finding_summary(_finding("ss-1", 70, RiskLevel.HIGH), index)
    text = json.dumps(summary)
    assert TOKEN not in text
    for withheld in ("github:acme/ss-1", "dana@acme.example", "src/agent.py", "StateGraph(State)"):
        assert withheld not in text
    assert summary["technologies"] == ["LangGraph"] and summary["heuristic_risk"] == "high"


def test_selection_order_and_floor():
    findings = [
        _finding("a", 40, RiskLevel.MEDIUM),
        _finding("b", 90, RiskLevel.CRITICAL),
        _finding("c", 10, RiskLevel.LOW),
        _finding("d", 90, RiskLevel.CRITICAL),
    ]
    settings = TriageSettings(enabled=True, model="m", max_findings=2, min_level="medium")
    assert [f.id for f in select(findings, settings)] == ["b", "d"]


@pytest.mark.parametrize(
    ("text", "verdict"),
    [
        (
            '{"verdict": "likely-agent", "rationale": "uses tools", "suggested_action": "register"}',
            "likely-agent",
        ),
        ('Sure! ```json\n{"verdict": "uncertain"}\n```', "uncertain"),
        ('{"verdict": "delete everything"}', None),
        ("no json here", None),
        ("{not json}", None),
        ('["likely-agent"]', None),
    ],
)
def test_parse_reply(text, verdict):
    reply = parse_reply(text)
    assert (reply or {}).get("verdict") == verdict


def test_run_records_advisory_verdicts_without_changing_scores(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    findings = [_finding("hi", 80, RiskLevel.HIGH), _finding("mid", 50, RiskLevel.MEDIUM)]
    settings = TriageSettings.from_options({"enabled": True, "model": "some-model"})
    client = FakeClient(
        [
            _anthropic(
                '{"verdict": "likely-agent", "rationale": "' + "x" * 900 + '", "suggested_action": "own it"}'
            ),
            _anthropic("I cannot help with that"),
        ]
    )
    warnings = Triage(settings, client=client).run(findings)
    assert warnings == ["llm triage: 1 finding(s) without a usable verdict"]
    hi, mid = findings
    assert hi.metadata["llm_triage"]["verdict"] == "likely-agent" and hi.metadata["llm_triage"]["advisory"]
    assert len(hi.metadata["llm_triage"]["rationale"]) == 500
    assert mid.metadata["llm_triage"] == {"status": "unparseable", "advisory": True}
    assert (hi.risk.score, hi.kind, hi.shadow) == (80, Kind.AGENT, None)
    path, payload = client.requests[0]
    assert path == "/v1/messages" and payload["model"] == "some-model"
    assert "untrusted" in payload["system"] and TOKEN not in json.dumps(payload)


def test_openai_provider_and_request_failures(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    settings = TriageSettings.from_options({"enabled": True, "model": "m", "provider": "openai"})
    reply = {"choices": [{"message": {"content": '{"verdict": "likely-benign"}'}}]}
    findings = [_finding(str(i), 90 - i, RiskLevel.HIGH) for i in range(3)]
    client = FakeClient(
        [reply, HttpError(429, "https://api.openai.com/v1/chat/completions"), {"choices": []}]
    )
    warnings = Triage(settings, client=client).run(findings)
    assert findings[0].metadata["llm_triage"]["verdict"] == "likely-benign"
    assert findings[1].metadata["llm_triage"]["status"] == "failed"
    assert findings[2].metadata["llm_triage"]["status"] == "unparseable"
    assert warnings[0].startswith("llm triage request failed (HttpError)")
    assert client.requests[0][0] == "/chat/completions"
    assert client.requests[0][1]["messages"][0]["role"] == "system"


def test_missing_api_key_is_refused(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(TriageConfigError, match="ANTHROPIC_API_KEY"):
        Triage(TriageSettings.from_options({"enabled": True, "model": "m"}))


def test_engine_runs_triage_only_when_enabled(monkeypatch, index, tmp_path):
    calls = []

    class Recorder:
        def __init__(self, settings, index=None, **kwargs):
            calls.append(settings)

        def run(self, findings):
            for f in findings:
                f.metadata["llm_triage"] = {"status": "ok", "advisory": True}
            return ["llm triage: 1 finding(s) without a usable verdict"]

    import shadowscan.engine as engine_module

    monkeypatch.setattr(engine_module, "Triage", Recorder)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("langgraph==0.2.0\n")
    spec = {"connectors": [{"name": "code.filesystem", "path": str(repo), "use_git": False}]}
    plain = Engine(ScanConfig.from_dict(spec), index).run()
    assert not calls and all("llm_triage" not in f.metadata for f in plain.findings)

    spec["options"] = {"llm_triage": {"enabled": True, "model": "m", "min_level": "info"}}
    triaged = Engine(ScanConfig.from_dict(spec), index).run()
    assert len(calls) == 1 and triaged.complete
    assert all(f.metadata["llm_triage"]["advisory"] for f in triaged.findings)
    entry = next(s for s in triaged.stats if s.connector == "engine.llm-triage")
    assert entry.warnings and not entry.incomplete
