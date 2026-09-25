"""Precision safeguards: placeholder credentials, derivative usage findings,
environment-name saturation, vendor-neutral heuristics, MCP capabilities and
the gateway temporal signal.
"""

from __future__ import annotations

import hashlib
import json
import random
import string
from pathlib import Path

import pytest

from shadowscan.connectors.cloud.common import scan_env
from shadowscan.connectors.common import (
    apply_matches,
    blob_matches,
    cap_confidence,
    finalize,
    looks_like_placeholder,
    placeholder_reason,
)
from shadowscan.models import Evidence, Finding, Kind, Likelihood, Surface
from shadowscan.risk import CAPABILITY_WEIGHTS, assess
from shadowscan.signatures import Match, Signal, Signature
from tools.evaluation.evaluate import DEFAULT_CORPUS, evaluate

# Random-looking synthetic values; they are not credentials for any service.
SYNTHETIC_OPENAI_KEY = "sk-proj-kLKFlNfzW2mTofMpnx1qOu7fTm9F8IRv6iKzoC2h"
SYNTHETIC_GITHUB_TOKEN = "ghp_Cf85qKYbxE5f5FdUlWJLY8mYNi2TZf50hya5"
PLACEHOLDER_ANTHROPIC_KEY = "sk-ant-api03-REPLACE_ME_WITH_REAL_KEY"
PROVIDER_ENV_NAMES = [
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "MISTRAL_API_KEY", "COHERE_API_KEY", "GROQ_API_KEY",
    "TOGETHER_API_KEY", "FIREWORKS_API_KEY", "OPENROUTER_API_KEY", "DEEPSEEK_API_KEY", "XAI_API_KEY", "PERPLEXITY_API_KEY",
]
HEURISTIC_ONLY_SOURCE = (
    "import subprocess\n\n"
    "while True:\n"
    "    supervisor = get_supervisor()\n"
    "    subprocess.run(cmd, check=True)\n"
    "    execute_command(handoff, dry_run=False, unattended=True)\n"
)


def _project(findings):
    return next((f for f in findings if f.resource_type == "project"), None)


def _finding(**kwargs) -> Finding:
    return Finding(surface=Surface.CODE, connector="test", kind=Kind.FRAMEWORK_USAGE, title="t",
                   resource="repo", resource_type="project", **kwargs)


# ------------------------------------------------------------- placeholders
@pytest.mark.parametrize("value, reason", [
    (PLACEHOLDER_ANTHROPIC_KEY, "placeholder-word"),
    ("sk-proj-PLACEHOLDERpUdqnr1cfLxYE5WueqDoGMF2D4CB97", "placeholder-word"),
    ("sk-proj-YourKeyHere" + "q7Lm3Xz9" * 4, "placeholder-word"),
    ("sk-proj-YOURKEYHERE1234567890123456789012345", "placeholder-word"),
    ("sk-proj-your_openai_key_goes_here_1234567890ab", "placeholder-word"),
    ("ghp_EXAMPLE0000000000000000000000000000", "placeholder-word"),
    ("sk-proj-" + "x" * 40, "placeholder-word"),
    ("sk-proj-Crc02JkJzPUMAhGr0lDZ-TEST-HKAGp2hVbFoYL8sAgiCi", "placeholder-word"),
    ("sk-proj-dummyvalueH5tyKbgZMTpFuWSUSzxGajsbgRsMn7", "placeholder-word"),
    ("sk-proj-" + "b" * 40, "low-entropy"),
    ("sk-proj-" + "0" * 40, "low-entropy"),
    ("sk-proj-0000-0000-0000-0000-0000-0000-0000-0000", "low-entropy"),
    ("sk-proj-" + "1234567890" * 4, "low-entropy"),
    ("sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN", "low-entropy"),
    ("sk-proj-1234567890abcdef1234567890abcdef", "low-entropy"),
    ("AIza" + "0" * 35, "low-entropy"),
    ("hf_" + "a" * 34, "low-entropy"),
    ("sk-proj-<your-key>", "template"),
    ("${OPENAI_API_KEY}", "template"),
    ("{{ secrets.OPENAI_API_KEY }}", "template"),
    ("changeme", "template"),
    ("xxxxxxxx", "template"),
])
def test_placeholder_reason_recognises_documentation_samples(value, reason):
    assert placeholder_reason(value) == reason
    assert looks_like_placeholder(value)


@pytest.mark.parametrize("value", [
    SYNTHETIC_OPENAI_KEY,
    SYNTHETIC_GITHUB_TOKEN,
    "sk-proj-3OoFmQTsHfOvesPLUXvRXpfToFF2XPOcdJ2kMQJ2g0",
    "sk-ant-api03-6cH3uWOWa4kNYqST0kQrUnYKWYg3BbZ4Tg2XxyRRBIGPepmhEU-FrMwGYwsaVeZAA",
    "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",
    # Derived at runtime from a digest so no secret-shaped literal sits in the source.
    "lsv2_pt_" + hashlib.sha256(b"langsmith-sample-body").hexdigest()[:32] + "_" + hashlib.sha256(b"langsmith-sample-suffix").hexdigest()[:10],
    "sk-or-v1-" + hashlib.sha256(b"openrouter-sample").hexdigest(),
    "sk-proj-syntheticcredentialvaluenotarealkey",
    "opaque-synthetic-credential-value",
    "SG.opaque-value-1234567890",
    "",
])
def test_placeholder_heuristic_keeps_real_looking_values(value):
    assert placeholder_reason(value) is None
    assert not looks_like_placeholder(value)


def test_placeholder_heuristic_does_not_suppress_random_keys():
    rng = random.Random(20260924)
    alphabet = string.ascii_letters + string.digits
    flagged = [
        key for key in (
            "sk-proj-" + "".join(rng.choice(alphabet) for _ in range(rng.choice([32, 48, 64])))
            for _ in range(1000)
        ) if looks_like_placeholder(key)
    ]
    assert flagged == []


def test_env_sample_placeholder_is_example_credential_not_secret(tmp_path: Path, run_connector, index):
    (tmp_path / ".env.sample").write_text(
        f"ANTHROPIC_API_KEY={PLACEHOLDER_ANTHROPIC_KEY}\nOPENAI_API_KEY=sk-proj-{'x' * 40}\n"
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path))
    assert not ctx.stats.errors
    assert not any(f.kind == Kind.SECRET for f in findings)
    project = _project(findings)
    assert project is not None and project.kind == Kind.FRAMEWORK_USAGE
    assert "example-credential" in project.tags
    examples = [e for e in project.evidence if e.signal.startswith("example-credential:")]
    assert {e.signal for e in examples} == {"example-credential:provider.anthropic", "example-credential:provider.openai"}
    for e in examples:
        assert e.weight == 0.1 and e.attributes["placeholder"] == "placeholder-word"
        assert "REPLACE_ME" not in e.description and "xxxx" not in e.description
        assert e.location.startswith(".env.sample:")
    assert project.metadata["placeholder_samples"] == {"count": 2, "files": [".env.sample"]}
    # The env names still say "likely LLM usage"; the sample keys add nothing that alarms.
    assert project.likelihood != Likelihood.CONFIRMED
    assert "hardcoded-credential" not in project.tags
    assert assess(project, index).score < 50


def test_marker_words_outside_the_matched_key_do_not_hide_real_keys(tmp_path: Path, run_connector):
    (tmp_path / "config.py").write_text(f'OPENAI_API_KEY = "{SYNTHETIC_OPENAI_KEY}"  # TODO rotate this example\n')
    (tmp_path / ".env").write_text(f"OPENAI_API_KEY={SYNTHETIC_OPENAI_KEY} # replace me later\n")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path))
    assert not ctx.stats.errors
    secrets = {f.metadata["path"]: f for f in findings if f.kind == Kind.SECRET}
    assert set(secrets) == {"config.py", ".env"}
    assert all(f.metadata["count"] == 1 and "provider.openai" in f.model_providers for f in secrets.values())
    assert not any("example-credential" in f.tags for f in findings)


def test_placeholder_token_in_mcp_config_is_not_an_inline_secret(tmp_path: Path, run_connector):
    def scan(token: str):
        (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"github": {
            "command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"],
            "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": token},
        }}}))
        findings, _ = run_connector("code.filesystem", path=str(tmp_path))
        return next(f for f in findings if f.kind == Kind.MCP_SERVER)

    sample = scan("ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
    assert sample.metadata["servers"][0]["secrets_inline"] is False and "inline-secrets" not in sample.tags
    real = scan(SYNTHETIC_GITHUB_TOKEN)
    assert real.metadata["servers"][0]["secrets_inline"] is True and "inline-secrets" in real.tags


def test_cloud_env_scan_judges_each_matched_key(index):
    finding = _finding()
    scan_env(index, finding, {"OPENAI_API_KEY": PLACEHOLDER_ANTHROPIC_KEY, "ANTHROPIC_API_KEY": "sk-ant-api03-" + "0" * 40})
    assert "plaintext-credential" not in finding.tags and "secret-in-env" not in finding.tags
    finding = _finding()
    scan_env(index, finding, {"OPENAI_BASE_URL": f"https://test.example.com/v1?api_key={SYNTHETIC_OPENAI_KEY}"})
    assert "plaintext-credential" in finding.tags
    assert all(SYNTHETIC_OPENAI_KEY not in e.description for e in finding.evidence)


def test_blob_matches_skip_placeholder_secrets(index):
    assert not [m for m in blob_matches(index, f"key: {PLACEHOLDER_ANTHROPIC_KEY}", secrets=True) if m.signal.type == "secret"]
    assert [m for m in blob_matches(index, f"key: {SYNTHETIC_OPENAI_KEY}", secrets=True) if m.signal.type == "secret"]


# ------------------------------------------------ derivative usage findings
def test_secret_alone_does_not_establish_llm_usage(tmp_path: Path, run_connector):
    (tmp_path / "README.md").write_text(f"# Demo\nExport your key before running: {SYNTHETIC_OPENAI_KEY}\n")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path))
    assert not ctx.stats.errors
    assert [f.kind for f in findings] == [Kind.SECRET]
    assert _project(findings) is None
    # With any other technology observation the credential joins the project evidence.
    (tmp_path / "requirements.txt").write_text("openai>=1.0\n")
    findings, _ = run_connector("code.filesystem", path=str(tmp_path))
    project = _project(findings)
    assert project is not None and "provider.openai" in project.model_providers
    assert any(e.signal == "secret:provider.openai" for e in project.evidence)


# -------------------------------------------------- environment-name saturation
def test_env_names_only_stay_below_confirmed(tmp_path: Path, run_connector):
    (tmp_path / ".env.example").write_text("".join(f"{name}=\n" for name in PROVIDER_ENV_NAMES[:3]))
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path))
    assert not ctx.stats.errors
    project = _project(findings)
    assert project is not None and project.kind == Kind.FRAMEWORK_USAGE
    assert "env-names-only" in project.tags
    assert project.likelihood == Likelihood.LIKELY and project.confidence < 0.85
    assert all(e.weight == pytest.approx(0.3) for e in project.evidence)
    assert project.title == "LLM usage in repository root: OpenAI, Anthropic, Google Gemini API (AI Studio)"

    (tmp_path / ".env.example").write_text("".join(f"{name}=\n" for name in PROVIDER_ENV_NAMES))
    findings, _ = run_connector("code.filesystem", path=str(tmp_path))
    project = _project(findings)
    assert project is not None and len(project.evidence) >= 10
    assert project.likelihood == Likelihood.LIKELY and project.confidence <= 0.8
    assert project.metadata["confidence_cap"] == {"reason": "env-names-only", "maximum": 0.8}
    project.recompute_confidence()  # the cap lives in the evidence, so recomputation keeps it
    assert project.likelihood == Likelihood.LIKELY

    (tmp_path / "app.py").write_text("import openai\nclient = openai.OpenAI()\n")
    findings, _ = run_connector("code.filesystem", path=str(tmp_path))
    project = _project(findings)
    assert project is not None and "env-names-only" not in project.tags and "confidence_cap" not in project.metadata
    assert project.likelihood == Likelihood.CONFIRMED


def test_evidence_per_signature_is_capped_before_confidence_is_computed():
    signal = Signal(type="env", weight=0.6, names=["TEST_KEY"])
    signature = Signature(id="provider.test", name="Test", category="provider", signals=[signal])
    finding = _finding()
    indicators = apply_matches(finding, [Match(signature, signal, f"TEST_KEY_{i}", 0.6) for i in range(30)])
    assert indicators == 0 and len(finding.evidence) == 12
    finalize(finding)
    assert finding.metadata["evidence_counts"] == {"provider.test|env": 30}
    assert finding.confidence == round(1 - 0.4 ** 12, 3)


def test_cap_confidence_rescales_evidence_and_survives_recomputation():
    finding = _finding(evidence=[Evidence(signal=f"env:{i}", description="x", weight=0.3) for i in range(12)])
    finding.recompute_confidence()
    assert finding.confidence > 0.95
    cap_confidence(finding, 0.8)
    assert 0.79 <= finding.confidence <= 0.8 and finding.likelihood == Likelihood.LIKELY
    assert all(0 < e.weight < 0.3 for e in finding.evidence)
    finding.recompute_confidence()
    assert finding.confidence <= 0.8
    untouched = _finding(evidence=[Evidence(signal="env:a", description="x", weight=0.3)])
    cap_confidence(untouched, 0.8)
    assert untouched.evidence[0].weight == 0.3 and untouched.confidence == 0.3


# ------------------------------------------------------ heuristics alone
def test_vendor_neutral_heuristics_alone_are_not_an_agent(tmp_path: Path, run_connector):
    (tmp_path / "deploy.py").write_text(HEURISTIC_ONLY_SOURCE)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path))
    assert not ctx.stats.errors and findings == []
    (tmp_path / "agent.py").write_text("from langgraph.graph import StateGraph\ngraph = StateGraph(dict)\n")
    findings, _ = run_connector("code.filesystem", path=str(tmp_path))
    project = _project(findings)
    assert project is not None and project.kind == Kind.AGENT and "framework.langgraph" in project.frameworks
    assert {"code-exec", "autonomous"} <= set(project.capabilities)
    assert any(e.signal == "code:heuristic.code-execution" and e.location.startswith("deploy.py:") for e in project.evidence)


def test_heuristics_with_only_a_secret_are_dropped(tmp_path: Path, run_connector):
    (tmp_path / "deploy.py").write_text(HEURISTIC_ONLY_SOURCE + f'KEY = "{SYNTHETIC_OPENAI_KEY}"\n')
    findings, _ = run_connector("code.filesystem", path=str(tmp_path))
    assert [f.kind for f in findings] == [Kind.SECRET]


def test_heuristics_next_to_env_names_only_do_not_make_an_agent(tmp_path: Path, run_connector, index):
    (tmp_path / ".env.example").write_text("OPENAI_API_KEY=\n")
    (tmp_path / "deploy.py").write_text(HEURISTIC_ONLY_SOURCE)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path))
    assert not ctx.stats.errors
    assert not any(f.kind == Kind.AGENT for f in findings)
    project = _project(findings)
    assert project is not None and project.kind == Kind.FRAMEWORK_USAGE
    assert "env-names-only" in project.tags
    assert project.metadata["confidence_cap"] == {"reason": "env-names-only", "maximum": 0.8}
    assert project.confidence <= 0.8 and project.likelihood != Likelihood.CONFIRMED
    assert not {"autonomous", "code-exec"} & set(project.capabilities)
    assert project.metadata["agent_indicators"] == 0
    # The finding is built from the name references alone: no heuristic evidence, no deploy.py.
    assert {e.signal for e in project.evidence} == {"env:provider.openai"}
    assert all(e.weight == pytest.approx(0.3) and e.location.startswith(".env.example:") for e in project.evidence)
    assert project.title == "LLM usage in repository root: OpenAI"
    assert assess(project, index).score < 50

    # An import anchors the provider, so the idioms are recorded again as
    # supporting evidence with full weights. Vendor-neutral loops and
    # subprocess calls still cannot confirm an agent on their own.
    (tmp_path / "app.py").write_text("from openai import OpenAI\n")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path))
    assert not ctx.stats.errors
    project = _project(findings)
    assert project is not None and project.kind == Kind.FRAMEWORK_USAGE
    assert "env-names-only" not in project.tags and "confidence_cap" not in project.metadata
    assert {"autonomous", "code-exec"} <= set(project.capabilities)
    assert project.metadata["agent_indicators"] == 0
    assert any(e.signal == "import:provider.openai" and e.location.startswith("app.py:") for e in project.evidence)
    assert any(e.signal == "code:heuristic.code-execution" and e.location.startswith("deploy.py:") for e in project.evidence)


def test_env_names_only_keeps_generic_llm_env_names(tmp_path: Path, run_connector):
    (tmp_path / ".env.example").write_text("OPENAI_API_KEY=\nLLM_MODEL=\n")
    (tmp_path / "deploy.py").write_text(HEURISTIC_ONLY_SOURCE)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path))
    assert not ctx.stats.errors
    project = _project(findings)
    assert project is not None and project.kind == Kind.FRAMEWORK_USAGE and "env-names-only" in project.tags
    # A generic LLM_* name is itself a name reference; only the heuristic code idioms are dropped.
    assert {e.signal for e in project.evidence} == {"env:provider.openai", "env:heuristic.llm-env-names"}
    assert not project.capabilities and project.metadata["agent_indicators"] == 0


def test_live_credential_is_not_an_env_name_only_anchor(tmp_path: Path, run_connector):
    (tmp_path / ".env").write_text(f"OPENAI_API_KEY={SYNTHETIC_OPENAI_KEY}\n")
    (tmp_path / "deploy.py").write_text(HEURISTIC_ONLY_SOURCE)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path))
    assert not ctx.stats.errors
    assert any(f.kind == Kind.SECRET for f in findings)
    project = _project(findings)
    assert project is not None and "env-names-only" not in project.tags and "confidence_cap" not in project.metadata
    assert any(e.signal == "secret:provider.openai" for e in project.evidence)
    # Full weights and heuristic capabilities are kept, but generic idioms never confirm an agent.
    assert project.kind == Kind.FRAMEWORK_USAGE and {"autonomous", "code-exec"} <= set(project.capabilities)
    assert project.metadata["agent_indicators"] == 0


# ------------------------------------------------------ MCP capabilities
def test_mcp_servers_map_to_data_access_browsing_and_code_exec(tmp_path: Path, run_connector, index):
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {
        "files": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/srv"]},
        "db": {"command": "uvx", "args": ["mcp-server-sqlite", "--db-path", "app.db"]},
        "web": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-puppeteer"]},
        "gh": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]},
        "sh": {"command": "npx", "args": ["-y", "mcp-shell"]},
    }}))
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path))
    assert not ctx.stats.errors
    mcp = next(f for f in findings if f.kind == Kind.MCP_SERVER)
    assert {"tool-use", "data-access", "browsing", "saas-actions", "code-exec"} <= set(mcp.capabilities)
    assert CAPABILITY_WEIGHTS["data-access"][0] == CAPABILITY_WEIGHTS["saas-actions"][0]
    assert any(factor.id == "capability:data-access" for factor in assess(mcp, index).factors)


# ----------------------------------------------------- gateway temporal signal
def _gateway_records(caller: dict, *, tools: bool = False, user_agent: str = "OpenAI/Python 1.51.0") -> list[dict]:
    records = []
    for day in range(3):
        for hour in range(24):
            record = {**caller, "model": "gpt-4o", "user_agent": user_agent,
                      "timestamp": f"2026-09-{5 + day:02d}T{hour:02d}:15:00Z"}
            if tools:
                record["request"] = {"tools": [{"type": "function", "function": {"name": "search"}}]}
            records.append(record)
    return records


def _scan_gateway(tmp_path: Path, run_connector, records: list[dict]) -> Finding:
    path = tmp_path / "gateway.jsonl"
    path.write_text("".join(json.dumps(record) + "\n" for record in records))
    findings, ctx = run_connector("gateway.logs", input=str(path))
    assert not ctx.stats.errors and len(findings) == 1
    return findings[0]


def test_round_the_clock_human_caller_is_not_agentic(tmp_path: Path, run_connector):
    finding = _scan_gateway(tmp_path, run_connector, _gateway_records({"api_key": "hashed-key-alice", "user": "alice@acme.com"}))
    assert finding.title.startswith("LLM caller")
    assert "always-on" in finding.tags and "autonomous" not in finding.capabilities
    assert finding.metadata["agent_indicators"] == 0
    assert finding.metadata["activity"]["always_on"] is True and finding.metadata["activity"]["always_on_corroborated"] is False
    always_on = next(e for e in finding.evidence if e.signal == "gateway:always-on")
    assert always_on.weight == 0.3 and "without tool use" in always_on.description


@pytest.mark.parametrize("caller, kwargs", [
    ({"api_key": "hashed-key-alice", "user": "alice@acme.com"}, {"tools": True}),
    ({"api_key": "hashed-key-alice", "user": "alice@acme.com"}, {"user_agent": "langchain/0.3.1 OpenAI/Python 1.51.0"}),
    ({"api_key": "hashed-key-batch"}, {}),
    ({"service": "nightly-summariser", "user": "svc@acme.com"}, {}),
])
def test_corroborated_round_the_clock_callers_are_agentic(tmp_path: Path, run_connector, caller, kwargs):
    finding = _scan_gateway(tmp_path, run_connector, _gateway_records(caller, **kwargs))
    assert finding.title.startswith("Agentic caller")
    assert "always-on" in finding.tags and "autonomous" in finding.capabilities
    assert finding.metadata["agent_indicators"] >= 1
    assert finding.metadata["activity"]["always_on_corroborated"] is True
    assert next(e for e in finding.evidence if e.signal == "gateway:always-on").weight == 0.5


def test_business_hours_caller_has_no_temporal_signal(tmp_path: Path, run_connector):
    records = [r for r in _gateway_records({"api_key": "hashed-key-batch"}) if 9 <= int(r["timestamp"][11:13]) < 17]
    records = records * 3  # keep at least 50 timestamped events
    finding = _scan_gateway(tmp_path, run_connector, records)
    assert "always-on" not in finding.tags and finding.metadata["activity"]["always_on"] is False
    assert finding.title.startswith("LLM caller")


# ---------------------------------------------------------------- corpus
def test_bundled_corpus_covers_precision_regressions():
    report = evaluate(DEFAULT_CORPUS)
    rows = {row["id"]: row for row in report["cases"]}
    expected = {
        "env-sample-placeholder-key": False,
        "config-hardcoded-key": True,
        "readme-key-only-usage": False,
        "env-names-only-usage": True,
        "devops-heuristics-only-agent": False,
        "devops-heuristics-only-usage": False,
        "py-langgraph-agent-with-heuristics": True,
        "env-names-with-heuristics-agent": False,
        "env-names-import-with-heuristics-agent": True,
    }
    for case_id, present in expected.items():
        assert rows[case_id]["present"] is present and rows[case_id]["predicted"] is present, case_id
        assert rows[case_id]["correct"], rows[case_id]["assertion_failures"]
    assert 0.6 <= rows["env-names-only-usage"]["score"] < 0.85
    assert max(f["confidence"] for f in rows["env-names-with-heuristics-agent"]["findings"]) <= 0.8
    assert report["passed"]
