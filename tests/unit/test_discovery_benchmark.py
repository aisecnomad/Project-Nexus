"""Unit tests for the shadow AI discovery benchmark harness (tools/discovery_benchmark)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from tools.discovery_benchmark import compare, evidence, report, score, taxonomy
from tools.discovery_benchmark.adapters import Command, ToolConfig, facts_from_purl
from tools.discovery_benchmark.adapters.agentdiscover import AgentDiscoverAdapter
from tools.discovery_benchmark.adapters.agentic_radar import AgenticRadarAdapter
from tools.discovery_benchmark.adapters.cdxgen import CdxgenAdapter
from tools.discovery_benchmark.adapters.geiger import GeigerAdapter
from tools.discovery_benchmark.adapters.nuguard import NuGuardAdapter
from tools.discovery_benchmark.adapters.registry import all_adapters
from tools.discovery_benchmark.adapters.shadowscan import ShadowScanAdapter
from tools.discovery_benchmark.adapters.trusera_ai_bom import TruseraAdapter
from tools.discovery_benchmark.adapters.vet import VetAdapter
from tools.discovery_benchmark.adapters.xbom import XbomAdapter
from tools.discovery_benchmark.corpus import (
    Corpus,
    CorpusError,
    Expected,
    Repo,
    corpus_from_dict,
    load_corpus,
    save_corpus,
)
from tools.discovery_benchmark.runner import RunPolicy, _wrap, run_pair, scrubbed_env

SHA = "0" * 40


# --- taxonomy -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("ecosystem", "name", "expected"),
    [
        ("pypi", "langchain-openai>=0.2", {"framework:langchain", "provider:openai"}),
        ("pypi", "LangChain_Core", {"framework:langchain"}),
        ("pypi", "crewai[tools]", {"framework:crewai"}),
        ("pypi", "requests", set()),
        ("npm", "@ai-sdk/openai", {"framework:vercel-ai", "provider:openai"}),
        ("npm", "ai", {"framework:vercel-ai"}),
        ("npm", "@langchain/core", {"framework:langchain"}),
        ("jsimport", "@langchain/langgraph/prebuilt", {"framework:langgraph"}),
        ("jsimport", "openai/helpers/zod", {"provider:openai"}),
        ("goimport", "github.com/mark3labs/mcp-go/server", {"mcp:sdk"}),
        (
            "maven",
            "org.springframework.ai:spring-ai-starter-model-openai",
            {"framework:spring-ai", "provider:openai"},
        ),
        ("maven", "dev.langchain4j:langchain4j-anthropic", {"framework:langchain4j", "provider:anthropic"}),
        (
            "nuget",
            "Microsoft.SemanticKernel.Connectors.OpenAI",
            {"framework:semantic-kernel", "provider:openai"},
        ),
        ("cargo", "rig-core", {"framework:rig"}),
        ("pyimport", "google.genai", {"provider:google-gemini"}),
        ("pyimport", "google.adk.agents", {"framework:google-adk"}),
        ("csimport", "Microsoft.Extensions.AI", {"framework:microsoft-extensions-ai"}),
        ("rsimport", "rmcp::ServerHandler", {"mcp:sdk"}),
        ("pypi", "ag-ui-protocol", {"framework:copilotkit"}),
    ],
)
def test_facts_for(ecosystem: str, name: str, expected: set[str]) -> None:
    assert set(taxonomy.facts_for(ecosystem, name)) == expected


def test_facts_from_name_consumes_specific_aliases_first() -> None:
    assert taxonomy.facts_from_name("LangChain4j OpenAI") == {"framework:langchain4j", "provider:openai"}
    assert "framework:langchain" not in taxonomy.facts_from_name("langchain4j")
    assert taxonomy.facts_from_name("Azure OpenAI Service") == {"provider:azure-openai"}
    assert taxonomy.facts_from_name("gpt-4o-mini") == {"provider:openai"}
    assert taxonomy.facts_from_name("Totally unrelated text") == frozenset()


def test_facts_for_config_path() -> None:
    assert taxonomy.facts_for_config_path("/x/.cursor/mcp.json") == {"mcp-client-config:cursor"}
    assert taxonomy.facts_for_config_path("docs/mcp.json") == {"mcp-client-config:generic"}
    assert taxonomy.facts_for_config_path("CLAUDE.md:12") == {"agent-config:claude-md"}
    assert taxonomy.facts_for_config_path(".claude/agents/reviewer.md") == {"agent-config:claude-dir"}
    assert taxonomy.facts_for_config_path(".well-known/agent.json") == {"a2a:agent-card"}
    assert taxonomy.facts_for_config_path("src/main.py") == frozenset()


def test_fact_validation_and_hosts() -> None:
    assert taxonomy.is_fact("provider:openai")
    assert not taxonomy.is_fact("Provider:OpenAI")
    assert not taxonomy.is_fact("unknown:thing")
    assert taxonomy.facts_in_text("host", 'base_url = "https://api.anthropic.com/v1"') == {
        "provider:anthropic"
    }
    assert taxonomy.facts_in_text("idiom", "client = boto3.client('bedrock-runtime')") == {"provider:bedrock"}
    assert taxonomy.facts_in_text("idiom", 'model = "vertex_ai/claude-3-5-haiku"') == {
        "provider:vertex-ai",
        "provider:anthropic",
    }
    assert taxonomy.facts_in_text("idiom", "key = os.environ['MISTRAL_API_KEY']") == {"provider:mistral"}
    assert taxonomy.facts_in_text("idiom", "AnthropicVertex(region='us')") == {
        "provider:vertex-ai",
        "provider:anthropic",
    }
    assert taxonomy.facts_in_text("idiom", "id = 'anthropic.claude-3-5-sonnet-20241022-v2:0'") == {
        "provider:bedrock",
        "provider:anthropic",
    }
    assert taxonomy.facts_in_text("idiom", "from pathlib import Path") == frozenset()
    assert taxonomy.facts_from_name("High Risk (Agent Frameworks)") == frozenset()
    assert all(taxonomy.is_fact(f) for f in taxonomy.all_known_facts())


def test_facts_from_purl() -> None:
    assert facts_from_purl("pkg:pypi/langgraph@0.2.1") == {"framework:langgraph"}
    assert facts_from_purl("pkg:maven/dev.langchain4j/langchain4j@1.0") == {"framework:langchain4j"}
    assert facts_from_purl("pkg:golang/github.com/tmc/langchaingo@v0.1") == {"framework:langchaingo"}
    assert facts_from_purl("pkg:npm/%40ai-sdk/openai") == frozenset()
    assert facts_from_purl("not a purl") == frozenset()


# --- evidence extraction --------------------------------------------------------------------------


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_evidence_extraction_labels_a_synthetic_repo(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "requirements.txt",
        "langchain-openai>=0.2\nmcp\n# comment\n-e git+https://x#egg=ignored_pkg\n",
    )
    _write(tmp_path, "package.json", json.dumps({"dependencies": {"ai": "^4", "@ai-sdk/anthropic": "1"}}))
    _write(tmp_path, "go.mod", "module x\n\nrequire (\n\tgithub.com/mark3labs/mcp-go v0.1.0 // indirect\n)\n")
    _write(tmp_path, "poetry.lock", '[[package]]\nname = "crewai"\nversion = "1"\n')
    _write(tmp_path, ".cursor/mcp.json", '{"mcpServers": {"fs": {"command": "npx"}}}')
    _write(tmp_path, "docs/mcp.json", '{"mcpServers": {}}')
    _write(tmp_path, "mods/mcp.json", '{"minecraft": true}')
    _write(tmp_path, "CLAUDE.md", "# rules\n")
    _write(tmp_path, "server.py", "from mcp.server.fastmcp import FastMCP\n\napp = FastMCP('demo')\n")
    _write(
        tmp_path, "infra/main.tf", 'resource "aws_bedrockagent_agent" "ops" {\n  foundation_model = "x"\n}\n'
    )
    _write(
        tmp_path,
        "flows/lead.json",
        json.dumps(
            {"nodes": [{"type": "@n8n/n8n-nodes-langchain.agent", "name": "AI Agent"}], "connections": {}}
        ),
    )
    _write(tmp_path, "README.md", "Talks to https://api.anthropic.com and uses CrewAI.\n")
    _write(tmp_path, "config.yaml", "llm:\n  base_url: https://api.mistral.ai/v1\n")
    _write(
        tmp_path,
        ".well-known/agent.json",
        json.dumps({"name": "a", "url": "http://x", "skills": [], "capabilities": {}}),
    )
    _write(
        tmp_path, "dify/app.yml", "app:\n  mode: workflow\n  name: demo\nkind: app\nworkflow:\n  graph: {}\n"
    )
    _write(tmp_path, "tests/fixtures/args.yaml", "base_url: http://localhost:11434\n")
    _write(tmp_path, "website/_data/leaderboard.yml", "- model: xai/grok-4\n")
    _write(tmp_path, "docs/CLAUDE.md", "# docs copy\n")
    _write(tmp_path, "src/i18n/locales/de/mcp.json", '{"servers": "Server", "title": "MCP"}')
    _write(
        tmp_path,
        "nb.ipynb",
        json.dumps(
            {
                "cells": [
                    {"cell_type": "code", "source": ["!pip install -q smolagents\n", "import smolagents\n"]}
                ]
            }
        ),
    )
    _write(
        tmp_path, "oa.py", "from agents import Agent, Runner\n\nagent = Agent(name='x', model='gpt-4.1')\n"
    )
    _write(tmp_path, "other.py", "from agents import load_registry\n")

    ev = evidence.extract(tmp_path)
    facts = set(ev.facts)
    assert {"framework:langchain", "provider:openai", "mcp:sdk", "mcp:server"} <= facts
    assert {"framework:vercel-ai", "provider:anthropic"} <= facts
    assert {"mcp-client-config:cursor", "mcp-client-config:generic", "agent-config:claude-md"} <= facts
    assert {"iac:bedrock", "lowcode:n8n", "lowcode:dify", "a2a:agent-card", "provider:mistral"} <= facts
    assert "framework:smolagents" in facts
    assert "framework:openai-agents" in facts and "provider:openai" in facts
    assert all("other.py" not in h.location for h in ev.facts["framework:openai-agents"])
    assert "framework:crewai" not in facts and "framework:crewai" in ev.tolerated
    assert "provider:ollama" not in facts and "provider:ollama" in ev.tolerated  # test fixture only
    assert "provider:xai" in ev.tolerated and "provider:xai" not in facts  # documentation-site data only
    assert "agent-config:claude-md" in facts  # committed config paths count even under docs/
    assert evidence.is_test_path("pkg/server_test.go") and not evidence.is_test_path("pkg/server.go")
    assert evidence.is_test_path("src/broker_tests.rs") and evidence.is_test_path("src/net/tests.rs")
    assert not evidence.is_test_path("src/contest.rs")
    assert "mcp:sdk" not in ev.tolerated  # required evidence wins over the indirect go.mod entry
    locations = {h.location for h in ev.facts["provider:mistral"]}
    assert "config.yaml:2" in locations
    assert all("README.md" not in h.location for hits in ev.facts.values() for h in hits)
    assert all(h.location != "mods/mcp.json" for hits in ev.facts.values() for h in hits)
    assert all("locales" not in h.location for hits in ev.facts.values() for h in hits)


def test_evidence_skips_binary_and_vendor_and_handles_malformed(tmp_path: Path) -> None:
    _write(tmp_path, "node_modules/openai/package.json", json.dumps({"dependencies": {"openai": "1"}}))
    _write(tmp_path, "pyproject.toml", "this is = not toml [[[\n")
    _write(tmp_path, "package.json", "{not json")
    (tmp_path / "model.gguf").write_bytes(b"\0\0GGUF")
    ev = evidence.extract(tmp_path)
    assert not ev.facts
    assert ev.files == 3


# --- corpus ---------------------------------------------------------------------------------------


def _repo(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": "acme__demo",
        "host": "github",
        "path": "acme/demo",
        "commit": SHA,
        "default_branch": "main",
        "class": "positive",
        "expected": [{"fact": "framework:langgraph", "evidence": ["manifest:pyproject.toml"]}],
    }
    base.update(overrides)
    return base


def test_corpus_round_trip_and_validation(tmp_path: Path) -> None:
    corpus = corpus_from_dict({"schema": 1, "metadata": {"name": "t"}, "repos": [_repo()]})
    assert corpus.repos[0].url == "https://github.com/acme/demo.git"
    assert corpus.repos[0].expected_facts == {"framework:langgraph"}
    path = tmp_path / "corpus.json"
    save_corpus(corpus, path)
    assert load_corpus(path).repos[0].id == "acme__demo"
    with pytest.raises(CorpusError):
        corpus_from_dict({"schema": 1, "metadata": {}, "repos": [_repo(**{"class": "control"})]})
    with pytest.raises(CorpusError):
        corpus_from_dict(
            {"schema": 1, "metadata": {}, "repos": [_repo(expected=[{"fact": "bogus:x", "evidence": ["e"]}])]}
        )
    with pytest.raises(CorpusError):
        corpus_from_dict({"schema": 1, "metadata": {}, "repos": [_repo(commit="abc")]})
    with pytest.raises(CorpusError):
        corpus_from_dict({"schema": 1, "metadata": {}, "repos": [_repo(), _repo()]})
    with pytest.raises(CorpusError):
        corpus_from_dict({"schema": 1, "metadata": {}, "repos": [_repo(tolerated=["framework:langgraph"])]})


# --- scoring --------------------------------------------------------------------------------------


def test_match_values_wildcards_and_tolerated() -> None:
    tp, fp, fn = score.match_values(
        {"mcp-client-config:generic", "provider:openai", "provider:cohere"},
        {"mcp-client-config:cursor", "provider:openai", "framework:langchain"},
    )
    assert sorted(tp) == ["mcp-client-config:generic", "provider:openai"]
    assert fp == ["provider:cohere"]
    assert fn == ["framework:langchain"]
    repo = Repo(
        id="r", host="github", path="a/b", commit=SHA, default_branch="main", klass="positive",
        expected=(Expected("provider:openai", ("e",)),), tolerated=("framework:litellm",),
    )  # fmt: skip
    result = score.score_repo(
        repo,
        ["provider:openai", "framework:litellm", "lowcode:n8n"],
        frozenset({"provider"}),
        status="ok",
        seconds=1.0,
    )
    assert result.tp == ["provider:openai"] and result.fp == ["lowcode:n8n"]
    assert result.tolerated_hits == ["framework:litellm"] and result.out_of_scope == ["lowcode:n8n"]


def _tiny_corpus() -> Corpus:
    return corpus_from_dict(
        {
            "schema": 1,
            "metadata": {"name": "tiny"},
            "repos": [
                _repo(),
                _repo(id="acme__ctl", path="acme/ctl", **{"class": "control"}, expected=[]),
                _repo(id="acme__near", path="acme/near", **{"class": "nearmiss"}, expected=[]),
            ],
        }
    )


def _manifest() -> dict[str, object]:
    return {
        "started": "t0",
        "finished": "t1",
        "host": {"platform": "test"},
        "workers": 1,
        "tool_versions": {"shadowscan": "0.1.2", "cdxgen": "12"},
        "tools_skipped": {"cisco_aibom": "needs an LLM"},
        "results": [
            {
                "tool": "shadowscan",
                "repo": "acme__demo",
                "status": "ok",
                "seconds": 2.0,
                "facts": ["framework:langgraph"],
            },
            {"tool": "shadowscan", "repo": "acme__ctl", "status": "ok", "seconds": 1.0, "facts": []},
            {
                "tool": "shadowscan",
                "repo": "acme__near",
                "status": "ok",
                "seconds": 1.0,
                "facts": ["provider:openai"],
            },
            {"tool": "cdxgen", "repo": "acme__demo", "status": "timeout", "seconds": 900.0, "facts": []},
            {"tool": "cdxgen", "repo": "acme__ctl", "status": "ok", "seconds": 1.0, "facts": []},
            {"tool": "cdxgen", "repo": "acme__near", "status": "ok", "seconds": 1.0, "facts": []},
        ],
    }


def test_score_all_and_report_render() -> None:
    corpus = _tiny_corpus()
    scopes = {"shadowscan": frozenset(taxonomy.CATEGORIES), "cdxgen": frozenset({"framework", "provider"})}
    metrics = score.score_all(corpus, _manifest(), scopes, {"shadowscan": "ShadowScan", "cdxgen": "cdxgen"})
    ss = metrics["tools"]["shadowscan"]
    assert ss["value_level"]["in_scope"] == {
        "tp": 1,
        "fp": 1,
        "fn": 0,
        "precision": 0.5,
        "recall": 1.0,
        "f1": 0.6667,
    }
    assert ss["repo_level"]["positives_detected"] == 1 and ss["repo_level"]["nearmiss_flagged"] == 1
    cdx = metrics["tools"]["cdxgen"]
    assert cdx["runs"]["timeout"] == 1 and cdx["value_level"]["in_scope"]["fn"] == 1
    assert metrics["corpus"]["expected_facts"] == 1
    text = report.render(metrics, corpus, title="T")
    assert "## Headline" in text and "ShadowScan (0.1.2)" in text and "acme/near" in text
    assert "cisco_aibom" in text


# --- adapters -------------------------------------------------------------------------------------


def test_shadowscan_normalize(tmp_path: Path) -> None:
    findings = [
        {
            "kind": "agent",
            "resource": "r/svc",
            "frameworks": ["framework.langgraph", "protocol.mcp"],
            "model_providers": ["provider.openai"],
            "evidence": [],
        },
        {
            "kind": "mcp-server",
            "resource": "r/.cursor/mcp.json",
            "frameworks": ["protocol.mcp"],
            "model_providers": [],
            "evidence": [{"location": ".cursor/mcp.json"}],
        },
        {
            "kind": "agent-config",
            "resource": "r",
            "frameworks": ["coding-agent.claude-code"],
            "model_providers": [],
            "evidence": [{"location": "CLAUDE.md"}],
        },
        {
            "kind": "infra",
            "resource": "r/main.tf",
            "frameworks": ["cloud.aws-bedrock-agents"],
            "model_providers": ["provider.anthropic"],
            "evidence": [],
        },
        {
            "kind": "framework-usage",
            "resource": "r/sdk",
            "frameworks": ["platform.dify"],
            "model_providers": [],
            "evidence": [],
        },
        {
            "kind": "workflow",
            "resource": "r/flow.json",
            "frameworks": ["platform.n8n"],
            "model_providers": ["provider.openai"],
            "evidence": [],
        },
        {
            "kind": "secret",
            "resource": "r/config.py",
            "frameworks": [],
            "model_providers": ["provider.openai"],
            "evidence": [],
        },
        {
            "kind": "agent",
            "resource": "r/.well-known/agent.json",
            "frameworks": ["protocol.a2a"],
            "model_providers": [],
            "evidence": [],
        },
    ]
    (tmp_path / "report.json").write_text(json.dumps({"findings": findings, "stats": [{"incomplete": True}]}))
    result = ShadowScanAdapter().normalize(tmp_path)
    assert result.facts == {
        "framework:langgraph", "mcp:sdk", "provider:openai", "mcp-client-config:cursor", "agent-config:claude-md",
        "iac:bedrock", "provider:anthropic", "lowcode:n8n", "a2a:agent-card",
    }  # fmt: skip
    assert result.detail["incomplete"] is True
    assert ShadowScanAdapter().normalize(tmp_path / "missing").error


def test_cdxgen_trusera_xbom_normalize(tmp_path: Path) -> None:
    (tmp_path / "bom.json").write_text(
        json.dumps({"components": [{"purl": "pkg:pypi/langgraph@1"}, {"purl": "pkg:npm/express@4"}]})
    )
    assert CdxgenAdapter().normalize(tmp_path).facts == {"framework:langgraph"}
    components = [
        {
            "name": "aws_bedrockagent_agent.ops",
            "purl": "pkg:pypi/x",
            "properties": [
                {"name": "trusera:source", "value": "cloud"},
                {"name": "trusera:provider", "value": "AWS Bedrock"},
            ],
        },
        {
            "name": "github (MCP Server)",
            "properties": [
                {"name": "trusera:source", "value": "mcp-config"},
                {"name": "trusera:source_location", "value": "/r/.mcp.json"},
            ],
        },
        {
            "name": "LangChain Model",
            "properties": [
                {"name": "trusera:source", "value": "code"},
                {"name": "trusera:provider", "value": "OpenAI"},
            ],
        },
        {
            "name": "@ai-sdk/openai",
            "purl": "pkg:npm/@ai-sdk/openai",
            "properties": [
                {"name": "trusera:source", "value": "code"},
                {"name": "trusera:provider", "value": "Unknown"},
            ],
        },
    ]
    (tmp_path / "ai-bom.json").write_text(json.dumps({"components": components}))
    assert TruseraAdapter().normalize(tmp_path).facts == {
        "iac:bedrock", "mcp-client-config:claude-code", "framework:langchain", "provider:openai", "framework:vercel-ai",
    }  # fmt: skip
    (tmp_path / "xbom.json").write_text(
        json.dumps(
            {
                "components": [
                    {
                        "bom-ref": "langchain_community.tools",
                        "name": "Langchain Community Library - Tools",
                        "manufacturer": {"name": "Langchain"},
                    }
                ]
            }
        )
    )
    assert XbomAdapter().normalize(tmp_path).facts == {"framework:langchain"}


def test_geiger_vet_agentdiscover_radar_nuguard_normalize(tmp_path: Path) -> None:
    (tmp_path / "geiger.json").write_text(
        json.dumps(
            {
                "findings": [
                    {"kind": "mcp-server", "name": "fs", "evidence": [{"file": "/r/.cursor/mcp.json"}]},
                    {"kind": "skill", "name": "s", "evidence": []},
                ]
            }
        )
    )
    assert GeigerAdapter().normalize(tmp_path).facts == {
        "mcp-client-config:cursor",
        "agent-config:skills",
    }
    assert GeigerAdapter().normalize(tmp_path / "none").error is None
    (tmp_path / "vet.json").write_text(
        json.dumps(
            [
                {
                    "Name": "Claude Code",
                    "App": "claude_code",
                    "ConfigPath": "/r",
                    "Agent": {"InstructionFiles": ["/r/CLAUDE.md"]},
                },
                {"Name": "fs", "MCPServer": {"Transport": "stdio"}, "ConfigPath": "/r/.vscode/mcp.json"},
            ]
        )
    )
    assert VetAdapter().normalize(tmp_path).facts == {
        "agent-config:claude-md",
        "mcp-client-config:vscode",
    }
    (tmp_path / "vet.json").write_text(
        json.dumps(
            [
                {
                    "Name": "academy-guide",
                    "App": "openclaw",
                    "ConfigPath": "/r/skills/academy-guide",
                    "Metadata": {"skill.description": "x"},
                }
            ]
        )
    )
    assert VetAdapter().normalize(tmp_path).facts == {"agent-config:skills"}
    (tmp_path / "vet.json").write_text("")
    assert VetAdapter().normalize(tmp_path).error is None
    sarif = {
        "runs": [
            {
                "results": [
                    {"ruleId": "DAI003", "message": {"text": "LangGraph StateGraph detected"}},
                    {"ruleId": "DAI005", "message": {"text": "Direct HTTP LLM client detected"}},
                ]
            }
        ]
    }
    (tmp_path / "scan.sarif").write_text(json.dumps(sarif))
    (tmp_path / "mcp-policy.yaml").write_text("servers:\n- server: github\n")
    assert AgentDiscoverAdapter().normalize(tmp_path).facts == {
        "framework:langgraph",
        "mcp-client-config:generic",
    }
    (tmp_path / "crewai.json").write_text(json.dumps({"nodes": [{"id": "a", "tools": ["mcp_search"]}]}))
    assert AgenticRadarAdapter().normalize(tmp_path).facts == {"framework:crewai", "mcp:sdk"}
    sbom = {
        "summary": {"frameworks": ["crewai"]},
        "deps": [{"purl": "pkg:pypi/openai"}],
        "nodes": [{"component_type": "MODEL", "name": "claude-3-5-sonnet", "metadata": {}}],
    }
    (tmp_path / "sbom.json").write_text(json.dumps(sbom))
    assert NuGuardAdapter().normalize(tmp_path).facts == {
        "framework:crewai",
        "provider:openai",
        "provider:anthropic",
    }


def test_all_adapters_declare_known_categories_and_unique_ids() -> None:
    adapters = all_adapters()
    ids = [a.spec.id for a in adapters]
    assert len(ids) == len(set(ids))
    for adapter in adapters:
        assert adapter.spec.categories <= set(taxonomy.CATEGORIES)
        assert adapter.unavailable_reason(ToolConfig({"tools": {}}))


# --- runner ---------------------------------------------------------------------------------------


def test_scrubbed_env_has_no_credentials_and_dead_proxy(tmp_path: Path) -> None:
    env = scrubbed_env(RunPolicy(), tmp_path, tmp_path, {"EXTRA": "1"})
    assert env["HTTPS_PROXY"] == "http://127.0.0.1:9" and env["NO_PROXY"] == "" and env["EXTRA"] == "1"
    assert not any(k.endswith("_API_KEY") for k in env)
    argv = _wrap(RunPolicy(as_user="root"), ("tool", "--flag"), {"A": "b"})
    assert argv[:1] == ["setpriv"] and argv[-2:] == ["tool", "--flag"] and "A=b" in argv


class _FakeAdapter:
    """Writes a JSON file through python so the whole run loop executes without any tool."""

    spec = ShadowScanAdapter.spec

    def __init__(self, sleep: float = 0.0) -> None:
        self.sleep = sleep

    def unavailable_reason(self, cfg: ToolConfig) -> str | None:
        return None

    def version(self, cfg: ToolConfig) -> str:
        return "fake"

    def commands(self, cfg: ToolConfig, repo_dir: Path, out_dir: Path) -> list[Command]:
        code = f"import json,time; time.sleep({self.sleep}); open({str(out_dir / 'report.json')!r},'w').write(json.dumps({{'findings': [], 'stats': []}}))"
        return [Command((sys.executable, "-c", code))]

    def normalize(self, out_dir: Path) -> object:
        return ShadowScanAdapter().normalize(out_dir)


def test_run_pair_executes_commands_and_records_timeouts(tmp_path: Path) -> None:
    repo = _tiny_corpus().repos[0]
    cfg = ToolConfig({"tools": {}})
    result = run_pair(_FakeAdapter(), cfg, repo, tmp_path / "repo", tmp_path / "out", RunPolicy(timeout=30))  # type: ignore[arg-type]
    assert result.status == "ok" and result.facts == [] and (tmp_path / "out" / "result.json").exists()
    slow = run_pair(
        _FakeAdapter(sleep=5), cfg, repo, tmp_path / "repo", tmp_path / "out2", RunPolicy(timeout=1)
    )  # type: ignore[arg-type]
    assert slow.status == "timeout" and slow.commands[0].timed_out


# --- compare --------------------------------------------------------------------------------------


def test_compare_flags_f1_drop_and_new_negative_only() -> None:
    corpus = _tiny_corpus()
    classes = {r.id: r.klass for r in corpus.repos}
    scopes = {"shadowscan": frozenset(taxonomy.CATEGORIES), "cdxgen": frozenset({"framework", "provider"})}
    names = {"shadowscan": "ShadowScan", "cdxgen": "cdxgen"}
    baseline = score.score_all(corpus, _manifest(), scopes, names)
    improved = _manifest()
    improved["results"][2]["facts"] = []  # the near-miss is clean now
    current = score.score_all(corpus, improved, scopes, names)
    results = compare.compare(baseline, current, classes)
    by = {r.tool: r for r in results}
    assert by["shadowscan"].ok and by["shadowscan"].newly_clean == ["acme__near"]
    worse = _manifest()
    worse["results"][0]["facts"] = []  # lost the positive
    worse["results"][1]["facts"] = ["provider:openai"]  # flagged the control
    results = compare.compare(baseline, score.score_all(corpus, worse, scopes, names), classes)
    bad = {r.tool: r for r in results}["shadowscan"]
    assert not bad.ok and bad.newly_flagged == ["acme__ctl"]
    assert any("F1" in r for r in bad.regressions) and any("recall" in r for r in bad.regressions)
