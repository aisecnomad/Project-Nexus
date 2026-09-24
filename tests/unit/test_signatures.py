from __future__ import annotations

import re
from collections import Counter

from shadowscan.signatures import SignatureIndex, load_signatures
from shadowscan.signatures.loader import VALID_CATEGORIES, VALID_SIGNAL_TYPES


def test_all_signatures_load_and_validate():
    sigs = load_signatures()
    assert len(sigs) >= 150
    ids = [s.id for s in sigs]
    assert len(ids) == len(set(ids)), "duplicate signature ids"
    for s in sigs:
        assert s.category in VALID_CATEGORIES
        assert s.signals, f"{s.id} has no signals"
        for sig in s.signals:
            assert sig.type in VALID_SIGNAL_TYPES
            assert len(sig.compiled) == len(sig.bounded_compiled) == len(sig.patterns)
            for rx in sig.compiled:
                assert isinstance(rx, re.Pattern)


def test_required_frameworks_present(index: SignatureIndex):
    required = [
        "framework.langchain",
        "framework.langgraph",
        "framework.llamaindex",
        "framework.crewai",
        "framework.google-adk",
        "framework.aws-strands",
        "framework.microsoft-agent-framework",
        "framework.smolagents",
        "framework.openai-agents-sdk",
        "framework.claude-agent-sdk",
        "framework.pydantic-ai",
        "framework.autogen",
        "framework.semantic-kernel",
        "protocol.mcp",
        "protocol.a2a",
        "coding-agent.claude-code",
        "coding-agent.github-copilot",
        "coding-agent.cursor",
        "platform.copilot-studio",
        "platform.salesforce-agentforce",
        "cloud.aws-bedrock-agents",
        "cloud.gcp-vertex-agent-engine",
        "cloud.azure-ai-foundry-agents",
        "cloud.oci-generative-ai-agents",
        "provider.openai",
        "provider.anthropic",
        "provider.google-gemini",
        "provider.aws-bedrock",
        "provider.azure-openai",
    ]
    for rid in required:
        assert index.get(rid) is not None, rid


def test_dependency_matching_across_ecosystems(index: SignatureIndex):
    cases = {
        ("pypi", "langchain-openai"): "framework.langchain",
        ("pypi", "LangGraph"): "framework.langgraph",
        ("pypi", "crewai_tools"): "framework.crewai",
        ("pypi", "google-adk"): "framework.google-adk",
        ("pypi", "strands-agents-tools"): "framework.aws-strands",
        ("pypi", "agent-framework-azure-ai"): "framework.microsoft-agent-framework",
        ("pypi", "smolagents"): "framework.smolagents",
        ("npm", "@openai/agents"): "framework.openai-agents-sdk",
        ("npm", "@modelcontextprotocol/server-github"): "protocol.mcp",
        ("npm", "@langchain/langgraph"): "framework.langgraph",
        ("go", "github.com/tmc/langchaingo"): "framework.langchaingo",
        ("maven", "dev.langchain4j:langchain4j-open-ai"): "framework.langchain4j",
        ("nuget", "Microsoft.Agents.AI.OpenAI"): "framework.microsoft-agent-framework",
        ("cargo", "rig-core"): "framework.rig",
    }
    for (eco, name), expected in cases.items():
        ids = {m.signature_id for m in index.match_dependency(eco, name)}
        assert expected in ids, f"{eco}:{name} -> {ids}"


def test_import_and_code_patterns(index: SignatureIndex):
    py = "from crewai import Agent, Crew\nfrom google.adk.agents import LlmAgent\nagent = create_react_agent(llm, tools)\n"
    ids = {m.signature_id for m in index.match_imports(py, "python")}
    assert {"framework.crewai", "framework.google-adk"} <= ids
    code_ids = {m.signature_id for m in index.match_code(py, "python")}
    assert "framework.langchain" in code_ids or "framework.langgraph" in code_ids
    js = 'import { Agent, run } from "@openai/agents";\nconst s = new McpServer({ name: "x" });\n'
    ids = {m.signature_id for m in index.match_imports(js, "javascript")} | {m.signature_id for m in index.match_code(js, "javascript")}
    assert {"framework.openai-agents-sdk", "protocol.mcp"} <= ids


def test_domain_user_agent_model_and_secret(index: SignatureIndex):
    assert {m.signature_id for m in index.match_domain("api.anthropic.com")} == {"provider.anthropic"} | {m.signature_id for m in index.match_domain("api.anthropic.com") if m.signature_id != "provider.anthropic"}
    assert "provider.aws-bedrock" in {m.signature_id for m in index.match_domain("bedrock-runtime.eu-west-1.amazonaws.com")}
    assert "cloud.aws-bedrock-agents" in {m.signature_id for m in index.match_domain("bedrock-agent-runtime.us-east-1.amazonaws.com")}
    assert "provider.azure-openai" in {m.signature_id for m in index.match_domain("acme.openai.azure.com")}
    assert "provider.ollama" in {m.signature_id for m in index.match_domain("localhost:11434")}
    ua = {m.signature_id for m in index.match_user_agent("crewai/0.80 OpenAI/Python 1.5")}
    assert {"framework.crewai", "provider.openai"} <= ua
    assert "provider.anthropic" in {m.signature_id for m in index.match_model("claude-sonnet-4-5")}
    assert "provider.aws-bedrock" in {m.signature_id for m in index.match_model("us.anthropic.claude-3-5-sonnet-20241022-v2:0")}
    assert "provider.google-gemini" in {m.signature_id for m in index.match_model("gemini-2.5-pro")}
    secrets = {m.signature_id for m in index.match_secrets('KEY="sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH-ijklmnopqrstAA"')}
    assert secrets == {"provider.anthropic"}
    assert {m.signature_id for m in index.match_secrets("gsk_" + "a" * 50)} == {"provider.groq"}


def test_file_env_scope_iac_and_names(index: SignatureIndex):
    assert "coding-agent.claude-code" in {m.signature_id for m in index.match_file(".claude/agents/reviewer.md")}
    assert "coding-agent.github-copilot" in {m.signature_id for m in index.match_file(".github/agents/planner.agent.md")}
    assert "protocol.a2a" in {m.signature_id for m in index.match_file("public/.well-known/agent.json")}
    assert "protocol.mcp" in {m.signature_id for m in index.match_file(".cursor/mcp.json")}
    assert "provider.openai" in {m.signature_id for m in index.match_env("OPENAI_API_KEY")}
    assert "heuristic.llm-env-names" in {m.signature_id for m in index.match_env("LLM_PROVIDER")}
    assert "policy.privileged-scopes" in {m.signature_id for m in index.match_scope("Directory.ReadWrite.All")}
    assert "policy.data-access-scopes" in {m.signature_id for m in index.match_scope("channels:history")}
    assert "policy.llm-access-scopes" in {m.signature_id for m in index.match_scope("bedrock:InvokeModel")}
    assert "cloud.aws-bedrock-agents" in {m.signature_id for m in index.match_iac("aws_bedrockagent_agent")}
    assert "cloud.gcp-vertex-agent-engine" in {m.signature_id for m in index.match_iac("google_dialogflow_cx_agent")}
    assert "identity-app.meeting-notetakers" in {m.signature_id for m in index.match_name("Otter.ai for Zoom")}
    assert "identity-app.openai-chatgpt" in {m.signature_id for m in index.match_name("ChatGPT")}
    assert "platform.n8n" in {m.signature_id for m in index.match_image("n8nio/n8n:1.60")}


def test_signature_categories_cover_all_surfaces(index: SignatureIndex):
    counts = Counter(s.category for s in index.signatures.values())
    for cat in ("framework", "provider", "protocol", "coding-agent", "platform", "cloud-service", "identity-app", "policy", "heuristic"):
        assert counts[cat] >= 3, cat
