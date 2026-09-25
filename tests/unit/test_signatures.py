from __future__ import annotations

import re
from collections import Counter

import pytest
import regex

from shadowscan.signatures import SignatureIndex, load_signatures
from shadowscan.signatures.loader import VALID_CATEGORIES, VALID_SIGNAL_TYPES


def _ids(matches) -> set[str]:
    return {m.signature_id for m in matches}


def test_all_signatures_load_and_validate():
    sigs = load_signatures()
    assert len(sigs) >= 200
    ids = [s.id for s in sigs]
    assert len(ids) == len(set(ids)), "duplicate signature ids"
    for s in sigs:
        assert s.category in VALID_CATEGORIES
        assert s.signals, f"{s.id} has no signals"
        for sig in s.signals:
            assert sig.type in VALID_SIGNAL_TYPES
            assert len(sig.bounded_compiled) == len(sig.patterns)
            assert all(isinstance(rx, regex.Pattern) for rx in sig.bounded_compiled)
            # The stdlib view is computed on demand and never drives matching.
            assert len(sig.compiled) == len(sig.patterns)
            assert all(isinstance(rx, re.Pattern) for rx in sig.compiled)


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
        ("pypi", "openai"): "provider.openai",
        ("npm", "@anthropic-ai/sdk"): "provider.anthropic",
        ("pypi", "autogen-agentchat"): "framework.autogen",
        ("pypi", "pydantic-ai"): "framework.pydantic-ai",
        ("npm", "@mastra/core"): "framework.mastra",
        ("pypi", "mcp"): "protocol.mcp",
        ("pypi", "langchain-xai"): "framework.langchain",
        ("npm", "@langchain/openai"): "framework.langchain",
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
    # The API host is the provider; the identity-app signature's *.anthropic.com
    # wildcard matches it as well, by design, and nothing else may.
    anthropic = {m.signature_id for m in index.match_domain("api.anthropic.com")}
    assert anthropic == {"provider.anthropic", "identity-app.anthropic-claude"}
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


# ------------------------------------------------------------ hard negatives
@pytest.mark.parametrize(
    ("ecosystem", "name"),
    [
        ("pypi", "openapi"), ("pypi", "openapi-generator"), ("pypi", "azure-storage-blob"), ("pypi", "imagenai"),
        ("pypi", "gemini-python"), ("pypi", "python-telegram-bot"), ("npm", "user-agent"), ("pypi", "crew"),
        ("npm", "@langchainx/textsplitters"), ("pypi", "langchainx"), ("pypi", "langchain4j"),
    ],
)
def test_lookalike_dependencies_do_not_match(index: SignatureIndex, ecosystem, name):
    assert index.match_dependency(ecosystem, name) == []


def test_langchain_text_splitters_is_a_utility_not_framework_usage(index: SignatureIndex):
    for eco, name in (("pypi", "langchain-text-splitters"), ("npm", "@langchain/textsplitters")):
        matches = index.match_dependency(eco, name)
        assert [m.signature_id for m in matches] == ["framework.langchain-utilities"], (eco, name)
        assert all(m.weight <= 0.35 and not m.agent_indicator for m in matches)
    utility = index.match_imports("from langchain_text_splitters import RecursiveCharacterTextSplitter\n", "python")
    assert _ids(utility) == {"framework.langchain-utilities"}
    assert _ids(index.match_imports("from langchain_openai import ChatOpenAI\n", "python")) == {"framework.langchain"}
    assert "framework.langchain" in _ids(index.match_dependency("pypi", "langchain-openai"))


@pytest.mark.parametrize(
    "display_name",
    [
        "Mistral Dubois", "Graphite Metrics", "Devin Smith", "Otter Insurance Portal", "Jules Verne Book Club",
        "copilot-css", "copilot-theme", "cursor position", "Sweep the floor", "Codex Manuscripts",
        "Amp Hours Calculator", "Jasper Johns exhibition", "Monica Geller", "Harvey Specter", "Kimi Antonelli fan page",
        "Grok pattern library", "Edgar Allan Poe", "Gong Show archive", "Drift Racing League", "Clay Pottery Studio",
        "Minecraft Bedrock Edition server", "Palantir Foundry", "Sierra Nevada trip", "Warp Drive Physics",
    ],
)
def test_dictionary_words_and_person_names_do_not_match_products(index: SignatureIndex, display_name):
    assert _ids(index.match_name(display_name)) == set(), display_name


def test_ambiguous_product_names_match_with_product_context(index: SignatureIndex):
    expected = {
        "Graphite PR review bot": "coding-agent.pr-review-bots",
        "Bito AI code review": "coding-agent.pr-review-bots",
        "Devin AI": "identity-app.coding-assistants-saas",
        "devin-ai-integration[bot]": "identity-app.coding-assistants-saas",
        "Otter.ai for Zoom": "identity-app.meeting-notetakers",
        "Otter meeting notes": "identity-app.meeting-notetakers",
        "Jules (Google Labs)": "coding-agent.gemini-cli",
        "OpenAI Codex": "coding-agent.openai-codex",
        # The bare word as the whole display name is the product itself (an OAuth
        # app or GitHub App is not named after a person or a metal).
        "Gong": "identity-app.meeting-notetakers",
        "Devin": "identity-app.coding-assistants-saas",
        "Jasper": "identity-app.writing-assistants",
        "Graphite": "coding-agent.pr-review-bots",
        "Sweep": "coding-agent.pr-review-bots",
        "Jules": "coding-agent.gemini-cli",
        "Codex": "coding-agent.openai-codex",
        "Kimi": "identity-app.kimi",
        "Grok": "identity-app.xai-grok",
        "Poe": "identity-app.poe",
        "Mistral": "identity-app.mistral-le-chat",
        "Cursor": "identity-app.coding-assistants-saas",
        "Windsurf": "identity-app.coding-assistants-saas",
        "Zapier": "identity-app.automation-agents",
        "Jasper AI": "identity-app.writing-assistants",
        "Monica AI assistant": "identity-app.browser-extensions-ai",
        "Harvey legal AI": "identity-app.ai-search-research",
        "Mistral Le Chat": "identity-app.mistral-le-chat",
        "Le Chat": "identity-app.mistral-le-chat",
        "DeepSeek": "identity-app.deepseek",
        "Qwen Chat": "identity-app.qwen",
        "Kimi AI": "identity-app.kimi",
        "Grok by xAI": "identity-app.xai-grok",
        "Poe by Quora": "identity-app.poe",
        "Character.ai": "identity-app.character-ai",
        "Microsoft 365 Copilot": "identity-app.microsoft-copilot",
        "Copilot for Sales": "identity-app.microsoft-copilot",
        "Vertex AI Agent Builder": "cloud.gcp-vertex-agent-engine",
        "Azure AI Studio": "cloud.azure-ai-foundry-agents",
        "Google AI Studio": "identity-app.google-gemini",
        "watsonx Orchestrate": "platform.ibm-watsonx-orchestrate",
    }
    for name, signature in expected.items():
        assert signature in _ids(index.match_name(name)), name


def test_display_names_are_not_misattributed_to_the_wrong_vendor(index: SignatureIndex):
    assert "platform.salesforce-agentforce" not in _ids(index.match_name("Copilot for Sales"))
    assert "cloud.gcp-vertex-agent-engine" not in _ids(index.match_name("Agent Builder"))
    assert "identity-app.google-gemini" not in _ids(index.match_name("Azure AI Studio"))
    assert "cloud.azure-ai-foundry-agents" not in _ids(index.match_name("Google AI Studio"))
    # A generic "X Copilot" product is a naming hint, not Microsoft Copilot.
    assert _ids(index.match_name("Contoso Copilot Agent")) == {"identity-app.generic-ai-name"}
    # Umbrella identity-app signatures own SaaS display names; product signatures do not double-claim them.
    for name, owner in (("Windsurf", "identity-app.coding-assistants-saas"), ("Zapier", "identity-app.automation-agents"), ("n8n", "identity-app.automation-agents")):
        assert _ids(index.match_name(name)) == {owner}, name


def test_domain_suffix_spoofing_and_sk_prefixed_keys(index: SignatureIndex):
    assert index.match_domain("api.openai.com.evil.example") == []
    assert _ids(index.match_domains_in_text("https://api.openai.com.evil.example/v1")) == set()
    # Synthetic values in every vendor's sk- shape; each attributes exactly one owner.
    cases = {
        "sk-lf-12345678-1234-1234-1234-123456789abc": "observability.langfuse",
        "sk-litellm-" + "a" * 32: "platform.litellm",
        "sk-or-v1-" + "a" * 64: "provider.openrouter",
        "sk-ant-api03-" + "a" * 40: "provider.anthropic",
        "sk-proj-" + "a" * 48: "provider.openai",
        "sk-svcacct-" + "a" * 48: "provider.openai",
        "sk-" + "a" * 20 + "T3BlbkFJ" + "b" * 20: "provider.openai",
        "sk-" + "a" * 48: "heuristic.unattributed-api-key",
        "sk-" + "0123456789abcdef" * 2: "heuristic.unattributed-api-key",
    }
    for value, owner in cases.items():
        matches = index.match_secrets(f'API_KEY="{value}"')
        assert _ids(matches) == {owner}, value
    generic = index.match_secrets("sk-" + "a" * 48)
    assert generic[0].weight == 0.4 and generic[0].signature.category == "heuristic" and not generic[0].agent_indicator


def test_azure_openai_model_ids_need_azure_context(index: SignatureIndex):
    for model in ("gpt-4o", "o3-mini", "text-embedding-3-small"):
        assert _ids(index.match_model(model)) == {"provider.openai"}, model
    for model in ("azure/gpt-4o", "azure_openai/gpt-4o-mini", "https://acme.openai.azure.com/openai/deployments/gpt-4o"):
        assert "provider.azure-openai" in _ids(index.match_model(model)), model


def test_bedrock_needs_aws_context_outside_hostnames(index: SignatureIndex):
    assert index.match_user_agent("Minecraft Bedrock Dedicated Server/1.21") == []
    assert "provider.aws-bedrock" in _ids(index.match_user_agent("Boto3/1.34.0 md/Botocore#1.34.0 ua/2.0 cfg/retry-mode#legacy bedrock-runtime"))
    text = "We host a Minecraft Bedrock server on bedrock.example.com for the team\n"
    assert _ids(index.match_domains_in_text(text) + index.match_code(text) + index.match_name(text)) == set()


def test_shared_code_idioms_do_not_pin_a_framework(index: SignatureIndex):
    def code(text: str, language: str = "python"):
        return index.match_imports(text, language) + index.match_code(text, language)

    assert _ids(code("tool = CodeInterpreterTool()\n")) == {"heuristic.code-execution"}
    assert _ids(code("search = WebSearchTool()\n")) == {"heuristic.browsing"}
    generic = code("const a = new Agent({ name: 'x', instructions: 'y' });\n", "javascript")
    assert _ids(generic) == {"heuristic.agent-construction"} and not any(m.agent_indicator for m in generic)
    agno = code("from agno.agent import Agent\nagent = Agent(model=OpenAIChat(), tools=[])\n")
    assert "framework.agno" in _ids(agno) and "framework.aws-strands" not in _ids(agno)
    pydantic = code("from pydantic_ai import Agent\nagent = Agent(model='openai:gpt-4o', system_prompt='x')\n")
    assert "framework.pydantic-ai" in _ids(pydantic) and "framework.aws-strands" not in _ids(pydantic)
    assert "framework.aws-strands" in _ids(code("from strands import Agent\nagent = Agent(model=BedrockModel())\n"))
    memory = code("memory = MemorySaver()\n")
    assert "framework.langgraph" in _ids(memory) and "framework.langchain" not in _ids(memory)
    assert _ids(code("client = AzureAIAgentClient(project_client=client)\n")) == {"cloud.azure-ai-foundry-agents"}
    assert "framework.microsoft-agent-framework" in _ids(code("from agent_framework.azure import AzureAIAgentClient\n"))
    assert _ids(code("tool = BingGroundingTool(connection_id=conn)\n")) == {"cloud.azure-ai-foundry-agents"}
    assert _ids(code("adapter = CloudAdapter(ConfigurationBotFrameworkAuthentication(CONFIG))\n")) == {"framework.bot-framework"}
    assert _ids(code("ADAPTER = CloudAdapter(CONNECTION_MANAGER)\n")) == set()
    assert _ids(code("from microsoft_agents.hosting.core import AgentApplication, CloudAdapter\n")) == {"framework.m365-agents-sdk"}
    assert _ids(code("client = CopilotClient(settings, token)\n")) == {"platform.copilot-studio"}
    assert index.match_image("berriai/litellm:main-latest") and _ids(index.match_image("berriai/litellm:main-latest")) == {"platform.litellm"}
    codex = code("codex exec --dangerously-bypass-approvals-and-sandbox\n")
    assert Counter(m.signature_id for m in codex)["coding-agent.openai-codex"] == 2  # identity + autonomy signals, once each


# --------------------------------------------------------------- coverage
@pytest.mark.parametrize(
    ("ecosystem", "name", "expected", "agent"),
    [
        ("pypi", "llama-cpp-python", "provider.llama-cpp", False),
        ("pypi", "llamacpp", "provider.llama-cpp", False),
        ("npm", "node-llama-cpp", "provider.llama-cpp", False),
        ("pypi", "lmstudio", "provider.lm-studio", False),
        ("npm", "@lmstudio/sdk", "provider.lm-studio", False),
        ("pypi", "sglang", "provider.sglang", False),
        ("pypi", "guardrails-ai", "framework.guardrails-ai", False),
        ("pypi", "nemoguardrails", "framework.nemo-guardrails", False),
        ("pypi", "llm-guard", "framework.llm-guard", False),
        ("pypi", "llama-stack", "provider.llama-stack", False),
        ("pypi", "llama-stack-client", "provider.llama-stack", False),
        ("npm", "llama-stack-client", "provider.llama-stack", False),
        ("pypi", "llama-api-client", "provider.meta-llama-api", False),
        ("pypi", "dashscope", "provider.alibaba-dashscope", False),
        ("pypi", "qwen-agent", "framework.qwen-agent", True),
        ("pypi", "ai21", "provider.ai21", False),
        ("npm", "ai21", "provider.ai21", False),
        ("pypi", "ibm-watsonx-orchestrate", "platform.ibm-watsonx-orchestrate", True),
        ("pypi", "nvidia-nat", "framework.nvidia-nemo-agent-toolkit", True),
        ("pypi", "aiqtoolkit", "framework.nvidia-nemo-agent-toolkit", True),
        ("pypi", "dapr-agents", "framework.dapr-agents", True),
        ("pypi", "praisonaiagents", "framework.praisonai", True),
        ("pypi", "deepagents", "framework.deepagents", True),
        ("pypi", "sweagent", "framework.swe-agent", True),
        ("pypi", "gpt-engineer", "framework.gpt-engineer", True),
        ("pypi", "open-interpreter", "framework.open-interpreter", True),
        ("pypi", "chainlit", "framework.chainlit", False),
        ("pypi", "promptflow", "framework.promptflow", False),
    ],
)
def test_new_coverage_dependencies(index: SignatureIndex, ecosystem, name, expected, agent):
    matches = index.match_dependency(ecosystem, name)
    assert [m.signature_id for m in matches] == [expected], (ecosystem, name)
    assert matches[0].agent_indicator is agent


def test_new_coverage_imports_env_models_and_capabilities(index: SignatureIndex):
    imports = {
        "from llama_cpp import Llama\n": "provider.llama-cpp",
        "import sglang as sgl\n": "provider.sglang",
        "from guardrails import Guard\n": "framework.guardrails-ai",
        "from nemoguardrails import RailsConfig, LLMRails\n": "framework.nemo-guardrails",
        "from llm_guard import scan_prompt\n": "framework.llm-guard",
        "from llama_stack_client import LlamaStackClient\n": "provider.llama-stack",
        "import dashscope\n": "provider.alibaba-dashscope",
        "from qwen_agent.agents import Assistant\n": "framework.qwen-agent",
        "from ai21 import AI21Client\n": "provider.ai21",
        "from ibm_watsonx_orchestrate.agent_builder.agents import Agent\n": "platform.ibm-watsonx-orchestrate",
        "from nat.agent.react_agent import ReActAgent\n": "framework.nvidia-nemo-agent-toolkit",
        "from aiq.builder.builder import Builder\n": "framework.nvidia-nemo-agent-toolkit",
        "from dapr_agents import DurableAgent\n": "framework.dapr-agents",
        "from praisonaiagents import Agent\n": "framework.praisonai",
        "from deepagents import create_deep_agent\n": "framework.deepagents",
        "from sweagent.agent.agents import DefaultAgent\n": "framework.swe-agent",
        "from gpt_engineer.core.ai import AI\n": "framework.gpt-engineer",
        "from interpreter import interpreter\n": "framework.open-interpreter",
        "import chainlit as cl\n": "framework.chainlit",
        "from promptflow.core import Flow\n": "framework.promptflow",
    }
    for text, expected in imports.items():
        assert expected in _ids(index.match_imports(text, "python")), text
    assert "framework.open-interpreter" not in _ids(index.match_imports("from interpreter import Foo\n", "python"))
    assert "framework.nvidia-nemo-agent-toolkit" not in _ids(index.match_imports("import nat\n", "python"))
    envs = {
        "DASHSCOPE_API_KEY": "provider.alibaba-dashscope", "AI21_API_KEY": "provider.ai21", "MOONSHOT_API_KEY": "provider.moonshot",
        "LLAMA_STACK_BASE_URL": "provider.llama-stack", "WO_API_KEY": "platform.ibm-watsonx-orchestrate",
        "LMSTUDIO_BASE_URL": "provider.lm-studio", "LOCALAI_BASE_URL": "provider.localai", "CHAINLIT_AUTH_SECRET": "framework.chainlit",
    }
    for env, expected in envs.items():
        assert _ids(index.match_env(env)) == {expected}, env
    models = {"qwen-max": "provider.alibaba-dashscope", "kimi-k2": "provider.moonshot", "jamba-1.5-large": "provider.ai21"}
    for model, expected in models.items():
        assert expected in _ids(index.match_model(model)), model
    assert "provider.moonshot" in _ids(index.match_domain("api.moonshot.cn"))
    assert "provider.alibaba-dashscope" in _ids(index.match_domain("dashscope-intl.aliyuncs.com"))
    assert "provider.localai" in _ids(index.match_image("localai/localai:latest-aio-cpu"))
    assert "provider.llama-cpp" in _ids(index.match_image("ghcr.io/ggml-org/llama.cpp:server"))
    assert "framework.promptflow" in _ids(index.match_file("flows/chat/flow.dag.yaml"))
    assert "framework.chainlit" in _ids(index.match_file(".chainlit/config.toml"))
    interpreter = index.match_code("interpreter.auto_run = True\n", "python")
    assert "framework.open-interpreter" in _ids(interpreter)
    assert {"code-exec", "autonomous"} <= set(next(m for m in interpreter if m.signature_id == "framework.open-interpreter").capabilities())
    stack = index.match_code("from llama_stack_client import Agent\n", "python")
    assert any(m.signature_id == "provider.llama-stack" and m.agent_indicator for m in stack)


@pytest.mark.parametrize("ecosystem,name,expected", [
    ("pypi", "langchain-nomic", True),
    ("pypi", "langchain-google-cloud-sql-pg", True),
    ("pypi", "langchain-text-splitters", False),
    ("npm", "@langchain/nomic", True),
    ("npm", "@langchain/textsplitters", False),
    ("npm", "@langchain/langgraph", False),
    ("npm", "@langchain/langgraph-sdk", False),
])
def test_langchain_prefix_keeps_partners_and_carves_out_utilities(index, ecosystem, name, expected):
    ids = {m.signature_id for m in index.match_dependency(ecosystem, name)}
    assert ("framework.langchain" in ids) is expected, ids
    if name.startswith("@langchain/langgraph"):
        assert "framework.langgraph" in ids
