from __future__ import annotations

import random
import re
import string
from collections import Counter

import pytest
import regex

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.signatures import SignatureIndex, load_signatures
from shadowscan.signatures.loader import VALID_CATEGORIES, VALID_SIGNAL_TYPES
from shadowscan.signatures.matcher import language_for_path


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
    ids = {m.signature_id for m in index.match_imports(js, "javascript")} | {
        m.signature_id for m in index.match_code(js, "javascript")
    }
    assert {"framework.openai-agents-sdk", "protocol.mcp"} <= ids


def test_domain_user_agent_model_and_secret(index: SignatureIndex):
    # The API host is the provider; the identity-app signature's *.anthropic.com
    # wildcard matches it as well, by design, and nothing else may.
    anthropic = {m.signature_id for m in index.match_domain("api.anthropic.com")}
    assert anthropic == {"provider.anthropic", "identity-app.anthropic-claude"}
    assert "provider.aws-bedrock" in {
        m.signature_id for m in index.match_domain("bedrock-runtime.eu-west-1.amazonaws.com")
    }
    assert "cloud.aws-bedrock-agents" in {
        m.signature_id for m in index.match_domain("bedrock-agent-runtime.us-east-1.amazonaws.com")
    }
    assert "provider.azure-openai" in {m.signature_id for m in index.match_domain("acme.openai.azure.com")}
    assert "provider.ollama" in {m.signature_id for m in index.match_domain("localhost:11434")}
    ua = {m.signature_id for m in index.match_user_agent("crewai/0.80 OpenAI/Python 1.5")}
    assert {"framework.crewai", "provider.openai"} <= ua
    assert "provider.anthropic" in {m.signature_id for m in index.match_model("claude-sonnet-4-5")}
    assert "provider.aws-bedrock" in {
        m.signature_id for m in index.match_model("us.anthropic.claude-3-5-sonnet-20241022-v2:0")
    }
    assert "provider.google-gemini" in {m.signature_id for m in index.match_model("gemini-2.5-pro")}
    secrets = {
        m.signature_id
        for m in index.match_secrets(
            'KEY="sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH-ijklmnopqrstAA"'
        )
    }
    assert secrets == {"provider.anthropic"}
    assert {m.signature_id for m in index.match_secrets("gsk_" + "a" * 50)} == {"provider.groq"}


def test_file_env_scope_iac_and_names(index: SignatureIndex):
    assert "coding-agent.claude-code" in {
        m.signature_id for m in index.match_file(".claude/agents/reviewer.md")
    }
    assert "coding-agent.github-copilot" in {
        m.signature_id for m in index.match_file(".github/agents/planner.agent.md")
    }
    assert "protocol.a2a" in {m.signature_id for m in index.match_file("public/.well-known/agent.json")}
    assert "protocol.mcp" in {m.signature_id for m in index.match_file(".cursor/mcp.json")}
    assert "provider.openai" in {m.signature_id for m in index.match_env("OPENAI_API_KEY")}
    assert "heuristic.llm-env-names" in {m.signature_id for m in index.match_env("LLM_PROVIDER")}
    assert "policy.privileged-scopes" in {
        m.signature_id for m in index.match_scope("Directory.ReadWrite.All")
    }
    assert "policy.data-access-scopes" in {m.signature_id for m in index.match_scope("channels:history")}
    assert "policy.llm-access-scopes" in {m.signature_id for m in index.match_scope("bedrock:InvokeModel")}
    assert "cloud.aws-bedrock-agents" in {m.signature_id for m in index.match_iac("aws_bedrockagent_agent")}
    assert "cloud.gcp-vertex-agent-engine" in {
        m.signature_id for m in index.match_iac("google_dialogflow_cx_agent")
    }
    assert "identity-app.meeting-notetakers" in {
        m.signature_id for m in index.match_name("Otter.ai for Zoom")
    }
    assert "identity-app.openai-chatgpt" in {m.signature_id for m in index.match_name("ChatGPT")}
    assert "platform.n8n" in {m.signature_id for m in index.match_image("n8nio/n8n:1.60")}


def test_sab_holdout_file_dialects_are_inventory_only(index: SignatureIndex):
    cases = {
        "openclaw.json": "platform.openclaw",
        "clawdbot.json": "platform.openclaw",
        "moltbot.json": "platform.openclaw",
        "opencode.json": "coding-agent.misc-rules",
        "goose_config.yaml": "coding-agent.goose",
        "aider.conf.yml": "coding-agent.aider",
        "flowise.json": "platform.flowise",
        "dify.yml": "platform.dify",
        "SKILL.md": "coding-agent.agent-skills",
        "AGENTS.md": "coding-agent.agents-md",
        "agent-card.json": "protocol.a2a",
    }
    for filename, expected in cases.items():
        matches = index.match_file(filename)
        assert expected in _ids(matches), filename
    assert not index.get("platform.openclaw").agent_indicator
    # The personal agent's state directory, under each of its names, belongs to
    # the coding-agent signature alone.
    for state_file in (
        ".openclaw/openclaw.json",
        ".openclaw/config.json",
        "home/.clawdbot/clawdbot.json",
        "home/.clawdbot/config.json",
        ".moltbot/moltbot.json",
        "home/.moltbot/config.json",
    ):
        assert _ids(index.match_file(state_file)) >= {"coding-agent.openclaw"}, state_file
        assert "platform.openclaw" not in _ids(index.match_file(state_file)), state_file
    for other in ("config.json", "app/config.json", "openclaw/config.json"):
        assert "coding-agent.openclaw" not in _ids(index.match_file(other)), other
    assert not index.get("coding-agent.agent-skills").agent_indicator
    assert "platform.openclaw" in _ids(index.match_code("gateway.port: 18789"))
    assert "platform.flowise" in _ids(index.match_code('{"category":"Agents","name":"toolAgent"}'))
    assert "cloud.azure-ai-foundry-agents" in _ids(
        index.match_iac("Microsoft.CognitiveServices/accounts/projects/agents")
    )


@pytest.mark.parametrize(
    "value",
    ["", "${VAR}", "changeme", "your-key-here", "a" * 32, "abcdefghijklmnop"],
)
def test_empty_placeholder_and_low_entropy_credentials_do_not_match(index: SignatureIndex, value: str):
    assert index.match_secrets(f"OPENAI_API_KEY={value}") == []


def test_high_entropy_assigned_credential_is_matched(index: SignatureIndex):
    value = "R4nd0m9Qx2Vb7Lp6"
    matches = index.match_secrets(f"OPENAI_API_KEY={value}")
    assert [match.signature_id for match in matches] == ["heuristic.inline-credential"]


def test_signature_categories_cover_all_surfaces(index: SignatureIndex):
    counts = Counter(s.category for s in index.signatures.values())
    for cat in (
        "framework",
        "provider",
        "protocol",
        "coding-agent",
        "platform",
        "cloud-service",
        "identity-app",
        "policy",
        "heuristic",
    ):
        assert counts[cat] >= 3, cat


# ------------------------------------------------------------ hard negatives
@pytest.mark.parametrize(
    ("ecosystem", "name"),
    [
        ("pypi", "openapi"),
        ("pypi", "openapi-generator"),
        ("pypi", "azure-storage-blob"),
        ("pypi", "imagenai"),
        ("pypi", "gemini-python"),
        ("pypi", "python-telegram-bot"),
        ("npm", "user-agent"),
        ("pypi", "crew"),
        ("npm", "@langchainx/textsplitters"),
        ("pypi", "langchainx"),
        ("pypi", "langchain4j"),
    ],
)
def test_lookalike_dependencies_do_not_match(index: SignatureIndex, ecosystem, name):
    assert index.match_dependency(ecosystem, name) == []


def test_langchain_text_splitters_is_a_utility_not_framework_usage(index: SignatureIndex):
    for eco, name in (("pypi", "langchain-text-splitters"), ("npm", "@langchain/textsplitters")):
        matches = index.match_dependency(eco, name)
        assert [m.signature_id for m in matches] == ["framework.langchain-utilities"], (eco, name)
        assert all(m.weight <= 0.35 and not m.agent_indicator for m in matches)
    utility = index.match_imports(
        "from langchain_text_splitters import RecursiveCharacterTextSplitter\n", "python"
    )
    assert _ids(utility) == {"framework.langchain-utilities"}
    # The integration package also attributes the model provider it wraps.
    assert _ids(index.match_imports("from langchain_openai import ChatOpenAI\n", "python")) == {
        "framework.langchain",
        "provider.openai",
    }
    assert "framework.langchain" in _ids(index.match_dependency("pypi", "langchain-openai"))


@pytest.mark.parametrize(
    "display_name",
    [
        "Mistral Dubois",
        "Graphite Metrics",
        "Devin Smith",
        "Otter Insurance Portal",
        "Jules Verne Book Club",
        "copilot-css",
        "copilot-theme",
        "cursor position",
        "Sweep the floor",
        "Codex Manuscripts",
        "Amp Hours Calculator",
        "Jasper Johns exhibition",
        "Monica Geller",
        "Harvey Specter",
        "Kimi Antonelli fan page",
        "Grok pattern library",
        "Edgar Allan Poe",
        "Gong Show archive",
        "Drift Racing League",
        "Clay Pottery Studio",
        "Minecraft Bedrock Edition server",
        "Palantir Foundry",
        "Sierra Nevada trip",
        "Warp Drive Physics",
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
    for name, owner in (
        ("Windsurf", "identity-app.coding-assistants-saas"),
        ("Zapier", "identity-app.automation-agents"),
        ("n8n", "identity-app.automation-agents"),
    ):
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
    assert (
        generic[0].weight == 0.4
        and generic[0].signature.category == "heuristic"
        and not generic[0].agent_indicator
    )


def test_short_unattributed_sk_keys_are_reported_only_when_random(index: SignatureIndex):
    rng = random.Random(20261006)
    alphabet = string.ascii_letters + string.digits
    for length in (20, 22, 31):
        # A digit and a letter at the end keep the synthetic body unambiguous.
        key = "sk-" + "".join(rng.choice(alphabet) for _ in range(length - 2)) + "7q"
        for text in (
            f'client = OpenAI(api_key="{key}")',
            f"Authorization: Bearer {key}",
            f'{{"apiKey": "{key}"}}',
            f"api_key: {key}",
        ):
            matches = index.match_secrets(text)
            assert [(m.signature_id, m.value) for m in matches] == [("heuristic.unattributed-api-key", key)]
        # An assignment the generic rule already reports keeps that match and its weight.
        [assigned] = index.match_secrets(f"OPENAI_API_KEY={key}")
        assert (assigned.signature_id, assigned.weight) == ("heuristic.inline-credential", 0.8)
    assert index.match_secrets("token sk-" + "aB3dE5gH7jK9mN1pQ2s") == []  # 19 characters
    for lookalike in (
        "PubkeyAcceptedAlgorithms sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
        "PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com",
        '<div class="sk-folding-cube-spinner-wrap"></div>',
        "git checkout -b sk-1234-fix-the-login-page",
        "api_key = 'sk-" + "x" * 24 + "'",
        "api_key = 'sk-" + "1234567890abcdefghijkl" + "'",
        "api_key = 'sk-" + "abc123def456ghi789jkl0" + "'",
    ):
        assert index.match_secrets(lookalike) == [], lookalike
    # A short match never takes the prefix of a longer hyphenated key.
    longer = "sk-" + "Zx81Kq0Lm2Np4Rs6Tv8Wy" + "-" + "Ab1Cd3Ef5Gh7Ij9Kl"
    assert [m.value for m in index.match_secrets(f"key: {longer}")] == [longer]
    # A rejected look-alike does not hide the generic match of the same value.
    mixed = "sk-" + "AbCdEfGhIjKlMnOpQrStUv"
    assert _ids(index.match_secrets(f"MY_API_KEY={mixed}")) == {"heuristic.inline-credential"}


def test_azure_openai_model_ids_need_azure_context(index: SignatureIndex):
    for model in ("gpt-4o", "o3-mini", "text-embedding-3-small"):
        assert _ids(index.match_model(model)) == {"provider.openai"}, model
    for model in (
        "azure/gpt-4o",
        "azure_openai/gpt-4o-mini",
        "https://acme.openai.azure.com/openai/deployments/gpt-4o",
    ):
        assert "provider.azure-openai" in _ids(index.match_model(model)), model


def test_bedrock_needs_aws_context_outside_hostnames(index: SignatureIndex):
    assert index.match_user_agent("Minecraft Bedrock Dedicated Server/1.21") == []
    assert "provider.aws-bedrock" in _ids(
        index.match_user_agent("Boto3/1.34.0 md/Botocore#1.34.0 ua/2.0 cfg/retry-mode#legacy bedrock-runtime")
    )
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
    pydantic = code(
        "from pydantic_ai import Agent\nagent = Agent(model='openai:gpt-4o', system_prompt='x')\n"
    )
    assert "framework.pydantic-ai" in _ids(pydantic) and "framework.aws-strands" not in _ids(pydantic)
    assert "framework.aws-strands" in _ids(
        code("from strands import Agent\nagent = Agent(model=BedrockModel())\n")
    )
    memory = code("memory = MemorySaver()\n")
    assert "framework.langgraph" in _ids(memory) and "framework.langchain" not in _ids(memory)
    assert _ids(code("client = AzureAIAgentClient(project_client=client)\n")) == {
        "cloud.azure-ai-foundry-agents"
    }
    assert "framework.microsoft-agent-framework" in _ids(
        code("from agent_framework.azure import AzureAIAgentClient\n")
    )
    assert _ids(code("tool = BingGroundingTool(connection_id=conn)\n")) == {"cloud.azure-ai-foundry-agents"}
    assert _ids(code("adapter = CloudAdapter(ConfigurationBotFrameworkAuthentication(CONFIG))\n")) == {
        "framework.bot-framework"
    }
    assert _ids(code("ADAPTER = CloudAdapter(CONNECTION_MANAGER)\n")) == set()
    assert _ids(code("from microsoft_agents.hosting.core import AgentApplication, CloudAdapter\n")) == {
        "framework.m365-agents-sdk"
    }
    assert _ids(code("client = CopilotClient(settings, token)\n")) == {"platform.copilot-studio"}
    assert index.match_image("berriai/litellm:main-latest") and _ids(
        index.match_image("berriai/litellm:main-latest")
    ) == {"platform.litellm"}
    codex = code("codex exec --dangerously-bypass-approvals-and-sandbox\n")
    assert (
        Counter(m.signature_id for m in codex)["coding-agent.openai-codex"] == 2
    )  # identity + autonomy signals, once each


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
    assert "framework.open-interpreter" not in _ids(
        index.match_imports("from interpreter import Foo\n", "python")
    )
    assert "framework.nvidia-nemo-agent-toolkit" not in _ids(index.match_imports("import nat\n", "python"))
    envs = {
        "DASHSCOPE_API_KEY": "provider.alibaba-dashscope",
        "AI21_API_KEY": "provider.ai21",
        "MOONSHOT_API_KEY": "provider.moonshot",
        "LLAMA_STACK_BASE_URL": "provider.llama-stack",
        "WO_API_KEY": "platform.ibm-watsonx-orchestrate",
        "LMSTUDIO_BASE_URL": "provider.lm-studio",
        "LOCALAI_BASE_URL": "provider.localai",
        "CHAINLIT_AUTH_SECRET": "framework.chainlit",
    }
    for env, expected in envs.items():
        assert _ids(index.match_env(env)) == {expected}, env
    models = {
        "qwen-max": "provider.alibaba-dashscope",
        "kimi-k2": "provider.moonshot",
        "jamba-1.5-large": "provider.ai21",
    }
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
    assert {"code-exec", "autonomous"} <= set(
        next(m for m in interpreter if m.signature_id == "framework.open-interpreter").capabilities()
    )
    stack = index.match_code("from llama_stack_client import Agent\n", "python")
    assert any(m.signature_id == "provider.llama-stack" and m.agent_indicator for m in stack)


@pytest.mark.parametrize(
    "ecosystem,name,expected",
    [
        ("pypi", "langchain-nomic", True),
        ("pypi", "langchain-google-cloud-sql-pg", True),
        ("pypi", "langchain-text-splitters", False),
        ("npm", "@langchain/nomic", True),
        ("npm", "@langchain/textsplitters", False),
        ("npm", "@langchain/langgraph", False),
        ("npm", "@langchain/langgraph-sdk", False),
    ],
)
def test_langchain_prefix_keeps_partners_and_carves_out_utilities(index, ecosystem, name, expected):
    ids = {m.signature_id for m in index.match_dependency(ecosystem, name)}
    assert ("framework.langchain" in ids) is expected, ids
    if name.startswith("@langchain/langgraph"):
        assert "framework.langgraph" in ids


def _scan(index, root, files: dict[str, str], **config):
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    ctx = ConnectorContext(config={"path": str(root), "use_git": False, **config}, index=index)
    return FilesystemConnector(ctx).run(), ctx


@pytest.mark.parametrize(
    "client",
    [
        'boto3.client("bedrock-agent-runtime", region_name="us-east-1")',
        'boto3.client(service_name="bedrock-agent-runtime", region_name="us-east-1")',
        'boto3.client(region_name="us-east-1", service_name="bedrock-agent-runtime")',
    ],
)
def test_bedrock_agent_clients_corroborate_invoke_agent(tmp_path, index, client):
    findings, _ = _scan(
        index,
        tmp_path,
        {
            "agent.py": (
                "import boto3\n\n"
                f"client = {client}\n"
                'response = client.invoke_agent(agentId="A1", agentAliasId="B1", sessionId="s", inputText="hi")\n'
            )
        },
    )
    assert any("cloud.aws-bedrock-agents" in f.frameworks for f in findings)


@pytest.mark.parametrize(
    "text",
    [
        'boto3.client(service_name="bedrock-agentcore", region_name="us-east-1")',
        "session.client(region_name=region, service_name='bedrock-agentcore-control')",
    ],
)
def test_agentcore_clients_match_by_keyword(index, text):
    assert any(m.signature_id == "cloud.aws-bedrock-agents" for m in index.match_code(text, "python"))


def test_genai_vertex_switch_is_not_agent_development_kit_evidence(index) -> None:
    vertex = {m.signature_id for m in index.match_env("GOOGLE_GENAI_USE_VERTEXAI")}
    assert "framework.google-adk" not in vertex
    assert "provider.google-vertex-ai" in vertex
    assert "framework.google-adk" in {m.signature_id for m in index.match_env("ADK_API_KEY")}


# ------------------------------------------------------------ language gates
def test_language_bound_framework_idioms_do_not_match_other_languages(index: SignatureIndex) -> None:
    rust = "pub trait ToolCallback {\n    fn call(&self, input: &str) -> String;\n}\n"
    assert "framework.spring-ai" not in _ids(index.match_code(rust, "rust"))
    assert "framework.spring-ai" not in _ids(index.match_code(rust, "go"))
    java = "import org.springframework.ai.tool.ToolCallback;\n\nToolCallback callback = provider.get();\n"
    assert "framework.spring-ai" in _ids(index.match_code(java, "java"))
    # Kotlin and Scala sources classify as java, so the gate admits them.
    assert language_for_path("src/main/kotlin/Agent.kt") == "java"
    assert "framework.spring-ai" in _ids(index.match_code("val cb: ToolCallback = provider.get()\n", "java"))
    # The gate applies only when the caller knows the language: configuration
    # projections and `signatures test` pass none and run every pattern.
    assert "framework.spring-ai" in _ids(index.match_code(rust))
    # Other single-language idioms.
    csharp = "builder.Services.AddMcpServer().WithStdioServerTransport();\n"
    assert "protocol.mcp" in _ids(index.match_code(csharp, "dotnet"))
    assert "protocol.mcp" not in _ids(index.match_code(csharp, "python"))
    go = 's := server.NewMCPServer("demo", "1.0.0")\n'
    assert "protocol.mcp" in _ids(index.match_code(go, "go"))
    assert "protocol.mcp" not in _ids(index.match_code(go, "javascript"))
    kernel = "[KernelFunction]\npublic string Lookup(string id) => id;\n"
    assert "framework.semantic-kernel" in _ids(index.match_code(kernel, "dotnet"))
    assert "framework.semantic-kernel" not in _ids(index.match_code(kernel, "python"))
    assert "framework.semantic-kernel" in _ids(
        index.match_code("@kernel_function\ndef lookup(): ...\n", "python")
    )
    assert "framework.rig" not in _ids(index.match_code("class AgentBuilder:\n    pass\n", "python"))
    assert "framework.rig" in _ids(index.match_code("let agent = AgentBuilder::new(model);\n", "rust"))


def test_kotlin_koog_framework_matches_through_the_java_language(index: SignatureIndex) -> None:
    koog = index.get("framework.koog")
    assert koog is not None and koog.agent_indicator and "tool-use" in koog.capabilities
    for name in ("ai.koog:koog-agents", "ai.koog:agents-core", "ai.koog:prompt-executor-openai-client"):
        [match] = index.match_dependency("maven", name)
        assert match.signature_id == "framework.koog", name
    statement = "import ai.koog.agents.core.agent.AIAgent\n"
    assert _ids(index.match_imports(statement, language_for_path("Agent.kt"))) == {"framework.koog"}
    assert "framework.koog" not in _ids(index.match_imports(statement, "python"))


# ------------------------------------------------------- MCP server / client
def test_mcp_server_idioms_carry_the_mcp_server_capability(index: SignatureIndex) -> None:
    servers = [
        ("python", 'mcp = FastMCP("demo")\n'),
        ("python", 'server = mcp.server.Server("demo")\n'),
        ("python", "@mcp.tool()\ndef add(a: int, b: int) -> int:\n    return a + b\n"),
        ("python", "async with stdio_server() as (read, write):\n    pass\n"),
        ("python", "mcp.run(transport='stdio')\n"),
        ("javascript", 'const server = new McpServer({ name: "demo", version: "1.0.0" });\n'),
        ("javascript", "const transport = new StdioServerTransport();\n"),
        ("javascript", 'server.registerTool("add", { description: "x" }, handler);\n'),
        ("go", 's := server.NewMCPServer("demo", "1.0.0")\n'),
        ("go", 'srv := mcp.NewServer(&mcp.Implementation{Name: "demo"}, nil)\n'),
        ("dotnet", "builder.Services.AddMcpServer().WithStdioServerTransport();\n"),
        ("dotnet", '[McpServerTool, Description("Adds two numbers")]\n'),
        ("dotnet", "var server = McpServer.Create(transport, options);\n"),
        ("java", "McpSyncServer server = McpServer.sync(transport).build();\n"),
        ("java", "McpAsyncServer server = McpServer.async(transport).build();\n"),
        ("rust", "impl ServerHandler for Counter {\n"),
    ]
    for language, text in servers:
        matches = [m for m in index.match_code(text, language) if m.signature_id == "protocol.mcp"]
        assert matches, (language, text)
        assert all("mcp-server" in m.capabilities() for m in matches), (language, text)
        assert any(not m.signal.ambiguous and m.weight == 0.9 for m in matches), (language, text)
    # Client idioms only consume servers: no capability beyond the signature's tool-use.
    client = (
        "async with stdio_client(params) as (read, write):\n"
        "    async with ClientSession(read, write) as session:\n"
        "        await session.initialize()\n"
        "tools = MultiServerMCPClient(servers)\n"
    )
    mcp = [m for m in index.match_code(client, "python") if m.signature_id == "protocol.mcp"]
    assert mcp and not any("mcp-server" in m.capabilities() for m in mcp)
    assert all(m.capabilities() == ["tool-use"] for m in mcp)


def test_mcp_server_idioms_match_only_in_their_language(index: SignatureIndex) -> None:
    rust = "impl ServerHandler for Counter {\n"
    assert "protocol.mcp" in _ids(index.match_code(rust, "rust"))
    assert not [m for m in index.match_code(rust, "python") if m.signature_id == "protocol.mcp"]
    assert not [m for m in index.match_code(rust, "javascript") if m.signature_id == "protocol.mcp"]
    java = "McpSyncServer server = McpServer.sync(transport).build();\n"
    assert "protocol.mcp" in _ids(index.match_code(java, "java"))
    for language in ("python", "javascript", "go", "dotnet", "rust"):
        assert not [m for m in index.match_code(java, language) if m.signature_id == "protocol.mcp"], language
    # Kotlin sources classify as java, so the gate admits them.
    assert "protocol.mcp" in _ids(index.match_code(java, language_for_path("Server.kt")))


def test_bare_server_class_is_ambiguous_mcp_server_evidence(index: SignatureIndex) -> None:
    # The low-level SDK class shares its name with every HTTP server class, so
    # the pattern is ambiguous: the code connector counts it only with an MCP
    # import, dependency or specific code match in the same project.
    for text, language in (
        ('server = Server("demo")\n', "python"),
        ('const server = new Server({ name: "demo" }, {});\n', "javascript"),
    ):
        matches = [m for m in index.match_code(text, language) if m.signature_id == "protocol.mcp"]
        assert matches, text
        assert all(
            m.signal.ambiguous and m.weight == 0.6 and "mcp-server" in m.capabilities() for m in matches
        )
    # Other servers never match the MCP pattern at all.
    for text in (
        "httpd = http.server.HTTPServer(('', 8000), Handler)\n",
        "server = HTTPServer(addr, Handler)\n",
        "const app = new WebSocketServer({ port: 8080 });\n",
        "class McpServer(Server):\n    pass\n",
    ):
        assert not [m for m in index.match_code(text, "python") if m.signature_id == "protocol.mcp"], text
    signature = index.get("protocol.mcp")
    assert signature is not None
    # Every signature with an ambiguous signal also declares library evidence.
    assert any(s.type in {"import", "dependency"} for s in signature.signals)


# ---------------------------------------------------- OpenAI-compatible shape
def test_bare_openai_request_shape_is_ambiguous_without_the_sdk(index: SignatureIndex) -> None:
    text = 'response = client.chat.completions.create(model="m", messages=[])\n'
    openai = [m for m in index.match_code(text, "python") if m.signature_id == "provider.openai"]
    assert openai and all(m.signal.ambiguous for m in openai)
    responses = [
        m
        for m in index.match_code("client.responses.create(input=x)\n", "python")
        if m.signature_id == "provider.openai"
    ]
    assert responses and all(m.signal.ambiguous for m in responses)
    # The Assistants shapes are OpenAI's alone and stay unambiguous.
    assistants = [
        m
        for m in index.match_code("client.beta.assistants.create(model='m')\n", "python")
        if m.signature_id == "provider.openai"
    ]
    assert assistants and not any(m.signal.ambiguous for m in assistants)
    # provider.openai-compatible reports the same shape at low weight, and only
    # next to a base-URL override of its own: the shape is ambiguous there too.
    compatible = [
        m for m in index.match_code(text, "python") if m.signature_id == "provider.openai-compatible"
    ]
    assert compatible and all(m.weight == 0.5 and m.signal.ambiguous for m in compatible)


def test_openai_client_with_a_base_url_is_openai_compatible_evidence(index: SignatureIndex) -> None:
    constructed = 'client = OpenAI(\n    api_key=os.getenv("LLM_API_KEY"),\n    base_url=os.getenv("LLM_BASE_URL"),\n)\n'
    overrides = [
        m for m in index.match_code(constructed, "python") if m.signature_id == "provider.openai-compatible"
    ]
    # The override itself is specific evidence and stays unambiguous.
    assert overrides and not any(m.signal.ambiguous for m in overrides)
    assert "provider.openai-compatible" in _ids(
        index.match_code("client = AsyncOpenAI(base_url=settings.llm_url, api_key=settings.key)\n", "python")
    )
    js = "const client = new OpenAI({ apiKey: process.env.KEY, baseURL: process.env.LLM_URL });\n"
    assert "provider.openai-compatible" in _ids(index.match_code(js, "javascript"))
    # The window closes at the constructor's closing parenthesis: a later
    # assignment of the same name is not the client's base URL, and Azure's
    # client is its own signature.
    later = "client = OpenAI()\nx = 1\nbase_url = settings.llm_url\n"
    assert "provider.openai-compatible" not in _ids(index.match_code(later, "python"))
    azure = "client = AzureOpenAI(azure_endpoint=endpoint, api_key=key)\n"
    assert "provider.openai-compatible" not in _ids(index.match_code(azure, "python"))


# ------------------------------------------- Claude on Bedrock and Vertex AI
def test_claude_platform_clients_attribute_the_platform(index: SignatureIndex) -> None:
    bedrock = "from anthropic import AnthropicBedrock\n\nclient = AnthropicBedrock(aws_region='us-east-1')\n"
    ids = _ids(index.match_imports(bedrock, "python") + index.match_code(bedrock, "python"))
    assert {"provider.aws-bedrock", "provider.anthropic"} <= ids
    assert _ids(index.match_code("client = AnthropicBedrock()\n", "python")) == {"provider.aws-bedrock"}
    vertex = "from anthropic import AnthropicVertex\n\nclient = AnthropicVertex(region='us-east5', project_id='p')\n"
    ids = _ids(index.match_imports(vertex, "python") + index.match_code(vertex, "python"))
    assert {"provider.google-vertex-ai", "provider.anthropic"} <= ids
    assert _ids(index.match_code("client = AnthropicVertex()\n", "python")) == {"provider.google-vertex-ai"}
    js = 'import AnthropicBedrock from "@anthropic-ai/bedrock-sdk";\n'
    assert {"provider.aws-bedrock", "provider.anthropic"} <= _ids(index.match_imports(js, "javascript"))
    assert "provider.aws-bedrock" in _ids(index.match_dependency("npm", "@anthropic-ai/bedrock-sdk"))
    assert "provider.google-vertex-ai" in _ids(index.match_dependency("npm", "@anthropic-ai/vertex-sdk"))
    assert {"provider.anthropic", "provider.aws-bedrock"} <= _ids(index.match_env("CLAUDE_CODE_USE_BEDROCK"))
    assert {"provider.anthropic", "provider.google-vertex-ai"} <= _ids(
        index.match_env("CLAUDE_CODE_USE_VERTEX")
    )
    assert _ids(index.match_env("AWS_BEARER_TOKEN_BEDROCK")) == {"provider.aws-bedrock"}
    java = "BedrockRuntimeClient client = BedrockRuntimeClient.builder().region(Region.US_EAST_1).build();\n"
    assert "provider.aws-bedrock" in _ids(index.match_code(java, "java"))
    assert "provider.aws-bedrock" in _ids(
        index.match_code('client = session.client("bedrock-runtime")\n', "python")
    )
    assert "provider.aws-bedrock" in _ids(index.match_dependency("cargo", "aws-sdk-bedrockruntime"))


# ---------------------------------------------------- JVM and long-tail SDKs
def test_jvm_integration_modules_attribute_framework_and_provider(index: SignatureIndex) -> None:
    dependencies = {
        ("maven", "dev.langchain4j:langchain4j-anthropic"): {"framework.langchain4j", "provider.anthropic"},
        ("maven", "dev.langchain4j:langchain4j-open-ai"): {"framework.langchain4j", "provider.openai"},
        ("maven", "dev.langchain4j:langchain4j-azure-open-ai"): {
            "framework.langchain4j",
            "provider.azure-openai",
        },
        ("maven", "dev.langchain4j:langchain4j-bedrock"): {"framework.langchain4j", "provider.aws-bedrock"},
        ("maven", "dev.langchain4j:langchain4j-vertex-ai-gemini"): {
            "framework.langchain4j",
            "provider.google-vertex-ai",
        },
        ("maven", "dev.langchain4j:langchain4j-google-ai-gemini"): {
            "framework.langchain4j",
            "provider.google-gemini",
        },
        ("maven", "dev.langchain4j:langchain4j-cohere"): {"framework.langchain4j", "provider.cohere"},
        ("maven", "dev.langchain4j:langchain4j-hugging-face"): {
            "framework.langchain4j",
            "provider.huggingface",
        },
        ("maven", "dev.langchain4j:langchain4j-ollama"): {"framework.langchain4j", "provider.ollama"},
        ("maven", "dev.langchain4j:langchain4j-mistral-ai"): {"framework.langchain4j", "provider.mistral"},
        ("maven", "dev.langchain4j:langchain4j-voyage-ai"): {"framework.langchain4j", "provider.voyage-ai"},
        ("maven", "dev.langchain4j:langchain4j-mcp"): {"framework.langchain4j", "protocol.mcp"},
        ("maven", "org.springframework.ai:spring-ai-starter-model-anthropic"): {
            "framework.spring-ai",
            "provider.anthropic",
        },
        ("maven", "org.springframework.ai:spring-ai-starter-model-bedrock-converse"): {
            "framework.spring-ai",
            "provider.aws-bedrock",
        },
        ("maven", "org.springframework.ai:spring-ai-starter-model-vertex-ai-gemini"): {
            "framework.spring-ai",
            "provider.google-vertex-ai",
        },
        ("maven", "org.springframework.ai:spring-ai-ollama"): {"framework.spring-ai", "provider.ollama"},
        ("maven", "org.springframework.ai:spring-ai-starter-mcp-server-webmvc"): {
            "framework.spring-ai",
            "protocol.mcp",
        },
        ("maven", "org.springframework.ai:spring-ai-mcp-annotations"): {
            "framework.spring-ai",
            "protocol.mcp",
        },
        ("nuget", "OllamaSharp"): {"provider.ollama"},
        ("npm", "voyageai"): {"provider.voyage-ai"},
        ("npm", "voyage-ai-provider"): {"provider.voyage-ai"},
        ("npm", "@xenova/transformers"): {"provider.huggingface"},
    }
    for (ecosystem, name), expected in dependencies.items():
        assert _ids(index.match_dependency(ecosystem, name)) == expected, name
    imports = {
        ("import dev.langchain4j.model.ollama.OllamaChatModel;\n", "java"): {
            "framework.langchain4j",
            "provider.ollama",
        },
        ("import dev.langchain4j.model.anthropic.AnthropicChatModel;\n", "java"): {
            "framework.langchain4j",
            "provider.anthropic",
        },
        ("import dev.langchain4j.mcp.McpToolProvider;\n", "java"): {"framework.langchain4j", "protocol.mcp"},
        ("import org.springframework.ai.bedrock.converse.BedrockProxyChatModel;\n", "java"): {
            "framework.spring-ai",
            "provider.aws-bedrock",
        },
        ("using OllamaSharp;\n", "dotnet"): {"provider.ollama"},
        ("import voyageai\n", "python"): {"provider.voyage-ai"},
        ('import { pipeline } from "@xenova/transformers";\n', "javascript"): {"provider.huggingface"},
        ('import { HfInference } from "@huggingface/inference";\n', "javascript"): {"provider.huggingface"},
        ('import { Stagehand } from "@browserbasehq/stagehand";\n', "javascript"): {"framework.stagehand"},
        ('import Browserbase from "@browserbasehq/sdk";\n', "javascript"): {"platform.browserbase"},
        ("from browserbase import Browserbase\n", "python"): {"platform.browserbase"},
        ("from stagehand import Stagehand, StagehandConfig\n", "python"): {"framework.stagehand"},
    }
    for (statement, language), expected in imports.items():
        assert _ids(index.match_imports(statement, language)) == expected, statement
    assert "provider.voyage-ai" in _ids(index.match_code("vo = voyageai.Client()\n", "python"))
    assert "provider.ollama" in _ids(
        index.match_code('OLLAMA = "http://host.docker.internal:11434"\n', "python")
    )
    stagehand = index.match_code('const stagehand = new Stagehand({ env: "LOCAL" });\n', "javascript")
    assert _ids(stagehand) == {"framework.stagehand"}
    assert "framework.stagehand" in _ids(
        index.match_code("stagehand = Stagehand(StagehandConfig(env='LOCAL'))\n", "python")
    )
