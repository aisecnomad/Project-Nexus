"""Tool-neutral discovery facts and the alias tables that map names onto them.

A *fact* is ``<category>:<value>``. Categories are the kinds of evidence any
code-surface discovery tool could surface from a repository checkout:

* ``framework`` - an agent or LLM orchestration framework is a declared
  dependency or is imported (``framework:langgraph``).
* ``provider`` - a model provider SDK, endpoint or managed runtime is used
  (``provider:openai``, ``provider:ollama``).
* ``mcp`` - Model Context Protocol: ``mcp:sdk`` (an MCP SDK dependency or
  import) and ``mcp:server`` (a server construct in code).
* ``mcp-client-config`` - a committed MCP client configuration file, valued by
  the client it belongs to (``mcp-client-config:cursor``).
* ``agent-config`` - coding-agent instruction or configuration surfaces
  (``agent-config:claude-md``, ``agent-config:agents-md``).
* ``a2a`` - Agent-to-Agent protocol: ``a2a:sdk`` or ``a2a:agent-card``.
* ``lowcode`` - an exported low-code flow with AI steps (``lowcode:n8n``).
* ``iac`` - infrastructure as code provisioning managed AI or agent resources
  (``iac:bedrock``, ``iac:azure-openai``, ``iac:vertex-ai``).

Alias rules translate ecosystem package names, import paths and free-text
names into facts. The same table labels ground truth from manifests and
imports and normalizes tool output, so both sides share one vocabulary; it is
independent of every tool under test, including ShadowScan's signature packs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

CATEGORIES: tuple[str, ...] = (
    "framework",
    "provider",
    "mcp",
    "mcp-client-config",
    "agent-config",
    "a2a",
    "lowcode",
    "iac",
)

_FACT = re.compile(r"[a-z][a-z0-9-]*:[a-z0-9][a-z0-9.-]*\Z")


def is_fact(value: str) -> bool:
    """Return whether ``value`` is a well-formed fact in a known category."""
    return bool(_FACT.match(value)) and value.split(":", 1)[0] in CATEGORIES


def category(fact: str) -> str:
    return fact.split(":", 1)[0]


@dataclass(frozen=True)
class Rule:
    """One alias: a regular expression over a normalized name in an ecosystem."""

    ecosystem: str
    pattern: str
    facts: tuple[str, ...]


def _r(ecosystem: str, pattern: str, *facts: str) -> Rule:
    return Rule(ecosystem, pattern, facts)


# Provider shorthands keep the table readable.
_OPENAI = "provider:openai"
_ANTHROPIC = "provider:anthropic"
_GEMINI = "provider:google-gemini"
_VERTEX = "provider:vertex-ai"
_BEDROCK = "provider:bedrock"
_AZURE = "provider:azure-openai"
_MISTRAL = "provider:mistral"
_COHERE = "provider:cohere"
_GROQ = "provider:groq"
_OLLAMA = "provider:ollama"
_HF = "provider:huggingface"
_TOGETHER = "provider:together"
_FIREWORKS = "provider:fireworks"
_DEEPSEEK = "provider:deepseek"
_XAI = "provider:xai"
_PERPLEXITY = "provider:perplexity"
_OPENROUTER = "provider:openrouter"
_REPLICATE = "provider:replicate"
_CEREBRAS = "provider:cerebras"
_VOYAGE = "provider:voyage"
_VLLM = "provider:vllm"
_LLAMACPP = "provider:llama-cpp"
_NVIDIA = "provider:nvidia-nim"
_LC4J = "framework:langchain4j"
_SPRING = "framework:spring-ai"
_SK = "framework:semantic-kernel"

RULES: tuple[Rule, ...] = (
    # ---- PyPI distribution names (normalized: lowercase, '_' -> '-') ----
    _r("pypi", r"langchain-openai", "framework:langchain", _OPENAI),
    _r("pypi", r"langchain-anthropic", "framework:langchain", _ANTHROPIC),
    _r("pypi", r"langchain-google-genai", "framework:langchain", _GEMINI),
    _r("pypi", r"langchain-google-vertexai", "framework:langchain", _VERTEX),
    _r("pypi", r"langchain-aws", "framework:langchain", _BEDROCK),
    _r("pypi", r"langchain-mistralai", "framework:langchain", _MISTRAL),
    _r("pypi", r"langchain-cohere", "framework:langchain", _COHERE),
    _r("pypi", r"langchain-groq", "framework:langchain", _GROQ),
    _r("pypi", r"langchain-ollama", "framework:langchain", _OLLAMA),
    _r("pypi", r"langchain-huggingface", "framework:langchain", _HF),
    _r("pypi", r"langchain-together", "framework:langchain", _TOGETHER),
    _r("pypi", r"langchain-fireworks", "framework:langchain", _FIREWORKS),
    _r("pypi", r"langchain-deepseek", "framework:langchain", _DEEPSEEK),
    _r("pypi", r"langchain-xai", "framework:langchain", _XAI),
    _r("pypi", r"langchain-perplexity", "framework:langchain", _PERPLEXITY),
    _r("pypi", r"langchain-nvidia-ai-endpoints", "framework:langchain", _NVIDIA),
    _r("pypi", r"langchain-mcp-adapters", "framework:langchain", "mcp:sdk"),
    _r("pypi", r"langchain(-[a-z0-9.-]+)?", "framework:langchain"),
    _r("pypi", r"langgraph(-[a-z0-9.-]+)?", "framework:langgraph"),
    _r("pypi", r"langsmith", "framework:langchain"),
    _r("pypi", r"crewai(-tools)?", "framework:crewai"),
    _r("pypi", r"(pyautogen|autogen|autogen-agentchat|autogen-core|autogen-ext|ag2)", "framework:autogen"),
    _r("pypi", r"openai-agents", "framework:openai-agents", _OPENAI),
    _r("pypi", r"google-adk", "framework:google-adk"),
    _r("pypi", r"pydantic-ai(-slim)?", "framework:pydantic-ai"),
    _r("pypi", r"llama-index-llms-openai(-like)?", "framework:llamaindex", _OPENAI),
    _r("pypi", r"llama-index-llms-anthropic", "framework:llamaindex", _ANTHROPIC),
    _r("pypi", r"llama-index-llms-(gemini|google-genai)", "framework:llamaindex", _GEMINI),
    _r("pypi", r"llama-index-llms-vertex", "framework:llamaindex", _VERTEX),
    _r("pypi", r"llama-index-llms-bedrock(-converse)?", "framework:llamaindex", _BEDROCK),
    _r("pypi", r"llama-index-llms-azure-openai", "framework:llamaindex", _AZURE),
    _r("pypi", r"llama-index-llms-ollama", "framework:llamaindex", _OLLAMA),
    _r("pypi", r"llama-index-llms-mistralai", "framework:llamaindex", _MISTRAL),
    _r("pypi", r"llama-index-llms-groq", "framework:llamaindex", _GROQ),
    _r("pypi", r"llama-index-llms-cohere", "framework:llamaindex", _COHERE),
    _r("pypi", r"llama-index-llms-huggingface(-api)?", "framework:llamaindex", _HF),
    _r("pypi", r"llama-index-tools-mcp", "framework:llamaindex", "mcp:sdk"),
    _r("pypi", r"llama-index(-[a-z0-9.-]+)?", "framework:llamaindex"),
    _r("pypi", r"llama-deploy", "framework:llamaindex"),
    _r("pypi", r"semantic-kernel", _SK),
    _r("pypi", r"smolagents", "framework:smolagents"),
    _r("pypi", r"(claude-agent-sdk|claude-code-sdk)", "framework:claude-agent-sdk", _ANTHROPIC),
    _r("pypi", r"strands-agents(-tools|-builder)?", "framework:strands"),
    _r("pypi", r"(haystack-ai|farm-haystack)", "framework:haystack"),
    _r("pypi", r"dspy(-ai)?", "framework:dspy"),
    _r("pypi", r"(agno|phidata)", "framework:agno"),
    _r("pypi", r"letta(-client)?", "framework:letta"),
    _r("pypi", r"browser-use", "framework:browser-use"),
    _r("pypi", r"litellm", "framework:litellm"),
    _r("pypi", r"camel-ai", "framework:camel"),
    _r("pypi", r"metagpt", "framework:metagpt"),
    _r("pypi", r"agentscope", "framework:agentscope"),
    _r("pypi", r"swarms", "framework:swarms"),
    _r("pypi", r"langflow", "framework:langflow"),
    _r("pypi", r"instructor", "framework:instructor"),
    _r("pypi", r"mirascope", "framework:mirascope"),
    _r("pypi", r"ag-ui-protocol", "framework:copilotkit"),
    _r("pypi", r"stagehand(-py)?", "framework:stagehand"),
    _r("pypi", r"(mcp|fastmcp)", "mcp:sdk"),
    _r("pypi", r"a2a-sdk", "a2a:sdk"),
    _r("pypi", r"openai", _OPENAI),
    _r("pypi", r"anthropic", _ANTHROPIC),
    _r("pypi", r"(google-genai|google-generativeai|google-ai-generativelanguage)", _GEMINI),
    _r("pypi", r"(google-cloud-aiplatform|vertexai)", _VERTEX),
    _r("pypi", r"(bedrock-agentcore|amazon-bedrock-agentcore|bedrock-agentcore-starter-toolkit)", _BEDROCK),
    _r("pypi", r"(azure-ai-inference|azure-ai-projects|azure-ai-agents)", _AZURE),
    _r("pypi", r"mistralai", _MISTRAL),
    _r("pypi", r"cohere", _COHERE),
    _r("pypi", r"groq", _GROQ),
    _r("pypi", r"ollama", _OLLAMA),
    _r("pypi", r"together", _TOGETHER),
    _r("pypi", r"fireworks-ai", _FIREWORKS),
    _r("pypi", r"replicate", _REPLICATE),
    _r("pypi", r"cerebras-cloud-sdk", _CEREBRAS),
    _r("pypi", r"voyageai", _VOYAGE),
    _r("pypi", r"xai-sdk", _XAI),
    _r("pypi", r"(huggingface-hub|transformers|text-generation|smolagents-hub)", _HF),
    _r("pypi", r"vllm", _VLLM),
    _r("pypi", r"llama-cpp-python", _LLAMACPP),
    # ---- npm package names ----
    _r("npm", r"@langchain/openai", "framework:langchain", _OPENAI),
    _r("npm", r"@langchain/anthropic", "framework:langchain", _ANTHROPIC),
    _r("npm", r"@langchain/google-genai", "framework:langchain", _GEMINI),
    _r("npm", r"@langchain/google-vertexai(-web)?", "framework:langchain", _VERTEX),
    _r("npm", r"@langchain/aws", "framework:langchain", _BEDROCK),
    _r("npm", r"@langchain/mistralai", "framework:langchain", _MISTRAL),
    _r("npm", r"@langchain/cohere", "framework:langchain", _COHERE),
    _r("npm", r"@langchain/groq", "framework:langchain", _GROQ),
    _r("npm", r"@langchain/ollama", "framework:langchain", _OLLAMA),
    _r("npm", r"@langchain/langgraph(-[a-z0-9.-]+)?", "framework:langgraph"),
    _r("npm", r"@langchain/mcp-adapters", "framework:langchain", "mcp:sdk"),
    _r("npm", r"(langchain|@langchain/(?!langgraph)[a-z0-9.-]+)", "framework:langchain"),
    _r("npm", r"langsmith", "framework:langchain"),
    _r("npm", r"@ai-sdk/openai(-compatible)?", "framework:vercel-ai", _OPENAI),
    _r("npm", r"@ai-sdk/anthropic", "framework:vercel-ai", _ANTHROPIC),
    _r("npm", r"@ai-sdk/google", "framework:vercel-ai", _GEMINI),
    _r("npm", r"@ai-sdk/google-vertex", "framework:vercel-ai", _VERTEX),
    _r("npm", r"@ai-sdk/amazon-bedrock", "framework:vercel-ai", _BEDROCK),
    _r("npm", r"@ai-sdk/azure", "framework:vercel-ai", _AZURE),
    _r("npm", r"@ai-sdk/mistral", "framework:vercel-ai", _MISTRAL),
    _r("npm", r"@ai-sdk/cohere", "framework:vercel-ai", _COHERE),
    _r("npm", r"@ai-sdk/groq", "framework:vercel-ai", _GROQ),
    _r("npm", r"@ai-sdk/xai", "framework:vercel-ai", _XAI),
    _r("npm", r"@ai-sdk/togetherai", "framework:vercel-ai", _TOGETHER),
    _r("npm", r"@ai-sdk/fireworks", "framework:vercel-ai", _FIREWORKS),
    _r("npm", r"@ai-sdk/deepseek", "framework:vercel-ai", _DEEPSEEK),
    _r("npm", r"@ai-sdk/perplexity", "framework:vercel-ai", _PERPLEXITY),
    _r("npm", r"@ai-sdk/cerebras", "framework:vercel-ai", _CEREBRAS),
    _r("npm", r"(ai|@ai-sdk/[a-z0-9.-]+)", "framework:vercel-ai"),
    _r("npm", r"ollama-ai-provider(-v2)?", "framework:vercel-ai", _OLLAMA),
    _r("npm", r"@openrouter/ai-sdk-provider", "framework:vercel-ai", _OPENROUTER),
    _r("npm", r"@openai/agents(-[a-z0-9.-]+)?", "framework:openai-agents", _OPENAI),
    _r("npm", r"openai", _OPENAI),
    _r("npm", r"@anthropic-ai/(claude-agent-sdk|claude-code)", "framework:claude-agent-sdk", _ANTHROPIC),
    _r("npm", r"@anthropic-ai/(sdk|bedrock-sdk|vertex-sdk)", _ANTHROPIC),
    _r("npm", r"@google/(genai|generative-ai)", _GEMINI),
    _r("npm", r"@google-cloud/(vertexai|aiplatform)", _VERTEX),
    _r("npm", r"@google/adk", "framework:google-adk"),
    _r("npm", r"@mistralai/mistralai", _MISTRAL),
    _r("npm", r"cohere-ai", _COHERE),
    _r("npm", r"groq-sdk", _GROQ),
    _r("npm", r"ollama", _OLLAMA),
    _r("npm", r"together-ai", _TOGETHER),
    _r("npm", r"replicate", _REPLICATE),
    _r("npm", r"@cerebras/cerebras_cloud_sdk", _CEREBRAS),
    _r("npm", r"(@huggingface/(inference|hub|transformers)|@xenova/transformers)", _HF),
    _r("npm", r"(@azure/openai|@azure-rest/ai-inference|@azure/ai-projects|@azure/ai-agents)", _AZURE),
    _r("npm", r"@aws-sdk/client-bedrock[a-z0-9.-]*", _BEDROCK),
    _r("npm", r"(mastra|@mastra/[a-z0-9.-]+)", "framework:mastra"),
    _r("npm", r"(llamaindex|@llamaindex/[a-z0-9.-]+)", "framework:llamaindex"),
    _r("npm", r"@modelcontextprotocol/(sdk|server-[a-z0-9.-]+|inspector)", "mcp:sdk"),
    _r("npm", r"fastmcp", "mcp:sdk"),
    _r("npm", r"@a2a-js/sdk", "a2a:sdk"),
    _r("npm", r"@genkit-ai/(googleai|google-genai)", "framework:genkit", _GEMINI),
    _r("npm", r"@genkit-ai/vertexai", "framework:genkit", _VERTEX),
    _r("npm", r"(genkit|@genkit-ai/[a-z0-9.-]+)", "framework:genkit"),
    _r("npm", r"(copilotkit|@copilotkit/[a-z0-9.-]+|@ag-ui/[a-z0-9.-]+)", "framework:copilotkit"),
    _r("npm", r"@browserbasehq/stagehand", "framework:stagehand"),
    _r("npm", r"portkey-ai", "framework:portkey"),
    _r("pypi", r"portkey-ai", "framework:portkey"),
    _r("pyimport", r"portkey_ai(\..*)?", "framework:portkey"),
    _r("npm", r"@n8n/n8n-nodes-langchain", "lowcode:n8n"),
    # ---- Go module paths (prefix match) ----
    _r("golang", r"github\.com/tmc/langchaingo(/.*)?", "framework:langchaingo"),
    _r("golang", r"github\.com/cloudwego/eino(-[a-z0-9-]+)?(/.*)?", "framework:eino"),
    _r("golang", r"github\.com/firebase/genkit(/.*)?", "framework:genkit"),
    _r("golang", r"github\.com/google/adk-go(/.*)?", "framework:google-adk"),
    _r("golang", r"github\.com/openai/openai-go(/.*)?", _OPENAI),
    _r("golang", r"github\.com/sashabaranov/go-openai(/.*)?", _OPENAI),
    _r("golang", r"github\.com/anthropics/anthropic-sdk-go(/.*)?", _ANTHROPIC),
    _r("golang", r"google\.golang\.org/genai(/.*)?", _GEMINI),
    _r("golang", r"github\.com/google/generative-ai-go(/.*)?", _GEMINI),
    _r("golang", r"cloud\.google\.com/go/(vertexai|aiplatform)(/.*)?", _VERTEX),
    _r("golang", r"github\.com/aws/aws-sdk-go-v2/service/bedrock[a-z]*(/.*)?", _BEDROCK),
    _r("golang", r"github\.com/ollama/ollama(/.*)?", _OLLAMA),
    _r("golang", r"github\.com/cohere-ai/cohere-go(/.*)?", _COHERE),
    _r("golang", r"github\.com/mark3labs/mcp-go(/.*)?", "mcp:sdk"),
    _r("golang", r"github\.com/modelcontextprotocol/go-sdk(/.*)?", "mcp:sdk"),
    _r("golang", r"github\.com/metoro-io/mcp-golang(/.*)?", "mcp:sdk"),
    _r("golang", r"github\.com/a2aproject/a2a-go(/.*)?", "a2a:sdk"),
    # ---- Maven coordinates group:artifact ----
    _r("maven", r"dev\.langchain4j:langchain4j-open-ai[a-z0-9.-]*", _LC4J, _OPENAI),
    _r("maven", r"dev\.langchain4j:langchain4j-anthropic[a-z0-9.-]*", _LC4J, _ANTHROPIC),
    _r("maven", r"dev\.langchain4j:langchain4j-google-ai-gemini[a-z0-9.-]*", _LC4J, _GEMINI),
    _r("maven", r"dev\.langchain4j:langchain4j-vertex-ai[a-z0-9.-]*", _LC4J, _VERTEX),
    _r("maven", r"dev\.langchain4j:langchain4j-bedrock[a-z0-9.-]*", _LC4J, _BEDROCK),
    _r("maven", r"dev\.langchain4j:langchain4j-ollama[a-z0-9.-]*", _LC4J, _OLLAMA),
    _r("maven", r"dev\.langchain4j:langchain4j-mistral-ai[a-z0-9.-]*", _LC4J, _MISTRAL),
    _r("maven", r"dev\.langchain4j:langchain4j-azure-open-ai[a-z0-9.-]*", _LC4J, _AZURE),
    _r("maven", r"dev\.langchain4j:langchain4j-hugging-face[a-z0-9.-]*", _LC4J, _HF),
    _r("maven", r"dev\.langchain4j:langchain4j-mcp[a-z0-9.-]*", _LC4J, "mcp:sdk"),
    _r("maven", r"dev\.langchain4j:[a-z0-9.-]+", _LC4J),
    _r("maven", r"org\.springframework\.ai:spring-ai-[\w.-]*openai[\w.-]*", _SPRING, _OPENAI),
    _r("maven", r"org\.springframework\.ai:spring-ai-[\w.-]*anthropic[\w.-]*", _SPRING, _ANTHROPIC),
    _r("maven", r"org\.springframework\.ai:spring-ai-[\w.-]*vertex[\w.-]*", _SPRING, _VERTEX),
    _r("maven", r"org\.springframework\.ai:spring-ai-[\w.-]*bedrock[\w.-]*", _SPRING, _BEDROCK),
    _r("maven", r"org\.springframework\.ai:spring-ai-[\w.-]*ollama[\w.-]*", _SPRING, _OLLAMA),
    _r("maven", r"org\.springframework\.ai:spring-ai-[\w.-]*mistral[\w.-]*", _SPRING, _MISTRAL),
    _r("maven", r"org\.springframework\.ai:spring-ai-[\w.-]*mcp[\w.-]*", _SPRING, "mcp:sdk"),
    _r("maven", r"org\.springframework\.ai:[a-z0-9.-]+", _SPRING),
    _r("maven", r"com\.openai:[a-z0-9.-]+", _OPENAI),
    _r("maven", r"com\.anthropic:[a-z0-9.-]+", _ANTHROPIC),
    _r("maven", r"com\.google\.genai:[a-z0-9.-]+", _GEMINI),
    _r("maven", r"com\.google\.cloud:google-cloud-(vertexai|aiplatform)", _VERTEX),
    _r("maven", r"software\.amazon\.awssdk:bedrock[a-z0-9.-]*", _BEDROCK),
    _r("maven", r"com\.azure:azure-ai-(openai|inference|projects|agents)[a-z0-9.-]*", _AZURE),
    _r("maven", r"io\.modelcontextprotocol\.sdk:[a-z0-9.-]+", "mcp:sdk"),
    _r("maven", r"com\.google\.adk:[a-z0-9.-]+", "framework:google-adk"),
    _r("maven", r"com\.microsoft\.semantic-kernel:[a-z0-9.-]+", _SK),
    _r("maven", r"(io\.a2a\.sdk|io\.github\.a2asdk):[a-z0-9.-]+", "a2a:sdk"),
    _r("maven", r"ai\.koog:[a-z0-9.-]+", "framework:koog"),
    # ---- NuGet package ids (lowercase) ----
    _r("nuget", r"microsoft\.semantickernel\.connectors\.openai", _SK, _OPENAI),
    _r("nuget", r"microsoft\.semantickernel\.connectors\.azureopenai", _SK, _AZURE),
    _r("nuget", r"microsoft\.semantickernel\.connectors\.ollama", _SK, _OLLAMA),
    _r("nuget", r"microsoft\.semantickernel\.connectors\.google", _SK, _GEMINI),
    _r("nuget", r"microsoft\.semantickernel\.connectors\.amazon", _SK, _BEDROCK),
    _r("nuget", r"microsoft\.semantickernel[a-z0-9.]*", _SK),
    _r("nuget", r"microsoft\.extensions\.ai\.openai", "framework:microsoft-extensions-ai", _OPENAI),
    _r("nuget", r"microsoft\.extensions\.ai\.ollama", "framework:microsoft-extensions-ai", _OLLAMA),
    _r("nuget", r"microsoft\.extensions\.ai[a-z0-9.]*", "framework:microsoft-extensions-ai"),
    _r("nuget", r"microsoft\.agents\.ai[a-z0-9.]*", "framework:microsoft-agent-framework"),
    _r("nuget", r"autogen[a-z0-9.]*", "framework:autogen"),
    _r("nuget", r"openai", _OPENAI),
    _r("nuget", r"azure\.ai\.(openai|inference|projects|agents)[a-z0-9.]*", _AZURE),
    _r("nuget", r"anthropic(\.sdk)?", _ANTHROPIC),
    _r("nuget", r"modelcontextprotocol[a-z0-9.]*", "mcp:sdk"),
    _r("nuget", r"awssdk\.bedrock[a-z0-9.]*", _BEDROCK),
    _r("nuget", r"ollamasharp", _OLLAMA),
    _r("nuget", r"llamasharp[a-z0-9.]*", _LLAMACPP),
    _r("nuget", r"a2a", "a2a:sdk"),
    # ---- Cargo crate names (normalized '_' -> '-') ----
    _r("cargo", r"rig-[a-z0-9-]+", "framework:rig"),
    _r("cargo", r"async-openai", _OPENAI),
    _r("cargo", r"openai(-api-rs|-api|-rs)?", _OPENAI),
    _r("cargo", r"anthropic(-sdk)?[a-z0-9-]*", _ANTHROPIC),
    _r("cargo", r"rmcp", "mcp:sdk"),
    _r("cargo", r"(mcp-sdk|mcp-rs|mcp-rust-sdk|mcp-core|mcp-client|mcp-server)", "mcp:sdk"),
    _r("cargo", r"ollama-rs", _OLLAMA),
    _r("cargo", r"a2a-rs", "a2a:sdk"),
    _r("cargo", r"swiftide(-[a-z0-9-]+)?", "framework:swiftide"),
    # ---- Python import paths (dotted, lowercase) ----
    _r("pyimport", r"langchain_openai(\..*)?", "framework:langchain", _OPENAI),
    _r("pyimport", r"langchain_anthropic(\..*)?", "framework:langchain", _ANTHROPIC),
    _r("pyimport", r"langchain_google_genai(\..*)?", "framework:langchain", _GEMINI),
    _r("pyimport", r"langchain_google_vertexai(\..*)?", "framework:langchain", _VERTEX),
    _r("pyimport", r"langchain_aws(\..*)?", "framework:langchain", _BEDROCK),
    _r("pyimport", r"langchain_mistralai(\..*)?", "framework:langchain", _MISTRAL),
    _r("pyimport", r"langchain_cohere(\..*)?", "framework:langchain", _COHERE),
    _r("pyimport", r"langchain_groq(\..*)?", "framework:langchain", _GROQ),
    _r("pyimport", r"langchain_ollama(\..*)?", "framework:langchain", _OLLAMA),
    _r("pyimport", r"langchain_huggingface(\..*)?", "framework:langchain", _HF),
    _r("pyimport", r"langchain_mcp_adapters(\..*)?", "framework:langchain", "mcp:sdk"),
    _r("pyimport", r"langchain(_[a-z0-9_]+)?(\..*)?", "framework:langchain"),
    _r("pyimport", r"langgraph(_[a-z0-9_]+)?(\..*)?", "framework:langgraph"),
    _r("pyimport", r"langsmith(\..*)?", "framework:langchain"),
    _r("pyimport", r"crewai(_tools)?(\..*)?", "framework:crewai"),
    _r("pyimport", r"autogen(_[a-z0-9_]+)?(\..*)?", "framework:autogen"),
    _r("pyimport", r"google\.adk(\..*)?", "framework:google-adk"),
    _r("pyimport", r"pydantic_ai(\..*)?", "framework:pydantic-ai"),
    _r("pyimport", r"llama_index\.llms\.openai(\..*)?", "framework:llamaindex", _OPENAI),
    _r("pyimport", r"llama_index\.llms\.anthropic(\..*)?", "framework:llamaindex", _ANTHROPIC),
    _r("pyimport", r"llama_index\.llms\.(gemini|google_genai)(\..*)?", "framework:llamaindex", _GEMINI),
    _r("pyimport", r"llama_index\.llms\.bedrock[a-z_]*(\..*)?", "framework:llamaindex", _BEDROCK),
    _r("pyimport", r"llama_index\.llms\.ollama(\..*)?", "framework:llamaindex", _OLLAMA),
    _r("pyimport", r"llama_index(\..*)?", "framework:llamaindex"),
    _r("pyimport", r"llama_deploy(\..*)?", "framework:llamaindex"),
    _r("pyimport", r"semantic_kernel(\..*)?", _SK),
    _r("pyimport", r"smolagents(\..*)?", "framework:smolagents"),
    _r("pyimport", r"(claude_agent_sdk|claude_code_sdk)(\..*)?", "framework:claude-agent-sdk", _ANTHROPIC),
    _r("pyimport", r"strands(_tools)?(\..*)?", "framework:strands"),
    _r("pyimport", r"haystack(\..*)?", "framework:haystack"),
    _r("pyimport", r"dspy(\..*)?", "framework:dspy"),
    _r("pyimport", r"agno(\..*)?", "framework:agno"),
    _r("pyimport", r"letta(_client)?(\..*)?", "framework:letta"),
    _r("pyimport", r"browser_use(\..*)?", "framework:browser-use"),
    _r("pyimport", r"litellm(\..*)?", "framework:litellm"),
    _r("pyimport", r"camel(\..*)?", "framework:camel"),
    _r("pyimport", r"metagpt(\..*)?", "framework:metagpt"),
    _r("pyimport", r"agentscope(\..*)?", "framework:agentscope"),
    _r("pyimport", r"swarms(\..*)?", "framework:swarms"),
    _r("pyimport", r"langflow(\..*)?", "framework:langflow"),
    _r("pyimport", r"instructor(\..*)?", "framework:instructor"),
    _r("pyimport", r"mirascope(\..*)?", "framework:mirascope"),
    _r("pyimport", r"ag_ui(\..*)?", "framework:copilotkit"),
    _r("pyimport", r"stagehand(\..*)?", "framework:stagehand"),
    _r("pyimport", r"openai_agents_sdk_marker", "framework:openai-agents", _OPENAI),
    _r("pyimport", r"(mcp|fastmcp)(\..*)?", "mcp:sdk"),
    _r("pyimport", r"a2a(\..*)?", "a2a:sdk"),
    _r("pyimport", r"openai(\..*)?", _OPENAI),
    _r("pyimport", r"anthropic(\..*)?", _ANTHROPIC),
    _r("pyimport", r"google\.(genai|generativeai|ai\.generativelanguage)(\..*)?", _GEMINI),
    _r("pyimport", r"(vertexai|google\.cloud\.aiplatform)(\..*)?", _VERTEX),
    _r("pyimport", r"bedrock_agentcore(\..*)?", _BEDROCK),
    _r("pyimport", r"azure\.ai\.(inference|projects|agents)(\..*)?", _AZURE),
    _r("pyimport", r"mistralai(\..*)?", _MISTRAL),
    _r("pyimport", r"cohere(\..*)?", _COHERE),
    _r("pyimport", r"groq(\..*)?", _GROQ),
    _r("pyimport", r"ollama(\..*)?", _OLLAMA),
    _r("pyimport", r"together(\..*)?", _TOGETHER),
    _r("pyimport", r"fireworks(\..*)?", _FIREWORKS),
    _r("pyimport", r"replicate(\..*)?", _REPLICATE),
    _r("pyimport", r"cerebras\.cloud\.sdk(\..*)?", _CEREBRAS),
    _r("pyimport", r"voyageai(\..*)?", _VOYAGE),
    _r("pyimport", r"xai_sdk(\..*)?", _XAI),
    _r("pyimport", r"(huggingface_hub|transformers)(\..*)?", _HF),
    _r("pyimport", r"vllm(\..*)?", _VLLM),
    _r("pyimport", r"llama_cpp(\..*)?", _LLAMACPP),
    # ---- Java / Kotlin import paths ----
    _r("javaimport", r"dev\.langchain4j\.mcp(\..*)?", _LC4J, "mcp:sdk"),
    _r("javaimport", r"dev\.langchain4j\.model\.openai(\..*)?", _LC4J, _OPENAI),
    _r("javaimport", r"dev\.langchain4j\.model\.anthropic(\..*)?", _LC4J, _ANTHROPIC),
    _r("javaimport", r"dev\.langchain4j\.model\.googleai(\..*)?", _LC4J, _GEMINI),
    _r("javaimport", r"dev\.langchain4j\.model\.vertexai(\..*)?", _LC4J, _VERTEX),
    _r("javaimport", r"dev\.langchain4j\.model\.bedrock(\..*)?", _LC4J, _BEDROCK),
    _r("javaimport", r"dev\.langchain4j\.model\.ollama(\..*)?", _LC4J, _OLLAMA),
    _r("javaimport", r"dev\.langchain4j\.model\.mistralai(\..*)?", _LC4J, _MISTRAL),
    _r("javaimport", r"dev\.langchain4j\.model\.azure(\..*)?", _LC4J, _AZURE),
    _r("javaimport", r"dev\.langchain4j(\..*)?", _LC4J),
    _r("javaimport", r"org\.springframework\.ai\.openai(\..*)?", _SPRING, _OPENAI),
    _r("javaimport", r"org\.springframework\.ai\.anthropic(\..*)?", _SPRING, _ANTHROPIC),
    _r("javaimport", r"org\.springframework\.ai\.vertexai(\..*)?", _SPRING, _VERTEX),
    _r("javaimport", r"org\.springframework\.ai\.bedrock(\..*)?", _SPRING, _BEDROCK),
    _r("javaimport", r"org\.springframework\.ai\.ollama(\..*)?", _SPRING, _OLLAMA),
    _r("javaimport", r"org\.springframework\.ai\.mistralai(\..*)?", _SPRING, _MISTRAL),
    _r("javaimport", r"org\.springframework\.ai\.mcp(\..*)?", _SPRING, "mcp:sdk"),
    _r("javaimport", r"org\.springframework\.ai(\..*)?", _SPRING),
    _r("javaimport", r"com\.openai(\..*)?", _OPENAI),
    _r("javaimport", r"com\.anthropic(\..*)?", _ANTHROPIC),
    _r("javaimport", r"com\.google\.genai(\..*)?", _GEMINI),
    _r("javaimport", r"com\.google\.cloud\.(vertexai|aiplatform)(\..*)?", _VERTEX),
    _r("javaimport", r"software\.amazon\.awssdk\.services\.bedrock[a-z]*(\..*)?", _BEDROCK),
    _r("javaimport", r"com\.azure\.ai\.(openai|inference|projects|agents)(\..*)?", _AZURE),
    _r("javaimport", r"io\.modelcontextprotocol(\..*)?", "mcp:sdk"),
    _r("javaimport", r"com\.google\.adk(\..*)?", "framework:google-adk"),
    _r("javaimport", r"com\.microsoft\.semantickernel(\..*)?", _SK),
    _r("javaimport", r"io\.a2a(\..*)?", "a2a:sdk"),
    _r("javaimport", r"ai\.koog(\..*)?", "framework:koog"),
    # ---- C# using directives ----
    _r("csimport", r"microsoft\.semantickernel\.connectors\.openai(\..*)?", _SK, _OPENAI),
    _r("csimport", r"microsoft\.semantickernel\.connectors\.azureopenai(\..*)?", _SK, _AZURE),
    _r("csimport", r"microsoft\.semantickernel(\..*)?", _SK),
    _r("csimport", r"microsoft\.extensions\.ai(\..*)?", "framework:microsoft-extensions-ai"),
    _r("csimport", r"microsoft\.agents\.ai(\..*)?", "framework:microsoft-agent-framework"),
    _r("csimport", r"autogen(\..*)?", "framework:autogen"),
    _r("csimport", r"openai(\..*)?", _OPENAI),
    _r("csimport", r"azure\.ai\.(openai|inference|projects|agents)(\..*)?", _AZURE),
    _r("csimport", r"anthropic(\..*)?", _ANTHROPIC),
    _r("csimport", r"modelcontextprotocol(\..*)?", "mcp:sdk"),
    _r("csimport", r"amazon\.bedrock[a-z]*(\..*)?", _BEDROCK),
    _r("csimport", r"ollamasharp(\..*)?", _OLLAMA),
    _r("csimport", r"llamasharp(\..*)?", _LLAMACPP),
    _r("csimport", r"a2a(\..*)?", "a2a:sdk"),
    # ---- Rust crate roots in `use` / `extern crate` (normalized '_' -> '-') ----
    _r("rsimport", r"rig", "framework:rig"),
    _r("rsimport", r"async-openai", _OPENAI),
    _r("rsimport", r"anthropic[a-z0-9-]*", _ANTHROPIC),
    _r("rsimport", r"rmcp", "mcp:sdk"),
    _r("rsimport", r"(mcp-core|mcp-client|mcp-server|mcp-sdk)", "mcp:sdk"),
    _r("rsimport", r"ollama-rs", _OLLAMA),
    _r("rsimport", r"a2a-rs", "a2a:sdk"),
    _r("rsimport", r"swiftide(-[a-z0-9-]+)?", "framework:swiftide"),
    # ---- Service hostnames and SDK idioms found in code or configuration ----
    _r("host", r"api\.openai\.com", _OPENAI),
    _r("host", r"api\.anthropic\.com", _ANTHROPIC),
    _r("host", r"generativelanguage\.googleapis\.com", _GEMINI),
    _r("host", r"aiplatform\.googleapis\.com", _VERTEX),
    _r("host", r"bedrock(-runtime|-agent|-agent-runtime)?\.[a-z0-9-]+\.amazonaws\.com", _BEDROCK),
    _r("host", r"\.openai\.azure\.com", _AZURE),
    _r("host", r"api\.mistral\.ai", _MISTRAL),
    _r("host", r"api\.replicate\.com", _REPLICATE),
    _r("host", r"api\.cohere\.(ai|com)", _COHERE),
    _r("host", r"api\.groq\.com", _GROQ),
    _r("host", r"(localhost|127\.0\.0\.1|host\.docker\.internal|ollama):11434", _OLLAMA),
    _r("host", r"api\.together\.xyz", _TOGETHER),
    _r("host", r"api\.fireworks\.ai", _FIREWORKS),
    _r("host", r"openrouter\.ai/api", _OPENROUTER),
    _r("host", r"api\.deepseek\.com", _DEEPSEEK),
    _r("host", r"api\.x\.ai", _XAI),
    _r("host", r"api\.perplexity\.ai", _PERPLEXITY),
    _r("host", r"(api-inference\.huggingface\.co|router\.huggingface\.co)", _HF),
    _r("host", r"api\.cerebras\.ai", _CEREBRAS),
    _r("host", r"integrate\.api\.nvidia\.com", _NVIDIA),
    _r("idiom", r"bedrock[-_]?runtime|bedrock-agent(-runtime)?", _BEDROCK),
    _r("idiom", r"azureopenai\(|azurechatopenai\(|azureopenaichatcompletionclient\(", _AZURE),
    _r("idiom", r"ollama/ollama", _OLLAMA),
    _r("idiom", r"vllm/vllm-openai", _VLLM),
    _r("idiom", r"anthropicvertex\b", _VERTEX, _ANTHROPIC),
    _r("idiom", r"anthropicbedrock\b", _BEDROCK, _ANTHROPIC),
    _r("idiom", r"\blitellm_params\b", "framework:litellm"),
    # provider credential and endpoint variable names in code or configuration
    _r("idiom", r"\bopenai_api_key\b", _OPENAI),
    _r("idiom", r"\banthropic_api_key\b", _ANTHROPIC),
    _r("idiom", r"\bazure_openai_(api_key|endpoint|api_base|deployment)", _AZURE),
    _r("idiom", r"\bgemini_api_key\b", _GEMINI),
    _r("idiom", r"\bmistral_api_key\b", _MISTRAL),
    _r("idiom", r"\bcohere_api_key\b", _COHERE),
    _r("idiom", r"\bgroq_api_key\b", _GROQ),
    _r("idiom", r"\btogether(ai)?_api_key\b", _TOGETHER),
    _r("idiom", r"\bfireworks_api_key\b", _FIREWORKS),
    _r("idiom", r"\bdeepseek_api_key\b", _DEEPSEEK),
    _r("idiom", r"\bopenrouter_api_key\b", _OPENROUTER),
    _r("idiom", r"\bxai_api_key\b", _XAI),
    _r("idiom", r"\bperplexity(ai)?_api_key\b", _PERPLEXITY),
    _r("idiom", r"\b(hf_token|huggingface_hub_token|huggingfacehub_api_token)\b", _HF),
    _r("idiom", r"\bollama_(host|base_url)\b", _OLLAMA),
    _r("idiom", r"\breplicate_api_token\b", _REPLICATE),
    _r("idiom", r"\bcerebras_api_key\b", _CEREBRAS),
    _r("idiom", r"\bvoyage_api_key\b", _VOYAGE),
    _r("idiom", r"\bnvidia_api_key\b", _NVIDIA),
    _r("idiom", r"\baws_bearer_token_bedrock\b", _BEDROCK),
    _r("idiom", r"\bclaude_code_use_bedrock\b", _BEDROCK),
    _r("idiom", r"\bclaude_code_use_vertex\b", _VERTEX),
    # LiteLLM-style provider routes and well-known model identifiers
    _r("idiom", r"\banthropic/claude", _ANTHROPIC),
    _r("idiom", r"\bazure/(gpt|o[1-5]|text-|chatgpt)", _AZURE),
    _r("idiom", r"\bbedrock/(anthropic|amazon|meta|mistral|cohere|ai21|converse)", _BEDROCK),
    _r("idiom", r"\bvertex_ai/(gemini|claude|text|chat|codechat|mistral|llama)", _VERTEX),
    _r("idiom", r"\bgemini/gemini", _GEMINI),
    _r("idiom", r"\bgroq/(llama|mixtral|gemma|qwen|deepseek|whisper|openai)", _GROQ),
    _r("idiom", r"\bdeepseek/deepseek", _DEEPSEEK),
    _r("idiom", r"\bfireworks_ai/accounts", _FIREWORKS),
    _r("idiom", r"\bmistral/(mistral|codestral|pixtral|open-mi|magistral|ministral)", _MISTRAL),
    _r("idiom", r"\bopenrouter/[a-z0-9-]+/", _OPENROUTER),
    _r("idiom", r"\bollama(_chat)?/[a-z0-9]", _OLLAMA),
    _r("idiom", r"\btogether_ai/", _TOGETHER),
    _r("idiom", r"\bcohere(_chat)?/command", _COHERE),
    _r("idiom", r"\bxai/grok", _XAI),
    _r("idiom", r"\bperplexity/(sonar|llama)", _PERPLEXITY),
    _r("idiom", r"\bcerebras/(llama|qwen|gpt)", _CEREBRAS),
    _r("idiom", r"\bclaude-(3|4|opus|sonnet|haiku|2)", _ANTHROPIC),
    _r("idiom", r"\bgpt-(4|3\.5|5|oss)|\bo[134]-mini\b|\bo1-preview\b|\btext-embedding-(ada|3)", _OPENAI),
    _r("idiom", r"\bgemini-(1\.5|2\.|pro|flash|ultra|exp)", _GEMINI),
    _r(
        "idiom",
        r"\bmixtral-|\bmistral-(large|medium|small|7b|nemo|tiny)|\bcodestral|\bpixtral|\bmagistral|\bministral",
        _MISTRAL,
    ),
    _r("idiom", r"\bcommand-r(-plus|7b|-08)?\b", _COHERE),
    _r("idiom", r"\bdeepseek-(chat|coder|reasoner|r1|v[23])", _DEEPSEEK),
    _r("idiom", r"\bgrok-[0-9]", _XAI),
    _r("idiom", r"\banthropic\.claude-[a-z0-9.-]+-v\d:\d", _BEDROCK, _ANTHROPIC),
    _r("idiom", r"\bamazon\.(titan|nova)-", _BEDROCK),
    _r("idiom", r"\bmeta\.llama[0-9]", _BEDROCK),
)

# Free-text names that tools print instead of package identifiers. Matched by
# substring search in the listed order; a match is consumed from the string
# before later rules run, so "langchain4j" never also yields "langchain".
NAME_RULES: tuple[Rule, ...] = (
    _r("name", r"azure[ -]?open[ -]?ai|azure ai (foundry|inference|projects|agents)", _AZURE),
    _r("name", r"openai[ -]?agents|agents sdk", "framework:openai-agents", _OPENAI),
    _r("name", r"langgraph", "framework:langgraph"),
    _r("name", r"langchain4j", _LC4J),
    _r("name", r"langchaingo", "framework:langchaingo"),
    _r("name", r"langchain|langsmith", "framework:langchain"),
    _r("name", r"crew[ -]?ai", "framework:crewai"),
    _r("name", r"autogen|\bag2\b", "framework:autogen"),
    _r("name", r"google[ -]?adk|agent development kit", "framework:google-adk"),
    _r("name", r"pydantic[ -]?ai", "framework:pydantic-ai"),
    _r("name", r"llama[ _-]?index", "framework:llamaindex"),
    _r("name", r"semantic[ -]?kernel", _SK),
    _r("name", r"smolagents", "framework:smolagents"),
    _r("name", r"mastra", "framework:mastra"),
    _r("name", r"vercel ai|@ai-sdk|\bai sdk\b", "framework:vercel-ai"),
    _r("name", r"claude[ -]?(agent|code)[ -]?sdk", "framework:claude-agent-sdk"),
    _r("name", r"strands", "framework:strands"),
    _r("name", r"haystack", "framework:haystack"),
    _r("name", r"\bdspy\b", "framework:dspy"),
    _r("name", r"\bagno\b|phidata", "framework:agno"),
    _r("name", r"\bletta\b|memgpt", "framework:letta"),
    _r("name", r"browser[ -]?use", "framework:browser-use"),
    _r("name", r"litellm", "framework:litellm"),
    _r("name", r"spring[ -]?ai", _SPRING),
    _r("name", r"extensions\.ai", "framework:microsoft-extensions-ai"),
    _r("name", r"microsoft agent framework|agent[-_]framework\b", "framework:microsoft-agent-framework"),
    _r("name", r"\brig\b", "framework:rig"),
    _r("name", r"\beino\b", "framework:eino"),
    _r("name", r"genkit", "framework:genkit"),
    _r("name", r"copilotkit", "framework:copilotkit"),
    _r("name", r"stagehand", "framework:stagehand"),
    _r("name", r"\bkoog\b", "framework:koog"),
    _r("name", r"metagpt", "framework:metagpt"),
    _r("name", r"agentscope", "framework:agentscope"),
    _r("name", r"instructor", "framework:instructor"),
    _r("name", r"model context protocol|\bmcp\b", "mcp:sdk"),
    _r("name", r"agent2agent|agent-to-agent|\ba2a\b", "a2a:sdk"),
    _r("name", r"\bn8n\b", "lowcode:n8n"),
    _r("name", r"\bdify\b", "lowcode:dify"),
    _r("name", r"flowise", "lowcode:flowise"),
    _r("name", r"langflow", "lowcode:langflow"),
    _r("name", r"vertex", _VERTEX),
    _r("name", r"bedrock", _BEDROCK),
    _r("name", r"gemini|google ?gen(erative)? ?ai|generativelanguage", _GEMINI),
    _r("name", r"anthropic|claude", _ANTHROPIC),
    _r("name", r"openai|\bgpt-?[345o]|\bo[134]-mini|chatgpt", _OPENAI),
    _r("name", r"mistral", _MISTRAL),
    _r("name", r"cohere", _COHERE),
    _r("name", r"\bgroq\b", _GROQ),
    _r("name", r"ollama", _OLLAMA),
    _r("name", r"hugging ?face|transformers", _HF),
    _r("name", r"together", _TOGETHER),
    _r("name", r"fireworks", _FIREWORKS),
    _r("name", r"openrouter", _OPENROUTER),
    _r("name", r"deepseek", _DEEPSEEK),
    _r("name", r"\bxai\b|\bgrok\b", _XAI),
    _r("name", r"perplexity", _PERPLEXITY),
    _r("name", r"replicate", _REPLICATE),
    _r("name", r"cerebras", _CEREBRAS),
    _r("name", r"\bvllm\b", _VLLM),
    _r("name", r"llama[.-]?cpp", _LLAMACPP),
    _r("name", r"nvidia nim|\bnim\b", _NVIDIA),
)

_COMPILED: dict[str, list[tuple[re.Pattern[str], tuple[str, ...]]]] = {}
for _rule in RULES:
    _COMPILED.setdefault(_rule.ecosystem, []).append((re.compile(_rule.pattern), _rule.facts))
_NAME_COMPILED: list[tuple[re.Pattern[str], tuple[str, ...]]] = [
    (re.compile(rule.pattern), rule.facts) for rule in NAME_RULES
]


def normalize(ecosystem: str, name: str) -> str:
    """Normalize a package or import name for its ecosystem."""
    text = name.strip().lower()
    if ecosystem in {"pypi", "cargo"}:
        text = re.split(r"[\[;<>=!~ @]", text, maxsplit=1)[0]
        text = text.replace("_", "-")
    elif ecosystem == "rsimport":
        text = text.split("::", 1)[0].replace("_", "-")
    elif ecosystem in {"golang", "goimport"}:
        text = text.strip('"')
    elif ecosystem == "jsimport":
        parts = text.split("/")
        text = "/".join(parts[:2]) if text.startswith("@") else parts[0]
    return text


def facts_for(ecosystem: str, name: str) -> frozenset[str]:
    """Facts an exact package or import name establishes in ``ecosystem``.

    ``jsimport`` and ``goimport`` fall back to the ``npm`` and ``golang``
    tables after normalization. Unknown names yield no facts.
    """
    text = normalize(ecosystem, name)
    if not text:
        return frozenset()
    table = {"jsimport": "npm", "goimport": "golang"}.get(ecosystem, ecosystem)
    found: set[str] = set()
    for pattern, facts in _COMPILED.get(table, []):
        if pattern.fullmatch(text):
            found.update(facts)
    return frozenset(found)


def facts_in_text(ecosystem: str, text: str) -> frozenset[str]:
    """Facts whose ``host`` or ``idiom`` pattern occurs anywhere in ``text``."""
    return frozenset(fact for fact, _match in text_matches(ecosystem, text))


def text_matches(ecosystem: str, text: str) -> list[tuple[str, re.Match[str]]]:
    """The first match of every ``host`` or ``idiom`` pattern in lower-cased ``text``."""
    lowered = text.lower()
    found: list[tuple[str, re.Match[str]]] = []
    for pattern, facts in _COMPILED.get(ecosystem, []):
        match = pattern.search(lowered)
        if match:
            found.extend((fact, match) for fact in facts)
    return found


def facts_from_name(name: str) -> frozenset[str]:
    """Facts a free-text technology or model name denotes.

    Rules run in order and each match is removed from the text before the next
    rule, so the most specific alias wins.
    """
    text = name.lower()
    found: set[str] = set()
    for pattern, facts in _NAME_COMPILED:
        text, count = pattern.subn(" ", text)
        if count:
            found.update(facts)
    return frozenset(found)


def all_known_facts() -> frozenset[str]:
    facts: set[str] = set()
    for rule in RULES + NAME_RULES:
        facts.update(rule.facts)
    return frozenset(facts)


# --- committed configuration surfaces ---------------------------------------------------------------
# (regex over the posix relative path, fact, optional content check name used by the evidence extractor)
CONFIG_PATH_RULES: tuple[tuple[str, str, str | None], ...] = (
    (r"(^|/)\.mcp\.json$", "mcp-client-config:claude-code", "mcp_servers"),
    (r"(^|/)\.cursor/mcp\.json$", "mcp-client-config:cursor", "mcp_servers"),
    (r"(^|/)\.vscode/mcp\.json$", "mcp-client-config:vscode", "mcp_servers_or_servers"),
    (r"(^|/)\.vscode/settings\.json$", "mcp-client-config:vscode", "vscode_settings_mcp"),
    (r"(^|/)claude_desktop_config\.json$", "mcp-client-config:claude-desktop", "mcp_servers"),
    (r"(^|/)\.gemini/settings\.json$", "mcp-client-config:gemini-cli", "mcp_servers"),
    (r"(^|/)\.codex/config\.toml$", "mcp-client-config:codex", "codex_mcp"),
    (r"(^|/)\.kiro/settings/mcp\.json$", "mcp-client-config:kiro", "mcp_servers"),
    (r"(^|/)\.roo/mcp\.json$", "mcp-client-config:roo", "mcp_servers"),
    (r"(^|/)\.windsurf/mcp\.json$", "mcp-client-config:windsurf", "mcp_servers"),
    (r"(^|/)\.amazonq/mcp\.json$", "mcp-client-config:amazon-q", "mcp_servers"),
    (r"(^|/)cline_mcp_settings\.json$", "mcp-client-config:cline", "mcp_servers"),
    (r"(^|/)\.continue/config\.(json|yaml|yml)$", "mcp-client-config:continue", "continue_mcp"),
    (r"(^|/)\.zed/settings\.json$", "mcp-client-config:zed", "zed_context_servers"),
    (r"(^|/)opencode\.jsonc?$", "mcp-client-config:opencode", "opencode_mcp"),
    (r"(^|/)mcp\.json$", "mcp-client-config:generic", "mcp_servers"),
    (r"(^|/)CLAUDE\.md$", "agent-config:claude-md", None),
    (r"(^|/)\.claude/(agents|skills|commands|hooks|rules)(/|$)", "agent-config:claude-dir", None),
    (r"(^|/)\.claude/settings(\.local)?\.json$", "agent-config:claude-dir", None),
    (r"(^|/)\.claude-plugin(/|$)", "agent-config:claude-dir", None),
    (r"(^|/)AGENTS\.md$", "agent-config:agents-md", None),
    (r"(^|/)\.cursor/rules(/|$)", "agent-config:cursor-rules", None),
    (r"(^|/)\.cursorrules$", "agent-config:cursor-rules", None),
    (r"(^|/)\.github/copilot-instructions\.md$", "agent-config:copilot-instructions", None),
    (r"(^|/)\.github/instructions/.*\.instructions\.md$", "agent-config:copilot-instructions", None),
    (r"(^|/)\.github/prompts/.*\.prompt\.md$", "agent-config:copilot-instructions", None),
    (r"(^|/)\.github/agents/.*\.agent\.md$", "agent-config:copilot-agents", None),
    (r"(^|/)\.github/chatmodes/.*\.chatmode\.md$", "agent-config:copilot-agents", None),
    (r"(^|/)GEMINI\.md$", "agent-config:gemini-md", None),
    (r"(^|/)\.clinerules(/|$)", "agent-config:clinerules", None),
    (r"(^|/)\.roo/(rules|rules-[^/]+)(/|$)", "agent-config:roo", None),
    (r"(^|/)\.roomodes$", "agent-config:roo", None),
    (r"(^|/)\.roorules[^/]*$", "agent-config:roo", None),
    (r"(^|/)\.windsurfrules$", "agent-config:windsurf", None),
    (r"(^|/)\.windsurf/rules(/|$)", "agent-config:windsurf", None),
    (r"(^|/)\.codex/config\.toml$", "agent-config:codex", None),
    (r"(^|/)\.kiro/steering(/|$)", "agent-config:kiro", None),
    (r"(^|/)\.junie/guidelines\.md$", "agent-config:junie", None),
    (r"(^|/)\.goosehints$", "agent-config:goose", None),
    (r"(^|/)SKILL\.md$", "agent-config:skills", None),
    (r"(^|/)\.continue/(rules|prompts)(/|$)", "agent-config:continue", None),
    (r"(^|/)\.aider\.conf\.yml$", "agent-config:aider", None),
    (r"(^|/)\.amp(/|$)", "agent-config:amp", None),
    (r"(^|/)\.augment(/|$)", "agent-config:augment", None),
    (r"(^|/)\.well-known/agent(-card)?\.json$", "a2a:agent-card", None),
)
_CONFIG_COMPILED: list[tuple[re.Pattern[str], str, str | None]] = [
    (re.compile(p), fact, check) for p, fact, check in CONFIG_PATH_RULES
]


def config_rules() -> list[tuple[re.Pattern[str], str, str | None]]:
    return list(_CONFIG_COMPILED)


def facts_for_config_path(path: str) -> frozenset[str]:
    """Facts a committed configuration path denotes, judged by its path alone."""
    text = path.replace("\\", "/")
    if "://" not in text and ":" in text.rsplit("/", 1)[-1]:
        text = text.rsplit(":", 1)[0]  # strip a trailing :line
    found: set[str] = set()
    for pattern, fact, _check in _CONFIG_COMPILED:
        if pattern.search(text):
            found.add(fact)
    if len([f for f in found if f.startswith("mcp-client-config:")]) > 1:
        found.discard("mcp-client-config:generic")
    return frozenset(found)
