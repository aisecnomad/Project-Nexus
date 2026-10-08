"""Build the evidence packet annotator A starts from (annotator B gets none).

``python -m tools.realbench.packet --corpus DIR --manifest corpus.json --output DIR``

A packet is a plain-text overview of one checkout: size and file types, the
top of the tree, the README head, AI coding-assistant files, the direct
dependencies declared in each manifest, and ripgrep matches for a broad
vocabulary of generative-AI SDK, framework, protocol, host, model,
configuration and CI identifiers. The vocabulary is written from public SDK
and product documentation; it is deliberately wider than any detector, and
it is not ShadowScan's signature set. A packet is a starting point: the
annotator must confirm every match in the file and look beyond it.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

EXCLUDED_DIRS = (
    ".git", "node_modules", "vendor", "third_party", "third-party", "site-packages", ".venv", "venv",
    "bower_components", "__pycache__", ".tox", ".mypy_cache",
)  # fmt: skip
MAX_HITS_PER_GROUP = 30
MAX_HITS_PER_FILE = 3
MAX_LINE = 180

# group -> (description, ripgrep regex). Matching is case-sensitive unless the
# pattern starts with (?i).
VOCABULARY: dict[str, tuple[str, str]] = {
    "python-import": (
        "Python imports of generative-AI SDKs, agent frameworks and MCP",
        r"^\s*(from|import)\s+(openai|anthropic|google\.genai|google\.generativeai|vertexai|langchain\w*"
        r"|langgraph\w*|llama_index|crewai\w*|autogen\w*|ag2|semantic_kernel|haystack|dspy|smolagents"
        r"|pydantic_ai|agno|phi\.|mistralai|cohere|groq|together|replicate|ollama|litellm|instructor"
        r"|guidance|transformers|diffusers|vllm|llama_cpp|gpt4all|huggingface_hub|mcp\b|fastmcp|strands"
        r"|swarm|camel|letta|openai_agents|agents\b|claude_agent_sdk|claude_code_sdk|google\.adk"
        r"|langfuse|langsmith|chromadb|pinecone|weaviate|qdrant_client|sentence_transformers|whisper)",
    ),
    "js-import": (
        "JavaScript/TypeScript imports of generative-AI SDKs, agent frameworks and MCP",
        r"""(from\s+|require\(\s*|import\(\s*)['"](openai|@anthropic-ai/[\w./-]+|@google/genai"""
        r"""|@google/generative-ai|@google-cloud/vertexai|langchain[\w./-]*|@langchain/[\w./-]+|llamaindex"""
        r"""|ai|@ai-sdk/[\w./-]+|@modelcontextprotocol/[\w./-]+|@mastra/[\w./-]+|ollama[\w./-]*"""
        r"""|@mistralai/[\w./-]+|cohere-ai|groq-sdk|together-ai|replicate|@huggingface/[\w./-]+"""
        r"""|@openai/[\w./-]+|@aws-sdk/client-bedrock[\w-]*|@azure/openai|@xenova/transformers"""
        r"""|@huggingface/transformers|fastmcp|@vercel/ai|openai-edge|gpt-tokenizer|tiktoken)['"]""",
    ),
    "other-import": (
        "Go, JVM, .NET, Rust, Ruby and PHP generative-AI SDK references",
        r"github\.com/(sashabaranov/go-openai|openai/openai-go|anthropics/anthropic-sdk-go|tmc/langchaingo"
        r"|google/generative-ai-go|googleapis/go-genai|ollama/ollama/api|mark3labs/mcp-go"
        r"|modelcontextprotocol/go-sdk|cloudwego/eino|firebase/genkit)"
        r"|service/bedrock(runtime|agent)|(import|using)\s+(dev\.langchain4j|org\.springframework\.ai"
        r"|com\.openai|com\.anthropic|com\.google\.genai|com\.google\.cloud\.vertexai|io\.modelcontextprotocol"
        r"|software\.amazon\.awssdk\.services\.bedrock|Microsoft\.SemanticKernel|OpenAI|Azure\.AI\.OpenAI"
        r"|Azure\.AI\.Inference|Microsoft\.Extensions\.AI|ModelContextProtocol|Amazon\.BedrockRuntime"
        r"|Microsoft\.Agents)|async_openai|rig::|ollama_rs|rmcp::|OpenAI::Client|Anthropic::Client"
        r"|Langchain::|OpenAI\\Client|OpenAI::client|Prism\\Prism",
    ),
    "model-call": (
        "Model, embedding and generation calls",
        r"chat\.completions\.create|ChatCompletion\.create|\.messages\.(create|stream)\(|responses\.create"
        r"|generate_content|generateContent|generateText\(|streamText\(|generateObject\(|streamObject\("
        r"|invoke_model|InvokeModel|\.converse(_stream|Stream)?\(|ChatOpenAI|ChatAnthropic|AzureChatOpenAI"
        r"|ChatOllama|ChatGoogleGenerativeAI|ChatBedrock|ChatVertexAI|ChatMistralAI|ChatGroq|OpenAIEmbeddings"
        r"|embeddings\.create|completions\.create|createChatCompletion|CreateChatCompletion|ollama\.chat"
        r"|ollama\.generate|pipeline\(\s*['\"]text-generation|AutoModelForCausalLM|AutoModelForSeq2SeqLM"
        r"|DiffusionPipeline|StableDiffusion|from_pretrained\(|litellm\.completion|acompletion\(",
    ),
    "agent-construct": (
        "Agent, tool-calling and MCP construction",
        r"AgentExecutor|create_react_agent|create_tool_calling_agent|create_openai_\w*agent|create_agent\("
        r"|initialize_agent|StateGraph\(|ToolNode|bind_tools|\bCrew\(|AssistantAgent|UserProxyAgent"
        r"|GroupChat|Runner\.run|function_tool|@tool\b|tool_calls|tool_choice|function_call|FunctionTool"
        r"|ToolLoopAgent|stopWhen|maxSteps|McpServer|FastMCP|@mcp\.tool|server\.tool\(|registerTool"
        r"|ListToolsRequestSchema|CallToolRequestSchema|add_plugin|KernelFunction|FunctionChoiceBehavior"
        r"|CodeAgent|ToolCallingAgent|LlmAgent|ReActAgent|FunctionAgent|AgentWorkflow|new Agent\("
        r"|Agent\(\s*(name|model|role|instructions|llm|tools)\s*=|tools\s*=\s*\[|\"tools\"\s*:\s*\[",
    ),
    "api-host": (
        "Model provider hosts and local runtimes",
        r"api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|aiplatform\.googleapis"
        r"|openai\.azure\.com|cognitiveservices\.azure\.com|bedrock-runtime|bedrock-agent|openrouter\.ai"
        r"|api\.mistral\.ai|api\.groq\.com|api\.together\.(xyz|ai)|api\.deepseek\.com|api\.x\.ai"
        r"|api\.perplexity\.ai|api\.cohere\.(ai|com)|api-inference\.huggingface\.co|router\.huggingface\.co"
        r"|localhost:11434|127\.0\.0\.1:11434|:11434|/v1/chat/completions|api\.fireworks\.ai",
    ),
    "model-name": (
        "Model identifiers",
        r"(?i)\b(gpt-4[\w.-]*|gpt-3\.5[\w.-]*|gpt-5[\w.-]*|o[134]-mini|text-embedding-[\w-]+"
        r"|claude-(3|sonnet|opus|haiku|instant|2)[\w.-]*|gemini-(1|2|3|pro|flash)[\w.-]*|llama-?[234][\w.:-]*"
        r"|mistral-(7b|large|small|medium|tiny)[\w.-]*|mixtral[\w.-]*|qwen[\w.:-]*|deepseek-(chat|r1|coder|v3)"
        r"|phi-?[34][\w.-]*|gemma[\w.:-]*|command-r[\w.-]*)\b",
    ),
    "env-key": (
        "Provider credential and endpoint variable names",
        r"OPENAI_API_KEY|ANTHROPIC_API_KEY|GEMINI_API_KEY|GOOGLE_GENERATIVE_AI_API_KEY|GOOGLE_API_KEY"
        r"|AZURE_OPENAI\w*|MISTRAL_API_KEY|GROQ_API_KEY|TOGETHER_API_KEY|DEEPSEEK_API_KEY|OPENROUTER_API_KEY"
        r"|COHERE_API_KEY|HF_TOKEN|HUGGINGFACEHUB_API_TOKEN|REPLICATE_API_TOKEN|OLLAMA_HOST|LANGCHAIN_API_KEY"
        r"|LANGSMITH_\w+|XAI_API_KEY|PERPLEXITY_API_KEY|FIREWORKS_API_KEY",
    ),
    "agent-config": (
        "MCP client configuration and agent configuration blocks",
        r"mcpServers|\"mcp\"\s*:\s*\{|\[mcp_servers|mcp_servers\s*:|\"servers\"\s*:\s*\{.*\"(command|url)\"",
    ),
    "workflow-iac": (
        "Workflow exports, infrastructure and model serving",
        r"@n8n/n8n-nodes-langchain|n8n-nodes-base\.openAi|lmChat\w+|aws_bedrockagent_\w+|AWS::Bedrock::\w+"
        r"|CfnAgent|bedrock-agentcore|aws_bedrock_\w+|azurerm_cognitive_deployment|azurerm_ai_\w+"
        r"|Microsoft\.CognitiveServices|kind:\s*['\"]?OpenAI|google_vertex_ai_\w+|ollama/ollama"
        r"|vllm/vllm-openai|vllm serve|berriai/litellm|text-generation-inference|model_list:|open-webui"
        r"|^\s*app:\s*$|^\s*mode:\s*(agent-chat|advanced-chat|completion|chat|workflow)\s*$|flowise|langflow",
    ),
    "ci-agent": (
        "AI agents run from CI",
        r"anthropics/claude-code(-base)?-action|openai/codex-action|run-gemini-cli|coderabbit"
        r"|copilot-swe-agent|aider-chat|claude\s+-p\b|codex\s+exec|gemini\s+-p\b|claude-code",
    ),
    "ml-nongen": (
        "Classical or non-generative ML (for the ml_only attribute)",
        r"^\s*(from|import)\s+(sklearn|torch|tensorflow|keras|xgboost|lightgbm|catboost|stable_baselines3"
        r"|gym|gymnasium|ultralytics|torchvision|jax|flax|mxnet)\b",
    ),
}

ASSISTANT_FILES = re.compile(
    r"(^|/)(AGENTS\.md|CLAUDE\.md|GEMINI\.md|\.cursorrules|\.windsurfrules|\.clinerules|copilot-instructions\.md"
    r"|\.aider[\w.-]*)$|(^|/)(\.cursor/rules|\.github/instructions|\.claude|\.codex|\.gemini|\.continue|\.roo"
    r"|\.kiro|\.junie)/",
)
MCP_FILES = re.compile(r"(^|/)(\.mcp\.json|mcp\.json|claude_desktop_config\.json|mcp_config\.json)$")
MANIFESTS = re.compile(
    r"(^|/)(requirements[\w.-]*\.txt|pyproject\.toml|setup\.py|setup\.cfg|Pipfile|environment\.ya?ml"
    r"|package\.json|go\.mod|pom\.xml|build\.gradle(\.kts)?|[\w.-]+\.csproj|Gemfile|composer\.json"
    r"|Cargo\.toml|mix\.exs|pubspec\.yaml|deno\.json)$"
)


def _rg_files(root: Path) -> list[str]:
    cmd = ["rg", "--files", "--hidden", "--no-ignore", "--no-messages"]
    for d in EXCLUDED_DIRS:
        cmd += ["-g", f"!{d}/"]
    out = subprocess.run(cmd, cwd=root, capture_output=True, text=True, timeout=300).stdout
    return sorted(out.splitlines())


def _rg(root: Path, pattern: str) -> list[tuple[str, int, str]]:
    cmd = [
        "rg", "--hidden", "--no-ignore", "--no-messages", "-n", "--no-heading", "--color", "never",
        "--max-filesize", "1M", "-g", "!*.min.js", "-g", "!*.map", "-g", "!*.lock", "-g", "!*-lock.json",
        "-g", "!*.svg",
    ]  # fmt: skip
    for d in EXCLUDED_DIRS:
        cmd += ["-g", f"!{d}/"]
    cmd += ["-e", pattern, "."]
    proc = subprocess.run(cmd, cwd=root, capture_output=True, text=True, timeout=600, errors="replace")
    hits: list[tuple[str, int, str]] = []
    for line in proc.stdout.splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3 and parts[1].isdigit():
            hits.append((parts[0].removeprefix("./"), int(parts[1]), parts[2].strip()))
    return hits


def manifest_dependencies(path: Path) -> list[str]:
    """Best-effort direct dependency names; the annotator reads the manifest for anything unclear."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")[:200_000]
    except OSError:
        return []
    name = path.name
    deps: list[str] = []
    if name == "package.json":
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            return ["<unparseable package.json>"]
        for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            block = doc.get(section) if isinstance(doc, dict) else None
            if isinstance(block, dict):
                deps += [f"{k} ({section})" for k in block]
    elif name.startswith("requirements") or name == "Pipfile":
        for line in text.splitlines():
            line = line.split("#")[0].strip()
            match = re.match(r"^([A-Za-z0-9_.\-\[\]]+)", line)
            if match and not line.startswith("-"):
                deps.append(match.group(1))
    elif name == "go.mod":
        deps = re.findall(r"^\s*(?:require\s+)?([\w.-]+\.[\w./-]+)\s+v[\d.]", text, re.M)
    elif name.endswith(".csproj"):
        deps = re.findall(r'PackageReference\s+Include="([^"]+)"', text)
    elif name == "pom.xml":
        deps = re.findall(r"<artifactId>([^<]+)</artifactId>", text)[1:]
    elif name.startswith("build.gradle"):
        deps = re.findall(
            r"""(?:implementation|api|compileOnly|runtimeOnly)\s*\(?\s*['"]([^'"]+)['"]""", text
        )
    elif name == "Gemfile":
        deps = re.findall(r"""^\s*gem\s+['"]([^'"]+)['"]""", text, re.M)
    elif name == "composer.json":
        try:
            doc = json.loads(text)
            deps = list((doc.get("require") or {}) | (doc.get("require-dev") or {}))
        except (json.JSONDecodeError, AttributeError, TypeError):
            deps = ["<unparseable composer.json>"]
    else:
        # pyproject.toml, setup.py/cfg, Cargo.toml, environment.yml, mix.exs, pubspec.yaml, deno.json:
        # quoted or key-style package names on dependency-looking lines.
        deps = re.findall(r"""^\s*['"]?([A-Za-z][\w.\-/@]*)['"]?\s*(?:[=<>~!^:]|\[|\s*$)""", text, re.M)
        deps = [d for d in deps if not d.startswith(("[", "#"))][:150]
    return deps


def _clip(text: str) -> str:
    text = text.replace("\t", " ")
    return text if len(text) <= MAX_LINE else text[: MAX_LINE - 3] + "..."


def build(root: Path, repo: dict[str, Any], vocabulary: bool = True) -> str:
    files = _rg_files(root)
    ext = Counter(Path(f).suffix.lower() or "(none)" for f in files)
    top = Counter(f.split("/")[0] + ("/" if "/" in f else "") for f in files)
    out: list[str] = [
        f"# Evidence packet for {repo['id']}",
        f"url: {repo['url']}  commit: {repo['sha']}",
        f"files (excluding vendored dirs): {len(files)}; bytes: {repo['bytes']}",
        "file types: " + ", ".join(f"{k} {v}" for k, v in ext.most_common(15)),
        "",
        "## Top-level entries (file counts)",
        *(f"- {k} ({v})" for k, v in sorted(top.items())[:80]),
    ]
    readme = next((f for f in files if re.fullmatch(r"(?i)readme(\.\w+)?", f)), None)
    if readme:
        head = (root / readme).read_text(encoding="utf-8", errors="replace").splitlines()[:40]
        out += ["", f"## {readme} (first 40 lines)", *(_clip(line) for line in head)]
    if vocabulary:
        assistant = [f for f in files if ASSISTANT_FILES.search(f)]
        mcp = [f for f in files if MCP_FILES.search(f)]
        out += ["", "## AI coding-assistant files", *(f"- {f}" for f in assistant[:40])] if assistant else []
        out += ["", "## MCP configuration file names", *(f"- {f}" for f in mcp[:40])] if mcp else []
    manifests = [f for f in files if MANIFESTS.search(f)][:25]
    if manifests:
        out += ["", "## Manifests and their direct dependencies"]
        for m in manifests:
            deps = manifest_dependencies(root / m)
            out.append(f"- {m}: " + (", ".join(deps[:120]) if deps else "(none parsed)"))
    if not vocabulary:
        return "\n".join(out) + "\n"
    out += ["", "## Vocabulary matches (path:line: text), capped per group and per file"]
    for group, (description, pattern) in VOCABULARY.items():
        hits = _rg(root, pattern)
        per_file: Counter[str] = Counter()
        kept: list[str] = []
        for path, line, text in hits:
            if per_file[path] >= MAX_HITS_PER_FILE:
                continue
            per_file[path] += 1
            kept.append(f"- {path}:{line}: {_clip(text)}")
            if len(kept) >= MAX_HITS_PER_GROUP:
                break
        files_hit = len({h[0] for h in hits})
        out += ["", f"### {group}: {description} ({len(hits)} matches in {files_hit} files)", *kept]
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True, help="directory holding <id>/ checkouts")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ids", default="", help="comma-separated subset")
    parser.add_argument(
        "--structure-only", action="store_true", help="annotator B: tree, README and manifests, no matches"
    )
    args = parser.parse_args(argv)
    repos = json.loads(args.manifest.read_text(encoding="utf-8"))["repos"]
    wanted = set(filter(None, args.ids.split(",")))
    args.output.mkdir(parents=True, exist_ok=True)
    for repo in repos:
        if wanted and repo["id"] not in wanted:
            continue
        text = build(args.corpus / repo["id"], repo, vocabulary=not args.structure_only)
        (args.output / f"{repo['id']}.md").write_text(text, encoding="utf-8")
        print(repo["id"], len(text), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
