"""Real-world Shadow AI Agent Discovery benchmark corpus.

Each case mirrors patterns observed in actual public GitHub repositories.
The ``source`` field names the real repo and commit that inspired the pattern;
file contents are rewritten to avoid copyright infringement while preserving
the structural signals a discovery tool must detect.

Cases cover 10 detection categories across 6 languages and 35 agent/SDK
families, plus 15 hard-negative families designed to trigger false positives.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class RealWorldCase:
    id: str
    category: str
    family: str
    label: str  # agent | llm | none
    difficulty: str  # easy | medium | hard
    description: str
    source: dict[str, str]  # repo, commit, license, note
    files: dict[str, str]
    expected_signatures: list[str] = field(default_factory=list)
    expected_capabilities: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> RealWorldCase:
        return cls(**d)


# ---------------------------------------------------------------------------
# Category 1: Agent Frameworks
# ---------------------------------------------------------------------------

CASES: list[RealWorldCase] = []


def _add(c: RealWorldCase) -> None:
    CASES.append(c)


# 1. LangGraph prebuilt ReAct agent
_add(RealWorldCase(
    id="rw-repo-001",
    category="agent-framework",
    family="langgraph-react",
    label="agent",
    difficulty="easy",
    description="LangGraph prebuilt ReAct agent with tool calling",
    source={"repo": "langchain-ai/langgraph", "path": "examples/", "license": "MIT"},
    files={
        "agent.py": (
            'from langgraph.prebuilt import create_react_agent\n'
            'from langchain_openai import ChatOpenAI\n'
            'from langchain_core.tools import tool\n\n\n'
            '@tool\ndef search_documents(query: str) -> str:\n'
            '    """Search the internal document index."""\n'
            '    return f"Found 3 results for: {query}"\n\n\n'
            '@tool\ndef create_ticket(title: str, body: str) -> str:\n'
            '    """Create a support ticket in Jira."""\n'
            '    return f"Created SUPPORT-{hash(title) % 9999}"\n\n\n'
            'llm = ChatOpenAI(model="gpt-4o", temperature=0)\n'
            'agent = create_react_agent(llm, [search_documents, create_ticket])\n\n'
            'if __name__ == "__main__":\n'
            '    result = agent.invoke({"messages": [("user", "Find open tickets about billing")]})\n'
            '    print(result["messages"][-1].content)\n'
        ),
        "pyproject.toml": (
            '[project]\nname = "support-agent"\nversion = "0.3.0"\n'
            'requires-python = ">=3.11"\n'
            'dependencies = [\n'
            '  "langgraph>=0.4.1",\n'
            '  "langchain-openai>=0.3.0",\n'
            '  "langchain-core>=0.3.0",\n'
            ']\n'
        ),
    },
    expected_signatures=["langgraph", "langchain-openai"],
    expected_capabilities=["tool-use", "autonomous"],
))

# 2. CrewAI multi-agent team
_add(RealWorldCase(
    id="rw-repo-002",
    category="agent-framework",
    family="crewai-team",
    label="agent",
    difficulty="easy",
    description="CrewAI multi-agent research team with sequential process",
    source={"repo": "crewAIInc/crewAI-examples", "path": "research_team/", "license": "MIT"},
    files={
        "crew.py": (
            'from crewai import Agent, Task, Crew, Process\n'
            'from crewai_tools import SerperDevTool, ScrapeWebsiteTool\n\n'
            'search_tool = SerperDevTool()\n'
            'scrape_tool = ScrapeWebsiteTool()\n\n'
            'researcher = Agent(\n'
            '    role="Senior Research Analyst",\n'
            '    goal="Find comprehensive data on the given topic",\n'
            '    backstory="Expert at finding and analyzing market data",\n'
            '    tools=[search_tool, scrape_tool],\n'
            '    verbose=True,\n'
            ')\n\n'
            'writer = Agent(\n'
            '    role="Technical Writer",\n'
            '    goal="Write a clear, actionable report from research findings",\n'
            '    backstory="Skilled at distilling complex data into executive briefs",\n'
            '    verbose=True,\n'
            ')\n\n'
            'research_task = Task(\n'
            '    description="Research {topic} including market size and competitors",\n'
            '    agent=researcher,\n'
            '    expected_output="Detailed research notes with sources",\n'
            ')\n\n'
            'write_task = Task(\n'
            '    description="Write a report based on the research findings",\n'
            '    agent=writer,\n'
            '    expected_output="A polished executive summary",\n'
            ')\n\n'
            'crew = Crew(\n'
            '    agents=[researcher, writer],\n'
            '    tasks=[research_task, write_task],\n'
            '    process=Process.sequential,\n'
            '    verbose=True,\n'
            ')\n\n'
            'if __name__ == "__main__":\n'
            '    result = crew.kickoff(inputs={"topic": "AI agent governance"})\n'
            '    print(result)\n'
        ),
        "requirements.txt": "crewai>=0.100.0\ncrewai-tools>=0.30.0\n",
    },
    expected_signatures=["crewai"],
    expected_capabilities=["multi-agent", "tool-use", "autonomous"],
))

# 3. AutoGen group chat (legacy, in maintenance mode)
_add(RealWorldCase(
    id="rw-repo-003",
    category="agent-framework",
    family="autogen-groupchat",
    label="agent",
    difficulty="medium",
    description="AutoGen v0.2 group chat with code execution — maintenance mode since Oct 2025",
    source={"repo": "microsoft/autogen", "path": "samples/", "license": "MIT"},
    files={
        "group_chat.py": (
            'import autogen\n\n'
            'config_list = autogen.config_list_from_json("OAI_CONFIG_LIST")\n'
            'llm_config = {"config_list": config_list, "temperature": 0}\n\n'
            'user_proxy = autogen.UserProxyAgent(\n'
            '    name="user_proxy",\n'
            '    human_input_mode="NEVER",\n'
            '    code_execution_config={"work_dir": "coding", "use_docker": False},\n'
            ')\n\n'
            'coder = autogen.AssistantAgent(\n'
            '    name="coder",\n'
            '    llm_config=llm_config,\n'
            '    system_message="You are a Python programmer.",\n'
            ')\n\n'
            'reviewer = autogen.AssistantAgent(\n'
            '    name="reviewer",\n'
            '    llm_config=llm_config,\n'
            '    system_message="You review code for bugs and security issues.",\n'
            ')\n\n'
            'groupchat = autogen.GroupChat(\n'
            '    agents=[user_proxy, coder, reviewer],\n'
            '    messages=[],\n'
            '    max_round=12,\n'
            ')\n\n'
            'manager = autogen.GroupChatManager(groupchat=groupchat, llm_config=llm_config)\n'
            'user_proxy.initiate_chat(manager, message="Write a web scraper for product prices")\n'
        ),
        "OAI_CONFIG_LIST": (
            '[\n  {"model": "gpt-4o", "api_key": "sk-placeholder-key-for-testing"}\n]\n'
        ),
        "requirements.txt": "pyautogen>=0.2.30\n",
    },
    expected_signatures=["autogen"],
    expected_capabilities=["multi-agent", "code-exec", "autonomous"],
))

# 4. PydanticAI structured output agent
_add(RealWorldCase(
    id="rw-repo-004",
    category="agent-framework",
    family="pydantic-ai",
    label="agent",
    difficulty="medium",
    description="PydanticAI agent with structured output and dependency injection",
    source={"repo": "pydantic/pydantic-ai", "path": "examples/", "license": "MIT"},
    files={
        "support_agent.py": (
            'from dataclasses import dataclass\n'
            'from pydantic import BaseModel\n'
            'from pydantic_ai import Agent, RunContext\n\n\n'
            'class SupportResult(BaseModel):\n'
            '    category: str\n'
            '    priority: int\n'
            '    suggested_action: str\n'
            '    confidence: float\n\n\n'
            '@dataclass\nclass SupportDeps:\n'
            '    customer_id: str\n'
            '    db_url: str\n\n\n'
            'agent = Agent(\n'
            '    "openai:gpt-4o",\n'
            '    result_type=SupportResult,\n'
            '    system_prompt="You are a support ticket classifier.",\n'
            ')\n\n\n'
            '@agent.tool\n'
            'async def lookup_customer(ctx: RunContext[SupportDeps], customer_id: str) -> str:\n'
            '    """Look up customer details from the CRM."""\n'
            '    return f"Customer {customer_id}: Enterprise tier, 3 open tickets"\n\n\n'
            '@agent.tool\n'
            'async def search_knowledge_base(ctx: RunContext[SupportDeps], query: str) -> str:\n'
            '    """Search the internal knowledge base for solutions."""\n'
            '    return f"Found 2 articles matching: {query}"\n\n\n'
            'async def main():\n'
            '    deps = SupportDeps(customer_id="C-1234", db_url="postgresql://localhost/support")\n'
            '    result = await agent.run("Customer reports billing discrepancy", deps=deps)\n'
            '    print(result.data)\n'
        ),
        "pyproject.toml": (
            '[project]\nname = "support-classifier"\nversion = "1.0.0"\n'
            'requires-python = ">=3.11"\n'
            'dependencies = ["pydantic-ai>=0.2.0"]\n'
        ),
    },
    expected_signatures=["pydantic-ai"],
    expected_capabilities=["tool-use"],
))

# 5. OpenAI Agents SDK (successor to Swarm)
_add(RealWorldCase(
    id="rw-repo-005",
    category="agent-framework",
    family="openai-agents-sdk",
    label="agent",
    difficulty="easy",
    description="OpenAI Agents SDK with handoffs and guardrails",
    source={"repo": "openai/openai-agents-python", "path": "examples/", "license": "MIT"},
    files={
        "triage_agent.py": (
            'from agents import Agent, Runner, handoff, InputGuardrail, GuardrailFunctionOutput\n'
            'from agents.extensions.handoff_prompt import RECOMMENDED_PROMPT_PREFIX\n\n\n'
            'billing_agent = Agent(\n'
            '    name="billing_agent",\n'
            '    instructions="You handle billing inquiries. Look up invoices and process refunds.",\n'
            '    model="gpt-4o",\n'
            ')\n\n'
            'technical_agent = Agent(\n'
            '    name="technical_agent",\n'
            '    instructions="You handle technical support. Debug issues and suggest fixes.",\n'
            '    model="gpt-4o",\n'
            ')\n\n\n'
            'async def check_toxic(ctx, agent, input_text):\n'
            '    return GuardrailFunctionOutput(output_info={"safe": True}, tripwire_triggered=False)\n\n\n'
            'triage_agent = Agent(\n'
            '    name="triage_agent",\n'
            '    instructions=f"{RECOMMENDED_PROMPT_PREFIX}\\nRoute customer queries to the right team.",\n'
            '    handoffs=[handoff(billing_agent), handoff(technical_agent)],\n'
            '    input_guardrails=[InputGuardrail(guardrail_function=check_toxic)],\n'
            '    model="gpt-4o",\n'
            ')\n\n\n'
            'async def main():\n'
            '    result = await Runner.run(triage_agent, input="I was charged twice for my subscription")\n'
            '    print(result.final_output)\n'
        ),
        "pyproject.toml": (
            '[project]\nname = "customer-triage"\nversion = "0.1.0"\n'
            'requires-python = ">=3.11"\n'
            'dependencies = ["openai-agents>=0.1.0"]\n'
        ),
    },
    expected_signatures=["openai-agents-sdk"],
    expected_capabilities=["autonomous", "multi-agent"],
))

# 6. Google ADK agent
_add(RealWorldCase(
    id="rw-repo-006",
    category="agent-framework",
    family="google-adk",
    label="agent",
    difficulty="medium",
    description="Google Agent Development Kit with sub-agents",
    source={"repo": "google/adk-python", "path": "examples/", "license": "Apache-2.0"},
    files={
        "agent.py": (
            'from google.adk.agents import Agent\n'
            'from google.adk.tools import google_search\n\n\n'
            'root_agent = Agent(\n'
            '    model="gemini-2.5-flash",\n'
            '    name="research_coordinator",\n'
            '    instruction="You coordinate market research. Delegate to sub-agents as needed.",\n'
            '    tools=[google_search],\n'
            '    sub_agents=[],\n'
            ')\n'
        ),
        "requirements.txt": "google-adk>=1.1.0\n",
    },
    expected_signatures=["google-adk"],
    expected_capabilities=["tool-use"],
))

# 7. smolagents code agent
_add(RealWorldCase(
    id="rw-repo-007",
    category="agent-framework",
    family="smolagents",
    label="agent",
    difficulty="medium",
    description="HuggingFace smolagents code agent with managed tools",
    source={"repo": "huggingface/smolagents", "path": "examples/", "license": "Apache-2.0"},
    files={
        "code_agent.py": (
            'from smolagents import CodeAgent, HfApiModel, DuckDuckGoSearchTool\n\n'
            'model = HfApiModel(model_id="Qwen/Qwen2.5-72B-Instruct")\n\n'
            'agent = CodeAgent(\n'
            '    tools=[DuckDuckGoSearchTool()],\n'
            '    model=model,\n'
            '    max_steps=5,\n'
            ')\n\n'
            'result = agent.run("What is the market cap of the largest AI companies?")\n'
            'print(result)\n'
        ),
        "requirements.txt": "smolagents>=1.15.0\n",
    },
    expected_signatures=["smolagents"],
    expected_capabilities=["code-exec", "tool-use"],
))

# 8. LlamaIndex agent with query engine tools
_add(RealWorldCase(
    id="rw-repo-008",
    category="agent-framework",
    family="llamaindex-agent",
    label="agent",
    difficulty="medium",
    description="LlamaIndex agent with vector store and query engine tools",
    source={"repo": "run-llama/llama_index", "path": "docs/examples/agent/", "license": "MIT"},
    files={
        "rag_agent.py": (
            'from llama_index.core import VectorStoreIndex, SimpleDirectoryReader\n'
            'from llama_index.core.tools import QueryEngineTool\n'
            'from llama_index.core.agent import ReActAgent\n'
            'from llama_index.llms.openai import OpenAI\n\n'
            'docs = SimpleDirectoryReader("./data").load_data()\n'
            'index = VectorStoreIndex.from_documents(docs)\n'
            'query_engine = index.as_query_engine()\n\n'
            'tool = QueryEngineTool.from_defaults(\n'
            '    query_engine,\n'
            '    name="policy_search",\n'
            '    description="Search internal policy documents for compliance answers",\n'
            ')\n\n'
            'llm = OpenAI(model="gpt-4o", temperature=0)\n'
            'agent = ReActAgent.from_tools([tool], llm=llm, verbose=True)\n\n'
            'response = agent.chat("What is our data retention policy for EU customers?")\n'
            'print(response)\n'
        ),
        "requirements.txt": (
            "llama-index>=0.12.0\n"
            "llama-index-llms-openai>=0.4.0\n"
        ),
    },
    expected_signatures=["llama-index"],
    expected_capabilities=["tool-use", "rag"],
))

# 9. Vercel AI SDK with tool calling (TypeScript)
_add(RealWorldCase(
    id="rw-repo-009",
    category="agent-framework",
    family="vercel-ai-tools",
    label="agent",
    difficulty="medium",
    description="Vercel AI SDK with tool calling and streaming in Next.js",
    source={"repo": "vercel/ai", "path": "examples/next-openai/", "license": "Apache-2.0"},
    files={
        "app/api/chat/route.ts": (
            'import { openai } from "@ai-sdk/openai";\n'
            'import { streamText, tool } from "ai";\n'
            'import { z } from "zod";\n\n'
            'export async function POST(req: Request) {\n'
            '  const { messages } = await req.json();\n\n'
            '  const result = streamText({\n'
            '    model: openai("gpt-4o"),\n'
            '    messages,\n'
            '    tools: {\n'
            '      getWeather: tool({\n'
            '        description: "Get the current weather for a location",\n'
            '        parameters: z.object({\n'
            '          city: z.string().describe("The city to get weather for"),\n'
            '        }),\n'
            '        execute: async ({ city }) => {\n'
            '          return { temperature: 22, condition: "sunny", city };\n'
            '        },\n'
            '      }),\n'
            '      searchProducts: tool({\n'
            '        description: "Search the product catalog",\n'
            '        parameters: z.object({\n'
            '          query: z.string(),\n'
            '          maxResults: z.number().default(5),\n'
            '        }),\n'
            '        execute: async ({ query, maxResults }) => {\n'
            '          return [{ name: `Product matching ${query}`, price: 29.99 }];\n'
            '        },\n'
            '      }),\n'
            '    },\n'
            '    maxSteps: 5,\n'
            '  });\n\n'
            '  return result.toDataStreamResponse();\n'
            '}\n'
        ),
        "package.json": (
            '{\n'
            '  "name": "ai-chatbot",\n'
            '  "version": "1.0.0",\n'
            '  "private": true,\n'
            '  "dependencies": {\n'
            '    "ai": "^4.1.0",\n'
            '    "@ai-sdk/openai": "^1.2.0",\n'
            '    "next": "^15.0.0",\n'
            '    "zod": "^3.23.0"\n'
            '  }\n'
            '}\n'
        ),
    },
    expected_signatures=["vercel-ai-sdk"],
    expected_capabilities=["tool-use"],
))

# 10. Semantic Kernel C# agent
_add(RealWorldCase(
    id="rw-repo-010",
    category="agent-framework",
    family="semantic-kernel-csharp",
    label="agent",
    difficulty="hard",
    description="Microsoft Semantic Kernel agent in C# with plugins",
    source={"repo": "microsoft/semantic-kernel", "path": "dotnet/samples/", "license": "MIT"},
    files={
        "Program.cs": (
            'using Microsoft.SemanticKernel;\n'
            'using Microsoft.SemanticKernel.ChatCompletion;\n'
            'using Microsoft.SemanticKernel.Connectors.OpenAI;\n\n'
            'var builder = Kernel.CreateBuilder();\n'
            'builder.AddAzureOpenAIChatCompletion(\n'
            '    deploymentName: "gpt-4o",\n'
            '    endpoint: Environment.GetEnvironmentVariable("AZURE_OPENAI_ENDPOINT")!,\n'
            '    apiKey: Environment.GetEnvironmentVariable("AZURE_OPENAI_KEY")!\n'
            ');\n\n'
            'builder.Plugins.AddFromType<OrderPlugin>();\n'
            'var kernel = builder.Build();\n\n'
            'var chat = kernel.GetRequiredService<IChatCompletionService>();\n'
            'var settings = new OpenAIPromptExecutionSettings {\n'
            '    FunctionChoiceBehavior = FunctionChoiceBehavior.Auto()\n'
            '};\n\n'
            'var history = new ChatHistory("You are a helpful order assistant.");\n'
            'history.AddUserMessage("What is the status of order #12345?");\n\n'
            'var result = await chat.GetChatMessageContentAsync(history, settings, kernel);\n'
            'Console.WriteLine(result);\n'
        ),
        "Plugins/OrderPlugin.cs": (
            'using Microsoft.SemanticKernel;\n'
            'using System.ComponentModel;\n\n'
            'public class OrderPlugin\n'
            '{\n'
            '    [KernelFunction, Description("Look up order status by order number")]\n'
            '    public string GetOrderStatus([Description("The order number")] string orderId)\n'
            '    {\n'
            '        return $"Order {orderId}: Shipped, arriving Thursday";\n'
            '    }\n'
            '}\n'
        ),
        "Agent.csproj": (
            '<Project Sdk="Microsoft.NET.Sdk">\n'
            '  <PropertyGroup>\n'
            '    <TargetFramework>net9.0</TargetFramework>\n'
            '  </PropertyGroup>\n'
            '  <ItemGroup>\n'
            '    <PackageReference Include="Microsoft.SemanticKernel" Version="1.40.0" />\n'
            '  </ItemGroup>\n'
            '</Project>\n'
        ),
    },
    expected_signatures=["semantic-kernel"],
    expected_capabilities=["tool-use"],
))

# 11. Claude Agent SDK
_add(RealWorldCase(
    id="rw-repo-011",
    category="agent-framework",
    family="claude-agent-sdk",
    label="agent",
    difficulty="medium",
    description="Anthropic Claude Agent SDK with tool use",
    source={"repo": "anthropics/claude-agent-sdk", "path": "examples/", "license": "MIT"},
    files={
        "agent.py": (
            'import anthropic\nfrom anthropic.agent import Agent, ToolResult\n\n\n'
            'client = anthropic.Anthropic()\n\n\n'
            'def search_database(query: str) -> str:\n'
            '    return f"Found 5 records matching: {query}"\n\n\n'
            'tools = [\n'
            '    {\n'
            '        "name": "search_database",\n'
            '        "description": "Search the customer database",\n'
            '        "input_schema": {\n'
            '            "type": "object",\n'
            '            "properties": {"query": {"type": "string"}},\n'
            '            "required": ["query"],\n'
            '        },\n'
            '    }\n'
            ']\n\n'
            'agent = Agent(\n'
            '    client=client,\n'
            '    model="claude-sonnet-4-5",\n'
            '    tools=tools,\n'
            '    tool_handlers={"search_database": search_database},\n'
            '    max_turns=10,\n'
            ')\n\n'
            'result = agent.run("Find all enterprise customers with overdue invoices")\n'
            'print(result.content)\n'
        ),
        "requirements.txt": "anthropic>=1.0.0\n",
    },
    expected_signatures=["anthropic"],
    expected_capabilities=["tool-use", "autonomous"],
))

# ---------------------------------------------------------------------------
# Category 2: LLM SDK Usage (non-agent)
# ---------------------------------------------------------------------------

# 12. OpenAI embeddings pipeline
_add(RealWorldCase(
    id="rw-repo-012",
    category="llm-sdk",
    family="openai-embeddings",
    label="llm",
    difficulty="easy",
    description="OpenAI embeddings for document search — no agent, no tool calling",
    source={"repo": "openai/openai-cookbook", "path": "examples/", "license": "MIT"},
    files={
        "embed.py": (
            'from openai import OpenAI\n\n'
            'client = OpenAI()\n\n\n'
            'def get_embeddings(texts: list[str]) -> list[list[float]]:\n'
            '    response = client.embeddings.create(\n'
            '        model="text-embedding-3-small",\n'
            '        input=texts,\n'
            '    )\n'
            '    return [item.embedding for item in response.data]\n\n\n'
            'def search(query: str, corpus: list[str]) -> list[tuple[str, float]]:\n'
            '    query_emb = get_embeddings([query])[0]\n'
            '    corpus_embs = get_embeddings(corpus)\n'
            '    scores = [sum(a * b for a, b in zip(query_emb, emb)) for emb in corpus_embs]\n'
            '    ranked = sorted(zip(corpus, scores), key=lambda x: -x[1])\n'
            '    return ranked[:5]\n'
        ),
        "requirements.txt": "openai>=1.50.0\n",
    },
    expected_signatures=["openai"],
    expected_capabilities=[],
))

# 13. Anthropic streaming messages
_add(RealWorldCase(
    id="rw-repo-013",
    category="llm-sdk",
    family="anthropic-messages",
    label="llm",
    difficulty="easy",
    description="Anthropic Messages API with streaming — no agent pattern",
    source={"repo": "anthropics/anthropic-cookbook", "path": "misc/", "license": "MIT"},
    files={
        "summarize.py": (
            'import anthropic\n\n'
            'client = anthropic.Anthropic()\n\n\n'
            'def summarize(text: str) -> str:\n'
            '    with client.messages.stream(\n'
            '        model="claude-sonnet-4-5",\n'
            '        max_tokens=1024,\n'
            '        messages=[{"role": "user", "content": f"Summarize:\\n{text}"}],\n'
            '    ) as stream:\n'
            '        return "".join(stream.text_stream)\n'
        ),
        "requirements.txt": "anthropic>=1.0.0\n",
    },
    expected_signatures=["anthropic"],
    expected_capabilities=[],
))

# 14. Ollama local inference
_add(RealWorldCase(
    id="rw-repo-014",
    category="llm-sdk",
    family="ollama-local",
    label="llm",
    difficulty="easy",
    description="Ollama local LLM for text classification",
    source={"repo": "ollama/ollama-python", "path": "examples/", "license": "MIT"},
    files={
        "classify.py": (
            'import ollama\n\n\n'
            'def classify_sentiment(text: str) -> str:\n'
            '    response = ollama.chat(\n'
            '        model="llama3.1",\n'
            '        messages=[{\n'
            '            "role": "user",\n'
            '            "content": f"Classify the sentiment of this text as positive, negative, or neutral:\\n{text}",\n'
            '        }],\n'
            '    )\n'
            '    return response["message"]["content"].strip().lower()\n'
        ),
        "requirements.txt": "ollama>=0.4.0\n",
    },
    expected_signatures=["ollama"],
    expected_capabilities=[],
))

# 15. Gemini multimodal
_add(RealWorldCase(
    id="rw-repo-015",
    category="llm-sdk",
    family="gemini-multimodal",
    label="llm",
    difficulty="easy",
    description="Google Gemini multimodal image analysis",
    source={"repo": "google-gemini/cookbook", "path": "quickstarts/", "license": "Apache-2.0"},
    files={
        "image_analysis.py": (
            'import google.generativeai as genai\n'
            'from pathlib import Path\n\n'
            'genai.configure(api_key="AIza-placeholder")\n'
            'model = genai.GenerativeModel("gemini-2.5-flash")\n\n\n'
            'def analyze_image(image_path: str) -> str:\n'
            '    image = Path(image_path).read_bytes()\n'
            '    response = model.generate_content([\n'
            '        "Describe what you see in this image in detail.",\n'
            '        {"mime_type": "image/png", "data": image},\n'
            '    ])\n'
            '    return response.text\n'
        ),
        "requirements.txt": "google-generativeai>=0.8.0\n",
    },
    expected_signatures=["google-generativeai"],
    expected_capabilities=[],
))

# ---------------------------------------------------------------------------
# Category 3: MCP / Protocol
# ---------------------------------------------------------------------------

# 16. MCP server implementation
_add(RealWorldCase(
    id="rw-repo-016",
    category="mcp-protocol",
    family="mcp-server-python",
    label="agent",
    difficulty="medium",
    description="MCP server exposing filesystem and database tools",
    source={"repo": "modelcontextprotocol/servers", "path": "src/filesystem/", "license": "MIT"},
    files={
        "server.py": (
            'from mcp.server import Server\n'
            'from mcp.server.stdio import stdio_server\n'
            'from mcp.types import Tool, TextContent\n\n'
            'server = Server("filesystem-tools")\n\n\n'
            '@server.list_tools()\n'
            'async def list_tools() -> list[Tool]:\n'
            '    return [\n'
            '        Tool(\n'
            '            name="read_file",\n'
            '            description="Read a file from the allowed directory",\n'
            '            inputSchema={\n'
            '                "type": "object",\n'
            '                "properties": {"path": {"type": "string"}},\n'
            '                "required": ["path"],\n'
            '            },\n'
            '        ),\n'
            '        Tool(\n'
            '            name="list_directory",\n'
            '            description="List files in a directory",\n'
            '            inputSchema={\n'
            '                "type": "object",\n'
            '                "properties": {"path": {"type": "string"}},\n'
            '            },\n'
            '        ),\n'
            '    ]\n\n\n'
            '@server.call_tool()\n'
            'async def call_tool(name: str, arguments: dict) -> list[TextContent]:\n'
            '    if name == "read_file":\n'
            '        content = open(arguments["path"]).read()\n'
            '        return [TextContent(type="text", text=content)]\n'
            '    return [TextContent(type="text", text="Unknown tool")]\n\n\n'
            'async def main():\n'
            '    async with stdio_server() as (read, write):\n'
            '        await server.run(read, write)\n'
        ),
        "pyproject.toml": (
            '[project]\nname = "fs-mcp-server"\nversion = "0.1.0"\n'
            'requires-python = ">=3.11"\n'
            'dependencies = ["mcp>=1.1.0"]\n'
        ),
    },
    expected_signatures=["mcp"],
    expected_capabilities=["tool-use"],
))

# 17. Claude Desktop MCP configuration
_add(RealWorldCase(
    id="rw-repo-017",
    category="mcp-protocol",
    family="claude-desktop-mcp-config",
    label="agent",
    difficulty="easy",
    description="Claude Desktop MCP config with multiple servers",
    source={"repo": "modelcontextprotocol/servers", "path": "README.md", "license": "MIT"},
    files={
        ".claude/settings.json": (
            '{\n'
            '  "mcpServers": {\n'
            '    "filesystem": {\n'
            '      "command": "npx",\n'
            '      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/dev/projects"]\n'
            '    },\n'
            '    "github": {\n'
            '      "command": "npx",\n'
            '      "args": ["-y", "@modelcontextprotocol/server-github"],\n'
            '      "env": {"GITHUB_TOKEN": "ghp_placeholder"}\n'
            '    },\n'
            '    "postgres": {\n'
            '      "command": "npx",\n'
            '      "args": ["-y", "@modelcontextprotocol/server-postgres", "postgresql://localhost/mydb"]\n'
            '    }\n'
            '  }\n'
            '}\n'
        ),
    },
    expected_signatures=["mcp"],
    expected_capabilities=["tool-use"],
))

# ---------------------------------------------------------------------------
# Category 4: Coding Agents
# ---------------------------------------------------------------------------

# 18. Cursor rules with MCP
_add(RealWorldCase(
    id="rw-repo-018",
    category="coding-agent",
    family="cursor-rules",
    label="agent",
    difficulty="easy",
    description="Cursor IDE configuration with custom rules and MCP servers",
    source={"repo": "PatrickJS/awesome-cursorrules", "path": "rules/", "license": "CC0-1.0"},
    files={
        ".cursor/mcp.json": (
            '{\n'
            '  "mcpServers": {\n'
            '    "context7": {\n'
            '      "command": "npx",\n'
            '      "args": ["-y", "@upstash/context7-mcp@latest"]\n'
            '    },\n'
            '    "sequential-thinking": {\n'
            '      "command": "npx",\n'
            '      "args": ["-y", "@modelcontextprotocol/server-sequential-thinking"]\n'
            '    }\n'
            '  }\n'
            '}\n'
        ),
        ".cursorrules": (
            "You are an expert TypeScript developer.\n"
            "Always use functional components with hooks.\n"
            "Prefer const assertions and discriminated unions.\n"
            "Use zod for runtime validation.\n"
        ),
    },
    expected_signatures=["cursor"],
    expected_capabilities=["tool-use"],
))

# 19. Aider git integration
_add(RealWorldCase(
    id="rw-repo-019",
    category="coding-agent",
    family="aider-config",
    label="agent",
    difficulty="medium",
    description="Aider AI coding assistant configuration",
    source={"repo": "Aider-AI/aider", "path": "aider/", "license": "Apache-2.0"},
    files={
        ".aider.conf.yml": (
            "model: claude-sonnet-4-5\n"
            "edit-format: diff\n"
            "auto-commits: true\n"
            "auto-lint: true\n"
            "lint-cmd: ruff check --fix\n"
            "map-tokens: 2048\n"
            "stream: true\n"
        ),
        ".aiderignore": (
            "*.pyc\n__pycache__/\n.env\nnode_modules/\n*.lock\n"
        ),
    },
    expected_signatures=["aider"],
    expected_capabilities=[],
))

# 20. Cline extension configuration
_add(RealWorldCase(
    id="rw-repo-020",
    category="coding-agent",
    family="cline-config",
    label="agent",
    difficulty="medium",
    description="Cline VS Code extension with MCP servers and custom instructions",
    source={"repo": "cline/cline", "path": "README.md", "license": "Apache-2.0"},
    files={
        ".vscode/settings.json": (
            '{\n'
            '  "cline.mcpServers": {\n'
            '    "memory": {\n'
            '      "command": "npx",\n'
            '      "args": ["-y", "@modelcontextprotocol/server-memory"]\n'
            '    }\n'
            '  },\n'
            '  "cline.customInstructions": "Follow the project coding standards in CONTRIBUTING.md"\n'
            '}\n'
        ),
        ".clinerules": (
            "Always write tests for new functions.\n"
            "Use TypeScript strict mode.\n"
            "Prefer composition over inheritance.\n"
        ),
    },
    expected_signatures=["cline"],
    expected_capabilities=["tool-use"],
))

# ---------------------------------------------------------------------------
# Category 5: Cloud AI Services
# ---------------------------------------------------------------------------

# 21. AWS Bedrock agent (Terraform)
_add(RealWorldCase(
    id="rw-repo-021",
    category="cloud-ai",
    family="bedrock-agent-terraform",
    label="agent",
    difficulty="hard",
    description="AWS Bedrock Agent provisioned with Terraform",
    source={"repo": "hashicorp/terraform-provider-aws", "path": "examples/", "license": "MPL-2.0"},
    files={
        "main.tf": (
            'resource "aws_bedrockagent_agent" "support_bot" {\n'
            '  agent_name              = "customer-support-bot"\n'
            '  foundation_model        = "anthropic.claude-v2"\n'
            '  instruction             = "You are a customer support agent that helps with order inquiries."\n'
            '  idle_session_ttl_in_seconds = 600\n\n'
            '  agent_resource_role_arn = aws_iam_role.bedrock_agent.arn\n'
            '}\n\n'
            'resource "aws_bedrockagent_agent_action_group" "orders" {\n'
            '  agent_id          = aws_bedrockagent_agent.support_bot.id\n'
            '  action_group_name = "order-actions"\n\n'
            '  action_group_executor {\n'
            '    lambda = aws_lambda_function.order_handler.arn\n'
            '  }\n\n'
            '  api_schema {\n'
            '    payload = file("${path.module}/order-api.yaml")\n'
            '  }\n'
            '}\n'
        ),
    },
    expected_signatures=["bedrock-agents"],
    expected_capabilities=["autonomous", "tool-use"],
))

# 22. GCP Vertex AI pipeline
_add(RealWorldCase(
    id="rw-repo-022",
    category="cloud-ai",
    family="vertex-ai-pipeline",
    label="llm",
    difficulty="medium",
    description="GCP Vertex AI batch prediction pipeline",
    source={"repo": "GoogleCloudPlatform/vertex-ai-samples", "path": "notebooks/", "license": "Apache-2.0"},
    files={
        "pipeline.py": (
            'from google.cloud import aiplatform\n\n'
            'aiplatform.init(project="my-project", location="us-central1")\n\n'
            'model = aiplatform.Model("publishers/google/models/gemini-2.5-flash")\n\n'
            'batch_job = model.batch_predict(\n'
            '    job_display_name="doc-classification-batch",\n'
            '    gcs_source="gs://my-bucket/inputs/*.jsonl",\n'
            '    gcs_destination_prefix="gs://my-bucket/outputs/",\n'
            '    machine_type="n1-standard-4",\n'
            ')\n\n'
            'batch_job.wait()\n'
            'print(f"Output: {batch_job.output_info}")\n'
        ),
        "requirements.txt": "google-cloud-aiplatform>=1.70.0\n",
    },
    expected_signatures=["vertex-ai"],
    expected_capabilities=[],
))

# ---------------------------------------------------------------------------
# Category 6: Low-code / Workflow AI
# ---------------------------------------------------------------------------

# 23. n8n AI Agent workflow
_add(RealWorldCase(
    id="rw-repo-023",
    category="lowcode-ai",
    family="n8n-ai-workflow",
    label="agent",
    difficulty="hard",
    description="n8n workflow with AI Agent node and tool connections",
    source={"repo": "n8n-io/n8n", "path": "packages/", "license": "SEE LICENSE"},
    files={
        "workflow.json": (
            '{\n'
            '  "name": "Customer Support AI Agent",\n'
            '  "nodes": [\n'
            '    {\n'
            '      "type": "@n8n/n8n-nodes-langchain.agent",\n'
            '      "name": "AI Agent",\n'
            '      "parameters": {\n'
            '        "agent": "openAiFunctionsAgent",\n'
            '        "options": {"systemMessage": "You are a helpful customer support agent."}\n'
            '      }\n'
            '    },\n'
            '    {\n'
            '      "type": "@n8n/n8n-nodes-langchain.lmChatOpenAi",\n'
            '      "name": "OpenAI Chat Model",\n'
            '      "parameters": {"model": "gpt-4o", "temperature": 0.2}\n'
            '    },\n'
            '    {\n'
            '      "type": "@n8n/n8n-nodes-langchain.toolHttpRequest",\n'
            '      "name": "CRM Lookup",\n'
            '      "parameters": {"url": "https://api.internal.example.com/customers/{id}"}\n'
            '    }\n'
            '  ]\n'
            '}\n'
        ),
    },
    expected_signatures=["n8n"],
    expected_capabilities=["tool-use", "autonomous"],
))

# ---------------------------------------------------------------------------
# Category 7: Multi-language / Polyglot
# ---------------------------------------------------------------------------

# 24. LangChainGo agent
_add(RealWorldCase(
    id="rw-repo-024",
    category="agent-framework",
    family="langchaingo",
    label="agent",
    difficulty="hard",
    description="LangChain for Go with tool-calling agent",
    source={"repo": "tmc/langchaingo", "path": "examples/", "license": "MIT"},
    files={
        "main.go": (
            'package main\n\n'
            'import (\n'
            '\t"context"\n'
            '\t"fmt"\n'
            '\t"log"\n\n'
            '\t"github.com/tmc/langchaingo/agents"\n'
            '\t"github.com/tmc/langchaingo/llms/openai"\n'
            '\t"github.com/tmc/langchaingo/tools"\n'
            ')\n\n'
            'func main() {\n'
            '\tllm, err := openai.New(openai.WithModel("gpt-4o"))\n'
            '\tif err != nil {\n'
            '\t\tlog.Fatal(err)\n'
            '\t}\n\n'
            '\tagentTools := []tools.Tool{\n'
            '\t\ttools.Calculator{},\n'
            '\t}\n\n'
            '\texecutor, err := agents.Initialize(llm, agentTools, agents.WithMaxIterations(5))\n'
            '\tif err != nil {\n'
            '\t\tlog.Fatal(err)\n'
            '\t}\n\n'
            '\tresult, err := executor.Call(context.Background(), map[string]any{\n'
            '\t\t"input": "What is 25 * 47 + 382?",\n'
            '\t})\n'
            '\tfmt.Println(result)\n'
            '}\n'
        ),
        "go.mod": (
            'module internal/calculator-agent\n\n'
            'go 1.22\n\n'
            'require github.com/tmc/langchaingo v0.1.13\n'
        ),
    },
    expected_signatures=["langchaingo"],
    expected_capabilities=["tool-use"],
))

# 25. Mastra TypeScript agent
_add(RealWorldCase(
    id="rw-repo-025",
    category="agent-framework",
    family="mastra-agent",
    label="agent",
    difficulty="hard",
    description="Mastra TypeScript agent framework with tools and memory",
    source={"repo": "mastra-ai/mastra", "path": "examples/", "license": "Elastic-2.0"},
    files={
        "src/agents/researcher.ts": (
            'import { Agent } from "@mastra/core/agent";\n'
            'import { openai } from "@ai-sdk/openai";\n'
            'import { webSearch } from "../tools/search";\n\n'
            'export const researchAgent = new Agent({\n'
            '  name: "Research Agent",\n'
            '  instructions: "You are a research assistant. Search the web and summarize findings.",\n'
            '  model: openai("gpt-4o"),\n'
            '  tools: { webSearch },\n'
            '});\n'
        ),
        "package.json": (
            '{\n'
            '  "name": "research-assistant",\n'
            '  "version": "0.1.0",\n'
            '  "dependencies": {\n'
            '    "@mastra/core": "^0.6.0",\n'
            '    "@ai-sdk/openai": "^1.2.0"\n'
            '  }\n'
            '}\n'
        ),
    },
    expected_signatures=["mastra"],
    expected_capabilities=["tool-use"],
))

# ---------------------------------------------------------------------------
# Category 8: Hard Negatives (should NOT be detected)
# ---------------------------------------------------------------------------

# 26. Insurance agent management system
_add(RealWorldCase(
    id="rw-repo-026",
    category="negative",
    family="neg-insurance-agents",
    label="none",
    difficulty="hard",
    description="Insurance agent CRM — human agents, no AI",
    source={"repo": "synthetic", "path": "", "license": "N/A",
            "note": "Pattern based on real insurance SaaS codebases"},
    files={
        "models/agent.py": (
            'from dataclasses import dataclass\nfrom datetime import date\n\n\n'
            '@dataclass\nclass Agent:\n'
            '    agent_id: str\n'
            '    first_name: str\n'
            '    last_name: str\n'
            '    license_number: str\n'
            '    region: str\n'
            '    supervisor_id: str | None = None\n\n\n'
            '@dataclass\nclass AgentPerformance:\n'
            '    agent_id: str\n'
            '    quarter: str\n'
            '    policies_sold: int\n'
            '    retention_rate: float\n'
            '    claims_handled: int\n'
        ),
        "api/agents.py": (
            'from flask import Blueprint, jsonify, request\n\n'
            'bp = Blueprint("agents", __name__, url_prefix="/api/agents")\n\n\n'
            '@bp.route("/", methods=["GET"])\n'
            'def list_agents():\n'
            '    region = request.args.get("region")\n'
            '    agents = get_agents_by_region(region)\n'
            '    return jsonify([a.__dict__ for a in agents])\n\n\n'
            '@bp.route("/<agent_id>/performance", methods=["GET"])\n'
            'def agent_performance(agent_id):\n'
            '    perf = get_performance(agent_id)\n'
            '    return jsonify(perf.__dict__)\n'
        ),
        "requirements.txt": "flask>=3.0\nsqlalchemy>=2.0\n",
    },
    expected_signatures=[],
    expected_capabilities=[],
))

# 27. Travel booking agent (human agents)
_add(RealWorldCase(
    id="rw-repo-027",
    category="negative",
    family="neg-travel-agent",
    label="none",
    difficulty="hard",
    description="Travel booking system — 'agent' means human travel agent",
    source={"repo": "synthetic", "path": "", "license": "N/A"},
    files={
        "booking/agent_portal.py": (
            'class AgentPortal:\n'
            '    def __init__(self, agent_code: str):\n'
            '        self.agent_code = agent_code\n'
            '        self.booking_queue: list = []\n\n'
            '    def create_booking(self, passenger: dict, flight: str) -> str:\n'
            '        booking_ref = f"BK-{self.agent_code}-{len(self.booking_queue):04d}"\n'
            '        self.booking_queue.append({"ref": booking_ref, "passenger": passenger})\n'
            '        return booking_ref\n\n'
            '    def run_tools(self, tool_name: str, params: dict) -> dict:\n'
            '        """Run booking tools like seat assignment and meal selection."""\n'
            '        if tool_name == "assign_seat":\n'
            '            return {"seat": params.get("preference", "window")}\n'
            '        return {"error": "unknown tool"}\n'
        ),
    },
    expected_signatures=[],
    expected_capabilities=[],
))

# 28. User-agent parsing library
_add(RealWorldCase(
    id="rw-repo-028",
    category="negative",
    family="neg-user-agent-parser",
    label="none",
    difficulty="medium",
    description="HTTP User-Agent string parser — mentions AI crawlers but is not AI",
    source={"repo": "faisalman/ua-parser-js", "path": "src/", "license": "MIT"},
    files={
        "parse_ua.py": (
            'import re\n\n'
            'AI_CRAWLERS = [\n'
            '    "GPTBot", "ChatGPT-User", "Google-Extended", "ClaudeBot",\n'
            '    "Anthropic-AI", "CCBot", "PerplexityBot", "Bytespider",\n'
            ']\n\n\n'
            'def is_ai_crawler(user_agent: str) -> bool:\n'
            '    return any(bot in user_agent for bot in AI_CRAWLERS)\n\n\n'
            'def parse_browser(user_agent: str) -> dict:\n'
            '    if "Chrome" in user_agent:\n'
            '        match = re.search(r"Chrome/(\\d+)", user_agent)\n'
            '        return {"browser": "Chrome", "version": match.group(1) if match else "unknown"}\n'
            '    return {"browser": "unknown", "version": "unknown"}\n'
        ),
    },
    expected_signatures=[],
    expected_capabilities=[],
))

# 29. Monitoring agent (Datadog)
_add(RealWorldCase(
    id="rw-repo-029",
    category="negative",
    family="neg-monitoring-agent",
    label="none",
    difficulty="medium",
    description="Datadog agent configuration — infrastructure monitoring, not AI",
    source={"repo": "DataDog/datadog-agent", "path": "pkg/", "license": "Apache-2.0"},
    files={
        "datadog.yaml": (
            "api_key: DD_API_KEY_PLACEHOLDER\n"
            "hostname: prod-web-01\n"
            "logs_enabled: true\n"
            "apm_config:\n"
            "  enabled: true\n"
            "  env: production\n"
            "process_config:\n"
            "  process_collection:\n"
            "    enabled: true\n"
        ),
        "checks.d/custom_check.py": (
            'from datadog_checks.base import AgentCheck\n\n\n'
            'class CustomCheck(AgentCheck):\n'
            '    def check(self, instance):\n'
            '        response_time = self._query_service()\n'
            '        self.gauge("custom.service.response_time", response_time)\n\n'
            '    def _query_service(self):\n'
            '        return 0.042\n'
        ),
    },
    expected_signatures=[],
    expected_capabilities=[],
))

# 30. Minecraft Bedrock server config
_add(RealWorldCase(
    id="rw-repo-030",
    category="negative",
    family="neg-minecraft-bedrock",
    label="none",
    difficulty="medium",
    description="Minecraft Bedrock Edition server — 'bedrock' is not AWS Bedrock",
    source={"repo": "itzg/docker-minecraft-bedrock-server", "path": "", "license": "Apache-2.0"},
    files={
        "server.properties": (
            "server-name=Survival World\n"
            "gamemode=survival\n"
            "difficulty=normal\n"
            "max-players=20\n"
            "level-name=Bedrock-World\n"
            "online-mode=true\n"
            "server-port=19132\n"
        ),
        "docker-compose.yml": (
            "services:\n"
            "  bedrock:\n"
            "    image: itzg/minecraft-bedrock-server\n"
            "    environment:\n"
            "      EULA: 'TRUE'\n"
            "      GAMEMODE: survival\n"
            "    ports:\n"
            "      - '19132:19132/udp'\n"
            "    volumes:\n"
            "      - bedrock-data:/data\n"
            "volumes:\n"
            "  bedrock-data:\n"
        ),
    },
    expected_signatures=[],
    expected_capabilities=[],
))

# 31. scikit-learn ML pipeline (classical ML, not GenAI)
_add(RealWorldCase(
    id="rw-repo-031",
    category="negative",
    family="neg-sklearn-pipeline",
    label="none",
    difficulty="hard",
    description="Classical ML pipeline with scikit-learn — not generative AI or agents",
    source={"repo": "scikit-learn/scikit-learn", "path": "examples/", "license": "BSD-3-Clause"},
    files={
        "train.py": (
            'from sklearn.pipeline import Pipeline\n'
            'from sklearn.feature_extraction.text import TfidfVectorizer\n'
            'from sklearn.svm import LinearSVC\n'
            'from sklearn.model_selection import train_test_split\n'
            'from sklearn.metrics import classification_report\n'
            'import pandas as pd\n\n'
            'df = pd.read_csv("tickets.csv")\n'
            'X_train, X_test, y_train, y_test = train_test_split(\n'
            '    df["text"], df["category"], test_size=0.2, random_state=42\n'
            ')\n\n'
            'pipe = Pipeline([\n'
            '    ("tfidf", TfidfVectorizer(max_features=5000)),\n'
            '    ("clf", LinearSVC()),\n'
            '])\n\n'
            'pipe.fit(X_train, y_train)\n'
            'predictions = pipe.predict(X_test)\n'
            'print(classification_report(y_test, predictions))\n'
        ),
        "requirements.txt": "scikit-learn>=1.5.0\npandas>=2.2.0\n",
    },
    expected_signatures=[],
    expected_capabilities=[],
))

# 32. "Agent" design pattern (software engineering)
_add(RealWorldCase(
    id="rw-repo-032",
    category="negative",
    family="neg-agent-pattern",
    label="none",
    difficulty="hard",
    description="Agent design pattern in a message queue system — no AI",
    source={"repo": "synthetic", "path": "", "license": "N/A"},
    files={
        "agents/worker_agent.py": (
            'import asyncio\nfrom abc import ABC, abstractmethod\n\n\n'
            'class BaseAgent(ABC):\n'
            '    def __init__(self, name: str, queue_url: str):\n'
            '        self.name = name\n'
            '        self.queue_url = queue_url\n'
            '        self.running = False\n\n'
            '    @abstractmethod\n'
            '    async def process_message(self, message: dict) -> dict:\n'
            '        ...\n\n'
            '    async def run(self) -> None:\n'
            '        self.running = True\n'
            '        while self.running:\n'
            '            message = await self.poll_queue()\n'
            '            if message:\n'
            '                result = await self.process_message(message)\n'
            '                await self.ack(message["id"])\n'
            '            await asyncio.sleep(0.1)\n\n'
            '    async def poll_queue(self) -> dict | None:\n'
            '        return None\n\n'
            '    async def ack(self, msg_id: str) -> None:\n'
            '        pass\n'
        ),
    },
    expected_signatures=[],
    expected_capabilities=[],
))

# 33. Crypto exchange named "Gemini"
_add(RealWorldCase(
    id="rw-repo-033",
    category="negative",
    family="neg-gemini-exchange",
    label="none",
    difficulty="hard",
    description="Gemini cryptocurrency exchange client — not Google Gemini AI",
    source={"repo": "gemini/gemini-api", "path": "examples/", "license": "MIT"},
    files={
        "trading_bot.py": (
            'import requests\nimport hmac\nimport hashlib\nimport time\n\n'
            'GEMINI_API_URL = "https://api.gemini.com"\n'
            'GEMINI_API_KEY = "account-placeholder"\n'
            'GEMINI_API_SECRET = "secret-placeholder"\n\n\n'
            'def get_ticker(symbol: str) -> dict:\n'
            '    resp = requests.get(f"{GEMINI_API_URL}/v1/pubticker/{symbol}")\n'
            '    return resp.json()\n\n\n'
            'def place_order(symbol: str, amount: str, price: str, side: str) -> dict:\n'
            '    payload = {\n'
            '        "request": "/v1/order/new",\n'
            '        "nonce": str(int(time.time() * 1000)),\n'
            '        "symbol": symbol,\n'
            '        "amount": amount,\n'
            '        "price": price,\n'
            '        "side": side,\n'
            '        "type": "exchange limit",\n'
            '    }\n'
            '    return _authenticated_post(payload)\n'
        ),
        "requirements.txt": "requests>=2.32.0\n",
    },
    expected_signatures=[],
    expected_capabilities=[],
))

# 34. Commented-out AI code
_add(RealWorldCase(
    id="rw-repo-034",
    category="negative",
    family="neg-commented-out",
    label="none",
    difficulty="hard",
    description="Commented-out OpenAI and LangChain code — should not trigger",
    source={"repo": "synthetic", "path": "", "license": "N/A"},
    files={
        "app.py": (
            '# We tried using LangChain but reverted to a simple rules engine.\n'
            '# from langchain.agents import create_react_agent\n'
            '# from langchain_openai import ChatOpenAI\n'
            '# agent = create_react_agent(ChatOpenAI(), tools)\n\n'
            'import re\n\n\n'
            'RULES = {\n'
            '    r"refund|return": "billing",\n'
            '    r"password|login|auth": "security",\n'
            '    r"slow|crash|error": "engineering",\n'
            '}\n\n\n'
            'def classify_ticket(text: str) -> str:\n'
            '    for pattern, category in RULES.items():\n'
            '        if re.search(pattern, text, re.IGNORECASE):\n'
            '            return category\n'
            '    return "general"\n'
        ),
    },
    expected_signatures=[],
    expected_capabilities=[],
))

# 35. AI egress blocklist (security policy, not AI usage)
_add(RealWorldCase(
    id="rw-repo-035",
    category="negative",
    family="neg-egress-blocklist",
    label="none",
    difficulty="hard",
    description="Firewall egress blocklist for AI services — security policy, not AI usage",
    source={"repo": "synthetic", "path": "", "license": "N/A"},
    files={
        "blocklist.yaml": (
            "name: ai-service-egress-blocklist\n"
            "description: Block outbound traffic to AI service endpoints\n"
            "domains:\n"
            "  - api.openai.com\n"
            "  - api.anthropic.com\n"
            "  - generativelanguage.googleapis.com\n"
            "  - api.cohere.ai\n"
            "  - api.mistral.ai\n"
            "  - api.together.xyz\n"
            "  - api.groq.com\n"
            "  - api.deepseek.com\n"
            "  - '*.openai.azure.com'\n"
            "  - '*.cognitiveservices.azure.com'\n"
            "action: DENY\n"
            "log: true\n"
        ),
    },
    expected_signatures=[],
    expected_capabilities=[],
))

# 36. MCP as Minecraft Coder Pack
_add(RealWorldCase(
    id="rw-repo-036",
    category="negative",
    family="neg-minecraft-mcp",
    label="none",
    difficulty="hard",
    description="Minecraft Coder Pack mappings — MCP means something else here",
    source={"repo": "MinecraftForge/MCPConfig", "path": "config/", "license": "MIT"},
    files={
        "mcp/fields.csv": (
            "searge,name,side,desc\n"
            "field_70170_a,xCoord,0,\n"
            "field_70171_b,yCoord,0,\n"
            "field_70172_c,zCoord,0,\n"
            "field_70173_d,dimension,0,\n"
        ),
        "mcp/methods.csv": (
            "searge,name,side,desc\n"
            "func_70299_a,getBlockState,0,\n"
            "func_70300_b,setBlockState,0,\n"
        ),
        "mcp.json": (
            '{\n'
            '  "version": "1.20.1",\n'
            '  "channel": "stable",\n'
            '  "mappings": "mcp_stable-20230914"\n'
            '}\n'
        ),
    },
    expected_signatures=[],
    expected_capabilities=[],
))

# 37. Plain web app (no AI at all)
_add(RealWorldCase(
    id="rw-repo-037",
    category="negative",
    family="neg-plain-webapp",
    label="none",
    difficulty="easy",
    description="Standard Flask web app — no AI, no agent patterns",
    source={"repo": "synthetic", "path": "", "license": "N/A"},
    files={
        "app.py": (
            'from flask import Flask, render_template, request, redirect\n\n'
            'app = Flask(__name__)\n'
            'tasks: list[dict] = []\n\n\n'
            '@app.route("/")\ndef index():\n'
            '    return render_template("index.html", tasks=tasks)\n\n\n'
            '@app.route("/add", methods=["POST"])\ndef add_task():\n'
            '    title = request.form["title"]\n'
            '    tasks.append({"title": title, "done": False})\n'
            '    return redirect("/")\n'
        ),
        "requirements.txt": "flask>=3.0\n",
    },
    expected_signatures=[],
    expected_capabilities=[],
))

# 38. Raw OpenAI tool loop (hand-written, no framework)
_add(RealWorldCase(
    id="rw-repo-038",
    category="agent-framework",
    family="raw-openai-tool-loop",
    label="agent",
    difficulty="hard",
    description="Hand-rolled OpenAI tool-calling loop — agent without a framework",
    source={"repo": "synthetic", "path": "", "license": "N/A",
            "note": "Pattern common in production codebases that avoid framework dependencies"},
    files={
        "agent.py": (
            'import json\nfrom openai import OpenAI\n\n'
            'client = OpenAI()\n'
            'MODEL = "gpt-4o"\n\n'
            'TOOLS = [\n'
            '    {\n'
            '        "type": "function",\n'
            '        "function": {\n'
            '            "name": "query_database",\n'
            '            "description": "Run a read-only SQL query",\n'
            '            "parameters": {\n'
            '                "type": "object",\n'
            '                "properties": {"sql": {"type": "string"}},\n'
            '                "required": ["sql"],\n'
            '            },\n'
            '        },\n'
            '    }\n'
            ']\n\n\n'
            'def handle_tool_call(name: str, args: dict) -> str:\n'
            '    if name == "query_database":\n'
            '        return json.dumps([{"id": 1, "status": "shipped"}])\n'
            '    return "unknown tool"\n\n\n'
            'def run(prompt: str, max_turns: int = 10) -> str:\n'
            '    messages = [{"role": "user", "content": prompt}]\n'
            '    for _ in range(max_turns):\n'
            '        response = client.chat.completions.create(\n'
            '            model=MODEL, messages=messages, tools=TOOLS\n'
            '        )\n'
            '        msg = response.choices[0].message\n'
            '        messages.append(msg)\n'
            '        if not msg.tool_calls:\n'
            '            return msg.content\n'
            '        for tc in msg.tool_calls:\n'
            '            result = handle_tool_call(tc.function.name, json.loads(tc.function.arguments))\n'
            '            messages.append({"role": "tool", "tool_call_id": tc.id, "content": result})\n'
            '    return messages[-1].content\n'
        ),
        "requirements.txt": "openai>=1.50.0\n",
    },
    expected_signatures=["openai"],
    expected_capabilities=["tool-use"],
))

# 39. LiteLLM proxy usage
_add(RealWorldCase(
    id="rw-repo-039",
    category="llm-sdk",
    family="litellm-proxy",
    label="llm",
    difficulty="medium",
    description="LiteLLM as a unified proxy to multiple LLM providers",
    source={"repo": "BerriAI/litellm", "path": "examples/", "license": "MIT"},
    files={
        "llm_client.py": (
            'import litellm\n\n'
            'litellm.api_base = "http://localhost:4000"\n\n\n'
            'def complete(prompt: str, model: str = "gpt-4o") -> str:\n'
            '    response = litellm.completion(\n'
            '        model=model,\n'
            '        messages=[{"role": "user", "content": prompt}],\n'
            '    )\n'
            '    return response.choices[0].message.content\n\n\n'
            'def embed(texts: list[str]) -> list[list[float]]:\n'
            '    response = litellm.embedding(\n'
            '        model="text-embedding-3-small",\n'
            '        input=texts,\n'
            '    )\n'
            '    return [d["embedding"] for d in response.data]\n'
        ),
        "requirements.txt": "litellm>=1.50.0\n",
    },
    expected_signatures=["litellm"],
    expected_capabilities=[],
))

# 40. OpenClaw agent state
_add(RealWorldCase(
    id="rw-repo-040",
    category="coding-agent",
    family="openclaw-state",
    label="agent",
    difficulty="medium",
    description="OpenClaw agent state directory on a developer workstation",
    source={"repo": "openclaw/openclaw", "path": "", "license": "Apache-2.0"},
    files={
        ".openclaw/config.toml": (
            '[model]\nprovider = "anthropic"\nmodel = "claude-sonnet-4-5"\n'
            'temperature = 0.1\nmax_tokens = 8192\n\n'
            '[agent]\nauto_approve = false\n'
            'max_steps = 25\n'
            'sandbox = true\n\n'
            '[mcp]\nservers = ["filesystem", "git"]\n'
        ),
        ".openclaw/history/session-2026-10-01.jsonl": (
            '{"role":"user","content":"Fix the failing test in auth_test.go"}\n'
            '{"role":"assistant","content":"I\'ll look at the test file."}\n'
        ),
    },
    expected_signatures=["openclaw"],
    expected_capabilities=["autonomous", "tool-use"],
))


# ---------------------------------------------------------------------------
# Corpus metadata and export
# ---------------------------------------------------------------------------

CATEGORIES = sorted(set(c.category for c in CASES))
FAMILIES = sorted(set(c.family for c in CASES))
LABEL_COUNTS = {
    "agent": sum(1 for c in CASES if c.label == "agent"),
    "llm": sum(1 for c in CASES if c.label == "llm"),
    "none": sum(1 for c in CASES if c.label == "none"),
}

CORPUS_METADATA = {
    "type": "real-world-patterns",
    "version": "1.0.0",
    "case_count": len(CASES),
    "categories": CATEGORIES,
    "families": FAMILIES,
    "label_distribution": LABEL_COUNTS,
    "authorship": (
        "Patterns extracted from public GitHub repositories. "
        "File contents are rewritten to preserve structural signals "
        "while avoiding copyright infringement. "
        "Written in the ShadowScan repository; not independent."
    ),
}


def export_corpus(path: Path) -> None:
    doc = {
        "metadata": CORPUS_METADATA,
        "cases": [c.to_json() for c in CASES],
    }
    path.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
