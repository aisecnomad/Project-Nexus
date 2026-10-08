"""Real-world Shadow AI Agent Discovery benchmark corpus.

Each case mirrors patterns observed in actual public GitHub repositories.
The ``source`` field names the real repo and commit that inspired the pattern;
file contents are rewritten to avoid copyright infringement while preserving
the structural signals a discovery tool must detect.

Cases cover 10 detection categories across 10+ languages and 70+ agent/SDK
families, plus 39 hard-negative families designed to trigger false positives.
An adversarial category targets known ShadowScan blind spots so author bias
is surfaced rather than hidden.

Corpus version 2.0.0 adds the ``surface`` field (repo | endpoint), an
``adversarial`` category, expanded negatives, and 90+ new cases for a total
of 130.
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
    surface: str = "repo"  # repo | endpoint

    def to_json(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> RealWorldCase:
        return cls(**d)


CASES: list[RealWorldCase] = []


def _add(c: RealWorldCase) -> None:
    CASES.append(c)


# ===================================================================
# Category 1: Agent Frameworks (30 cases)
# ===================================================================

_add(RealWorldCase(
    id="rw-repo-001", category="agent-framework", family="langgraph-react",
    label="agent", difficulty="easy",
    description="LangGraph prebuilt ReAct agent with tool calling",
    source={"repo": "langchain-ai/langgraph", "license": "MIT"},
    files={
        "agent.py": (
            'from langgraph.prebuilt import create_react_agent\n'
            'from langchain_openai import ChatOpenAI\n'
            'from langchain_core.tools import tool\n\n'
            '@tool\ndef search(query: str) -> str:\n'
            '    """Search documents."""\n    return f"Results for {query}"\n\n'
            'llm = ChatOpenAI(model="gpt-4o", temperature=0)\n'
            'agent = create_react_agent(llm, [search])\n'
            'result = agent.invoke({"messages": [("user", "Find billing tickets")]})\n'
        ),
        "pyproject.toml": (
            '[project]\nname = "support-agent"\nversion = "0.3.0"\n'
            'dependencies = ["langgraph>=0.4.1", "langchain-openai>=0.3.0"]\n'
        ),
    },
    expected_signatures=["langgraph", "langchain-openai"],
    expected_capabilities=["tool-use", "autonomous"],
))

_add(RealWorldCase(
    id="rw-repo-002", category="agent-framework", family="crewai-team",
    label="agent", difficulty="easy",
    description="CrewAI multi-agent research team with sequential process",
    source={"repo": "crewAIInc/crewAI-examples", "license": "MIT"},
    files={
        "crew.py": (
            'from crewai import Agent, Task, Crew, Process\n'
            'from crewai_tools import SerperDevTool\n\n'
            'researcher = Agent(role="Analyst", goal="Find data",\n'
            '    backstory="Expert researcher", tools=[SerperDevTool()], verbose=True)\n'
            'writer = Agent(role="Writer", goal="Write report",\n'
            '    backstory="Technical writer", verbose=True)\n\n'
            'research = Task(description="Research {topic}", agent=researcher,\n'
            '    expected_output="Research notes")\n'
            'write = Task(description="Write report", agent=writer,\n'
            '    expected_output="Executive summary")\n\n'
            'crew = Crew(agents=[researcher, writer], tasks=[research, write],\n'
            '    process=Process.sequential, verbose=True)\n'
            'crew.kickoff(inputs={"topic": "AI governance"})\n'
        ),
        "requirements.txt": "crewai>=0.100.0\ncrewai-tools>=0.30.0\n",
    },
    expected_signatures=["crewai"],
    expected_capabilities=["multi-agent", "tool-use", "autonomous"],
))

_add(RealWorldCase(
    id="rw-repo-003", category="agent-framework", family="autogen-groupchat",
    label="agent", difficulty="medium",
    description="AutoGen v0.2 group chat with code execution",
    source={"repo": "microsoft/autogen", "license": "MIT"},
    files={
        "group_chat.py": (
            'import autogen\n\n'
            'config_list = autogen.config_list_from_json("OAI_CONFIG_LIST")\n'
            'llm_config = {"config_list": config_list, "temperature": 0}\n\n'
            'user_proxy = autogen.UserProxyAgent(name="user_proxy",\n'
            '    human_input_mode="NEVER",\n'
            '    code_execution_config={"work_dir": "coding", "use_docker": False})\n'
            'coder = autogen.AssistantAgent(name="coder", llm_config=llm_config)\n\n'
            'groupchat = autogen.GroupChat(agents=[user_proxy, coder], messages=[], max_round=12)\n'
            'manager = autogen.GroupChatManager(groupchat=groupchat, llm_config=llm_config)\n'
            'user_proxy.initiate_chat(manager, message="Write a web scraper")\n'
        ),
        "requirements.txt": "pyautogen>=0.2.30\n",
    },
    expected_signatures=["autogen"],
    expected_capabilities=["multi-agent", "code-exec", "autonomous"],
))

_add(RealWorldCase(
    id="rw-repo-004", category="agent-framework", family="pydantic-ai",
    label="agent", difficulty="medium",
    description="PydanticAI agent with structured output and dependency injection",
    source={"repo": "pydantic/pydantic-ai", "license": "MIT"},
    files={
        "support_agent.py": (
            'from dataclasses import dataclass\nfrom pydantic import BaseModel\n'
            'from pydantic_ai import Agent, RunContext\n\n'
            'class SupportResult(BaseModel):\n'
            '    category: str\n    priority: int\n    action: str\n\n'
            '@dataclass\nclass Deps:\n    customer_id: str\n\n'
            'agent = Agent("openai:gpt-4o", result_type=SupportResult,\n'
            '              system_prompt="You classify support tickets.")\n\n'
            '@agent.tool\nasync def lookup(ctx: RunContext[Deps], cid: str) -> str:\n'
            '    return f"Customer {cid}: Enterprise tier"\n\n'
            'async def main():\n'
            '    result = await agent.run("Billing issue", deps=Deps("C-1234"))\n'
            '    print(result.data)\n'
        ),
        "pyproject.toml": '[project]\nname = "support"\ndependencies = ["pydantic-ai>=0.2.0"]\n',
    },
    expected_signatures=["pydantic-ai"],
    expected_capabilities=["tool-use"],
))

_add(RealWorldCase(
    id="rw-repo-005", category="agent-framework", family="openai-agents-sdk",
    label="agent", difficulty="easy",
    description="OpenAI Agents SDK with handoffs and guardrails",
    source={"repo": "openai/openai-agents-python", "license": "MIT"},
    files={
        "triage.py": (
            'from agents import Agent, Runner, handoff, InputGuardrail, GuardrailFunctionOutput\n\n'
            'billing = Agent(name="billing", instructions="Handle billing.", model="gpt-4o")\n'
            'technical = Agent(name="technical", instructions="Handle tech.", model="gpt-4o")\n\n'
            'async def check_toxic(ctx, agent, text):\n'
            '    return GuardrailFunctionOutput(output_info={"safe": True}, tripwire_triggered=False)\n\n'
            'triage = Agent(name="triage", instructions="Route queries.",\n'
            '    handoffs=[handoff(billing), handoff(technical)],\n'
            '    input_guardrails=[InputGuardrail(guardrail_function=check_toxic)], model="gpt-4o")\n\n'
            'async def main():\n    result = await Runner.run(triage, input="Charged twice")\n'
        ),
        "pyproject.toml": '[project]\ndependencies = ["openai-agents>=0.1.0"]\n',
    },
    expected_signatures=["openai-agents-sdk"],
    expected_capabilities=["autonomous", "multi-agent"],
))

_add(RealWorldCase(
    id="rw-repo-006", category="agent-framework", family="google-adk",
    label="agent", difficulty="medium",
    description="Google Agent Development Kit with sub-agents",
    source={"repo": "google/adk-python", "license": "Apache-2.0"},
    files={
        "agent.py": (
            'from google.adk.agents import Agent\nfrom google.adk.tools import google_search\n\n'
            'root_agent = Agent(model="gemini-2.5-flash", name="researcher",\n'
            '    instruction="You coordinate research.", tools=[google_search], sub_agents=[])\n'
        ),
        "requirements.txt": "google-adk>=1.1.0\n",
    },
    expected_signatures=["google-adk"],
    expected_capabilities=["tool-use"],
))

_add(RealWorldCase(
    id="rw-repo-007", category="agent-framework", family="smolagents",
    label="agent", difficulty="medium",
    description="HuggingFace smolagents code agent with managed tools",
    source={"repo": "huggingface/smolagents", "license": "Apache-2.0"},
    files={
        "code_agent.py": (
            'from smolagents import CodeAgent, HfApiModel, DuckDuckGoSearchTool\n\n'
            'model = HfApiModel(model_id="Qwen/Qwen2.5-72B-Instruct")\n'
            'agent = CodeAgent(tools=[DuckDuckGoSearchTool()], model=model, max_steps=5)\n'
            'print(agent.run("What is the market cap of Apple?"))\n'
        ),
        "requirements.txt": "smolagents>=1.15.0\n",
    },
    expected_signatures=["smolagents"],
    expected_capabilities=["code-exec", "tool-use"],
))

_add(RealWorldCase(
    id="rw-repo-008", category="agent-framework", family="llamaindex-agent",
    label="agent", difficulty="medium",
    description="LlamaIndex agent with vector store and query engine tools",
    source={"repo": "run-llama/llama_index", "license": "MIT"},
    files={
        "rag_agent.py": (
            'from llama_index.core import VectorStoreIndex, SimpleDirectoryReader\n'
            'from llama_index.core.tools import QueryEngineTool\n'
            'from llama_index.core.agent import ReActAgent\n'
            'from llama_index.llms.openai import OpenAI\n\n'
            'docs = SimpleDirectoryReader("./data").load_data()\n'
            'index = VectorStoreIndex.from_documents(docs)\n'
            'tool = QueryEngineTool.from_defaults(index.as_query_engine(),\n'
            '    name="policy", description="Search policies")\n'
            'agent = ReActAgent.from_tools([tool], llm=OpenAI(model="gpt-4o"), verbose=True)\n'
            'agent.chat("Data retention policy?")\n'
        ),
        "requirements.txt": "llama-index>=0.12.0\nllama-index-llms-openai>=0.4.0\n",
    },
    expected_signatures=["llama-index"],
    expected_capabilities=["tool-use", "rag"],
))

_add(RealWorldCase(
    id="rw-repo-009", category="agent-framework", family="vercel-ai-tools",
    label="agent", difficulty="medium",
    description="Vercel AI SDK with tool calling and streaming in Next.js",
    source={"repo": "vercel/ai", "license": "Apache-2.0"},
    files={
        "app/api/chat/route.ts": (
            'import { openai } from "@ai-sdk/openai";\n'
            'import { streamText, tool } from "ai";\nimport { z } from "zod";\n\n'
            'export async function POST(req: Request) {\n'
            '  const { messages } = await req.json();\n'
            '  const result = streamText({\n'
            '    model: openai("gpt-4o"), messages,\n'
            '    tools: {\n'
            '      getWeather: tool({\n'
            '        description: "Get weather",\n'
            '        parameters: z.object({ city: z.string() }),\n'
            '        execute: async ({ city }) => ({ temperature: 22, city }),\n'
            '      }),\n'
            '    }, maxSteps: 5,\n'
            '  });\n  return result.toDataStreamResponse();\n}\n'
        ),
        "package.json": '{"name":"ai-chatbot","dependencies":{"ai":"^4.1.0","@ai-sdk/openai":"^1.2.0"}}\n',
    },
    expected_signatures=["vercel-ai-sdk"],
    expected_capabilities=["tool-use"],
))

_add(RealWorldCase(
    id="rw-repo-010", category="agent-framework", family="semantic-kernel-csharp",
    label="agent", difficulty="hard",
    description="Microsoft Semantic Kernel agent in C# with plugins",
    source={"repo": "microsoft/semantic-kernel", "license": "MIT"},
    files={
        "Program.cs": (
            'using Microsoft.SemanticKernel;\n'
            'using Microsoft.SemanticKernel.ChatCompletion;\n'
            'using Microsoft.SemanticKernel.Connectors.OpenAI;\n\n'
            'var builder = Kernel.CreateBuilder();\n'
            'builder.AddAzureOpenAIChatCompletion("gpt-4o",\n'
            '    Environment.GetEnvironmentVariable("AZURE_OPENAI_ENDPOINT")!,\n'
            '    Environment.GetEnvironmentVariable("AZURE_OPENAI_KEY")!);\n'
            'builder.Plugins.AddFromType<OrderPlugin>();\n'
            'var kernel = builder.Build();\n'
            'var chat = kernel.GetRequiredService<IChatCompletionService>();\n'
            'var settings = new OpenAIPromptExecutionSettings { FunctionChoiceBehavior = FunctionChoiceBehavior.Auto() };\n'
        ),
        "Agent.csproj": (
            '<Project Sdk="Microsoft.NET.Sdk">\n'
            '  <ItemGroup><PackageReference Include="Microsoft.SemanticKernel" Version="1.40.0" /></ItemGroup>\n'
            '</Project>\n'
        ),
    },
    expected_signatures=["semantic-kernel"],
    expected_capabilities=["tool-use"],
))

_add(RealWorldCase(
    id="rw-repo-011", category="agent-framework", family="claude-agent-sdk",
    label="agent", difficulty="medium",
    description="Anthropic Claude Agent SDK with tool use",
    source={"repo": "anthropics/claude-agent-sdk", "license": "MIT"},
    files={
        "agent.py": (
            'import anthropic\n\nclient = anthropic.Anthropic()\n'
            'tools = [{"name": "search_db", "description": "Search customer DB",\n'
            '          "input_schema": {"type": "object", "properties": {"query": {"type": "string"}}}}]\n'
            'response = client.messages.create(model="claude-sonnet-4-5", max_tokens=1024,\n'
            '    tools=tools, messages=[{"role": "user", "content": "Find overdue invoices"}])\n'
        ),
        "requirements.txt": "anthropic>=1.0.0\n",
    },
    expected_signatures=["anthropic"],
    expected_capabilities=["tool-use", "autonomous"],
))

_add(RealWorldCase(
    id="rw-repo-012", category="agent-framework", family="langchaingo",
    label="agent", difficulty="hard",
    description="LangChain for Go with tool-calling agent",
    source={"repo": "tmc/langchaingo", "license": "MIT"},
    files={
        "main.go": (
            'package main\n\nimport (\n\t"context"\n\t"fmt"\n\t"log"\n\n'
            '\t"github.com/tmc/langchaingo/agents"\n'
            '\t"github.com/tmc/langchaingo/llms/openai"\n'
            '\t"github.com/tmc/langchaingo/tools"\n)\n\n'
            'func main() {\n'
            '\tllm, err := openai.New(openai.WithModel("gpt-4o"))\n'
            '\tif err != nil { log.Fatal(err) }\n'
            '\texecutor, err := agents.Initialize(llm, []tools.Tool{tools.Calculator{}},\n'
            '\t\tagents.WithMaxIterations(5))\n'
            '\tif err != nil { log.Fatal(err) }\n'
            '\tresult, _ := executor.Call(context.Background(), map[string]any{"input": "25 * 47?"})\n'
            '\tfmt.Println(result)\n}\n'
        ),
        "go.mod": 'module internal/calc-agent\n\ngo 1.22\n\nrequire github.com/tmc/langchaingo v0.1.13\n',
    },
    expected_signatures=["langchaingo"],
    expected_capabilities=["tool-use"],
))

_add(RealWorldCase(
    id="rw-repo-013", category="agent-framework", family="mastra-agent",
    label="agent", difficulty="hard",
    description="Mastra TypeScript agent framework with tools",
    source={"repo": "mastra-ai/mastra", "license": "Elastic-2.0"},
    files={
        "src/agents/researcher.ts": (
            'import { Agent } from "@mastra/core/agent";\nimport { openai } from "@ai-sdk/openai";\n\n'
            'export const researchAgent = new Agent({\n'
            '  name: "Research Agent", instructions: "You research topics.",\n'
            '  model: openai("gpt-4o"), tools: { webSearch },\n});\n'
        ),
        "package.json": '{"name":"research","dependencies":{"@mastra/core":"^0.6.0","@ai-sdk/openai":"^1.2.0"}}\n',
    },
    expected_signatures=["mastra"],
    expected_capabilities=["tool-use"],
))

_add(RealWorldCase(
    id="rw-repo-014", category="agent-framework", family="ag2-swarm",
    label="agent", difficulty="medium",
    description="AG2 (AutoGen successor) swarm pattern with handoffs",
    source={"repo": "ag2ai/ag2", "license": "Apache-2.0"},
    files={
        "swarm.py": (
            'from autogen import ConversableAgent, initiate_swarm_chat, ON_CONDITION, AFTER_WORK\n\n'
            'triage = ConversableAgent("triage", system_message="Route to specialists.",\n'
            '    llm_config={"config_list": [{"model": "gpt-4o"}]})\n'
            'specialist = ConversableAgent("specialist", system_message="Handle tech issues.",\n'
            '    llm_config={"config_list": [{"model": "gpt-4o"}]})\n\n'
            'triage.register_hand_off(ON_CONDITION(specialist, "Technical issue"))\n'
            'specialist.register_hand_off(AFTER_WORK(triage))\n'
            'initiate_swarm_chat(initial_agent=triage, agents=[triage, specialist],\n'
            '    messages="Server returning 503")\n'
        ),
        "requirements.txt": "ag2[openai]>=0.7.0\n",
    },
    expected_signatures=["autogen"],
    expected_capabilities=["multi-agent", "autonomous"],
))

_add(RealWorldCase(
    id="rw-repo-015", category="agent-framework", family="dspy-pipeline",
    label="agent", difficulty="hard",
    description="DSPy modular pipeline with signatures and optimizers",
    source={"repo": "stanfordnlp/dspy", "license": "MIT"},
    files={
        "rag.py": (
            'import dspy\n\nlm = dspy.LM("openai/gpt-4o")\ndspy.configure(lm=lm)\n\n'
            'class GenerateAnswer(dspy.Signature):\n'
            '    """Answer using context."""\n'
            '    context = dspy.InputField(desc="retrieved docs")\n'
            '    question = dspy.InputField()\n    answer = dspy.OutputField()\n\n'
            'class RAG(dspy.Module):\n'
            '    def __init__(self):\n        super().__init__()\n'
            '        self.retrieve = dspy.Retrieve(k=3)\n'
            '        self.generate = dspy.ChainOfThought(GenerateAnswer)\n'
            '    def forward(self, question):\n'
            '        ctx = self.retrieve(question).passages\n'
            '        return self.generate(context=ctx, question=question)\n'
        ),
        "requirements.txt": "dspy>=2.6.0\n",
    },
    expected_signatures=["dspy"],
    expected_capabilities=["rag"],
))

_add(RealWorldCase(
    id="rw-repo-016", category="agent-framework", family="haystack-agent",
    label="agent", difficulty="medium",
    description="deepset Haystack pipeline with OpenAI chat",
    source={"repo": "deepset-ai/haystack", "license": "Apache-2.0"},
    files={
        "agent.py": (
            'from haystack.components.generators.chat import OpenAIChatGenerator\n'
            'from haystack.dataclasses import ChatMessage\nfrom haystack import Pipeline\n\n'
            'pipe = Pipeline()\npipe.add_component("llm", OpenAIChatGenerator(model="gpt-4o"))\n'
            'messages = [ChatMessage.from_user("Weather in Berlin?")]\n'
            'pipe.run({"llm": {"messages": messages}})\n'
        ),
        "requirements.txt": "haystack-ai>=2.8.0\n",
    },
    expected_signatures=["haystack"],
    expected_capabilities=["tool-use"],
))

_add(RealWorldCase(
    id="rw-repo-017", category="agent-framework", family="spring-ai-java",
    label="agent", difficulty="hard",
    description="Spring AI agent with function calling in Java",
    source={"repo": "spring-projects/spring-ai", "license": "Apache-2.0"},
    files={
        "src/main/java/com/example/ChatController.java": (
            'package com.example;\nimport org.springframework.ai.chat.client.ChatClient;\n'
            'import org.springframework.web.bind.annotation.*;\n\n'
            '@RestController\npublic class ChatController {\n'
            '    private final ChatClient chatClient;\n'
            '    public ChatController(ChatClient.Builder b) { this.chatClient = b.build(); }\n\n'
            '    @PostMapping("/chat")\n    public String chat(@RequestBody String msg) {\n'
            '        return chatClient.prompt().user(msg)\n'
            '            .functions("orderLookup").call().content();\n    }\n}\n'
        ),
        "pom.xml": (
            '<project><dependencies><dependency>\n'
            '  <groupId>org.springframework.ai</groupId>\n'
            '  <artifactId>spring-ai-openai-spring-boot-starter</artifactId>\n'
            '</dependency></dependencies></project>\n'
        ),
    },
    expected_signatures=["spring-ai"],
    expected_capabilities=["tool-use"],
))

_add(RealWorldCase(
    id="rw-repo-018", category="agent-framework", family="langchain4j-agent",
    label="agent", difficulty="hard",
    description="LangChain4j AI service with tools in Java",
    source={"repo": "langchain4j/langchain4j", "license": "Apache-2.0"},
    files={
        "src/main/java/Assistant.java": (
            'import dev.langchain4j.service.AiServices;\nimport dev.langchain4j.model.openai.OpenAiChatModel;\n'
            'import dev.langchain4j.service.SystemMessage;\n\n'
            'interface Assistant {\n    @SystemMessage("You are a service agent.")\n'
            '    String chat(String message);\n}\n\npublic class Main {\n'
            '    public static void main(String[] args) {\n'
            '        var model = OpenAiChatModel.builder().apiKey(System.getenv("OPENAI_API_KEY"))\n'
            '            .modelName("gpt-4o").build();\n'
            '        var asst = AiServices.builder(Assistant.class)\n'
            '            .chatLanguageModel(model).tools(new OrderTools()).build();\n'
            '        System.out.println(asst.chat("Check order #123"));\n    }\n}\n'
        ),
        "build.gradle": 'dependencies {\n    implementation "dev.langchain4j:langchain4j:0.36.0"\n    implementation "dev.langchain4j:langchain4j-open-ai:0.36.0"\n}\n',
    },
    expected_signatures=["langchain4j"],
    expected_capabilities=["tool-use"],
))

_add(RealWorldCase(
    id="rw-repo-019", category="agent-framework", family="agency-swarm",
    label="agent", difficulty="medium",
    description="Agency Swarm multi-agent with CEO and workers",
    source={"repo": "VRSEN/agency-swarm", "license": "MIT"},
    files={
        "agency.py": (
            'from agency_swarm import Agent, Agency, set_openai_key\n\n'
            'set_openai_key("sk-placeholder")\n'
            'ceo = Agent(name="CEO", description="Manages tasks.",\n'
            '    instructions="Coordinate workers.", model="gpt-4o")\n'
            'dev = Agent(name="Dev", description="Writes code.",\n'
            '    instructions="Write Python.", model="gpt-4o")\n'
            'agency = Agency([ceo, [ceo, dev]], shared_instructions="Best practices.")\n'
        ),
        "requirements.txt": "agency-swarm>=0.3.0\n",
    },
    expected_signatures=["agency-swarm"],
    expected_capabilities=["multi-agent", "autonomous"],
))

_add(RealWorldCase(
    id="rw-repo-020", category="agent-framework", family="letta-memgpt",
    label="agent", difficulty="hard",
    description="Letta (formerly MemGPT) agent with persistent memory",
    source={"repo": "letta-ai/letta", "license": "Apache-2.0"},
    files={
        "agent.py": (
            'from letta import create_client\n\nclient = create_client()\n'
            'agent_state = client.create_agent(name="support-agent",\n'
            '    llm_config=client.list_llm_configs()[0],\n'
            '    embedding_config=client.list_embedding_configs()[0],\n'
            '    system="You are a support agent with memory.")\n'
            'response = client.send_message(agent_id=agent_state.id,\n'
            '    role="user", message="Remember customer C-1234 prefers email.")\n'
        ),
        "requirements.txt": "letta>=0.6.0\n",
    },
    expected_signatures=["letta"],
    expected_capabilities=["memory", "autonomous"],
))

_add(RealWorldCase(
    id="rw-repo-021", category="agent-framework", family="phidata-agent",
    label="agent", difficulty="easy",
    description="phidata Agent with finance tools",
    source={"repo": "phidatahq/phidata", "license": "MPL-2.0"},
    files={
        "finance.py": (
            'from phi.agent import Agent\nfrom phi.model.openai import OpenAIChat\n'
            'from phi.tools.yfinance import YFinanceTools\n\n'
            'agent = Agent(model=OpenAIChat(id="gpt-4o"),\n'
            '    tools=[YFinanceTools(stock_price=True)],\n'
            '    instructions=["Use tables"], show_tool_calls=True, markdown=True)\n'
            'agent.print_response("NVDA stock price?")\n'
        ),
        "requirements.txt": "phidata>=2.7.0\n",
    },
    expected_signatures=["phidata"],
    expected_capabilities=["tool-use"],
))

_add(RealWorldCase(
    id="rw-repo-022", category="agent-framework", family="instructor-extraction",
    label="llm", difficulty="medium",
    description="Instructor for structured LLM extraction (not an agent)",
    source={"repo": "jxnl/instructor", "license": "MIT"},
    files={
        "extract.py": (
            'import instructor\nfrom openai import OpenAI\nfrom pydantic import BaseModel\n\n'
            'client = instructor.from_openai(OpenAI())\n\n'
            'class UserInfo(BaseModel):\n    name: str\n    age: int\n\n'
            'user = client.chat.completions.create(model="gpt-4o",\n'
            '    response_model=UserInfo,\n'
            '    messages=[{"role": "user", "content": "John Doe, 30"}])\n'
        ),
        "requirements.txt": "instructor>=1.7.0\nopenai>=1.50.0\n",
    },
    expected_signatures=["instructor"],
))

_add(RealWorldCase(
    id="rw-repo-023", category="agent-framework", family="metagpt-team",
    label="agent", difficulty="hard",
    description="MetaGPT multi-agent software development team",
    source={"repo": "geekan/MetaGPT", "license": "MIT"},
    files={
        "team.py": (
            'import asyncio\nfrom metagpt.roles import ProjectManager, Architect, Engineer\n'
            'from metagpt.team import Team\n\nasync def main():\n'
            '    team = Team()\n    team.hire([ProjectManager(), Architect(), Engineer()])\n'
            '    team.invest(investment=5.0)\n'
            '    team.run_project("Build a CSV to JSON CLI")\n'
            '    await team.run(n_round=3)\n\nasyncio.run(main())\n'
        ),
        "requirements.txt": "metagpt>=0.8.0\n",
    },
    expected_signatures=["metagpt"],
    expected_capabilities=["multi-agent", "code-exec", "autonomous"],
))

_add(RealWorldCase(
    id="rw-repo-024", category="agent-framework", family="autogpt",
    label="agent", difficulty="medium",
    description="AutoGPT autonomous agent configuration",
    source={"repo": "Significant-Gravitas/AutoGPT", "license": "MIT"},
    files={
        ".env.template": 'OPENAI_API_KEY=sk-placeholder\nSMART_LLM=gpt-4o\nFAST_LLM=gpt-4o-mini\n',
        "autogpt/agent.json": '{"ai_name": "ResearchBot", "ai_role": "Autonomous researcher",\n "ai_goals": ["Research topic", "Summarize"], "api_budget": 5.0}\n',
    },
    expected_signatures=["autogpt"],
    expected_capabilities=["autonomous"],
))

_add(RealWorldCase(
    id="rw-repo-025", category="agent-framework", family="composio-agent",
    label="agent", difficulty="medium",
    description="Composio tool integration with LangChain agent",
    source={"repo": "ComposioHQ/composio", "license": "Elastic-2.0"},
    files={
        "github_agent.py": (
            'from composio_langchain import ComposioToolSet, Action\n'
            'from langchain.agents import create_openai_functions_agent, AgentExecutor\n'
            'from langchain_openai import ChatOpenAI\nfrom langchain import hub\n\n'
            'llm = ChatOpenAI(model="gpt-4o")\ntoolset = ComposioToolSet()\n'
            'tools = toolset.get_tools(actions=[Action.GITHUB_STAR_A_REPOSITORY_FOR_THE_AUTHENTICATED_USER])\n'
            'prompt = hub.pull("hwchase17/openai-functions-agent")\n'
            'agent = create_openai_functions_agent(llm, tools, prompt)\n'
            'AgentExecutor(agent=agent, tools=tools).invoke({"input": "Star composio"})\n'
        ),
        "requirements.txt": "composio-langchain>=0.7.0\nlangchain-openai>=0.3.0\n",
    },
    expected_signatures=["composio"],
    expected_capabilities=["tool-use"],
))

_add(RealWorldCase(
    id="rw-repo-026", category="agent-framework", family="semantic-kernel-python",
    label="agent", difficulty="medium",
    description="Semantic Kernel Python agent with plugins",
    source={"repo": "microsoft/semantic-kernel", "license": "MIT"},
    files={
        "agent.py": (
            'import semantic_kernel as sk\n'
            'from semantic_kernel.connectors.ai.open_ai import OpenAIChatCompletion\n'
            'from semantic_kernel.functions import kernel_function\n\n'
            'kernel = sk.Kernel()\nkernel.add_service(OpenAIChatCompletion(ai_model_id="gpt-4o"))\n\n'
            'class OrderPlugin:\n'
            '    @kernel_function(description="Look up order status")\n'
            '    def get_status(self, order_id: str) -> str:\n'
            '        return f"Order {order_id}: Shipped"\n\n'
            'kernel.add_plugin(OrderPlugin(), "orders")\n'
        ),
        "requirements.txt": "semantic-kernel>=1.15.0\n",
    },
    expected_signatures=["semantic-kernel"],
    expected_capabilities=["tool-use"],
))

_add(RealWorldCase(
    id="rw-repo-027", category="agent-framework", family="copilotkit-agent",
    label="agent", difficulty="medium",
    description="CopilotKit in-app AI copilot with React",
    source={"repo": "CopilotKit/CopilotKit", "license": "MIT"},
    files={
        "src/app/page.tsx": (
            'import { CopilotKit } from "@copilotkit/react-core";\n'
            'import { CopilotSidebar } from "@copilotkit/react-ui";\n'
            'import { useCopilotAction } from "@copilotkit/react-core";\n\n'
            'export default function App() {\n'
            '  useCopilotAction({ name: "createTask", description: "Create task",\n'
            '    parameters: [{ name: "title", type: "string" }],\n'
            '    handler: async ({ title }) => console.log("Created:", title),\n'
            '  });\n  return <CopilotKit runtimeUrl="/api/copilotkit"><CopilotSidebar /></CopilotKit>;\n}\n'
        ),
        "package.json": '{"dependencies":{"@copilotkit/react-core":"^1.4.0","@copilotkit/react-ui":"^1.4.0"}}\n',
    },
    expected_signatures=["copilotkit"],
    expected_capabilities=["tool-use"],
))

_add(RealWorldCase(
    id="rw-repo-028", category="agent-framework", family="browser-use-agent",
    label="agent", difficulty="medium",
    description="Browser-use AI agent for web automation",
    source={"repo": "browser-use/browser-use", "license": "MIT"},
    files={
        "search.py": (
            'from langchain_openai import ChatOpenAI\nfrom browser_use import Agent\nimport asyncio\n\n'
            'async def main():\n'
            '    agent = Agent(task="Find cheapest NYC to London flight",\n'
            '        llm=ChatOpenAI(model="gpt-4o"))\n'
            '    print(await agent.run())\n\nasyncio.run(main())\n'
        ),
        "requirements.txt": "browser-use>=0.2.0\nlangchain-openai>=0.3.0\n",
    },
    expected_signatures=["browser-use"],
    expected_capabilities=["autonomous", "tool-use"],
))

_add(RealWorldCase(
    id="rw-repo-029", category="agent-framework", family="langchain-lcel-agent",
    label="agent", difficulty="medium",
    description="LangChain LCEL agent with custom tool binding",
    source={"repo": "langchain-ai/langchain", "license": "MIT"},
    files={
        "lcel_agent.py": (
            'from langchain_openai import ChatOpenAI\nfrom langchain_core.tools import tool\n'
            'from langchain.agents import create_tool_calling_agent, AgentExecutor\n'
            'from langchain import hub\n\n'
            '@tool\ndef search(query: str) -> str:\n    """Search the web."""\n    return f"Results: {query}"\n\n'
            'llm = ChatOpenAI(model="gpt-4o")\nprompt = hub.pull("hwchase17/openai-tools-agent")\n'
            'agent = create_tool_calling_agent(llm, [search], prompt)\n'
            'AgentExecutor(agent=agent, tools=[search]).invoke({"input": "AI news"})\n'
        ),
        "requirements.txt": "langchain>=0.3.0\nlangchain-openai>=0.3.0\n",
    },
    expected_signatures=["langchain"],
    expected_capabilities=["tool-use"],
))

_add(RealWorldCase(
    id="rw-repo-030", category="agent-framework", family="openai-swarm-node",
    label="agent", difficulty="hard",
    description="OpenAI Swarm pattern reimplemented in Node.js",
    source={"repo": "openai/swarm", "license": "MIT"},
    files={
        "src/swarm.ts": (
            'import OpenAI from "openai";\n\nconst client = new OpenAI();\n\n'
            'interface Agent { name: string; instructions: string; functions: any[]; model: string; }\n\n'
            'async function runSwarm(agent: Agent, messages: any[]) {\n'
            '  return client.chat.completions.create({\n'
            '    model: agent.model,\n'
            '    messages: [{ role: "system", content: agent.instructions }, ...messages],\n'
            '    tools: agent.functions.map(f => ({ type: "function", function: f })),\n'
            '  });\n}\n'
        ),
        "package.json": '{"name":"swarm-node","dependencies":{"openai":"^4.73.0"}}\n',
    },
    expected_signatures=["openai"],
    expected_capabilities=["multi-agent", "tool-use"],
))

# ===================================================================
# Category 2: LLM SDK Usage (12 cases)
# ===================================================================

_add(RealWorldCase(
    id="rw-repo-031", category="llm-sdk", family="openai-embeddings",
    label="llm", difficulty="easy",
    description="OpenAI embeddings for document search",
    source={"repo": "openai/openai-cookbook", "license": "MIT"},
    files={
        "embed.py": (
            'from openai import OpenAI\n\nclient = OpenAI()\n\n'
            'def get_embeddings(texts: list[str]) -> list:\n'
            '    resp = client.embeddings.create(model="text-embedding-3-small", input=texts)\n'
            '    return [item.embedding for item in resp.data]\n'
        ),
        "requirements.txt": "openai>=1.50.0\n",
    },
    expected_signatures=["openai"],
))

_add(RealWorldCase(
    id="rw-repo-032", category="llm-sdk", family="anthropic-messages",
    label="llm", difficulty="easy",
    description="Anthropic Messages API with streaming",
    source={"repo": "anthropics/anthropic-cookbook", "license": "MIT"},
    files={
        "summarize.py": (
            'import anthropic\n\nclient = anthropic.Anthropic()\n\n'
            'def summarize(text: str) -> str:\n'
            '    with client.messages.stream(model="claude-sonnet-4-5", max_tokens=1024,\n'
            '            messages=[{"role": "user", "content": f"Summarize:\\n{text}"}]) as s:\n'
            '        return "".join(s.text_stream)\n'
        ),
        "requirements.txt": "anthropic>=1.0.0\n",
    },
    expected_signatures=["anthropic"],
))

_add(RealWorldCase(
    id="rw-repo-033", category="llm-sdk", family="ollama-local",
    label="llm", difficulty="easy",
    description="Ollama local LLM for classification",
    source={"repo": "ollama/ollama-python", "license": "MIT"},
    files={
        "classify.py": (
            'import ollama\n\ndef classify(text: str) -> str:\n'
            '    resp = ollama.chat(model="llama3.1",\n'
            '        messages=[{"role": "user", "content": f"Classify: {text}"}])\n'
            '    return resp["message"]["content"].strip().lower()\n'
        ),
        "requirements.txt": "ollama>=0.4.0\n",
    },
    expected_signatures=["ollama"],
))

_add(RealWorldCase(
    id="rw-repo-034", category="llm-sdk", family="gemini-multimodal",
    label="llm", difficulty="easy",
    description="Google Gemini multimodal image analysis",
    source={"repo": "google-gemini/cookbook", "license": "Apache-2.0"},
    files={
        "image.py": (
            'import google.generativeai as genai\nfrom pathlib import Path\n\n'
            'genai.configure(api_key="AIza-placeholder")\n'
            'model = genai.GenerativeModel("gemini-2.5-flash")\n\n'
            'def analyze(path: str) -> str:\n'
            '    data = Path(path).read_bytes()\n'
            '    resp = model.generate_content(["Describe.", {"mime_type": "image/png", "data": data}])\n'
            '    return resp.text\n'
        ),
        "requirements.txt": "google-generativeai>=0.8.0\n",
    },
    expected_signatures=["google-generativeai"],
))

_add(RealWorldCase(
    id="rw-repo-035", category="llm-sdk", family="litellm-proxy",
    label="llm", difficulty="medium",
    description="LiteLLM as unified proxy to multiple providers",
    source={"repo": "BerriAI/litellm", "license": "MIT"},
    files={
        "client.py": (
            'import litellm\n\nlitellm.api_base = "http://localhost:4000"\n\n'
            'def complete(prompt: str, model: str = "gpt-4o") -> str:\n'
            '    resp = litellm.completion(model=model,\n'
            '        messages=[{"role": "user", "content": prompt}])\n'
            '    return resp.choices[0].message.content\n'
        ),
        "requirements.txt": "litellm>=1.50.0\n",
    },
    expected_signatures=["litellm"],
))

_add(RealWorldCase(
    id="rw-repo-036", category="llm-sdk", family="cohere-chat",
    label="llm", difficulty="easy",
    description="Cohere chat completion",
    source={"repo": "cohere-ai/cohere-python", "license": "MIT"},
    files={
        "chat.py": (
            'import cohere\n\nco = cohere.ClientV2(api_key="placeholder")\n'
            'resp = co.chat(model="command-a-08-2025",\n'
            '    messages=[{"role": "user", "content": "Explain quantum computing"}])\n'
            'print(resp.message.content[0].text)\n'
        ),
        "requirements.txt": "cohere>=5.0\n",
    },
    expected_signatures=["cohere"],
))

_add(RealWorldCase(
    id="rw-repo-037", category="llm-sdk", family="mistral-client",
    label="llm", difficulty="easy",
    description="Mistral AI chat client",
    source={"repo": "mistralai/client-python", "license": "Apache-2.0"},
    files={
        "chat.py": (
            'from mistralai import Mistral\n\nclient = Mistral(api_key="placeholder")\n'
            'resp = client.chat.complete(model="mistral-large-latest",\n'
            '    messages=[{"role": "user", "content": "Write a haiku"}])\n'
            'print(resp.choices[0].message.content)\n'
        ),
        "requirements.txt": "mistralai>=1.3.0\n",
    },
    expected_signatures=["mistral"],
))

_add(RealWorldCase(
    id="rw-repo-038", category="llm-sdk", family="groq-inference",
    label="llm", difficulty="easy",
    description="Groq ultra-fast LLM inference",
    source={"repo": "groq/groq-python", "license": "Apache-2.0"},
    files={
        "fast.py": (
            'from groq import Groq\n\nclient = Groq()\n'
            'resp = client.chat.completions.create(model="llama-3.3-70b-versatile",\n'
            '    messages=[{"role": "user", "content": "Explain transformers"}])\n'
            'print(resp.choices[0].message.content)\n'
        ),
        "requirements.txt": "groq>=0.13.0\n",
    },
    expected_signatures=["groq"],
))

_add(RealWorldCase(
    id="rw-repo-039", category="llm-sdk", family="azure-openai-sdk",
    label="llm", difficulty="medium",
    description="Azure OpenAI Service via Python SDK",
    source={"repo": "Azure-Samples/openai", "license": "MIT"},
    files={
        "azure_chat.py": (
            'from openai import AzureOpenAI\n\n'
            'client = AzureOpenAI(azure_endpoint="https://my-resource.openai.azure.com/",\n'
            '    api_key="placeholder", api_version="2025-04-01-preview")\n'
            'resp = client.chat.completions.create(model="gpt-4o",\n'
            '    messages=[{"role": "user", "content": "Hello"}])\n'
        ),
        "requirements.txt": "openai>=1.50.0\n",
    },
    expected_signatures=["openai"],
))

_add(RealWorldCase(
    id="rw-repo-040", category="llm-sdk", family="huggingface-inference",
    label="llm", difficulty="medium",
    description="HuggingFace Inference API for text generation",
    source={"repo": "huggingface/huggingface_hub", "license": "Apache-2.0"},
    files={
        "inference.py": (
            'from huggingface_hub import InferenceClient\n\n'
            'client = InferenceClient(model="meta-llama/Llama-3.1-8B-Instruct")\n'
            'resp = client.chat_completion(\n'
            '    messages=[{"role": "user", "content": "What is ML?"}], max_tokens=500)\n'
            'print(resp.choices[0].message.content)\n'
        ),
        "requirements.txt": "huggingface-hub>=0.27.0\n",
    },
    expected_signatures=["huggingface"],
))

_add(RealWorldCase(
    id="rw-repo-041", category="llm-sdk", family="replicate-prediction",
    label="llm", difficulty="medium",
    description="Replicate API for running open models",
    source={"repo": "replicate/replicate-python", "license": "Apache-2.0"},
    files={
        "generate.py": (
            'import replicate\n\noutput = replicate.run("meta/meta-llama-3-70b-instruct",\n'
            '    input={"prompt": "Write a poem about AI"})\nprint("".join(output))\n'
        ),
        "requirements.txt": "replicate>=1.0.0\n",
    },
    expected_signatures=["replicate"],
))

_add(RealWorldCase(
    id="rw-repo-042", category="llm-sdk", family="bedrock-invoke-model",
    label="llm", difficulty="medium",
    description="AWS Bedrock InvokeModel (no agent)",
    source={"repo": "aws-samples/amazon-bedrock-samples", "license": "MIT"},
    files={
        "invoke.py": (
            'import boto3, json\n\nbedrock = boto3.client("bedrock-runtime", region_name="us-east-1")\n'
            'resp = bedrock.invoke_model(modelId="anthropic.claude-3-sonnet-20240229-v1:0",\n'
            '    body=json.dumps({"anthropic_version": "bedrock-2023-05-31", "max_tokens": 256,\n'
            '        "messages": [{"role": "user", "content": "Summarize."}]}))\n'
            'print(json.loads(resp["body"].read())["content"][0]["text"])\n'
        ),
        "requirements.txt": "boto3>=1.35.0\n",
    },
    expected_signatures=["bedrock"],
))

# ===================================================================
# Category 3: MCP / Protocol (6 cases)
# ===================================================================

_add(RealWorldCase(
    id="rw-repo-043", category="mcp-protocol", family="mcp-server-python",
    label="agent", difficulty="medium",
    description="MCP server exposing filesystem tools",
    source={"repo": "modelcontextprotocol/servers", "license": "MIT"},
    files={
        "server.py": (
            'from mcp.server import Server\nfrom mcp.server.stdio import stdio_server\n'
            'from mcp.types import Tool, TextContent\n\n'
            'server = Server("fs-tools")\n\n'
            '@server.list_tools()\nasync def list_tools() -> list[Tool]:\n'
            '    return [Tool(name="read_file", description="Read a file",\n'
            '        inputSchema={"type": "object", "properties": {"path": {"type": "string"}}})]\n\n'
            '@server.call_tool()\nasync def call_tool(name: str, arguments: dict) -> list[TextContent]:\n'
            '    if name == "read_file":\n'
            '        return [TextContent(type="text", text=open(arguments["path"]).read())]\n'
            '    return [TextContent(type="text", text="Unknown")]\n'
        ),
        "pyproject.toml": '[project]\nname = "fs-mcp"\ndependencies = ["mcp>=1.1.0"]\n',
    },
    expected_signatures=["mcp"],
    expected_capabilities=["tool-use"],
))

_add(RealWorldCase(
    id="rw-repo-044", category="mcp-protocol", family="claude-desktop-mcp-config",
    label="agent", difficulty="easy",
    description="Claude Desktop MCP config with multiple servers",
    source={"repo": "modelcontextprotocol/servers", "license": "MIT"},
    files={
        ".claude/settings.json": (
            '{"mcpServers":{"filesystem":{"command":"npx",'
            '"args":["-y","@modelcontextprotocol/server-filesystem","/Users/dev/projects"]},'
            '"github":{"command":"npx","args":["-y","@modelcontextprotocol/server-github"]}}}\n'
        ),
    },
    expected_signatures=["mcp"],
    expected_capabilities=["tool-use"],
))

_add(RealWorldCase(
    id="rw-repo-045", category="mcp-protocol", family="mcp-server-typescript",
    label="agent", difficulty="medium",
    description="MCP TypeScript server with database tools",
    source={"repo": "modelcontextprotocol/typescript-sdk", "license": "MIT"},
    files={
        "src/index.ts": (
            'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
            'import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";\n\n'
            'const server = new McpServer({ name: "db-tools", version: "1.0.0" });\n'
            'server.tool("query", { sql: { type: "string" } },\n'
            '  async ({ sql }) => ({ content: [{ type: "text", text: `Query: ${sql}` }] }));\n'
            'await server.connect(new StdioServerTransport());\n'
        ),
        "package.json": '{"name":"db-mcp","dependencies":{"@modelcontextprotocol/sdk":"^1.7.0"}}\n',
    },
    expected_signatures=["mcp"],
    expected_capabilities=["tool-use"],
))

_add(RealWorldCase(
    id="rw-repo-046", category="mcp-protocol", family="mcp-client-python",
    label="agent", difficulty="hard",
    description="MCP client connecting via SSE",
    source={"repo": "modelcontextprotocol/python-sdk", "license": "MIT"},
    files={
        "client.py": (
            'from mcp import ClientSession\nfrom mcp.client.sse import sse_client\n\n'
            'async def main():\n'
            '    async with sse_client("http://localhost:8080/sse") as (read, write):\n'
            '        async with ClientSession(read, write) as session:\n'
            '            await session.initialize()\n'
            '            tools = await session.list_tools()\n'
            '            await session.call_tool("query", {"sql": "SELECT 1"})\n'
        ),
        "requirements.txt": "mcp>=1.1.0\n",
    },
    expected_signatures=["mcp"],
    expected_capabilities=["tool-use"],
))

_add(RealWorldCase(
    id="rw-repo-047", category="mcp-protocol", family="windsurf-mcp-config",
    label="agent", difficulty="easy",
    description="Windsurf IDE MCP server configuration",
    source={"repo": "synthetic", "license": "N/A"},
    files={
        ".windsurf/mcp.json": (
            '{"mcpServers":{"memory":{"command":"npx",'
            '"args":["-y","@modelcontextprotocol/server-memory"]},'
            '"brave-search":{"command":"npx",'
            '"args":["-y","@modelcontextprotocol/server-brave-search"]}}}\n'
        ),
    },
    expected_signatures=["mcp"],
    expected_capabilities=["tool-use"],
))

_add(RealWorldCase(
    id="rw-repo-048", category="mcp-protocol", family="zed-mcp-config",
    label="agent", difficulty="easy",
    description="Zed editor MCP context server configuration",
    source={"repo": "zed-industries/zed", "license": "GPL-3.0"},
    files={
        ".zed/settings.json": (
            '{"context_servers":{"postgres-mcp":{"command":{"path":"npx",'
            '"args":["-y","@modelcontextprotocol/server-postgres","postgresql://localhost/mydb"]}}}}\n'
        ),
    },
    expected_signatures=["mcp"],
    expected_capabilities=["tool-use"],
))

# ===================================================================
# Category 4: Coding Agents (10 cases)
# ===================================================================

_add(RealWorldCase(
    id="rw-repo-049", category="coding-agent", family="cursor-rules",
    label="agent", difficulty="easy",
    description="Cursor IDE with MCP servers and rules",
    source={"repo": "PatrickJS/awesome-cursorrules", "license": "CC0-1.0"},
    files={
        ".cursor/mcp.json": (
            '{"mcpServers":{"context7":{"command":"npx","args":["-y","@upstash/context7-mcp@latest"]}}}\n'
        ),
        ".cursorrules": "You are an expert TypeScript developer.\nUse functional components.\n",
    },
    expected_signatures=["cursor"],
    expected_capabilities=["tool-use"],
))

_add(RealWorldCase(
    id="rw-repo-050", category="coding-agent", family="aider-config",
    label="agent", difficulty="medium",
    description="Aider AI coding assistant configuration",
    source={"repo": "Aider-AI/aider", "license": "Apache-2.0"},
    files={
        ".aider.conf.yml": "model: claude-sonnet-4-5\nedit-format: diff\nauto-commits: true\nauto-lint: true\n",
        ".aiderignore": "*.pyc\n__pycache__/\n.env\n",
    },
    expected_signatures=["aider"],
))

_add(RealWorldCase(
    id="rw-repo-051", category="coding-agent", family="cline-config",
    label="agent", difficulty="medium",
    description="Cline VS Code extension with MCP servers",
    source={"repo": "cline/cline", "license": "Apache-2.0"},
    files={
        ".vscode/settings.json": (
            '{"cline.mcpServers":{"memory":{"command":"npx",'
            '"args":["-y","@modelcontextprotocol/server-memory"]}}}\n'
        ),
        ".clinerules": "Always write tests.\nUse TypeScript strict mode.\n",
    },
    expected_signatures=["cline"],
    expected_capabilities=["tool-use"],
))

_add(RealWorldCase(
    id="rw-repo-052", category="coding-agent", family="continue-dev-config",
    label="agent", difficulty="medium",
    description="Continue.dev AI coding assistant configuration",
    source={"repo": "continuedev/continue", "license": "Apache-2.0"},
    files={
        ".continue/config.json": (
            '{"models":[{"title":"Claude","provider":"anthropic",'
            '"model":"claude-sonnet-4-5"}],'
            '"tabAutocompleteModel":{"title":"Codestral","provider":"mistral",'
            '"model":"codestral-latest"},"contextProviders":[{"name":"codebase"}]}\n'
        ),
    },
    expected_signatures=["continue"],
    expected_capabilities=["tool-use"],
))

_add(RealWorldCase(
    id="rw-repo-053", category="coding-agent", family="windsurf-rules",
    label="agent", difficulty="easy",
    description="Windsurf IDE global rules",
    source={"repo": "synthetic", "license": "N/A"},
    files={
        ".windsurfrules": "You are a senior Python developer.\nUse type hints.\nWrite pytest tests.\n",
    },
    expected_signatures=["windsurf"],
))

_add(RealWorldCase(
    id="rw-repo-054", category="coding-agent", family="github-copilot-workspace",
    label="agent", difficulty="medium",
    description="GitHub Copilot agent configuration",
    source={"repo": "synthetic", "license": "N/A"},
    files={
        ".github/copilot-instructions.md": "# Copilot\nYou are a TypeScript expert.\nUse App Router.\n",
        ".vscode/settings.json": '{"github.copilot.enable":{"*":true}}\n',
    },
    expected_signatures=["github-copilot"],
    expected_capabilities=["code-gen"],
))

_add(RealWorldCase(
    id="rw-repo-055", category="coding-agent", family="claude-code-project",
    label="agent", difficulty="easy",
    description="Claude Code project with CLAUDE.md",
    source={"repo": "synthetic", "license": "N/A"},
    files={
        "CLAUDE.md": "# Project\nFastAPI project.\n## Commands\n- `make test` - pytest\n- `make lint` - ruff\n",
        ".claude/settings.json": '{"permissions":{"allow":["Bash(make test)","Bash(make lint)"]}}\n',
    },
    expected_signatures=["claude-code"],
    expected_capabilities=["code-gen"],
))

_add(RealWorldCase(
    id="rw-repo-056", category="coding-agent", family="sourcegraph-cody-config",
    label="agent", difficulty="medium",
    description="Sourcegraph Cody AI assistant context config",
    source={"repo": "sourcegraph/cody", "license": "Apache-2.0"},
    files={
        ".vscode/cody.json": '{"contextProviders":[{"name":"codebase"}],"models":{"chat":"claude-sonnet-4-5"}}\n',
    },
    expected_signatures=["cody"],
))

_add(RealWorldCase(
    id="rw-repo-057", category="coding-agent", family="devin-config",
    label="agent", difficulty="easy",
    description="Devin AI software engineer instructions",
    source={"repo": "synthetic", "license": "N/A"},
    files={
        "devin.md": "## Devin Instructions\nDjango REST API project.\nRun tests before committing.\n",
    },
    expected_signatures=["devin"],
))

_add(RealWorldCase(
    id="rw-repo-058", category="coding-agent", family="openclaw-state",
    label="agent", difficulty="medium",
    description="OpenClaw agent state directory",
    source={"repo": "openclaw/openclaw", "license": "Apache-2.0"},
    files={
        ".openclaw/config.toml": (
            '[model]\nprovider = "anthropic"\nmodel = "claude-sonnet-4-5"\n\n'
            '[agent]\nauto_approve = false\nmax_steps = 25\n\n[mcp]\nservers = ["filesystem"]\n'
        ),
        ".openclaw/history/session-2026-10-01.jsonl": '{"role":"user","content":"Fix test"}\n',
    },
    expected_signatures=["openclaw"],
    expected_capabilities=["autonomous", "tool-use"],
))

# ===================================================================
# Category 5: Cloud AI Services (8 cases)
# ===================================================================

_add(RealWorldCase(
    id="rw-repo-059", category="cloud-ai", family="bedrock-agent-terraform",
    label="agent", difficulty="hard",
    description="AWS Bedrock Agent provisioned with Terraform",
    source={"repo": "hashicorp/terraform-provider-aws", "license": "MPL-2.0"},
    files={
        "main.tf": (
            'resource "aws_bedrockagent_agent" "bot" {\n'
            '  agent_name       = "support-bot"\n'
            '  foundation_model = "anthropic.claude-v2"\n'
            '  instruction      = "You are a support agent."\n'
            '  agent_resource_role_arn = aws_iam_role.bedrock.arn\n}\n\n'
            'resource "aws_bedrockagent_agent_action_group" "orders" {\n'
            '  agent_id          = aws_bedrockagent_agent.bot.id\n'
            '  action_group_name = "orders"\n'
            '  action_group_executor { lambda = aws_lambda_function.orders.arn }\n'
            '  api_schema { payload = file("${path.module}/api.yaml") }\n}\n'
        ),
    },
    expected_signatures=["bedrock-agents"],
    expected_capabilities=["autonomous", "tool-use"],
))

_add(RealWorldCase(
    id="rw-repo-060", category="cloud-ai", family="vertex-ai-pipeline",
    label="llm", difficulty="medium",
    description="GCP Vertex AI batch prediction pipeline",
    source={"repo": "GoogleCloudPlatform/vertex-ai-samples", "license": "Apache-2.0"},
    files={
        "pipeline.py": (
            'from google.cloud import aiplatform\n\n'
            'aiplatform.init(project="my-project", location="us-central1")\n'
            'model = aiplatform.Model("publishers/google/models/gemini-2.5-flash")\n'
            'job = model.batch_predict(job_display_name="classify",\n'
            '    gcs_source="gs://bucket/in.jsonl", gcs_destination_prefix="gs://bucket/out/")\n'
        ),
        "requirements.txt": "google-cloud-aiplatform>=1.70.0\n",
    },
    expected_signatures=["vertex-ai"],
))

_add(RealWorldCase(
    id="rw-repo-061", category="cloud-ai", family="azure-openai-terraform",
    label="llm", difficulty="hard",
    description="Azure OpenAI Service deployed with Terraform",
    source={"repo": "hashicorp/terraform-provider-azurerm", "license": "MPL-2.0"},
    files={
        "main.tf": (
            'resource "azurerm_cognitive_account" "openai" {\n'
            '  name = "company-openai"\n  location = "eastus"\n  kind = "OpenAI"\n  sku_name = "S0"\n'
            '  resource_group_name = azurerm_resource_group.rg.name\n}\n\n'
            'resource "azurerm_cognitive_deployment" "gpt4o" {\n'
            '  name = "gpt-4o"\n  cognitive_account_id = azurerm_cognitive_account.openai.id\n'
            '  model { format = "OpenAI" name = "gpt-4o" version = "2024-11-20" }\n'
            '  sku { name = "Standard" capacity = 30 }\n}\n'
        ),
    },
    expected_signatures=["azure-openai"],
))

_add(RealWorldCase(
    id="rw-repo-062", category="cloud-ai", family="sagemaker-llm-endpoint",
    label="llm", difficulty="hard",
    description="AWS SageMaker endpoint for LLM serving",
    source={"repo": "aws/amazon-sagemaker-examples", "license": "Apache-2.0"},
    files={
        "deploy.py": (
            'import sagemaker\nfrom sagemaker.huggingface import HuggingFaceModel\n\n'
            'role = sagemaker.get_execution_role()\n'
            'hub = {"HF_MODEL_ID": "meta-llama/Llama-3.1-8B-Instruct", "HF_TASK": "text-generation"}\n'
            'model = HuggingFaceModel(role=role, env=hub,\n'
            '    transformers_version="4.45.0", pytorch_version="2.5.0", py_version="py311")\n'
            'model.deploy(initial_instance_count=1, instance_type="ml.g5.2xlarge")\n'
        ),
        "requirements.txt": "sagemaker>=2.230.0\n",
    },
    expected_signatures=["sagemaker"],
))

_add(RealWorldCase(
    id="rw-repo-063", category="cloud-ai", family="bedrock-knowledge-base",
    label="agent", difficulty="hard",
    description="AWS Bedrock Knowledge Base with RAG (Terraform)",
    source={"repo": "aws-samples/amazon-bedrock-samples", "license": "MIT"},
    files={
        "main.tf": (
            'resource "aws_bedrockagent_knowledge_base" "docs" {\n'
            '  name = "company-kb"\n  role_arn = aws_iam_role.kb.arn\n'
            '  knowledge_base_configuration {\n    type = "VECTOR"\n'
            '    vector_knowledge_base_configuration {\n'
            '      embedding_model_arn = "arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-embed-text-v2:0"\n'
            '    }\n  }\n  storage_configuration {\n    type = "OPENSEARCH_SERVERLESS"\n'
            '    opensearch_serverless_configuration {\n'
            '      collection_arn = aws_opensearchserverless_collection.docs.arn\n'
            '      vector_index_name = "kb-index"\n    }\n  }\n}\n'
        ),
    },
    expected_signatures=["bedrock"],
    expected_capabilities=["rag"],
))

_add(RealWorldCase(
    id="rw-repo-064", category="cloud-ai", family="lambda-ai-function",
    label="llm", difficulty="medium",
    description="AWS Lambda using OpenAI SDK",
    source={"repo": "synthetic", "license": "N/A"},
    files={
        "handler.py": (
            'import json, os\nfrom openai import OpenAI\n\nclient = OpenAI(api_key=os.environ["OPENAI_API_KEY"])\n\n'
            'def lambda_handler(event, context):\n'
            '    resp = client.chat.completions.create(model="gpt-4o-mini",\n'
            '        messages=[{"role": "user", "content": event.get("prompt", "")}], max_tokens=256)\n'
            '    return {"statusCode": 200, "body": json.dumps({"answer": resp.choices[0].message.content})}\n'
        ),
        "requirements.txt": "openai>=1.50.0\n",
        "serverless.yml": "service: ai-summarizer\nprovider:\n  name: aws\n  runtime: python3.12\nfunctions:\n  summarize:\n    handler: handler.lambda_handler\n",
    },
    expected_signatures=["openai"],
))

_add(RealWorldCase(
    id="rw-repo-065", category="cloud-ai", family="azure-ai-search-rag",
    label="agent", difficulty="hard",
    description="Azure AI Search + OpenAI for RAG",
    source={"repo": "Azure-Samples/azure-search-openai-demo", "license": "MIT"},
    files={
        "app/backend/rag.py": (
            'from openai import AzureOpenAI\nfrom azure.search.documents import SearchClient\n\n'
            'class ChatRAG:\n    def __init__(self, search: SearchClient, openai: AzureOpenAI):\n'
            '        self.search = search\n        self.openai = openai\n\n'
            '    async def run(self, query: str) -> str:\n'
            '        results = self.search.search(query, top=3)\n'
            '        ctx = "\\n".join(r["content"] for r in results)\n'
            '        resp = self.openai.chat.completions.create(model="gpt-4o",\n'
            '            messages=[{"role": "system", "content": f"Context:\\n{ctx}"},\n'
            '                      {"role": "user", "content": query}])\n'
            '        return resp.choices[0].message.content\n'
        ),
        "requirements.txt": "openai>=1.50.0\nazure-search-documents>=11.6.0\n",
    },
    expected_signatures=["openai", "azure-ai-search"],
    expected_capabilities=["rag"],
))

_add(RealWorldCase(
    id="rw-repo-066", category="cloud-ai", family="vertex-agent-builder",
    label="agent", difficulty="hard",
    description="Google Vertex AI Agent Builder",
    source={"repo": "GoogleCloudPlatform/generative-ai", "license": "Apache-2.0"},
    files={
        "agent.py": (
            'from vertexai.preview.reasoning_engines import AdkApp\n'
            'from google.adk.agents import Agent\nfrom google.adk.tools import google_search\n\n'
            'agent = Agent(model="gemini-2.5-flash", name="search_agent",\n'
            '    instruction="Answer using search.", tools=[google_search])\n'
            'app = AdkApp(agent=agent, enable_tracing=True)\n'
        ),
        "requirements.txt": "google-cloud-aiplatform>=1.70.0\ngoogle-adk>=1.1.0\n",
    },
    expected_signatures=["google-adk", "vertex-ai"],
    expected_capabilities=["tool-use"],
))

# ===================================================================
# Category 6: Low-code / Workflow AI (5 cases)
# ===================================================================

_add(RealWorldCase(
    id="rw-repo-067", category="lowcode-ai", family="n8n-ai-workflow",
    label="agent", difficulty="hard",
    description="n8n workflow with AI Agent node",
    source={"repo": "n8n-io/n8n", "license": "SEE LICENSE"},
    files={
        "workflow.json": (
            '{"name":"Support AI","nodes":['
            '{"type":"@n8n/n8n-nodes-langchain.agent","name":"AI Agent",'
            '"parameters":{"agent":"openAiFunctionsAgent"}},'
            '{"type":"@n8n/n8n-nodes-langchain.lmChatOpenAi","name":"OpenAI",'
            '"parameters":{"model":"gpt-4o"}}]}\n'
        ),
    },
    expected_signatures=["n8n"],
    expected_capabilities=["tool-use", "autonomous"],
))

_add(RealWorldCase(
    id="rw-repo-068", category="lowcode-ai", family="dify-workflow",
    label="agent", difficulty="hard",
    description="Dify AI workflow with knowledge base",
    source={"repo": "langgenius/dify", "license": "Apache-2.0"},
    files={
        "dify-workflow.yaml": (
            'app:\n  mode: agent-chat\n  name: "Support Agent"\nmodel:\n  provider: openai\n  name: gpt-4o\n'
            'agent:\n  strategy: function_call\n  max_iteration: 10\n'
            'tools:\n  - type: api\n    name: ticket_lookup\ndataset:\n  retrieval_model: semantic_search\n'
        ),
    },
    expected_signatures=["dify"],
    expected_capabilities=["tool-use", "rag"],
))

_add(RealWorldCase(
    id="rw-repo-069", category="lowcode-ai", family="flowise-chatflow",
    label="agent", difficulty="hard",
    description="Flowise visual chatflow with tool agent",
    source={"repo": "FlowiseAI/Flowise", "license": "Apache-2.0"},
    files={
        "chatflow.json": (
            '{"nodes":[{"id":"chat_0","data":{"label":"ChatOpenAI","inputs":{"modelName":"gpt-4o"}}},'
            '{"id":"agent_0","data":{"label":"Tool Agent","inputs":{"maxIterations":10}}}],'
            '"edges":[{"source":"chat_0","target":"agent_0"}]}\n'
        ),
    },
    expected_signatures=["flowise"],
    expected_capabilities=["tool-use"],
))

_add(RealWorldCase(
    id="rw-repo-070", category="lowcode-ai", family="langflow-pipeline",
    label="agent", difficulty="hard",
    description="Langflow visual pipeline with RAG",
    source={"repo": "langflow-ai/langflow", "license": "MIT"},
    files={
        "flow.json": (
            '{"nodes":[{"data":{"type":"OpenAIModel","node":{"template":{"model_name":{"value":"gpt-4o"}}}}},'
            '{"data":{"type":"RetrievalQA","node":{"template":{"chain_type":{"value":"stuff"}}}}}]}\n'
        ),
    },
    expected_signatures=["langflow"],
    expected_capabilities=["rag"],
))

_add(RealWorldCase(
    id="rw-repo-071", category="lowcode-ai", family="rivet-graph",
    label="agent", difficulty="hard",
    description="Rivet visual AI pipeline with looping agent",
    source={"repo": "Ironclad/rivet", "license": "MPL-2.0"},
    files={
        "agent.rivet-project": (
            '{"metadata":{"title":"Agent"},"graphs":{"main":{"nodes":['
            '{"type":"chat","data":{"model":"gpt-4o","useToolCalling":true}},'
            '{"type":"loopController","data":{"maxIterations":10}}]}}}\n'
        ),
    },
    expected_signatures=["rivet"],
    expected_capabilities=["tool-use"],
))

# ===================================================================
# Category 7: Adversarial / Edge Cases (15 cases)
#
# These target known ShadowScan blind spots. A benchmark that hides
# tool weaknesses is not useful for independent validation.
# ===================================================================

_add(RealWorldCase(
    id="rw-repo-072", category="adversarial", family="raw-openai-tool-loop",
    label="agent", difficulty="hard",
    description="Hand-rolled OpenAI tool loop without any framework",
    source={"repo": "synthetic", "license": "N/A",
            "note": "Common in production; no framework dep"},
    files={
        "agent.py": (
            'import json\nfrom openai import OpenAI\n\nclient = OpenAI()\n'
            'TOOLS = [{"type": "function", "function": {"name": "query_db",\n'
            '    "description": "SQL query", "parameters": {"type": "object",\n'
            '    "properties": {"sql": {"type": "string"}}, "required": ["sql"]}}}]\n\n'
            'def run(prompt: str, max_turns: int = 10) -> str:\n'
            '    msgs = [{"role": "user", "content": prompt}]\n'
            '    for _ in range(max_turns):\n'
            '        resp = client.chat.completions.create(model="gpt-4o", messages=msgs, tools=TOOLS)\n'
            '        msg = resp.choices[0].message\n        msgs.append(msg)\n'
            '        if not msg.tool_calls: return msg.content\n'
            '        for tc in msg.tool_calls:\n'
            '            result = handle_call(tc.function.name, json.loads(tc.function.arguments))\n'
            '            msgs.append({"role": "tool", "tool_call_id": tc.id, "content": result})\n'
        ),
        "requirements.txt": "openai>=1.50.0\n",
    },
    expected_signatures=["openai"],
    expected_capabilities=["tool-use"],
))

# BLIND SPOT: Go has dep signals but sparse import/code patterns.
_add(RealWorldCase(
    id="rw-repo-073", category="adversarial", family="go-import-only-agent",
    label="agent", difficulty="hard",
    description="Go agent via import only — go.mod omits AI dep",
    source={"repo": "synthetic", "license": "N/A",
            "note": "BLIND SPOT: Go sparse import/code patterns"},
    files={
        "main.go": (
            'package main\n\nimport (\n\t"context"\n\t"fmt"\n\n'
            '\t"github.com/sashabaranov/go-openai"\n)\n\n'
            'func main() {\n\tclient := openai.NewClient("sk-xxx")\n'
            '\treq := openai.ChatCompletionRequest{Model: openai.GPT4o,\n'
            '\t\tMessages: []openai.ChatCompletionMessage{{Role: openai.ChatMessageRoleUser, Content: "Hello"}}}\n'
            '\tresp, _ := client.CreateChatCompletion(context.Background(), req)\n'
            '\tfmt.Println(resp.Choices[0].Message.Content)\n}\n'
        ),
        "go.mod": "module example.com/chatbot\n\ngo 1.22\n",
    },
    expected_signatures=["go-openai"],
))

# BLIND SPOT: Rust has dependency signals but sparse import/code patterns
_add(RealWorldCase(
    id="rw-repo-074", category="adversarial", family="rust-llm-cargo-only",
    label="llm", difficulty="hard",
    description="Rust LLM client — Cargo.toml only, sparse code patterns",
    source={"repo": "synthetic", "license": "N/A",
            "note": "BLIND SPOT: Rust sparse code patterns"},
    files={
        "Cargo.toml": '[package]\nname = "ai-bot"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\nasync-openai = "0.25"\ntokio = { version = "1", features = ["full"] }\n',
        "src/main.rs": (
            'use async_openai::{Client, types::CreateChatCompletionRequestArgs};\n\n'
            '#[tokio::main]\nasync fn main() {\n    let client = Client::new();\n'
            '    let req = CreateChatCompletionRequestArgs::default()\n'
            '        .model("gpt-4o").messages(vec![]).build().unwrap();\n'
            '    let resp = client.chat().create(req).await.unwrap();\n'
            '    println!("{}", resp.choices[0].message.content.as_ref().unwrap());\n}\n'
        ),
    },
    expected_signatures=["async-openai"],
))

# BLIND SPOT: No SDK dep = no heuristic gate triggers
_add(RealWorldCase(
    id="rw-repo-075", category="adversarial", family="custom-http-llm-client",
    label="llm", difficulty="hard",
    description="Custom HTTP client calling OpenAI API without SDK",
    source={"repo": "synthetic", "license": "N/A",
            "note": "BLIND SPOT: No SDK dep means zero heuristic findings"},
    files={
        "llm.py": (
            'import httpx, os\n\ndef chat(prompt: str) -> str:\n'
            '    resp = httpx.post("https://api.openai.com/v1/chat/completions",\n'
            '        headers={"Authorization": f"Bearer {os.environ[\'OPENAI_API_KEY\']}"},\n'
            '        json={"model": "gpt-4o", "messages": [{"role": "user", "content": prompt}]})\n'
            '    return resp.json()["choices"][0]["message"]["content"]\n'
        ),
        "requirements.txt": "httpx>=0.27.0\n",
    },
    expected_signatures=[],
))

_add(RealWorldCase(
    id="rw-repo-076", category="adversarial", family="dynamic-import-agent",
    label="agent", difficulty="hard",
    description="Agent loaded via importlib — no static imports",
    source={"repo": "synthetic", "license": "N/A"},
    files={
        "loader.py": (
            'import importlib, os\n\nMOD = os.environ.get("AGENT_BACKEND", "langchain.agents")\n\n'
            'def create_agent():\n    mod = importlib.import_module(MOD)\n'
            '    return getattr(mod, "create_react_agent")(llm=get_llm(), tools=get_tools())\n'
        ),
        "pyproject.toml": '[project]\nname = "dynamic"\ndependencies = ["langchain>=0.3.0", "langchain-openai>=0.3.0"]\n',
    },
    expected_signatures=["langchain"],
    expected_capabilities=["tool-use"],
))

_add(RealWorldCase(
    id="rw-repo-077", category="adversarial", family="minified-js-ai-sdk",
    label="llm", difficulty="hard",
    description="Minified JS bundle containing AI SDK usage",
    source={"repo": "synthetic", "license": "N/A"},
    files={
        "dist/bundle.min.js": (
            'const o=require("openai");const c=new o.OpenAI();'
            'async function r(p){const m=await c.chat.completions.create('
            '{model:"gpt-4o",messages:[{role:"user",content:p}]});'
            'return m.choices[0].message.content}module.exports={run:r};\n'
        ),
        "package.json": '{"name":"ai-svc","dependencies":{"openai":"^4.73.0"}}\n',
    },
    expected_signatures=["openai"],
))

_add(RealWorldCase(
    id="rw-repo-078", category="adversarial", family="polyglot-ai-project",
    label="agent", difficulty="hard",
    description="Polyglot project with AI code in Python + JS + Go",
    source={"repo": "synthetic", "license": "N/A"},
    files={
        "python/agent.py": 'from langchain_openai import ChatOpenAI\nfrom langchain.agents import create_tool_calling_agent\nllm = ChatOpenAI(model="gpt-4o")\n',
        "node/chat.ts": 'import Anthropic from "@anthropic-ai/sdk";\nconst client = new Anthropic();\n',
        "go/main.go": 'package main\nimport "github.com/tmc/langchaingo/llms/openai"\nfunc main() { _, _ = openai.New() }\n',
        "python/requirements.txt": "langchain>=0.3.0\nlangchain-openai>=0.3.0\n",
        "node/package.json": '{"dependencies":{"@anthropic-ai/sdk":"^0.37.0"}}\n',
        "go/go.mod": "module example.com/poly\ngo 1.22\nrequire github.com/tmc/langchaingo v0.1.13\n",
    },
    expected_signatures=["langchain", "anthropic", "langchaingo"],
    expected_capabilities=["tool-use"],
))

_add(RealWorldCase(
    id="rw-repo-079", category="adversarial", family="test-only-ai-code",
    label="llm", difficulty="hard",
    description="AI SDK only in test files, not production code",
    source={"repo": "synthetic", "license": "N/A"},
    files={
        "src/app.py": 'from flask import Flask, jsonify\napp = Flask(__name__)\n\n@app.route("/health")\ndef health(): return jsonify(status="ok")\n',
        "tests/test_llm.py": (
            'from openai import OpenAI\nclient = OpenAI()\n\n'
            'def test_summarize():\n'
            '    resp = client.chat.completions.create(model="gpt-4o-mini",\n'
            '        messages=[{"role": "user", "content": "Say hello"}])\n'
            '    assert resp.choices[0].message.content\n'
        ),
        "requirements.txt": "flask>=3.0\n",
        "requirements-dev.txt": "openai>=1.50.0\npytest>=8.0\n",
    },
    expected_signatures=["openai"],
))

_add(RealWorldCase(
    id="rw-repo-080", category="adversarial", family="monorepo-hidden-ai",
    label="agent", difficulty="hard",
    description="Large monorepo with AI buried in one subfolder",
    source={"repo": "synthetic", "license": "N/A"},
    files={
        "apps/web/src/index.ts": 'console.log("Main app");\n',
        "apps/web/package.json": '{"name":"web","dependencies":{"react":"^18.3.1"}}\n',
        "packages/shared/utils.ts": 'export const fmt = (d: Date) => d.toISOString();\n',
        "services/ai/agent.py": (
            'from crewai import Agent, Task, Crew\nresearcher = Agent(role="R", goal="Find data",\n'
            '    backstory="Expert", verbose=True)\ntask = Task(description="Research", agent=researcher,\n'
            '    expected_output="Report")\ncrew = Crew(agents=[researcher], tasks=[task])\n'
        ),
        "services/ai/requirements.txt": "crewai>=0.100.0\n",
    },
    expected_signatures=["crewai"],
    expected_capabilities=["autonomous"],
))

_add(RealWorldCase(
    id="rw-repo-081", category="adversarial", family="docker-ai-deployment",
    label="llm", difficulty="hard",
    description="AI service deployed via Docker only — no local source",
    source={"repo": "synthetic", "license": "N/A"},
    files={
        "docker-compose.yml": (
            'services:\n  ollama:\n    image: ollama/ollama:latest\n    ports: ["11434:11434"]\n'
            '    deploy:\n      resources:\n        reservations:\n          devices: [{capabilities: [gpu]}]\n'
            '  open-webui:\n    image: ghcr.io/open-webui/open-webui:main\n'
            '    ports: ["3000:8080"]\n    environment:\n      OLLAMA_BASE_URL: http://ollama:11434\n'
        ),
    },
    expected_signatures=["ollama"],
))

# BLIND SPOT: C/C++ not in SOURCE_EXTENSIONS at all
_add(RealWorldCase(
    id="rw-repo-082", category="adversarial", family="cpp-llm-rest-client",
    label="llm", difficulty="hard",
    description="C++ calling OpenAI API via libcurl — not in SOURCE_EXTENSIONS",
    source={"repo": "synthetic", "license": "N/A",
            "note": "BLIND SPOT: C/C++ not in SOURCE_EXTENSIONS"},
    files={
        "src/main.cpp": (
            '#include <curl/curl.h>\n#include <string>\nint main() {\n'
            '    CURL *curl = curl_easy_init();\n'
            '    struct curl_slist *h = NULL;\n'
            '    h = curl_slist_append(h, "Authorization: Bearer sk-placeholder");\n'
            '    curl_easy_setopt(curl, CURLOPT_URL, "https://api.openai.com/v1/chat/completions");\n'
            '    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, h);\n'
            '    curl_easy_perform(curl);\n    curl_easy_cleanup(curl);\n}\n'
        ),
        "CMakeLists.txt": 'cmake_minimum_required(VERSION 3.20)\nproject(ai CXX)\nfind_package(CURL REQUIRED)\nadd_executable(ai src/main.cpp)\ntarget_link_libraries(ai CURL::libcurl)\n',
    },
    expected_signatures=[],
))

# BLIND SPOT: Kotlin/Scala share "java" tag, sparse idiomatic patterns
_add(RealWorldCase(
    id="rw-repo-083", category="adversarial", family="kotlin-openai-ktor",
    label="llm", difficulty="hard",
    description="Kotlin OpenAI client using idiomatic Kotlin (not Java patterns)",
    source={"repo": "synthetic", "license": "N/A",
            "note": "BLIND SPOT: Kotlin shares java tag"},
    files={
        "src/main/kotlin/Main.kt": (
            'import com.aallam.openai.api.chat.*\nimport com.aallam.openai.client.OpenAI\n\n'
            'suspend fun main() {\n    val openAI = OpenAI(System.getenv("OPENAI_API_KEY"))\n'
            '    val req = ChatCompletionRequest(model = ModelId("gpt-4o"),\n'
            '        messages = listOf(ChatMessage(role = ChatRole.User, content = "Hello")))\n'
            '    val resp = openAI.chatCompletion(req)\n'
            '    println(resp.choices[0].message.content)\n}\n'
        ),
        "build.gradle.kts": 'dependencies {\n    implementation("com.aallam.openai:openai-client:3.8.0")\n    implementation("io.ktor:ktor-client-okhttp:2.3.12")\n}\n',
    },
    expected_signatures=["openai-kotlin"],
))

_add(RealWorldCase(
    id="rw-repo-084", category="adversarial", family="ruby-langchain-agent",
    label="agent", difficulty="hard",
    description="Ruby LangChain agent with tools",
    source={"repo": "patterns-ai-core/langchainrb", "license": "MIT"},
    files={
        "agent.rb": (
            'require "langchain"\n\nllm = Langchain::LLM::OpenAI.new(api_key: ENV["OPENAI_API_KEY"],\n'
            '    default_options: { chat_model: "gpt-4o" })\n\n'
            'agent = Langchain::Agent::ReActAgent.new(llm: llm,\n'
            '    tools: [Langchain::Tool::Calculator.new, Langchain::Tool::Wikipedia.new])\n'
            'agent.run(question: "Population of Tokyo?")\n'
        ),
        "Gemfile": 'source "https://rubygems.org"\ngem "langchainrb", "~> 0.17"\n',
    },
    expected_signatures=["langchainrb"],
    expected_capabilities=["tool-use"],
))

_add(RealWorldCase(
    id="rw-repo-085", category="adversarial", family="php-openai-client",
    label="llm", difficulty="hard",
    description="PHP OpenAI client in Laravel",
    source={"repo": "openai-php/client", "license": "MIT"},
    files={
        "app/Services/AiService.php": (
            '<?php\nnamespace App\\Services;\nuse OpenAI;\n\nclass AiService {\n'
            '    private $client;\n    public function __construct() {\n'
            '        $this->client = OpenAI::client(env("OPENAI_API_KEY"));\n    }\n'
            '    public function summarize(string $text): string {\n'
            '        $r = $this->client->chat()->create(["model" => "gpt-4o",\n'
            '            "messages" => [["role" => "user", "content" => "Summarize: $text"]]]);\n'
            '        return $r->choices[0]->message->content;\n    }\n}\n'
        ),
        "composer.json": '{"require":{"openai-php/client":"^0.10"}}\n',
    },
    expected_signatures=["openai-php"],
))

_add(RealWorldCase(
    id="rw-repo-086", category="adversarial", family="github-actions-ai",
    label="agent", difficulty="hard",
    description="GitHub Actions workflow using AI for PR review",
    source={"repo": "synthetic", "license": "N/A"},
    files={
        ".github/workflows/ai-review.yml": (
            'name: AI Review\non: [pull_request]\njobs:\n  review:\n    runs-on: ubuntu-latest\n'
            '    steps:\n      - uses: actions/checkout@v4\n'
            '      - name: AI Review\n        uses: coderabbitai/ai-pr-reviewer@v1\n'
            '        with:\n          openai_model: gpt-4o\n'
            '        env:\n          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}\n'
        ),
    },
    expected_signatures=["coderabbit"],
    expected_capabilities=["code-review"],
))

# ===================================================================
# Category 8: Endpoint Surface (5 cases)
# ===================================================================

_add(RealWorldCase(
    id="rw-repo-087", category="endpoint", family="dev-home-claude-dir",
    label="agent", difficulty="easy",
    description="Claude Code config on developer workstation",
    source={"repo": "synthetic", "license": "N/A"},
    surface="endpoint",
    files={
        ".claude/settings.json": (
            '{"permissions":{"allow":["Bash(npm test)"]},'
            '"mcpServers":{"filesystem":{"command":"npx",'
            '"args":["-y","@modelcontextprotocol/server-filesystem","/home/dev"]}}}\n'
        ),
    },
    expected_signatures=["claude-code"],
    expected_capabilities=["tool-use"],
))

_add(RealWorldCase(
    id="rw-repo-088", category="endpoint", family="vscode-ai-extensions",
    label="agent", difficulty="medium",
    description="VS Code with multiple AI extensions",
    source={"repo": "synthetic", "license": "N/A"},
    surface="endpoint",
    files={
        ".vscode/extensions.json": '{"recommendations":["github.copilot","github.copilot-chat","saoudrizwan.claude-dev","codeium.codeium"]}\n',
        ".vscode/settings.json": '{"github.copilot.enable":{"*":true}}\n',
    },
    expected_signatures=["github-copilot", "cline", "codeium"],
    expected_capabilities=["code-gen"],
))

_add(RealWorldCase(
    id="rw-repo-089", category="endpoint", family="shell-history-ai-cli",
    label="agent", difficulty="medium",
    description="Shell history showing AI coding tool usage",
    source={"repo": "synthetic", "license": "N/A"},
    surface="endpoint",
    files={
        ".bash_history": (
            'ls -la\ngit status\nclaude "fix the failing test"\n'
            'aider --model claude-sonnet-4-5 src/api.py\ncursor .\nnpm test\n'
        ),
    },
    expected_signatures=["claude-code", "aider"],
))

_add(RealWorldCase(
    id="rw-repo-090", category="endpoint", family="jetbrains-ai-plugin",
    label="agent", difficulty="medium",
    description="JetBrains IDE AI assistant plugin config",
    source={"repo": "synthetic", "license": "N/A"},
    surface="endpoint",
    files={
        ".config/JetBrains/IntelliJIdea2025.1/options/ai-assistant.xml": (
            '<?xml version="1.0"?>\n<application>\n'
            '  <component name="AiAssistantSettings">\n'
            '    <option name="enabled" value="true" />\n'
            '    <option name="provider" value="JetBrains AI" />\n'
            '  </component>\n</application>\n'
        ),
    },
    expected_signatures=["jetbrains-ai"],
))

_add(RealWorldCase(
    id="rw-repo-091", category="endpoint", family="npm-global-ai-packages",
    label="agent", difficulty="medium",
    description="Globally installed npm AI packages",
    source={"repo": "synthetic", "license": "N/A"},
    surface="endpoint",
    files={
        ".npm-global/lib/node_modules/@anthropic-ai/claude-code/package.json": '{"name":"@anthropic-ai/claude-code","version":"1.0.25"}\n',
        ".npm-global/lib/node_modules/@modelcontextprotocol/server-filesystem/package.json": '{"name":"@modelcontextprotocol/server-filesystem","version":"1.0.5"}\n',
    },
    expected_signatures=["claude-code", "mcp"],
))

# ===================================================================
# Category 9: Hard Negatives (39 cases)
# ===================================================================

_add(RealWorldCase(
    id="rw-repo-092", category="negative", family="neg-insurance-agents",
    label="none", difficulty="hard",
    description="Insurance agent CRM — human agents, no AI",
    source={"repo": "synthetic", "license": "N/A"},
    files={
        "models/agent.py": '@dataclass\nclass Agent:\n    agent_id: str\n    first_name: str\n    license_number: str\n',
        "api/agents.py": (
            'from flask import Blueprint, jsonify, request\n\n'
            'bp = Blueprint("agents", __name__, url_prefix="/api/agents")\n\n'
            '@bp.route("/")\ndef list_agents():\n'
            '    return jsonify(get_agents_by_region(request.args.get("region")))\n'
        ),
        "requirements.txt": "flask>=3.0\nsqlalchemy>=2.0\n",
    },
))

_add(RealWorldCase(
    id="rw-repo-093", category="negative", family="neg-travel-agent",
    label="none", difficulty="hard",
    description="Travel booking system — human travel agents",
    source={"repo": "synthetic", "license": "N/A"},
    files={
        "booking/agent_portal.py": (
            'class AgentPortal:\n    def __init__(self, agent_code: str):\n'
            '        self.agent_code = agent_code\n\n'
            '    def create_booking(self, passenger: dict, flight: str) -> str:\n'
            '        return f"BK-{self.agent_code}-{hash(flight) % 9999:04d}"\n\n'
            '    def run_tools(self, tool_name: str, params: dict) -> dict:\n'
            '        if tool_name == "assign_seat": return {"seat": "window"}\n'
            '        return {"error": "unknown"}\n'
        ),
    },
))

_add(RealWorldCase(
    id="rw-repo-094", category="negative", family="neg-user-agent-parser",
    label="none", difficulty="medium",
    description="User-Agent parser mentioning AI crawlers",
    source={"repo": "faisalman/ua-parser-js", "license": "MIT"},
    files={
        "parse_ua.py": 'AI_CRAWLERS = ["GPTBot", "ChatGPT-User", "ClaudeBot", "PerplexityBot"]\n\ndef is_ai_crawler(ua: str) -> bool:\n    return any(bot in ua for bot in AI_CRAWLERS)\n',
    },
))

_add(RealWorldCase(
    id="rw-repo-095", category="negative", family="neg-monitoring-agent",
    label="none", difficulty="medium",
    description="Datadog agent configuration",
    source={"repo": "DataDog/datadog-agent", "license": "Apache-2.0"},
    files={
        "datadog.yaml": "api_key: DD_KEY_PLACEHOLDER\nhostname: prod-01\nlogs_enabled: true\napm_config:\n  enabled: true\n",
        "checks.d/custom.py": 'from datadog_checks.base import AgentCheck\n\nclass Custom(AgentCheck):\n    def check(self, instance): self.gauge("svc.latency", 0.042)\n',
    },
))

_add(RealWorldCase(
    id="rw-repo-096", category="negative", family="neg-minecraft-bedrock",
    label="none", difficulty="medium",
    description="Minecraft Bedrock server — not AWS Bedrock",
    source={"repo": "itzg/docker-minecraft-bedrock-server", "license": "Apache-2.0"},
    files={
        "server.properties": "server-name=Survival\ngamemode=survival\nmax-players=20\nlevel-name=Bedrock-World\n",
        "docker-compose.yml": 'services:\n  bedrock:\n    image: itzg/minecraft-bedrock-server\n    environment:\n      EULA: "TRUE"\n    ports: ["19132:19132/udp"]\n',
    },
))

_add(RealWorldCase(
    id="rw-repo-097", category="negative", family="neg-sklearn-pipeline",
    label="none", difficulty="hard",
    description="Classical ML pipeline — not generative AI",
    source={"repo": "scikit-learn/scikit-learn", "license": "BSD-3-Clause"},
    files={
        "train.py": 'from sklearn.pipeline import Pipeline\nfrom sklearn.feature_extraction.text import TfidfVectorizer\nfrom sklearn.svm import LinearSVC\n\npipe = Pipeline([("tfidf", TfidfVectorizer()), ("clf", LinearSVC())])\n',
        "requirements.txt": "scikit-learn>=1.5.0\n",
    },
))

_add(RealWorldCase(
    id="rw-repo-098", category="negative", family="neg-agent-pattern",
    label="none", difficulty="hard",
    description="Agent design pattern in message queue — no AI",
    source={"repo": "synthetic", "license": "N/A"},
    files={
        "agents/worker.py": (
            'import asyncio\nfrom abc import ABC, abstractmethod\n\n'
            'class BaseAgent(ABC):\n'
            '    def __init__(self, name: str, queue_url: str):\n'
            '        self.name = name\n        self.queue_url = queue_url\n\n'
            '    @abstractmethod\n    async def process_message(self, msg: dict) -> dict: ...\n\n'
            '    async def run(self) -> None:\n'
            '        while True:\n            msg = await self.poll_queue()\n'
            '            if msg: await self.process_message(msg)\n'
            '            await asyncio.sleep(0.1)\n'
        ),
    },
))

_add(RealWorldCase(
    id="rw-repo-099", category="negative", family="neg-gemini-exchange",
    label="none", difficulty="hard",
    description="Gemini cryptocurrency exchange — not Google Gemini AI",
    source={"repo": "gemini/gemini-api", "license": "MIT"},
    files={
        "trading.py": (
            'import requests\n\nGEMINI_API = "https://api.gemini.com"\n\n'
            'def get_ticker(symbol: str) -> dict:\n'
            '    return requests.get(f"{GEMINI_API}/v1/pubticker/{symbol}").json()\n\n'
            'def place_order(symbol: str, amount: str, price: str, side: str) -> dict:\n'
            '    return _authenticated_post({"request": "/v1/order/new",\n'
            '        "symbol": symbol, "amount": amount, "price": price, "side": side})\n'
        ),
        "requirements.txt": "requests>=2.32.0\n",
    },
))

_add(RealWorldCase(
    id="rw-repo-100", category="negative", family="neg-commented-out",
    label="none", difficulty="hard",
    description="Commented-out AI code that should not trigger",
    source={"repo": "synthetic", "license": "N/A"},
    files={
        "app.py": (
            '# Tried LangChain but reverted to rules engine.\n'
            '# from langchain.agents import create_react_agent\n'
            '# from langchain_openai import ChatOpenAI\n\n'
            'import re\nRULES = {r"refund": "billing", r"password": "security"}\n\n'
            'def classify(text: str) -> str:\n'
            '    for pat, cat in RULES.items():\n'
            '        if re.search(pat, text, re.IGNORECASE): return cat\n'
            '    return "general"\n'
        ),
    },
))

_add(RealWorldCase(
    id="rw-repo-101", category="negative", family="neg-egress-blocklist",
    label="none", difficulty="hard",
    description="Firewall egress blocklist for AI services — policy, not usage",
    source={"repo": "synthetic", "license": "N/A"},
    files={
        "blocklist.yaml": "name: ai-egress-blocklist\ndescription: Block AI endpoints\ndomains:\n  - api.openai.com\n  - api.anthropic.com\n  - api.mistral.ai\naction: DENY\nlog: true\n",
    },
))

_add(RealWorldCase(
    id="rw-repo-102", category="negative", family="neg-minecraft-mcp",
    label="none", difficulty="hard",
    description="Minecraft Coder Pack — MCP means something else",
    source={"repo": "MinecraftForge/MCPConfig", "license": "MIT"},
    files={
        "mcp/fields.csv": "searge,name,side,desc\nfield_70170_a,xCoord,0,\nfield_70171_b,yCoord,0,\n",
        "mcp.json": '{"version":"1.20.1","channel":"stable","mappings":"mcp_stable-20230914"}\n',
    },
))

_add(RealWorldCase(
    id="rw-repo-103", category="negative", family="neg-plain-webapp",
    label="none", difficulty="easy",
    description="Standard Flask web app — no AI",
    source={"repo": "synthetic", "license": "N/A"},
    files={
        "app.py": 'from flask import Flask, render_template\n\napp = Flask(__name__)\ntasks = []\n\n@app.route("/")\ndef index(): return render_template("index.html", tasks=tasks)\n',
        "requirements.txt": "flask>=3.0\n",
    },
))

_add(RealWorldCase(
    id="rw-repo-104", category="negative", family="neg-pytorch-training",
    label="none", difficulty="hard",
    description="PyTorch training — classical DL, not GenAI",
    source={"repo": "pytorch/examples", "license": "BSD-3-Clause"},
    files={
        "train.py": (
            'import torch\nimport torch.nn as nn\n\n'
            'class Net(nn.Module):\n    def __init__(self):\n        super().__init__()\n'
            '        self.fc1 = nn.Linear(784, 128)\n        self.fc2 = nn.Linear(128, 10)\n'
            '    def forward(self, x):\n        return self.fc2(torch.relu(self.fc1(x.view(-1, 784))))\n\n'
            'model = Net()\nopt = torch.optim.Adam(model.parameters())\n'
        ),
        "requirements.txt": "torch>=2.4.0\ntorchvision>=0.19.0\n",
    },
))

_add(RealWorldCase(
    id="rw-repo-105", category="negative", family="neg-tensorflow-serving",
    label="none", difficulty="hard",
    description="TensorFlow Serving — classical ML serving",
    source={"repo": "tensorflow/serving", "license": "Apache-2.0"},
    files={
        "serving_config.yaml": "model_config_list:\n  config:\n    - name: classifier\n      base_path: /models/classifier\n      model_platform: tensorflow\n",
        "docker-compose.yml": "services:\n  tf:\n    image: tensorflow/serving:latest\n    ports: ['8501:8501']\n    command: --model_config_file=/models/config.yaml\n",
    },
))

_add(RealWorldCase(
    id="rw-repo-106", category="negative", family="neg-prometheus-agent",
    label="none", difficulty="medium",
    description="Prometheus metrics collection",
    source={"repo": "prometheus/node_exporter", "license": "Apache-2.0"},
    files={
        "prometheus.yml": "global:\n  scrape_interval: 15s\nscrape_configs:\n  - job_name: node\n    static_configs:\n      - targets: ['localhost:9100']\n",
    },
))

_add(RealWorldCase(
    id="rw-repo-107", category="negative", family="neg-ansible-agent",
    label="none", difficulty="medium",
    description="Ansible playbook with agent forwarding",
    source={"repo": "ansible/ansible", "license": "GPL-3.0"},
    files={
        "playbook.yml": "---\n- hosts: webservers\n  become: true\n  vars:\n    agent_forward: true\n  tasks:\n    - name: Install nginx\n      apt: name=nginx state=present\n",
    },
))

_add(RealWorldCase(
    id="rw-repo-108", category="negative", family="neg-puppet-agent",
    label="none", difficulty="medium",
    description="Puppet agent manifest",
    source={"repo": "puppetlabs/puppet", "license": "Apache-2.0"},
    files={
        "puppet.conf": "[agent]\nserver = puppet.example.com\nruninterval = 3600\nenvironment = production\n",
    },
))

_add(RealWorldCase(
    id="rw-repo-109", category="negative", family="neg-jenkins-agent",
    label="none", difficulty="medium",
    description="Jenkins build agent",
    source={"repo": "jenkinsci/jenkins", "license": "MIT"},
    files={
        "Jenkinsfile": 'pipeline {\n    agent { docker { image "python:3.12" } }\n    stages {\n        stage("Test") { steps { sh "pytest tests/" } }\n    }\n}\n',
    },
))

_add(RealWorldCase(
    id="rw-repo-110", category="negative", family="neg-snmp-agent",
    label="none", difficulty="medium",
    description="SNMP agent for network monitoring",
    source={"repo": "net-snmp/net-snmp", "license": "BSD-3-Clause"},
    files={
        "snmpd.conf": "agentAddress udp:161\nrocommunity public default\nsysLocation Server Room A\nagentuser root\n",
    },
))

_add(RealWorldCase(
    id="rw-repo-111", category="negative", family="neg-rule-based-chatbot",
    label="none", difficulty="hard",
    description="Rule-based chatbot — no AI/ML",
    source={"repo": "synthetic", "license": "N/A"},
    files={
        "chatbot.py": (
            'import re\nINTENTS = {\n'
            '    r"(?:hi|hello)": "Hello! How can I help?",\n'
            '    r"(?:price|cost)": "Plans start at $9.99/month.",\n'
            '    r"(?:bye)": "Goodbye!",\n}\n\n'
            'def respond(msg: str) -> str:\n'
            '    for pat, resp in INTENTS.items():\n'
            '        if re.search(pat, msg, re.IGNORECASE): return resp\n'
            '    return "Please rephrase."\n'
        ),
    },
))

_add(RealWorldCase(
    id="rw-repo-112", category="negative", family="neg-blockchain-contract",
    label="none", difficulty="medium",
    description="Solidity smart contract",
    source={"repo": "OpenZeppelin/openzeppelin-contracts", "license": "MIT"},
    files={
        "contracts/Token.sol": '// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\nimport "@openzeppelin/contracts/token/ERC20/ERC20.sol";\ncontract MyToken is ERC20 {\n    constructor() ERC20("MyToken", "MTK") { _mint(msg.sender, 1000000 * 10 ** decimals()); }\n}\n',
    },
))

_add(RealWorldCase(
    id="rw-repo-113", category="negative", family="neg-spacy-nlp",
    label="none", difficulty="hard",
    description="spaCy NLP — classical NLP, not GenAI",
    source={"repo": "explosion/spaCy", "license": "MIT"},
    files={
        "ner.py": 'import spacy\nnlp = spacy.load("en_core_web_sm")\ndef extract(text: str) -> list:\n    doc = nlp(text)\n    return [{"text": e.text, "label": e.label_} for e in doc.ents]\n',
        "requirements.txt": "spacy>=3.8.0\n",
    },
))

_add(RealWorldCase(
    id="rw-repo-114", category="negative", family="neg-opencv-cv",
    label="none", difficulty="medium",
    description="OpenCV image processing",
    source={"repo": "opencv/opencv", "license": "Apache-2.0"},
    files={
        "detect.py": 'import cv2\nface_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml")\ndef count_faces(path: str) -> int:\n    img = cv2.imread(path)\n    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)\n    return len(face_cascade.detectMultiScale(gray, 1.3, 5))\n',
    },
))

_add(RealWorldCase(
    id="rw-repo-115", category="negative", family="neg-gymnasium-rl",
    label="none", difficulty="hard",
    description="Gymnasium RL agent — not LLM agent",
    source={"repo": "Farama-Foundation/Gymnasium", "license": "MIT"},
    files={
        "train.py": (
            'import gymnasium as gym\nimport numpy as np\n\n'
            'env = gym.make("CartPole-v1")\n\nclass SimpleAgent:\n'
            '    def act(self, obs: np.ndarray) -> int: return 0 if obs[2] < 0 else 1\n\n'
            'agent = SimpleAgent()\nobs, _ = env.reset()\n'
            'for _ in range(1000):\n    obs, _, done, trunc, _ = env.step(agent.act(obs))\n'
            '    if done or trunc: obs, _ = env.reset()\n'
        ),
        "requirements.txt": "gymnasium>=1.0.0\n",
    },
))

_add(RealWorldCase(
    id="rw-repo-116", category="negative", family="neg-mesa-abm",
    label="none", difficulty="hard",
    description="Mesa agent-based simulation — not AI agent",
    source={"repo": "projectmesa/mesa", "license": "Apache-2.0"},
    files={
        "model.py": (
            'from mesa import Agent, Model\nfrom mesa.space import MultiGrid\n'
            'from mesa.time import RandomActivation\n\n'
            'class SchellingAgent(Agent):\n'
            '    def __init__(self, uid, model, atype):\n'
            '        super().__init__(uid, model)\n        self.type = atype\n\n'
            '    def step(self):\n'
            '        similar = sum(1 for n in self.model.grid.iter_neighbors(self.pos, True) if n.type == self.type)\n'
            '        if similar < 3: self.model.grid.move_to_empty(self)\n'
        ),
    },
))

_add(RealWorldCase(
    id="rw-repo-117", category="negative", family="neg-message-broker",
    label="none", difficulty="medium",
    description="RabbitMQ message consumer",
    source={"repo": "rabbitmq/rabbitmq-tutorials", "license": "Apache-2.0"},
    files={
        "consumer.py": 'import pika\nconn = pika.BlockingConnection(pika.ConnectionParameters("localhost"))\nch = conn.channel()\nch.queue_declare(queue="tasks")\n\ndef callback(ch, method, props, body):\n    print(f"Got: {body.decode()}")\n    ch.basic_ack(delivery_tag=method.delivery_tag)\n\nch.basic_consume(queue="tasks", on_message_callback=callback)\nch.start_consuming()\n',
    },
))

_add(RealWorldCase(
    id="rw-repo-118", category="negative", family="neg-game-npc-ai",
    label="none", difficulty="hard",
    description="Game NPC AI with state machine — not LLM",
    source={"repo": "synthetic", "license": "N/A"},
    files={
        "npc/ai.py": (
            'from enum import Enum\n\nclass State(Enum):\n'
            '    IDLE = "idle"\n    PATROL = "patrol"\n    CHASE = "chase"\n\n'
            'class AIController:\n    def __init__(self, npc):\n'
            '        self.npc = npc\n        self.state = State.IDLE\n\n'
            '    def update(self, dt: float):\n'
            '        if self.state == State.PATROL:\n'
            '            self.npc.move_to_next_waypoint(dt)\n'
            '            if self.npc.detect_player(): self.state = State.CHASE\n'
        ),
    },
))

_add(RealWorldCase(
    id="rw-repo-119", category="negative", family="neg-terraform-state",
    label="none", difficulty="medium",
    description="Terraform state backend",
    source={"repo": "hashicorp/terraform", "license": "MPL-2.0"},
    files={
        "main.tf": 'terraform {\n  backend "s3" {\n    bucket = "tf-state"\n    key = "prod/tf.tfstate"\n    region = "us-east-1"\n  }\n}\n\nprovider "aws" { region = "us-east-1" }\n\nresource "aws_instance" "web" {\n  ami = "ami-0c55b159cbfafe1f0"\n  instance_type = "t3.micro"\n}\n',
    },
))

_add(RealWorldCase(
    id="rw-repo-120", category="negative", family="neg-selenium-automation",
    label="none", difficulty="easy",
    description="Selenium browser test — not AI",
    source={"repo": "SeleniumHQ/selenium", "license": "Apache-2.0"},
    files={
        "test_login.py": 'from selenium import webdriver\nfrom selenium.webdriver.common.by import By\n\ndef test_login():\n    d = webdriver.Chrome()\n    d.get("http://localhost:3000/login")\n    d.find_element(By.ID, "email").send_keys("test@test.com")\n    d.find_element(By.CSS_SELECTOR, "button[type=submit]").click()\n    assert "Dashboard" in d.title\n    d.quit()\n',
    },
))

_add(RealWorldCase(
    id="rw-repo-121", category="negative", family="neg-consul-agent",
    label="none", difficulty="medium",
    description="Consul service mesh agent",
    source={"repo": "hashicorp/consul", "license": "MPL-2.0"},
    files={
        "consul.hcl": 'datacenter = "dc1"\ndata_dir = "/opt/consul"\nclient_addr = "0.0.0.0"\nui_config { enabled = true }\n\nservice {\n  name = "web"\n  port = 8080\n  check { http = "http://localhost:8080/health"  interval = "10s" }\n}\n',
    },
))

_add(RealWorldCase(
    id="rw-repo-122", category="negative", family="neg-vault-agent",
    label="none", difficulty="medium",
    description="Vault agent for secret injection",
    source={"repo": "hashicorp/vault", "license": "MPL-2.0"},
    files={
        "vault-agent.hcl": 'auto_auth {\n  method "kubernetes" {\n    config = { role = "webapp" }\n  }\n}\n\ntemplate {\n  source = "/vault/templates/config.ctmpl"\n  destination = "/app/config.json"\n}\n\nvault { address = "http://vault:8200" }\n',
    },
))

_add(RealWorldCase(
    id="rw-repo-123", category="negative", family="neg-nomad-agent",
    label="none", difficulty="medium",
    description="Nomad container orchestration agent",
    source={"repo": "hashicorp/nomad", "license": "MPL-2.0"},
    files={
        "nomad.hcl": 'data_dir = "/opt/nomad"\nclient { enabled = true }\nplugin "docker" { config { allow_privileged = false } }\n',
        "webapp.nomad": 'job "webapp" {\n  type = "service"\n  group "app" {\n    task "server" {\n      driver = "docker"\n      config { image = "nginx:latest" }\n      resources { cpu = 256  memory = 128 }\n    }\n  }\n}\n',
    },
))

_add(RealWorldCase(
    id="rw-repo-124", category="negative", family="neg-salt-minion",
    label="none", difficulty="medium",
    description="SaltStack minion configuration",
    source={"repo": "saltstack/salt", "license": "Apache-2.0"},
    files={
        "minion.conf": "master: salt-master.example.com\nid: web-01\ngrains:\n  roles:\n    - webserver\nmine_functions:\n  network.ip_addrs: []\n",
    },
))

_add(RealWorldCase(
    id="rw-repo-125", category="negative", family="neg-graphql-resolver",
    label="none", difficulty="medium",
    description="GraphQL with 'agent' field — not AI",
    source={"repo": "synthetic", "license": "N/A"},
    files={
        "schema.graphql": 'type Query { agents(region: String): [Agent!]!  agent(id: ID!): Agent }\ntype Agent { id: ID!  name: String!  region: String!  tools: [String!]! }\n',
        "resolvers/agent.ts": 'export const agentResolvers = {\n  Query: {\n    agents: (_: any, { region }: any) => db.agents.findByRegion(region),\n    agent: (_: any, { id }: any) => db.agents.findById(id),\n  },\n};\n',
    },
))

_add(RealWorldCase(
    id="rw-repo-126", category="negative", family="neg-kerberos-agent",
    label="none", difficulty="medium",
    description="Kerberos auth agent",
    source={"repo": "synthetic", "license": "N/A"},
    files={
        "krb5.conf": "[libdefaults]\n  default_realm = EXAMPLE.COM\n\n[realms]\n  EXAMPLE.COM = {\n    kdc = kerberos.example.com\n    admin_server = kerberos.example.com\n  }\n",
    },
))

_add(RealWorldCase(
    id="rw-repo-127", category="negative", family="neg-build-agent",
    label="none", difficulty="easy",
    description="CI/CD build agent",
    source={"repo": "synthetic", "license": "N/A"},
    files={
        "buildAgent.properties": "serverUrl=https://build.example.com\nname=agent-linux-01\nworkDir=/opt/agent/work\nownPort=9090\n",
    },
))

_add(RealWorldCase(
    id="rw-repo-128", category="negative", family="neg-db-replication",
    label="none", difficulty="medium",
    description="Database replication agent",
    source={"repo": "synthetic", "license": "N/A"},
    files={
        "replication.py": (
            'class ReplicationAgent:\n    def __init__(self, source: str, target: str):\n'
            '        self.source = source\n        self.target = target\n\n'
            '    def run(self, tables: list[str]) -> dict:\n'
            '        synced = 0\n        for t in tables:\n'
            '            rows = self._fetch(t)\n            self._apply(t, rows)\n'
            '            synced += len(rows)\n        return {"synced": synced}\n'
        ),
    },
))

_add(RealWorldCase(
    id="rw-repo-129", category="negative", family="neg-log-shipper",
    label="none", difficulty="easy",
    description="Log shipping agent (Filebeat)",
    source={"repo": "elastic/beats", "license": "Elastic-2.0"},
    files={
        "filebeat.yml": "filebeat.inputs:\n  - type: log\n    paths: ['/var/log/app/*.log']\noutput.elasticsearch:\n  hosts: ['elasticsearch:9200']\n  index: 'app-%{+yyyy.MM.dd}'\n",
    },
))

_add(RealWorldCase(
    id="rw-repo-130", category="negative", family="neg-deepseek-crypto",
    label="none", difficulty="hard",
    description="DeepSeek blockchain analytics — not DeepSeek AI",
    source={"repo": "synthetic", "license": "N/A"},
    files={
        "analytics.py": (
            'import requests\nDEEPSEEK_URL = "https://deepseekai.io/api/v1/blockchain"\n\n'
            'def get_metrics(addr: str) -> dict:\n'
            '    return requests.get(f"{DEEPSEEK_URL}/token/{addr}/metrics").json()\n\n'
            'def get_whales(chain: str = "ethereum") -> list:\n'
            '    return requests.get(f"{DEEPSEEK_URL}/whales", params={"chain": chain}).json()["movements"]\n'
        ),
        "requirements.txt": "requests>=2.32.0\n",
    },
))


# ===================================================================
# Corpus metadata and export
# ===================================================================

CATEGORIES = sorted(set(c.category for c in CASES))
FAMILIES = sorted(set(c.family for c in CASES))
SURFACES = sorted(set(c.surface for c in CASES))
LABEL_COUNTS = {
    "agent": sum(1 for c in CASES if c.label == "agent"),
    "llm": sum(1 for c in CASES if c.label == "llm"),
    "none": sum(1 for c in CASES if c.label == "none"),
}

CORPUS_METADATA = {
    "type": "real-world-patterns",
    "version": "2.0.0",
    "case_count": len(CASES),
    "categories": CATEGORIES,
    "families": FAMILIES,
    "surfaces": SURFACES,
    "label_distribution": LABEL_COUNTS,
    "authorship": (
        "Patterns extracted from public GitHub repositories. "
        "File contents are rewritten to preserve structural signals "
        "while avoiding copyright infringement. "
        "Written in the ShadowScan repository; not independent. "
        "Adversarial cases explicitly target known ShadowScan blind spots "
        "to surface author bias rather than hide it."
    ),
}


def export_corpus(path: Path) -> None:
    doc = {
        "metadata": CORPUS_METADATA,
        "cases": [c.to_json() for c in CASES],
    }
    path.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
