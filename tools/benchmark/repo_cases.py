"""Source-repository case families.

Positive templates follow the public quick-start idioms of each framework or
SDK; negatives share vocabulary with agents and LLM products without using
either. A template returns files relative to the repository root; the
generator may nest them under a monorepo prefix and add noise files.
"""

from __future__ import annotations

import json
from collections.abc import Callable

from tools.benchmark.common import (
    ANTHROPIC_MODELS,
    GEMINI_MODELS,
    OLLAMA_MODELS,
    OPENAI_MODELS,
    Draft,
    Rand,
    dump_json,
    fill,
)

# --------------------------------------------------------------------------
# manifests and noise


def _pyproject(rd: Rand, name: str, deps: list[str]) -> str:
    lines = "\n".join(f'  "{d}",' for d in deps)
    return f'[project]\nname = "{name}"\nversion = "{rd.version()}"\nrequires-python = ">=3.11"\ndependencies = [\n{lines}\n]\n'


def _requirements(deps: list[str]) -> str:
    return "\n".join(deps) + "\n"


def _package_json(rd: Rand, name: str, deps: dict[str, str]) -> str:
    return dump_json(
        {
            "name": name,
            "version": rd.version(),
            "private": True,
            "type": "module",
            "scripts": {"start": "node dist/index.js", "build": "tsc -p ."},
            "dependencies": deps,
            "devDependencies": {"typescript": "^5.6.3", "@types/node": "^22.7.5"},
        }
    )


def _py_manifest(rd: Rand, name: str, deps: list[str]) -> dict[str, str]:
    if rd.chance(0.5):
        return {"pyproject.toml": _pyproject(rd, name, deps)}
    return {"requirements.txt": _requirements(deps)}


NOISE_PY = (
    (
        "utils/text.py",
        "import re\n\n\ndef slugify(value: str) -> str:\n"
        "    value = re.sub(r'[^a-zA-Z0-9]+', '-', value).strip('-')\n    return value.lower()\n",
    ),
    (
        "utils/dates.py",
        "from datetime import datetime, timezone\n\n\ndef utcnow() -> datetime:\n"
        "    return datetime.now(timezone.utc)\n",
    ),
    (
        "tests/test_text.py",
        "from utils.text import slugify\n\n\ndef test_slugify():\n    assert slugify('Hello World') == 'hello-world'\n",
    ),
    (
        "db.py",
        "import sqlite3\n\nCONN = sqlite3.connect('app.db')\n\n\ndef search(term):\n"
        "    cur = CONN.execute('SELECT id, body FROM docs WHERE body LIKE ?', (f'%{term}%',))\n"
        "    return cur.fetchall()\n",
    ),
)
NOISE_TS = (
    (
        "src/lib/format.ts",
        "export function formatMoney(cents: number): string {\n  return (cents / 100).toFixed(2);\n}\n",
    ),
    (
        "src/lib/http.ts",
        "export async function getJson(url: string) {\n  const res = await fetch(url);\n"
        "  if (!res.ok) throw new Error(res.statusText);\n  return res.json();\n}\n",
    ),
    (
        "tsconfig.json",
        dump_json({"compilerOptions": {"target": "ES2022", "module": "ESNext", "strict": True}}),
    ),
)
README_LINES = (
    "Internal service maintained by the platform team.",
    "Run `make dev` to start a local copy.",
    "See docs/ for the deployment runbook.",
    "Owners: see CODEOWNERS.",
)


def readme(rd: Rand, title: str) -> str:
    body = "\n".join(rd.sample(README_LINES, 2))
    return f"# {title}\n\n{body}\n"


def _tool_py(name: str, desc: str, arg: str, decorator: str) -> str:
    deco = f"{decorator}\n" if decorator else ""
    return (
        f'{deco}def {name}({arg}: str) -> str:\n    """{desc}"""\n    return f"{name} result for {{{arg}}}"\n'
    )


# --------------------------------------------------------------------------
# agent positives (Python)


def py_langgraph(rd: Rand) -> Draft:
    tools = rd.tools(rd.randint(1, 3))
    prov = rd.choice(("openai", "anthropic"))
    model_import = (
        "from langchain_openai import ChatOpenAI"
        if prov == "openai"
        else "from langchain_anthropic import ChatAnthropic"
    )
    model_ctor = (
        f'ChatOpenAI(model="{rd.choice(OPENAI_MODELS)}", temperature=0)'
        if prov == "openai"
        else f'ChatAnthropic(model="{rd.choice(ANTHROPIC_MODELS)}")'
    )
    tool_src = "\n\n".join(_tool_py(n, d, a, "@tool") for n, d, a in tools)
    names = ", ".join(n for n, _, _ in tools)
    agent_var = rd.ident() + "_agent"
    if rd.chance(0.6):
        diff = "easy"
        body = fill(
            "@@model_import@@\nfrom langchain_core.tools import tool\nfrom langgraph.prebuilt import create_react_agent\n\n\n"
            "@@tools@@\n\nmodel = @@ctor@@\n@@agent@@ = create_react_agent(model, tools=[@@names@@], "
            'prompt="You are a @@dom@@ assistant.")\n\n\nif __name__ == "__main__":\n'
            '    out = @@agent@@.invoke({"messages": [("user", "What changed this week?")]})\n'
            '    print(out["messages"][-1].content)\n',
            model_import=model_import,
            tools=tool_src,
            ctor=model_ctor,
            agent=agent_var,
            names=names,
            dom=rd.choice(("billing", "support", "research")),
        )
    else:
        diff = "medium"
        body = fill(
            "@@model_import@@\nfrom langchain_core.tools import tool\n"
            "from langgraph.graph import StateGraph, MessagesState, START\n"
            "from langgraph.prebuilt import ToolNode, tools_condition\n\n\n@@tools@@\n\nTOOLS = [@@names@@]\n"
            "llm = @@ctor@@.bind_tools(TOOLS)\n\n\ndef call_model(state: MessagesState):\n"
            '    return {"messages": [llm.invoke(state["messages"])]}\n\n\n'
            "builder = StateGraph(MessagesState)\n"
            'builder.add_node("model", call_model)\nbuilder.add_node("tools", ToolNode(TOOLS))\n'
            'builder.add_edge(START, "model")\nbuilder.add_conditional_edges("model", tools_condition)\n'
            'builder.add_edge("tools", "model")\n@@agent@@ = builder.compile()\n',
            model_import=model_import,
            tools=tool_src,
            ctor=model_ctor,
            agent=agent_var,
            names=names,
        )
    pkg = "langchain-openai" if prov == "openai" else "langchain-anthropic"
    files = {"agent/graph.py": body, **_py_manifest(rd, rd.name(), ["langgraph>=0.4", pkg, "langchain-core"])}
    return Draft("py-langgraph", "agent", diff, "LangGraph agent with model-bound tools.", files)


def py_langchain_agent(rd: Rand) -> Draft:
    tools = rd.tools(rd.randint(1, 3))
    tool_src = "\n\n".join(_tool_py(n, d, a, "@tool") for n, d, a in tools)
    names = ", ".join(n for n, _, _ in tools)
    if rd.chance(0.5):
        body = fill(
            "from langchain.agents import create_agent\nfrom langchain.tools import tool\n\n\n@@tools@@\n\n"
            'agent = create_agent(model="openai:@@model@@", tools=[@@names@@], '
            'system_prompt="Answer questions about @@dom@@.")\n\n'
            'result = agent.invoke({"messages": [{"role": "user", "content": "status?"}]})\n',
            tools=tool_src,
            names=names,
            model=rd.choice(OPENAI_MODELS),
            dom=rd.choice(("orders", "tickets", "invoices")),
        )
        diff = "easy"
    else:
        body = fill(
            "from langchain.agents import AgentExecutor, create_tool_calling_agent\n"
            "from langchain_core.prompts import ChatPromptTemplate\nfrom langchain_core.tools import tool\n"
            "from langchain_openai import ChatOpenAI\n\n\n@@tools@@\n\n"
            "prompt = ChatPromptTemplate.from_messages([\n"
            '    ("system", "You help the @@dom@@ team."),\n    ("human", "{input}"),\n'
            '    ("placeholder", "{agent_scratchpad}"),\n])\n'
            'llm = ChatOpenAI(model="@@model@@")\nagent = create_tool_calling_agent(llm, [@@names@@], prompt)\n'
            "executor = AgentExecutor(agent=agent, tools=[@@names@@], verbose=True)\n",
            tools=tool_src,
            names=names,
            model=rd.choice(OPENAI_MODELS),
            dom=rd.choice(("finance", "ops", "legal")),
        )
        diff = "medium"
    files = {"app/agent.py": body, **_py_manifest(rd, rd.name(), ["langchain>=0.3", "langchain-openai"])}
    return Draft("py-langchain-agent", "agent", diff, "LangChain tool-calling agent.", files)


def py_crewai(rd: Rand) -> Draft:
    tools = rd.tools(rd.randint(1, 2))
    role = rd.choice(("Senior Researcher", "Claims Analyst", "Market Scout", "Release Manager"))
    if rd.chance(0.6):
        tool_src = "\n\n".join(_tool_py(n, d, a, f'@tool("{d.rstrip(".")}")') for n, d, a in tools)
        body = fill(
            "from crewai import Agent, Crew, Process, Task\nfrom crewai.tools import tool\n\n\n@@tools@@\n\n"
            'analyst = Agent(\n    role="@@role@@",\n    goal="Summarise new @@dom@@ signals",\n'
            '    backstory="Works for the @@dom@@ desk.",\n    tools=[@@names@@],\n    llm="@@model@@",\n)\n'
            'task = Task(description="Review this week\'s @@dom@@ items", expected_output="A short brief", '
            "agent=analyst)\ncrew = Crew(agents=[analyst], tasks=[task], process=Process.sequential)\n\n"
            'if __name__ == "__main__":\n    print(crew.kickoff())\n',
            tools=tool_src,
            role=role,
            dom=rd.choice(("claims", "market", "release")),
            names=", ".join(n for n, _, _ in tools),
            model=rd.choice(OPENAI_MODELS),
        )
        files = {"crew/main.py": body}
        diff = "easy"
    else:
        agent_key = rd.ident()
        files = {
            "src/crew/config/agents.yaml": f'{agent_key}:\n  role: "{role}"\n  goal: "Keep the backlog triaged"\n'
            '  backstory: "Experienced and careful."\n',
            "src/crew/config/tasks.yaml": f'triage_task:\n  description: "Triage new issues"\n'
            f'  expected_output: "A ranked list"\n  agent: {agent_key}\n',
            "src/crew/crew.py": fill(
                "from crewai import Agent, Crew, Process, Task\nfrom crewai.project import CrewBase, agent, crew, task\n\n\n"
                "@CrewBase\nclass TriageCrew:\n"
                '    agents_config = "config/agents.yaml"\n    tasks_config = "config/tasks.yaml"\n\n'
                "    @agent\n    def @@key@@(self) -> Agent:\n"
                '        return Agent(config=self.agents_config["@@key@@"], verbose=True)\n\n'
                "    @task\n    def triage_task(self) -> Task:\n"
                '        return Task(config=self.tasks_config["triage_task"])\n\n'
                "    @crew\n    def crew(self) -> Crew:\n"
                "        return Crew(agents=self.agents, tasks=self.tasks, process=Process.sequential)\n",
                key=agent_key,
            ),
        }
        diff = "medium"
    files.update(_py_manifest(rd, rd.name(), ["crewai>=0.80", "crewai-tools"]))
    return Draft("py-crewai", "agent", diff, "CrewAI crew with agents and tasks.", files)


def py_autogen(rd: Rand) -> Draft:
    n, d, a = rd.choice(rd.tools(1))
    body = fill(
        "import asyncio\n\nfrom autogen_agentchat.agents import AssistantAgent\n"
        "from autogen_ext.models.openai import OpenAIChatCompletionClient\n\n\n"
        'async def @@n@@(@@a@@: str) -> str:\n    """@@d@@"""\n    return "ok"\n\n\n'
        "async def main() -> None:\n"
        '    client = OpenAIChatCompletionClient(model="@@model@@")\n'
        '    agent = AssistantAgent("@@name@@", model_client=client, tools=[@@n@@], '
        'system_message="Use tools to answer.")\n'
        '    result = await agent.run(task="Check the latest @@n@@ output")\n    print(result.messages[-1])\n'
        "    await client.close()\n\n\nasyncio.run(main())\n",
        n=n,
        d=d,
        a=a,
        model=rd.choice(OPENAI_MODELS),
        name=rd.ident(),
    )
    files = {
        "assistant.py": body,
        **_py_manifest(rd, rd.name(), ["autogen-agentchat", "autogen-ext[openai]"]),
    }
    return Draft("py-autogen", "agent", "easy", "AutoGen AssistantAgent with a tool.", files)


def py_openai_agents(rd: Rand) -> Draft:
    tools = rd.tools(rd.randint(1, 2))
    tool_src = "\n\n".join(_tool_py(n, d, a, "@function_tool") for n, d, a in tools)
    alias = rd.chance(0.3)
    imp = "import agents as oa" if alias else "from agents import Agent, Runner, function_tool"
    pre = "oa." if alias else ""
    tool_src = tool_src.replace("@function_tool", f"@{pre}function_tool")
    body = fill(
        "@@imp@@\n\n\n@@tools@@\n\n"
        '@@var@@ = @@pre@@Agent(\n    name="@@name@@",\n    instructions="Help the @@dom@@ team.",\n'
        '    tools=[@@names@@],\n    model="@@model@@",\n)\n\n'
        'if __name__ == "__main__":\n    result = @@pre@@Runner.run_sync(@@var@@, "Summarise open work")\n'
        "    print(result.final_output)\n",
        imp=imp,
        tools=tool_src,
        pre=pre,
        var=rd.ident(),
        name=rd.camel(),
        dom=rd.choice(("sales", "ops", "hr")),
        names=", ".join(n for n, _, _ in tools),
        model=rd.choice(OPENAI_MODELS),
    )
    files = {"worker/run.py": body, **_py_manifest(rd, rd.name(), ["openai-agents>=0.2"])}
    return Draft(
        "py-openai-agents", "agent", "medium" if alias else "easy", "OpenAI Agents SDK agent.", files
    )


def py_pydantic_ai(rd: Rand) -> Draft:
    n, d, a = rd.choice(rd.tools(1))
    provider = rd.choice(("openai:" + rd.choice(OPENAI_MODELS), "anthropic:" + rd.choice(ANTHROPIC_MODELS)))
    body = fill(
        "from dataclasses import dataclass\n\nfrom pydantic_ai import Agent, RunContext\n\n\n"
        "@dataclass\nclass Deps:\n    tenant: str\n\n\n"
        'agent = Agent("@@prov@@", deps_type=Deps, system_prompt="Be concise.")\n\n\n'
        '@agent.tool\nasync def @@n@@(ctx: RunContext[Deps], @@a@@: str) -> str:\n    """@@d@@"""\n'
        '    return f"{ctx.deps.tenant}:{@@a@@}"\n\n\n'
        'result = agent.run_sync("Look this up", deps=Deps(tenant="acme"))\nprint(result.output)\n',
        prov=provider,
        n=n,
        d=d,
        a=a,
    )
    files = {"service/agent.py": body, **_py_manifest(rd, rd.name(), ["pydantic-ai>=0.4"])}
    return Draft("py-pydantic-ai", "agent", "easy", "Pydantic AI agent with a registered tool.", files)


def py_smolagents(rd: Rand) -> Draft:
    n, d, a = rd.choice(rd.tools(1))
    kind = rd.choice(("CodeAgent", "ToolCallingAgent"))
    model = rd.choice(
        (
            'InferenceClientModel(model_id="Qwen/Qwen2.5-Coder-32B-Instruct")',
            f'LiteLLMModel(model_id="openai/{rd.choice(OPENAI_MODELS)}")',
        )
    )
    model_cls = model.split("(")[0]
    body = fill(
        "from smolagents import @@kind@@, @@mcls@@, tool\n\n\n@tool\ndef @@n@@(@@a@@: str) -> str:\n"
        '    """@@d@@\n\n    Args:\n        @@a@@: the lookup key\n    """\n    return "done"\n\n\n'
        "agent = @@kind@@(tools=[@@n@@], model=@@model@@, max_steps=6)\n"
        'agent.run("Use @@n@@ to answer the question")\n',
        kind=kind,
        mcls=model_cls,
        n=n,
        a=a,
        d=d,
        model=model,
    )
    files = {"agent_job.py": body, **_py_manifest(rd, rd.name(), ["smolagents[litellm]"])}
    return Draft("py-smolagents", "agent", "easy", "smolagents agent with a tool.", files)


def py_claude_agent_sdk(rd: Rand) -> Draft:
    allowed = rd.sample(("Read", "Grep", "Glob", "Bash", "Edit", "WebFetch"), rd.randint(2, 4))
    body = fill(
        "import anyio\n\nfrom claude_agent_sdk import ClaudeAgentOptions, query\n\n\n"
        "async def main() -> None:\n    options = ClaudeAgentOptions(\n"
        '        system_prompt="You maintain the @@dom@@ repository.",\n        allowed_tools=@@allowed@@,\n'
        "        max_turns=@@turns@@,\n    )\n"
        '    async for message in query(prompt="Find flaky tests and propose fixes", options=options):\n'
        "        print(message)\n\n\nanyio.run(main)\n",
        dom=rd.choice(DOMAINS_SHORT),
        allowed=json.dumps(allowed),
        turns=str(rd.randint(3, 20)),
    )
    files = {"scripts/maintainer.py": body, **_py_manifest(rd, rd.name(), ["claude-agent-sdk", "anyio"])}
    return Draft("py-claude-agent-sdk", "agent", "easy", "Claude Agent SDK query loop with tools.", files)


DOMAINS_SHORT = ("billing", "payments", "search", "mobile", "infra")


def py_google_adk(rd: Rand) -> Draft:
    n, d, a = rd.choice(rd.tools(1))
    cls = rd.choice(("LlmAgent", "Agent"))
    body = fill(
        "from google.adk.agents import @@cls@@\n\n\n"
        'def @@n@@(@@a@@: str) -> dict:\n    """@@d@@"""\n    return {"status": "ok", "value": @@a@@}\n\n\n'
        'root_agent = @@cls@@(\n    name="@@name@@",\n    model="@@model@@",\n'
        '    instruction="Answer using the available tools.",\n    tools=[@@n@@],\n)\n',
        cls=cls,
        n=n,
        a=a,
        d=d,
        name=rd.ident(),
        model=rd.choice(GEMINI_MODELS),
    )
    pkg = rd.ident()
    files = {
        f"{pkg}/agent.py": body,
        f"{pkg}/__init__.py": "from . import agent\n",
        **_py_manifest(rd, rd.name(), ["google-adk"]),
    }
    return Draft("py-google-adk", "agent", "easy", "Google ADK agent with a function tool.", files)


def py_llamaindex(rd: Rand) -> Draft:
    n, d, a = rd.choice(rd.tools(1))
    body = fill(
        "import asyncio\n\nfrom llama_index.core.agent.workflow import FunctionAgent\n"
        "from llama_index.llms.openai import OpenAI\n\n\n"
        'def @@n@@(@@a@@: str) -> str:\n    """@@d@@"""\n    return "ok"\n\n\n'
        'agent = FunctionAgent(tools=[@@n@@], llm=OpenAI(model="@@model@@"), '
        'system_prompt="You are a helpful assistant.")\n\n\n'
        'async def main() -> None:\n    response = await agent.run("What is the status?")\n    print(str(response))\n\n\n'
        "asyncio.run(main())\n",
        n=n,
        a=a,
        d=d,
        model=rd.choice(OPENAI_MODELS),
    )
    files = {"rag/agent.py": body, **_py_manifest(rd, rd.name(), ["llama-index", "llama-index-llms-openai"])}
    return Draft("py-llamaindex", "agent", "easy", "LlamaIndex FunctionAgent with a tool.", files)


def py_raw_tool_loop(rd: Rand) -> Draft:
    tools = rd.tools(rd.randint(1, 3))
    if rd.chance(0.5):
        schema = [
            {
                "type": "function",
                "function": {
                    "name": n,
                    "description": d,
                    "parameters": {"type": "object", "properties": {a: {"type": "string"}}, "required": [a]},
                },
            }
            for n, d, a in tools
        ]
        body = fill(
            "import json\n\nfrom openai import OpenAI\n\nfrom handlers import DISPATCH\n\nclient = OpenAI()\n"
            "TOOLS = @@schema@@\n\n\ndef answer(question: str) -> str:\n"
            '    messages = [{"role": "user", "content": question}]\n    for _ in range(8):\n'
            '        resp = client.chat.completions.create(model="@@model@@", messages=messages, tools=TOOLS)\n'
            "        msg = resp.choices[0].message\n        if not msg.tool_calls:\n            return msg.content\n"
            "        messages.append(msg)\n        for call in msg.tool_calls:\n"
            "            result = DISPATCH[call.function.name](**json.loads(call.function.arguments))\n"
            '            messages.append({"role": "tool", "tool_call_id": call.id, "content": json.dumps(result)})\n'
            '    raise RuntimeError("too many steps")\n',
            schema=json.dumps(schema, indent=4),
            model=rd.choice(OPENAI_MODELS),
        )
        dep = "openai>=1.40"
    else:
        schema = [
            {
                "name": n,
                "description": d,
                "input_schema": {"type": "object", "properties": {a: {"type": "string"}}, "required": [a]},
            }
            for n, d, a in tools
        ]
        body = fill(
            "import anthropic\n\nfrom handlers import DISPATCH\n\nclient = anthropic.Anthropic()\n"
            "TOOLS = @@schema@@\n\n\ndef answer(question: str) -> str:\n"
            '    messages = [{"role": "user", "content": question}]\n    while True:\n'
            "        resp = client.messages.create(\n"
            '            model="@@model@@", max_tokens=1024, tools=TOOLS, messages=messages\n        )\n'
            '        if resp.stop_reason != "tool_use":\n            return resp.content[0].text\n'
            '        messages.append({"role": "assistant", "content": resp.content})\n        results = []\n'
            "        for block in resp.content:\n"
            '            if block.type == "tool_use":\n'
            "                out = DISPATCH[block.name](**block.input)\n"
            '                results.append({"type": "tool_result", "tool_use_id": block.id, "content": str(out)})\n'
            '        messages.append({"role": "user", "content": results})\n',
            schema=json.dumps(schema, indent=4),
            model=rd.choice(ANTHROPIC_MODELS),
        )
        dep = "anthropic>=0.40"
    handlers = "\n\n".join(_tool_py(n, d, a, "") for n, d, a in tools)
    handlers += "\n\nDISPATCH = {" + ", ".join(f'"{n}": {n}' for n, _, _ in tools) + "}\n"
    files = {"loop.py": body, "handlers.py": handlers, **_py_manifest(rd, rd.name(), [dep])}
    return Draft(
        "py-raw-tool-loop",
        "agent",
        "hard",
        "Hand-written model-selected tool dispatch loop, no framework.",
        files,
    )


# --------------------------------------------------------------------------
# agent positives (TypeScript, Go, C#, config, IaC, low-code)


def _ts_files(rd: Rand, main: str, deps: dict[str, str], path: str = "src/agent.ts") -> dict[str, str]:
    deps = {**deps, "zod": "^3.23.8"}
    return {path: main, "package.json": _package_json(rd, rd.name(), deps)}


def ts_openai_agents(rd: Rand) -> Draft:
    n, d, a = rd.choice(rd.tools(1))
    body = fill(
        "import { Agent, run, tool } from '@openai/agents';\nimport { z } from 'zod';\n\n"
        "const @@n@@ = tool({\n  name: '@@n@@',\n  description: '@@d@@',\n"
        "  parameters: z.object({ @@a@@: z.string() }),\n  execute: async ({ @@a@@ }) => `result for ` + @@a@@,\n});\n\n"
        "export const agent = new Agent({\n  name: '@@name@@',\n  instructions: 'Help the team.',\n"
        "  tools: [@@n@@],\n  model: '@@model@@',\n});\n\n"
        "const result = await run(agent, 'What is pending?');\nconsole.log(result.finalOutput);\n",
        n=n,
        d=d,
        a=a,
        name=rd.camel(),
        model=rd.choice(OPENAI_MODELS),
    )
    files = _ts_files(rd, body, {"@openai/agents": "^0.1.0"})
    return Draft("ts-openai-agents", "agent", "easy", "OpenAI Agents SDK (TypeScript) agent.", files)


def ts_vercel_ai(rd: Rand) -> Draft:
    n, d, a = rd.choice(rd.tools(1))
    prov = rd.choice(("openai", "anthropic"))
    model = rd.choice(OPENAI_MODELS) if prov == "openai" else rd.choice(ANTHROPIC_MODELS)
    body = fill(
        "import { generateText, stepCountIs, tool } from 'ai';\nimport { @@prov@@ } from '@ai-sdk/@@prov@@';\n"
        "import { z } from 'zod';\n\nexport async function handle(prompt: string) {\n"
        "  const { text } = await generateText({\n    model: @@prov@@('@@model@@'),\n    tools: {\n"
        "      @@n@@: tool({\n        description: '@@d@@',\n        inputSchema: z.object({ @@a@@: z.string() }),\n"
        "        execute: async ({ @@a@@ }) => ({ ok: true, @@a@@ }),\n      }),\n    },\n"
        "    stopWhen: stepCountIs(@@steps@@),\n    prompt,\n  });\n  return text;\n}\n",
        prov=prov,
        model=model,
        n=n,
        d=d,
        a=a,
        steps=str(rd.randint(3, 10)),
    )
    path = rd.choice(("src/agent.ts", "app/api/chat/route.ts", "lib/assistant.ts"))
    files = _ts_files(rd, body, {"ai": "^5.0.0", f"@ai-sdk/{prov}": "^2.0.0"}, path)
    return Draft("ts-vercel-ai-tools", "agent", "medium", "Vercel AI SDK multi-step tool loop.", files)


def ts_mastra(rd: Rand) -> Draft:
    n, d, a = rd.choice(rd.tools(1))
    body = fill(
        "import { Agent } from '@mastra/core/agent';\nimport { createTool } from '@mastra/core/tools';\n"
        "import { openai } from '@ai-sdk/openai';\nimport { z } from 'zod';\n\n"
        "export const @@n@@Tool = createTool({\n  id: '@@n@@',\n  description: '@@d@@',\n"
        "  inputSchema: z.object({ @@a@@: z.string() }),\n  execute: async ({ context }) => ({ value: context.@@a@@ }),\n});\n\n"
        "export const @@var@@ = new Agent({\n  name: '@@name@@',\n  instructions: 'Use the tool when needed.',\n"
        "  model: openai('@@model@@'),\n  tools: { @@n@@Tool },\n});\n",
        n=n,
        d=d,
        a=a,
        var=rd.ident().replace("_", ""),
        name=rd.camel(),
        model=rd.choice(OPENAI_MODELS),
    )
    files = _ts_files(
        rd, body, {"@mastra/core": "^0.10.0", "@ai-sdk/openai": "^2.0.0"}, "src/mastra/agents/index.ts"
    )
    return Draft("ts-mastra", "agent", "easy", "Mastra agent with a tool.", files)


def ts_langgraph(rd: Rand) -> Draft:
    n, d, a = rd.choice(rd.tools(1))
    body = fill(
        "import { createReactAgent } from '@langchain/langgraph/prebuilt';\nimport { ChatOpenAI } from '@langchain/openai';\n"
        "import { tool } from '@langchain/core/tools';\nimport { z } from 'zod';\n\n"
        "const @@n@@ = tool(async ({ @@a@@ }) => `ok ${@@a@@}`, {\n  name: '@@n@@',\n  description: '@@d@@',\n"
        "  schema: z.object({ @@a@@: z.string() }),\n});\n\n"
        "export const agent = createReactAgent({ llm: new ChatOpenAI({ model: '@@model@@' }), tools: [@@n@@] });\n",
        n=n,
        a=a,
        d=d,
        model=rd.choice(OPENAI_MODELS),
    )
    files = _ts_files(
        rd,
        body,
        {"@langchain/langgraph": "^0.3.0", "@langchain/openai": "^0.5.0", "@langchain/core": "^0.3.0"},
    )
    return Draft("ts-langgraph", "agent", "easy", "LangGraph.js ReAct agent.", files)


def go_langchaingo(rd: Rand) -> Draft:
    body = (
        'package main\n\nimport (\n\t"context"\n\t"fmt"\n\n\t"github.com/tmc/langchaingo/agents"\n'
        '\t"github.com/tmc/langchaingo/chains"\n\t"github.com/tmc/langchaingo/llms/openai"\n'
        '\t"github.com/tmc/langchaingo/tools"\n)\n\nfunc main() {\n\tllm, err := openai.New()\n'
        "\tif err != nil {\n\t\tpanic(err)\n\t}\n"
        "\tagent := agents.NewOneShotAgent(llm, []tools.Tool{tools.Calculator{}}, agents.WithMaxIterations(4))\n"
        "\texecutor := agents.NewExecutor(agent)\n"
        '\tanswer, err := chains.Run(context.Background(), executor, "What is 17 * 23?")\n'
        "\tif err != nil {\n\t\tpanic(err)\n\t}\n\tfmt.Println(answer)\n}\n"
    )
    mod = f"module github.com/acme/{rd.name()}\n\ngo 1.23\n\nrequire github.com/tmc/langchaingo v0.1.13\n"
    return Draft(
        "go-langchaingo",
        "agent",
        "medium",
        "LangChainGo one-shot agent with a tool.",
        {"main.go": body, "go.mod": mod},
    )


def cs_semantic_kernel(rd: Rand) -> Draft:
    plugin = rd.camel() + "Plugin"
    body = fill(
        "using System.ComponentModel;\nusing Microsoft.SemanticKernel;\nusing Microsoft.SemanticKernel.Connectors.OpenAI;\n\n"
        "var builder = Kernel.CreateBuilder();\n"
        'builder.AddOpenAIChatCompletion("@@model@@", Environment.GetEnvironmentVariable("OPENAI_API_KEY")!);\n'
        "builder.Plugins.AddFromType<@@plugin@@>();\nvar kernel = builder.Build();\n"
        "var settings = new OpenAIPromptExecutionSettings { FunctionChoiceBehavior = FunctionChoiceBehavior.Auto() };\n"
        'var result = await kernel.InvokePromptAsync("What needs attention today?", new(settings));\n'
        "Console.WriteLine(result);\n\npublic class @@plugin@@\n{\n"
        '    [KernelFunction("lookup"), Description("Look up a record.")]\n'
        '    public string Lookup(string id) => $"record {id}";\n}\n',
        model=rd.choice(OPENAI_MODELS),
        plugin=plugin,
    )
    proj = (
        '<Project Sdk="Microsoft.NET.Sdk">\n  <PropertyGroup>\n    <OutputType>Exe</OutputType>\n'
        "    <TargetFramework>net8.0</TargetFramework>\n  </PropertyGroup>\n  <ItemGroup>\n"
        '    <PackageReference Include="Microsoft.SemanticKernel" Version="1.30.0" />\n  </ItemGroup>\n</Project>\n'
    )
    return Draft(
        "cs-semantic-kernel",
        "agent",
        "medium",
        "Semantic Kernel app with auto function invocation.",
        {"Program.cs": body, f"{plugin}.csproj": proj},
    )


def _mcp_servers(rd: Rand, k: int) -> dict[str, dict[str, object]]:
    options: list[tuple[str, dict[str, object]]] = [
        (
            "github",
            {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-github"],
                "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_TOKEN}"},
            },
        ),
        (
            "filesystem",
            {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/srv/data"]},
        ),
        ("postgres", {"command": "uvx", "args": ["mcp-server-postgres", "--read-only"]}),
        ("fetch", {"command": "uvx", "args": ["mcp-server-fetch"]}),
        ("sentry", {"url": "https://mcp.sentry.dev/mcp"}),
        ("linear", {"url": "https://mcp.linear.app/sse"}),
        ("playwright", {"command": "npx", "args": ["@playwright/mcp@latest"]}),
        (f"{rd.ident()}-tools", {"command": "python", "args": ["-m", "internal_mcp.server"]}),
    ]
    return dict(rd.sample(options, k))


def mcp_project_config(rd: Rand) -> Draft:
    servers = _mcp_servers(rd, rd.randint(1, 3))
    style = rd.choice((".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json"))
    if style == ".vscode/mcp.json":
        content = dump_json(
            {"servers": {k: {"type": "http" if "url" in v else "stdio", **v} for k, v in servers.items()}}
        )
    else:
        content = dump_json({"mcpServers": servers})
    files = {style: content, "README.md": readme(rd, rd.name()), "src/index.js": "console.log('hello');\n"}
    files["package.json"] = _package_json(rd, rd.name(), {"express": "^4.21.0"})
    return Draft(
        "mcp-project-config",
        "agent",
        "easy" if style == ".mcp.json" else "medium",
        "Project MCP server config.",
        files,
    )


def n8n_ai_agent(rd: Rand) -> Draft:
    wf = {
        "name": f"{rd.camel()} triage",
        "nodes": [
            {"parameters": {}, "name": "When chat message received", "type": "@n8n/n8n-nodes-langchain.chatTrigger",
             "typeVersion": 1.1, "position": [0, 0]},
            {"parameters": {"options": {"systemMessage": "Route tickets."}}, "name": "AI Agent",
             "type": "@n8n/n8n-nodes-langchain.agent", "typeVersion": 1.7, "position": [220, 0]},
            {"parameters": {"model": rd.choice(OPENAI_MODELS)}, "name": "OpenAI Chat Model",
             "type": "@n8n/n8n-nodes-langchain.lmChatOpenAi", "typeVersion": 1, "position": [220, 200]},
            {"parameters": {"url": "https://api.internal/tickets"}, "name": "HTTP Request Tool",
             "type": "@n8n/n8n-nodes-langchain.toolHttpRequest", "typeVersion": 1.1, "position": [420, 200]},
        ],
        "connections": {
            "OpenAI Chat Model": {"ai_languageModel": [[{"node": "AI Agent", "type": "ai_languageModel", "index": 0}]]},
            "HTTP Request Tool": {"ai_tool": [[{"node": "AI Agent", "type": "ai_tool", "index": 0}]]},
        },
    }  # fmt: skip
    return Draft(
        "n8n-ai-agent",
        "agent",
        "medium",
        "n8n workflow export with an AI Agent node and a tool.",
        {f"workflows/{rd.ident()}.json": dump_json(wf), "README.md": readme(rd, "Automations")},
    )


def tf_bedrock_agent(rd: Rand) -> Draft:
    name = rd.ident()
    body = fill(
        'resource "aws_iam_role" "@@n@@" {\n  name               = "@@n@@-agent"\n'
        "  assume_role_policy = data.aws_iam_policy_document.assume.json\n}\n\n"
        'resource "aws_bedrockagent_agent" "@@n@@" {\n  agent_name              = "@@n@@"\n'
        "  agent_resource_role_arn = aws_iam_role.@@n@@.arn\n"
        '  foundation_model        = "anthropic.claude-3-5-sonnet-20240620-v1:0"\n'
        '  instruction             = "You help employees with @@dom@@ questions using the action group."\n}\n\n'
        'resource "aws_bedrockagent_agent_action_group" "@@n@@" {\n  action_group_name = "lookup"\n'
        '  agent_id          = aws_bedrockagent_agent.@@n@@.agent_id\n  agent_version     = "DRAFT"\n'
        "  action_group_executor {\n    lambda = aws_lambda_function.lookup.arn\n  }\n}\n",
        n=name,
        dom=rd.choice(("hr", "it", "travel")),
    )
    return Draft(
        "tf-bedrock-agent",
        "agent",
        "medium",
        "Terraform-provisioned Bedrock agent with an action group.",
        {"infra/agent.tf": body, "infra/versions.tf": 'terraform {\n  required_version = ">= 1.6"\n}\n'},
    )


# --------------------------------------------------------------------------
# LLM-only positives


def py_openai_chat(rd: Rand) -> Draft:
    if rd.chance(0.5):
        call = 'resp = client.chat.completions.create(model="@@m@@", messages=[{"role": "user", "content": text}])\n    return resp.choices[0].message.content\n'
    else:
        call = 'resp = client.responses.create(model="@@m@@", input=text)\n    return resp.output_text\n'
    body = fill(
        "from openai import OpenAI\n\nclient = OpenAI()\n\n\ndef summarise(text: str) -> str:\n    " + call,
        m=rd.choice(OPENAI_MODELS),
    )
    files = {"summarise.py": body, **_py_manifest(rd, rd.name(), ["openai>=1.40"])}
    return Draft("py-openai-chat", "llm", "easy", "Single OpenAI call without tools.", files)


def py_anthropic_messages(rd: Rand) -> Draft:
    body = fill(
        "import anthropic\n\nclient = anthropic.Anthropic()\n\n\ndef classify(ticket: str) -> str:\n"
        '    msg = client.messages.create(\n        model="@@m@@",\n        max_tokens=256,\n'
        '        messages=[{"role": "user", "content": f"Classify: {ticket}"}],\n    )\n    return msg.content[0].text\n',
        m=rd.choice(ANTHROPIC_MODELS),
    )
    files = {"classify.py": body, **_py_manifest(rd, rd.name(), ["anthropic>=0.40"])}
    return Draft(
        "py-anthropic-messages", "llm", "easy", "Single Anthropic Messages call without tools.", files
    )


def py_gemini(rd: Rand) -> Draft:
    body = fill(
        "from google import genai\n\nclient = genai.Client()\n\n\ndef draft_reply(note: str) -> str:\n"
        '    resp = client.models.generate_content(model="@@m@@", contents=f"Draft a reply: {note}")\n'
        "    return resp.text\n",
        m=rd.choice(GEMINI_MODELS),
    )
    files = {"reply.py": body, **_py_manifest(rd, rd.name(), ["google-genai"])}
    return Draft("py-gemini", "llm", "easy", "Single Gemini call.", files)


def py_ollama(rd: Rand) -> Draft:
    body = fill(
        "import ollama\n\n\ndef tag(text: str) -> str:\n"
        '    resp = ollama.chat(model="@@m@@", messages=[{"role": "user", "content": f"Tag: {text}"}])\n'
        '    return resp["message"]["content"]\n',
        m=rd.choice(OLLAMA_MODELS),
    )
    files = {"tagger.py": body, **_py_manifest(rd, rd.name(), ["ollama"])}
    return Draft("py-ollama", "llm", "medium", "Local model call through Ollama.", files)


def py_litellm(rd: Rand) -> Draft:
    body = fill(
        "from litellm import completion\n\n\ndef translate(text: str) -> str:\n"
        '    resp = completion(model="@@m@@", messages=[{"role": "user", "content": f"Translate: {text}"}])\n'
        "    return resp.choices[0].message.content\n",
        m=rd.choice(("gpt-4o-mini", "anthropic/claude-3-5-haiku-latest", "gemini/gemini-2.5-flash")),
    )
    files = {"translate.py": body, **_py_manifest(rd, rd.name(), ["litellm"])}
    return Draft("py-litellm", "llm", "easy", "LiteLLM completion call.", files)


def ts_openai_chat(rd: Rand) -> Draft:
    body = fill(
        "import OpenAI from 'openai';\n\nconst client = new OpenAI();\n\nexport async function title(text: string) {\n"
        "  const res = await client.chat.completions.create({\n    model: '@@m@@',\n"
        "    messages: [{ role: 'user', content: 'Title: ' + text }],\n  });\n  return res.choices[0].message.content;\n}\n",
        m=rd.choice(OPENAI_MODELS),
    )
    return Draft(
        "ts-openai-chat",
        "llm",
        "easy",
        "OpenAI Node call without tools.",
        _ts_files(rd, body, {"openai": "^4.70.0"}, "src/title.ts"),
    )


def js_fetch_anthropic(rd: Rand) -> Draft:
    body = fill(
        "export async function summarize(text) {\n  const res = await fetch('https://api.anthropic.com/v1/messages', {\n"
        "    method: 'POST',\n    headers: {\n      'x-api-key': process.env.ANTHROPIC_API_KEY,\n"
        "      'anthropic-version': '2023-06-01',\n      'content-type': 'application/json',\n    },\n"
        "    body: JSON.stringify({ model: '@@m@@', max_tokens: 300, messages: [{ role: 'user', content: text }] }),\n"
        "  });\n  const data = await res.json();\n  return data.content[0].text;\n}\n",
        m=rd.choice(ANTHROPIC_MODELS),
    )
    files = {"lib/summarize.mjs": body, "package.json": _package_json(rd, rd.name(), {"express": "^4.21.0"})}
    return Draft("js-fetch-anthropic", "llm", "hard", "Raw HTTPS call to the Anthropic API, no SDK.", files)


def ts_vercel_ai_plain(rd: Rand) -> Draft:
    body = fill(
        "import { generateText } from 'ai';\nimport { openai } from '@ai-sdk/openai';\n\n"
        "export async function describe(product: string) {\n"
        "  const { text } = await generateText({ model: openai('@@m@@'), prompt: 'Describe ' + product });\n"
        "  return text;\n}\n",
        m=rd.choice(OPENAI_MODELS),
    )
    files = _ts_files(rd, body, {"ai": "^5.0.0", "@ai-sdk/openai": "^2.0.0"}, "src/describe.ts")
    return Draft("ts-vercel-ai-plain", "llm", "easy", "Vercel AI SDK single generation, no tools.", files)


# --------------------------------------------------------------------------
# negatives


def neg_insurance_agents(rd: Rand) -> Draft:
    body = (
        "from dataclasses import dataclass, field\n\n\n@dataclass\nclass Agent:\n"
        '    """A licensed insurance agent."""\n\n    agent_id: str\n    name: str\n'
        "    licenses: list[str] = field(default_factory=list)\n\n\n@dataclass\nclass Supervisor:\n"
        "    name: str\n    team: list[Agent] = field(default_factory=list)\n\n"
        "    def handoff(self, claim_id: str, to: Agent) -> None:\n"
        '        print(f"claim {claim_id} handed off to {to.name}")\n\n\n'
        "def assign_claim(agents: list[Agent], claim_id: str) -> Agent:\n"
        "    agent = min(agents, key=lambda a: len(a.licenses))\n    return agent\n"
    )
    files = {"insurance/agents.py": body, **_py_manifest(rd, rd.name(), ["sqlalchemy>=2"])}
    return Draft(
        "neg-insurance-agents", "none", "hard", "Human insurance agents, supervisors and handoffs.", files
    )


def neg_user_agent(rd: Rand) -> Draft:
    body = (
        "from ua_parser import user_agent_parser\n\n\ndef browser_family(user_agent: str) -> str:\n"
        "    parsed = user_agent_parser.Parse(user_agent)\n    return parsed['user_agent']['family']\n\n\n"
        "BOT_AGENTS = ('Googlebot', 'bingbot', 'GPTBot', 'ClaudeBot')\n\n\n"
        "def is_crawler(user_agent: str) -> bool:\n    return any(b in user_agent for b in BOT_AGENTS)\n"
    )
    files = {"analytics/ua.py": body, **_py_manifest(rd, rd.name(), ["ua-parser"])}
    return Draft("neg-user-agent", "none", "hard", "User-agent parsing that names AI crawlers.", files)


def neg_monitoring_agent(rd: Rand) -> Draft:
    files = {
        "charts/monitoring/values.yaml": "datadog:\n  site: datadoghq.eu\n  logs:\n    enabled: true\n"
        "agents:\n  image:\n    tag: 7.58.0\n  resources:\n    limits:\n      memory: 512Mi\n",
        "charts/monitoring/Chart.yaml": "apiVersion: v2\nname: monitoring\nversion: 0.3.1\n"
        "dependencies:\n  - name: datadog\n    version: 3.74.0\n    repository: https://helm.datadoghq.com\n",
        "ansible/roles/zabbix_agent/tasks/main.yml": "- name: Install zabbix agent\n  ansible.builtin.package:\n"
        "    name: zabbix-agent2\n    state: present\n",
    }
    return Draft(
        "neg-monitoring-agent", "none", "medium", "Monitoring agents (Datadog, Zabbix), no AI.", files
    )


def neg_readme_prose(rd: Rand) -> Draft:
    text = (
        f"# {rd.camel()}\n\nThis service generates PDF statements.\n\n## AI usage policy\n\n"
        "This repository does not call ChatGPT, Claude, Gemini or Copilot. Do not paste customer\n"
        "data into any AI assistant. Questions go to the security team.\n"
    )
    files = {
        "README.md": text,
        "statements/render.py": "def render(rows):\n    return '\\n'.join(map(str, rows))\n",
    }
    files.update(_py_manifest(rd, rd.name(), ["reportlab"]))
    return Draft("neg-readme-prose", "none", "medium", "Prose policy that names AI products; no use.", files)


def neg_commented_out(rd: Rand) -> Draft:
    body = (
        "# TODO(2024-11): evaluate an LLM summariser here; blocked by legal review.\n"
        "# from openai import OpenAI\n# client = OpenAI()\n\n\n"
        "def summarise(text: str, limit: int = 200) -> str:\n"
        "    return text if len(text) <= limit else text[: limit - 3] + '...'\n"
    )
    files = {"notes/summary.py": body, **_py_manifest(rd, rd.name(), ["click"])}
    return Draft(
        "neg-commented-out", "none", "hard", "Commented-out SDK import; no executable AI use.", files
    )


def neg_sklearn(rd: Rand) -> Draft:
    body = (
        "import pandas as pd\nfrom sklearn.ensemble import RandomForestClassifier\n"
        "from sklearn.model_selection import train_test_split\n\n"
        "df = pd.read_csv('churn.csv')\nX, y = df.drop(columns=['churned']), df['churned']\n"
        "X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)\n"
        "model = RandomForestClassifier(n_estimators=200).fit(X_train, y_train)\n"
        "print(model.score(X_test, y_test))\n"
    )
    files = {"train.py": body, **_py_manifest(rd, rd.name(), ["scikit-learn", "pandas"])}
    return Draft("neg-sklearn", "none", "medium", "Classical ML training, no LLM or agent.", files)


def neg_egress_blocklist(rd: Rand) -> Draft:
    hosts = rd.sample(
        (
            "api.openai.com", "chatgpt.com", "api.anthropic.com", "claude.ai", "gemini.google.com",
            "api.mistral.ai", "api.deepseek.com", "openrouter.ai", "api.groq.com", "perplexity.ai",
        ),
        rd.randint(6, 10),
    )  # fmt: skip
    if rd.chance(0.5):
        content = "# Egress denied by default for unmanaged devices\nblocked_domains:\n" + "".join(
            f"  - {h}\n" for h in hosts
        )
        path = "policies/egress-blocklist.yaml"
    else:
        content = dump_json({"version": 3, "action": "deny", "domains": hosts})
        path = "firewall/ai-deny.json"
    files = {path: content, "README.md": readme(rd, "Network policy")}
    return Draft("neg-egress-blocklist", "none", "hard", "Security blocklist naming AI hosts.", files)


def neg_travel_agent(rd: Rand) -> Draft:
    body = (
        'import requests\n\n\nclass TravelAgent:\n    """Books trips for employees through the travel desk API."""\n\n'
        "    def __init__(self, base_url: str) -> None:\n        self.base_url = base_url\n\n"
        "    def run_tools(self, itinerary: dict) -> dict:\n"
        "        flight = requests.post(f'{self.base_url}/flights', json=itinerary, timeout=10).json()\n"
        "        hotel = requests.post(f'{self.base_url}/hotels', json=itinerary, timeout=10).json()\n"
        "        return {'flight': flight, 'hotel': hotel}\n"
    )
    files = {"travel/agent.py": body, **_py_manifest(rd, rd.name(), ["requests"])}
    return Draft(
        "neg-travel-agent", "none", "hard", "Travel-booking 'agent' class with tools, no model.", files
    )


def neg_gemini_exchange(rd: Rand) -> Draft:
    body = (
        "import hashlib\nimport hmac\nimport time\n\nimport requests\n\nBASE = 'https://api.gemini.com'\n\n\n"
        "def ticker(symbol: str = 'btcusd') -> dict:\n    return requests.get(f'{BASE}/v1/pubticker/{symbol}', timeout=5).json()\n\n\n"
        "def sign(payload: bytes, secret: bytes) -> str:\n    return hmac.new(secret, payload, hashlib.sha384).hexdigest()\n"
    )
    files = {"exchange/gemini_client.py": body, **_py_manifest(rd, rd.name(), ["requests"])}
    return Draft("neg-gemini-exchange", "none", "hard", "Gemini crypto-exchange client.", files)


def neg_minecraft_bedrock(rd: Rand) -> Draft:
    files = {
        "server/server.properties": "server-name=Bedrock Dedicated Server\ngamemode=survival\n"
        "difficulty=normal\nmax-players=20\nserver-port=19132\n",
        "server/start.sh": "#!/bin/sh\nLD_LIBRARY_PATH=. ./bedrock_server\n",
        "README.md": "# Bedrock server\n\nMinecraft Bedrock Edition server for the office LAN.\n",
    }
    return Draft("neg-minecraft-bedrock", "none", "medium", "Minecraft Bedrock server config.", files)


def neg_rule_chatbot(rd: Rand) -> Draft:
    body = (
        "import re\n\nINTENTS = {\n    'reset_password': re.compile(r'reset|forgot', re.I),\n"
        "    'vpn': re.compile(r'vpn|tunnel', re.I),\n}\nREPLIES = {\n"
        "    'reset_password': 'Use the self-service portal.',\n    'vpn': 'Install the VPN client from the catalog.',\n}\n\n\n"
        "def reply(message: str) -> str:\n    for intent, pattern in INTENTS.items():\n"
        "        if pattern.search(message):\n            return REPLIES[intent]\n"
        "    return 'A human agent will reply soon.'\n"
    )
    files = {"helpdesk/bot.py": body, **_py_manifest(rd, rd.name(), ["slack-bolt"])}
    return Draft("neg-rule-chatbot", "none", "medium", "Rule-based helpdesk chatbot, no model.", files)


def neg_webapp(rd: Rand) -> Draft:
    if rd.chance(0.5):
        body = (
            "from flask import Flask, jsonify\n\napp = Flask(__name__)\n\n\n@app.get('/health')\ndef health():\n"
            "    return jsonify(status='ok')\n"
        )
        files = {"app.py": body, **_py_manifest(rd, rd.name(), ["flask"])}
    else:
        body = (
            "import express from 'express';\n\nconst app = express();\napp.get('/health', (_req, res) => res.json({ ok: true }));\n"
            "app.listen(3000);\n"
        )
        files = {"src/server.js": body, "package.json": _package_json(rd, rd.name(), {"express": "^4.21.0"})}
    return Draft("neg-webapp", "none", "easy", "Ordinary web service.", files)


def neg_modcoderpack(rd: Rand) -> Draft:
    files = {
        "mcp/conf/fields.csv": "searge,name,side,desc\nfield_70170_p,worldObj,2,Reference to the World object.\n",
        "mcp/conf/mcp.cfg": "[VERSION]\nClientVersion = 1.12.2\nServerVersion = 1.12.2\n",
        "build.gradle": 'minecraft {\n    version = "1.12.2-14.23.5.2860"\n    mappings = "stable_39"\n}\n',
    }
    return Draft(
        "neg-modcoderpack",
        "none",
        "hard",
        "Minecraft Coder Pack ('MCP') mappings, not Model Context Protocol.",
        files,
    )


def neg_call_center_api(rd: Rand) -> Draft:
    body = (
        'import requests\n\n\nclass AgentServiceClient:\n    """Generated client for the contact-centre agent roster API."""\n\n'
        "    def __init__(self, host: str) -> None:\n        self.host = host\n\n"
        "    def invoke_agent(self, agent_id: str, call_id: str) -> dict:\n"
        "        return requests.post(f'{self.host}/agents/{agent_id}/calls/{call_id}', timeout=5).json()\n"
    )
    files = {"clients/agent_service.py": body, **_py_manifest(rd, rd.name(), ["requests"])}
    return Draft("neg-call-center-api", "none", "hard", "Contact-centre agent API client.", files)


Family = Callable[[Rand], Draft]

AGENT_FAMILIES: tuple[Family, ...] = (
    py_langgraph, py_langchain_agent, py_crewai, py_autogen, py_openai_agents, py_pydantic_ai, py_smolagents,
    py_claude_agent_sdk, py_google_adk, py_llamaindex, py_raw_tool_loop, ts_openai_agents, ts_vercel_ai,
    ts_mastra, ts_langgraph, go_langchaingo, cs_semantic_kernel, mcp_project_config, n8n_ai_agent,
    tf_bedrock_agent,
)  # fmt: skip
LLM_FAMILIES: tuple[Family, ...] = (
    py_openai_chat, py_anthropic_messages, py_gemini, py_ollama, py_litellm, ts_openai_chat, js_fetch_anthropic,
    ts_vercel_ai_plain,
)  # fmt: skip
NEG_FAMILIES: tuple[Family, ...] = (
    neg_insurance_agents, neg_user_agent, neg_monitoring_agent, neg_readme_prose, neg_commented_out, neg_sklearn,
    neg_egress_blocklist, neg_travel_agent, neg_gemini_exchange, neg_minecraft_bedrock, neg_rule_chatbot,
    neg_webapp, neg_modcoderpack, neg_call_center_api,
)  # fmt: skip


def augment(rd: Rand, draft: Draft) -> Draft:
    """Randomize layout: optional monorepo prefix, README and unrelated noise files."""
    files = dict(draft.files)
    has_ts = any(p.endswith((".ts", ".js", ".mjs")) for p in files)
    noise_pool = NOISE_TS if has_ts else NOISE_PY
    for path, text in rd.sample(noise_pool, rd.randint(0, len(noise_pool))):
        files.setdefault(path, text)
    if "README.md" not in files and rd.chance(0.6):
        files["README.md"] = readme(rd, rd.camel())
    difficulty = draft.difficulty
    if rd.chance(0.3):
        prefix = f"{rd.choice(('services', 'packages', 'apps'))}/{rd.name()}/"
        files = {prefix + p: t for p, t in files.items()}
        if difficulty == "easy":
            difficulty = "medium"
    return Draft(draft.family, draft.label, difficulty, draft.rationale, files)
