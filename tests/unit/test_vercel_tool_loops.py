"""Vercel AI SDK multi-step tool loops are agents; single-step calls stay SDK usage.

AI SDK 5 and later run tools in a loop only past the first step (``stopWhen``;
AI SDK 7 renamed ``stepCountIs`` to ``isStepCount``), AI SDK 4 with ``maxSteps``.
The tools of such a loop are usually imported definitions, not inline
``tool({ execute })`` calls, so the loop shape itself establishes the agent.
"""

from __future__ import annotations

import pytest

from shadowscan.models import Kind

TOOLS = """import { tool } from "ai";
import { z } from "zod";

export const getWeather = tool({
  description: "Current weather for a city",
  inputSchema: z.object({ city: z.string() }),
  execute: async ({ city }) => ({ city, celsius: 21 }),
});
"""


def _project(tmp_path, run_connector, source):
    (tmp_path / "route.ts").write_text(source)
    (tmp_path / "tools.ts").write_text(TOOLS)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False)
    assert not ctx.stats.incomplete, ctx.stats.errors
    return next(f for f in findings if f.resource_type == "project")


def _route(imports: str, options: str, call: str = "streamText") -> str:
    return (
        f'import {{ {imports} }} from "ai";\n'
        'import { getWeather } from "./tools";\n\n'
        "export async function POST(request) {\n"
        "  const { messages } = await request.json();\n"
        f"  const result = {call}({{\n    model,\n    messages,\n    {options}\n  }});\n"
        "  return result.toUIMessageStreamResponse();\n"
        "}\n"
    )


@pytest.mark.parametrize(
    ("imports", "options"),
    [
        # AI SDK 7, as in a current chat route with imported tools.
        ("isStepCount, streamText", "stopWhen: isStepCount(5),\n    tools: { getWeather },"),
        ("stepCountIs, streamText", "tools: { getWeather },\n    stopWhen: stepCountIs(10),"),
        ("hasToolCall, streamText", "tools: { getWeather },\n    stopWhen: hasToolCall('finalAnswer'),"),
        (
            "hasToolCall, isStepCount, streamText",
            "tools: toolSet,\n    stopWhen: [isStepCount(8), hasToolCall('done')],",
        ),
        ("streamText", "tools: { weather: getWeather },\n    stopWhen: stopCondition,"),
        # AI SDK 4.
        ("streamText", "tools: { getWeather },\n    maxSteps: 5,"),
        ("streamText", "tools: { getWeather },\n    maxSteps: MAX_STEPS,"),
        # Callbacks written as methods, nested spreads and a dynamic tool
        # selection do not hide the loop.
        (
            "isStepCount, streamText",
            "activeTools: reasoning ? [] : ['getWeather'],\n"
            "    onFinish() {\n      record();\n    },\n"
            "    async onError({ error }) {\n      report(error);\n    },\n"
            "    providerOptions: { ...(order && { gateway: { order } }) },\n"
            "    stopWhen: isStepCount(5),\n"
            "    tools: { getWeather, lookup: lookupTool({ session }) },",
        ),
    ],
)
def test_multi_step_tool_loop_is_an_agent(tmp_path, run_connector, imports, options):
    finding = _project(tmp_path, run_connector, _route(imports, options))
    assert finding.kind == Kind.AGENT
    assert "framework.vercel-ai-sdk" in finding.frameworks
    assert "tool-use" in finding.capabilities
    assert any("multi-step tool loop" in e.description for e in finding.evidence)


def test_generate_text_and_namespace_imports_are_resolved(tmp_path, run_connector):
    source = (
        'import * as ai from "ai";\n'
        'import { getWeather } from "./tools";\n'
        "const { text } = await ai.generateText({ model, prompt, tools: { getWeather }, "
        "stopWhen: ai.isStepCount(4) });\n"
    )
    finding = _project(tmp_path, run_connector, source)
    assert finding.kind == Kind.AGENT and "tool-use" in finding.capabilities


@pytest.mark.parametrize(
    ("imports", "options"),
    [
        # A plain chat route: one model call, no tools.
        ("streamText", "temperature: 0.2,"),
        # Several steps without tools add nothing for the model to call.
        ("isStepCount, streamText", "stopWhen: isStepCount(5),"),
        # Imported tools without a stop condition: the call ends after one step.
        ("streamText", "tools: { getWeather },"),
        ("isStepCount, streamText", "tools: { getWeather },\n    stopWhen: isStepCount(1),"),
        ("streamText", "tools: { getWeather },\n    maxSteps: 1,"),
        ("isStepCount, streamText", "tools: {},\n    stopWhen: isStepCount(5),"),
        ("isStepCount, streamText", "tools: undefined,\n    stopWhen: isStepCount(5),"),
        ("isStepCount, streamText", "tools: { getWeather },\n    stopWhen: undefined,"),
        (
            "isStepCount, streamText",
            "tools: { getWeather },\n    stopWhen: isStepCount(5),\n    toolChoice: 'none',",
        ),
        (
            "isStepCount, streamText",
            "tools: { getWeather },\n    stopWhen: isStepCount(5),\n    activeTools: [],",
        ),
        # A later spread can replace the stop condition and the tools.
        (
            "isStepCount, streamText",
            "tools: { getWeather },\n    stopWhen: isStepCount(5),\n    ...overrides,",
        ),
        # Option text inside a prompt string is not an option.
        ("streamText", "tools: { getWeather },\n    prompt: 'stopWhen: isStepCount(5), maxSteps: 9',"),
    ],
)
def test_single_step_or_toolless_calls_stay_sdk_usage(tmp_path, run_connector, imports, options):
    finding = _project(tmp_path, run_connector, _route(imports, options))
    assert finding.kind == Kind.FRAMEWORK_USAGE
    assert "framework.vercel-ai-sdk" in finding.frameworks
    assert "tool-use" not in finding.capabilities


def test_a_local_function_named_like_the_sdk_is_not_bound(tmp_path, run_connector):
    source = _route("generateText", "tools: { getWeather },\n    stopWhen: isStepCount(5),").replace(
        "export async function POST", "const streamText = (options) => options;\nexport async function POST"
    )
    finding = _project(tmp_path, run_connector, source)
    assert finding.kind == Kind.FRAMEWORK_USAGE


def test_options_built_elsewhere_are_not_read(tmp_path, run_connector):
    # The options object is not inline, so neither its tools nor its stop condition is known.
    source = (
        'import { isStepCount, streamText } from "ai";\n'
        'import { getWeather } from "./tools";\n'
        "const options = { model, tools: { getWeather }, stopWhen: isStepCount(5) };\n"
        "export const result = streamText(options);\n"
    )
    assert _project(tmp_path, run_connector, source).kind == Kind.FRAMEWORK_USAGE


@pytest.mark.parametrize("name", ["ToolLoopAgent", "Agent"])
def test_agent_classes_bound_to_the_sdk_are_agents(tmp_path, run_connector, name):
    source = (
        f'import {{ {name}, isStepCount }} from "ai";\n'
        'import { getWeather } from "./tools";\n'
        f"export const assistant = new {name}({{ model, tools: {{ getWeather }}, stopWhen: isStepCount(20) }});\n"
    )
    finding = _project(tmp_path, run_connector, source)
    assert finding.kind == Kind.AGENT


def test_signature_names_the_ai_sdk_7_stop_conditions(index):
    for text in ("stopWhen: isStepCount(5)", "stopWhen: stepCountIs(5)", "stopWhen: [hasToolCall('x')]"):
        matches = [
            m for m in index.match_code(text, "javascript") if m.signature_id == "framework.vercel-ai-sdk"
        ]
        assert matches and all(m.agent_indicator for m in matches), text
