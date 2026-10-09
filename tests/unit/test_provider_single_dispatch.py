"""One executed model selection makes a tool-calling agent; repetition is not required.

The benchmark rubric (A2) counts code that sends tool definitions to a model and
runs at least one call the model selects. ShadowScan required a loop that fed
the result back into the conversation, so examples that run the selected tool
once (the original corpus's single-dispatch repositories, a pre-1.0
`openai.ChatCompletion` example among them) were plain LLM usage. A request
offering tools, followed in the same block by a call to the declared tool, the
callable the model named, or an execution sink fed with the model's arguments,
is now a single selected action: an agent with `tool-use`, without the
`autonomous` capability that only the loop proves.
"""

from __future__ import annotations

import pytest

from shadowscan.models import Kind

TOOLS = (
    'TOOLS = [{"type": "function", "function": {"name": "get_weather", "parameters": {"type": "object"}}}]\n'
)

LEGACY = (
    "import json\nimport openai\n\n\ndef get_weather(location):\n    return location\n\n\n"
    "def main():\n"
    '    tools = [{"type": "function", "function": {"name": "get_weather"}}]\n'
    "    response = openai.ChatCompletion.create(\n"
    '        model="m", messages=[{"role": "user", "content": "weather?"}], tools=tools, tool_choice="auto"\n'
    "    )\n"
    "    tool_call = response.choices[0].message.tool_calls[0].function\n"
    '    print(f"Function called: {tool_call.name}")\n'
    "    result = get_weather(**json.loads(tool_call.arguments))\n"
    "    print(result)\n"
)

CLIENT = (
    "import json\nfrom openai import OpenAI\n\nclient = OpenAI()\n" + TOOLS + "HANDLERS = {}\n\n\n"
    "def answer(question):\n"
    '    response = client.chat.completions.create(model="m", messages=[{"role": "user", "content": question}], tools=TOOLS)\n'
    "    message = response.choices[0].message\n"
    "    if message.tool_calls:\n"
    "        call = message.tool_calls[0]\n"
    "{dispatch}"
    "    return message.content\n"
)

ANTHROPIC = (
    "import anthropic\n\nclient = anthropic.Anthropic()\n"
    'TOOLS = [{"name": "lookup", "description": "d", "input_schema": {"type": "object"}}]\n\n\n'
    "def run(prompt):\n"
    '    response = client.messages.create(model="m", max_tokens=64, tools=TOOLS, messages=[{"role": "user", "content": prompt}])\n'
    "    for block in response.content:\n"
    '        if block.type == "tool_use":\n'
    "            return HANDLERS[block.name](**block.input)\n"
    "    return None\n"
)


DISPATCH = "{dispatch}"


def client(dispatch: str) -> str:
    return CLIENT.replace(DISPATCH, dispatch)


def scan(tmp_path, run_connector, source):
    (tmp_path / "app.py").write_text(source)
    return run_connector("code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False)


def _single_action(findings):
    (agent,) = [finding for finding in findings if finding.kind == Kind.AGENT]
    assert (agent.metadata["agent_type"], agent.metadata["agentic"]) == ("tool-loop", True)
    assert "tool-use" in agent.capabilities
    assert "autonomous" not in agent.capabilities
    assert any("model-selected tool dispatch:" in evidence.description for evidence in agent.evidence)
    return agent


@pytest.mark.parametrize(
    "source",
    [
        LEGACY,
        LEGACY.replace("openai.ChatCompletion.create(", "openai.chat.completions.create("),
        client("        return HANDLERS[call.function.name](**json.loads(call.function.arguments))\n"),
        client(
            "        handler = HANDLERS.get(call.function.name)\n"
            "        handler(**json.loads(call.function.arguments))\n"
        ),
        client("        get_weather(**json.loads(call.function.arguments))\n"),
        client(
            "        try:\n            get_weather(**json.loads(call.function.arguments))\n"
            "        except ValueError:\n            pass\n"
        ),
        client(
            "        for selected in message.tool_calls:\n"
            "            arguments = json.loads(selected.function.arguments)\n"
            "            HANDLERS[selected.function.name](**arguments)\n"
        ),
        ANTHROPIC,
    ],
    ids=["legacy", "module-client", "returned", "registry-get", "declared", "try", "each-call", "anthropic"],
)
def test_one_executed_selection_is_a_single_action_agent(tmp_path, run_connector, source) -> None:
    findings, ctx = scan(tmp_path, run_connector, source)
    assert not ctx.stats.incomplete, ctx.stats.errors
    _single_action(findings)


@pytest.mark.parametrize(
    "source",
    [
        # No tools offered: the model selects nothing.
        LEGACY.replace(', tools=tools, tool_choice="auto"', ""),
        LEGACY.replace('tool_choice="auto"', 'tool_choice="none"'),
        # The selection is only printed or logged.
        client("        print(call.function.arguments)\n"),
        # A handler the model did not name, or a call that is not a declared tool.
        client('        HANDLERS["fixed"](**json.loads(call.function.arguments))\n'),
        client("        transform(**json.loads(call.function.arguments))\n"),
        # The selected call comes from somewhere else.
        client("        call = cached_call\n        get_weather(**json.loads(call.function.arguments))\n"),
        CLIENT.replace(
            "    message = response.choices[0].message", "    message = cached.choices[0].message"
        ).replace(DISPATCH, "        get_weather(**json.loads(call.function.arguments))\n"),
        client("        import cached as call\n        get_weather(**json.loads(call.function.arguments))\n"),
        client(
            "        try:\n            raise ValueError\n        except ValueError as call:\n"
            "            get_weather(**json.loads(call.function.arguments))\n"
        ),
        # Unreachable or deferred dispatch.
        client("        return None\n        get_weather(**json.loads(call.function.arguments))\n"),
        client("        if False:\n            get_weather(**json.loads(call.function.arguments))\n"),
        client("        def later():\n            get_weather(**json.loads(call.function.arguments))\n"),
        client("        run = lambda: get_weather(**json.loads(call.function.arguments))\n"),
        LEGACY.replace("def main():\n", "def main():\n    return\n"),
        # Inside a branch, the selection is not trusted after the branch.
        client(
            "        if ready:\n            call = cached_call\n"
            "        get_weather(**json.loads(call.function.arguments))\n"
        ),
        # A request under a literal-false guard never runs.
        "if False:\n" + "".join("    " + line + "\n" for line in LEGACY.splitlines()),
        # In a string.
        "from openai import OpenAI\nEXAMPLE = " + repr(LEGACY) + "\n",
    ],
    ids=[
        "no-tools",
        "tool-choice-none",
        "printed",
        "fixed-handler",
        "undeclared",
        "rebound-call",
        "other-response",
        "import-alias",
        "except-name",
        "after-return",
        "literal-false",
        "nested-def",
        "lambda",
        "unreachable-request",
        "branch-rebinding",
        "guarded-module",
        "string",
    ],
)
def test_selection_that_is_not_executed_is_not_an_agent(tmp_path, run_connector, source) -> None:
    findings, ctx = scan(tmp_path, run_connector, source)
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert not any(finding.kind == Kind.AGENT for finding in findings)


def test_loop_keeps_its_stronger_evidence(tmp_path, run_connector) -> None:
    from test_provider_loop_semantics import LOOP

    findings, _ = scan(tmp_path, run_connector, LOOP)
    (agent,) = [finding for finding in findings if finding.kind == Kind.AGENT]
    assert "autonomous" in agent.capabilities
    # The loop's request is not reported a second time as a single action.
    assert not any("model-selected tool dispatch:" in evidence.description for evidence in agent.evidence)
