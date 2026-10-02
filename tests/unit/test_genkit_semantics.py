from __future__ import annotations

import pytest

from shadowscan.models import Kind

_INITIALIZE = 'import { genkit } from "genkit";\nconst ai = genkit({plugins: []});\n'
_REGISTER = 'const lookup = ai.defineTool({name: "lookup"}, async (input) => input);\n'


def _scan(tmp_path, run_connector, source: str, suffix: str):
    (tmp_path / f"app{suffix}").write_text(source)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), scan_secrets=False, use_git=False)
    assert not ctx.stats.incomplete, ctx.stats.errors
    return next(f for f in findings if "framework.genkit" in f.frameworks)


@pytest.mark.parametrize("suffix", [".js", ".ts"])
@pytest.mark.parametrize(
    "body",
    [
        "",
        'ai.defineFlow({name: "echo"}, async (input) => input);\n',
        _REGISTER,
        'await ai.generate({prompt: "Hello"});\n',
        'await ai.generate({prompt: "Hello", tools: []});\n',
        _REGISTER + "await ai.generate({tools: [lookup], returnToolRequests: true});\n",
        _REGISTER + "await ai.generate({tools: [lookup], returnToolRequests: dynamic});\n",
        _REGISTER + 'await ai.generate({tools: [lookup], toolChoice: "none"});\n',
        _REGISTER + "await ai.generate({tools: [lookup], ...options});\n",
        'const lookup = ai.defineTool({name: "lookup"}, false);\nawait ai.generate({tools: [lookup]});\n',
        'const lookup = ai.defineTool({name: "lookup"}, (() => false)());\n'
        "await ai.generate({tools: [lookup]});\n",
        "await ai.generate({tools: [unknown]});\n",
        "await ai.generate({tools: [lookup]});\n" + _REGISTER,
        _REGISTER + "lookup = foreign;\nawait ai.generate({tools: [lookup]});\n",
        "const other = genkit({plugins: []});\n"
        'const lookup = other.defineTool({name: "lookup"}, async (input) => input);\n'
        "await ai.generate({tools: [lookup]});\n",
    ],
)
def test_genkit_framework_configuration_does_not_establish_an_agent(tmp_path, run_connector, suffix, body):
    finding = _scan(tmp_path, run_connector, _INITIALIZE + body, suffix)
    assert finding.kind == Kind.FRAMEWORK_USAGE
    assert finding.capabilities == []
    assert finding.metadata["agent_indicators"] == 0


@pytest.mark.parametrize(
    "body",
    [
        "ai = foreign;\nawait ai.generate({tools: [lookup]});\n",
        "function unrelated(ai) {return ai.generate({tools: [lookup]});}\n",
    ],
)
def test_uncertain_genkit_receivers_cannot_establish_agent_calls(tmp_path, run_connector, body):
    finding = _scan(tmp_path, run_connector, _INITIALIZE + _REGISTER + body, ".ts")
    assert finding.kind == Kind.FRAMEWORK_USAGE
    assert finding.metadata["agent_indicators"] == 0


@pytest.mark.parametrize("suffix", [".js", ".ts"])
@pytest.mark.parametrize("method", ["generate", "generateStream"])
@pytest.mark.parametrize("reference", ["lookup", '"lookup"'])
def test_genkit_registered_tools_preserve_automatic_agent_loops(
    tmp_path, run_connector, suffix, method, reference
):
    finding = _scan(
        tmp_path,
        run_connector,
        _INITIALIZE + _REGISTER + f"await ai.{method}({{tools: [{reference}]}});\n",
        suffix,
    )
    assert finding.kind == Kind.AGENT
    assert finding.capabilities == ["tool-use"]
    assert finding.metadata["agent_indicators"] >= 1


@pytest.mark.parametrize("method", ["defineAgent", "definePromptAgent", "defineCustomAgent"])
@pytest.mark.parametrize("tools", ["", ", tools: []"])
def test_explicit_genkit_agent_definitions_remain_agents_without_tools(
    tmp_path, run_connector, method, tools
):
    finding = _scan(
        tmp_path,
        run_connector,
        _INITIALIZE + f'const worker = ai.{method}({{name: "worker"{tools}}});\n',
        ".ts",
    )
    assert finding.kind == Kind.AGENT
    assert finding.capabilities == []


def test_genkit_alias_and_namespace_instances_remain_detectable(tmp_path, run_connector):
    finding = _scan(
        tmp_path,
        run_connector,
        'import * as sdk from "genkit/beta";\n'
        "const worker = sdk.genkit({plugins: []});\n"
        'worker.defineAgent({name: "worker"});\n',
        ".ts",
    )
    assert finding.kind == Kind.AGENT
    assert finding.capabilities == []


def test_function_local_genkit_instance_cannot_bind_unrelated_code(tmp_path, run_connector):
    finding = _scan(
        tmp_path,
        run_connector,
        'import { genkit } from "genkit";\n'
        "function configure() { const ai = genkit({plugins: []}); }\n"
        'ai.defineAgent({name: "foreign"});\n',
        ".ts",
    )
    assert finding.kind == Kind.FRAMEWORK_USAGE


@pytest.mark.parametrize("reference", ["lookup", '"lookup"'])
def test_function_local_tool_registration_cannot_bind_module_generation(tmp_path, run_connector, reference):
    finding = _scan(
        tmp_path,
        run_connector,
        _INITIALIZE
        + "function neverCalled() {\n"
        + _REGISTER
        + "}\n"
        + f"await ai.generate({{tools: [{reference}]}});\n",
        ".ts",
    )
    assert finding.kind == Kind.FRAMEWORK_USAGE
    assert finding.capabilities == []
    assert finding.metadata["agent_indicators"] == 0


@pytest.mark.parametrize("suffix", [".js", ".ts"])
@pytest.mark.parametrize(
    "registration",
    [
        'const register = () => ai.defineTool({name: "lookup"}, async (input) => input);\n',
        'const register = () =>\n  ai.defineTool({name: "lookup"}, async (input) => input);\n',
        'const register = async () =>\n  ai.defineTool({name: "lookup"}, async (input) => input);\n',
        'const register = () => (ai.defineTool({name: "lookup"}, async (input) => input));\n',
        'if (false)\n  ai.defineTool({name: "lookup"}, async (input) => input);\n',
    ],
)
def test_concise_arrow_or_conditional_tool_registration_is_not_module_execution(
    tmp_path, run_connector, suffix, registration
):
    finding = _scan(
        tmp_path,
        run_connector,
        _INITIALIZE + registration + 'await ai.generate({tools: ["lookup"]});\n',
        suffix,
    )
    assert finding.kind == Kind.FRAMEWORK_USAGE
    assert finding.capabilities == []
    assert finding.metadata["agent_indicators"] == 0


@pytest.mark.parametrize("suffix", [".js", ".ts"])
def test_standalone_module_tool_registration_preserves_named_generation(tmp_path, run_connector, suffix):
    finding = _scan(
        tmp_path,
        run_connector,
        _INITIALIZE
        + 'ai.defineTool({name: "lookup"}, async (input) => input);\n'
        + 'await ai.generate({tools: ["lookup"]});\n',
        suffix,
    )
    assert finding.kind == Kind.AGENT
    assert finding.capabilities == ["tool-use"]


@pytest.mark.parametrize("suffix", [".js", ".ts"])
def test_long_bound_agent_calls_fail_incomplete(tmp_path, run_connector, suffix):
    (tmp_path / f"app{suffix}").write_text(
        'import { Agent } from "@openai/agents";\n'
        'const worker = new Agent({name: "worker", instructions: "' + "x" * 9000 + '"});\n'
    )
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), scan_secrets=False, use_git=False)
    assert ctx.stats.incomplete
    assert any("call text limit" in error for error in ctx.stats.errors)


@pytest.mark.parametrize("suffix", [".js", ".ts"])
def test_short_bound_agent_calls_remain_complete(tmp_path, run_connector, suffix):
    (tmp_path / f"app{suffix}").write_text(
        'import { Agent } from "@openai/agents";\n'
        'const worker = new Agent({name: "worker", instructions: "Help"});\n'
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), scan_secrets=False, use_git=False)
    assert not ctx.stats.incomplete
    assert any(f.kind == Kind.AGENT and "framework.openai-agents-sdk" in f.frameworks for f in findings)
