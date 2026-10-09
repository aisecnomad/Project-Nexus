"""Agent classification requires imported receiver and tool-loop provenance."""

from __future__ import annotations

import pytest

from shadowscan.connectors.code import polyglot_bindings
from shadowscan.models import Kind


def _scan(tmp_path, run_connector, filename, source):
    (tmp_path / filename).write_text(source)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False)
    assert not ctx.stats.incomplete, ctx.stats.errors
    return findings


def _cs(body, parameters="IChatClient inner, AIFunction weather", imports="using Microsoft.Extensions.AI;"):
    return (
        imports
        + "\nclass App { async System.Threading.Tasks.Task Run("
        + parameters
        + ") { "
        + body
        + " } }\n"
    )


def _agent(findings, signature):
    return [finding for finding in findings if finding.kind == Kind.AGENT and signature in finding.frameworks]


CS_CLIENT = "var client = new FunctionInvokingChatClient(inner); "
CS_OPTIONS = "var options = new ChatOptions { Tools = [weather] }; "
CS_REQUEST = 'await client.GetResponseAsync("weather", options); '


@pytest.mark.parametrize(
    "body",
    [
        "var tool = AIFunctionFactory.Create(Greet); System.Console.WriteLine(tool.Name);",
        "var client = new FunctionInvokingChatClient(inner);",
        "var client = inner.AsBuilder().UseFunctionInvocation().Build();",
    ],
)
def test_dotnet_tool_definitions_and_unconfigured_clients_are_usage(tmp_path, run_connector, body):
    findings = _scan(tmp_path, run_connector, "App.cs", _cs(body))
    assert not _agent(findings, "framework.microsoft-extensions-ai")
    assert all(not finding.capabilities for finding in findings)


@pytest.mark.parametrize(
    "client",
    [
        CS_CLIENT,
        "var client = inner.AsBuilder().UseFunctionInvocation().Build(); ",
        "var client = new ChatClientBuilder(inner).UseFunctionInvocation().Build(); ",
    ],
)
@pytest.mark.parametrize("method", ["GetResponseAsync", "GetStreamingResponseAsync"])
def test_dotnet_function_invocation_dispatch_is_agent(tmp_path, run_connector, client, method):
    body = client + CS_OPTIONS + CS_REQUEST.replace("GetResponseAsync", method)
    agents = _agent(_scan(tmp_path, run_connector, "App.cs", _cs(body)), "framework.microsoft-extensions-ai")
    assert len(agents) == 1 and agents[0].capabilities == ["tool-use"]


@pytest.mark.parametrize(
    "tools",
    ["[]", "null", "unknown", "new AITool[] {}", "new List<AITool>() {}", "[schema]"],
)
def test_dotnet_empty_or_unproven_tools_do_not_establish_agent(tmp_path, run_connector, tools):
    body = CS_CLIENT + f"var options = new ChatOptions {{ Tools = {tools} }}; " + CS_REQUEST
    findings = _scan(tmp_path, run_connector, "App.cs", _cs(body))
    assert not _agent(findings, "framework.microsoft-extensions-ai")


@pytest.mark.parametrize(
    "change",
    [
        "client = null; ",
        "{ client = null; } ",
        "if (ready) { client = null; } ",
        "options = new ChatOptions(); ",
        "{ options = new ChatOptions(); } ",
        "options.Tools = []; ",
        "options.ToolMode = ChatToolMode.None; ",
        "options.Tools.Clear(); ",
        "{ options.Tools = []; } ",
    ],
)
def test_dotnet_rebindings_and_disabling_mutations_invalidate_dispatch(tmp_path, run_connector, change):
    findings = _scan(tmp_path, run_connector, "App.cs", _cs(CS_CLIENT + CS_OPTIONS + change + CS_REQUEST))
    assert not _agent(findings, "framework.microsoft-extensions-ai")


@pytest.mark.parametrize("mutation", ["tools.Clear();", "alias.Clear();", "options.Tools.Clear();"])
def test_dotnet_options_retain_collection_mutation_provenance(tmp_path, run_connector, mutation):
    body = (
        CS_CLIENT
        + "var tools = new List<AITool> { weather }; var alias = tools; "
        + "var options = new ChatOptions { Tools = tools }; "
        + mutation
        + CS_REQUEST
    )
    findings = _scan(tmp_path, run_connector, "App.cs", _cs(body))
    assert not _agent(findings, "framework.microsoft-extensions-ai")
    assert findings[0].capabilities == []
    assert "tool-use" in findings[0].metadata["contextual_capabilities"]
    assert "tool-use" in findings[0].metadata["potential_capabilities"]


def test_dotnet_tool_factory_registers_a_local_function_for_dispatch(tmp_path, run_connector):
    body = CS_CLIENT + "var weather = AIFunctionFactory.Create(Greet); " + CS_OPTIONS + CS_REQUEST
    findings = _scan(tmp_path, run_connector, "App.cs", _cs(body, "IChatClient inner"))
    assert _agent(findings, "framework.microsoft-extensions-ai")


@pytest.mark.parametrize(
    "imports,parameters,body",
    [
        (
            "using AI = Microsoft.Extensions.AI;",
            "AI.IChatClient inner, AI.AIFunction weather",
            "var client = new AI.FunctionInvokingChatClient(inner); "
            "var options = new AI.ChatOptions { Tools = [weather] }; " + CS_REQUEST,
        ),
        (
            "using Loop = Microsoft.Extensions.AI.FunctionInvokingChatClient; "
            "using Options = Microsoft.Extensions.AI.ChatOptions; "
            "using Tool = Microsoft.Extensions.AI.AIFunction; "
            "using Client = Microsoft.Extensions.AI.IChatClient;",
            "Client inner, Tool weather",
            "var client = new Loop(inner); var options = new Options { Tools = [weather] }; " + CS_REQUEST,
        ),
    ],
)
def test_dotnet_namespace_and_type_aliases_preserve_provenance(
    tmp_path, run_connector, imports, parameters, body
):
    findings = _scan(tmp_path, run_connector, "App.cs", _cs(body, parameters, imports))
    assert _agent(findings, "framework.microsoft-extensions-ai")


@pytest.mark.parametrize("lookalike", ["FunctionInvokingChatClient", "ChatOptions", "AIFunctionFactory"])
def test_dotnet_local_type_collisions_do_not_borrow_sdk_identity(tmp_path, run_connector, lookalike):
    body = CS_CLIENT + "var weather = AIFunctionFactory.Create(Greet); " + CS_OPTIONS + CS_REQUEST
    source = _cs(body, "IChatClient inner") + f"class {lookalike} {{ }}\n"
    assert not _agent(_scan(tmp_path, run_connector, "App.cs", source), "framework.microsoft-extensions-ai")


def test_dotnet_nested_local_shadow_does_not_replace_outer_client(tmp_path, run_connector):
    body = CS_CLIENT + CS_OPTIONS + "{ var client = new Queue(); } " + CS_REQUEST
    assert _agent(_scan(tmp_path, run_connector, "App.cs", _cs(body)), "framework.microsoft-extensions-ai")


def test_dotnet_unknown_member_receiver_cannot_borrow_local_client(tmp_path, run_connector):
    body = CS_CLIENT + CS_OPTIONS + CS_REQUEST.replace("client.Get", "holder.client.Get")
    assert not _agent(
        _scan(tmp_path, run_connector, "App.cs", _cs(body)), "framework.microsoft-extensions-ai"
    )


@pytest.mark.parametrize(
    "imports, name",
    [
        ("using Microsoft.Extensions.AI;", "ChatToolMode"),
        ("using Microsoft.Extensions.AI; using Mode = Microsoft.Extensions.AI.ChatToolMode;", "Mode"),
    ],
)
def test_dotnet_shadowed_tool_mode_cannot_borrow_sdk_enum_identity(tmp_path, run_connector, imports, name):
    body = (
        CS_CLIENT
        + CS_OPTIONS
        + f"var {name} = new {{ Auto = Microsoft.Extensions.AI.ChatToolMode.None }}; "
        + f"options.ToolMode = {name}.Auto; "
        + CS_REQUEST
    )
    assert not _agent(
        _scan(tmp_path, run_connector, "App.cs", _cs(body, imports=imports)),
        "framework.microsoft-extensions-ai",
    )


@pytest.mark.parametrize("mode", ["Auto", "RequireAny"])
def test_dotnet_unshadowed_tool_mode_alias_retains_agent_proof(tmp_path, run_connector, mode):
    imports = "using Microsoft.Extensions.AI; using Mode = Microsoft.Extensions.AI.ChatToolMode;"
    body = CS_CLIENT + CS_OPTIONS + f"options.ToolMode = Mode.{mode}; " + CS_REQUEST
    assert _agent(
        _scan(tmp_path, run_connector, "App.cs", _cs(body, imports=imports)),
        "framework.microsoft-extensions-ai",
    )


@pytest.mark.parametrize("alias", ["agents", "sdk", "executor"])
@pytest.mark.parametrize("factory", ["NewExecutor", "NewOneShotAgent", "NewConversationalAgent"])
def test_go_exact_agents_import_and_aliases_bind_constructors(tmp_path, run_connector, alias, factory):
    source = (
        f'package main\nimport {alias} "github.com/tmc/langchaingo/agents"\n'
        f"func run() {{ {alias}.{factory}(ctx, model) }}\n"
    )
    assert _agent(_scan(tmp_path, run_connector, "main.go", source), "framework.langchaingo")


def test_go_real_constructor_after_inert_prefix_retains_import_proof(tmp_path, run_connector):
    source = (
        'package main\nimport "github.com/tmc/langchaingo/agents"\n'
        "// agents.NewExecutor(ctx, model)\n"
        'var example = "agents.NewExecutor(ctx, model)"\n'
        "func run() { agents.NewExecutor(ctx, model) }\n"
    )
    assert _agent(_scan(tmp_path, run_connector, "main.go", source), "framework.langchaingo")


@pytest.mark.parametrize(
    "body",
    [
        "func run() { agents := Queue{}; agents.NewExecutor() }",
        "func run(agents Queue) { agents.NewExecutor() }",
        "func run(agents Queue) Result { return agents.NewExecutor() }",
        "func run(agents Queue) *Result { return agents.NewExecutor() }",
        "func run(agents Queue) (Result, error) { return agents.NewExecutor(), nil }",
        "func run(agents Queue) interface{} { return agents.NewExecutor() }",
        "func run(agents Queue) struct{X int} { return agents.NewExecutor() }",
        "func run(agents Queue) func() Result { return agents.NewExecutor() }",
        "func (agents Queue) run() Result { return agents.NewExecutor() }",
        "func run() (agents Queue) { agents.NewExecutor(); return }",
        "func run() { var agents Queue; agents.NewExecutor() }",
        "func run() { var (agents Queue); agents.NewExecutor() }",
        "func run() { first, agents := build(); agents.NewExecutor() }",
        "func run() { holder.agents.NewExecutor() }",
    ],
)
def test_go_local_receivers_and_parameters_do_not_borrow_package_identity(tmp_path, run_connector, body):
    source = 'package main\nimport "github.com/tmc/langchaingo/agents"\n' + body + "\n"
    assert not _agent(_scan(tmp_path, run_connector, "main.go", source), "framework.langchaingo")


def test_go_llms_import_does_not_bind_unrelated_agents_receiver(tmp_path, run_connector):
    source = (
        'package main\nimport "github.com/tmc/langchaingo/llms"\n'
        "func run() { agents := Queue{}; agents.NewExecutor() }\n"
    )
    findings = _scan(tmp_path, run_connector, "main.go", source)
    assert not _agent(findings, "framework.langchaingo")
    assert findings[0].capabilities == []


def test_go_block_shadow_is_confined_to_its_scope(tmp_path, run_connector):
    source = (
        'package main\nimport "github.com/tmc/langchaingo/agents"\n'
        "func run() { { agents := Queue{}; agents.NewExecutor() }; agents.NewExecutor(ctx, model) }\n"
    )
    assert _agent(_scan(tmp_path, run_connector, "main.go", source), "framework.langchaingo")


@pytest.mark.parametrize("condition", ["if (false)", "if (ready)", "while (false)", "while (ready)"])
def test_dotnet_unbraced_conditional_writes_do_not_establish_tools(tmp_path, run_connector, condition):
    body = (
        CS_CLIENT
        + "var options = new ChatOptions(); "
        + condition
        + " options = new ChatOptions { Tools = [weather] }; "
        + CS_REQUEST
    )
    assert not _agent(
        _scan(tmp_path, run_connector, "App.cs", _cs(body)), "framework.microsoft-extensions-ai"
    )


@pytest.mark.parametrize("body", ["if (false) " + CS_REQUEST, "while (false) { " + CS_REQUEST + " }"])
def test_dotnet_literal_false_dispatch_cannot_establish_agent(tmp_path, run_connector, body):
    source = _cs(CS_CLIENT + CS_OPTIONS + body)
    assert not _agent(_scan(tmp_path, run_connector, "App.cs", source), "framework.microsoft-extensions-ai")


@pytest.mark.parametrize("budget", ["MAX_TOKENS", "MAX_DEPTH"])
def test_polyglot_proof_budget_exhaustion_marks_scan_incomplete(tmp_path, run_connector, monkeypatch, budget):
    monkeypatch.setattr(polyglot_bindings, budget, 1)
    source = (
        'package main\nimport "github.com/tmc/langchaingo/agents"\n'
        "func run() { agents.NewExecutor(ctx, model) }\n"
    )
    (tmp_path / "main.go").write_text(source)
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete
    assert any("budget exceeded" in message for message in ctx.stats.errors)


@pytest.mark.parametrize(
    "filename,signature,present",
    [
        ("go_agent_alias.go", "framework.langchaingo", True),
        ("go_unrelated_receiver.go", "framework.langchaingo", False),
        ("dotnet_function_definition.cs", "framework.microsoft-extensions-ai", False),
        ("dotnet_function_invocation.cs", "framework.microsoft-extensions-ai", True),
    ],
)
def test_polyglot_file_backed_agent_provenance(
    tmp_path, fixtures, run_connector, filename, signature, present
):
    source = (fixtures / "polyglot_provenance" / filename).read_text()
    findings = _scan(tmp_path, run_connector, filename, source)
    assert bool(_agent(findings, signature)) is present
    assert len(findings) == 1
    assert findings[0].capabilities == (["tool-use"] if present else [])
