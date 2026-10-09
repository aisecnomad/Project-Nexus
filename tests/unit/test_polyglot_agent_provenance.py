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
    ],
)
def test_dotnet_tool_definitions_and_unconfigured_clients_are_usage(tmp_path, run_connector, body):
    findings = _scan(tmp_path, run_connector, "App.cs", _cs(body))
    assert not _agent(findings, "framework.microsoft-extensions-ai")
    assert all(not finding.capabilities for finding in findings)


MEAI_PROJECT = (
    '<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup><ImplicitUsings>enable</ImplicitUsings>'
    '</PropertyGroup><ItemGroup><PackageReference Include="Microsoft.Extensions.AI" Version="9.5.0" />'
    "</ItemGroup></Project>\n"
)
MEAI_DI_PROGRAM = (
    "var builder = WebApplication.CreateBuilder(args);\n"
    'builder.Services.AddChatClient(new OpenAIClient(key).GetChatClient("gpt-4o-mini").AsIChatClient())\n'
    "    .UseFunctionInvocation();\n"
    "builder.Services.AddSingleton<WeatherAgent>();\n"
    "builder.Build().Run();\n"
)
MEAI_DI_AGENT = (
    "using Microsoft.Extensions.AI;\n"
    "public class WeatherAgent(IChatClient chatClient)\n{\n"
    "    public async Task<string> Ask(string q)\n    {\n"
    "        var options = new ChatOptions { Tools = [AIFunctionFactory.Create(GetWeather)] };\n"
    "        return (await chatClient.GetResponseAsync(q, options)).Text;\n"
    "    }\n"
    '    static string GetWeather(string city) => "sunny";\n}\n'
)
MEAI_CONSOLE = (
    "using Microsoft.Extensions.AI;\n"
    'IChatClient client = new OllamaChatClient(new Uri("http://localhost:11434"), "llama3.1")\n'
    "    .AsBuilder().UseFunctionInvocation().Build();\n"
    "ChatOptions options = new() { Tools = [AIFunctionFactory.Create(GetWeather)] };\n"
    'Console.WriteLine(await client.GetResponseAsync("Weather in Paris?", options));\n'
    'static string GetWeather(string city) => "sunny";\n'
)


@pytest.mark.parametrize(
    "files",
    [
        # DI registration with an injected client; Program.cs relies on ImplicitUsings.
        {"App.csproj": MEAI_PROJECT, "Program.cs": MEAI_DI_PROGRAM, "WeatherAgent.cs": MEAI_DI_AGENT},
        {
            "Program.cs": "using Microsoft.Extensions.AI;\n" + MEAI_DI_PROGRAM,
            "WeatherAgent.cs": MEAI_DI_AGENT,
        },
        # Provider constructor chains and target-typed options from the SDK documentation.
        {"Program.cs": MEAI_CONSOLE},
        {"App.cs": _cs("var client = inner.AsBuilder().UseFunctionInvocation().Build();")},
    ],
)
def test_dotnet_function_invocation_middleware_is_a_corroborated_agent_indicator(
    tmp_path, run_connector, files
):
    # UseFunctionInvocation opts every response through the pipeline into the
    # model-directed tool loop, including clients that DI injects elsewhere,
    # which the bounded per-file proof cannot follow.
    for name, source in files.items():
        (tmp_path / name).write_text(source)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False)
    assert not ctx.stats.incomplete, ctx.stats.errors
    agents = _agent(findings, "framework.microsoft-extensions-ai")
    assert len(agents) == 1 and agents[0].capabilities == ["tool-use"]


def test_dotnet_function_invocation_middleware_requires_library_corroboration(tmp_path, run_connector):
    findings = _scan(tmp_path, run_connector, "Program.cs", MEAI_DI_PROGRAM)
    assert not _agent(findings, "framework.microsoft-extensions-ai")
    assert all(not finding.capabilities for finding in findings)


@pytest.mark.parametrize(
    "files",
    [
        {
            "Program.cs": "using Microsoft.Extensions.AI;\n"
            "var builder = WebApplication.CreateBuilder(args);\n"
            "builder.Services.AddSingleton<IChatClient>(sp => new FunctionInvokingChatClient(inner));\n"
            "builder.Build().Run();\n",
            "WeatherAgent.cs": MEAI_DI_AGENT,
        },
        {
            "Helper.cs": "using Microsoft.Extensions.AI;\npublic class Helper\n{\n"
            "    private readonly IChatClient _client;\n    private readonly ChatOptions _options;\n"
            "    public Helper(IChatClient inner)\n    {\n"
            "        _client = new FunctionInvokingChatClient(inner);\n"
            "        _options = new ChatOptions { Tools = [AIFunctionFactory.Create(GetWeather)] };\n"
            "    }\n"
            "    public async Task<string> Ask(string q) => (await _client.GetResponseAsync(q, _options)).Text;\n"
            '    static string GetWeather(string city) => "sunny";\n}\n',
        },
    ],
)
def test_dotnet_explicit_invoker_in_di_or_fields_is_documented_usage(tmp_path, run_connector, files):
    # The explicit client type is not a lexical indicator, since it would override
    # the per-file proof's rejections. Registered through DI or held in fields,
    # it is beyond that proof; docs/connectors/code.md documents this as usage.
    files = {"App.csproj": MEAI_PROJECT, **files}
    for name, source in files.items():
        (tmp_path / name).write_text(source)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False)
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert not _agent(findings, "framework.microsoft-extensions-ai")
    assert any("framework.microsoft-extensions-ai" in finding.frameworks for finding in findings)


def test_dotnet_large_file_without_the_sdk_namespace_stays_complete(tmp_path, run_connector):
    # WebRequest.GetResponseAsync shares the SDK's method name. A file that never
    # names Microsoft.Extensions.AI cannot bind the proof, so it must not spend
    # the proof's token budget and turn an ordinary .NET scan incomplete.
    statement = "total += Compute(request.Alpha, request.Beta, {}) * Scale(request.Gamma, request.Delta);\n"
    body = (
        "".join(statement.format(i) for i in range(2600)) + "using var response = await r.GetResponseAsync();"
    )
    source = _cs(body, "WebRequest r, Request request", "using System.Net;")
    assert source.count("\n") > 2500
    assert len(polyglot_bindings._TOKEN.findall(source)) > polyglot_bindings.MAX_TOKENS
    assert not _agent(_scan(tmp_path, run_connector, "Big.cs", source), "framework.microsoft-extensions-ai")


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


@pytest.mark.parametrize(
    "body",
    [
        CS_CLIENT + "ChatOptions options = new() { Tools = [weather] }; " + CS_REQUEST,
        CS_CLIENT
        + "Microsoft.Extensions.AI.ChatOptions options = new() { Tools = [weather] }; "
        + CS_REQUEST,
        CS_CLIENT + 'await client.GetResponseAsync("weather", new() { Tools = [weather] }); ',
        CS_CLIENT + 'await client.GetResponseAsync("weather", options: new() { Tools = [weather] }); ',
        "FunctionInvokingChatClient client = new(inner); " + CS_OPTIONS + CS_REQUEST,
    ],
)
def test_dotnet_target_typed_options_bind_tools(tmp_path, run_connector, body):
    # The SDK documentation declares ChatOptions with target-typed new().
    agents = _agent(_scan(tmp_path, run_connector, "App.cs", _cs(body)), "framework.microsoft-extensions-ai")
    assert len(agents) == 1 and agents[0].capabilities == ["tool-use"]


@pytest.mark.parametrize(
    "body",
    [
        CS_CLIENT + "ChatOptions options = new(); " + CS_REQUEST,
        CS_CLIENT + "ChatOptions options = new() { Tools = [] }; " + CS_REQUEST,
        CS_CLIENT
        + "ChatOptions options = new() { Tools = [weather], ToolMode = ChatToolMode.None }; "
        + CS_REQUEST,
        CS_CLIENT + "Settings options = new() { Tools = [weather] }; " + CS_REQUEST,
        CS_CLIENT + "var options = new() { Tools = [weather] }; " + CS_REQUEST,
        CS_CLIENT + 'await client.GetResponseAsync("weather", new() { Tools = [] }); ',
        CS_CLIENT + "await client.GetResponseAsync(new() { Tools = [weather] }); ",
    ],
)
def test_dotnet_target_typed_options_need_the_sdk_type_and_tools(tmp_path, run_connector, body):
    findings = _scan(tmp_path, run_connector, "App.cs", _cs(body))
    assert not _agent(findings, "framework.microsoft-extensions-ai")


def test_dotnet_target_typed_lookalike_options_do_not_borrow_sdk_identity(tmp_path, run_connector):
    body = CS_CLIENT + "ChatOptions options = new() { Tools = [weather] }; " + CS_REQUEST
    source = _cs(body) + "class ChatOptions { public object[] Tools; }\n"
    assert not _agent(_scan(tmp_path, run_connector, "App.cs", source), "framework.microsoft-extensions-ai")


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


GO_FUNC_TYPES = [
    "type Hook func(int)",
    "type Option func(*config)",
    "var hook func(int) error",
    # Results that end in a struct or interface literal close with "}".
    "type Factory func() interface{}",
    "type Factory func() struct{}",
    "type Factory func() map[string]interface{}",
    "type Factory func() interface {\n\tGet() int\n}",
]


@pytest.mark.parametrize("declaration", GO_FUNC_TYPES)
@pytest.mark.parametrize(
    "function",
    [
        "func run(agents Queue) { agents.NewExecutor() }",
        "func run(\n\tagents Queue,\n) {\n\tagents.NewExecutor()\n}",
    ],
)
def test_go_parameter_shadow_is_read_from_its_own_header(tmp_path, run_connector, declaration, function):
    # A preceding function type ends at its newline; its func keyword is not
    # the header whose parameter list shadows the imported package.
    source = (
        'package main\nimport "github.com/tmc/langchaingo/agents"\n' + declaration + "\n" + function + "\n"
    )
    assert not _agent(_scan(tmp_path, run_connector, "main.go", source), "framework.langchaingo")


@pytest.mark.parametrize("declaration", GO_FUNC_TYPES)
def test_go_preceding_function_types_keep_unshadowed_package_proof(tmp_path, run_connector, declaration):
    source = (
        'package main\nimport "github.com/tmc/langchaingo/agents"\n'
        + declaration
        + "\nfunc run(queue Queue) { agents.NewExecutor(ctx, model) }\n"
    )
    assert _agent(_scan(tmp_path, run_connector, "main.go", source), "framework.langchaingo")


@pytest.mark.parametrize(
    "declaration",
    [
        "type Hook func(agents int)",
        "type Hook func(agents int) interface{}",
        "type Hook func(agents int) struct{}",
        "type Hook func(agents []string) map[string]interface{}",
        "type Hook func(agents int) interface {\n\tGet() int\n}",
    ],
)
def test_go_preceding_function_type_parameters_do_not_shadow_the_next_body(
    tmp_path, run_connector, declaration
):
    # The function type's own parameter is not in scope in the next function.
    source = (
        'package main\nimport "github.com/tmc/langchaingo/agents"\n'
        + declaration
        + "\nfunc run() {\n\texecutor := agents.NewExecutor(agent)\n\t_ = executor\n}\n"
    )
    assert _agent(_scan(tmp_path, run_connector, "main.go", source), "framework.langchaingo")


@pytest.mark.parametrize(
    "function, shadowed",
    [
        ("func run(cfg struct {\n\tA int\n}, agents Queue) {\n\tagents.NewExecutor()\n}", True),
        ("func run(agents Queue) interface {\n\tGet() int\n} {\n\tagents.NewExecutor()\n}", True),
        ("func run(cfg struct {\n\tA int\n}) {\n\tagents.NewExecutor(ctx, model)\n}", False),
    ],
)
def test_go_headers_spanning_struct_and_interface_literals_are_read_whole(
    tmp_path, run_connector, function, shadowed
):
    source = (
        'package main\nimport "github.com/tmc/langchaingo/agents"\n'
        "type Factory func() interface{}\n" + function + "\n"
    )
    agents = _agent(_scan(tmp_path, run_connector, "main.go", source), "framework.langchaingo")
    assert bool(agents) != shadowed


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
