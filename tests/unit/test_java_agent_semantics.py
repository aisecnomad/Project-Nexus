"""JVM chat clients and tool declarations are not necessarily configured agents."""

from __future__ import annotations

from pathlib import Path

import pytest

from shadowscan.models import Kind


@pytest.mark.parametrize(
    ("framework", "import_name", "expression"),
    [
        (
            "framework.spring-ai",
            "org.springframework.ai.chat.client.ChatClient",
            'ChatClient.create(model).prompt("Summarize").call().content()',
        ),
        (
            "framework.spring-ai",
            "org.springframework.ai.chat.client.ChatClient",
            "ChatClient.builder(model).build()",
        ),
        (
            "framework.langchain4j",
            "dev.langchain4j.service.AiServices",
            "AiServices.create(Assistant.class, model)",
        ),
        (
            "framework.langchain4j",
            "dev.langchain4j.service.AiServices",
            "AiServices.builder(Assistant.class).chatModel(model).build()",
        ),
        (
            "framework.langchain4j",
            "dev.langchain4j.agentic.AgenticServices",
            "AgenticServices.agentAction(action)",
        ),
    ],
)
def test_chat_construction_and_agentic_utilities_are_framework_usage(
    tmp_path: Path, run_connector, framework: str, import_name: str, expression: str
):
    (tmp_path / "App.java").write_text(
        f"import {import_name};\nclass App {{ void run() {{ {expression}; }} }}\n"
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert len(findings) == 1
    finding = findings[0]
    assert framework in finding.frameworks
    assert finding.kind == Kind.FRAMEWORK_USAGE
    assert "tool-use" not in finding.capabilities


@pytest.mark.parametrize(
    ("framework", "import_name"),
    [
        ("framework.spring-ai", "org.springframework.ai.tool.annotation.Tool"),
        ("framework.langchain4j", "dev.langchain4j.agent.tool.Tool"),
    ],
)
def test_standalone_tool_declaration_does_not_establish_agent_or_tool_configuration(
    tmp_path: Path, run_connector, framework: str, import_name: str
):
    (tmp_path / "WeatherTools.java").write_text(
        f"import {import_name};\nclass WeatherTools {{\n"
        '  @Tool(description = "Current weather")\n'
        '  String weather() { return "sunny"; }\n}\n'
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert len(findings) == 1
    assert framework in findings[0].frameworks
    assert findings[0].kind == Kind.FRAMEWORK_USAGE
    assert "tool-use" not in findings[0].capabilities


@pytest.mark.parametrize("method", ["agentBuilder", "sequenceBuilder", "createAgenticSystem"])
def test_explicit_agent_factories_preserve_agent_without_inventing_tools(
    tmp_path: Path, run_connector, method: str
):
    (tmp_path / "App.java").write_text(
        "import dev.langchain4j.agentic.AgenticServices;\n"
        f"class App {{ void run() {{ AgenticServices.{method}(Assistant.class); }} }}\n"
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert len(findings) == 1
    assert findings[0].kind == Kind.AGENT
    assert "tool-use" not in findings[0].capabilities


_REGISTERED_CHAINS = [
    (
        "framework.spring-ai",
        "org.springframework.ai.chat.client.ChatClient",
        "ChatClient.builder(model).defaultTools({tools}).build()",
    ),
    (
        "framework.langchain4j",
        "dev.langchain4j.service.AiServices",
        "AiServices.builder(Assistant.class).chatModel(model).tools({tools}).build()",
    ),
]


@pytest.mark.parametrize(("framework", "import_name", "chain"), _REGISTERED_CHAINS)
def test_inline_registered_tools_preserve_tool_using_agent(
    tmp_path: Path, run_connector, framework: str, import_name: str, chain: str
):
    expression = chain.format(tools="new WeatherTools()")
    (tmp_path / "App.java").write_text(
        f"import {import_name};\nclass App {{ void run() {{ {expression}; }} }}\n"
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert len(findings) == 1
    assert framework in findings[0].frameworks
    assert findings[0].kind == Kind.AGENT
    assert "tool-use" in findings[0].capabilities


@pytest.mark.parametrize(("framework", "import_name", "chain"), _REGISTERED_CHAINS)
@pytest.mark.parametrize(
    "tools", ["", "null", "List.of()", "new ArrayList()", "new Object()", "new Object[0]"]
)
def test_empty_null_or_non_tool_registration_does_not_establish_agent(
    tmp_path: Path, run_connector, framework: str, import_name: str, chain: str, tools: str
):
    expression = chain.format(tools=tools)
    (tmp_path / "App.java").write_text(
        f"import {import_name};\nclass App {{ void run() {{ {expression}; }} }}\n"
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert len(findings) == 1
    assert framework in findings[0].frameworks
    assert findings[0].kind == Kind.FRAMEWORK_USAGE
    assert "tool-use" not in findings[0].capabilities


@pytest.mark.parametrize(("framework", "import_name", "chain"), _REGISTERED_CHAINS)
@pytest.mark.parametrize(
    "context", ["// {expression}\n", 'String sample = "{expression}";', "/* {expression} */"]
)
def test_tool_registration_examples_are_inert(
    tmp_path: Path, run_connector, framework: str, import_name: str, chain: str, context: str
):
    expression = chain.format(tools="new WeatherTools()")
    (tmp_path / "App.java").write_text(f"import {import_name};\n" + context.format(expression=expression))
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert len(findings) == 1
    assert framework in findings[0].frameworks
    assert findings[0].kind == Kind.FRAMEWORK_USAGE
    assert "tool-use" not in findings[0].capabilities


@pytest.mark.parametrize(("framework", "import_name", "chain"), _REGISTERED_CHAINS)
def test_unbound_tool_registration_is_only_a_candidate(
    tmp_path: Path, run_connector, framework: str, import_name: str, chain: str
):
    (tmp_path / "App.java").write_text(chain.format(tools="new WeatherTools()") + ";\n")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert len(findings) == 1
    assert framework in findings[0].frameworks
    assert findings[0].kind == Kind.FRAMEWORK_USAGE
    assert "tool-use" not in findings[0].capabilities


_TYPED_RECEIVER = """\
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.tool.annotation.Tool;
class TicketAssistant {
    private ChatClient client;
    @Tool(description = "Look up a ticket")
    public String findTicket(String ticket) { return ticket; }
    String answer(String question) {
        return client.prompt().user(question).tools(this).call().content();
    }
}
"""


@pytest.mark.parametrize("receiver", ["client", "this.client"])
def test_typed_field_registering_same_class_tools_is_an_agent(tmp_path: Path, run_connector, receiver: str):
    (tmp_path / "TicketAssistant.java").write_text(
        _TYPED_RECEIVER.replace("return client.", f"return {receiver}.")
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert len(findings) == 1
    assert findings[0].kind == Kind.AGENT
    assert findings[0].capabilities == ["tool-use"]
    assert any(e.location == "TicketAssistant.java:8" for e in findings[0].evidence)


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("private ChatClient client;", "private OtherClient client;"),
        ("private ChatClient client;", ""),
        ('@Tool(description = "Look up a ticket")', ""),
        ("tools(this)", "tools(null)"),
        ("tools(this)", "tools()"),
        ("tools(this)", "tools(other)"),
        ("String answer(String question)", "String answer(String question, OtherClient client)"),
        ("return client.prompt()", "OtherClient client = other; return client.prompt()"),
        ("return client.prompt()", "OtherClient other = null, client = custom; return client.prompt()"),
        ("String answer(String question)", "String answer(String question, Generic<OtherClient> client)"),
        ("return client.prompt()", "return other.client.prompt()"),
        ("return client.prompt()", "// return client.prompt()"),
        (
            "return client.prompt().user(question).tools(this).call().content();",
            'return "client.prompt().tools(this).call()";',
        ),
        ("class TicketAssistant", "class ChatClient"),
        ("class TicketAssistant", "class TicketAssistant<ChatClient>"),
        (
            "import org.springframework.ai.chat.client.ChatClient;",
            "import org.springframework.ai.chat.client.ChatClient;\nimport local.ChatClient;",
        ),
        (
            "import org.springframework.ai.tool.annotation.Tool;",
            "import org.springframework.ai.tool.annotation.Tool;\nimport local.Tool;",
        ),
        (
            "return client.prompt().user(question).tools(this).call().content();",
            "return new Other() { String answer() { return client.prompt().tools(this).call().content(); } };",
        ),
    ],
)
def test_typed_field_proof_rejects_unbound_shadowed_or_inert_calls(
    tmp_path: Path, run_connector, old: str, new: str
):
    (tmp_path / "TicketAssistant.java").write_text(_TYPED_RECEIVER.replace(old, new))
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert len(findings) == 1
    assert findings[0].kind == Kind.FRAMEWORK_USAGE
    assert "tool-use" not in findings[0].capabilities


def test_tool_annotation_in_other_class_does_not_qualify_typed_receiver(tmp_path: Path, run_connector):
    (tmp_path / "TicketAssistant.java").write_text(
        _TYPED_RECEIVER.replace('@Tool(description = "Look up a ticket")', "")
        + '\nclass Tools { @Tool String lookup() { return "ok"; } }\n'
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert len(findings) == 1
    assert findings[0].kind == Kind.FRAMEWORK_USAGE
    assert "tool-use" not in findings[0].capabilities


def test_java_registration_budget_exhaustion_marks_scan_incomplete(
    tmp_path: Path, run_connector, monkeypatch
):
    from shadowscan.connectors.code import java_semantics

    (tmp_path / "TicketAssistant.java").write_text(_TYPED_RECEIVER)
    monkeypatch.setattr(java_semantics, "_MAX_TOKENS", 32)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert any("Java tool registration token budget exceeded" in error for error in ctx.stats.errors)
    assert not any(finding.kind == Kind.AGENT for finding in findings)


_INJECTED_CONTROLLER = """\
package example;
import org.springframework.ai.chat.client.ChatClient;
class AssistantController {
    private final ChatClient client;
    private final TicketTools ticketTools;
    AssistantController(ChatClient.Builder builder, TicketTools ticketTools) {
        this.client = builder.build();
        this.ticketTools = ticketTools;
    }
    record Request(String message) {}
    String answer(String question) {
        return client.prompt()
            .user(u -> u.text("User {user} asks: {message}").param("user", question).param("message", question))
            .tools(ticketTools)
            .advisors(a -> a.param("conversation", question))
            .call().content();
    }
}
"""
_INJECTED_TOOLS = """\
package example;
import org.springframework.ai.tool.annotation.Tool;
class TicketTools {
    @Tool(description = "Look up a ticket")
    String findTicket(String ticket) { return ticket; }
}
"""


def test_injected_tool_class_is_resolved_across_project_files(tmp_path: Path, run_connector):
    (tmp_path / "Controller.java").write_text(_INJECTED_CONTROLLER)
    (tmp_path / "TicketTools.java").write_text(_INJECTED_TOOLS)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert len(findings) == 1
    assert findings[0].kind == Kind.AGENT
    assert findings[0].capabilities == ["tool-use"]


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("private final TicketTools ticketTools", "private final OtherTools ticketTools"),
        ("this.ticketTools = ticketTools", "this.ticketTools = null"),
        ("tools(ticketTools)", "tools(null)"),
        ("tools(ticketTools)", "tools(List.of())"),
        ("String answer(String question)", "String answer(String question, OtherTools ticketTools)"),
        ("return client.prompt()", "OtherTools ticketTools = other; return client.prompt()"),
        ("return client.prompt()", "Object[] ticketTools = new Object[0]; return client.prompt()"),
        (
            "return client.prompt()",
            "Object other = new Object(), ticketTools = new Object(); return client.prompt()",
        ),
        (
            "return client.prompt()",
            "java.util.List<Object> ticketTools = java.util.List.of(); return client.prompt()",
        ),
        ("String answer(String question)", "String answer(String question, Object[] ticketTools)"),
        ("return client.prompt()", "return (ticketTools) -> client.prompt()"),
        ("return client.prompt()", "return (x, client) -> client.prompt()"),
        (
            "record Request(String message) {}",
            "record Request(String message) {} static class TicketTools {}",
        ),
        ("package example;", "package example;\nimport elsewhere.TicketTools;"),
        ("package example;", "package example;\nimport example.TicketTools;\nimport elsewhere.TicketTools;"),
        ("String answer(String question)", "String answer(String question, OtherClient client)"),
        ("return client.prompt()", "return new Other() { String answer() { return client.prompt()"),
    ],
)
def test_injected_tool_resolution_rejects_unrelated_empty_and_shadowed_objects(
    tmp_path: Path, run_connector, old: str, new: str
):
    source = _INJECTED_CONTROLLER.replace(old, new)
    if "return new Other()" in source:
        source = source.replace(".call().content();", ".call().content(); } };")
    (tmp_path / "Controller.java").write_text(source)
    (tmp_path / "TicketTools.java").write_text(_INJECTED_TOOLS)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert len(findings) == 1
    assert findings[0].kind == Kind.FRAMEWORK_USAGE
    assert "tool-use" not in findings[0].capabilities


@pytest.mark.parametrize(
    "tool_source",
    [
        _INJECTED_TOOLS.replace("package example;", "package elsewhere;"),
        _INJECTED_TOOLS.replace('@Tool(description = "Look up a ticket")', ""),
        _INJECTED_TOOLS.replace("org.springframework.ai.tool.annotation.Tool", "local.Tool"),
    ],
)
def test_injected_tool_resolution_requires_exact_class_and_spring_annotation(
    tmp_path: Path, run_connector, tool_source: str
):
    (tmp_path / "Controller.java").write_text(_INJECTED_CONTROLLER)
    (tmp_path / "TicketTools.java").write_text(tool_source)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert len(findings) == 1
    assert findings[0].kind == Kind.FRAMEWORK_USAGE
    assert "tool-use" not in findings[0].capabilities


def test_test_only_tool_class_does_not_promote_production_registration(tmp_path: Path, run_connector):
    (tmp_path / "Controller.java").write_text(_INJECTED_CONTROLLER)
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "TicketTools.java").write_text(_INJECTED_TOOLS)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert len(findings) == 1
    assert findings[0].kind == Kind.FRAMEWORK_USAGE
    assert "tool-use" not in findings[0].capabilities
