"""Regressions from the 2026-10-08 head-to-head benchmark (archive/reviews/head-to-head-2026-10-08.md).

Typing precision: classic-ML tooling is not an LLM provider, a Spring AI builder
chain that registers tools is an agent, and a project that serves tools over MCP
carries the mcp-server capability and server metadata rather than reading as LLM usage.
"""

from __future__ import annotations

from pathlib import Path

from shadowscan.models import Kind

GO_MOD = "module example.com/ops-tools\n\ngo 1.23\n\nrequire github.com/mark3labs/mcp-go v0.40.0\n"
GO_SERVER = """package main

import (
\t"context"
\t"os/exec"

\t"github.com/mark3labs/mcp-go/mcp"
\t"github.com/mark3labs/mcp-go/server"
)

func main() {
\ts := server.NewMCPServer("ops-tools", "1.0.0")
\trestart := mcp.NewTool("restart_service", mcp.WithDescription("Restart a service"))
\ts.AddTool(restart, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
\t\tout, _ := exec.CommandContext(ctx, "systemctl", "restart", "x").CombinedOutput()
\t\treturn mcp.NewToolResultText(string(out)), nil
\t})
\t_ = server.ServeStdio(s)
}
"""
POM = (
    "<project><dependencies><dependency><groupId>org.springframework.ai</groupId>"
    "<artifactId>spring-ai-starter-model-openai</artifactId><version>1.0.1</version>"
    "</dependency></dependencies></project>\n"
)
SPRING_CHAIN = """package com.acme;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.client.advisor.MessageChatMemoryAdvisor;
import org.springframework.ai.tool.annotation.Tool;

public class AssistantService {
    private final ChatClient chatClient;

    public AssistantService(ChatClient.Builder builder) {
        this.chatClient = builder
            .defaultSystem("You are the finance desk assistant. Use tools to look up invoices.")
            .defaultAdvisors(MessageChatMemoryAdvisor.builder(memory).build())
            .defaultTools(new InvoiceTools())
            .build();
    }

    static class InvoiceTools {
        @Tool(description = "Approve an invoice for payment by id")
        String approveInvoice(String invoiceId) { return "approved " + invoiceId; }
    }
}
"""
TS_CLIENT = """import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const transport = new StdioClientTransport({ command: "npx", args: ["-y", "@acme/inventory-mcp"] });
const client = new Client({ name: "web-assistant", version: "1.0.0" });
await client.connect(transport);
const { tools } = await client.listTools();
"""


def _project(findings):
    return next(f for f in findings if f.resource_type == "project")


def test_mlflow_tracking_alone_is_not_a_model_provider(tmp_path: Path, run_connector):
    (tmp_path / "requirements.txt").write_text("mlflow==3.4.0\ntorch==2.8.0\npandas==2.3.2\n")
    (tmp_path / "train.py").write_text(
        "import mlflow\nimport torch\n\nwith mlflow.start_run():\n    mlflow.log_metric('loss', 0.1)\n"
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert not [f for f in findings if "provider.databricks" in f.model_providers]
    assert not [f for f in findings if f.resource_type == "project"]


def test_mlflow_llm_flavor_still_establishes_databricks(tmp_path: Path, run_connector):
    (tmp_path / "deploy.py").write_text(
        "import mlflow\nfrom databricks import agents\n\nmlflow.langchain.log_model(chain, 'chain')\n"
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert "provider.databricks" in _project(findings).model_providers


def test_spring_ai_builder_chain_registering_tools_is_an_agent(tmp_path: Path, run_connector):
    (tmp_path / "pom.xml").write_text(POM)
    src = tmp_path / "src" / "main" / "java" / "com" / "acme"
    src.mkdir(parents=True)
    (src / "AssistantService.java").write_text(SPRING_CHAIN)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    project = _project(findings)
    assert project.kind == Kind.AGENT
    assert "framework.spring-ai" in project.frameworks
    assert "tool-use" in project.capabilities
    assert project.title.startswith("Agent in repository root")


def test_spring_ai_chat_client_without_tools_stays_llm_usage(tmp_path: Path, run_connector):
    (tmp_path / "pom.xml").write_text(POM)
    (tmp_path / "ChatService.java").write_text(
        "import org.springframework.ai.chat.client.ChatClient;\n"
        'public class ChatService { ChatService(ChatClient.Builder b) { b.defaultSystem("Hi").build(); } }\n'
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert _project(findings).kind == Kind.FRAMEWORK_USAGE


def test_go_mcp_server_is_reported_as_an_mcp_server(tmp_path: Path, run_connector):
    (tmp_path / "go.mod").write_text(GO_MOD)
    (tmp_path / "main.go").write_text(GO_SERVER)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    project = _project(findings)
    assert "mcp-server" in project.capabilities
    assert [c["file"] for c in project.metadata["mcp_server"]["constructions"]] == ["main.go"]
    assert project.title.startswith("MCP server in repository root")
    assert "protocol.mcp" in project.frameworks
    assert "code-exec" in project.capabilities
    # A server implementation keeps its project kind and resource identity;
    # Kind.MCP_SERVER stays reserved for MCP configuration inventories.
    assert project.kind != Kind.MCP_SERVER
    assert project.resource_type == "project"


def test_mcp_client_code_is_not_a_server_implementation(tmp_path: Path, run_connector):
    (tmp_path / "package.json").write_text(
        '{"name": "web", "dependencies": {"@modelcontextprotocol/sdk": "^1.18.1"}}\n'
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "client.ts").write_text(TS_CLIENT)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    project = _project(findings)
    assert "mcp-server" not in project.capabilities
    assert "mcp_server" not in project.metadata


def test_mcp_server_idiom_only_in_tests_does_not_type_the_project(tmp_path: Path, run_connector):
    (tmp_path / "go.mod").write_text(GO_MOD)
    (tmp_path / "main.go").write_text(
        'package main\n\nimport "github.com/mark3labs/mcp-go/mcp"\n\nfunc main() { _ = mcp.CallToolRequest{} }\n'
    )
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "server_test.go").write_text(GO_SERVER)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    project = _project(findings)
    assert "mcp-server" not in project.capabilities
    assert "mcp_server" not in project.metadata
