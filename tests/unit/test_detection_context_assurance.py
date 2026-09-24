"""Evidence must come from executable code or structurally valid configuration."""

from __future__ import annotations

import json
from pathlib import Path

from shadowscan.connectors.code.manifests import parse_pom
from shadowscan.models import Kind


def test_generic_server_filename_does_not_confirm_mcp(tmp_path: Path, run_connector, index):
    (tmp_path / "server.json").write_text(json.dumps({"name": "ordinary web service"}))
    assert not [m for m in index.match_file("server.json") if m.signature_id == "protocol.mcp"]
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert not [f for f in findings if "protocol.mcp" in f.frameworks or f.kind == Kind.MCP_SERVER]

    (tmp_path / "server.json").write_text(json.dumps({
        "name": "ordinary web service",
        "remotes": [{"url": "https://replica.example.test"}],
    }))
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert not [f for f in findings if "protocol.mcp" in f.frameworks or f.kind == Kind.MCP_SERVER]


def test_mcp_registry_manifest_requires_structural_package_or_remote(tmp_path: Path, run_connector):
    (tmp_path / "server.json").write_text(json.dumps({
        "name": "io.github.acme/tools",
        "packages": [{"registryType": "npm", "identifier": "@acme/mcp-tools"}],
    }))
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    mcp = [f for f in findings if f.kind == Kind.MCP_SERVER]
    assert len(mcp) == 1
    assert mcp[0].metadata["servers"][0]["name"] == "io.github.acme/tools"

    (tmp_path / "server.json").write_text(json.dumps({
        "name": "io.github.acme/tools",
        "remotes": [{"type": "streamable-http", "url": "https://tools.example.test/mcp"}],
    }))
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert [f.metadata["servers"][0]["url"] for f in findings if f.kind == Kind.MCP_SERVER] == [
        "https://tools.example.test/mcp"
    ]


def test_readme_examples_do_not_confirm_framework_or_agent(tmp_path: Path, run_connector):
    (tmp_path / "README.md").write_text(
        "Example: create_agent(model, tools)\n"
        "```python\nfrom langchain.agents import create_agent\n"
        "agent = create_agent(model, tools)\n```\n"
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert not [f for f in findings if f.kind == Kind.AGENT or "framework.langchain" in f.frameworks]

    (tmp_path / "agent.py").write_text("from langchain.agents import create_agent\nagent = create_agent(model, tools)\n")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert [f for f in findings if f.kind == Kind.AGENT and "framework.langchain" in f.frameworks]


def test_maven_comments_are_neither_dependencies_nor_code(tmp_path: Path, run_connector):
    pom = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <!-- <dependency><groupId>dev.langchain4j</groupId>
       <artifactId>langchain4j</artifactId></dependency>
       create_agent(model, tools) -->
  <dependencies><dependency><groupId>org.example</groupId>
    <artifactId>web-service</artifactId></dependency></dependencies>
</project>"""
    parsed = parse_pom(pom)
    assert [(d.ecosystem, d.name) for d in parsed.deps] == [("maven", "org.example:web-service")]
    assert not parsed.errors
    (tmp_path / "pom.xml").write_text(pom)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert not [f for f in findings if "framework.langchain4j" in f.frameworks or "framework.langchain" in f.frameworks]


def test_pom_cdata_examples_do_not_confirm_agent_but_active_dependencies_do(tmp_path: Path, run_connector):
    path = tmp_path / "pom.xml"
    description = "<description><![CDATA[Example: create_agent(model, tools)]]></description>"
    path.write_text(f"<project>{description}</project>")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert not [f for f in findings if f.kind == Kind.AGENT or "framework.langchain" in f.frameworks]

    path.write_text(
        f"<project>{description}<dependencies><dependency>"
        "<groupId>dev.langchain4j</groupId><artifactId>langchain4j</artifactId>"
        "</dependency></dependencies></project>"
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert [f for f in findings if "framework.langchain4j" in f.frameworks]
    assert not [f for f in findings if "framework.langchain" in f.frameworks]


def test_pom_xml_entities_fail_closed():
    result = parse_pom(
        '<!DOCTYPE project [<!ENTITY x "dev.langchain4j">]>'
        '<project><dependencies><dependency><groupId>&x;</groupId>'
        '<artifactId>langchain4j</artifactId></dependency></dependencies></project>'
    )
    assert not result.deps
    assert result.errors
