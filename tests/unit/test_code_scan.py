from __future__ import annotations

import json
from pathlib import Path

from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.code.filesystem import FilesystemConnector, _nearest_root
from shadowscan.models import Kind


def _by_kind(findings):
    out = {}
    for f in findings:
        out.setdefault(f.kind, []).append(f)
    return out


def test_sample_repo_scan(run_connector, fixtures):
    findings, ctx = run_connector("code.filesystem", path=str(fixtures / "sample_repo"), label="fixture")
    assert not ctx.stats.errors
    kinds = _by_kind(findings)
    projects = {f.metadata["path"]: f for f in kinds[Kind.AGENT] if f.resource_type == "project"}
    research = projects["services/research-agent"]
    assert {"framework.langgraph", "framework.langchain", "protocol.mcp", "observability.langsmith"} <= set(research.frameworks)
    assert {"provider.openai", "provider.anthropic"} <= set(research.model_providers)
    assert {"tool-use", "code-exec", "browsing", "memory"} <= set(research.capabilities)
    assert research.owner == "@acme/data-science"  # CODEOWNERS
    support = projects["services/support-bot"]
    assert "framework.vercel-ai-sdk" in support.frameworks and "protocol.mcp" in support.frameworks
    root = projects["."]
    assert {"framework.microsoft-agent-framework", "framework.langchain4j", "framework.spring-ai", "framework.langchaingo"} <= set(root.frameworks)
    # notebook code cells are scanned
    assert "framework.crewai" in root.frameworks

    mcp = {f.metadata["path"]: f for f in kinds[Kind.MCP_SERVER]}
    assert set(mcp) == {".mcp.json", ".cursor/mcp.json"}
    servers = {s["name"]: s for s in mcp[".mcp.json"].metadata["servers"]}
    assert servers["github"]["secrets_inline"] is True
    assert servers["zapier"]["transport"] == "http"
    assert "inline-secrets" in mcp[".mcp.json"].tags
    assert mcp[".cursor/mcp.json"].metadata["client"] == "Cursor"

    cfg = kinds[Kind.AGENT_CONFIG]
    claude = next(f for f in cfg if "coding-agent.claude-code" in f.frameworks)
    assert ".claude/agents/reviewer.md" in claude.metadata["files"]
    assert claude.metadata["agent_definitions"][0]["name"] == "code-reviewer"
    assert "autonomous" in claude.capabilities  # bypassPermissions / Bash(*)

    secrets = kinds[Kind.SECRET]
    assert len(secrets) == 1 and secrets[0].metadata["path"] == "services/research-agent/app/config.py"
    assert {"provider.openai", "provider.anthropic"} <= set(secrets[0].model_providers)
    for e in secrets[0].evidence:
        assert "sk-proj-abcdefghijklmnopqrstuvwxyz" not in (e.description + (e.snippet or "")), "secret must be redacted"

    infra = {f.metadata["path"]: f for f in kinds[Kind.INFRA]}
    assert "cloud.aws-bedrock-agents" in infra["infra/terraform/bedrock.tf"].frameworks
    assert "ops-provisioning-04" in infra["infra/terraform/bedrock.tf"].metadata["names"]
    assert {"platform.litellm", "platform.n8n"} <= set(infra["infra/docker-compose.yml"].frameworks)

    cards = [f for f in kinds[Kind.AGENT] if f.resource_type == "agent-manifest"]
    a2a = next(f for f in cards if "protocol.a2a" in f.frameworks)
    assert a2a.metadata["agent_card"]["skills"] == ["Request quote", "Issue purchase order"]
    assert "no-auth-declared" in a2a.tags
    wf = kinds[Kind.WORKFLOW]
    assert len(wf) == 1 and "platform.n8n" in wf[0].frameworks


def test_scan_ignores_noise_dirs_and_binary(tmp_path: Path, run_connector):
    (tmp_path / "node_modules" / "langchain").mkdir(parents=True)
    (tmp_path / "node_modules" / "langchain" / "index.js").write_text("import { OpenAI } from 'openai'")
    (tmp_path / "app.bin").write_bytes(b"\x00\x01" + b"from langchain import x" * 10)
    (tmp_path / "README.md").write_text("plain readme")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path))
    assert findings == [] and not ctx.stats.errors


def test_scan_detects_frameworks_from_source_only(tmp_path: Path, run_connector):
    (tmp_path / "bot.py").write_text("from strands import Agent\nfrom strands_tools import shell\nagent = Agent(model='us.anthropic.claude-3-7-sonnet', tools=[shell])\nagent('deploy')\n")
    findings, _ = run_connector("code.filesystem", path=str(tmp_path))
    f = findings[0]
    assert f.kind == Kind.AGENT and "framework.aws-strands" in f.frameworks and "code-exec" in f.capabilities


def test_project_root_walk_uses_active_ancestors_for_nested_and_wide_repos(tmp_path: Path, index):
    for relative in ("first", "first/nested", "second"):
        project = tmp_path / relative
        project.mkdir(parents=True, exist_ok=True)
        (project / "pyproject.toml").write_text("[project]\nname='example'\n")
        (project / "bot.py").write_text("from langchain import agents\n")
    files = FilesystemConnector(ConnectorContext(config={"path": str(tmp_path)}, index=index))._iter_files(tmp_path)
    assigned = {rel: project for rel, _, project in files if rel.endswith("bot.py")}
    assert assigned == {
        "first/bot.py": "first", "first/nested/bot.py": "first/nested", "second/bot.py": "second",
    }

    active = ["."]
    for number in range(4000):
        sibling = f"repo-{number}"
        assert _nearest_root(sibling, active) == "."
        active.append(sibling)
        assert _nearest_root(f"{sibling}/src", active) == sibling
        assert len(active) == 2  # completed sibling roots must not accumulate


def test_mcp_toml_and_vscode_variants(tmp_path: Path, run_connector):
    (tmp_path / ".codex").mkdir()
    (tmp_path / ".codex" / "config.toml").write_text('[mcp_servers.fs]\ncommand = "npx"\nargs = ["-y", "@modelcontextprotocol/server-filesystem"]\n')
    (tmp_path / ".vscode").mkdir()
    (tmp_path / ".vscode" / "mcp.json").write_text(json.dumps({"servers": {"remote": {"type": "http", "url": "http://tools.internal:8080/mcp"}}}))
    findings, _ = run_connector("code.filesystem", path=str(tmp_path))
    mcp = {f.metadata["path"]: f for f in findings if f.kind == Kind.MCP_SERVER}
    assert mcp[".codex/config.toml"].metadata["client"] == "OpenAI Codex"
    assert mcp[".vscode/mcp.json"].metadata["servers"][0]["url"].startswith("http://")
