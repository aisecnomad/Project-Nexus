from __future__ import annotations

import json
from pathlib import Path

from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.code.filesystem import FilesystemConnector, _nearest_root
from shadowscan.models import Kind
from shadowscan.signatures import SignatureIndex
from shadowscan.signatures.loader import signature_from_dict


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
    assert {"framework.langgraph", "framework.langchain", "protocol.mcp", "observability.langsmith"} <= set(
        research.frameworks
    )
    assert {"provider.openai", "provider.anthropic"} <= set(research.model_providers)
    assert {"tool-use", "code-exec", "browsing", "memory"} <= set(research.capabilities)
    assert research.owner == "@acme/data-science"  # CODEOWNERS
    support = projects["services/support-bot"]
    assert "framework.vercel-ai-sdk" in support.frameworks and "protocol.mcp" in support.frameworks
    root = projects["."]
    assert {
        "framework.microsoft-agent-framework",
        "framework.langchain4j",
        "framework.spring-ai",
        "framework.langchaingo",
    } <= set(root.frameworks)
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
        assert "sk-proj-3OoFmQTsHfOvesPLUXvRXpfToFF2XPOcdJ2kMQJ2g0" not in (
            e.description + (e.snippet or "")
        ), "secret must be redacted"

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
    (tmp_path / "bot.py").write_text(
        "from strands import Agent\nfrom strands_tools import shell\nagent = Agent(model='us.anthropic.claude-3-7-sonnet', tools=[shell])\nagent('deploy')\n"
    )
    findings, _ = run_connector("code.filesystem", path=str(tmp_path))
    f = findings[0]
    assert f.kind == Kind.AGENT and "framework.aws-strands" in f.frameworks and "code-exec" in f.capabilities


def test_project_root_walk_uses_active_ancestors_for_nested_and_wide_repos(tmp_path: Path, index):
    for relative in ("first", "first/nested", "second"):
        project = tmp_path / relative
        project.mkdir(parents=True, exist_ok=True)
        (project / "pyproject.toml").write_text("[project]\nname='example'\n")
        (project / "bot.py").write_text("from langchain import agents\n")
    files = FilesystemConnector(ConnectorContext(config={"path": str(tmp_path)}, index=index))._iter_files(
        tmp_path
    )
    assigned = {rel: project for rel, _, project in files if rel.endswith("bot.py")}
    assert assigned == {
        "first/bot.py": "first",
        "first/nested/bot.py": "first/nested",
        "second/bot.py": "second",
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
    (tmp_path / ".codex" / "config.toml").write_text(
        '[mcp_servers.fs]\ncommand = "npx"\nargs = ["-y", "@modelcontextprotocol/server-filesystem"]\n'
    )
    (tmp_path / ".vscode").mkdir()
    (tmp_path / ".vscode" / "mcp.json").write_text(
        json.dumps({"servers": {"remote": {"type": "http", "url": "http://tools.internal:8080/mcp"}}})
    )
    findings, _ = run_connector("code.filesystem", path=str(tmp_path))
    mcp = {f.metadata["path"]: f for f in findings if f.kind == Kind.MCP_SERVER}
    assert mcp[".codex/config.toml"].metadata["client"] == "OpenAI Codex"
    assert mcp[".vscode/mcp.json"].metadata["servers"][0]["url"].startswith("http://")


def test_same_text_from_distinct_signals_retains_agent_capabilities(tmp_path):
    index = SignatureIndex(
        [
            signature_from_dict(
                {
                    "id": "custom.agent",
                    "category": "framework",
                    "signals": [
                        {
                            "type": "import",
                            "languages": ["python"],
                            "patterns": [r"^from custom_sdk import execute_agent\b"],
                            "weight": 0.8,
                        },
                        {"type": "code", "patterns": [r"execute_agent\("], "weight": 0.5},
                        {
                            "type": "code",
                            "patterns": [r"execute_agent\("],
                            "weight": 0.95,
                            "agent_indicator": True,
                            "capabilities": ["code-exec"],
                        },
                    ],
                }
            )
        ]
    )
    (tmp_path / "agent.py").write_text("from custom_sdk import execute_agent\nexecute_agent()\n")
    context = ConnectorContext(config={"path": str(tmp_path), "use_git": False}, index=index)
    findings = FilesystemConnector(context).run()
    project = next(f for f in findings if f.resource_type == "project")
    assert project.kind == Kind.AGENT
    assert "code-exec" in project.capabilities
    code_evidence = [e for e in project.evidence if e.signal == "code:custom.agent"]
    assert len(code_evidence) == 2
    assert {e.weight for e in code_evidence} == {0.5, 0.95}


SECRET = "sk-proj-aP9rVv3qN4zY7bC2hJ8Lm5Qw6Dt0KsX1eR7uT4p"


def _scan(index, root: Path, **config):
    ctx = ConnectorContext(config={"path": str(root), **config}, index=index)
    return FilesystemConnector(ctx).run(), ctx


def test_directory_exclusion_names_do_not_skip_files(tmp_path, index):
    (tmp_path / "build").write_text(f"#!/bin/sh\nexport OPENAI_API_KEY={SECRET}\n")
    for config in ({}, {"exclude": ["*.log"]}):
        findings, ctx = _scan(index, tmp_path, **config)
        assert any(f.kind == Kind.SECRET for f in findings) and ctx.stats.objects_examined == 1
    (tmp_path / "build").unlink()
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "out.py").write_text(f"KEY = '{SECRET}'\n")
    findings, _ = _scan(index, tmp_path)
    assert not findings, "the build directory itself is still excluded"


def _run(index, root, **config):
    ctx = ConnectorContext(config={"path": str(root), "use_git": False, **config}, index=index)
    return FilesystemConnector(ctx).run(), ctx


def test_duplicate_manifest_and_text_observations_count_once(tmp_path, index):
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\nENV OPENAI_API_KEY=\n")
    findings, _ = _run(index, tmp_path)
    project = next(f for f in findings if f.resource_type == "project")
    env_evidence = [e for e in project.evidence if e.signal == "env:provider.openai"]
    assert len(env_evidence) == 1
    assert project.confidence < 0.85  # a single mention is not a confirmed agent
    (tmp_path / "Dockerfile").unlink()
    (tmp_path / ".env").write_text("OPENAI_API_KEY=sk-proj-kLKFlNfzW2mTofMpnx1qOu7fTm9F8IRv6iKzoC2h\n")
    findings, _ = _run(index, tmp_path)
    secret = next(f for f in findings if f.kind == Kind.SECRET)
    assert secret.metadata["count"] == 1 and len(secret.evidence) == 1
