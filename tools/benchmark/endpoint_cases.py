"""Developer-workstation (home directory) case families.

Paths follow each client's documented Linux user-scope location. A case is a
home directory snapshot; tools that inspect ``$HOME`` are run with ``HOME``
pointing at it. Running processes, sockets and installed binaries are out of
scope: a file tree cannot represent them.
"""

from __future__ import annotations

from collections.abc import Callable

from tools.benchmark.common import ANTHROPIC_MODELS, OLLAMA_MODELS, OPENAI_MODELS, Draft, Rand, dump_json
from tools.benchmark.repo_cases import _mcp_servers


def _vscode_ext(rd: Rand, publisher: str, name: str, display: str, root: str = ".vscode") -> dict[str, str]:
    version = f"{rd.randint(0, 3)}.{rd.randint(0, 30)}.{rd.randint(0, 9)}"
    manifest = {
        "name": name,
        "displayName": display,
        "publisher": publisher,
        "version": version,
        "engines": {"vscode": "^1.90.0"},
        "main": "./dist/extension.js",
    }
    return {f"{root}/extensions/{publisher}.{name}-{version}/package.json": dump_json(manifest)}


PLAIN_EXTENSIONS = (
    ("ms-python", "python", "Python"),
    ("esbenp", "prettier-vscode", "Prettier - Code formatter"),
    ("dbaeumer", "vscode-eslint", "ESLint"),
    ("eamodio", "gitlens", "GitLens"),
    ("ms-azuretools", "vscode-docker", "Docker"),
    ("redhat", "vscode-yaml", "YAML"),
    ("golang", "go", "Go"),
    ("hashicorp", "terraform", "HashiCorp Terraform"),
)


def base_home(rd: Rand) -> dict[str, str]:
    """Ordinary developer dotfiles present in every endpoint case."""
    user = rd.choice(("alice", "bilal", "chen", "dana", "eitan", "fatima", "gopal", "hana"))
    files = {
        ".bashrc": "export EDITOR=vim\nalias ll='ls -alF'\n[ -f ~/.fzf.bash ] && source ~/.fzf.bash\n",
        ".profile": 'if [ -d "$HOME/bin" ] ; then\n    PATH="$HOME/bin:$PATH"\nfi\n',
        ".gitconfig": f"[user]\n\tname = {user.capitalize()}\n\temail = {user}@corp.example\n[pull]\n\trebase = true\n",
        ".config/Code/User/settings.json": dump_json(
            {
                "editor.formatOnSave": True,
                "files.trimTrailingWhitespace": True,
                "workbench.colorTheme": "Default Dark+",
            }
        ),
    }
    for ext in rd.sample(PLAIN_EXTENSIONS, rd.randint(1, 4)):
        files.update(_vscode_ext(rd, *ext))
    if rd.chance(0.4):
        files[".npmrc"] = "registry=https://registry.npmjs.org/\nfund=false\n"
    if rd.chance(0.4):
        files[".bash_history"] = "\n".join(
            rd.sample(
                (
                    "git status", "kubectl get pods -n web", "docker compose up -d", "make test",
                    'eval "$(ssh-agent -s)"', "gpg-agent --daemon", "terraform plan", "npm run build",
                ),
                4,
            )
        ) + "\n"  # fmt: skip
    return files


# --------------------------------------------------------------------------
# agent positives


def ep_claude_desktop(rd: Rand) -> Draft:
    cfg = dump_json({"mcpServers": _mcp_servers(rd, rd.randint(1, 3))})
    return Draft(
        "ep-claude-desktop-mcp",
        "agent",
        "easy",
        "Claude Desktop with configured MCP servers.",
        {".config/Claude/claude_desktop_config.json": cfg},
    )


def ep_cursor(rd: Rand) -> Draft:
    return Draft(
        "ep-cursor-mcp",
        "agent",
        "easy",
        "Cursor user MCP servers.",
        {".cursor/mcp.json": dump_json({"mcpServers": _mcp_servers(rd, rd.randint(1, 3))})},
    )


def ep_vscode_mcp(rd: Rand) -> Draft:
    servers = {
        k: {"type": "http" if "url" in v else "stdio", **v}
        for k, v in _mcp_servers(rd, rd.randint(1, 3)).items()
    }
    return Draft(
        "ep-vscode-mcp",
        "agent",
        "medium",
        "VS Code user-profile MCP servers.",
        {".config/Code/User/mcp.json": dump_json({"servers": servers})},
    )


def ep_windsurf(rd: Rand) -> Draft:
    return Draft(
        "ep-windsurf-mcp",
        "agent",
        "medium",
        "Windsurf MCP config.",
        {".codeium/windsurf/mcp_config.json": dump_json({"mcpServers": _mcp_servers(rd, rd.randint(1, 2))})},
    )


def ep_claude_code(rd: Rand) -> Draft:
    files: dict[str, str] = {}
    variant = rd.choice(("mcp", "subagent", "skill"))
    if variant == "mcp":
        files[".claude.json"] = dump_json(
            {"numStartups": rd.randint(3, 400), "mcpServers": _mcp_servers(rd, rd.randint(1, 2))}
        )
    elif variant == "subagent":
        name = rd.ident().replace("_", "-")
        files[f".claude/agents/{name}.md"] = (
            f"---\nname: {name}\ndescription: Reviews pull requests for security issues.\n"
            "tools: Read, Grep, Glob, Bash\n---\n\nYou are a careful reviewer.\n"
        )
        files[".claude/settings.json"] = dump_json({"permissions": {"allow": ["Bash(npm test:*)"]}})
    else:
        name = rd.ident().replace("_", "-")
        files[f".claude/skills/{name}/SKILL.md"] = (
            f"---\nname: {name}\ndescription: Generates release notes from merged PRs.\n---\n\n"
            "Run `git log --merges` and summarise.\n"
        )
    return Draft("ep-claude-code", "agent", "medium", f"Claude Code user config ({variant}).", files)


def ep_gemini_cli(rd: Rand) -> Draft:
    return Draft(
        "ep-gemini-cli",
        "agent",
        "medium",
        "Gemini CLI settings with MCP servers.",
        {
            ".gemini/settings.json": dump_json(
                {"theme": "Default", "mcpServers": _mcp_servers(rd, rd.randint(1, 2))}
            )
        },
    )


def ep_codex(rd: Rand) -> Draft:
    lines = [f'model = "{rd.choice(OPENAI_MODELS)}"', 'approval_policy = "on-request"', ""]
    for name, spec in _mcp_servers(rd, rd.randint(1, 2)).items():
        lines.append(f"[mcp_servers.{name}]")
        if "url" in spec:
            lines.append(f'url = "{spec["url"]}"')
        else:
            args = spec.get("args", [])
            assert isinstance(args, list)
            lines.append(f'command = "{spec["command"]}"')
            lines.append("args = [" + ", ".join(f'"{a}"' for a in args) + "]")
        lines.append("")
    return Draft(
        "ep-codex",
        "agent",
        "medium",
        "Codex CLI config with MCP servers.",
        {".codex/config.toml": "\n".join(lines)},
    )


def ep_openclaw(rd: Rand) -> Draft:
    skill = rd.ident().replace("_", "-")
    files = {
        ".openclaw/openclaw.json": dump_json(
            {
                "agent": {"model": f"anthropic/{rd.choice(ANTHROPIC_MODELS)}"},
                "gateway": {"port": 18789, "bind": "loopback"},
                "channels": {"telegram": {"enabled": rd.chance(0.5)}},
            }
        ),
        f".openclaw/workspace/skills/{skill}/SKILL.md": f"---\nname: {skill}\ndescription: Checks my calendar.\n---\n",
        ".openclaw/workspace/AGENTS.md": "# Workspace\n\nBe brief. Ask before sending messages.\n",
    }
    return Draft("ep-openclaw", "agent", "medium", "OpenClaw personal agent state directory.", files)


def ep_cline(rd: Rand) -> Draft:
    files = _vscode_ext(rd, "saoudrizwan", "claude-dev", "Cline")
    if rd.chance(0.6):
        files[".config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"] = (
            dump_json({"mcpServers": _mcp_servers(rd, 1)})
        )
    return Draft("ep-cline", "agent", "medium", "Cline autonomous coding-agent extension.", files)


def ep_continue(rd: Rand) -> Draft:
    text = (
        f"name: Local Assistant\nversion: 1.0.0\nschema: v1\nmodels:\n  - name: {rd.choice(OLLAMA_MODELS)}\n"
        f"    provider: ollama\n    model: {rd.choice(OLLAMA_MODELS)}\n    roles: [chat, edit]\n"
        "mcpServers:\n  - name: sqlite\n    command: uvx\n    args: [mcp-server-sqlite, --db-path, /tmp/app.db]\n"
    )
    return Draft(
        "ep-continue",
        "agent",
        "medium",
        "Continue config with models and an MCP server.",
        {".continue/config.yaml": text},
    )


def ep_aider(rd: Rand) -> Draft:
    files = {
        ".aider.conf.yml": f"model: {rd.choice(('sonnet', 'gpt-4o', 'deepseek'))}\nauto-commits: true\ndark-mode: true\n",
        f"src/{rd.name()}/.aider.chat.history.md": "# aider chat started at 2026-09-30 10:12:01\n\n> /add app.py\n",
    }
    return Draft("ep-aider", "agent", "medium", "Aider coding agent config and chat history.", files)


def ep_goose(rd: Rand) -> Draft:
    text = (
        f"GOOSE_PROVIDER: openai\nGOOSE_MODEL: {rd.choice(OPENAI_MODELS)}\nextensions:\n  developer:\n"
        "    enabled: true\n    name: developer\n    type: builtin\n  github:\n    enabled: true\n"
        "    cmd: npx\n    args: ['-y', '@modelcontextprotocol/server-github']\n    type: stdio\n"
    )
    return Draft(
        "ep-goose",
        "agent",
        "medium",
        "Goose agent config with extensions.",
        {".config/goose/config.yaml": text},
    )


def ep_kiro(rd: Rand) -> Draft:
    return Draft(
        "ep-kiro",
        "agent",
        "medium",
        "Kiro user MCP config.",
        {".kiro/settings/mcp.json": dump_json({"mcpServers": _mcp_servers(rd, rd.randint(1, 2))})},
    )


def ep_amazonq(rd: Rand) -> Draft:
    return Draft(
        "ep-amazonq",
        "agent",
        "medium",
        "Amazon Q Developer MCP config.",
        {".aws/amazonq/mcp.json": dump_json({"mcpServers": _mcp_servers(rd, rd.randint(1, 2))})},
    )


# --------------------------------------------------------------------------
# AI-tool (LLM) positives without agent evidence


def ep_copilot(rd: Rand) -> Draft:
    files = _vscode_ext(rd, "github", "copilot", "GitHub Copilot")
    if rd.chance(0.5):
        files.update(_vscode_ext(rd, "github", "copilot-chat", "GitHub Copilot Chat"))
    return Draft("ep-copilot-ext", "llm", "easy", "GitHub Copilot extension installed.", files)


def ep_ollama(rd: Rand) -> Draft:
    model = rd.choice(OLLAMA_MODELS)
    tag = rd.choice(("latest", "8b", "7b", "14b"))
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "layers": [
            {
                "mediaType": "application/vnd.ollama.image.model",
                "digest": "sha256:" + rd.hexid(64),
                "size": 4661211424,
            }
        ],
    }
    return Draft(
        "ep-ollama-models",
        "llm",
        "medium",
        "Local Ollama model store.",
        {f".ollama/models/manifests/registry.ollama.ai/library/{model}/{tag}": dump_json(manifest)},
    )


def ep_lmstudio(rd: Rand) -> Draft:
    path = ".lmstudio/models/lmstudio-community/Meta-Llama-3.1-8B-Instruct-GGUF/Meta-Llama-3.1-8B-Instruct-Q4_K_M.gguf"
    return Draft(
        "ep-lmstudio",
        "llm",
        "medium",
        "LM Studio with a downloaded GGUF model (header-only placeholder).",
        {
            path: "GGUF" + "\x00" * 12 + "general.architecture llama\n",
            ".lmstudio/settings.json": dump_json({"theme": "dark"}),
        },
    )


def ep_browser_ai_ext(rd: Rand) -> Draft:
    ext_id = "".join(rd.choice("abcdefghijklmnop") for _ in range(32))
    name = rd.choice(
        ("ChatGPT Sidebar", "Monica - Your ChatGPT AI Assistant", "Claude", "Perplexity - AI Companion")
    )
    manifest = {"manifest_version": 3, "name": name, "version": f"{rd.randint(1, 9)}.{rd.randint(0, 20)}.0"}
    return Draft(
        "ep-browser-ai-ext",
        "llm",
        "medium",
        "AI assistant browser extension.",
        {
            f".config/google-chrome/Default/Extensions/{ext_id}/{manifest['version']}_0/manifest.json": dump_json(
                manifest
            )
        },
    )


def ep_shell_history_ai(rd: Rand) -> Draft:
    cmds = rd.sample(
        (
            "ollama run llama3.1",
            "claude -p 'explain this diff'",
            "gemini",
            "codex exec 'fix tests'",
            "aider app.py",
        ),
        2,
    )
    return Draft(
        "ep-shell-history-ai",
        "llm",
        "hard",
        "Shell history shows AI CLI invocations; no config on disk.",
        {
            ".zsh_history": "\n".join(
                [": 1727690000:0;git pull", *[f": 1727690{i}00:0;{c}" for i, c in enumerate(cmds)]]
            )
            + "\n"
        },
    )


# --------------------------------------------------------------------------
# negatives (always on top of base_home)


def ep_plain(rd: Rand) -> Draft:
    return Draft("ep-neg-plain", "none", "easy", "Ordinary developer home.", {})


def ep_infra_dotfiles(rd: Rand) -> Draft:
    files = {
        ".docker/config.json": dump_json({"credsStore": "desktop", "currentContext": "default"}),
        ".kube/config": "apiVersion: v1\nkind: Config\ncurrent-context: dev\ncontexts:\n- name: dev\n  context:\n"
        "    cluster: dev\n    user: dev\n",
        ".ssh/config": f"Host claude-bastion\n  HostName 10.0.{rd.randint(0, 9)}.4\n  User ops\n  ForwardAgent yes\n",
    }
    return Draft(
        "ep-neg-infra-dotfiles",
        "none",
        "hard",
        "Infra dotfiles; a bastion host happens to be named 'claude'.",
        files,
    )


def ep_minecraft_mcp(rd: Rand) -> Draft:
    files = {
        f"projects/{rd.ident()}-mod/mcp/conf/mcp.cfg": "[VERSION]\nClientVersion = 1.12.2\n",
        f"projects/{rd.ident()}-mod/mcp.json": dump_json({"mcpVersion": "9.42", "mappings": "stable_39"}),
    }
    return Draft("ep-neg-minecraft-mcp", "none", "hard", "Minecraft Coder Pack files named mcp.", files)


def ep_datadog_agent(rd: Rand) -> Draft:
    files = {
        ".datadog-agent/datadog.yaml": "site: datadoghq.com\nlogs_enabled: true\nprocess_config:\n  enabled: true\n",
        ".config/systemd/user/datadog-agent.service": "[Service]\nExecStart=/opt/datadog-agent/bin/agent/agent run\n",
    }
    return Draft("ep-neg-datadog-agent", "none", "medium", "Monitoring agent config.", files)


def ep_browser_plain_ext(rd: Rand) -> Draft:
    ext_id = "".join(rd.choice("abcdefghijklmnop") for _ in range(32))
    name = rd.choice(
        ("uBlock Origin", "1Password - Password Manager", "React Developer Tools", "Grammar Checker Pro")
    )
    manifest = {"manifest_version": 3, "name": name, "version": "1.60.0"}
    return Draft(
        "ep-neg-browser-ext",
        "none",
        "medium",
        "Non-AI browser extension.",
        {f".config/google-chrome/Default/Extensions/{ext_id}/1.60.0_0/manifest.json": dump_json(manifest)},
    )


def ep_agent_named_projects(rd: Rand) -> Draft:
    files = {
        "projects/agent-portal/README.md": "# Agent portal\n\nCommission dashboard for real-estate agents.\n",
        "projects/agent-portal/agents.csv": "agent_id,name,region\nA-104,Jo Park,North\nA-221,Sam Ruiz,West\n",
        "projects/agent-portal/package.json": dump_json(
            {"name": "agent-portal", "dependencies": {"react": "^18.3.1"}}
        ),
    }
    return Draft("ep-neg-agent-projects", "none", "hard", "Real-estate agent portal project.", files)


EP_AGENT: tuple[Callable[[Rand], Draft], ...] = (
    ep_claude_desktop, ep_cursor, ep_vscode_mcp, ep_windsurf, ep_claude_code, ep_gemini_cli, ep_codex, ep_openclaw,
    ep_cline, ep_continue, ep_aider, ep_goose, ep_kiro, ep_amazonq,
)  # fmt: skip
EP_LLM: tuple[Callable[[Rand], Draft], ...] = (
    ep_copilot,
    ep_ollama,
    ep_lmstudio,
    ep_browser_ai_ext,
    ep_shell_history_ai,
)
EP_NEG: tuple[Callable[[Rand], Draft], ...] = (
    ep_plain, ep_infra_dotfiles, ep_minecraft_mcp, ep_datadog_agent, ep_browser_plain_ext, ep_agent_named_projects,
)  # fmt: skip


def wrap(rd: Rand, draft: Draft) -> Draft:
    files = base_home(rd)
    files.update(draft.files)
    return Draft(draft.family, draft.label, draft.difficulty, draft.rationale, files)
