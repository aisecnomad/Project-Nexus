"""What the endpoint inventory looks for, and where, relative to a home directory.

Every path is a documented user-scope location of the client on Linux, macOS
or Windows (``AppData``), written with ``/``. Nothing here is a pattern over
the whole home directory: the connector reads only these locations, so a scan
of a home directory stays bounded and does not read unrelated personal files.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ConfigLocation:
    """One client configuration file or directory below a home directory."""

    client: str  # stable client id used in resources and reports
    product: str  # display name
    path: str  # relative to the home directory
    signature: str | None  # signature id that owns the product, when one exists
    mcp: bool = False  # the file holds MCP server definitions
    directory: bool = False  # the location is a directory whose existence is the evidence


_VSCODE_USER = (".config/Code/User", "Library/Application Support/Code/User", "AppData/Roaming/Code/User")
_CURSOR_USER = (
    ".config/Cursor/User",
    "Library/Application Support/Cursor/User",
    "AppData/Roaming/Cursor/User",
)


def _per_editor(user_dirs: tuple[str, ...], tail: str) -> list[str]:
    return [f"{base}/{tail}" for base in user_dirs]


CONFIG_LOCATIONS: tuple[ConfigLocation, ...] = (
    # MCP client configurations
    *(
        ConfigLocation("claude-desktop", "Claude Desktop", p, None, mcp=True)
        for p in (
            ".config/Claude/claude_desktop_config.json",
            "Library/Application Support/Claude/claude_desktop_config.json",
            "AppData/Roaming/Claude/claude_desktop_config.json",
        )
    ),
    ConfigLocation("cursor", "Cursor", ".cursor/mcp.json", "coding-agent.cursor", mcp=True),
    *(
        ConfigLocation("vscode", "VS Code", p, "coding-agent.github-copilot", mcp=True)
        for p in _per_editor(_VSCODE_USER, "mcp.json")
    ),
    ConfigLocation(
        "windsurf", "Windsurf", ".codeium/windsurf/mcp_config.json", "coding-agent.windsurf", mcp=True
    ),
    ConfigLocation("claude-code", "Claude Code", ".claude.json", "coding-agent.claude-code", mcp=True),
    ConfigLocation("gemini-cli", "Gemini CLI", ".gemini/settings.json", "coding-agent.gemini-cli", mcp=True),
    ConfigLocation("codex", "OpenAI Codex CLI", ".codex/config.toml", "coding-agent.openai-codex", mcp=True),
    ConfigLocation("kiro", "Kiro", ".kiro/settings/mcp.json", None, mcp=True),
    ConfigLocation(
        "amazon-q", "Amazon Q Developer", ".aws/amazonq/mcp.json", "coding-agent.amazon-q-developer", mcp=True
    ),
    ConfigLocation("lm-studio", "LM Studio", ".lmstudio/mcp.json", None, mcp=True),
    ConfigLocation("continue", "Continue", ".continue/config.yaml", "coding-agent.continue", mcp=True),
    ConfigLocation("continue", "Continue", ".continue/config.json", "coding-agent.continue", mcp=True),
    ConfigLocation("goose", "Goose", ".config/goose/config.yaml", "coding-agent.goose", mcp=True),
    ConfigLocation(
        "goose", "Goose", "AppData/Roaming/Block/goose/config/config.yaml", "coding-agent.goose", mcp=True
    ),
    *(
        ConfigLocation("cline", "Cline", p, "coding-agent.cline", mcp=True)
        for p in _per_editor(
            _VSCODE_USER + _CURSOR_USER,
            "globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",
        )
    ),
    *(
        ConfigLocation("roo-code", "Roo Code", p, "coding-agent.roo-code", mcp=True)
        for p in _per_editor(
            _VSCODE_USER + _CURSOR_USER, "globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json"
        )
    ),
    # Agent settings and definitions (no MCP section)
    ConfigLocation("claude-code", "Claude Code", ".claude/settings.json", "coding-agent.claude-code"),
    ConfigLocation("claude-code", "Claude Code", ".claude/settings.local.json", "coding-agent.claude-code"),
    ConfigLocation(
        "claude-code", "Claude Code", ".claude/agents", "coding-agent.claude-code", directory=True
    ),
    ConfigLocation(
        "claude-code", "Claude Code", ".claude/skills", "coding-agent.claude-code", directory=True
    ),
    ConfigLocation(
        "claude-code", "Claude Code", ".claude/commands", "coding-agent.claude-code", directory=True
    ),
    ConfigLocation("codex", "OpenAI Codex CLI", ".codex/AGENTS.md", "coding-agent.openai-codex"),
    ConfigLocation("gemini-cli", "Gemini CLI", ".gemini/GEMINI.md", "coding-agent.gemini-cli"),
    ConfigLocation("aider", "Aider", ".aider.conf.yml", "coding-agent.aider"),
    ConfigLocation("aider", "Aider", ".aider.model.settings.yml", "coding-agent.aider"),
    ConfigLocation("openclaw", "OpenClaw", ".openclaw/openclaw.json", "coding-agent.openclaw"),
    ConfigLocation("openclaw", "OpenClaw", ".openclaw/workspace", "coding-agent.openclaw", directory=True),
    ConfigLocation("openclaw", "OpenClaw", ".clawdbot/clawdbot.json", "coding-agent.openclaw"),
    ConfigLocation(
        "github-copilot", "GitHub Copilot CLI", ".copilot", "coding-agent.github-copilot", directory=True
    ),
    ConfigLocation("kiro", "Kiro", ".kiro", None, directory=True),
)


@dataclass(frozen=True, slots=True)
class ExtensionProduct:
    product: str
    signature: str | None
    agentic: bool  # acts on the workspace with tools (agent mode), not only completions/chat


# VS Code marketplace identifiers (publisher.name), lower case.
IDE_EXTENSIONS: dict[str, ExtensionProduct] = {
    "github.copilot": ExtensionProduct("GitHub Copilot", "coding-agent.github-copilot", False),
    "github.copilot-chat": ExtensionProduct("GitHub Copilot Chat", "coding-agent.github-copilot", True),
    "saoudrizwan.claude-dev": ExtensionProduct("Cline", "coding-agent.cline", True),
    "rooveterinaryinc.roo-cline": ExtensionProduct("Roo Code", "coding-agent.roo-code", True),
    "kilocode.kilo-code": ExtensionProduct("Kilo Code", None, True),
    "continue.continue": ExtensionProduct("Continue", "coding-agent.continue", True),
    "anthropic.claude-code": ExtensionProduct("Claude Code", "coding-agent.claude-code", True),
    "openai.chatgpt": ExtensionProduct("OpenAI Codex", "coding-agent.openai-codex", True),
    "amazonwebservices.amazon-q-vscode": ExtensionProduct(
        "Amazon Q Developer", "coding-agent.amazon-q-developer", True
    ),
    "google.geminicodeassist": ExtensionProduct("Gemini Code Assist", None, True),
    "augment.vscode-augment": ExtensionProduct("Augment Code", None, True),
    "codeium.codeium": ExtensionProduct("Windsurf Plugin (Codeium)", "coding-agent.windsurf", False),
    "sourcegraph.cody-ai": ExtensionProduct("Sourcegraph Cody", "coding-agent.sourcegraph-cody", False),
    "tabnine.tabnine-vscode": ExtensionProduct("Tabnine", None, False),
    "supermaven.supermaven": ExtensionProduct("Supermaven", None, False),
    "danielsanmedium.dscodegpt": ExtensionProduct("CodeGPT", None, False),
    "genieai.chatgpt-vscode": ExtensionProduct("ChatGPT - Genie AI", None, False),
}

# Editor extension directories below a home directory.
IDE_EXTENSION_DIRS: dict[str, str] = {
    ".vscode/extensions": "VS Code",
    ".vscode-insiders/extensions": "VS Code Insiders",
    ".vscode-server/extensions": "VS Code Server",
    ".vscode-oss/extensions": "VSCodium",
    ".cursor/extensions": "Cursor",
    ".windsurf/extensions": "Windsurf",
}

# Chromium user-data directories below a home directory; profiles are their children.
CHROMIUM_USER_DATA: dict[str, str] = {
    ".config/google-chrome": "Chrome",
    ".config/chromium": "Chromium",
    ".config/microsoft-edge": "Edge",
    ".config/BraveSoftware/Brave-Browser": "Brave",
    "Library/Application Support/Google/Chrome": "Chrome",
    "Library/Application Support/Microsoft Edge": "Edge",
    "Library/Application Support/BraveSoftware/Brave-Browser": "Brave",
    "AppData/Local/Google/Chrome/User Data": "Chrome",
    "AppData/Local/Microsoft/Edge/User Data": "Edge",
    "AppData/Local/BraveSoftware/Brave-Browser/User Data": "Brave",
}
FIREFOX_PROFILE_DIRS: tuple[str, ...] = (
    ".mozilla/firefox",
    "Library/Application Support/Firefox/Profiles",
    "AppData/Roaming/Mozilla/Firefox/Profiles",
)

# Browser extensions are matched by product name: store identifiers change
# between listings and copycats, and the name is what a user installed.
_AI_EXTENSION_NAMES = (
    r"ChatGPT", r"OpenAI", r"Claude", r"Anthropic", r"Gemini(?!\s+(?:Wallet|Exchange|Trading))", r"Copilot",
    r"Perplexity", r"Monica", r"Merlin", r"Sider", r"HARPA", r"MaxAI", r"AIPRM", r"DeepSeek", r"Grok",
    r"Mistral\s+AI", r"Le\s+Chat", r"Poe", r"Character\.AI", r"Grammarly", r"QuillBot", r"Wordtune",
    r"Writesonic", r"Jasper",
)  # fmt: skip
AI_EXTENSION_NAME = re.compile(
    r"\b(?:" + "|".join(_AI_EXTENSION_NAMES) + r")\b"
    r"|\bAI\s+(?:assistant|agent|chat|copilot|sidebar|writer|writing|summar\w*|companion)\b"
    r"|\bGPT-?\d",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class ModelStore:
    runtime: str
    product: str
    path: str  # directory below the home directory
    provider: str | None  # provider signature id
    layout: str  # how models are laid out: "ollama", "files" or "hf-hub"


MODEL_STORES: tuple[ModelStore, ...] = (
    ModelStore("ollama", "Ollama", ".ollama/models/manifests", "provider.ollama", "ollama"),
    ModelStore("lm-studio", "LM Studio", ".lmstudio/models", "provider.lm-studio", "files"),
    ModelStore("lm-studio", "LM Studio", ".cache/lm-studio/models", "provider.lm-studio", "files"),
    ModelStore(
        "huggingface", "Hugging Face cache", ".cache/huggingface/hub", "provider.huggingface", "hf-hub"
    ),
    ModelStore("gpt4all", "GPT4All", ".local/share/nomic.ai/GPT4All", None, "files"),
    ModelStore("gpt4all", "GPT4All", "Library/Application Support/nomic.ai/GPT4All", None, "files"),
    ModelStore("jan", "Jan", "jan/models", None, "files"),
)
MODEL_FILE_SUFFIXES = (".gguf", ".ggml", ".safetensors", ".llamafile", ".mlx")

SHELL_HISTORY_FILES: dict[str, str] = {
    ".bash_history": "bash",
    ".zsh_history": "zsh",
    ".local/share/fish/fish_history": "fish",
    "AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt": "powershell",
}

# First word of a command line -> (product, signature id). Only commands that are
# specific to an AI tool: generic words such as ``q`` or ``llm`` are omitted.
SHELL_TOOLS: dict[str, tuple[str, str | None]] = {
    "claude": ("Claude Code", "coding-agent.claude-code"),
    "codex": ("OpenAI Codex CLI", "coding-agent.openai-codex"),
    "gemini": ("Gemini CLI", "coding-agent.gemini-cli"),
    "aider": ("Aider", "coding-agent.aider"),
    "goose": ("Goose", "coding-agent.goose"),
    "openclaw": ("OpenClaw", "coding-agent.openclaw"),
    "ollama": ("Ollama", None),
    "lms": ("LM Studio CLI", None),
    "opencode": ("OpenCode", None),
    "cursor-agent": ("Cursor CLI", "coding-agent.cursor"),
    "copilot": ("GitHub Copilot CLI", "coding-agent.github-copilot"),
    "kiro-cli": ("Kiro CLI", None),
}
