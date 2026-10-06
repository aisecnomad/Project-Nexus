# Runtime connector

The runtime connector reports AI tools seen **running**: coding-agent CLIs,
AI desktop apps, MCP servers launched by a client, local model servers and
agent frameworks' development servers. A configured tool might never run; a
running process shows that it does. The engine links these findings to the
endpoint findings for the same tool on the same device.

## `runtime.processes`

| Matched | Examples |
|---|---|
| Coding-agent CLIs | `claude`, `codex`, `gemini`, `aider`, `goose`, `openclaw`, `opencode`, `cursor-agent`, and the same tools run as npm packages (`node …/@anthropic-ai/claude-code/cli.js`) or Python modules (`python -m aider`) |
| AI desktop apps | Claude Desktop, ChatGPT desktop, Cursor, Windsurf, LM Studio, Ollama, matched by executable name *and* the vendor's install path |
| MCP servers | packages launched through `npx`, `uvx`, `uv tool run`, `pipx run`, `bunx` or `node` whose names follow MCP conventions (`@modelcontextprotocol/server-*`, `mcp-server-*`, `*-mcp`), and `github-mcp-server` |
| Model servers | `ollama serve` / `run`, `llama-server`, `lms`, `python -m vllm.entrypoints…` |
| Frameworks and gateways | `crewai`, `langgraph` dev servers, Open WebUI, the LiteLLM proxy |

One `runtime-process` finding is reported per host, user and tool, with the
process count, up to ten process ids, the executable names and, for an MCP
server, its package name.

**Command lines never enter a finding.** They can carry credentials
(`--api-key …`), so only the matched tool, the executable's base name and an
MCP package name are kept.

### Input

- **Offline** (`input`): osquery `processes` results, as an array of rows or
  as logger lines with `columns` and `hostIdentifier`; Microsoft Defender
  `DeviceProcessEvents` (`DeviceName`, `AccountName`, `FileName`,
  `FolderPath`, `ProcessCommandLine`); CrowdStrike process events
  (`ComputerName`, `UserName`, `ImageFileName`, `CommandLine`); or any JSON or
  CSV with a command line or an executable. osquery's `processes` table has a
  `uid`, not a user name: join `users` to report names, as in
  `SELECT u.username, p.* FROM processes p LEFT JOIN users u USING (uid);`.
- **Live** (no `input`, Linux only): reads `/proc/<pid>/cmdline` without
  following the `exe` link. Processes of other users are visible only to an
  account allowed to read them; unreadable processes are reported and make the
  scan incomplete. Elsewhere, export osquery results instead.

Options: `label` (host name for records that carry none; default the host
name), `max_processes` (live mode bound, default 100,000; reaching it makes
the scan incomplete) and `input`. A record with neither a command line nor an
executable makes the scan incomplete.

### Lifecycle corroboration

After all connectors finish, the engine links endpoint findings
(`configured` agent and MCP configurations, `installed` apps, extensions and
model stores) to `running` process findings for the same tool on the same
device. Devices match by host name without its DNS domain
(`dev-laptop-07.corp.example` is `dev-laptop-07`). An MCP configuration links
to a running MCP server only when one of its server's arguments names the
same package.

Linked findings carry `metadata.lifecycle` (`states`, `subjects`, `related`,
and on the endpoint side `same_user`), and the configured or installed side
gains the tag `observed-running` with zero-weight evidence. Corroboration
changes neither confidence nor risk. A process seen at export time says
nothing about other times: absence from a process list does not show that a
tool is unused.

See the [main connector reference](../connectors.md) for shared options and offline safety limits.
