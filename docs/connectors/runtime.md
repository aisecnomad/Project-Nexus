# Runtime connector

The runtime connector reports AI tools seen **running**: coding-agent CLIs,
AI desktop apps, MCP servers launched by a client, local model servers and
agent frameworks' development servers. A configured tool might never run; a
running process shows that it does. The engine links these findings to the
`endpoint.inventory` findings for the same tool on the same device.

## `runtime.processes`

| Matched | Examples |
|---|---|
| Coding-agent CLIs | `claude`, `codex`, `gemini`, `aider`, `goose`, `openclaw`, `opencode`, `cursor-agent`, and the same tools run as npm packages (`node …/@anthropic-ai/claude-code/cli.js`) or Python modules (`python -m aider`) |
| AI desktop apps | Claude Desktop, ChatGPT desktop and Ollama.app, matched by executable name *and* the vendor's app bundle or package path; Cursor, Windsurf and LM Studio, matched by executable name alone, so another program with the same name is reported as that app |
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
  scan incomplete. Some views do not list other processes at all, and then
  the scan is marked incomplete with a warning that says why: a `/proc` that
  belongs to a container's own PID namespace (detected from the namespace's
  inode, not from `NSpid`, which shows one entry inside a container as on the
  host); `hidepid=invisible` or `noaccess`, unless the scanning account is in
  the mount's `gid=` group (group 0 by default, so root sees everything); and
  `hidepid=ptraceable`, which hides processes the account may not trace even
  from root. `subset=pid` hides no process. Elsewhere, export osquery results
  instead.

Options: `label` (host name for records that carry none; default the host
name), `max_processes` (live mode bound, default 100,000; reaching it makes
the scan incomplete) and `input`. A record with neither a command line nor an
executable makes the scan incomplete.

### Lifecycle corroboration

After all connectors finish, the engine links `endpoint.inventory` findings
(`configured` agent and MCP configurations, `installed` apps, extensions and
model stores) to `running` process findings for the same tool on the same
device. The same tool means the same signature or, for a client configuration,
the same tool id, so Claude Desktop, Kiro and LM Studio, which have no
signature, link too. Code findings and the offline `endpoint.*` inventories
are not linked. Devices match by the complete trimmed, case-insensitive device
value: `dev-laptop-07.corp.example` does not match `dev-laptop-07` or a host in
another DNS domain. Use the same canonical device identifier or full hostname
in both exports; do not strip domains when combining different estates. An MCP configuration links
to a running MCP server only when one of its server's arguments names the
same package.

Linked findings carry `metadata.lifecycle` (`states`, `subjects`, `related`,
and on the endpoint side `same_user`), and the configured or installed side
gains the tag `observed-running` with zero-weight evidence. Corroboration
changes neither confidence nor risk. A process seen at export time says
nothing about other times: absence from a process list does not show that a
tool is unused.

See the [main connector reference](../connectors.md) for shared options and offline safety limits.
