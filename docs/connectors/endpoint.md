# Endpoint and runtime inventories

Endpoint connectors inventory AI tools on workstations and hosts. Two kinds
are available:

- `endpoint.inventory` reads a fixed list of documented user-scope locations
  in home directories (or osquery extension exports) and reports the clients
  and coding agents a person has configured, their MCP servers, AI editor and
  browser extensions, local model stores and, when enabled, AI command-line
  tools named in shell history. It finds tools that never touch a repository,
  an identity provider or a gateway, such as a Claude Desktop MCP server or an
  Ollama model pulled onto a laptop.
- `endpoint.host`, `endpoint.mcp`, `endpoint.ollama`, `endpoint.models` and
  `endpoint.ebpf` consume bounded offline exports from host, MDM, MCP, model
  and eBPF collectors (see [offline inventories](#offline-host-mcp-model-and-ebpf-inventories)).

Running processes are reported by [`runtime.processes`](runtime.md), which
links them to `endpoint.inventory` findings for the same tool and device.

## `endpoint.inventory`

The connector reads a fixed list of documented user-scope locations below
each home directory, on Linux, macOS and Windows (`AppData`) layouts. It does
not walk the home directory, so unrelated personal files are never opened.

| Category | Locations | Finding |
|---|---|---|
| Client and agent configuration | Claude Desktop, Claude Code (`~/.claude.json`, `~/.claude/settings*.json`, `agents/`, `skills/`, `commands/`), Cursor, VS Code `mcp.json`, Windsurf, Gemini CLI, Codex `config.toml` and `AGENTS.md`, Kiro, Amazon Q, LM Studio, Continue, Goose, Cline and Roo Code global storage, Aider, OpenClaw, Copilot CLI | `agent-config` for a product with a coding-agent signature, else `ai-app`; plus an `mcp-server` finding per client listing its servers |
| Editor extensions | VS Code, VS Code Insiders, VS Code Server, VSCodium, Cursor and Windsurf extension directories | `agent-config` for an agentic extension (Cline, Roo Code, Copilot Chat, Claude Code, Codex, Amazon Q…), else `ai-app` |
| Browser extensions | Chrome, Chromium, Edge and Brave profiles; Firefox `extensions.json` | `ai-app`, only when the extension name matches an AI product |
| Local models | Ollama manifests, LM Studio, the Hugging Face hub cache, GPT4All, Jan | `local-model` listing up to 50 model names |
| Shell history (opt-in) | bash, zsh, fish and PowerShell history | evidence on the tool's configuration finding, or an `ai-app` finding when the tool has none |

MCP server findings carry the same static server risks as the code
connector (`mcp-unpinned-package`, `mcp-broad-filesystem`,
`mcp-shell-command`, plaintext transport, auto-approved tools), and agent
configuration findings carry the same posture checks
(`posture-permissions-bypassed`, `posture-unrestricted-shell`,
`posture-unsandboxed`, `posture-exposed-gateway`,
`posture-unauthenticated-gateway`). See [risk](../concepts/risk.md).

Options:

- `path`: the home directory to inventory. The default is the home directory
  of the account running the scan.
- `paths`: a list of home directories, for example every directory under
  `/home` on a shared build host. Set `path` or `paths`, not both.
- `label`: the device name used in resource ids, titles and the finding's
  `account`. The default is the host name.
- `shell_history`: `true` to read shell history. Only the AI tool name and a
  run count are kept; command lines, arguments and timestamps are not. The
  default is `false`.
- `max_entries`: the number of directory entries examined per home directory
  (default 50,000). Reaching it makes the scan incomplete.
- `input`: offline records exported with `--dump-records`, or osquery
  results.

### Offline fleet inventory with osquery

`input` accepts the JSON output of these osquery queries, as an array of rows
or as osquery logger lines that carry `columns` and `hostIdentifier`:

```sql
SELECT u.username, e.* FROM users u CROSS JOIN vscode_extensions e USING (uid);
SELECT u.username, e.* FROM users u CROSS JOIN chrome_extensions e USING (uid);
SELECT u.username, a.* FROM users u CROSS JOIN firefox_addons a USING (uid);
```

Rows for extensions that are not AI products are ignored. The device comes
from `hostIdentifier` (or `label`), and the home from `username`, then the
user directory in the extension path, then `uid-<uid>`. Records exported with `--dump-records` replay unchanged, so a
collection on each laptop can be analysed centrally.

### Safety and completeness

- Every file and directory is opened without following a symbolic link in
  any path component. A link, an unreadable location, an oversized file or an
  exhausted entry budget is a coverage gap: a warning names the location and
  the scan is incomplete. A location that does not exist is not a gap.
- File contents never enter a record. MCP server entries are the sanitized
  projection the code connector uses (environment variable and header names,
  never values), browser extensions are kept only when their name matches an
  AI product, and posture records hold enumerated setting values, never a
  token.
- Malformed configuration (invalid JSON, YAML or TOML) still produces the
  configuration finding, records a warning and makes the scan incomplete,
  because its MCP servers could not be listed.
- A malformed offline record is ignored with a warning, and the scan is
  incomplete.

Findings are owned by the home directory name and scoped to the device, so
`owner` and `account` identify whose workstation a finding came from. An
endpoint inventory shows that a tool is installed or configured, not that it
ran; shell history is evidence of use on that account only.

## Offline host, MCP, model and eBPF inventories

The `endpoint.host`, `endpoint.mcp`, `endpoint.ollama`, `endpoint.models`,
`endpoint.ebpf` and `gateway.otel` connectors consume bounded offline JSON,
JSONL, or YAML exports. They do not probe network services, discover local
configuration files, or traverse model directories in the current version
(`endpoint.inventory` above reads its fixed list of local locations). Supply
only synthetic or appropriately sanitized exports.

These offline inventories are not correlated with other surfaces. In
particular, MCP tool fingerprints are not compared with a rug-pull baseline.

| Connector | Offline input |
|---|---|
| `endpoint.host` | Host/MDM inventory records with a runtime or configuration name |
| `endpoint.mcp` | Server records containing MCP tool-list responses |
| `endpoint.ollama` | Ollama-compatible model inventory, including an `endpoint` and `models` list |
| `endpoint.models` | Artifact metadata records; do not serialize model contents |
| `endpoint.ebpf` | Tetragon, Falco, Tracee, or Hubble event records |
| `gateway.otel` | OTLP span records with GenAI semantic-convention attributes |

MCP tool definitions are analyzed for risky capability names, prompt-injection
or exfiltration indicators, missing declared authentication, and duplicate
tool names across servers. Tool definitions are fingerprinted for downstream
comparison, but baseline/rug-pull detection is not yet implemented. No tool is
invoked.

OTLP analysis selects only service, agent, provider, model, and operation
attributes; prompt and completion content is not copied into findings.
`endpoint.models` consumes metadata supplied by an offline collector. It does
not parse GGUF/safetensors headers or hash files. Unsafe pickle-based extensions
are tagged and are never unpickled.

eBPF event correlation is heuristic and offline-only. ShadowScan does not load
eBPF programs; example operator policies are under `examples/ebpf/`.

See the [main connector reference](../connectors.md) for shared options and offline safety limits.
