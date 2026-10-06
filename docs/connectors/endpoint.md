# Endpoint and runtime inventories

The `endpoint.*` and `gateway.otel` connectors consume bounded offline JSON,
JSONL, or YAML exports. They do not probe network services, discover local
configuration files, or traverse model directories in the current version.
Supply only synthetic or appropriately sanitized exports.

These offline inventories do not provide cross-surface correlation. In
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
