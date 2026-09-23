# Signatures

All product knowledge lives in YAML packs under `shadowscan/signatures/data/`.
Connectors never hard-code vendor names; they ask the signature index what an
observation (a dependency, a host, a scope, a user agent, a file path…) means.

```
shadowscan signatures list [--category framework]
shadowscan signatures show framework.langgraph
shadowscan signatures test "api2.cursor.sh"            # auto-detects the kind
shadowscan signatures test langchain-aws --kind dependency --ecosystem pypi
```

For `--kind secret` (including auto-detected secret matches), the CLI shows
`[REDACTED]` instead of the matched credential. Use synthetic test values:
command arguments can still be retained in shell history or process listings.

## Anatomy

```yaml
signatures:
  - id: framework.crewai              # namespace.slug; namespaces mirror categories
    name: CrewAI
    category: framework               # see categories below
    vendor: CrewAI Inc.
    homepage: https://www.crewai.com
    description: Role-playing multi-agent framework.
    capabilities: [tool-use, multi-agent]   # implied whenever the signature matches
    agent_indicator: true             # presence alone means "an agent", not just LLM use
    risk_notes: ["..."]               # surfaced in reports, adds a small risk factor
    signals:
      - type: dependency
        ecosystem: pypi               # pypi | npm | go | cargo | maven | nuget | rubygems | composer | conda | any
        names: [crewai, crewai-tools]
        prefixes: [crewai]
        weight: 0.97
      - type: import
        languages: [python]           # python | javascript | go | rust | java | dotnet | ruby | php
        patterns: ['^[^\S\r\n]*(?:from|import)\s+crewai\b']
        weight: 0.97
      - type: code
        patterns: ['\bCrew\s*\(', '\.kickoff\s*\(']
        weight: 0.9
        capabilities: [code-exec]     # signal-level capabilities (optional)
        agent_indicator: true         # signal-level indicator (optional)
      - type: file
        globs: ["**/config/agents.yaml"]
        weight: 0.75
      - type: env
        names: [CREWAI_API_KEY]
        patterns: ['^CREWAI_']        # regex alternative
        weight: 0.6
      - type: domain
        values: [app.crewai.com, "*.crewai.com", "re:^hook\\.(eu|us)\\d*\\.make\\.com$"]
        weight: 0.7
      - type: user_agent
        patterns: ['(?i)\bcrewai\b']
        weight: 0.85
      - type: image
        patterns: ['langflowai/langflow']
      - type: iac
        values: [aws_bedrockagent_agent, "AWS::Bedrock::Agent", "Microsoft.BotService/botServices"]
      - type: name                    # display names of apps / roles / bots / principals
        patterns: ['(?i)\botter\.?ai\b']
      - type: scope                   # OAuth scopes, Graph permissions, IAM actions, RBAC role names/ids
        values: [Mail.ReadWrite, "bedrock:InvokeAgent"]
      - type: model
        patterns: ['^claude-']
      - type: secret
        patterns: ['\bsk-ant-api\d{2}-[A-Za-z0-9_-]{20,}\b']
        description: Anthropic API key
      - type: client_id
        names: ["fb8d773d-7ef8-4ec0-a117-179f88add510"]
```

### Categories

| category | meaning | goes to |
|---|---|---|
| `framework` | orchestration / agent SDKs | `finding.frameworks` |
| `protocol` | MCP, A2A, ACP, tool-calling shapes | `finding.frameworks` |
| `coding-agent` | IDE / CI coding agents & their config files | `finding.frameworks`, separate `agent-config` findings on the code surface |
| `platform` | hosted / low-code agent platforms, gateways | `finding.frameworks` |
| `cloud-service` | managed cloud agent services | `finding.frameworks` |
| `observability`, `memory`, `sandbox` | corroborating infrastructure | `finding.frameworks` |
| `identity-app` | AI SaaS products as they appear in IdPs / SaaS directories | `finding.frameworks` (+ their `tags`: assistant, meeting-bot, automation…) |
| `provider` | model providers / inference APIs | `finding.model_providers` |
| `policy` | permission classes (privileged / data-access / llm-access) | `finding.tags` → risk factors |
| `heuristic` | vendor-neutral idioms (tool registration, agent loops, autonomy flags, code execution) | capabilities + confidence only |

### Weights and confidence

Each match contributes its weight as evidence; a finding's confidence is the
noisy-OR of its evidence weights (`1 - Π(1 - w)`). Rules of thumb:

* `0.9+` unambiguous: a dedicated package, an agent class, a config file that only one product writes;
* `0.6–0.85` strong: an import of the framework namespace, a vendor host;
* `0.3–0.5` supporting: an env var, a generic idiom, a display-name hint.

`agent_indicator` (on the signature or a signal) is what promotes a code
project from `framework-usage` to `agent`. Plain provider SDK usage never does.

## Adding or overriding

Put YAML files in a directory and pass `--signatures DIR` (or `signatures:` in
the config). Built-in identifiers are reserved by default. A reviewed replacement
requires `options.allow_signature_override: true` or `--allow-signature-override`;
it replaces the complete signature, not individual fields. Custom packs can:

* add an internal platform (`platform.acme-agent-runtime`) with its images, hosts and env vars;
* raise the weight of a scope that is privileged in your tenant;
* add your organisation's internal AI SaaS vendors to `identity-app.*`;
* tune `heuristic.*` patterns for your code base.

Validate with `python -m shadowscan.signatures.validate DIR` before committing.
This checks built-ins plus the supplied directory; use `--no-builtin DIR` to
validate an isolated custom pack. CI runs the same validator on every push and
pull request. `shadowscan signatures test` exercises representative inputs.

The schema requires a signature `id`, `category`, and nonempty `signals` list.
Each signal has a supported `type` and that type's matcher fields. Unknown
fields, incorrect types, duplicate YAML keys or IDs within a pack directory,
empty packs, invalid categories, and malformed regexes (including `re:` domain
values) fail loading. Lists must contain strings; booleans cannot be strings.
Weights must be finite numbers in `[0, 1]`. Overrides are allowed only between
separate pack directories, in the order configured.

Signature packs do **not** support a `severity` field: severity is calculated
centrally by the risk engine from the finding. Every `severity` field is rejected,
including apparently valid values such as `high`, so it cannot silently bypass
risk scoring. `weight` controls confidence in the evidence, not finding severity.

## Conventions

* Regexes must compile as Python `re` expressions with `MULTILINE`; execution uses
  the timeout-capable `regex` engine in compatibility mode. Use `(?i)` for
  case-insensitivity. Write line-leading whitespace as `[^\S\r\n]*`, not `\s*`,
  so blank lines cannot trigger repeated scans of the rest of a file.
* Each signature regex execution is limited to 100 ms. Fixed linear hostname
  and environment tokenizers use the shared input deadline instead. Filesystem scans share a configurable
  execution budget across the file's matching operations (2 seconds by default).
  Exceeding either limit raises an error and makes the scan incomplete; timeout
  is never treated as a clean non-match. A costly custom pattern should be
  rewritten rather than relying on a larger budget.
* `domain` values: exact host, `*.suffix`, or `re:` regex (regexes may include a port, e.g. `re:.*:11434$`).
* `file` globs use `fnmatch` on the repository-relative POSIX path; `**/` prefixes match at any depth.
* Dependency names are normalised PEP 503-style (`Foo_Bar` == `foo-bar`) for every ecosystem.
* `secret` patterns must be specific enough not to match placeholders; matches are redacted before they reach any report.

Pack traversal does not follow symlinks. Explicit unsafe paths fail validation;
directory walks skip symlinked entries. YAML parsing has construction budgets
before schema validation, including bounds on aliases and merge expansion.
