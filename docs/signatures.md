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
        languages: [python]           # python | javascript | go | rust | java | dotnet | ruby | php | swift | dart
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

Signature ids are `namespace.slug` and the namespace fixes the category:
`framework`, `provider`, `protocol`, `coding-agent`, `platform`,
`observability`, `memory`, `sandbox`, `identity-app`, `heuristic` and `policy`
map to the category of the same name, `cloud.*` is the `cloud-service`
category and `tool.*` (tool providers such as web-search APIs) shares the
`sandbox` category as corroborating infrastructure. Any other namespace
(`custom.*`, `acme.*`) is free for custom packs and carries no category
requirement; the built-in packs may only use the namespaces above.

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
Overrides are allowed only between separate pack directories, in the order
configured.

The schema also pins the closed vocabularies the matcher and the risk engine
key on, so a typo fails loading instead of silently never matching:

* `ecosystem` must be one of `pypi`, `npm`, `nuget`, `maven`, `go`, `cargo`,
  `rubygems`, `composer`, `conda` or `any` (omitted means `any`);
* `languages` entries must be canonical language names (`python`, `javascript`,
  `go`, `rust`, `java`, `dotnet`, `ruby`, `php`, `swift`, `dart`);
* `capabilities` (signature or signal level) must be capabilities the risk
  engine scores: `code-exec`, `autonomous`, `saas-actions`, `browsing`,
  `memory`, `multi-agent`, `delegated-identity`, `tool-use`, `rag`;
* the id namespace must match the category (table above);
* `weight` must be a finite number greater than 0 and at most 1; a zero-weight
  signal contributes nothing and is rejected;
* list fields (`names`, `patterns`, `globs`, `values`, `capabilities`, `tags`...)
  may not repeat a value inside one signal (distinct signals of a signature may
  restate a value to layer a different weight or capability on it);
* a regex that matches the empty string (`a*`, `^`, `foo|`) is rejected, for
  `patterns` and for `re:` domain values;
* `file` globs must have balanced `[...]` classes and no `{a,b}` braces, which
  `fnmatch` would match literally.

`python -m shadowscan.signatures.validate` additionally checks the whole set:
an identical regex (same signal type, or a `re:` domain value) claimed by two
or more signatures is an error unless every claimant but one is a `heuristic`,
because a shared regex cannot attribute a match to either product. Shared
plain values (a dependency name that is both a framework integration and a
provider SDK, a scope that a `policy.*` signature classifies and a provider
claims) are allowed. Built-in signatures must use a known namespace.

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
  A prefix shared by several vendors (`sk-`) is only attributed when the rest of the key is vendor-specific
  (`sk-ant-`, `sk-or-v1-`, `sk-lf-`, `sk-litellm-`, OpenAI's `sk-proj-` / `T3BlbkFJ` marker); anything else is
  reported by `heuristic.unattributed-api-key` at low weight.
* `name` patterns for products whose name is also a dictionary word or a first name (Otter, Devin, Jasper,
  Drift...) are context-guarded: the vendor form (`otter\.ai`) matches on its own; the bare word only when it is
  the whole display name (`^[^\S\r\n]*otter[^\S\r\n]*$`, an app called just "Otter") or with product context on
  the same line (`(?i)^(?=.*\b(?:ai|meeting|notes)\b).*\botter\b`), so "Otter Insurance Portal" and "Devin Smith"
  never match. Umbrella `identity-app.*` signatures own the display names of the SaaS products they list;
  dedicated `coding-agent.*` / `platform.*` signatures do not repeat them.
* Code idioms shared by several SDKs (`CodeInterpreterTool(`, `WebSearchTool(`, `Agent(model=...)`,
  `new Agent({ name: ... })`) live in `heuristic.*` signatures at low weight without `agent_indicator`; a product
  signature only claims idioms that are unique to it, so a generic constructor can never pin the wrong framework.

Pack traversal does not follow symlinks. Explicit unsafe paths fail validation;
directory walks skip symlinked entries. YAML parsing has construction budgets
before schema validation, including bounds on aliases and merge expansion.

### Dependency exclusions

A `dependency` signal may combine `prefixes` with `exclude_names` (exact package names) and `exclude_prefixes` (name prefixes) so a broad family such as `langchain-` can carve out packages that belong to another signature (`langchain-text-splitters`, `@langchain/langgraph`). Exclusions apply only to the prefix match; `names` on the same signal still match.
