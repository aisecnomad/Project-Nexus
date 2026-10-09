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

### Schema reference

| Field | Type | Required | Meaning |
|---|---|---:|---|
| Signature `id` | string | Yes | `namespace.slug`; the namespace determines the category for built-in namespaces. |
| Signature `category` | string | Yes | Signature category; it must match the ID namespace where one is defined. |
| Signature `signals` | nonempty list | Yes | Evidence matchers; each entry has a supported `type`. |
| Signature `name` | string | No | Display name. |
| Signature `vendor`, `homepage`, `description` | string or null | No | Optional vendor, URL and description metadata. |
| Signature `tags`, `capabilities`, `risk_notes`, `references` | list of strings | No | Supplemental tags, scored capabilities, report notes and references. Capability values use the closed vocabulary below. |
| Signature `agent_indicator` | boolean | No | Marks a signature whose presence alone indicates an agent rather than only LLM use. |
| Signal `type` | string | Yes | Matcher type: `dependency`, `import`, `code`, `file`, `env`, `domain`, `user_agent`, `image`, `iac`, `name`, `scope`, `model`, `secret` or `client_id`. |
| Signal `weight` | finite number in `(0, 1]` | No | Evidence weight; it controls confidence, not severity. |
| Signal `capabilities` | list of strings | No | Capabilities implied by this signal. |
| Signal `agent_indicator` | boolean | No | Signal-level agent indicator. |
| Signal `description` | string | No | Optional signal description. |
| `dependency` matcher | fields vary by type | No | `ecosystem`, `names`, `prefixes`, `exclude_names`, `exclude_prefixes`. |
| `import` matcher | fields vary by type | No | `languages`, `patterns`. |
| `code` matcher | fields vary by type | No | `languages`, `patterns`, `ambiguous`. |
| `file` matcher | fields vary by type | No | `globs`. |
| `env` matcher | fields vary by type | No | `names`, `patterns`. |
| `domain`, `iac`, `scope` matchers | fields vary by type | No | `values`. |
| `user_agent`, `image`, `name`, `model`, `secret` matchers | fields vary by type | No | `patterns`. |
| `client_id` matcher | fields vary by type | No | `names`, `patterns`. |

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

`ambiguous: true` on a `code` signal marks patterns that are common identifiers
outside the product, such as aiohttp's `ClientSession(` or a UI component named
`AgentCard(`. The code connector counts such a match only when the same
signature also has an import, a dependency or a non-ambiguous code match in the
same project. Put ambiguous patterns in their own signal; every signature with
one must also declare an import, dependency or specific code signal.

## Adding or overriding

Put YAML files in a directory and pass `--signatures DIR` (or `signatures:` in
the config). Built-in identifiers are reserved by default. A reviewed replacement
requires `options.allow_signature_override: true` or `--allow-signature-override`;
it replaces the complete signature, not individual fields. Custom packs can:

* add an internal platform (`platform.acme-agent-runtime`) with its images, hosts and env vars;
* raise the weight of a scope that is privileged in your tenant;
* add your organization's internal AI SaaS vendors to `identity-app.*`;
* tune `heuristic.*` patterns for your code base.

Validate with `python -m shadowscan.signatures.validate DIR` and `make evaluate`
before committing.
This checks built-ins plus the supplied directory; use `--no-builtin DIR` to
validate an isolated custom pack. CI runs the same validator on every push and
pull request. `shadowscan signatures test` exercises representative inputs.

`signatures test` reports a signal's own weight and `agent_indicator`. The
code connector then decides how much a `code` match counts:

* In Python and JavaScript/TypeScript, calls are bound to their imports. A
  call through an import that matches a signature's `import` signal is
  checked against that signature's `code` patterns (the pattern must match at
  the called name). For a custom pack, the signature's or signal's
  `agent_indicator` applies to the bound call; built-in frameworks list their
  agent constructors instead. The built-in `framework` patterns count only
  this way: `Crew(` is CrewAI evidence when `Crew` was imported from
  `crewai`, not when a local class has that name.
* A custom pack's `framework` pattern also counts as a lexical match anywhere
  in the source, in every language, unless the bound call on that line already
  produced the same evidence. A lexical match promotes the project to an
  `agent` only when the same signature also has an `import` or `dependency`
  match in the project. Without one, the finding is `framework-usage`, with
  that evidence capped at weight 0.6 (`confidence_group:
  uncorroborated-lexical`). A pack with only a `code` signal therefore reports
  usage, not an agent; add the product's package or import to promote it.
* Other categories' unbound `code` matches in Python and JavaScript are
  supporting evidence and never promote an agent by themselves.

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

## Rule packs inside scanned repositories

A repository that stores detection rules lists the environment variables,
hosts and identifiers those rules detect. The code connector treats these
files as data: their content is never read as usage or configuration, so a
pack of custom signatures does not make its own repository an AI project.
It recognizes a YAML, JSON or TOML file only when the whole file has one of
these shapes, with no top-level key the format does not define:

| Format | Shape |
|---|---|
| ShadowScan signature pack | the loader's forms (`signatures:` alone, one signature, or a list), every signature with an `id`, a valid `category` and nonempty `signals` using schema field names |
| Semgrep | `rules:` alone, every rule with an `id`, a `message` and a `pattern`, `patterns`, `pattern-either`, `pattern-regex`, `match`, `taint` or `pattern-sources` matcher |
| Sigma | every document limited to Sigma rule fields, one with a `logsource` and a `detection` holding a `condition` |
| gitleaks | `title`, `extend`, `allowlist(s)` and `[[rules]]`, every rule with an `id` and a `regex` or `path` |

A file that adds anything else, such as an MCP server table beside gitleaks
rules, is scanned as before. File-name signals and real-format credentials in
a rule pack are still reported. The project finding lists recognized files
under `metadata.detection_rule_files` (a count per format and the first 20
paths). Scanning the scanner's own checkout still reports its Python sources
and tests, which call and test the products they detect.

## Conventions

* Regexes must compile as Python `re` expressions with `MULTILINE`; execution uses
  the timeout-capable `regex` engine in compatibility mode. Use `(?i)` for
  case-insensitivity. Write line-leading whitespace as `[^\S\r\n]*`, not `\s*`,
  so blank lines cannot trigger repeated scans of the rest of a file.
* Each signature regex execution is limited to 100 ms, scaled linearly with
  the declared input size for filesystem scans (0.25 s per million
  characters, never beyond the file's wall budget), so allowed work stays
  proportional to input length and super-linear patterns still fail on
  large inputs. `python -m shadowscan.signatures.validate` rejects secret
  patterns slower than that allowance on a pathological keyword-dense
  corpus. Fixed linear hostname
  and environment tokenizers use the shared input deadline instead. Filesystem scans share a configurable
  execution budget across the file's matching operations (2 seconds by default).
  Exceeding either limit raises an error and makes the scan incomplete; timeout
  is never treated as a clean non-match. A costly custom pattern should be
  rewritten rather than relying on a larger budget. Scanned files are untrusted,
  so a pattern must stay linear on a planted file: do not put two unbounded
  quantifiers over the same characters side by side (`:\s*\[?\s*` lets a run of
  blanks be split every way; write `:\s*(?:\[\s*)?`), and do not let a gap such
  as `\{[^}]*` run past the next place a match can start, or every repetition of
  the prefix rescans the rest of the file.
  `tests/unit/test_regex_linearity.py` times signature patterns on such shapes.
* `domain` values: exact host, `*.suffix`, or `re:` regex (regexes may include a port, e.g. `re:.*:11434$`).
  Domain signals match the host only, never a path. A host that also serves non-AI traffic (Cloudflare's
  general `api.cloudflare.com`, the `huggingface.co` site) is corroboration only (weight 0.15 or less) in
  its own signal; the AI-specific hosts (`gateway.ai.cloudflare.com`, `router.huggingface.co`) carry the
  high weight, so a DNS script or a dataset download stays a low-confidence hint, not LLM usage.
  A `re:` value must not match a dotted identifier: end it in a list of top-level domains or a fixed vendor
  domain, because the tokenizer reads every `a.b.c` word of a source file as a host
  (`re:^mcp\.[a-z0-9-]+\.(?:com|dev|app|ai|io|...)$`, not `\.[a-z]+$`). A host on a line of a hosts file,
  ad-block list, resolver configuration or proxy rule list is routed or blocked, not used, and never matches.
  `gateway.logs` still treats Cloudflare Workers AI inference paths (`/accounts/<id>/ai/run/`,
  `/accounts/<id>/ai/v1/`) as LLM traffic on any host.
* Dependency names that are also unrelated packages (the PyPI name `swarm`, which is not OpenAI Swarm) are
  not claimed; identify the product by its import, a vendor-qualified name or an idiom. A generic name that
  is the product's real package (npm `weave`) gets a low weight.
* `model` patterns are anchored and bounded: require the delimiter or digit that real ids carry
  (`tts-1`, `o1` followed by a non-alphanumeric, a Bedrock `vendor.model-name`), so `amazon.com`, `o1ne` or
  `tts-config` do not match.
* `policy.*` scope lists match the bare scope name for every provider. Names that are routine for ordinary
  apps (`offline_access`, `refresh_token`, `web`, `api`, `full`, `admin`, `workflow`) are not listed as
  privileged; list the qualified permission instead (`admin:org`, `admin.users:write`, `okta.users.manage`).
* `file` globs use `fnmatch` on the repository-relative POSIX path; `**/` prefixes match at any depth.
* Dependency names are normalized PEP 503-style (`Foo_Bar` == `foo-bar`) for every ecosystem.
* `secret` patterns must be specific enough not to match placeholders; matches are redacted before they reach any report.
  A prefix shared by several vendors (`sk-`) is only attributed when the rest of the key is vendor-specific
  (`sk-ant-`, `sk-or-v1-`, `sk-lf-`, `sk-litellm-`, OpenAI's `sk-proj-` / `T3BlbkFJ` marker); anything else is
  reported by `heuristic.unattributed-api-key` at low weight. A value of 20 to 31 characters after `sk-`
  (LiteLLM proxy virtual keys have 22) is reported only when it mixes letters and digits, has at most two
  `-` or `_` separators and passes the generic credential's diversity and entropy test, so hyphenated
  names and ticket branches are not keys; OpenSSH security-key algorithm names (`sk-ssh-…`, `sk-ecdsa-…`)
  never match. Shorter values are not reported. Anthropic API (`sk-ant-api03-`), admin
  (`sk-ant-admin01-`) and Claude Code OAuth (`sk-ant-oat01-`) tokens are attributed to `provider.anthropic`;
  other `sk-ant-` shapes match nothing, because the fallback deliberately excludes the prefix.
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
directory walks skip symlinked entries and log a warning naming each one. A
configured pack directory that contributes no `.yaml` or `.yml` pack (empty,
other file types only, or symlinks only) is an error that names the directory
and the entries it skipped; it never loads as an empty pack. YAML parsing has
construction budgets before schema validation, including bounds on aliases and
merge expansion.

### Dependency exclusions

A `dependency` signal may combine `prefixes` with `exclude_names` (exact package names) and `exclude_prefixes` (name prefixes) so a broad family such as `langchain-` can carve out packages that belong to another signature (`langchain-text-splitters`, `@langchain/langgraph`). Exclusions apply only to the prefix match; `names` on the same signal still match.
