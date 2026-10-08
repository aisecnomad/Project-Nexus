# Changelog

The detailed engineering log, recorded per change. RELEASE_NOTES.md
summarizes each release for people who install and operate ShadowScan.

## 0.1.1 — Unreleased

### October 8 real-world repository benchmark

- Added `tools/benchmark/realworld_corpus.json`: 91 public GitHub and GitLab
  repositories pinned to commits and labeled by hand with evidence paths
  (62 agent, 2 llm, 27 none) across application, framework-source,
  configuration-only, LLM-only, name-collision, classical-ML, docs-only and
  plain strata. Labels are the author's, single-reviewer and stratified, not a
  random sample or independent review; the corpus does not estimate field
  precision or recall.
- Added `tools/benchmark/realworld.py` (`validate`, `fetch`, `run`, `report`)
  and `adapters_repo.py` with adapters for Agentic Radar, OWASP cdxgen's AI
  inventory, Cisco Skill Scanner and a keyword-grep control. `Adapter.tree`
  copies a pinned checkout without `.git`, keeping links as links, so the
  existing ShadowScan, Cisco AI BOM, agent-bom and AgentDiscover adapters run
  unchanged. `Outcome.evidence` feeds a secondary evidence-coverage table and
  never changes a detection rule.
- Calibrated two adapters on three repositories before the scored run and
  recorded why: agent-bom no longer counts GitHub Actions pseudo-agents as
  AI; Agentic Radar's "didn't find any agentic workflow" exit is a clean
  nothing-found. The synthetic generator sources and their pre-registered
  digest are unchanged.
- Results and the per-repository matrix are in
  `tools/benchmark/results-realworld/`; `docs/evaluation.md` links the run.

### October 7 release merge-rule check with an administrator readback

- Fixed: the release-evidence workflow could never pass its merge-rule step.
  GitHub returns a ruleset's `bypass_actors` only to a caller with write
  access to it, the build job reads with its read-only token, and the verifier
  rightly refuses a response without the field. A dispatch of the governance
  audit, which reads the same way, confirmed the omission. The workflow had
  never been run, so nothing had shown the failure.
- The workflow takes a required `ruleset_readback` input: an administrator's
  `gh api repos/aisecnomad/Project-Nexus/rulesets/23913372` output.
  `python -m tools.release.rules verify --live` accepts it only when it equals
  the job's own read in every field that read returned, `updated_at`
  included, so a stale or edited readback fails and the readback can supply
  only the withheld `bypass_actors`. The full policy check then runs on the
  readback. The build job still holds no administrator credential.
- The merge-rule receipt records `bypass_actors_source` and
  `observed_updated_at`; `verify_receipt` and the evidence manifest validate
  both. Receipts without them still verify.
- Field names from a mismatching readback appear in the error only when they
  are plain lowercase names, so a crafted key cannot inject log lines or
  workflow commands.

### October 7 PyPI distribution and publishing

- The distribution is renamed from `project-nexus-shadowscan` to
  `NexusShadowScan`, so `pip install NexusShadowScan` installs the scanner once
  a release is published. The wheel is
  `nexusshadowscan-<version>-py3-none-any.whl` and the container inventory
  check looks for `pkg:pypi/nexusshadowscan`. The command, imports, connector
  entry-point group and report schemas keep the `shadowscan` name.
- The release-evidence workflow gains a `publish` input (`none` by default,
  `testpypi` or `pypi`). A `publication-gate` job requires exactly one wheel
  with matching digests, a public release version and, for `pypi`, the tag
  `v<version>` on the reviewed commit. A `publish` job, whose only permission
  is `id-token: write`, waits for approval in the protected environment of the
  same name, checks out nothing, and uploads that attested wheel with the
  SHA-pinned `pypa/gh-action-pypi-publish` v1.14.2 through trusted publishing,
  which adds PEP 740 attestations. No package-index token is stored.
- The repository policy tests allow that one upload step and no other. They
  pin each gate, and mutation tests show that removing a gate, uploading from
  another job, rebuilding in the publish job or adding a write scope fails.
- Fixed: the workflow's exactly-one-wheel checks were written
  `[ "${#wheels[@]}" -eq 1 ] && [ -f "${wheels[0]}" ]`. `set -e` ignores a
  failure of the first command of an `&&` list, so an artifact with two
  wheels passed. They now fail in an explicit `if`, and tests run the
  committed scripts with one and two wheels.
- README links are absolute repository URLs, because README is also the PyPI
  project description, where relative links resolve against pypi.org. A test
  keeps README free of relative links, and a new test resolves every absolute
  `blob/main` and `tree/main` link in the Markdown files, anchors included,
  against the checkout.
- Fixed a missing space in the README deployment install
  (`pip wheel. --no-deps`), which made the command fail.
- New maintainer runbook, `docs/operations/publishing.md`, for the one-time
  PyPI and environment setup and the per-release steps.

### Incomplete A2A cards, OpenClaw state files and short sk- keys

- An A2A card that fails validation but still names its agent and declares an
  endpoint, skills or capabilities gets its own `protocol.a2a` framework-usage
  finding ("Incomplete A2A agent card: …", tagged `incomplete-agent-card`,
  errors in `metadata.card_errors`) instead of disappearing from the report.
  It never becomes or joins an agent finding, so a valid card beside it keeps
  its single agent finding, and its validation errors still make the scan
  incomplete. An empty or unrelated object under a card file name is still
  not reported. Once the card is complete, the same finding ID reports the
  agent.
- `config.json` in an OpenClaw state directory (`.openclaw/`, `.clawdbot/`,
  `.moltbot/`) and `.moltbot/moltbot.json` belong to `coding-agent.openclaw`,
  so a state directory is one agent configuration finding. #155 placed the
  new paths under `platform.openclaw`; that signature covers configuration
  formats outside a state directory, which already belongs to the
  coding-agent signature alone.
- `heuristic.unattributed-api-key` has a second signal for `sk-` keys of 20 to
  31 characters after the prefix (LiteLLM proxy virtual keys have 22). A value
  is kept when it mixes letters and digits, has at most two separators, passes
  the generic credential's diversity and entropy test and is not already
  covered by a kept generic assigned-credential match, so an `*_API_KEY=`
  assignment keeps its finding and weight. OpenSSH security-key algorithm
  names (`sk-ssh-…`, `sk-ecdsa-…`) never match. Such keys were missed in SDK
  calls, JSON and YAML configuration and `Authorization` headers. A separate
  signal keeps rejected look-alikes from using the longer keys' match budget.
- `examples/inventory/sanctioned.yaml` shows the bare-list inventory form. The
  comment #155 gave it said the `agents:` mapping is not accepted; it is, and a
  test now loads both examples and checks that a name alone only suggests a
  match.
- The default evaluation corpus gains OpenClaw and Moltbot state-file cases, a
  short-key positive (which fails on the previous signatures) and a look-alike
  negative: SSH algorithm names, a spinner class and a ticket branch.
- A redaction test's parameter ID embedded a per-process HMAC, so pytest-xdist
  workers collected different test IDs and `make test-parallel` stopped at
  collection. The case now has a fixed ID.

### README command checks

- A README edit on `main` dropped the space in two copy-paste commands
  (`python -m pip wheel. …` and `shadowscan code. …`, both of which fail),
  misquoted the package classifier as `Development Status:: 3 - Alpha`, and
  indented the `Project status` heading so it rendered inside the preceding
  bullet. The PyPI publishing change fixed the `pip wheel` command and the
  classifier; the rest is fixed here, and the edit's wording and section
  order are kept.
- A repository test now checks that every `shadowscan` and `pip` command in a
  shell block of a Markdown page names a real subcommand, and that the
  classifier the README quotes is one `pyproject.toml` declares. Both checks
  fail on the edit as committed.
- `CITATION.cff`'s abstract named six of the nine discovery surfaces; it now
  names all nine, as the README does.

### Surface descriptions and pre-commit hooks

- The package summary in `pyproject.toml`, `shadowscan --help`, the HTML
  report's subtitle and the connector base docstring also named six of the
  nine surfaces, and the README said only identity, gateway, low-code, SaaS
  and cloud findings group repeated matches of one signal; every surface
  except code does. A repository test now checks that each one-line scope
  description names every `Surface`.
- `pre-commit run --all-files` failed on `main`. The benchmark report writer
  ended `REPORT.md` with a blank line, which `end-of-file-fixer` removes, and
  the mypy hook, which runs with `--ignore-missing-imports`, reported the Open
  Shadow AI helper's `import-not-found` ignores as unused. The writer now ends
  the report with one newline, `REPORT.md` is regenerated (the only change is
  that line), and the helper's ignores also allow `unused-ignore`, so CI's
  mypy and the hook both pass. The benchmark README's regeneration command
  wrote `REPORT.md` to the working directory; it names the committed path.

### October 6 merge-policy audit diagnostics

- The first scheduled merge-policy audit failed with "ruleset response does
  not match the expected repository and ruleset". A response missing a managed
  field produced the same message as a wrong repository or ruleset, and GitHub
  returns `bypass_actors` only to a caller with write access to the ruleset,
  which the read-only workflow token lacks. The verifier now names omitted
  fields separately. The job still fails until an administrator applies the
  reviewed payloads and a complete readback matches them; a complete readback
  taken on 2026-10-06 reports `readback differs from reviewed payload:
  bypass_actors, rules`.
- `docs/production.md` and `docs/operations/merge-policy.md` record that
  readback: both rulesets active again, with the gaps observed on 2026-10-03.

### October 6 head-to-head benchmark follow-ups

- The Goose signature matches the user configuration Goose writes on first
  run (`~/.config/goose/config.yaml`, and
  `%APPDATA%\Block\goose\config\config.yaml` on Windows). The benchmark
  missed all six Goose homes because only `.goose/`, `.goosehints` and
  `goose.yaml` were recognized.
- The Cline signature matches the installed extension directory
  (`saoudrizwan.claude-dev-*` under VS Code, VS Code Server, Cursor or
  Windsurf), so an install without `cline_mcp_settings.json` is found.
- `review_corpus.json` gains both cases and two look-alike negatives; the
  positives fail on the previous signatures.
- MCP configuration findings report static server risks: a package or image
  fetched without an exact version or digest (`mcp-unpinned-package`), a
  filesystem server rooted at `/` or a home directory
  (`mcp-broad-filesystem`), a shell-wrapped launch (`mcp-shell-command`),
  plaintext remote transport and auto-approved tools. The checks read the
  sanitized server record only; nothing is started or fetched.
- Coding-agent configuration findings report posture from the agent's own
  settings: Claude Code `bypassPermissions` and unrestricted `Bash` allow
  rules, Codex `approval_policy = "never"` and `danger-full-access`, Goose
  `GOOSE_MODE: auto`, and an OpenClaw gateway exposed beyond loopback or
  without an auth token. Only enumerated setting values are reported.
- A `coding-agent.openclaw` signature recognizes OpenClaw state directories.
- New default risk weights for these tags; see `docs/concepts/risk.md` and the
  October 6 migration note in `docs/production.md`.
- New `endpoint.inventory` connector on the `endpoint` surface. It reads a
  fixed list of documented user-scope locations below home directories: AI client
  and coding-agent configurations with their MCP servers, server risks and
  posture; AI editor and browser extensions; local model stores; and, with
  `shell_history: true`, AI command-line tool names and counts. Offline it
  replays exported records or osquery `vscode_extensions`,
  `chrome_extensions` and `firefox_addons` results. Symbolic links are never
  followed, and links, unreadable locations, oversized files or an exhausted
  `max_entries` budget make the scan incomplete.
- New finding kinds `ai-app`, `local-model`, `network-contact` and
  `runtime-process`, and surfaces `network` and `runtime`.
  `KIND_BASE` gives the first three 5 and `runtime-process` 10.
- MCP risk and posture recording moved to shared helpers
  (`record_server_risks`, `record_posture`) used by the code and endpoint
  connectors.
- The offline demo runs `endpoint.inventory`.
- `gateway.logs` classifies agentic callers from request metadata when logs
  carry no request bodies: hosted agent runtime operations
  (`agent-runtime-api`), MCP endpoints (`mcp-client`) and agent-loop cadence
  from programmatic callers (`agent-loop`). The indicators live in
  `shadowscan/connectors/agent_behavior.py` for reuse by other log sources.
- Fixed: every gateway caller to `*.openai.com` or `*.anthropic.com`, and any
  caller named after those vendors, was titled "Agentic caller" because the
  ChatGPT and Claude SaaS app signatures carry an agent indicator for OAuth
  grants. Gateway callers no longer take agent indicators from
  `identity-app` signatures; the golden replays record the corrected titles.
- Fixed: a user or key alias that matched a product name (a person called
  Jules) and browsing `chatgpt.com` (also listed by the ChatGPT plugin
  protocol signature) made gateway callers agentic. Name matches are hints,
  and a host counts only through the service it belongs to. Found by the
  post-change benchmark run; regression tests added.
- `framework.autogen` gains a user-agent signal (`autogen/…`, `ag2/…`).
- New `network.logs` connector and `network` surface. It reads Zeek
  `dns.log`, `ssl.log` and `conn.log` (TSV or JSON), Route 53 Resolver query
  logs, VPC Flow Logs and generic DNS/SNI exports, and reports one
  `network-contact` finding per client address and AI service. Host names
  match exactly or by a declared wildcard, and only AI host names are kept.
  Flows are attributed by Zeek `uid` to a TLS server name or through DNS
  answers in the same input; addresses shared with another service's host
  attribute nothing. The offline demo runs it.
- New `runtime.processes` connector and `runtime` surface: coding-agent CLIs,
  AI desktop apps, MCP servers, local model servers and agent dev servers seen
  running, from osquery `processes`, Defender `DeviceProcessEvents`,
  CrowdStrike process events, generic exports or `/proc` on Linux. Command
  lines never enter a finding, and the connector's records are excluded from
  `--dump-records` because command lines can carry credentials. The offline
  demo runs it.
- Lifecycle corroboration: the engine links endpoint findings (configured,
  installed) to running-process findings for the same tool on the same
  device, recording `metadata.lifecycle` and the tag `observed-running` with
  zero-weight evidence. MCP configurations link only through the same server
  package. Scores do not change.
- The CycloneDX 1.6 AI-BOM output (`--format cyclonedx`) models agents and
  other findings as application components, model artifacts and stores as
  machine-learning-model components, MCP and model-server inventories as
  services, and frameworks, models, providers and MCP servers as shared
  entries with dependencies.
  Credential findings are excluded, and `compositions` declares the inventory
  `incomplete` whenever the scan was. See `docs/operations/ai-bom.md`.
- Opt-in LLM triage (`options.llm_triage`, off by default): a redacted summary
  of the highest-risk findings goes to a model the operator names, through the
  scanner's HTTPS client, and the reply is stored as advisory
  `metadata.llm_triage`. Resource ids, owners, accounts, locations and
  snippets are not sent as fields, and their values are withheld from titles
  and evidence text; keys come only from an environment variable; replies
  never change scores or completeness. See `docs/operations/llm-triage.md`.
- `endpoint.inventory` coexists with the `endpoint.*` offline inventories:
  it reads local locations or osquery exports, they read collector exports.
  Their findings carry no device name, so lifecycle links do not apply to
  them.
- The CycloneDX output replaces the earlier candidate's exporter: findings
  other than models, MCP and Ollama inventories are `application` components
  instead of `machine-learning-model` components, risk is published as
  `shadowscan:heuristic-risk` (the earlier `shadowscan:risk_level` lookup never
  matched), per-tag `shadowscan:tag:<tag>` properties are one
  `shadowscan:tags` list, and credential findings are excluded. Regenerate
  BOMs and update their consumers.

#### Fixes from a review of the merged branch

- CycloneDX: MCP server risks were never emitted (the reporter expected
  objects, the records hold ids); `endpoint.ollama` model findings are
  `machine-learning-model` components again; each entry is sanitized on its
  own, so scans of about a thousand findings or more render; entries capped
  at 50 MCP servers or 20 models are recorded as `incomplete`; same-named
  servers and empty or repeated finding ids get distinct refs; providers carry
  no `trustZone`; names and vendors come from the scan's signature index,
  custom packs included.
- `endpoint.inventory`: a symbolically linked directory on the way to a
  location (Linux reports it as "not a directory") was treated as absent; it
  is now a gap. Unparseable agent settings, whose posture is therefore
  unknown, and a shell history longer than the read limit are gaps too.
  Malformed server, posture or model entries in replayed records are dropped
  with a warning (incomplete) instead of failing the connector or, through
  the lifecycle pass, the whole scan. Project servers in `~/.claude.json` that
  reuse a user-scope name are kept (`name#2`), MCP risk evidence cites the
  file that holds the servers, and the lock links a running Chromium browser
  keeps in its user-data directory no longer make every scan incomplete.
- `runtime.processes`: an export row whose pid is a non-ASCII digit no longer
  fails the export (64-bit ids such as CrowdStrike's `TargetProcessId` are
  kept). A live scan of a container's own `/proc`, identified by the PID
  namespace's inode, is marked incomplete because it cannot see the host's
  processes; so is one under a `hidepid` setting that hides processes from
  the scanning account. `subset=pid`, and root under the default `hidepid`
  group, hide nothing and stay complete.
- Lifecycle links also match by tool id, so Claude Desktop, Kiro and
  LM Studio configurations, which have no signature, link to their running
  processes.
- LLM triage withholds owner, account, resource, device, home, file and
  network client values from the title and evidence text it sends (one- and
  two-character values as whole words), while product names stay readable. A
  malformed reply is `unparseable`; an API key that is not a valid header
  value, or any other triage failure, is a warning on the triage entry that
  never echoes the key, and the scan keeps its report.
- MCP servers reached through `ws://`, an upper-case `HTTP://` scheme, or a
  URL that MCP clients' parsers read as plaintext despite embedded tabs,
  newlines or leading control characters gain the `mcp-plain-http` factor
  (+10): the factor parses the scheme as the `mcp-insecure-transport` tag
  does, so every tagged server is scored.
- A coding agent's own configuration file belongs to that agent's signature
  alone: `main`'s `platform.openclaw` no longer adds a second framework-usage
  finding for files in an OpenClaw state directory.

### Offline runtime inventory connectors

- Added the `endpoint` surface, offline analyzers for MCP tool inventories,
  OTLP GenAI spans, host/runtime records, local model metadata, and eBPF events,
  plus offline Kubernetes/OpenShift workload analysis.
- Added risk tags and OWASP/MITRE control references for selected runtime
  indicators, and a CycloneDX 1.6 AI-BOM output format. New runtime tag
  weights can change risk scores for findings that carry those tags.
- These offline inventories (`endpoint.host`, `endpoint.mcp`, `endpoint.ollama`,
  `endpoint.models`, `endpoint.ebpf`, `gateway.otel`, Kubernetes/OpenShift)
  remain offline-only; live MCP, Ollama and Kubernetes collection is
  unsupported. (`endpoint.inventory` and `runtime.processes`, above, read local
  state when no `input` is set.)
- Model metadata is supplied by an offline exporter; ShadowScan does not parse
  GGUF or safetensors files. MCP tool fingerprints have no rug-pull baseline, and
  findings from these inventories carry no device name, so lifecycle links do
  not apply to them.

### Security-review follow-ups

- `SHADOWSCAN_IDENTITY_KEY` accepts explicit `hex:<value>` and
  `base64:<value>` encodings. Bare values that are valid under both encodings
  now fail with a credential-free `SetupError` asking for a prefix. This
  intentionally breaks ambiguous bare keys, including ordinary 64-character
  hex strings; prefix them with `hex:`. The README now leads with the reviewed
  revision and hash-locked deployment install, and labels floating VCS installs
  as development-only and non-reproducible.
- Inventory approval warnings now include additional resource-shape probes and
  flag near-universal patterns as advisory sampled evidence. Only star-only
  globs are described as universal. The classifier retains the parsed pattern
  semantics, including literal whitespace and question-mark minimum lengths.
  Scope constraints, including observation discriminators, still limit approval.
  The Dockerfile documents the
  live-apk reproducibility trade-off and requires matching base-image and Python
  package pins across stages; a repository consistency test enforces the digest
  and pin synchronization.

### October 3 live merge-policy drift audit

- The weekly dependency-audit workflow now independently checks both live main
  rulesets against the reviewed update payloads using read-only GitHub API
  requests. Disabled, weakened, malformed or unavailable policy evidence fails
  the job. The audit does not apply settings or establish independent human
  review; an administrator must apply and read back the documented updates.
  Regression tests run the workflow's exact script against valid and invalid
  synthetic API snapshots.

### October 3 keyed credential evidence and invisible-character publication

- Code and cloud credential evidence now uses domain-separated HMAC-SHA-256
  pseudonyms rather than public SHA-256 digests of credentials. Engine workers
  share one random private key per scan. The existing `SHADOWSCAN_IDENTITY_KEY`
  opt-in supplies a stable key; it never enters configuration, reports or caches.
  Credential-bearing static results are rescanned without that stable key;
  stable-key rotation invalidates cached pseudonyms and collection comparability.
  Cache format 4 requires a fresh scan of previous entries. Resource-based
  finding IDs and existing private gateway exact-binding mappings are preserved.
  Regenerate older reports and comparison baselines; their public credential
  digests remain susceptible to candidate guessing. See the deployment guide.
- Saved HTML, CSV and Markdown now expose zero-width characters, byte-order
  marks, Unicode tag characters and lone surrogates consistently with terminal
  tables. Printable source characters and intentional format whitespace remain.

### October 3 source capability attribution

- Follow-up attribution checks reject discarded callbacks passed to unknown
  JavaScript factories, shadowed helpers and unrelated MCP member receivers.
  Supported import-bound tool factories retain async execute callbacks. Python
  tool regions omit statements after guaranteed exits and deferred lambdas in
  compound callees while retaining directly invoked lambdas. Regression cases
  cover positive registrations and contextual-only counterexamples.
- Unregistered tools and unrelated execution helpers no longer grant a
  project's agent `tool-use` or `code-exec`, or raise its confidence. Their
  evidence remains visible with zero weight and a contextual attribution;
  unproven features remain in `potential_capabilities`. Narrow local Python
  registrations, supported tool collections, direct unshadowed helper calls,
  and verified provider dispatch retain connected execution evidence. Tool
  registration does not establish runtime execution.
- JavaScript/TypeScript binding excludes provably constant-dead literal
  `if`/`else` and `while` branches while retaining executed alternatives and
  conservative hoisted-name shadow checks. Dynamic conditions and unsupported
  expression shapes remain possible source evidence. This is bounded static
  recognition, not whole-program reachability analysis.

### October 3 review remediation

- HTTP transport and streamed-body failures now preserve only controlled
  exception categories and the HTTPS origin, discarding opaque URL values
  and credential-bearing request/response objects and exception chains.
  Prior findings remain available and coverage remains incomplete.
- Strands constructor tool collections recognize non-empty literal tool
  names and paths. Other SDK collections and agent participants still require
  supported object evidence; strings do not establish an agent handoff.
- Shared HTTP diagnostics now retain only an HTTPS origin and status. URL
  paths, userinfo, queries and fragments are omitted, and malformed URL
  parsing produces fixed messages. Regression tests exercise the CLI logger,
  request errors, redirects and pagination; transport policy remains enforced.
- Configured capability analysis now covers supported ADK, Strands, AutoGen,
  LlamaIndex and Semantic Kernel constructors. Empty or unresolved options
  retain SDK features as potential capabilities instead of adding them to risk.
  Explicit participant collections and enabled execution options are interpreted
  using the SDK contract; weak planning vocabulary alone no longer establishes
  autonomous operation. Positive and negative cases cover the new behavior.
- Git submodule inventory can report controlled failure categories and numeric
  OS errors without publishing subprocess diagnostics or paths. Unknown
  coverage remains incomplete. Fast-exit metadata subprocess regressions and
  diagnostic assertions support investigation of the observed macOS failure;
  they do not establish its root cause or claim that it is fixed.
- Ruleset preparation refuses conflicting check-provider bindings. The merge
  runbook prepares both rulesets from fresh administrator snapshots, preserves
  stronger settings and verifies exact readback. Prepared policy files do not
  activate GitHub enforcement. Independent review and live tenant acceptance
  remain external prerequisites.

### October 3 incremental enumeration-budget review

- Incremental fingerprints now include the number of entries inspected by
  coverage probes in default-excluded directories. Moving a vendored file
  deeper can exceed `max_entries` without changing the probe's non-empty
  result; previously that change could reuse a cached complete scan. The
  changed fingerprint forces a full scan, which reports incomplete coverage
  when the entry limit is exhausted. Probes also share the fingerprint's
  cancellation, deadline and entry budgets. Regression tests cover cache
  invalidation and fingerprint-budget accounting.
- The testing guide now documents exact synthetic-secret approvals rather
  than the removed directory exclusions and placeholder-word exemptions.

### October 3 merge integration hygiene

- DCO checks every commit in the pull-request range, including merge commits.
  A merge can introduce conflict resolutions or other content beyond its
  signed-off parents; skipping it let that content pass without the merge
  author's certification. Regression tests exercise signed and unsigned
  two-parent commits with a file authored only in the merge.

### Bounded source-directory enumeration

- `code.filesystem` now limits directory enumeration before retaining entry
  names, including directories, excluded files and coverage probes. The new
  `max_entries` option defaults to 1,000,000 and is independent of `max_files`.
  GitHub and GitLab forward it to each checkout. Enumeration also checks
  cancellation and connector deadlines when there are no analyzable files.
  Entry and file limits retain findings already assessed and mark the scan incomplete
  (exit 3). Regression tests cover the limit, ignored and directory-only
  inputs, cancellation, deadlines and findings retained after a partial walk.

### October 3 incremental metadata confinement

- Incremental scans with `use_git: true` apply the bounded Git metadata
  preflight before fingerprinting, including when considering a cache hit.
  Unsafe metadata disables reuse and the full scan reports incomplete coverage
  while retaining source findings. This matches the existing history-enrichment
  policy; the preflight shares the connector deadline.

### October 3 secret-gate hygiene review

- Scan tests, signature packs and evaluation corpora for hardcoded credentials
  instead of exempting their directories. Synthetic fixtures and documentation
  placeholders require exact path, credential-family and SHA-256 approvals in
  `tools/secret_allowlist.json`; placeholder words no longer suppress findings.
  Private-key marker approvals also bind the whole fixture's bytes. Malformed,
  duplicate, stale or missing approvals fail the gate, including partial hooks.

### October 2 follow-ups to #135

- `test-macos (3.11)` failed `main` after #135 merged. The confinement test for
  a symlinked `.git/objects` deletes that directory right after its fixture
  commits. Since Git 2.47 a commit starts `git maintenance run --auto` in the
  background, and the detached process removed its `maintenance.lock` while
  `shutil.rmtree` was deleting the directory; Python 3.11 reports the vanished
  file as an error. With Git 2.55 and Python 3.11 the test failed in 4 of 150
  repeated runs. Every test helper that commits now passes
  `-c maintenance.auto=false`, and the repeated runs pass 150 of 150. The
  scanner's own Git commands (a clone and read-only metadata reads) never start
  maintenance.
- Five tests that read a repository snapshot need Git 2.45 or newer, like the
  other history tests, but were not marked `requires_git_2_45`. On an older
  Git, such as the 2.43 in Ubuntu 24.04, they failed instead of being skipped.
  They now carry the marker.
- The CI lock takes Dependabot's development-tool updates from #136
  (platformdirs 4.12.2, virtualenv 21.14.0), regenerated with the documented
  command and uv 0.12.18. The docs lock moves platformdirs with it, regenerated
  with its documented pip-compile command, because the combined install needs
  one version of each shared package. Dependabot changes only the constraints
  file, so its pull request failed the lock consistency tests.

### October 2 integration of #134 and repository hygiene review

Pull request #134 landed through an integration pull request as one
signed-off commit, rebuilt on the current `main`: its branch predated #123,
#132 and #133 and conflicted with the SARIF message escaping from #123. The
other changes come from an AI-assisted review of CI, documentation, code and
repository layout. Each defect was reproduced before it was fixed and has a
regression test or check; none had a second-person review. Migration notes are
in `docs/production.md` under "Candidate change history".

#### Heuristic severity in SARIF (#134)

- SARIF output no longer presents the heuristic risk level as a CVSS-like
  security severity. Rules carry neither `security-severity` nor the `security`
  tag. The level is recorded as the rule property `shadowscan/heuristic-risk`,
  next to `shadowscan/score-basis: heuristic-not-cvss`, and as the result
  property `risk_level`. Discovery hits are SARIF `warning` (critical, high,
  medium) or `note` (low, info), never `error`, which stays reserved for
  connector failures in the tool execution notifications. Each rule's help text
  and `helpUri` link to the new
  [severity guide](https://github.com/aisecnomad/Project-Nexus/blob/main/docs/severity.md),
  which states what the score is and what enforcement would require. Rule IDs
  and `partialFingerprints` are unchanged.

#### CI on `main`

- The SIGINT clone test failed `main` after #133 merged: its child scanner
  aborted (SIGABRT) instead of exiting after the interrupt. The child waited for
  its clone worker with `Thread.join()`. On CPython 3.11 and 3.12 a
  KeyboardInterrupt that interrupts `join()` marks the still-running thread as
  stopped, so interpreter shutdown did not wait for it, and the process aborts
  when that thread holds the stderr lock at exit. The child now waits with
  `concurrent.futures.wait` on a pool thread, as `Engine.run` does, and the test
  requires the clone worker to return before the process exits. The scanner's
  scan path already waited this way and is unaffected.

#### Scanner fixes

- JavaScript import, `require` and bound-call line numbers, and IaC model ids,
  are numbered incrementally (`shadowscan.utils.text.line_counter`). Each match
  counted the file's newlines from its start, which was charged against the
  match deadline: a scanned file with thousands of imports made its analysis
  incomplete on purpose. Line numbers are unchanged.
- `code.filesystem` rejects a boolean, fractional or non-numeric
  `max_file_size` or `max_files`, and a boolean, non-finite or out-of-range
  `scan_timeout`, as configuration errors with a fixed message. `max_file_size:
  true` was a 1-byte limit that skipped every file, and `max_files: 1.9` became
  1. Numbers and numeric text are accepted as before.
- The wheel ships `.yml` signature packs as well as `.yaml`; the loader reads
  both.

#### Container and CI tooling

- The worker image no longer carries the build backend: the wheel is built in
  a separate environment that is not copied, so `setuptools`, `wheel` and
  `packaging` stay out of `/opt/venv` (the Dockerfile already said so). The CI
  smoke test asserts it, and the Dockerfile policy test covers `pip wheel` as
  well as `pip install`.
- Both image stages pin Wolfi's `python-3.12` to `3.12.15-r0` for now.
  `3.12.15-r1`, published on 2026-10-02, has no SHA-224 or SHA3-224, and pip
  derives its cache keys from SHA-224, so every `pip install` in the build
  failed, on `main` as well. Drop the pin once a newer revision provides
  `hashlib.sha224`; the policy test requires both stages to stay on one
  interpreter revision.
- The consumer workflow example runs `python -m` from the runner's temporary
  directory, never from the scanned checkout, where a `pip/__main__.py` or
  `shadowscan/` package in a pull request would run in place of the installed
  tools. Its `security-events: write` permission moved to the job.
- Dependabot updates the example's action pins with the workflows' in one
  grouped pull request, and groups the remaining pip constraint updates; a
  bump that changed only the workflows failed the pin-equality test.
- The Docs workflow also builds for `RELEASE_NOTES.md` and the docstrings the
  API pages render, and a push no longer cancels a manual publishing run.
  Scorecard grants nothing at workflow level.
- Pre-commit: `pre-commit run --all-files` passes on a clean checkout again.
  The private-key hook skips the redaction rules and tests that name synthetic
  key markers, the format hook formats Python only (as CI does), the check hook
  uses its current id `ruff-check`, and Markdown line-break spaces are kept.
- `.gitignore` anchors root build, report and site outputs, so a source file
  such as `shadowscan/reporters/report.py` is no longer ignored, and the
  digest-bound license texts are never converted by Git (`-text`).

#### Documentation

- The README demo output and inventory example match the code; a consistency
  test reruns the demo and compares the shown totals and rows. Signature counts
  are checked in the root documents the site publishes (a stale "1,001
  signals" was in the release notes).
- Ruleset enforcement is described in one dated place, `docs/production.md`;
  the other documents no longer call the disabled rules active. The exit codes
  for usage errors (`docs/scanning.md`) and for expired or over-budget
  known-gap policies (`docs/evaluation.md`) match the code.
- Smaller corrections: the dark theme's toggle label, the inventory registry's
  place in the API reference, connector page heading levels, and a dropped
  fail-closed sentence in the connector overview.

### October 2 integrity and capability corrections

- Selected source and configuration files use strict supported text decoding,
  including Python's supported PEP 263 declarations and BOM-declared
  UTF-16/UTF-32. NUL bytes no longer silently exclude source from analysis;
  malformed configuration and unsupported encodings make coverage incomplete.
- MCP registration analysis distinguishes executable registrations from
  comments and examples, accepts supported decorator options, and preserves
  independent execution-sink evidence. Analysis limits must not imply complete
  capability coverage. Empty or explicitly disabled provider tool options no
  longer establish tool-use.
- GCP IAM collection requests policy version 3 and retains conditional-binding
  evidence. Ambiguous/degraded permissions and unresolved child records in
  Auth0/ServiceNow make coverage incomplete. SaaS exports missing a usable app
  name cannot produce a complete empty scan or resolve previous findings.
- Git metadata enrichment remains opt-in and now rejects metadata indirections,
  including local `include`/`includeIf` configuration sections, and bounds
  captured output. Bounded confined config reads reject unsupported section
  syntax, encodings, continuations and multiline values before Git runs.
  Credential source sanitization handles supported
  whitespace, wrapper and record forms without treating its output as public
  data. See the security policy for remaining limits.
- Proposed ruleset update payloads and offline verification tooling prepare
  mandatory aggregate CI and non-author review enforcement. Merging these
  files does not activate GitHub settings; live readback remains required.
- The documentation toolchain lock shares the reviewed `platformdirs` pin with
  CI, restoring the documented combined installation. Shared-pin consistency
  checks prevent independently refreshed locks from making that install fail.
- These changes are supported by authored regression tests. They do not
  establish independent human review, fresh field accuracy or live tenant
  acceptance. Review changed capabilities/risk scores and collect a new baseline
  before enforcement.

### October 2 integration of the open pull requests

The open pull requests #107 and #110 to #122 landed together through #123,
which was squash-merged into one commit on `main`. On #123's branch each of
them is one commit: each commit of the stack (#107, #110 to #120) has exactly
that pull request's tree, and #121 and #122 also carry their conflict
resolutions against the stack. The redaction review fixes and this grouping
followed in a separate pull request.

The review fixes below come from an AI-assisted review of the integrated code.
Each defect was reproduced before it was fixed and has a regression test.
Neither the review nor the fixes had a second-person review, and the offline
evaluation corpora are author-written: their unchanged results say nothing
about field precision. Migration notes are in `docs/production.md` under
"Candidate change history".

#### Integration changes

- Worker image: built on Chainguard's Wolfi base (`chainguard/wolfi-base`,
  pinned by index digest in both stages) instead of `python:3.12-slim-trixie`.
  The Debian image could not pass the strict container gate: 55 unfixed HIGH
  entries in util-linux, ncurses, Perl, systemd libraries and Git's
  `libcurl3t64-gnutls`. Python 3.12, its expat and Git are now Wolfi packages
  that the image scan inventories; the official image's interpreter and its
  bundled expat 2.8.3, affected by denial-of-service and memory-safety
  advisories and used for every XML file the scanner reads, were invisible to
  the scan. pip and the build tools stay in the build stage, the scanner runs
  from `/opt/venv`, and the build removes every setuid and setgid bit and fails
  if one remains. The gate policy is unchanged.
- `tools/container/verify.py` lists each blocking finding (identifier,
  package, installed and fixed version, status) in the job log and in
  `container-evidence.json`, so a failed gate explains itself without its
  artifact. The CI smoke run requires the image's expat to be 2.8.5 or newer,
  and `--os-type` states the distribution whose packages the inventory must
  contain.
- The lock audits drop pip-audit's redundant `--no-deps`; `--require-hashes`
  already pins every requirement.
- `bounded_safe_load_all` is removed, as both #112 and #121 intended; the
  stack still defined it.
- Ruff `BLE` and `RUF100`, enabled by #121, now cover the stack's code: two
  broad redaction handlers state why they are broad, a `noqa` on a handler that
  always re-raises is removed, and two tests catch the exact exception they
  expect.
- `docs/connectors/reference.md` is regenerated from the stack's connectors,
  and `docs/production.md` puts operator guidance first with every dated note,
  including the stack's, under "Candidate change history" (#122).

#### Review fixes: code connectors and signatures

- `framework.vercel-ai-sdk`: the `stopWhen:` and `tools: { … tool(` code
  patterns were quadratic on planted input. A 30 KB file with `stopWhen:`
  followed by blanks timed out signature matching, so the file's evidence was
  dropped and every scan of that repository exited 3. Both are linear now with
  the same matches, and `tests/unit/test_regex_linearity.py` times the
  signature's code patterns on such shapes.
- `code.filesystem`: the catalog rule no longer discounts deployment and CI
  configuration. A Kubernetes-style resource (`apiVersion` and `kind`, also in
  a multi-document stream), an ECS task definition, a CI pipeline
  (`.gitlab-ci.yml`, `azure-pipelines.yml`, `bitbucket-pipelines.yml`,
  `.circleci/`, `.buildkite/`, `buildspec.yml` and others), Spring
  `application*`/`bootstrap*` configuration, and any data file that assigns a
  variable it names under an `env`, `environment`, `variables` or `secrets` key
  are configuration however many products they name. A Deployment injecting
  four provider keys, or a pipeline handing them to a job, used to give no
  finding and a complete scan. When a project's only evidence is in
  catalog-like files, a scan note (a warning that does not make the scan
  incomplete) names them instead of dropping it silently.
- Submodule declarations (`.gitmodules`) are read in linear time. The
  configuration parser rescans a run of blanks before `=` from each of its
  positions, in C while holding the GIL, so one planted 1 MiB line froze the
  whole process for over an hour and neither the connector deadline nor
  `--job-deadline-seconds` could fire. A file with a run of more than 32 blanks
  is refused before parsing and reported like other unreadable declarations
  (submodule coverage unknown, scan incomplete).
- The Python import binder joins a loop's bindings over the names the loop
  assigns, as it already did for `if` branches, instead of copying and joining
  the whole enclosing scope for every `for`/`while` loop and loop `else`. A
  143 KB file of 6000 module-level names and 4000 loops (under the AST cap)
  took 15 s, seven times its matching budget; it now takes 0.5 s. The binder
  also checks the file's matching budget every 256 visited nodes, so any
  remaining expensive walk ends at that budget as partial import-bound
  analysis (scan incomplete) instead of overrunning it.
- A JavaScript or TypeScript call into a signature's library that is longer
  than 8192 characters (a Genkit flow body, an agent with long instructions)
  is analyzed from its first 8192 characters, as the Python binder does, and
  the file's other import-bound evidence is kept. It used to discard every
  import-bound call of the file, so a long Genkit flow also lost the file's
  `genkit()` constructor evidence. Options past the limit are unread, so the
  scan is still incomplete (exit 3) as before; the error names the call's
  line.
- Dockerfile comment masking reads the `escape` parser directive as BuildKit
  does: only from the leading directive lines. A `# escape=` after an ordinary
  comment, a blank line, an unknown directive or an instruction is a comment.
  It used to switch the escape character, so a trailing backtick joined the
  next `RUN pip install ...` into a shell comment and hid its dependencies
  while Docker ran it.
- Java sources are lexed after Unicode escapes are translated, as javac does
  (JLS 3.3), and the masked spans are mapped back onto the source. Only escaped
  line breaks in `//` comments were handled: `/* ... \u002a/` (or `*\u002f`)
  closes a block comment and `\u0022` closes a string, so code after them, such
  as an import, used to stay masked. An escape that spells a printable ASCII
  character in code (`\u0069mport`) hides that code from the matchers, which
  read the source as written: such a file's lexical analysis is reported as
  incomplete.
- When the Python or JavaScript import binder does not run (the source does
  not parse, or a binder budget is exhausted), the file's bundled framework
  patterns are kept as lexical evidence that counts only with an import or
  dependency of the same library, as for a language without a binder. They
  used to be dropped although the warning said "lexical evidence retained", so
  one PEP 695 line on Python 3.11 turned an agent into "LLM usage". A
  notebook's IPython magic (`%pip`, `%%time`) and shell (`!pip`) lines are
  read as inert expressions before parsing, as IPython rewrites them, so a
  notebook that installs its packages keeps the import binder.
- Notebook code cells are lexed and parsed one at a time, as Jupyter runs
  them. A cell that left a triple-quoted string open used to mask every later
  cell, so a notebook with one unfinished scratch cell gave no finding and a
  complete scan. A cell that does not parse (a `%%bash` cell, an unclosed
  bracket) is now left out of import binding alone, with a warning naming it,
  and its framework patterns count as lexical evidence; the other cells are
  bound as usual.
- `code.filesystem` reports a file it reads that is a Git LFS pointer as a
  coverage gap (scan incomplete; an error under `strict_coverage`) instead of
  analyzing the pointer text as the file. Only live clones and API snapshots
  checked for pointers, so a local checkout or a directory of offline clones
  made without git-lfs, with `agent.py` stored in LFS, gave no finding and a
  complete scan. A pointer in place of a file the scanner never reads (an
  image, a model) is not a gap; the live-clone check is unchanged.
- Python code after an unclosed bracket is no longer masked on Python 3.12
  and later. Those versions report the tokenizer error at the start of the
  last line rather than past it, so that line was masked as if it were a
  literal: a construction on it was lost while the scan said its lexical
  evidence was retained. Python 3.11 was unaffected.

#### Review fixes: gateway, low-code and cloud connectors

- `gateway.logs` access-log attribution: trailer and logfmt tokens are read
  as logfmt, so a key must start a token. An unquoted client value after the
  final quote (`args=a&host=api.openai.com host=intranet`) no longer becomes
  the host, a request line or query logged as one token can no longer set
  `model` (`GET /v1/x?model=forged`), and a line
  truncated inside the user agent is malformed instead of taking its host from
  the user agent. Combined-format fields keep `\"` escapes inside the field.
  A host token in or before a quoted trailer field, which a client can write
  when the gateway does not escape quotes, is still not trusted; when it alone
  would have made a request LLM traffic the scan is now incomplete with a
  warning, where such requests used to be skipped with exit 0. An inference
  operation with a static suffix (`/v1/chat/completions.css`, which a
  suffix-matching router serves as the endpoint) is no longer excluded as a
  static asset, while static files under inference-like prefixes
  (`/agents/app.js`, `/v1/images/logo.png`) still are, and `;name=value` path
  parameters are removed before the static-asset test.
- `lowcode.servicenow`: an empty page no longer ends a table. ACLs remove rows
  after `sysparm_limit`, so a whole 500-row window can come back empty while
  later windows hold readable records; collection used to stop there with exit
  0. It now pages until the windows cover `X-Total-Count`, which also saves the
  extra empty request per table. A response without a valid `X-Total-Count`
  ends the table at an empty page with a warning that makes the scan
  incomplete. `HttpClient.get_json` takes an `on_response` callback that sees
  the response headers once the body is decoded, as `paginate_link(on_page=)`
  does. The ServiceNow guide no longer claims that collection advances by the
  rows returned, which it never did.
- Integer options are validated like `max_pages`: `max_lambda`,
  `max_ecs_api_calls`, `max_projects`, `min_events` and `max_teams` must be
  positive integers, `cloudtrail_days` and `audit_days` non-negative integers.
  `int()` used to accept booleans and truncate fractions, so
  `cloudtrail_days: 0.5` silently switched CloudTrail lookups off, and text
  such as `"abc"` raised a bare `ValueError`; each is now a configuration
  error. The option descriptions and `docs/connectors/reference.md` name the
  requirement.
- `cloud.azure`: subscription ids from the subscription listing and resource
  ids from Resource Graph were used in ARM request paths unchecked. Requests
  removes `.`/`..` segments and `?` or `#` cuts off the appended suffix, so a
  crafted id could turn the app-settings POST into a POST to another ARM
  action (such as an account's `listKeys`) with the scanner's token, on the same
  host. A listed subscription id must now be a GUID and a resource id a plain
  ARM path (no `.`/`..` segments, `?`, `#`, `%`, `\`, whitespace or control
  characters); anything else is skipped with a warning and the scan is
  incomplete. Listed subscriptions without a string id used to be dropped
  silently and are now counted in that warning.

#### Review fixes: redaction and source decoding

- Redaction: a quoted value closes at its first quote that no backslash
  escapes. A JSON string that started with a credential and an escaped value
  (`{"log": "password: \"S\""}`, a ConfigMap's embedded YAML, Python's
  `'password: \'S\''`) closed at the escaped quote, only its backslash was
  withheld, and the credential was shown. Double-quoted option values
  (`--password "a\"S"`, `-u "user:a\"S"`, `echo "a\"S" | … --password-stdin`,
  `dotnet user-secrets set`) and `auth=(user, password)` pairs read `\"` the
  same way. A quote right after an assignment operator, or a line with no
  unescaped closing quote, keeps the former reading, and assignments are read
  the former way once more afterwards, so a Windows path ending in `\"` hides
  no credential after it.
- Redaction is linear again on comment blocks. Every word that ends a comment
  line (or precedes a comment) is read as a possible callee, and each skipped
  the rest of the block again to look for its `(`: about 250 KB of `#` or `//`
  comment lines took six seconds, and 1 MB took two minutes before it failed
  the redaction work limit and left the file incomplete. A call after a long
  block had its arguments lexed again for each word. A skipped comment is now
  remembered with where its trivia ends, and a `(` that several words reach is
  lexed and judged once.
- A Python source whose PEP 263 cookie names a codec that does not read ASCII
  as ASCII (`utf_16_le`, `utf-16-be` or `utf_32_le` without a byte-order mark,
  `utf-7`, HZ, EBCDIC code pages such as `cp037`) is a coverage gap
  (`binary or undecodable content in analyzable file`). The ASCII file was
  decoded into other characters, CJK text for UTF-16, and its imports and keys
  went unanalyzed with no gap reported; CPython refuses most such cookies. A
  codec error raised as a plain `UnicodeError` is reported as the same gap.
- Redaction: a `;` before an escaped line break or tab (`\n`, `\r`, `\t` in
  JSON-escaped text) ends an unquoted value. Read as a `;` inside the value,
  it ran `HOST=db;\n` into the next line and took that line's credential name
  with it, so `"HOST=db;\n:password => \"S\""` showed `S`.
- Redaction: the credential after an authorization scheme is never `=` signs
  alone. In `bearer => S`, `Bearer =~ S` and `bearer == S` the scheme rule took
  the operator's `=` as the credential, the assignment rules then found no
  operator, and `S` was shown. A credential glued to an `=` (`Basic =S`) is
  still withheld.
- Redaction: a braced ODBC connection string password is withheld whole, with
  anything a malformed value has after its closing brace up to the `;`. ODBC
  puts a value that holds `;` in braces and doubles a `}` inside them; the
  `Pwd=` rule read the value to its first `;` and showed the rest
  (`Pwd={a;S}`, `Pwd={a}};S}`). A brace that does not close within 256
  characters on its line, or opens a `{{` template, is read as before.
- `sanitize` costs each member of a set or frozenset as it costs a list item.
  The members were counted as leaves, so a set around a tuple nested more
  than 64 deep passed the structure check and its copy was cut short with a
  marker, and a set around a tuple of large texts was copied past the
  expanded-output limit. Both now fail the sanitization limit (exit 3), as
  the same tuple in a list does.
- Redaction: a URL inside another URL's text is read as a URL, so its
  userinfo, credential query fields and webhook path secret are withheld. A
  URL runs to the first blank or quote, so the second URL of a list
  (`redis://:a@h1,redis://:S@h2`, `amqp://u:secret@h1;amqp://u:secret@h2`)
  or one in a query value, path or fragment (`?next=https://u:secret@b`) was
  part of the first, whose authority alone was read, and its password was
  shown. Each inner URL is read up to the next one, after every other rule,
  and a text this changes is read once more, as the next sanitization would
  read it. A percent-encoded inner URL (`?u=https%3A%2F%2Fu%3AS%40h`) is
  still not decoded.

#### Review fixes: engine, incremental scans, plugins and CI

- Incremental scans: the fingerprint of an offline `code.github` or
  `code.gitlab` checkout follows `default_excludes`. With
  `default_excludes: false`, a change inside `vendor/`, `dist/` or `bin/`
  reused the cached result, so the scan exited 0 without the new evidence
  and `shadowscan diff` counted those findings as resolved.
- Incremental scans: the fingerprint records whether each skipped built-in
  directory that can hold first-party code (`bin/`, `build/`, `dist/`,
  `vendor/` and the like) holds a file. Adding `vendor/agent.py` to an empty
  `vendor/` used to reuse the cached result without the default-exclude
  warning.
- `identity.jwt` `tokens` are withheld from `repr()` and `str()` of a
  `ConnectorSpec` and its `ScanConfig`, like the credential-file locations.
  Opaque or malformed tokens match no value pattern, so a debug log or
  traceback that printed the configuration showed them verbatim.
- Process-mode plugins: a program the plugin starts no longer inherits the
  worker's result socket or multiprocessing's liveness pipe, and results
  carry a length prefix. A finished result used to be discarded as a
  timeout when a plugin ran `os.system` or a `Popen(close_fds=False)` helper.
  Connector timeouts above about 24.8 days no longer overflow the waits, and
  a deadline kill that races `Process.close()` no longer ends the scan
  without a report.
- Approval inventories: the approve-everything warning covers every pattern
  that matches all finding resources (`?*`, `*?`, ...), not only patterns
  made of `*`, and an inventory inside the offline clone directory
  (`input`) of a `code.github` or `code.gitlab` entry is reported like one
  inside a `code.filesystem` path.
- CI: every run outside a pull request has its own concurrency group, so a
  quick series of merges no longer replaces the pending push run of the
  middle commit. `make secrets` sets `pipefail`, and
  `tools/check_secrets.py` exits 2 when it is given no file instead of
  passing after checking nothing. A weekly run on `main` rebuilds the
  worker image from current Wolfi packages and rescans it with a fresh
  database.
- CI: the DCO check reads a sign-off after a `---` line in the commit
  message. Dependabot opens its YAML metadata with such a line, so its
  sign-off was never read and every Dependabot pull request failed the check.
- The CI lock takes Dependabot's eight pending development-tool updates
  (coverage 7.16.2, filelock 4.0.6, identify 2.6.20, librt 0.16.0, msgpack
  1.2.3, nodeenv 1.11.0, platformdirs 4.12.1, virtualenv 21.13.0), regenerated
  with the documented command and uv 0.12.18.

### October 2 review fixes (AI-assisted, not independently reviewed)

Fixes for defects found by an AI-assisted review of commit `d65b27f`. The
reviewers reproduced each one against that commit before it was fixed, and each
has a regression test. Neither the review nor the fixes had a second-person
review; the offline evaluation corpora are author-written and say nothing about
field precision. Behavior changes that affect an existing baseline are listed in
`docs/production.md` under "October 2 review changes".

#### Connectors: gateway, identity, low-code, SaaS and cloud

- `cloud.oci`: IAM policy statements are matched in linear time. The previous
  pattern retried a lazy scan from every `allow` word, so a 48 KB hostile
  statement took seconds (1 MiB about an hour) while holding the GIL and
  defeating `--connector-timeout-seconds`. A statement longer than 8192
  characters is a malformed record: that policy is skipped with a warning, the
  scan is incomplete, and valid neighbouring records are kept.
- `gateway.logs`: a client-chosen query string or fragment can no longer hide an
  inference call as a static asset or health probe (`POST
  /v1/chat/completions?_=.js` used to give 0 findings and a complete scan). Only
  the request path is tested and a probe name must be the last path segment, so
  `/healthz/../v1/chat/completions` is no longer excluded either. The number of
  excluded requests is reported as a scan note (a warning that does not make
  the scan incomplete).
- `gateway.logs`: `key=value` (logfmt) lines honor `\"` and `\\` escapes in
  quoted values, so a quoted client value can no longer inject `api_key=`,
  `user=` or `model=` pairs and attribute events to another caller. A line that
  repeats a key or leaves a quote open is malformed (scan incomplete); other
  lines are kept.
- Gateway provider attribution follows the RFC 3986 authority: userinfo up to
  the last `@` is dropped (an authority of `api.openai.com:443@evil.example`
  names `evil.example`), bracketed IPv6 literals lose brackets and port, and an
  empty host is `None`.
- Timestamps in microsecond and nanosecond epochs, Go `time.Time.String()`
  output and RFC 2822 dates are now parsed; they used to become empty, so
  events silently lost their time. Gateway records whose timestamp field no
  supported format parses are counted in a warning and make the scan incomplete.
- `identity.entra`: app-role and scope labels are resolved per resource. Another
  service principal that reuses a privileged role id with a harmless label can
  no longer relabel a grant (a `Mail.ReadWrite` grant used to print as a raw
  GUID, dropping risk from high to medium and losing `policy.privileged-scopes`).
  Conflicting labels for one resource and role keep the id and make the scan
  incomplete; a non-string `resourceId`/`resourceAppId` makes the record
  malformed.
- `lowcode.servicenow`: a page with fewer rows than `sysparm_limit` no longer
  ends collection of a table (ACLs filter rows after the limit is applied, so
  100 of 500 rows could come back with exit 0). Collection continues until an
  empty page; reaching `max_pages` first makes the scan incomplete. Each table
  costs one extra request.
- `lowcode.power-platform`: one flow, app or bot record that cannot be analyzed
  (signature-matching timeout or malformed fields) is skipped with a warning and
  the scan is incomplete; the records around it are still reported. A 3 MiB flow
  definition used to abort the connector with 0 findings. Signature matching
  examines at most the first 300000 characters of a definition, as the other
  low-code connectors do.
- `saas.generic` and `lowcode.zapier`: an export whose columns map to no app or
  zap name no longer gives 0 findings, a complete scan and exit 0. When no
  record has a name, a warning lists the accepted column names (never record
  values); when only some lack one they are skipped with a counted warning.
  Either way the scan is incomplete.
- `saas.slack`: a record naming another workspace (for example a Slack Connect
  bot with a foreign `team_id`) or an invalid workspace ID is skipped and
  counted in a warning, and the scan is incomplete; the workspace's other apps
  are still reported. One such record used to withhold every Slack finding.
- `identity.jwt`: without `jwks_url`, every token finding carries
  `metadata.verified: false` (with `verification_scope: "none"`,
  `issuer_verified: false`, `authorization_validated: false`) and a
  `jwt:signature` evidence line saying that claims are unverified. Previously
  there was no `verified` key, so an unsigned or tampered token read like a
  checked one. Confidence and risk are unchanged.

#### Engine, configuration, inventory, YAML and signature packs

- YAML with a malformed explicitly tagged scalar (`!!bool x`, `!!int >`,
  `!!timestamp ---`, an impossible date) is reported as malformed input
  everywhere ShadowScan reads YAML. PyYAML let `KeyError`, `IndexError`,
  `AttributeError` and `ValueError` escape, so one such file discarded the valid
  records of its neighbours, the connector error quoted the scalar, and a scan
  configuration with such a value printed a traceback. The bounded loaders raise
  `YAMLConstructionError` whose message gives only the line and column. A
  `RecursionError` during construction is a `YAMLResourceLimitError`.
- An integer or float scalar longer than 10,000 characters is a YAML resource
  limit (`YAMLResourceLimitError`; the scan is incomplete) instead of being
  converted. YAML 1.1 builds a sexagesimal integer (`1:1:1:...`) by repeated
  big-integer multiplication, which is quadratic: 80 KB took 0.5 s, 1 MB about a
  minute, and the 64 MiB input limit alone allowed hours.
- A connector or plugin that calls `sys.exit()` or raises another
  non-`Exception` `BaseException` during import, construction or collection is a
  failed connector: its error is recorded, the scan is incomplete (exit 3) and
  the report is still written. Previously the `SystemExit` ended the process
  with the plugin's exit status and no report, so `sys.exit(0)` read as a clean
  pass. `KeyboardInterrupt` still stops the scan.
- A scan warns when an inventory file or directory, or a file it loads, is
  inside a local path scanned by `code.filesystem` in the same run (scanned
  content, for example a pull request, could approve its own findings), and once
  per entry with a `*`-only resource pattern, which approves every finding. The
  warnings appear in a new `engine.inventory` entry of the report's `stats` and
  in table output; they do not make the scan incomplete or change the exit code.
  `shadowscan diff` ignores `engine.*` stats entries when it compares completion
  coverage.
- A configured custom signature pack directory that contributes no
  `.yaml`/`.yml` pack (empty, other file types only, or only symbolic links) is
  an error naming the directory and the skipped entries, in scans,
  `signatures list/show/test` and `python -m shadowscan.signatures.validate`.
  Symbolic links skipped inside pack directories, inventory directories or
  inventory globs are reported by name; links are still never followed. An
  inventory glob that matches no file is an error like a missing literal path
  instead of an empty inventory that marks every finding shadow.
- `shadowscan diff` requires each report's `summary.total` (and `by_surface` /
  `by_kind` counts when present) to match its `findings` array before missing
  findings can count as resolved. Emptying the `findings` array of a complete
  report used to print "1 resolved" with exit 0; such a report is now
  incomparable, its missing findings are listed as unknown and the exit is 3.
- `repr()`/`str()` of `ConnectorSpec` and of a `ScanConfig` holding it no longer
  print connector credentials. Values pass the report redaction rules and
  credential-file locations (`service_account_file`, `credentials_file`,
  `token_file`) are withheld.
- Inventories, configuration files, signature packs and reports accept a
  leading UTF-8 byte-order mark (spreadsheet "CSV UTF-8" inventories were
  rejected). A scan configuration that is a symbolic link, or reached through
  one (a Kubernetes ConfigMap mount), still fails, but the message now says that
  links are not followed and to pass the real path.
- Signature validation checks for empty-matching patterns with the same `regex`
  engine, flags and 0.1 s timeout as the matcher. A pattern only the `regex`
  module understands, such as `\p{L}*`, previously passed validation yet matched
  everywhere; it is now rejected.
- The default incremental state directory ignores an empty or relative
  `XDG_STATE_HOME`, as the XDG specification requires. An empty value used to
  put private state under `./shadowscan` in the repository being scanned.
- `shadowscan diff` text output no longer runs Rich's syntax highlighter over
  imported titles and resources, which was quadratic (a 50,000-character title
  took about 19 s).
- Inventory approval patterns are checked for citation markers (`[cite: 1]`,
  `[cite_start]`) in a single pass. The regular expression rescanned to the end
  of the item from every `[cite:` that had no closing `]`: 120 KB of `[cite:`
  took 13.6 s, and a megabyte about twenty minutes.
- `--incremental` with `--dump-records` logs that the cache is not used instead
  of disabling it silently. `docs/operations/ci.md` no longer recommends
  restoring incremental state with `actions/cache`: the fingerprint includes
  file identity, so a fresh checkout never reuses restored state.

#### code.filesystem: silent coverage gaps and denial of service

- Files that start with a UTF-8, UTF-16 or UTF-32 byte-order mark are decoded
  and the mark is removed. A UTF-16 `requirements.txt` (what Windows PowerShell
  5.1 `pip freeze >` writes), a UTF-16 `.env` and BOM-prefixed Python or JSON
  sources used to read as nothing and gave a complete, empty scan. A Python
  source is decoded with the codec its PEP 263 cookie declares; a codec that
  cannot decode it is a gap, and `punycode` is refused because its decoder is
  quadratic.
- A file the scanner analyzes by name that still holds a NUL byte in its first
  8 KiB (and is not a byte-order-marked text file) is a coverage gap, `binary or
  undecodable content in analyzable file`, so the scan is incomplete (exit 3).
  Compiled or packed artifacts without any file extension (ELF, Mach-O, wasm,
  archives, images, PDF) and names the scanner never analyzes stay quiet.
- The built-in directory exclusions are disclosed: a skipped non-empty `bin`,
  `build`, `dist`, `out`, `target`, `obj`, `coverage`, `vendor`, `third_party`,
  `thirdparty` or `external` directory is listed once per scan root in a warning
  (the scan stays complete). The new `default_excludes` option and `shadowscan
  code --no-default-excludes` scan them (also accepted by `code.github` and
  `code.gitlab`); version-control metadata stays excluded. The incremental
  fingerprint follows the option.
- Two quadratic patterns that hold the GIL, so neither
  `--connector-timeout-seconds` nor `--job-deadline-seconds` could interrupt
  them, are linear now and run under a matching budget: the agent-definition
  front matter (20 KB of blank lines took about 2.5 s) and the Terraform and
  CloudFormation IAM wildcard check (a 110 KB `.tf` made a scan take 137 s). A
  timeout is a file-level gap and the findings of other files are kept. Only
  horizontal whitespace may follow a front-matter marker now.
- `PackageReference` and `PackageVersion` items in `Directory.Build.props`,
  `Directory.Build.targets` and shared `*.props`/`*.targets` files are read as
  NuGet manifests (a `Microsoft.SemanticKernel` reference there gave no finding).
- `exclude` and `paths` must be lists of non-empty strings. A bare string was
  iterated per character, became the patterns `/` and `*`, excluded the whole
  tree and reported a complete, empty scan (`paths: "/srv/repo"` would have
  scanned `/`). The error names the option, never its value.
- A file or directory whose name is not valid UTF-8 no longer breaks the table,
  CSV, HTML, Markdown and SARIF reporters. Each undecodable byte is shown as a
  `\xNN` escape in reports while the file is still read under its real name.
- The directory walk uses an explicit stack. A chain about a thousand
  directories deep used to raise `RecursionError` on Python 3.11 and lose every
  finding.
- Python (or a notebook) that the running interpreter cannot parse, for example
  a PEP 695 `type A = int` on 3.11, adds a warning that import-bound analysis
  was skipped instead of dropping it silently; the lexical evidence is kept.
- An empty directory, or one holding only data files, named like an SDK
  (`openai`, `agents`, `langchain`) no longer makes every import of that SDK
  read as repository code. A `name.py` module, a package with `__init__.py` and
  a directory without it that holds Python source (a bounded look of 256
  entries and 8 levels) still count as local code.
- MCP servers that declare themselves disabled (`disabled: true`,
  `enabled: false`) are reported with the tag `declared-disabled` and
  `disabled: true` in `metadata.servers`, and `metadata.disabled` is set when
  none is enabled. The flag is client-specific (Cline honors it, Claude Code
  does not) and repository-controlled, so honoring it let a repository hide a
  server. `server_count` still counts the servers not declared disabled. The
  three `mcp-disabled-*` evaluation cases are now labelled present and the
  documented authored-corpus counts change from 29/48 to 32/45 positives and
  negatives; the evaluation harness scans cases with `default_excludes: false`.

#### Detection precision, labels and risk policy

- The top bucket of the `likelihood` field is renamed from `confirmed` to
  `strong` in every report format. It was only ever `confidence >= 0.85`, never a
  verification state; the thresholds are unchanged. Reports, `diff` baselines and
  incremental-cache entries that carry `confirmed` are still read, as `strong`
  (the label is derived from `confidence` and is not part of finding identity).
  Python callers: `Likelihood.CONFIRMED` is now `Likelihood.STRONG`. Anything that
  filters or counts on the string `confirmed` must accept `strong`; use
  `confidence` for thresholds.
- A data or prose file that only lists products no longer establishes a
  technology. A YAML, JSON, TOML, INI, XML, CSV, text or Markdown file that names
  four or more products through domains or environment-variable names, and holds
  no import, dependency, code, file-name, image, IaC, model or credential
  evidence, is a catalog (a proxy blocklist, an egress allowlist, a vendor policy,
  a copy of the signature packs). Its mentions count only for a signature with
  library evidence elsewhere in the project. A repository whose only content was
  such a list reported "LLM usage: CrewAI" at confidence 1.0 and high risk; it
  now yields no finding, and `metadata.catalog_mentions` lists the discounted
  files when a finding remains. Source code, manifest-named files (dotenv,
  Compose, Helm values, workflows, requirements, IaC) and data files naming one to
  three products are unchanged. Scanning `shadowscan/signatures/data` no longer
  reports LangGraph, CrewAI, Google ADK and Agno. Known cost: a bare data file
  that names four or more providers and is the only evidence (for example an
  Envoy routing table kept in YAML) is no longer reported; its deployment is still
  found through its dependency, import, image, IaC or file-name evidence.
- `Evidence` refuses a weight that is not a finite number between 0 and 1, at
  construction and on assignment. A NaN or infinite weight clamped to 1.0 inside
  the noisy-OR and produced confidence 1.0. A plugin that passes such a weight now
  fails its connector (the scan is incomplete) instead of reporting an inflated
  confidence.
- `options.risk_weights` keys under `capabilities` and `providers` are
  validated: a capability must be one of the ten capability names and a provider
  must be a provider signature id of the loaded packs, with a "did you mean" hint.
  `capabilities: {code-execution: 99}` used to exit 0 and change nothing; it now
  stops the scan setup. Tags stay open-ended, so an unfamiliar tag key is accepted
  and logged once per process.
- The risk score scales by confidence with exact arithmetic. Binary floats had
  drifted (`0.6 + 0.4 * 0.15` is `0.6599999999999999`), so a raw 75 at confidence
  0.15 scored 49 (medium) instead of 49.5, which rounds to 50 (high). Over raw
  totals 0 to 300 and confidences 0.000 to 1.000, five clamped scores move by one
  and one crosses a level (medium to high).

#### Remote collection: clones, listings and HTTP

- A scan that is terminated (SIGINT, SIGTERM, SIGHUP) or hits
  `--job-deadline-seconds` stops its in-flight `git clone` process groups and
  deletes the temporary checkout of the repository being scanned before it exits.
  Git used to keep running in its own session, without size or time limits and
  with the clone credential in its environment, and the checkout stayed on disk.
  No new clone starts afterwards, and an interrupted clone is not retried through
  the sampled API fallback. SIGKILL and OOM kills cannot be handled in process.
- `code.github` and `code.gitlab` read the organization, user or group listing to
  the end before the first repository is cloned or scanned, in an order a push
  cannot change (GitHub `sort=full_name`, GitLab `order_by=id`). The listing was
  ordered by recent activity and paged lazily, so a push to a not-yet-listed
  repository during the scan moved it behind the cursor: it was never examined
  and the scan stayed complete (exit 0). When more repositories exist than
  `max_repos` or `max_projects`, the covered subset is the first N in stable
  order. GitLab listings are compared with `X-Total` and `X-Total-Pages`; entries
  that do not add up make the scan incomplete. GitHub reports no total, so a
  repository deleted (not pushed) mid-listing can still hide another.
- A clone, and API mode, report Git LFS pointer files (small files opening with
  `version https://git-lfs.github.com/spec/v1`): `Git LFS pointer files in <repo>
  are not resolved; source coverage partial` makes the scan incomplete (an error
  under `strict_coverage`). Submodules are reported by the gitlink check merged
  from main.
- `topics`, `repos` and `projects` of `code.github` and `code.gitlab` must be
  lists of non-empty strings, and `max_repos`, `max_projects` and `clone_depth`
  whole numbers. `--set topics=llm` was iterated as the characters `l`, `l`, `m`,
  examined no repository and finished complete with exit 0; it now stops the
  connector with an error that names the option.
- Cloning requires Git 2.32 or newer: the clone protections travel in
  `GIT_CONFIG_COUNT` and `GIT_CONFIG_GLOBAL`, which an older Git ignores
  silently (a 302 to another host was followed and the scan finished). With an
  older or unidentifiable Git the connectors use sampled API mode and the scan is
  incomplete. Clones also verify received objects (`transfer.fsckObjects`).
- The HTTP destination policy refuses `168.63.129.16` (Azure wire server) and
  site-local IPv6 `fec0::/10`. A URL containing whitespace or control characters
  is refused instead of being cleaned by the parser while git rejects it, and an
  API tree that names a `.git` path component aborts that repository's snapshot.
- Documentation: the GitHub token needs Contents and Metadata plus Secrets,
  Variables, Codespaces secrets and Dependabot secrets (read). Without them every
  repository adds four identical `repository metadata HTTP 403` warnings and the
  scan exits 3. Use separate token variables for `code.github` (which reads
  untrusted content) and `saas.github-apps` (which needs organization admin).

#### Redaction and report output

- Credential redaction reads an operator whole. `'api_key' => '<value>'` used to
  become `'api_key' =[REDACTED] '<value>'` and `if token == '<value>':` became
  `if token =[REDACTED] '<value>':` (the marker replaced the operator's second
  character and the literal stayed in the report); `!=`, `||=`, `+=` and `.=`
  were not read at all. `=>`, `==`, `===`, `!=`, `!==`, `=~`, `:=`, `||=`, `&&=`,
  `??=`, `+=`, `-=`, `.=`, `?=` and `<-` now join a name to a value like `=` and
  `:` do: the literal is withheld and the operator is kept. A comparison with a
  sensitive name withholds only a quoted word or an opaque value, so `x == 1`
  and `key => users` stay.
- Provider tokens and JWTs are withheld when a word character precedes them:
  after a JSON-escaped line break or tab (`\n`, `\t`, `\x22`), a percent escape
  (`%3D`) or `_`, and, for the unmistakable prefixes (`sk-proj-` and the other
  `sk-<qualifier>-` forms, `ghp_`, `github_pat_`, `xox*-`, `AIza`, `AKIA`, `eyJ`),
  after a digit. Words that merely end in a prefix's text (`risk-`, `disk-`) stay.
  The JWT rule reads each run of base64url characters once (a 400 KB run of
  `eyJ-eyJ-...` took about a minute).
- URL userinfo is withheld whole when the password holds a raw `/`, `?` or `#`
  (`postgres://u:example#pw@h`, `https://svc:example7?x@llm-gw.example/v1`); URLs
  such as `https://host/path?x=a@b` are unchanged.
- `--dump-records` and report metadata withhold structured fields by the words of
  their name. `webhook_secret`, `signing_secret`, `bot_token`, `client_key`,
  `openai_key`, `pwd`, `passphrase`, `db_pass` and `jwtSecret` kept their raw
  values in the `NNNN-*.jsonl` dump of a `saas.generic` export. Cursors
  (`next_token`, `skipToken`), tokenizer tokens, switches (`requires_auth`) and
  the bare `key` of tags and objects are unchanged.
- A value of an unknown type in finding metadata or a record dump (bytes, a set,
  an exception, a plugin's object) is converted to text and redacted like any
  other value instead of reaching a report raw through `json.dumps(default=str)`
  or `repr`.
- Private-key blocks in PGP, RFC 4716 (SSH2) and PuTTY forms are withheld with
  their line count; `passphrase`, `SECRET_KEY_BASE`, `creds`, `db_pass`,
  `smtp_pwd`-style names, npm's `_auth` and an ODBC `Pwd=` member are withheld
  whatever the value, as are authentication headers named for a credential word
  (`curl -H "X-Token: v"`).
- `-f csv` neutralizes formula cells in one linear pass. A run of 20,000 CRLF
  pairs in a title, owner or evidence text took about five seconds and every
  doubling cost four times as much. The inserted markers are unchanged.
- The terminal shows zero-width characters, the byte-order mark and Unicode tag
  characters as escapes. A lone surrogate in a name read from an export no longer
  fails `-o x.csv|md|html` or prints a traceback; it is written as `\ud800`.
- Markdown reports defang `http://`, `https://` and `ftp://` after any non-letter
  and `www.` after any non-alphanumeric (`_https://host` was still an autolink),
  and SARIF message text escapes `\`, `[` and `]` so scanned text cannot write a
  `[text](destination)` link. These two follow the GFM and SARIF 3.11.6 rules and
  were not checked in a viewer. `SECURITY.md` lists what can still remain.

#### Source lexer

- The JavaScript lexer no longer treats a keyword-named property or method as a
  keyword. After `o.of`, `o?.in`, `this.#typeof` or `o.for(x)` a `/` is a
  division, so `o.of / 1; <code>; 2 / 1;` can no longer turn the code between
  the two slashes into a "regular expression" that hides it (the scan reported
  0 findings and was complete). `of` is a keyword only after an operand, and a
  regular expression after a spread is lexed as one. A `/` after `await` or
  `yield` cannot be classified without a parse and makes the file's lexical
  analysis incomplete. So does a regular expression after a closing brace that
  holds a quote, backtick or slash, which a block-then-regex statement could use
  to hide the rest of a line.
- Line comments end at the language's real line terminators: LF, CR, U+2028 and
  U+2029 in JavaScript and TypeScript (also inside a JSX tag), `?>` in PHP,
  escaped line breaks in Java. Replacing every LF of 1,221 real JavaScript files
  with CR, U+2028 or U+2029 changed what 838 of them hid before and none after.
  A backslash no longer escapes the quote of a JSX attribute string.
- The JSX look-ahead has a per-file allowance. A 250 KB run of `<A>(` took over
  a minute and discarded the results of the whole scan; it now ends in under a
  second as an incomplete file while the other files are scanned. A megabyte of
  `#` in Swift (13 s) and the Java escape search are no longer quadratic.
- A regular-expression literal up to 262,144 characters lexes completely. The
  `emoji-regex` tables found in most npm trees (10 to 17 KB on one line) used to
  make the whole scan incomplete.

#### CI, repository policy and developer tooling

- CI no longer cancels a `main` push run when the next push arrives:
  `cancel-in-progress` is `${{ github.event_name == 'pull_request' }}`. Before,
  29 of 83 `main` push runs ended `cancelled`, leaving merged commits without a
  complete CI record.
- The repository policy tests check workflows with either YAML extension (a
  `.yaml` workflow used to skip every check) and add invariants for: no
  `workflow_run` trigger; no job- or step-level `continue-on-error`; no
  `|| true`, `--exit-zero` or `--ignore-vuln`; no coverage floor below 80; no
  event text, `head_ref`, `ref_name`, `inputs.*` or `toJSON` dumps interpolated
  into `run:`; no publication command anywhere (`gh release`, `twine upload`,
  `uv|poetry|hatch publish`, `pypi-publish`, `docker push`, `git push`); a
  release workflow that stays `workflow_dispatch`-only with `id-token: write`
  only in its checkout-free `attest` job; Dockerfiles with digest-pinned `FROM`,
  a final non-root `USER`, no `ADD <url>` and hash-checked `pip install`; and an
  allow-list-style `.dockerignore`. Each rule runs on the real file and on a
  mutated copy (32 mutations) to show that it still catches the violation.
- The `no-hardcoded-secrets` hook recognises many more credential shapes: of 28
  planted synthetic examples the previous patterns found 7 and the new ones find
  all 28. They include GitHub `github_pat_`/`gho_`/`ghu_`/`ghs_`/
  `ghr_`, AWS `ASIA` keys and `aws_secret_access_key = ...`, Google `AIza`, Slack
  `xoxp-`/`xoxa-`/`xoxr-`, Hugging Face `hf_`, Stripe live keys, signed JWTs,
  PEM private-key headers, Azure `AccountKey=`/`SharedAccessKey=` and passwords
  in URLs. It prints at most four characters plus the match length (it used to
  print twelve), fails on an unreadable file, runs on every text file, and CI
  runs the same script over `git ls-files`.
- `tools/coverage_gate.py` fails closed: a module with statements in an unlisted
  connector family, in a nested package, or directly under
  `shadowscan/connectors/` (other than `base.py`, `common.py` and `offline.py`)
  fails the gate with a message naming the reason, where it used to be skipped
  while the gate printed "Checked N modules". A malformed coverage report exits
  2. `tests/test_coverage_gate.py` pins the 75% floor and the exit codes.
- `make audit` (and so `make check`) audits the four hash locks as CI does.
- `make secrets` (part of `make check`) runs the credential check that CI runs
  over every tracked file; a consistency test pins both commands.
- `tests/unit/test_regex_linearity.py` fails when a module-level regular
  expression is superlinear on hostile input (CPython's `re` cannot be
  interrupted, so such a pattern defeats the connector and job deadlines), and
  times the redaction passes end to end. Mutation tests were added for the
  credential-mixing guard, symlink reporting in inventory globs, the incremental
  cache's refusal to store incomplete results, the shipped YAML alias budget
  and the Makefile coverage floor.
- Documentation: `docs/testing.md` lists the expected skips (core-only installs
  skip about 60 cloud-SDK tests, Git < 2.45 and root-only permission tests);
  `docs/evaluation.md` states the real 5 to 7 files per realistic-corpus case; and
  `docs/connectors.md` documents the 44 connector configuration keys that no
  connector page named. A consistency test now fails when a key reported by
  `shadowscan connectors --json` is undocumented.

### October 2 production review corrections

- npm dependency aliases are attributed to their declared registry target,
  preserving development-dependency status. Invalid alias targets mark source
  coverage incomplete while valid neighboring dependencies remain visible.
- CSV inventory parsing preserves embedded line separators in quoted fields,
  so resource and account approvals retain their declared identity.
- Imported evidence validates nullable text fields and object attributes before
  postprocessing. Malformed incremental entries trigger a fresh scan instead
  of reaching correlation or confidence calculations.
- Notion and Atlassian collection reject provider error envelopes even when
  empty collection fields are present. Google Workspace rejects malformed user
  suspension flags with incomplete coverage and retains valid neighboring users.
- Wheel validation uses a unique private temporary environment and working
  directory, with cleanup on successful and failed validation.
- The connector coverage gate requires the report to name every module under
  `shadowscan/connectors/` in the checkout and rejects malformed counts. Its
  scope (every connector module, statements and branches) and 75% minimum are
  unchanged.

### Code structure and developer experience

- **Module boundaries:** finding merge logic lives in `shadowscan/merge.py`
  and cross-surface correlation in `shadowscan/correlation.py`; the engine
  imports both. The public API is unchanged.
- **Property-based tests:** Hypothesis tests for the redaction module check
  idempotency, crash-freedom on arbitrary Unicode and removal of known token
  formats. Hypothesis is part of the `dev` extra and the CI lock.
- **Parallel test runs:** `pytest-xdist` joins the `dev` extra, with a
  `make test-parallel` target.
- **API reference:** mkdocstrings pages for the core modules are part of the
  documentation site.

### October 2 production hygiene review

- Connector diagnostic sanitization retains credential context across errors,
  warnings and skip reasons. JSON statistics are sanitized together, matching
  the other report formats. A sanitization limit clears omitted skip reasons.
- GCP, Azure, OCI and Slack live collectors preserve their locally assigned
  record classification and collection scope over provider fields. Invalid
  discovered GCP project identifiers produce incomplete coverage rather than
  entering authenticated request paths.
- MCP tool attribution ignores commented and string examples, and counts only
  referenced enum members. Recheck capability labels and enforcement baselines
  when comparing reports made before this correction.
- The secret-pattern checker escapes control characters in the file names it
  reports, so a crafted name cannot forge a report line or a workflow log
  command. It runs over every tracked text file in CI, `make check` and the
  pre-commit hook; the test, signature-pack and evaluation-corpus exemptions
  remain explicit, and this pattern check is not a complete secret detector.
- Local coverage and wheel validation use private temporary paths with cleanup
  on success or failure. Wheel validation refuses multiple stale scanner wheels.
- Evaluation rejects ambiguous case/Unicode path layouts, file/directory
  collisions and overlong UTF-8 filename components before materialization.
  Existing labeled files are never overwritten.
- Gateway UTC timestamp validation runs before caller state changes. An invalid
  timestamp or interval end marks coverage incomplete without suppressing valid
  neighboring observations for the same caller.
- Tenant-canary verification indexes exact resource identities instead of
  comparing every control with every collected record. Dump verification reads
  lines incrementally under the existing file-size cap; acceptance selectors
  and scope requirements are unchanged.
- Live ruleset readback found both rulesets active, with independent approval
  required, but the required-check list still omitted `CI gate`. This review
  does not alter repository settings, publish a release or establish live
  tenant acceptance or independent human review.

### October 2 review remediation

- Gradle and Dockerfile dependency extraction, and the content matching of
  those manifests, ignore comments while keeping quoted strings and active
  declarations; a credential inside a comment is still reported. Named Python
  URL requirements keep their declared package identity. The paired regression
  cases are authored test evidence, not a fresh field-accuracy measurement.

### October 2 review corrections

- Name/value credential redaction caches line bounds and the first content
  position instead of repeatedly scanning or copying growing record prefixes.
  This removes quadratic work on long lines of repeated record names while
  preserving credential withholding and list boundaries. Deterministic
  character-work regressions complement the existing timing checks.

- JavaScript and TypeScript source calls that exceed the bounded semantic
  analysis budget now make coverage incomplete instead of silently losing
  agent-construction evidence. Valid neighboring findings are retained.
- Binary-looking `.ts` source is no longer silently classified as MPEG video
  from packet bytes. Source comments can mimic that prefix while hiding agent
  construction. Such files make coverage incomplete; trusted operators may
  explicitly exclude known media paths from the intended scan scope.
- Failed incremental cache-decision hooks now make connector coverage incomplete,
  retaining built-in validation diagnostics and exposing only exception types
  for plugin hook failures.
- Zapier blank-row tolerance requires a recognized identity column; all-blank
  records with unknown JSON keys or CSV headers make coverage incomplete.
- Generic Genkit initialization and flow/tool declarations no longer establish
  an agent or configured tool-use capability. Supported concrete agent
  definitions and model calls with registered tools retain detection.
- The shared HTTPS transport bounds response acquisition as well as body
  delivery, interrupting slow status/header delivery without releasing an
  actively cancelled connection back into the pool. System DNS and external
  SDK calls still require a process/job supervisor for a hard execution limit.
- CI checks the exact built worker image for HIGH/CRITICAL OS and Python
  vulnerabilities and retains a container SBOM, scan result and image identity.
  Vulnerability database acquisition and scanner errors fail the gate.
- The worker build upgrades base Debian packages from the enabled archives
  before installing Git and certificates, applying available security fixes.
  Unfixed HIGH/CRITICAL advisories continue to block the container gate.
- Release candidate evidence now checks active merge rules, independent-review
  requirements, strict `CI gate`/CodeQL checks and bypass visibility. An offline
  settings-patch command preserves additional protections while adding the
  aggregate check, binding required checks to GitHub Actions and requiring
  final-push approval, resolved review threads and deletion protection.
  Repository administration remains a separate action.
- These changes add authored regression evidence. They do not establish live
  tenant acceptance, fresh field accuracy or independent human approval.

### October 1 scan integrity remediation

An AI-assisted audit of the unreleased candidate (not independent human review)
found places where a scan could finish `complete` while skipping content or
persisting credential-shaped text. These changes close the confirmed gaps; each
has a regression test.

- **Silent coverage gaps now mark the scan incomplete.** A source or config file
  with a NUL byte in its first 8 KiB and no byte-order mark (UTF-8/16/32 files
  with a byte-order mark are now decoded instead; other invalid UTF-8 is still
  decoded with replacement characters), a FIFO, socket or device named like a
  config file, a directory named like an MCP configuration file (`.mcp.json/`),
  a directory tree nested too deeply for the Python 3.11 walker, any file
  without a supported export suffix in a connector's offline input directory (a
  rotated `access.log.1`, a `.bak` or `.zst` copy, a `README.md`),
  `saas.generic` rows without a resolvable name, wrong-schema `saas.generic` and
  `lowcode.zapier` objects, and negative or absurd gateway token and cost values
  each produce a specific incomplete diagnostic. A symlinked card inside an
  inventory directory stops setup instead of being skipped. A recognized binary
  artifact (executable, archive, image, PDF or SQLite database, by its header)
  stays a quiet skip when it has no file extension, when only a directory-wide
  signature glob such as `.cursor/rules/**` selected it. An analyzable source
  extension, including `.ts`, and unrecognised binary content remain a gap.
- **Disclosure without failure.** Code scans list default-excluded directory
  names (`build`, `vendor`, `external`, ...) once per root, and default-scope AWS
  and GCP scans name the regions or locations that were not scanned. Both are
  notices that do not mark the scan incomplete. Reports list disabled or
  `--only`-excluded connectors in `collection_scope.not_run`. The AWS CloudTrail
  management-events notice no longer forces exit 3.
- **Credential redaction.** Newly withheld: values of the `--passphrase`,
  `--pat` and `--auth` options (withheld as a `--password` value is, so a
  lowercase word after a space stays; in an argv list the value after these
  options and `--pass`, `--pwd` or `--password` is always withheld); whole
  armored PGP private key blocks, including one after a credential name; every
  cookie in a `Cookie` header; compact headers and passwords without a space
  (`x-api-key:S`, `password:S`); unquoted values containing `;`; values in
  escaped-quote JSON; the URL query keys `auth`, `pwd` and `pat`; Fireworks
  `fw_` keys; and provider tokens next to non-Latin text. Sets and bytes are
  traversed. Some text is over-redacted: `ffmpeg -pass 1` loses its pass
  number, `NAME=S;rest` loses the text after `;`, and `Authorization:` loses
  its scheme name. A quadratic JWT pattern that could stall a scan for minutes
  was replaced by a linear one. The unkeyed SHA-256 `credential:sha256:` digest
  is unchanged; see `docs/production.md`.
- **Gateway attribution.** Access-log hosts are read only from the trailing
  unquoted `host=` token, so a user agent or path cannot hide or forge LLM
  traffic. Generic vendor hosts (`api.cloudflare.com`, `huggingface.co`) are
  hints rather than LLM-usage evidence, except Cloudflare Workers AI inference
  paths (`/accounts/<id>/ai/run/`, `/accounts/<id>/ai/v1/`), which stay LLM
  traffic. PyPI `swarm` no longer maps to OpenAI Swarm. Scope names are matched by bare name across providers, so names that
  are routine on another provider no longer match `policy.privileged-scopes`:
  OIDC `offline_access`, Salesforce `full`, `web` and `refresh_token`, GitLab
  `api`, GitHub `workflow` and Slack `admin`. Findings that held only these
  scopes lose that risk factor and can drop a risk level.
  `identity.jwt` ignores empty or false agent claims, labels GitHub Actions,
  GitLab CI and Kubernetes service-account tokens `workload` (a Kubernetes
  service-account subject or claims make a `workload` for any issuer, including
  GKE), counts a GitHub Actions `actor` or `triggering_actor` as an agent hint
  only when it names an AI agent or product, and marks tokens scanned without a
  JWKS (`signature_verified: false`). Gateway registry matches on
  operator-asserted or unverified caller names carry
  `metadata.registry_match_assurance` and the `registry-identity-unverified` tag.
- **Engine and reports.** A connector or third-party plugin raising
  `SystemExit` or another `BaseException` other than `KeyboardInterrupt`, while
  it is imported, its class is verified, an engine hook runs or it collects, is
  an incomplete connector (exit 3 with a report), not a process exit. Only the
  exception type is reported. `KeyboardInterrupt` still ends the scan. Incomplete CSV
  reports start with a `SCAN-INCOMPLETE` status row. Saved CSV and HTML render
  terminal control characters visibly. `shadowscan diff --fail-on-new` exits 2 on
  new or higher-risk findings. Exit codes 1 and the usage-error 2 are documented.
- **HTTP client.** Okta `X-Rate-Limit-Reset` is honored, retries stop at the
  connector deadline, a response body must also finish before that deadline
  (in addition to the read deadline below), and `identity.jwt` accepts an
  explicit `ca_bundle` for private PKI (verification stays on; a relative path
  resolves beside the configuration file).
- Dialogflow CX and Discovery Engine use their regional endpoints. ServiceNow
  collection pages until an empty page. A weekly scheduled `pip-audit` workflow
  was added. The Anthropic signature recognises `sk-ant-oat01-` OAuth tokens.
  Unquoted Cursor `globs: **/*.ts` no longer causes a false exit 3,
  and `host_of` strips URL userinfo and handles IPv6 literals.
### October 1 review corrections

- Named Python direct-reference requirements retain their declared package
  identity before URL or VCS inference. Extras, fragments, environment markers
  and source lines remain available as evidence.
- Python semantic analysis ignores constant-false loop bodies, preserves the
  applicable loop `else` path, joins uncertain loop bindings conservatively,
  and stops unreachable statements after explicit local control transfers.
  This is bounded source analysis, not interprocedural execution proof.
- Optional Git enrichment streams stdout and stderr under a combined 16 KiB
  limit, caps accepted identity fields, and terminates children on overflow,
  cancellation or deadline. Limit hits retain code findings and mark coverage
  incomplete rather than publishing unbounded metadata.
- Credential redaction covers additional constructor syntax, environment
  fallback literals, credential records and explicitly named command/query
  values. Regenerate stored reports and incremental baselines under the revised
  policy before sharing them; ambiguous comments and arbitrary computed values
  still require confidential handling.
- Production evidence policies can add aggregate and per-kind 95% Wilson
  lower-endpoint thresholds. Legacy point-estimate policies remain compatible;
  successful decisions expose the lower endpoints. The example uses confidence
  gates and per-kind sample floors; these are operator-selected targets, not
  evidence of measured production accuracy.
- Added a versioned active merge policy and bounded snapshot checker requiring
  the aggregate CI gate, bound check origins, final-push review and no bypass
  actors. They do not change live repository settings. Administrator activation,
  independent human review, fresh holdout labels and tenant acceptance remain
  external requirements.
### October 1 review remediation

Fixes and recommendations from the 2026-10-01 repository review. Upgrade
steps are in docs/production.md ("October 1 review changes").

- **Exit codes:** usage errors exit 1 instead of 2, so exit 2 only means a
  complete scan reached `--fail-on`.
- **Gateway identity:** `diff` lists scan-local gateway findings under
  `not_comparable` instead of as new. The opt-in `SHADOWSCAN_IDENTITY_KEY`
  (environment only, at least 32 bytes) keeps gateway IDs and collection scope
  stable across scans; git child processes never receive it.
- **Confidence:** outside the code surface, repeated evidence of one signal
  counts once. n8n, Make and Zapier findings score all their evidence before
  they are finalized.
- **Inventory:** cards accept `discovery.discriminators`; `inventory stubs`
  binds each card to its own finding and writes plain-string names.
- **Cloud:** `cloud.aws` parses role trust policies (`Deny`, `NotAction` and
  `NotPrincipal` never establish trust; a malformed policy makes the scan
  incomplete). `cloud.oci` converts SDK models without silently dropping
  fields. Every connector validates `max_pages` and caps it at 1000.
- **Detection:** Vercel AI SDK multi-step tool loops, including AI SDK 7
  `isStepCount`, are agents. Custom-pack framework code patterns apply in
  Python and JavaScript. ShadowScan, Semgrep, Sigma and gitleaks rule files are
  treated as data and listed in `metadata.detection_rule_files`.
- **Threshold filtering:** `--min-confidence` removes `related` links and
  `runtime_activity` references to omitted findings.
- **Timestamps:** microsecond and nanosecond epoch values are parsed.
- **Redaction:** keys passed positionally to well-known LLM SDK calls are
  withheld, including the endpoint-`Uri` overloads. Long blank runs no longer
  make the Python 3.11 tokenizer quadratic, and Python 3.12+ codec errors no
  longer make a file's analysis incomplete.
- **Removed:** the unused `safe_yaml.bounded_safe_load_all` and
  `HttpClient.requests_made`; use `strict_bounded_safe_load_all`.
- **Evaluation:** `tools/evaluation/current_idioms_corpus.json` (24 cases)
  runs in `make evaluate` and CI.
- **Tests and CI:** tests resolve hostnames hermetically and fail on outbound
  connections. Both coverage floors count branches, and the connector floor
  covers every module under `shadowscan/connectors/`. Coverage is traced on
  Linux 3.11 only, and a traced run takes about half as long. Matcher budgets
  are generous in tests unless a test opts into the shipped values. CI never
  cancels a running `main` build and runs the secret hook over tracked files.
- **Governance and docs:** `.github/rulesets/require-ci-and-review.json` versions the intended
  `main` ruleset; the README regains its project-status section and an OpenSSF
  Scorecard badge; RELEASE_NOTES.md summarizes releases for users; ADR-004
  and ADR-005 propose a parsing strategy and code-scanner module boundaries.
### October 1 review fixes: bounded matching, link walks and record tolerance

Fixes for the findings of an AI-assisted repository review (not an
independent human review); each behavior change has a regression test.

- `code.filesystem`: the IaC wildcard-action and agent front-matter patterns
  now run on the bounded regex engine with possessive whitespace, under the
  per-input matching budget. Before, a planted file (`Action:` followed by a
  long run of spaces, or `---` followed by many blank lines) backtracked
  quadratically in stdlib patterns that nothing could interrupt, which could
  hold the connector past its deadline and discard every code finding.
- `code.filesystem`: symbolic links now count toward `max_files`, link checks
  stop at the connector deadline with an explicit error (`connector deadline
  reached while checking symbolic links`), and the project lookup behind each
  link is cached per directory. A tree planted with thousands of links was
  quadratic and uncounted. Scans of repositories holding more links than the
  remaining `max_files` budget become incomplete; raise `max_files` or exclude
  the link directories.
- `code.filesystem`: a JSON, YAML or TOML file that merely contains the words
  `"mcp"` and `"servers"` but configures no MCP server (an exported workflow
  tagged `mcp`, a template with such a comment) is ordinary configuration
  again. Before, it was treated as MCP configuration and the IaC,
  configuration and lexical passes skipped it without a diagnostic, hiding
  the workflow or the wildcard IAM grant. Dedicated MCP file names
  (`.mcp.json`, `claude_desktop_config.json`, ...) are unchanged.
- `code.filesystem`: a credential in a notebook code cell is counted once;
  the raw document's copy of the cell no longer doubles the count and the
  confidence. Outputs and markdown cells are still scanned.
- `cloud.aws`: a malformed provider record (a function without an ARN, an
  endpoint without a name, an alias version that is not a string) skips that
  record with a warning and incomplete coverage instead of aborting every
  remaining service and region. Failed SDK calls now report the operation
  and the provider error code (`cloud.aws: get_agent access denied
  (AccessDeniedException)`), never the message text, which can echo request
  arguments or encoded policy context. `cloud.gcp` treats a service record
  without a config name the same way.
- `identity.entra`, `saas.microsoft-teams`, `lowcode.make`: response-derived
  identifiers are percent-encoded before they enter a request path.
  `max_app_role_lookups`, `max_users` and the automation connectors'
  `max_pages` must be positive integers; a zero or non-numeric value now
  stops the connector with a configuration error instead of being coerced.
- Gateway timestamps: an eight-digit `yyyymmdd` value is a calendar day.
  It was read as epoch seconds and attributed callers to 1970.
- One `failure_summary` helper replaces eighteen copies of the HTTP-status or
  exception-type expression in connector diagnostics (no output change).
- Documentation: the README states the usage, setup and `diff` exit codes
  and carries the OpenSSF Scorecard badge the roadmap refers to;
  `docs/connectors.md` lists the GitHub credential-name permissions and adds
  least-privilege rows and option lists for Slack, ServiceNow and Notion. A
  repository test now checks the "25 of 27 connectors ship fixtures" claim.
### Confined file portability and plugin deadlines

- On platforms exposing `O_NOFOLLOW_ANY` without Linux `O_PATH` (including
  supported macOS versions), confined file reads use one kernel-checked path
  lookup, including reads relative to an already-open scan root. This avoids
  opening every ancestor for reading while still rejecting symbolic links in
  every component. FIFO protection and regular-file verification remain in
  force; paths are never resolved through symlinks as a fallback.
- Signature directory traversal now fails on unreadable subdirectories and
  enforces its entry budget for directory-only trees. A partial signature pack
  must not silently become an accepted policy or digest.
- `pytest` console invocations can import checkout-only evaluation and canary
  tooling without a caller-supplied `PYTHONPATH`; macOS CI exercises this entry
  point as part of the full suite.
- Optional `options.plugin_execution: process` / `--plugin-execution process`
  runs approved third-party connectors in dedicated spawned workers, including
  plugin import. Connector deadline expiry terminates the worker and marks its
  results incomplete. A worker also stops itself two seconds after that
  deadline, or as soon as the scanner process exits (including the job-deadline
  watchdog, SIGTERM and SIGKILL), and a `KeyboardInterrupt` during collection
  kills running workers. Processes a plugin starts itself are not terminated.
  Workers write record exports only into the private export directory the
  scanner prepared, and exit as soon as their result is sent, so lingering
  non-daemon plugin threads cannot turn a delivered result into a timeout.
  Result transport serializes like the JSON report (`str()` for values such as
  `datetime`, sets and bytes; NaN and infinity still fail closed).
  Crashes, malformed output and output above the 16 MiB transport
  limit also fail closed. The default remains `thread`; built-ins retain their
  existing execution path. Process mode provides lifecycle isolation, not a
  security sandbox or rollback of external effects.

### October 2 repository hygiene

- Agentforce metadata (`GenAiPlanner`, `GenAiPlugin`, `GenAiFunction`,
  `GenAiPromptTemplate`, `BotDefinition`, `BotVersion`) that declares XML
  entities or attribute defaults is no longer parsed and makes the scan
  incomplete (`structured configuration declares XML entities or attribute
  defaults; not parsed`), because Expat before 2.4 does not bound entity
  expansion. Other XML files with such declarations are skipped without a
  syntax warning; files without them are parsed as before.
- `docs/connectors/reference.md` is generated from the connector classes
  (`python -m tools.connector_reference`, checked by the docs consistency
  tests), so documented keys cannot drift from `config_keys`.
- Development: mypy checks every tool package and the pre-commit hook runs it
  with the project's settings; ruff reports broad exception handlers (`BLE`),
  and each suppression must state its reason; CodeQL cancels superseded
  pull-request analyses; `.gitignore` covers local credentials and tool state,
  and license texts are kept byte-exact.

### October 1 discovery review corrections

- Code collection identifies declared submodules whose source has not been
  materialized and reports incomplete coverage instead of a complete empty
  result. Remote clone collection also checks the Git tree for submodule
  entries. Submodule URLs are never fetched automatically.
- Ordinary Spring AI `ChatClient` and LangChain4j `AiServices` construction,
  and standalone Java tool declarations, no longer establish an agent or
  tool-use capability. Explicit agent construction and bounded, concrete tool
  registration remain evidence.
- Import-bound source calls distinguish configured workload capabilities from
  features merely offered by their framework. Empty tool/handoff collections
  and disabled delegation no longer add those capabilities or their risk
  factors. Review changed findings and rebuild enforcement baselines.
- Authored evaluation cases now check capability labels as well as kind and
  product attribution. The frozen independent corpus and its labels are
  unchanged; these regressions do not establish fresh field accuracy, live
  tenant acceptance or independent human review.

### October 1 code.filesystem coverage and precision

- A coding-agent instruction document that links to another one in the same
  project with the same test classification (`CLAUDE.md` to `AGENTS.md`) no
  longer marks the scan incomplete. The target is scanned at its real path and
  the alias-only file name is not reported as a second agent. Links across
  projects or into and out of test paths, and directory links, stay gaps.
- Credential policy: a real-format credential under a test, fixture or
  `cassettes/` path stays a `secret` finding and now follows the project
  test-code policy: half weight, lower confidence and risk, and the
  `test-code-only` tag unless `include_tests` is set. Recorded cassettes
  capture real traffic, so such keys are downweighted, never dropped.
- A coding-agent configuration finding now needs more than an environment-variable
  or display-name mention such as `GOOSE_PROVIDER`. Config files, instruction
  documents, dependencies and code patterns such as a workflow step still
  establish it. In test paths only config files and instruction documents count
  unless `include_tests` is set.
- MCP parsing skips `*.lock.yml` and `*.lock.yaml` files (compiled agentic
  workflows) and cookiecutter `{{...}}` template paths, which no longer raise an
  invalid-MCP error. Other GitHub Actions workflows are still parsed for MCP
  servers passed as JSON step inputs (see the field scan follow-up below).
- Not changed: signatures, risk scoring and inventory labeling. Oversize
  recorded fixtures (`cassettes/`, test data) stay coverage gaps, because they
  can hold real credentials; skipping them unread is an operator decision
  through `oversize_skip_globs` (for example `*/cassettes/*`). Examples,
  templates and benchmarks are not discounted like tests, because the bundled
  corpora label their agents as real. Evidence is offline regression tests and
  corpora only; it is not a measured field precision.

### October 1 field scan follow-up

Fixes for defects found by scanning five public agent repositories (see
`archive/reviews/field-scan-2026-10-01.md`); each has a regression test.

- The JSX lexer no longer marks valid TSX incomplete. It skips explicit type
  arguments on elements (`<Select<Option> ...>`, `<Form<{ email: string }>>`),
  comments between attributes (a comment just before `>` no longer makes the
  tag self-closing), and treats `<Text>(...)</Text>` as an element
  unless the parenthesized group is followed by `=>` or a return type. In the
  field scan this removed 139 false incomplete files; unbalanced tags still
  fail closed.
- Gemini CLI's `httpUrl` is an MCP endpoint alias. Such extension manifests no
  longer make the scan incomplete, and their remote servers are reported. A
  header or env value that is only a shell-style reference (`Bearer $TOKEN`) is
  not an inline credential.
- GitHub Actions workflows that pass MCP settings to an agent action no longer
  fail strict YAML parsing on the `on:` key. Servers embedded as JSON step inputs
  are reported as MCP findings; unparseable embedded settings stay incomplete.
- `GOOGLE_GENAI_USE_VERTEXAI` no longer attributes the Google Agent Development
  Kit. It remains Vertex AI provider evidence.
- Exported workflows under test or fixture paths follow the project test-code
  policy: half weight and the `test-code-only` tag unless `include_tests` is set.
- A `setup.py` marks a project root only when it references setuptools,
  distutils or scikit-build, or calls `setup(...)`. Ordinary modules named
  `setup.py` no longer split a package into a separate project; an unreadable
  file keeps the previous behavior.
- An MCP argument assigning a file path to a credential-file variable
  (`GOOGLE_APPLICATION_CREDENTIALS=/app/key.json`), or one whose only redacted
  part repeats a variable reference from `env` (`-v ${KEY_FILE}:/app/key.json`),
  is still redacted but no longer marks the server as carrying an inline secret.
  Literal values remain inline secrets.

### Completeness, report safety and credential policy (2026-09-28)

Behavior changes to review before upgrading (see
[production](https://github.com/aisecnomad/Project-Nexus/blob/main/docs/production.md#completeness-report-and-credential-changes)):

- **Credential policy:** the scan-wide `options.allow_instance_credentials`
  now replaces `allow_instance_credentials` in every connector entry. Only
  `cloud.*` entries were replaced before, so a third-party connector's own
  entry could grant it instance-credential approval. The scan-wide value
  still goes to every `cloud.*` connector, plugins included, and now also to
  any plugin that declares the cloud surface or documents the key in
  `config_keys`; with the default `false` this only denies. Built-in
  connectors behave as before.
- **New incomplete scans (exit 3):**
  - A shared HTTP response body must arrive within twice the client timeout
    (60 seconds by default), not only within the 30-second per-read timeout.
    A slower body, for example from a slow-drip server, is aborted (`HTTP
    response exceeds the read deadline`) and the connector's collection is
    incomplete, never truncated.
  - `code.filesystem` opens each scan root once and reads every file, and
    `CODEOWNERS`, relative to it without following a link in any path
    component; before, only the final component was protected. A directory
    replaced by a link during the scan fails the reads below it
    (`file could not be read`). A root that cannot be opened this way is
    reported, by its `label` when one is set, as
    `could not open the scan root safely (<reason>)`.
  - `code.gitlab` skips a group listing entry whose project `id` is not a
    positive integer (`group project listing entry has no valid numeric id;
    project skipped`) and scans the other projects. Such an id used to reach
    request paths, where it could send the token to another API endpoint,
    and a missing id aborted the whole listing.
  - `code.github` skips an org or user listing entry whose `full_name` is not
    a plain `owner/name` (`repository listing entry has no valid owner/name;
    repository skipped`). It used to reach request paths and the clone URL.
- **Changed diagnostics (these scans were already incomplete):**
  - A YAML value PyYAML cannot construct, such as an impossible date or an
    integer over 4,300 digits, is reported as malformed YAML: `invalid YAML`
    for conda environment files (was `manifest parsing failed (ValueError)`)
    and `invalid agent definition YAML` for agent front matter (was
    `file analysis incomplete (ValueError)`). The agent definition is now
    listed where it used to be dropped, which adds `agent_definitions`
    metadata and can raise the finding's risk score. Scan configuration and
    inventory files with such a value still fail at setup (exit 1), now with
    `ConfigValidationError` and `InventoryValidationError` instead of an
    unclassified `ValueError`.
  - A cancellation or connector deadline while `code.filesystem` builds a
    credential finding ends the connector, as it does everywhere else,
    instead of becoming that file's `credential analysis incomplete` error.
- **Scans that now complete:**
  - A Python module none of whose imports can resolve to a signature no
    longer makes a scan incomplete when it exceeds `max_ast_nodes` or the
    import binder's nesting limit: the binder, which could add no evidence
    there, is skipped. The check is linear in the module and matches at most
    4,096 distinct import statements; other modules keep the
    `import-bound analysis skipped (…); lexical evidence retained`
    diagnostic. A scan of installed libraries such as mypy, pip, requests and
    rich, which exited 3 because of `mypy/checker.py`, now completes.
  - Configuration, inventory, signature pack, `diff` report and offline
    export files below a traverse-only directory (mode `0711`) now open:
    directories are opened for traversal only (`O_PATH` on Linux), not for
    reading.
  - An unrendered Helm, Jinja or Go-template YAML file, whose placeholders
    read as mapping keys (`image: {{ .Values.image }}`) or whose conditional
    branches repeat a field, no longer reports `structured parsing incomplete
    (YAMLIntegrityError)`. Such a file is not YAML until rendered, so its
    excerpts use lexical redaction, as for any template the YAML parser
    rejects. Plain YAML with duplicate or non-finite data still fails closed.
- **Report redaction** withholds more credential forms, in excerpts and in
  structured connector metadata. Expect more `[REDACTED]` markers:
  - string literals passed to credential constructors, helpers and factories
    (`AzureKeyCredential("…")`, `HTTPBasicAuth("user", "…")`,
    `Credentials.basic`, `setBearerToken`, `WithAPIKey`, `cohere.Client`),
    including Rust `::new("…")`, C# target-typed `new("…")`, calls down a
    builder chain (`builder().apiKey("…")`, `.header("x-api-key", "…")`) and
    `auth=("user", "…")` tuples;
  - literal defaults of credentials read from the environment
    (`process.env.OPENAI_API_KEY || "…"`, `?? "…"`, `or "…"`, `?: "…"`,
    `${OPENAI_API_KEY:-…}`);
  - credential command-line options: `--api-key`, `--token`, `--password`,
    `--key` and `--pwd`, also in argv lists; `curl -u` and
    `-H "X-Api-Key:…"`; `-p` after `docker login`, other registry logins and
    `az`, `oc` or `cf` logins; `sshpass -p`; MySQL `-p…`; a literal echoed
    into `--password-stdin`; and `dotnet user-secrets set NAME VALUE`;
  - Dockerfile `ENV`, `setx`, `setenv`, C `#define`, PowerShell and TOML
    quoted keys assigned with `=`, and R `<-`;
  - XML key/name attributes, element names and name/value records, read as
    .NET settings by their last `:`, `__` or `.` segment as well as whole
    (`<add key="OpenAI:Secret" value="…"/>`, `- name: AzureOpenAI__Key`). In
    structured metadata the value is also removed from the record's other
    fields;
  - an opaque-looking value under a name whose last word, ignoring trailing
    digits, names a credential (`openaiKey`, `key`, `KEY1`), and a lone
    opaque value on the unindented line after a sensitive key;
  - more token prefixes: Google `ya29.`, `1//0` and `GOCSPX-`; Slack `xapp-`
    and `xoxe`; the GitLab `glrt-` family; `npm_`, `pypi-` and `dop_v1_`;
    and Stripe, SendGrid, Databricks, Shopify, Atlassian, Linear, Notion,
    Postman, Doppler, Supabase, Grafana, Sentry, Vault and Terraform Cloud
    tokens. `Ocp-Apim-Subscription-Key` and names ending in
    `subscriptionKey` are credentials.

  A C# `new AzureKeyCredential("<key>")`, a Java `builder().apiKey("<key>")`
  or a web.config `<appSettings>` key used to reach the reports of a complete
  scan; regenerate such reports and rotate the keys they show. Endpoint URLs,
  model names, variable names and references, placeholders and ordinary
  values (`<add key="CacheKey" value="users"/>`) stay visible. SECURITY.md
  lists the forms that are still not withheld, among them a space or comment
  before a call's parenthesis, redundant parentheses, C# interpolated and
  multi-line triple-quoted strings, one-letter options, a query parameter
  outside a URL and an unquoted value that reads as an identifier.
- **Redaction fixes:** a YAML parent key such as `openai:` no longer takes
  the next line as its value, which leaked a nested `api_key: <value>`. A
  `Bearer`/`Basic` scheme before a line break no longer drops a line from
  the excerpt, and a marker inside an unquoted value no longer gains a `]`
  each time a report sanitizes it again. Redaction is linear on hostile
  layouts that used to time out, exhaust the redaction budget or hang the
  scan without marking it incomplete: long runs of unfinished annotations,
  minified lines with thousands of sensitive keys, and long unquoted values
  after `key=`. Expressions nested more than 100 brackets deep are withheld
  through the end of the excerpt, and an unquoted word holding more than 16
  command-line options is withheld from its 17th option on.
- **Finding identity:** IDs are computed from sanitized resource fields, so
  an ID changes only where such a field held a value that is now withheld.
  These redaction rules leave the findings and IDs of the demo, the sample
  repository and every evaluation corpus unchanged; the classification
  corrections of September 27 below can still change findings. The redaction
  policy token changed, so findings verified clean under the old rules are
  sanitized again. Report sanitization takes about 28% longer (11 s to 14 s
  for 19 MB of library source).
- **Reports:**
  - CSV also inserts the `'` marker after a `,`, `;`, tab, `|` or line break
    inside a value when a formula could start there (OWASP CSV injection), so
    a report opened with another delimiter cannot create a formula cell.
    Leading no-break spaces and double quotes no longer hide a trigger.
    Consumers that strip only a leading `'` must strip these markers too, or
    read `json`.
  - Markdown writes `@` as `[@]` in untrusted text, like the existing
    `hxxp://` and `www[.]` defanging, so a pasted report no longer
    @-mentions users or teams or links e-mail addresses. Code spans stay
    verbatim.
- **Plugins and embedders:**
  - `shadowscan.utils.text.sanitize_record` is removed; call
    `shadowscan.utils.redaction.sanitize`.
  - `HttpClient.paginate_cursor` is removed; paginate explicitly. The Slack
    and Notion connectors keep their own cursor pagination.
  - The engine no longer names connectors. Per-root incremental caching, the
    instance-credential approval and the per-run gateway identity key are
    hooks a connector class declares (`cache_roots_separately`,
    `inherits_instance_credentials_approval`, `uses_run_identity_key`; see
    `docs/architecture.md`). Offline export parsing moved from
    `BaseConnector` to `shadowscan/connectors/offline.py` with
    `BaseConnector` names unchanged, and duplicate-finding metadata merging
    to `shadowscan.connectors.common.merge_duplicate_metadata`.
  - `shadowscan.utils.redaction` is split into `redaction_*` modules with the
    same public API and rule names. Patch rules through
    `shadowscan.utils.redaction`, never through a `redaction_*` module;
    `policy_token()` covers every module.
  - `SignatureIndex.signals_of_type(kind)` returns the (signature, signal)
    pairs of one signal type in pack order.

Development:

- ruff enforces line length (E501, 110 columns) outside `tests/` and
  loop-variable capture in closures (B023) everywhere. mypy requires
  annotated definitions (`disallow_untyped_defs`) and reports unused
  `type: ignore` comments (`warn_unused_ignores`). Only `regex`, `boto3`,
  `botocore` and `oci`, which ship neither stubs nor a `py.typed` marker, may
  be imported untyped.
- Unit tests live in files named after the module or feature they exercise,
  not the review round that added them; test bodies are unchanged.
- The evaluation, benchmark, canary and acceptance tools resolve the temporary
  directories they create before handing paths to the scanner, so they pass on
  macOS, where `/var` and `/tmp` are links into `/private`. The symbolic-link
  checks on untrusted input are unchanged.
- `docs/testing.md` describes the development environment, the offline suite
  and every `make` gate CI runs. `docs/maintainer-onboarding.md` is a reviewer
  and co-maintainer checklist, and `GOVERNANCE.md` has reviewer,
  co-maintainer and offboarding sections.
- `code.github` and `code.gitlab` share one implementation
  (`shadowscan/connectors/code/remote.py`), and the four cloud connectors
  share one offline-record dispatcher and audit-caller aggregator. New
  offline exports cover every GCP and OCI record kind, raising line coverage
  of `cloud/gcp.py` from 78% to 99% and of `cloud/oci.py` from 88% to 99%.
  The scanning commands share one option decorator; options, defaults and
  help are unchanged.
- Consistency tests check that documents describing CSV markers name every
  separator the reporter marks, and that the documented HTTP read deadline
  matches the client.
- Documentation: ADR-003 has a dated amendment recording the implemented
  confidence and risk formulas, and `docs/concepts/risk.md` matches the
  code. The cloud connector guide lists each connector's offline `_kind`
  values, and the architecture guide the engine hooks.

### September 28 repository hygiene

- The DCO check accepts Dependabot's app-authored commits with GitHub's fixed
  `support@github.com` sign-off, and only that pairing; every other commit
  still needs a sign-off matching its author or committer.
- CodeQL, Scorecard and the operator example workflow use `github/codeql-action`
  4.38.2 in every step, and Dependabot groups GitHub Actions updates so
  sub-actions of one repository move together instead of failing analysis with
  mixed versions.
- The development toolchain moves to ruff 0.16.9 with the regenerated hash
  lock and the matching pre-commit revision.

### September 27 review follow-up

- Opaque values nested under a sensitive credential container are now remembered
  before that container is redacted. Repeated values in sibling report fields
  and optional record exports are redacted too; descriptive provider and status
  fields remain available. Report and export regressions cover the boundary.
- GitHub and GitLab clones now check observed local checkout size during the
  clone and after Git exits, in addition to the provider size preflight. A
  measurement failure or exceeded cap stops the Git process group and leaves
  the scan incomplete with sampled API fallback. Sampling may overshoot and
  does not limit network bytes; use a worker disk quota for a hard ceiling.
- The evaluation runner supports explicit checks for expected and forbidden
  finding kinds, product signatures and model providers, with counts separated
  from the one-target binary accuracy result. Selected authored cases now
  guard against attribution noise; they do not establish field accuracy.
- Contributor and governance guidance now describes the configured pull-request
  approval and required-status rules, with dated observations of their changing
  enforcement state. The dated assurance report identifies its historical corpus
  count separately from the current corpus.

### September 27 review corrections

- Offline exports, approval inventories, imported reports, repository manifests,
  notebooks, agent/MCP configuration and other scanned JSON, JSONC and YAML
  reject duplicate or non-finite data. Rejected input makes collection
  incomplete instead of establishing absence; valid neighboring evidence is
  still retained.
- Structured projections reject conflicting schema aliases; CSV headers reject
  case-folded collisions; and conflicting provider records for the same logical
  Teams, Slack, Entra, Power Platform or Salesforce identity are quarantined
  without discarding valid neighbors. Azure pagination likewise refuses
  disagreeing continuation aliases.
- Generic graph and flow construction no longer establishes an agent by itself.
  Disabled, empty or schema-only tool options do not establish model-directed
  action execution. Source capabilities require corresponding evidence rather
  than inheriting every feature of an imported framework.
- CI exposes a single `CI gate` covering documentation, every supported Python
  version, the container checks, and DCO on pull requests. The repository ruleset
  must require that check; workflow code alone does not configure branch rules.
- Size-scaled source matching gives files near a 256 KiB budget boundary the
  next bounded time slice, avoiding scheduler-sensitive false incompleteness
  without weakening the fail-closed timeout behavior.
- The Python distribution is now `project-nexus-shadowscan` to distinguish it
  from the unrelated PyPI package. The `shadowscan` command, import namespace,
  entry-point group and report schemas retain their names. No package is
  published or namespace reserved by this change.
- Built-in connector options now use one fail-closed schema for YAML and
  programmatic configuration. Boolean aliases are normalized explicitly,
  ambiguous values and unknown/reserved built-in keys are rejected, later
  mutations and nested risk policy are revalidated before collection, and
  plugin-owned configuration stays schema-opaque while still rejecting cycles,
  excessive nesting and non-finite values.
  Configured inventory is reloaded on every run so the first execution cannot
  reuse an approval snapshot captured during engine construction.
- Shared JSON input rejects duplicate keys and non-finite values. JSON and
  SARIF publication refuses `NaN`/infinities. HTML/CSV sent to a terminal makes
  control and bidirectional-formatting characters visible, while explicit
  output files retain their serialized values. Reporter boundaries sanitize
  copied diagnostics, tolerate malformed related-finding metadata and preserve
  valid SARIF paths without treating provider resources as source locations.
- Incremental cache work now observes connector cancellation/deadlines, refuses
  `.git` indirection for Git-aware reuse, binds fingerprints to runtime/parser/
  Git versions, bounds tree traversal, and applies TTL, aggregate size/count,
  deterministic eviction and stale-pending/orphan-lock cleanup policies. Startup
  maintenance has a fixed two-second monotonic budget and disables reuse for the
  run when it expires. Lock acquisition verifies pathname identity after `flock`
  so cleanup cannot split one cache slot across stale and replacement lock inodes.
- Google Workspace domain-wide delegation strictly parses service-account JSON
  and pins both the signed assertion audience and token exchange to Google's
  HTTPS token endpoint; a key file cannot redirect the assertion.
- CI core/development tooling is now exact-versioned and SHA-256 hash-locked on
  Linux and macOS. All runtime, build, CI and documentation locks are audited.
  Pre-commit repositories use immutable commit SHAs and their additional type
  stubs are exact-pinned. Supported Python is explicitly 3.11 through 3.13.
- Release evidence now refuses a dirty checkout, builds from a clean archive,
  and assembles the exact attested wheel and bundles as a non-publishing
  `release-publication-input-<SHA>` artifact. The runtime SBOM remains a Python
  dependency SBOM, not a container/operating-system SBOM; no hermetic apt or
  package-index publication claim is made.
- Regenerate discovery baselines after adopting these classification and
  capability corrections. Fresh human-labeled holdouts, live tenant acceptance,
  independent release review and hosted artifact attestations remain separate
  release requirements; regression results do not supply that evidence.

### Self-graded audit follow-up

Fixes from an internal, AI-assisted grading pass over the repository; each
has a regression test.

- The registry's inventory scope-matching no longer hardcodes a single
  `google-workspace` string check to decide whether a card must list
  `accounts` before a resource pattern can approve a finding. The same
  requirement is now driven by
  `shadowscan.utils.identity.PROVIDERS_REQUIRING_CARD_ACCOUNT_SCOPE`, a single
  extensible set instead of a hand-patched exception repeated at three call
  sites (`Inventory.match`, `Inventory._scope_matches`, `card_stub_for`).
  Behavior for existing providers (AWS, Google Workspace, and every other
  built-in connector) is unchanged; adding the next provider that needs this
  protection is now a one-line addition to that set.
- `cloud.gcp` and `cloud.oci` test coverage now exercises the Cloud Function
  plaintext-secret handler, the Vertex endpoint and Discovery Engine
  handlers, the Cloud Audit Logs pagination edge cases (empty-token
  termination, repeated-token detection, invalid responses, transport
  failures), the instance-credential transport's redirect refusal and
  30-second timeout bound, and the three OCI GenAI resource handlers
  (dedicated endpoint, dedicated cluster, knowledge base) that had none.
  Both connectors were previously below the project's 75% per-connector
  coverage floor.
- `tests/test_repository_consistency.py`'s connector-count check now fails
  loudly (matching its signature-count sibling) if no doc states the count
  in bold, instead of silently matching zero times forever; README now
  states it (`**27 connectors**`).
- `docs/connectors/cloud.md` (the per-surface page reachable from the site
  nav) no longer omits the GCP pagination/audit-log page-cap sentence that
  `docs/connectors.md` documents; a regression test checks the two stay in
  sync on this point.
- `utils.output._require_private_pipe` now requires a named pipe's mode to
  be exactly `0600`, matching its own error message and the CHANGELOG's
  "Report output safety" description, instead of accepting any mode with no
  group/other bits (e.g. `0700`).
- `SetupError` now redacts its own message through the same sanitizer used
  for scan diagnostics, instead of relying on every call site to have
  hand-built a credential-free message; existing call sites that already do
  so are unaffected since sanitization is idempotent.

### Field-review follow-up

Fixes from the review of the field-review series; each has a regression test.

- A structured configuration the parsers refuse for nesting depth or XML
  entity expansion keeps the scan incomplete (exit 3) again. The series had
  reported it as a syntax warning outside coding-agent settings, so such a file
  hid its workflow evidence behind a complete scan.
- JSONC stripping is linear again: an unterminated string full of escaped
  quotes made it quadratic, so one small file could exhaust the scan deadline.
- The import-statement cache keeps only statements up to 256 characters,
  within 4 MiB of statement text, instead of any statement up to 65,536
  entries. Module names come from scanned code and the index lives for the
  process.
- GitHub Apps match their slug's words as well as the slug, so
  `amazon-q-developer`, `ellipsis-dev`, `mentatbot` and `factory-droid` are
  recognized again instead of dropping out of complete scans.
- `boto3.client(service_name="bedrock-agent-runtime")` and the AgentCore
  clients corroborate `invoke_agent` like the positional form.
- An MCP server keeps the capabilities its code implies when no tools were
  recognized, so a FastMCP shell tool registered with `@mcp.tool(description=...)`
  is `code-exec` again. Tools registered only in tests imply no capabilities.
- MCP enum tool names are found in one pass instead of one text search per enum.
- Documentation: the GitHub Apps rollout note lists the risk changes, the code
  and GitHub Apps connector options are documented, and the evaluation guide
  runs the field-review corpus.

### Report output safety

- A report path that already exists as a character device, such as
  `-o /dev/null`, is now written in place. Previously the report writer renamed
  a private temporary file over it, which, when run as root, replaced the
  system's `/dev/null` with a regular file. An existing named pipe is written
  in place only when the current user owns it with mode 0600 and a reader
  already has it open; otherwise the write fails at once instead of waiting.
  Sockets, directories, block devices and other non-regular paths are refused.
  Regular files are still replaced atomically with mode 0600, and symlinks are
  still refused. This covers `--output` for scans, the canary runner and the
  acceptance verifier, and the inventory stub and record-export manifest
  writers.

### Repository hygiene

- Every documentation page is reachable from the site navigation: the ADRs,
  the tenant canary guide and the 2026-09-24 assurance results were built but
  unlisted. A consistency test now fails on any page missing from the nav.
- Ruff enforces six more rules (`B007`, `B008`, `B034`, `C416`, `E741`,
  `SIM113`) after fixing their few violations: unused loop variables, a
  hand-maintained counter, a redundant comprehension and ambiguous `l` names.

### Type checking and lint coverage

- `mypy` runs with `warn_return_any` and `warn_unreachable`, and ruff's `B904`
  and `UP028` rules are enabled. The sites they reported are fixed at the
  source: untrusted API rows are typed as such so their guards are reachable,
  the AWS manual pagination path no longer runs inside an exception handler,
  and a GitLab variable shadow that hid a dead branch is renamed. The
  `pip install -e ".[dev]"` suite skips the two boto3-only tests without the
  AWS extra.

### Field review of public repositories (2026-09-25)

Behavior changes to review before upgrading (see
[production](https://github.com/aisecnomad/Project-Nexus/blob/main/docs/production.md#field-review-changes)):

- **Finding identity:** a CrewAI `agents.yaml` or `langgraph.json` inside a
  reported project is folded into that project's finding (listed under
  `metadata.manifests`) instead of a second agent finding. `diff` reports the
  former manifest findings as resolved. A2A cards and M365 declarative agents
  stay separate findings.
- **GitHub Apps:** an installation needs an AI signature or an AI-like name,
  whatever its permissions, so read-only apps with an AI-like name are now
  reported as well. Apps with neither, such as Renovate or Dependabot, are no
  longer reported unless `include_unrecognized_apps: true`, which caps them at
  possible confidence. A separate word "bot" in the slug (`changeset-bot`)
  still counts as an AI-like name. Only `workflows` or `actions` write access
  implies `code-exec`, so an app with only `contents` or `pull_requests` write
  access loses it and can drop a risk level (critical to high for the Claude
  app).
- **Scan completeness:** a syntax error in a configuration file that is not
  coding-agent settings (`.claude`, `.codex`, `.gemini`) is a warning; lexical
  checks still read the file. `strict_coverage` keeps it incomplete.

Fewer false incomplete scans:

- Structured configuration accepts JSONC (VS Code settings, dev containers,
  tsconfig) through a shared, faster lenient loader (`shadowscan.utils.jsonc`).
- A Python module over the AST budget keeps its lexical evidence and is reported
  as partially analyzed: a warning in test code, an error elsewhere. New
  `max_ast_nodes` option (default 50000).
- Notebooks whose saved outputs exceed `max_file_size` have their code cells
  analyzed up to `max_notebook_size` (default 20 MiB) instead of being skipped.
  Their outputs are not scanned for credentials at that size, which leaves the
  scan incomplete unless `scan_secrets` is off.

Precision and recall:

- Code signals accept `ambiguous: true` for identifiers common outside the
  product. Such matches count only with an import, dependency or specific code
  pattern of the same signature in the project. Applied to `ClientSession(`
  (aiohttp), `AgentCard(`/`AgentSkill(`/`DefaultRequestHandler(` (A2A),
  `invoke_agent(`/`invoke_flow(` (Bedrock Agents), `create_agent(model=`,
  `AgentsClient(`, `OpenApiTool(` (Azure AI Foundry), `CopilotClient(`
  (Copilot Studio) and `Exa(`/`GoogleSearch(`/`WebSearch` (web search tools).
- The cap on uncorroborated lexical evidence in languages without the import
  binder applies to every signature category, not only frameworks.
- On a host shared with another product and not named for MCP
  (`api.githubcopilot.com`), the URL path decides: `/mcp` or `/sse` is MCP.
- Provider tool loops are recognized with raw-response, streaming and
  helper-function requests.
- MCP server capabilities come from the tool names the server registers
  (`metadata.mcp_tools`). Test-path evidence adds no capability unless the
  project is only tests, and vendor-neutral idioms add none to an MCP server.
- Findings with only supporting technology are titled `AI tooling`.
- New `tools/evaluation/field_review_corpus.json` (8 synthetic cases) in
  `make evaluate`.

Performance:

- Regex signal passes select candidate patterns with one scan over their
  required literals instead of a per-pattern check, synthesized import
  statements are matched once per index, and unresolved imports skip a code
  pass whose results were discarded. Findings are unchanged.

Development:

- `pip install -e ".[dev]"` runs the whole suite: boto3 tests skip without the
  AWS extra, and the dev extra includes setuptools and wheel.
- Internal AI-assisted review logs move from `docs/` to `archive/reviews/`.

### Coverage and release verification follow-up

- Mark unread oversized source and configuration files and outward or unresolved
  symlinks as incomplete even without `strict_coverage`; the flag elevates the
  diagnostic from a warning to an error. Declared generated-file omissions in
  `oversize_skip_globs` remain visible warnings.
- Treat in-root directory symlinks, and file links to excluded or otherwise
  unread targets, as incomplete instead of assuming alias content was scanned.
  Links whose own names are never read (lockfiles, generated bundles, images)
  and source aliases analyzed in the same project with the same test
  classification stay complete.
- Treat malformed or mismatched explicit GitHub/GitLab repository responses and empty GitHub/GitLab
  offline clone inputs as incomplete scans instead of complete empty results.
- Compute the signature-set digest once per incremental scan run instead of
  reserializing it for every input snapshot; changes between runs still invalidate
  the cache.
- Accept GitHub's actual workflow-run path in the release evidence gate and
  require successful exact-commit CI and CodeQL before building a candidate.

### Scanner boundaries and acceptance consistency

- Redact the value of any call whose first argument, or `key=`/`name=`
  argument, is a literal credential key (`os.getenv("API_KEY", "...")`,
  `settings.get("password", ...)`) before publishing source evidence. The
  bounded lexer reads `#` and `//` as text when a comment reading cannot close
  a call, so prose such as `(#123)`, Python floor division and JavaScript private
  fields pass through unchanged. A credential call whose value cannot be
  bounded withholds the excerpt and marks the scan incomplete.
- Keep repository-connector exception logging free of raw exception payloads.
- Bind Google Workspace observations and registry approvals to an immutable
  customer identity. Unresolved identities remain visible for investigation but
  cannot establish approval or complete collection. **Operator action:** grant
  the audit identity `admin.directory.customer.readonly` before live
  collection; `customer` must be `my_customer` or a concrete `C…` ID (a domain
  is rejected at startup); offline scans need the verified `customer` or stay
  incomplete. Unresolved findings keep stable IDs per input or admin account.
- Preserve unresolved Entra permission evidence. Grants or role assignments
  whose service principal is missing, and principals exported with conflicting
  records, become `unresolved-principal` findings that report no type,
  publisher or first-party status.
- Reject contradictory AWS account envelopes: several or invalid `account`
  records, or a resource ARN from another account, leave short identities
  unresolved and the scan incomplete. An offline `account_id` that disagrees
  with the export's account record no longer silently wins.
- Require usable identity for n8n workflow observations; blueprints without an
  ID, including YAML exports, keep their evidence under an unresolved identity.
- Remove the duplicate lexical agent-promotion path. Provider dispatch findings
  must pass source-semantic provenance checks and the configured test-code policy.
  Python single dispatch is recognized whether its result is kept, discarded or
  returned. JavaScript recognition stays deliberately narrow (a small, complete
  top-level program): JS/TS files that the lexical path promoted, such as a
  dispatch inside a function or code without semicolons, now report
  `framework-usage`. Review their findings before relying on agent counts.
- Share source-overlap validation between the holdout acceptance tools so repeated
  examples cannot inflate sample counts or statistical confidence.
- These changes require fresh finding baselines and acceptance evidence. Offline
  regressions do not establish independent human review or live tenant acceptance.

### Markdown report safety

- Defang bare HTTP(S) and `www.` URLs in untrusted report text so copied Markdown
  does not automatically turn attacker-controlled values into clickable links.

### Supported-platform preflight

- Every `shadowscan` command now fails closed, with a clear error, on a host
  that cannot enforce the documented path confinement (Windows, or a platform
  without `O_NOFOLLOW`); `--help` and `--version` still work everywhere.
  `shadowscan.utils.platform.require_supported_platform()` performs the same
  check for embedding callers. `redact` in `shadowscan.utils.text` stays as
  a documented compatibility alias. `sanitize_record` was removed later in
  this release; call `shadowscan.utils.redaction.sanitize`.

### Community policy consistency

- Add a documentation issue form, keep detection reports and private security
  reports on their existing routes, and document safe vulnerability report inputs.
- Hash-lock the documentation toolchain, align local hooks with CI tool versions,
  and scope CodeQL and stale-triage write permissions to their jobs.
- Validate workflow and issue-form safety policies. Label synchronization creates
  or updates declared labels without deleting labels; inactive issues and pull
  requests remain open for maintainer review.
- `tests/test_repository_consistency.py` (run by `make policy`) fails CI when a
  relative Markdown link or heading anchor is broken, a community file is
  missing, `CITATION.cff` disagrees with `pyproject.toml`, the CI matrix
  differs from the classifiers, the Makefile or pre-commit hooks drift from the
  CI gates, the docs toolchain is installed outside its lock, CodeQL steps are
  pinned to different releases, or a documented signature, signal or connector
  count is stale. The CI docs job now installs from `requirements-docs.lock`;
  the install guide states that CI validates Python 3.13; the detection quality
  report asks for the signature involved and a sanitization acknowledgement;
  README's community table links the detection form, maintainers, roadmap,
  changelog and citation.
- A verified repository hygiene audit fixed the drift it found. Pre-commit: the
  secret hook used `types: [python, yaml]`, an AND filter that selected no file,
  so it had never run; it now uses `types_or`, recognises current OpenAI and
  Anthropic key formats and excludes the tests that hold synthetic tokens;
  `check-yaml` skips `mkdocs.yml`, whitespace fixers skip fixtures and the
  digest-bound retained licenses, and `detect-private-key` skips the redaction
  tests, so `pre-commit run --all-files` passes. The `pre-commit` dependency
  closure is pinned in `requirements-ci-constraints.txt`. Documentation: the
  production guide, constraints header and contributor guide state that Linux
  x86_64 is the only validated target, that Python 3.11 to 3.13 are all
  covered, that Windows is unsupported by design, and that the `main` ruleset's
  enforcement has changed during 2026-09 and must be checked live; the quick
  start no longer mixes a live code connector with credentialed tenant
  connectors in one configuration; the replay example uses the exported
  filename; the risk table, GitLab per-file cap (512,000 bytes), default
  `max_file_size`, evaluation corpora count and code connector modes match the
  code; two hardening logs no longer describe same-author passes as independent
  reviews and the two remaining 2026-09-24 review documents carry the internal
  work-log banner. Packaging: PEP 639 `license = "Apache-2.0"` with
  `license-files`, and the `Operating System :: POSIX :: Linux` classifier
  replaces `OS Independent`. Examples: the consumer workflow pins
  `upload-sarif` to a commit rather than a tag object and grants `actions:
  read` for private repositories. HTML report: sorting and evidence drill-down
  are real buttons reachable by keyboard with `aria-expanded`/`aria-sort`, the
  filters have accessible names, the result count is a live region, an `info`
  tile is shown, and pill and light-scheme colors meet WCAG AA contrast. The
  bug report form asks for the full commit SHA and describes exit codes
  accurately; the CSV reporter's formula-quoting is documented in README.

### Private holdout and CLI job deadline gates

- Reject bundled corpora and AI annotation ledgers from holdout acceptance;
  validate the human-review declaration used for the actual evaluation and read
  acceptance policies and annotations with bounded, symlink-free file access.
- Add optional `--job-deadline-seconds` / `options.job_deadline_seconds` for CLI
  scans. The cancellable process watchdog exits `3` when setup, scanning or output
  exceeds the deadline; external process supervision remains required.
- Start an explicit CLI deadline before reading JWTs from stdin, so an open,
  silent input pipe cannot hold the process past its configured deadline.

### Follow-up trust-boundary review (2026-09-24)

- Reject duplicate fields and nonfinite numbers in provider API JSON before
  interpreting collection, pagination or signing-key data.
- Mark offline Slack cursors and AWS truncation markers incomplete, retaining
  observed records while refusing a clean result for uncollected pages.
- Require intact, unambiguous code identities and recognized caller assurance
  before attaching runtime activity; clear stale derived observations.
- Sanitize imported findings before publishing report comparisons and require
  explicit, matching connector completion evidence before resolving findings.
- Render terminal control characters visibly in untrusted CLI display values.
- Bound evaluation corpus reads, reject the reserved aggregate family name,
  and bind annotation checks to the exact corpus snapshot being evaluated.

### Control-assurance fixes (2026-09-24)

- Redact long sensitive assignment keys before source evidence enters JSON or SARIF; bind Power Platform Dataverse token audiences and destinations to validated organization origins.
- Preserve valid neighboring provider records while marking provider errors, malformed Slack responses, missing collections and invalid pagination incomplete.
- Reduce generic-code false positives, recognize OpenAI Responses function dispatch, and fail closed on ambiguous source masking.
- Bound remote clone time, preflight provider repository size, avoid cloning when a usable size estimate is unavailable, terminate clone descendants on cancellation, remove partial checkouts and mark API fallbacks incomplete.
- Add a frozen holdout acceptance gate, tenant canary procedure, safer contributor guidance and a GitHub Action example. Field accuracy still needs independent review and live canaries.

### Scanner assurance and release evidence (2026-09-25)

- Preserve observed ServiceNow native agents if optional name or OAuth
  signature matching times out, mark coverage incomplete, and skip repeated
  matching for remaining records.
- Keep YAML manifest artifact matching within its existing one-second shared
  deadline during parallel scans, while allowing a chunk the manifest pattern
  budget; exhausted deadlines still make coverage incomplete.
- Recognize import-bound OpenAI Responses API function loops only when the
  model-selected call is dispatched and its result returns in the next request
  with matching call identity. Unreachable literal branches and locally
  shadowed execution names no longer establish provider tool loops.
- The offline acceptance verifier excludes previously evaluated source snapshots,
  validates the evaluator's known-gap report, and supports frozen per-kind
  sample and error limits. Its operator declarations still require independent
  human review and real tenant validation before rollout.
- The release candidate workflow binds a successful exact-commit main CI run
  to a wheel, hash-locked runtime and build dependencies, SBOM and retained
  provenance. The reviewed container base and consumer CI example are pinned;
  the workflow does not publish a package or authorize deployment.

### Detection precision, coverage policy and risk explainability

Behavior changes (review before upgrading an enforcement gate):

- Oversize files and symbolic links leaving the scan root are skipped with a
  warning instead of making the scan incomplete. `strict_coverage: true` /
  `--strict-coverage` restores the previous fail-closed behavior. Links that stay
  inside the scan root no longer affect coverage in either mode.
- Evidence found only in test or fixture code no longer establishes an agent
  (half weight, `test-code-only` tag); `include_tests` / `--include-tests` opts out.
- Project findings built only from evidence already reported by an MCP config,
  agent manifest, exported workflow, IaC or credential finding are no longer
  emitted as duplicates.
- Signature-level capabilities are narrower: LangGraph no longer implies memory,
  the OpenAI Agents SDK implies multi-agent only with hand-offs, and Bedrock
  AgentCore memory, code interpreter and browser come from their own resources.

Fixes and additions:

- The Python/JavaScript import binder counts only calls into modules that a
  signature describes. Ordinary large files (e.g. psf/requests' test suite) no
  longer fail with `source binding call limit exceeded`; diagnostics now include
  the scanner's own limit message.
- Provider SDK requests that pass tools (`tools=`, `toolConfig=`) record
  import-bound tool-use capability and provider attribution. The agent verdict
  still requires the model-selected dispatch and feedback loop, which is now
  recognized for Anthropic `messages.create` as well as OpenAI chat
  completions, including process or code execution sinks fed with the model's
  tool input, collected `tool_result` lists and dispatch inside `if` branches.
  Anthropic, OpenAI, Bedrock Converse and Gemini tool-call shapes are matched
  when written as dict keys or compared strings; loop checks accept `!=` as
  well as `==`.
- Shell, process and dynamic-code sinks count as code execution when the same
  file invokes a model, framework or tool-calling protocol.
- Model providers are attributed through LangChain, LlamaIndex and Vercel AI SDK
  integration packages and n8n model nodes (18 providers), and through model IDs
  declared in IaC. IaC projects with wildcard IAM statements are tagged
  `wildcard-permissions`.
- Placeholder credentials (repeated characters, marker words such as `EXAMPLE`,
  very low character diversity) are ignored; Azure OpenAI keys are recognized by
  their standard variable name. MCP inline-secret evidence names its location.
- Risk factors always add up to the score (explicit `confidence-scaling` and
  `bounds` factors). New `risk.danger_score` excludes governance factors;
  `options.risk_basis` (`combined` | `danger`) and validated `options.risk_weights`
  configure the model.
- Tests that need optional cloud SDKs or Git 2.45+ skip cleanly; the container
  base moves to Debian 13 (Git 2.47) and the build fails if Git is older than 2.45.

### Quality, precision and governance pass (2026-09-24)

#### Security

- Third-party connectors are verified when loaded: the class must be a concrete `BaseConnector` subclass whose `name` equals its entry-point name and is not a built-in name or namespace; violations fail closed with `PluginRegistryError`, and `plugin_registry_errors()` returns structured, credential-free diagnostics that the CLI now prints.
- The container build installs the build backend from the hash-locked `requirements-build.lock` with `--no-build-isolation`, pins the base image by digest (refreshed by a Dependabot `docker` entry), and admits only source, packaging and signature files into the build context.
- `Finding.from_dict` rejects malformed report shapes (non-object metadata, non-string list items, non-boolean `shadow`, evidence or risk factors without string identifiers) at the import boundary instead of failing later inside a scan.
- The two diverged copies of the `O_NOFOLLOW`/`dir_fd` offline-file open sequence are replaced by one confined helper in `shadowscan.utils.files`, with tests that both callers refuse symlinked components and special files and enforce their byte limits.

#### Detection

- Signature packs grow to 211 signatures and 912 signals (local inference, guardrails, Chinese-market providers, 2025 agent SDKs, more AI SaaS identity apps). The OpenAI secret regex is shape-specific and no longer claims Langfuse, LiteLLM or OpenRouter keys; dictionary-word display names match only with product context; two vendor misattributions are corrected; code idioms shared by competing frameworks move to heuristic signatures; the Azure OpenAI model pattern requires Azure context; `langchain-text-splitters` is a non-agent utility signature; and LangChain keeps prefix matching for every partner package through the new `exclude_names` / `exclude_prefixes` dependency fields.
- The signature validator enforces ecosystem, language and capability vocabularies, per-signal uniqueness, positive weights, non-empty-match patterns, balanced globs, id-namespace-to-category mapping and cross-signature duplicate regex detection. Custom packs that violate these rules now fail to load.
- Placeholder-looking provider keys (`REPLACE_ME`, `<your-key>`, repeated or sequential characters) become low-weight `example-credential` evidence instead of high-risk secret findings; the check is applied per matched key across filesystem, `.env`, MCP, cloud and blob scans.
- A repository whose only LLM signal is a credential no longer receives a derivative LLM-usage finding; vendor-neutral heuristics cannot create an `agent` finding without a framework, provider, platform, protocol or cloud-service match; projects observed only through environment-variable or display names are tagged `env-names-only`, weighted at half and capped at confidence 0.8.
- MCP filesystem and database servers carry a new `data-access` capability and browser servers carry `browsing`; gateway callers are titled `Agentic caller` only with a non-temporal indicator, and round-the-clock activity alone keeps the informational `always-on` tag.
- When a project's only technology anchors are environment-variable or display names, vendor-neutral heuristics contribute no evidence, indicators or capabilities; a dependency, import, code or file anchor restores their weight.
- Regression cases for each rule join `tools/evaluation/corpus.json`.
- `tools/evaluation/realistic_corpus.json` adds 31 multi-file cases written to resemble real repositories and naive-scanner false positives; the evaluator gains a `known_gap` flag and a `max_secret_findings` assertion, CI runs all three corpora, and docs/evaluation.md states what each corpus does and does not measure. Semantic Kernel C# projects now promote to agents, and a function defined as `create_agent()` no longer matches the LangChain call pattern.

#### Correctness

- SARIF output never emits a `physicalLocation.region` without `startLine` (line-less snippets move to the location's property bag), rule names are restricted to `[A-Za-z0-9_]`, invocation timestamps are ISO 8601 UTC or omitted, and null-valued keys are dropped; `render_sarif()` is validated against the vendored SARIF 2.1.0 JSON schema in the test suite.
- Risk scoring is total over malformed metadata: a non-numeric secret count or a non-object MCP server entry no longer aborts the scan, and the confidence-scaling factor never carries a positive weight.
- `shadowscan connectors` renders configuration keys with real styling instead of literal `[bold]` markup and prints plugin registry diagnostics; scans log the same diagnostics at WARNING.
- Setup failures print actionable, credential-free messages (`inventory path not found: …`, `signature directory not found: …`, a malformed pack named by file and document, an unknown connector key with a suggestion) through the new `shadowscan.errors.SetupError` contract; every other exception stays masked. Connector-level configuration keys now fail closed against each built-in connector's declared keys, YAML syntax errors report line and column without echoing source, and the deprecated `options.connector_timeout` alias logs a one-time deprecation warning.
- `shadowscan signatures test` reports an invalid pack as a click error and, in auto mode, also consults dependency signals across every ecosystem.

#### Performance and maintainability

- The filesystem scanner stops its walk cooperatively before the connector deadline, records one error naming examined and remaining files, and returns the findings collected so far; the engine keeps them and reports the scan incomplete instead of discarding everything.
- Domain, regex-signal and file-glob matching are prefiltered by required literals with engine-consistent case folding and batched deadline bookkeeping; equivalence tests assert identical results and the repository self-scan runs about twice as fast. The per-file budget scales with file size, files over `max_file_size` that match the new `oversize_skip_globs` key (lockfiles, minified bundles, source maps, images, fonts, archives, compiled artifacts) are skipped with a warning while other oversize files remain errors, and incremental fingerprints track oversize files by metadata instead of aborting.
- The gateway log normaliser is split into `shadowscan/connectors/gateway/normalise.py` with one small function per export format behind a registry; goldens generated from the previous code replay byte-for-byte under `tests/fixtures/gateway_golden/`.

- `Engine.run` is decomposed into named seams (`_prepare_run`, `_ConnectorRunner`, `_Supervisor`, `_ExportLedger`, `_postprocess`, `_write_manifest`) with identical ordering, thread-safety and deadline semantics.
- Signature packs are parsed once per `Engine` instead of twice, inventory is loaded once, and `Finding.sanitize()` skips objects unchanged since the last pass under the current redaction policy, so redaction runs once per finding instead of seven times while every call site keeps its defence in depth. Rendering 5,000 findings to JSON drops from about 18 s to under 2 s; sanitization semantics are unchanged.
- `Signal.compiled` is a lazy property; the scanner-source digest used by comparison and incremental caching is one shared helper; helpers with no callers are removed from the connector base, `utils.text`, `utils.safe_yaml` and the identity connectors.

#### Tests and tooling

- The suite collects on a core-only install (optional SDKs are imported with `importorskip`), deadline tests no longer depend on host speed, byte-identical duplicate tests are collapsed, and index-less `Engine()` constructions in tests reuse the session signature index.
- Every configuration key a connector reads is declared in its `config_keys`, shared offline-limit keys are surfaced through one `BaseConnector` list, `enabled` and `label` are documented, and a test parses each connector module so an undeclared key cannot reappear.

#### Governance and documentation

- `CONTRIBUTING.md` documents the actual single-maintainer, self-merge process with automated checks and requires independent human review before any tagged release; `docs/production.md` gives operators the commands to verify ruleset and review state themselves.
- The three 2026-09-24 review documents are relabelled as internal AI-assisted hardening logs (they now live under `archive/reviews/`); the package classifier drops from Beta to Alpha; README gains a Project status section and corrected claims; SECURITY.md states that no versions are released yet.

### Production acceptance fixes (2026-09-25)

- Redact opaque credentials assigned through indexed Python/JavaScript targets
  before capturing source evidence, and escape terminal control characters in
  verbose reports.
- Bind Slack findings to immutable workspace IDs; preserve workspace names only
  as display metadata. Legacy offline exports need a team envelope or explicit
  `team_id`. Refresh Slack comparison baselines after this identity correction.
- Reject Teams records with missing or malformed resource identity, retaining
  valid neighboring observations while reporting incomplete coverage.
- Distinguish repository-local Python modules from third-party agent SDKs and
  recognize supported provider-driven tool loops through structural source
  evidence. Static construction still does not establish runtime execution.
- Add deployment evidence validation and a manually invoked release-evidence
  workflow. Neither tool creates human review, live tenant results, a published
  release, or a production acceptance claim from offline tests.

### Production review round 2 (2026-09-24)

- Stop treating every environment value of a cloud inventory record as a credential to remove from sibling fields: a benign setting such as `STAGE=prod` or `WORKERS=4` no longer redacts ARNs, account IDs and names out of SageMaker findings and `--dump-records` exports, which also restores stable finding IDs when an export is reanalyzed offline. Environment values remain withheld in exports, and values under sensitive names or in recognizable credential formats are still removed everywhere. SageMaker findings now record environment variable names only, like Lambda findings.
- Snapshot Bedrock agent DRAFT details instead of storing the agent record inside itself; the previous self-reference collapsed to a redaction marker in record exports and marked every reanalyzed agent incomplete. Older exports with the collapsed entry are read without a coverage warning.
- Identify potential grants from IAM `NotAction` allow statements against a representative AI-action list, recorded with a `notaction-partially-evaluated` limitation (the wildcard treatment first described here was superseded before it shipped), and treat `sagemaker:*` as an LLM invoke grant during live collection, matching the offline analysis.
- Report OCI custom (fine-tuned) models by `type: CUSTOM` / base model reference instead of a vendor test that excluded every real custom model.
- A `bedrock-logging` export record without a `loggingConfig` key, or carrying an error body, is unknown coverage rather than a "logging DISABLED" finding.
- Show the configuration policy reason when scan setup is rejected (for example the code-scan and live-credential separation rule) instead of a generic message; the rule's message now names `--allow-credential-mixing`.
- Sort Entra delegated scopes so `permissions` are reproducible across runs.
- JWT classification: `client_name`, `app_displayname` and `azp_name` count as agent hints only when their value matches an AI product or agent name signature (every Entra v1 delegated token carries `app_displayname`, so ordinary user tokens were reported as agents); a user-subject token with an RFC 8693 actor and agent claims is `delegated-agent`, never weaker than the same token without `act`; nested claim values are sanitized before truncation so no token prefix is persisted.
- Entra service-principal findings use the scanned tenant as `account` (the publisher tenant is kept as `metadata.owner_tenant`); Google Workspace accepts the Admin SDK `tokenList` envelope and URL-encodes user keys; Atlassian validates `products`; Make pagination isolates invalid pages.
- n8n, Make, Workato and Notion exports containing a provider error body are incomplete coverage instead of an empty inventory; one malformed record in Teams, n8n, Make, Zapier, Workato, Notion, generic SaaS or live Slack lists is skipped with a warning instead of aborting the connector.
- Gateway: response-side tool calls count when inspected requests carried no tool definitions (LiteLLM with body logging off), Bedrock Converse `toolUse`/`stopReason` are recognized, activity buckets use UTC, `llm_hosts_only` keeps requests to known LLM hosts on unlisted paths, Vertex and Portkey/Helicone detection use structural fields, a token in a user or principal field is sanitized before the label is shortened, LiteLLM rows without key material are `service` callers rather than pseudonymized credentials, `identity.arn` wins over the `identity` object, prose `message` wrappers keep the structured event, retained labels and samples are bounded, and a caller's first model/provider/host label survives an exhausted detail budget. Opaque credential labels skip display-name matching.
- Code connectors: cooperative cancellation now stops the tree walk instead of being recorded as one error per remaining file; credential detection runs first and in its own isolation, so a content pass that exceeds its regex budget, a structured file that exceeds the sanitizer budget (excerpts withheld) or notebook outputs and markdown cells no longer hide a real key; one unsafe tree path in API mode skips that file rather than the repository; agent definitions (50 per project) and retained agent manifests (200) are bounded with an incomplete-scan error; directory exclusion names no longer skip files of the same name; `Containerfile` is parsed like a Dockerfile; per-repository diagnostics share the 1000-entry cap; Git author fields use NUL separators with a validated timestamp; Ruby `=begin` blocks scan in linear time; a Python 3.12 tokenizer error mid-file marks the file ambiguous instead of silently masking the remainder; multi-line structured secrets keep excerpt line numbers aligned.
- Environment-style credential names in text (`AZURE_OPENAI_KEY`, `DATABRICKS_TOKEN`, `MODAL_TOKEN_SECRET`, `LITELLM_MASTER_KEY`, ...) have their assigned values redacted in source excerpts, evidence and URL queries (indexed targets such as `os.environ["DATABRICKS_TOKEN"]` included); record field names keep their narrower sensitivity so provider inventories are not over-redacted. A connector's other findings survive one finding that exceeds the sanitizer's output budget.
- Tests that assert successful Git history enrichment skip with a clear reason when the local Git lacks `--no-lazy-fetch` (2.45+) instead of failing; CI enables pip caching and mypy checks untyped function bodies.

### Detection and collection assurance (2026-09-24)

- Require corroborating AI evidence and bind constructors to imported frameworks; resolve common Python and JavaScript/TypeScript aliases. Generic loops and subprocess calls cannot establish confirmed agents.
- Validate agent manifests and operational configuration; descriptions and empty files cannot establish agent presence.
- Preserve unknown Lambda coverage, identify potential IAM NotAction grants with explicit analysis limits, validate Slack workspace scope and report missing n8n definitions as incomplete.
- Add a frozen negative-heavy public corpus with separate AI labeling passes, provenance and annotation checks in CI. This is not field accuracy.
- Add read-only AWS and Slack tenant canaries with explicit controls, scope and coverage assertions, permission-denied tests and private reports. Offline replay does not establish live acceptance.

Live tenant acceptance remains a deployment gate. Neither offline tests nor static findings prove a production tenant was scanned.

### Final reconciliation after PR #33 (2026-09-24)

- Fence incremental cache and record publication against timed-out connectors, and refuse to reuse an Engine while a prior abandoned worker still runs. A separate process deadline remains necessary for blocked SDK or plugin calls.
- Redact short configured credentials in diagnostics. Bound gateway caller/detail/interval state and repository-wide CODEOWNERS work, and avoid excessive work on Go source ranges.
- Keep untrusted SDK diagnostics out of application logs, redact opaque API/Foundry/GitHub token fields and the `GH_TOKEN` fallback, and restrict Kubernetes JWT classification to documented claim shapes.
- Preserve the newer webhook, HTTP header, imported finding, CSP, SARIF, GCP and Azure safeguards from the consolidated candidate.
- Fix the example code-scanning workflow for repositories without an inventory directory and for fork pull requests.
- Record immutable commit/tree identities on GitHub and GitLab code findings, and reject downloaded blob bytes that do not match the enumerated Git object ID.

Package version: 0.1.1. No release tag or published artifact is implied by this
entry. Tenant canaries and container runtime acceptance are still required.

### Security

- Withhold the credential-bearing path of webhook capability URLs (Slack, Discord, Teams, Zapier, Make, IFTTT, Telegram, n8n) in evidence, reports and record exports; `webhookUrl`/`webhookUri`/`webhookId`/`hookUrl`, `AccountKey`, `SharedAccessKey` and `sas_token` fields are sensitive.
- Apply the Keycloak service-account rule to Keycloak issuers only; a `preferred_username` starting with `service-account-` no longer relabels tokens from other issuers.
- Match the Kubernetes JWT claim namespace on the exact `kubernetes.io` prefix.
- Validate headers before requests can echo credential-bearing invalid values; redact additional provider formats and escaped credentials before source excerpts are shortened.
- Redact opaque Azure app settings and OCI Function configuration in record exports. Reject malformed numeric fields in imported findings and restrict HTML scripts to the shipped script's SHA-256 hash.
- Redact multiline YAML credentials before evidence excerpts, and pin GitLab API tree pagination to an immutable commit.
- Route GCP token refresh through bounded response and redirect policy.
- Classify JWT issuer families by parsed hostname labels rather than substring matches.

- Separate repository scanning from live tenant credentials by default; mixing requires explicit `allow_credential_mixing` approval.
- Cloud instance-metadata credentials require `allow_instance_credentials` opt-in; connector settings cannot silently override the global policy.
- Checkouts disable persisted GitHub credentials, and the Docker build context permits only source and packaging inputs.
- Core and cloud runtime dependencies are version- and hash-locked for the documented Linux/Python deployment targets.

### Reliability

- Render inventory, signature and connector text literally in CLI tables: Rich markup in an approval card no longer crashes `inventory check` or restyles the review screen.
- Retry GitHub 403 rate-limit responses (`X-RateLimit-Remaining: 0` or `Retry-After`) but not plain permission denials; all HTTP backoff is jittered and capped at 120 seconds.
- SARIF artifact URIs are percent-encoded, made root-relative only on path boundaries, absolute outside the scan root, and each rule reports its most severe result.
- Preserve valid cloud, identity and SaaS records after individual collection/analysis failures. GCP service-account key coverage now distinguishes unknown inventory from observed zero keys.
- Normalize scalar cloud scope options and reject unknown AWS service selections instead of reporting an empty successful scan.
- Bound diagnostic streams, gateway detail cardinality and numeric aggregates; isolate failures without losing later valid records.
- Deduplicate repeated source observations without dropping distinct custom signal capabilities. Preserve caller scan budgets and bound concurrent manifest matching by both CPU and wall time.
- Add a default 120-second connector deadline with incomplete-scan reporting. This is a soft thread deadline; host job timeouts remain necessary for blocked SDK/plugin calls.
- Protect incremental cache slots with nonblocking POSIX advisory locks. Contention or missing platform locking falls back to full scans without unsafe cache reuse or saves.
- Preserve the required CodeQL check name `analyze` and test hash-locked runtime installation in the Python 3.11/3.12 CI matrix.

### Operations

- Reuse bounded inventory patterns and per-analysis JWKS documents; index source newlines, avoid unnecessary JSONC parsing and reuse OCI clients within one collection session.
- Consolidate additional verified fixes from PR #31 on top of the PR #30 candidate; preserve PR #30's credential isolation, default deadlines and release gates.
- Explain how to select and verify the final reviewed full commit SHA; avoid an install example that silently falls behind later candidate fixes.
- Raise the development Ruff requirement to 0.16.8 and validate wheel installations against the runtime lock.
- Correct README commands, formatting and discovery claims; document the active required checks and independent-review merge gate.
- Document dependency lock maintenance, soft deadline limits, rollout evidence and remaining tenant/container acceptance.
- Clarify that finding confidence is heuristic, that static signals and resource existence need runtime corroboration, and that field precision/recall require a held-out local corpus before risk-gate enforcement.

## Earlier hardening notes — 2026-09-24

The following summarizes the reconciled pre-release implementation.

### Security


- Escaped, multiline and nested sensitive mapping values are redacted before source evidence is emitted; TLS verification rejects all falsy effective settings.
- Live AWS account attribution is checked through STS even with a configured expected account.
- Report imports reject ambiguous JSON, unsafe file paths and invalid security attributes before generating inventory stubs.
- GitHub/GitLab API downloads use enumerated immutable blob IDs; links, submodules and malformed Base64 produce incomplete coverage.
- Accountless short AWS IDs cannot approve a registry entry; their scans report incomplete coverage until an account is supplied.
- Filesystem scans reject symlinked root paths and report skipped in-scope symbolic links as incomplete coverage.
- Injected HTTP sessions cannot retain origin-specific adapters that bypass destination checks; default buffered responses have a decoded-byte limit.
- Scan configuration rejects missing required environment values, duplicate authored YAML keys, invalid gate settings, and unsupported top-level options.
- Finding identity no longer includes `kind`; promotion from framework-usage to agent preserves merge/diff/incremental identity.
- Shared HTTP client bounds JSON response bodies by default.
- Injected `requests.Session` objects still receive the destination-policy adapter.
- Missing `${ENV}` expansions for required secrets fail closed instead of becoming empty strings.
- Full Apache-2.0 LICENSE text and NOTICE.

### Reliability
- Identity/low-code pagination retains valid neighbors and partial observations, rejects provider failures, and recognizes documented Google empty-list envelopes.
- GCP Cloud Run lists concrete locations; unreachable regions are incomplete. Azure ARM pages preserve observations while incomplete diagnostic collections remain unknown.
- AWS and OCI SDK clients use finite transport/retry bounds; AWS Lambda and GCP project limits stop enumeration early.
- Relative inventory globs and work directories resolve beside their configuration file.
- A later Azure Resource Graph page failure retains already observed resources and reports incomplete coverage; GCP caller attribution is scoped by project.
- Concurrent connector completion order no longer determines merged finding ownership or metadata.
- CLI documents exit 3 (incomplete), exit 2 (`--fail-on` on a complete scan), and Click's separate usage-error path.

### Operations
- Repeated gateway headers reuse bounded per-scan classification summaries; regex contention retries retain their original CPU and input deadlines.
- Docker build context uses an explicit input allowlist, Actions checkout drops persisted credentials, and both CI matrix jobs finish independently.
- Incremental fingerprints ignore literal excluded source directories while retaining CODEOWNERS inputs; project-root attribution scales with active ancestors in wide monorepos.
- Disposable non-root worker image (`Dockerfile`).
- CI runs lint, audit, test, and package checks in each Python matrix job, with a concurrency group.
- Example GitHub Action and README use commit-pinned install examples and document incomplete-scan gating.
- `docs/production.md` rollout checklist: split credentials, egress controls, tenant canaries, reports-as-secret.

### Migration
- Finding IDs for promoted resources change with these commits. Rebuild comparison baselines and incremental state when upgrading from an earlier revision.
- Install from a reviewed tag/SHA. Do not follow `main`.

### Known limits
- Connector deadlines are cooperative; blocked SDK/plugin calls still need host process timeouts.
- SDK timeouts and retry limits do not establish a universal deadline for authentication chains or whole scans; workers still require a host deadline.
- Incremental cache writes are atomic and protected by per-slot advisory locks on POSIX. Unsupported platforms and contention use full scans.
