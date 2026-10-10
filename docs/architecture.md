# Architecture

```
                 ┌───────────────────────── signatures/data/*.yaml ────────────────────────┐
                 │ frameworks · providers · protocols · coding agents · platforms · cloud     │
                 │ services · observability · identity apps · policies · heuristics            │
                 └──────────────────────────────┬─────────────────────────────────────┘
                                                 │ SignatureIndex (dependency, import, code, file,
                                                 │ env, domain, user_agent, image, iac, name,
                                                 │ scope, model, secret, client_id matchers)
   ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐
   │  code.*   │  │identity.* │  │gateway.*  │  │lowcode.*  │  │  saas.*   │  │  cloud.*  │  │endpoint.* │  │network.*  │  │runtime.*  │   connectors
   │ fs/gh/gl  │  │okta/entra │  │logs/otel  │  │pp/sf/snow │  │slack/teams│  │aws/gcp/az │  │inv/host/  │  │  logs     │  │processes  │   collect() live → records
   │           │  │gws/auth0  │  │           │  │n8n/make   │  │gh-apps/…  │  │oci/k8s/os │  │mcp/ollama │  │           │  │           │   load_offline() → records
   │           │  │jwt        │  │           │  │zap/work   │  │atlassian/ │  │           │  │models/    │  │           │  │           │   analyze(records) → Findings
   │           │  │           │  │           │  │           │  │notion/zoom│  │           │  │ebpf       │  │           │  │           │
   └─────┬──────┘  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘
         └─────────────└─────────────└──────┬───────└────────────└────────────└────────────└────────────└────────────└────────────┘
                                              ▼
                                   ┌───────────────────┐
                                   │       Engine       │  merge duplicates → correlate across surfaces →
                                   │                    │  reconcile with Inventory (shadow?) → Risk → sort
                                   └─────────┬──────────┘
                                             ▼
              table · json · sarif · csv · markdown · html · cyclonedx · ocsf   (reporters)
```

## Modules

| module | responsibility |
|---|---|
| `shadowscan/models.py` | `Finding`, `Evidence`, `Risk`, `ScanResult`; confidence = noisy-OR of evidence weights, each group of correlated evidence counted once at its strongest weight (`confidence_group`, else the same signal outside the code surface) |
| `shadowscan/signatures/` | YAML loader/validator (`loader.py`) and matchers (`matcher.py`); packs in `data/` |
| `shadowscan/connectors/base.py` | `BaseConnector` (`collect`, `analyze`, `load_offline`, `run`, record dumping, [engine hooks](#engine-hooks)), `ConnectorContext` |
| `shadowscan/connectors/offline.py` | offline export reading: file discovery without following links, confined readers with byte limits, JSON / JSONL / YAML / CSV parsing, envelope and pagination checks |
| `shadowscan/connectors/common.py` | turning matches into evidence / frameworks / capabilities, permission classification, blob scanning, merging the metadata of duplicate findings |
| `shadowscan/connectors/<surface>/` | one module per data source |
| `shadowscan/connectors/code/remote.py` | shared by `code.github` and `code.gitlab`: offline clone loading, clone hardening and origin pinning, API snapshots and blob verification |
| `shadowscan/connectors/code/source_semantics.py` | bounded Python import binding, reachability and tool attribution, including literal comprehension exclusions |
| `shadowscan/connectors/code/polyglot_bindings.py`, `go_semantics.py`, `dotnet_semantics.py` | bounded lexical import and scope checks for supported Go agent constructors and .NET automatic tool invocation; no cross-file type resolution |
| `shadowscan/utils/http.py` | shared HTTPS client: destination policy, retries, 16 MiB response limit and whole-body read deadline |
| `shadowscan/utils/files.py` | confined reads: no link followed in any path component, directories opened for traversal only (`O_PATH` on Linux) |
| `shadowscan/utils/redaction.py` | redaction API (`sanitize`, `sanitize_text`, `policy_token`) driving the passes in the `redaction_*` modules; patch rules here, never in a `redaction_*` module |
| `shadowscan/registry.py` | inventory formats and reconciliation, capability-card stub generation |
| `shadowscan/risk.py` | additive, explainable risk model |
| `shadowscan/engine.py` | parallel connector execution, merge, correlation, reconciliation, scoring; no connector names |
| `shadowscan/config.py` | YAML config with `${ENV}` expansion, `--set` parsing, connector key validation |
| `shadowscan/errors.py` | `SetupError`: setup failures whose messages are credential-free and printed verbatim by the CLI |
| `shadowscan/reporters/` | output formats |
| `shadowscan/cli.py` | `scan`, `run`, `code`, `gateway`, `jwt`, `connectors`, `signatures`, `inventory`, `diff` |

## Finding lifecycle

1. A connector produces raw **records** (API objects, log lines, files). Live
   records can be dumped to JSONL (`--dump-records`) and replayed offline.
2. `analyze()` turns records into findings. Product knowledge is looked up in
   the signature index; every match becomes an `Evidence` with a weight and
   may add frameworks, model providers, capabilities, tags and policy classes.
3. `finalize()` computes confidence and promotes `framework-usage` to `agent`
   when an agent indicator matched.
4. The engine **merges** findings with the same stable source identity (surface,
   connector, provider, account, region, resource and observation discriminator),
   **correlates** across surfaces by resource ids and normalised names
   (`metadata.related`), **reconciles** with the inventory (`shadow`,
   `registry_match`, inherited owner) and **scores** risk. Findings below
   `min_confidence` are then dropped, together with the `related` links that
   name them.
5. Reporters render. SARIF carries `file:line` for code findings and logical
   locations elsewhere; HTML is self-contained.

Record exports are sanitized and published atomically with owner-only
permissions. Each JSONL line must be strict JSON and fit the replay line limit;
the whole file must fit both the configured per-file and aggregate input limits,
including newline bytes. A rejected record marks the scan incomplete and
prevents publication of the entire new export, preserving any prior file.
Encoding and export-size failures retain the original records for live analysis;
a sanitizer safety rejection skips the unsafe record before analysis. Successful
empty collections produce an explicit empty inventory instead of a zero-byte file.

Merging keeps the first observation's owner and metadata and unions evidence,
frameworks, capabilities, tags, permissions and models. Metadata that combines
across observations (`variable_names`, `runtime_observations`, and the
per-source request, token and cost metrics of gateway-surface callers) is merged
by `merge_duplicate_metadata` in `shadowscan/connectors/common.py`, next to the
connectors that emit those keys.

Reports declare `shadowscan.finding-identity/v2`. Inferred classification and
current permissions do not enter the ID. The default observation discriminator
is the resource-type family before `/`; connectors emitting distinct observations
of one resource within the same family must supply different stable
`identity_discriminator` values. Schema upgrades require fresh comparison
baselines and invalidate older incremental caches.

## Engine hooks

The engine never special-cases a connector name. Behaviour that differs by
connector is a capability the class declares; `BaseConnector` holds the
defaults, which describe an ordinary connector.

| hook | default | declared by | engine behaviour |
|---|---|---|---|
| `cache_roots_separately(roots, root_ids, *, labelled)` | `False` | `code.filesystem` | an incremental scan of several `paths` runs and caches one job per root; raising `ConnectorError` runs the connector once so its own validation reports the scan incomplete; any other exception marks the connector incomplete without running it |
| `inherits_instance_credentials_approval()` | `True` for a connector on the cloud surface or one whose `config_keys` documents `allow_instance_credentials` | every `cloud.*` connector, plugins included, through its surface: the registry holds `cloud.*` names to it | the connector's `allow_instance_credentials` is set from `options.allow_instance_credentials`, whether or not it documents the key; a value in any connector entry is replaced the same way, so it never takes effect; an exception from the hook marks the connector incomplete without running it |
| `scanned_local_paths(config)` | `[]` | `code.filesystem`; `code.github` and `code.gitlab` through their shared base class | the local files or directories the entry scans: `code.filesystem` paths (none when it replays an `input` export) and the offline clone directory (`input`) of a remote repository connector, whose live clones stay in private temporary directories; an approval inventory inside one of them is reported in the `engine.inventory` stats entry, because scanned content could edit its own approvals. Only built-in connectors are asked: the lookup never imports a plugin |
| `uses_run_identity_key` | `False` | `gateway.logs` | the connector's jobs share one private key per scan run (`ConnectorContext.gateway_identity_key`), so identical sources in one report share opaque caller and scope IDs that separate runs cannot link; when the operator sets `SHADOWSCAN_IDENTITY_KEY`, every run uses that stable key instead (`gateway_identity_key_stable`) and its IDs can be compared across runs |

The engine looks up the connector class once per configured entry and reads
these hooks from it. As in collection, the lookup, which imports an approved
plugin, runs under the scan's private-origin policy and is skipped once the
entry is out of time. When the lookup fails or is skipped the defaults apply
and the entry is reported incomplete. Plugins run with scanner privileges, so a
hook a plugin declares is trusted like the rest of its code.

## Design principles

* **Data-driven detection.** Adding a framework, a SaaS vendor or a scope class is a YAML change, testable with `shadowscan signatures test`.
* **Offline parity.** Every connector consumes exports so analysts can run without credentials and CI can run deterministic tests (`tests/fixtures/`).
* **Read-only and redacting.** No connector mutates state; secrets are redacted at capture; secret stores are enumerated by name only; JWTs are hashed.
* **Explainable scores.** Confidence lists its evidence; risk lists its factors.
* **Bounded work.** Caps on files, repos, teams, lambdas, records and pages; retries with back-off on rate limits.
* **Explicit coverage.** Unsupported records, provider errors, truncation and
  invalid selections make scans incomplete. An empty finding list is not proof
  of successful collection. Connectors must warn on skipped coverage and retain
  valid neighboring observations.

## Writing a connector

```python
from shadowscan.connectors.base import BaseConnector, ConnectorContext
from shadowscan.connectors.common import apply_matches, finalize, name_matches
from shadowscan.models import Evidence, Finding, Kind, Surface

class AcmeAgentHubConnector(BaseConnector):
    name = "platform.acme-hub"          # surface.provider
    surface = Surface.LOWCODE
    provider = "acme-hub"
    description = "Agents registered in Acme's internal agent hub."
    config_keys = {"url": "hub base URL", "token": "env ACME_HUB_TOKEN", "input": "offline: /agents JSON"}

    def collect(self):
        http = HttpClient(self.ctx.require("url"), headers={"Authorization": f"Bearer {self.ctx.require('token', env='ACME_HUB_TOKEN')}"})
        yield from http.paginate_token("/agents", items_key="agents")

    def analyze(self, records):
        for rec in records:
            f = Finding(surface=self.surface, connector=self.name, kind=Kind.AGENT, title=f"Acme hub agent: {rec['name']}",
                        resource=f"acme-hub:agent:{rec['id']}", resource_type="hub-agent", provider=self.provider, owner=rec.get("owner"))
            f.add_evidence(Evidence(signal="acme-hub:agent", description="registered in hub", weight=0.9))
            apply_matches(f, name_matches(self.index, rec["name"], rec.get("description")))
            yield finalize(f, self.index)
```

Offline mode needs no code: `BaseConnector.load_offline` reads the `input`
export through `shadowscan/connectors/offline.py`. Override `load_offline`, or
one of the thin `_`-prefixed offline methods it calls, only for a format the
shared parser does not cover.

Register it in `pyproject.toml`:

```toml
[project.entry-points."shadowscan.connectors"]
"platform.acme-hub" = "acme_shadowscan.hub:AcmeAgentHubConnector"
```

It appears in `shadowscan connectors` without importing plugin code. To execute
it, explicitly permit its exact connector name:

```yaml
options:
  plugins: [platform.acme-hub]
connectors:
  - name: platform.acme-hub
    url: https://agents.example.com
```

Plugins run trusted Python code with scanner privileges. The allowlist expresses
operator approval; it is not a sandbox. Built-in connector names remain reserved.

### Plugin identity rules

The entry-point name is the plugin's identity: it is what operators approve in
`options.plugins`, what `connectors:` entries reference, and what every finding
(`Finding.connector`, which enters the finding id) and scan statistic is
attributed to. Listing (`shadowscan connectors`) never imports plugin code. When
an approved plugin is loaded, the registry verifies the class the entry point
names and refuses the plugin if any rule fails; that connector then produces no
findings, the scan is incomplete, and the reason is available through
`shadowscan.connectors.plugin_registry_errors()` as printable, credential-free
`PluginDiagnostic` records (`entry`, `rule`, `message`).

* The class must subclass `BaseConnector` and implement `collect()` and
  `analyze()`.
* It must declare `name` equal to its entry-point name. A class registered as
  `saas.acme-alias` that declares `name = "saas.slack"` is refused, so its
  findings can never be attributed to the built-in connector.
* It must declare `surface` (a `Surface` member), a nonempty `description` and
  `config_keys` (option name to description). When the name uses a built-in
  namespace such as `saas.`, `surface` must match it; a new namespace such as
  `platform.` may use any surface.
* Neither the entry-point name nor the declared `name` may be a built-in
  connector name, a variant of one that differs only by case or surrounding
  whitespace, or a bare built-in namespace (`code`, `identity`, `gateway`,
  `lowcode`, `saas`, `cloud`). Names must be single printable tokens.
* A name registered by more than one entry point with different targets is
  ambiguous; none of those entries is listed or loaded, whatever the
  installation order.

These checks enforce the attribution contract for well-behaved plugins. They do
not constrain code that a loaded plugin runs.

### Packaging a plugin

The distribution is named `NexusShadowScan`; its import package, CLI command
and connector entry-point group remain `shadowscan`, `shadowscan` and
`shadowscan.connectors`. Do not declare `shadowscan` as a dependency: that PyPI
name belongs to an unrelated project.

Once a release is published, a plugin declares the scanner as an ordinary
dependency with a lower bound on the reviewed release, for example
`NexusShadowScan>=0.1.2`. Before then, depend on a reviewed full git revision,
as the README install instructions do, for example
`NexusShadowScan @ git+https://github.com/aisecnomad/Project-Nexus.git@<40-character-sha>`.
PyPI rejects direct URL requirements, so a plugin published on PyPI cannot use
that form. Use a fresh virtual environment when moving from an earlier Project
Nexus distribution named `shadowscan` or `project-nexus-shadowscan`; installing
two of them together can overwrite their shared import package and command.
