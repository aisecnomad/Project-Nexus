# Architecture

```
                 ┌────────────────────────── signatures/data/*.yaml ──────────────────────────┐
                 │ frameworks · providers · protocols · coding agents · platforms · cloud     │
                 │ services · observability · identity apps · policies · heuristics            │
                 └───────────────────────────────┬─────────────────────────────────────────────┘
                                                 │ SignatureIndex (dependency, import, code, file,
                                                 │ env, domain, user_agent, image, iac, name,
                                                 │ scope, model, secret, client_id matchers)
   ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐
   │  code.*   │  │identity.* │  │gateway.*  │  │lowcode.*  │  │  saas.*   │  │  cloud.*  │   connectors
   │ fs/gh/gl  │  │okta/entra │  │  logs     │  │pp/sf/snow │  │slack/teams│  │aws/gcp/az │   collect() live → records
   └─────┬─────┘  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘   load_offline() → records
         └──────────────┴──────────────┴──────┬───────┴──────────────┴──────────────┘         analyze(records) → Findings
                                              ▼
                                   ┌────────────────────┐
                                   │       Engine       │  merge duplicates → correlate across surfaces →
                                   │                    │  reconcile with Inventory (shadow?) → Risk → sort
                                   └─────────┬──────────┘
                                             ▼
                        table · json · sarif · csv · markdown · html   (reporters)
```

## Modules

| module | responsibility |
|---|---|
| `shadowscan/models.py` | `Finding`, `Evidence`, `Risk`, `ScanResult`; confidence = noisy-OR of evidence weights |
| `shadowscan/signatures/` | YAML loader/validator (`loader.py`) and matchers (`matcher.py`); packs in `data/` |
| `shadowscan/connectors/base.py` | `BaseConnector` (`collect`, `analyze`, `load_offline`, `run`, record dumping), `ConnectorContext` |
| `shadowscan/connectors/common.py` | turning matches into evidence / frameworks / capabilities, permission classification, blob scanning |
| `shadowscan/connectors/<surface>/` | one module per data source |
| `shadowscan/registry.py` | inventory formats and reconciliation, capability-card stub generation |
| `shadowscan/risk.py` | additive, explainable risk model |
| `shadowscan/engine.py` | parallel connector execution, merge, correlation, reconciliation, scoring |
| `shadowscan/config.py` | YAML config with `${ENV}` expansion, `--set` parsing |
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
4. The engine **merges** findings with the same id (same connector + resource),
   **correlates** across surfaces by resource ids and normalised names
   (`metadata.related`), **reconciles** with the inventory (`shadow`,
   `registry_match`, inherited owner) and **scores** risk.
5. Reporters render. SARIF carries `file:line` for code findings and logical
   locations elsewhere; HTML is self-contained.

## Design principles

* **Data-driven detection.** Adding a framework, a SaaS vendor or a scope class is a YAML change, testable with `shadowscan signatures test`.
* **Offline parity.** Every connector consumes exports so analysts can run without credentials and CI can run deterministic tests (`tests/fixtures/`).
* **Read-only and redacting.** No connector mutates state; secrets are redacted at capture; secret stores are enumerated by name only; JWTs are hashed.
* **Explainable scores.** Confidence lists its evidence; risk lists its factors.
* **Bounded work.** Caps on files, repos, teams, lambdas, records and pages; retries with back-off on rate limits.

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

Register it in `pyproject.toml`:

```toml
[project.entry-points."shadowscan.connectors"]
"platform.acme-hub" = "acme_shadowscan.hub:AcmeAgentHubConnector"
```

It then appears in `shadowscan connectors` and can be used in configs.
