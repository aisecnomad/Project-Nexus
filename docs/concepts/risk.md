# Risk scoring

ShadowScan assigns every finding a **confidence** score and a **risk** score.
These are distinct concepts. Both are computed from the finding's recorded
evidence and factors, so every score is auditable in the finding JSON.

## Confidence

Confidence answers: *how sure are we this is an agent or agent enabler?*

It is a **noisy-OR** of evidence weights (`Finding.recompute_confidence`):

```text
confidence = round(1 − ∏(1 − wᵢ), 3)
```

Each weight `wᵢ` is a finite number from 0 to 1: `Evidence` refuses any other
value when it is built or changed, so a corrupt report, cache entry or plugin
fails instead of turning NaN or a huge weight into certainty. Evidence that
shares a `confidence_group` attribute is correlated (for example, repeated
matches of one framework in a project), so each group contributes only its
strongest weight. Outside the code surface, evidence without an explicit group
is grouped by its signal, so repeated matches of one signal (several scopes of
one permission class, several system prompts in one workflow) count once. A
project that merely imports `openai` is not the same as a Bedrock Agent with a
confirmed runtime status.

Confidence is a heuristic evidence score, not a calibrated probability of
agent execution: the weights are authored in signature packs and connectors,
not fitted to observed outcomes. The `likelihood` label is only a bucket of that
score, not a verification state (`strong` is not "confirmed"):

| Likelihood | Confidence |
|------------|------------|
| `strong` | ≥ 0.85 |
| `likely` | ≥ 0.6 |
| `possible` | ≥ 0.3 |
| `weak` | < 0.3 |

The top bucket was called `confirmed` before the label was renamed. Reports,
`diff` baselines and incremental-cache entries that carry `confirmed` are still
read, as `strong`; all output uses `strong`. The label is not part of a finding's
identity.

Static findings retain framework features supported only by imports or
dependencies under `metadata.potential_capabilities`. Those features are not
scored as observed capabilities. Stronger source evidence, such as an agent
factory or an enabled executable tool definition, can support a capability;
source evidence still does not prove that the code ran in production.

A name is a mention, not use. Environment-variable names alone cap a project at
confidence 0.8 (tag `env-names-only`, `metadata.confidence_cap`). A data file
that lists four or more products by domain or variable name, such as a proxy
blocklist, a vendor policy or a copy of the signature packs, is a *catalog*:
its mentions count only for a product that also has an import, a dependency or
specific code evidence elsewhere in the project, and a project with nothing
else yields no finding. Discounted files are listed in
`metadata.catalog_mentions`. Source code, dotenv, Compose, Helm and CI files,
files under `.devcontainer/` or a top-level `config/` directory, files that
assign the variables they name and data files the project's own code loads are
never catalogs, and a file naming one to three products is configuration; see
[Code connectors](../connectors/code.md) for the exact rule and the threshold.

## Risk

Risk answers: *if this is an agent, how concerned should we be?*

Risk is **additive and explainable** (`shadowscan/risk.py`). Each factor adds
a signed weight and is recorded in `risk.factors`. The default weights
include:

| Factor | Description | Default weight |
|--------|-------------|----------------|
| `kind` | Base weight by finding kind (listed below the table) | 5–30 |
| `shadow` | Not in the sanctioned inventory (only when an inventory is supplied) | 25 |
| `registered` | Matched to exactly one inventory entry | −10 |
| `no-owner` | No identifiable owner | 10 |
| `tag:plaintext-credential` | Plaintext credential exposed | 25 |
| `tag:public-network` | Public network access enabled | 5 |
| `tag:public-ingress` | Publicly reachable ingress | 10 |
| `tag:public-principal` | Granted to `allUsers` / `allAuthenticatedUsers` | 20 |
| `tag:mcp-unpinned-package` | An MCP server is fetched by `npx`, `uvx`, `pipx run`, `docker run` and similar without an exact version or image digest | 10 |
| `tag:mcp-broad-filesystem` | An MCP filesystem server is given `/`, a drive root or a home directory | 10 |
| `tag:mcp-shell-command` | An MCP server is started through `sh -c`, `cmd /c` or `powershell -Command` | 5 |
| `tag:posture-permissions-bypassed` | An agent's settings run tool calls without approval (Claude Code `bypassPermissions`, Codex `approval_policy = "never"`, Goose `GOOSE_MODE: auto`) | 15 |
| `tag:posture-unrestricted-shell` | An agent may run any shell command (a bare `Bash` or `Bash(*)` allow rule, OpenClaw shell access) | 10 |
| `tag:posture-unsandboxed` | Codex `sandbox_mode = "danger-full-access"` | 10 |
| `tag:posture-exposed-gateway` | An OpenClaw gateway listens beyond loopback | 15 |
| `tag:posture-unauthenticated-gateway` | That exposed gateway has no auth token | 15 |
| `tag:exposed-llm-server` | LLM inference service is reachable beyond loopback or cluster scope | 15 |
| `tag:tool-poisoning` | MCP tool description contains prompt-injection or exfiltration indicators | 15 |
| `tag:unsafe-serialization` | Model artifact uses an unsafe serialization format | 15 |
| `tag:cluster-admin` | Workload service account is bound to cluster-admin | 20 |
| `tag:privileged-pod` | Workload requests privileged host access | 15 |
| `tag:no-egress-policy` | AI workload namespace has no NetworkPolicy egress controls | 10 |
| `capability:code-exec` | Can execute arbitrary code | 15 |
| `capability:autonomous` | Operates without human approval | 10 |
| `capability:tool-use` | Calls tools / functions | 5 |
| `capability:mcp-server` | Exposes tools to other agents over MCP | 5 |
| `tag:hidden-instructions` | Instruction file carries content hidden from the rendered view (an HTML comment holding sentences) | 20 |
| `tag:remote-code-fetch` | Instruction file downloads and executes code in one step, or decodes an inline blob into an interpreter | 15 |
| `tag:invisible-text` | Instruction file contains invisible or bidirectional control characters | 10 |
| `tag:disabled` / `tag:inactive` / `tag:suspended` | Resource is not active | −10 |

The `kind` base weight is 30 for `secret`; 15 for `agent` and `mcp-server`;
10 for `agent-config`, `workflow`, `bot-app`, `oauth-grant`,
`service-identity`, `iam-grant`, `gateway-caller`, `infra` and
`runtime-process`; and 5 for `framework-usage`, `cloud-resource`, `token`,
`ai-app`, `local-model` and `network-contact`.

The complete tables are `KIND_BASE`, `CAPABILITY_WEIGHTS`, `TAG_WEIGHTS`,
`PROVIDER_WEIGHTS` and `GOVERNANCE_WEIGHTS` in `shadowscan/risk.py`; tags with
a zero weight add no factor. Some factors depend on finding metadata:
`vendor-notes` (5, signature risk notes), `multiple-secrets` (5),
`mcp-stdio` (5), `mcp-auto-approve` (10), `mcp-plain-http` (10), `sub-agents`
(3 per definition, at most 10), `volume` (5 from 1,000 gateway events, 10 from
10,000) and `blast-radius` (5 from 10 users or installations, 10 from 100).
The `mcp-auto-approve` and `mcp-insecure-transport` tags label servers that
those metadata factors already score, so they carry no weight of their own.
The factors are broader: `mcp-plain-http` scores any server URL whose scheme
(parsed as the tag parses it) is `http` or `ws`, loopback included, while the
tag marks only plaintext URLs to another host, and both factors also count servers marked disabled, which the
tags skip.
Posture and MCP-risk evidence has weight 0: it changes risk, not confidence.
`options.risk_weights` overrides weights; see the README's risk policy. Its
keys are checked, so a typo cannot silently change nothing: unknown groups,
`kinds` and `governance` keys are rejected, `capabilities` keys must be one of
the capability names (`code-exec`, `autonomous`, `saas-actions`, `data-access`,
`browsing`, `memory`, `multi-agent`, `delegated-identity`, `tool-use`,
`mcp-server`, `rag`),
and `providers` keys must be the id of a provider signature in the loaded
signature packs (for example `provider.deepseek`, or an id from your own pack).
The error names the key and never echoes the value. `tags` is open-ended
(signature packs, plugins and identity types add their own tags), so an
unfamiliar tag key is accepted and logged once as a warning, with a suggestion
when it resembles a built-in tag.

### Confidence scaling

The sum of the factor weights is scaled by confidence and bounded to 0–100:

```text
raw   = sum of factor weights
scale = 0.6 + 0.4 × confidence        (confidence clamped to 0–1)
score = min(100, max(0, round(raw × scale)))
```

`round` rounds halves to even, and the arithmetic is exact: the confidence is
read as the decimal number it is written as (0.15, not the nearest binary
float), so a raw 75 at confidence 0.15 is 49.5 and scores 50, not 49.

A finding with confidence 1.0 keeps its full score; lower confidence reduces
it by at most 40%, so a low-confidence finding produces a lower effective risk
but severe factors still register. Below confidence 1.0 the change is listed as
a `confidence-scaling` factor, which is never positive, and a clamp at 0 or 100
as a `bounds` factor, so the listed factors always add up to `score`.

`risk.danger_score` applies the same scale and bounds to the factors other than
the governance factors (`shadow`, `registered`, `no-owner`). With
`options.risk_basis: danger` the governance factors are reported with weight 0,
so `score`, `level` and `--fail-on` follow the danger score.

## Shadow determination

A finding is `shadow: true` unless **exactly one** inventory entry matches
via an explicit resource pattern and its configured scope restrictions.
Name-only matches suggest entries for review but do not approve.

An approved entry lends its `owner` to the finding.

## Risk levels

| Level | Score range |
|-------|------------|
| Critical | 75–100 |
| High | 50–74 |
| Medium | 25–49 |
| Low | 1–24 |
| Info | 0 (also accepted by `--fail-on`) |

`--fail-on` turns a minimum risk level into exit code 2. The levels are
heuristic labels, not CVSS severities: read
[Severity is not an enforcement signal](../severity.md) before using one as a
CI gate.
