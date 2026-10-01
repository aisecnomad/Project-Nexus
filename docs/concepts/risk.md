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

Each weight `wᵢ` is clamped to 0–1. Evidence that shares a
`confidence_group` attribute is correlated (for example, repeated matches of
one framework in a project), so each group contributes only its strongest
weight. A project that merely imports `openai` is not the same as a Bedrock
Agent with a confirmed runtime status.

Confidence is a heuristic evidence score, not a calibrated probability of
agent execution: the weights are authored in signature packs and connectors,
not fitted to observed outcomes. The `likelihood` label is derived from it:

| Likelihood | Confidence |
|------------|------------|
| `confirmed` | ≥ 0.85 |
| `likely` | ≥ 0.6 |
| `possible` | ≥ 0.3 |
| `weak` | < 0.3 |

Static findings retain framework features supported only by imports or
dependencies under `metadata.potential_capabilities`. Those features are not
scored as observed capabilities. Stronger source evidence, such as an agent
factory or an enabled executable tool definition, can support a capability;
source evidence still does not prove that the code ran in production.

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
| `capability:code-exec` | Can execute arbitrary code | 15 |
| `capability:autonomous` | Operates without human approval | 10 |
| `tag:disabled` / `tag:inactive` / `tag:suspended` | Resource is not active | −10 |

The `kind` base weight is 30 for `secret`; 15 for `agent` and `mcp-server`;
10 for `agent-config`, `workflow`, `bot-app`, `oauth-grant`,
`service-identity`, `iam-grant`, `gateway-caller` and `infra`; and 5 for
`framework-usage`, `cloud-resource` and `token`.

The complete tables are `KIND_BASE`, `CAPABILITY_WEIGHTS`, `TAG_WEIGHTS`,
`PROVIDER_WEIGHTS` and `GOVERNANCE_WEIGHTS` in `shadowscan/risk.py`; tags with
a zero weight add no factor. Some factors depend on finding metadata:
`vendor-notes` (5, signature risk notes), `multiple-secrets` (5),
`mcp-stdio` (5), `mcp-auto-approve` (10), `mcp-plain-http` (10), `sub-agents`
(3 per definition, at most 10), `volume` (5 from 1,000 gateway events, 10 from
10,000) and `blast-radius` (5 from 10 users or installations, 10 from 100).
`options.risk_weights` overrides weights; see the README's risk policy.

### Confidence scaling

The sum of the factor weights is scaled by confidence and bounded to 0–100:

```text
raw   = sum of factor weights
scale = 0.6 + 0.4 × confidence        (confidence clamped to 0–1)
score = min(100, max(0, round(raw × scale)))
```

`round` is Python's rounding (halves to even). A finding with confidence 1.0
keeps its full score; lower confidence reduces it by at most 40%, so a
low-confidence finding produces a lower effective risk but severe factors
still register. Below confidence 1.0 the change is listed as a
`confidence-scaling` factor, which is never positive, and a clamp at 0 or 100
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

Use `--fail-on` to gate CI pipelines on a minimum risk level.
