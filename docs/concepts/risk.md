# Risk scoring

ShadowScan assigns every finding a **confidence** score and a **risk** score.
These are distinct concepts.

## Confidence

Confidence answers: *how sure are we this is an agent or agent enabler?*

It is computed as a **noisy-OR** of evidence weights. A project that merely
imports `openai` is not the same as a Bedrock Agent with a confirmed runtime
status. Each piece of evidence (a dependency match, an import pattern, a
running process, an API response) contributes a weight between 0 and 1.

## Risk

Risk answers: *if this is an agent, how concerned should we be?*

Risk is **additive and explainable**. Each factor adds a weighted score:

| Factor | Description | Typical weight |
|--------|-------------|----------------|
| `shadow` | Not in the sanctioned inventory | 25 |
| `no-owner` | No identifiable owner | 10 |
| `tag:plaintext-credential` | Plaintext credential exposed | 25 |
| `tag:public-network` | Accessible from public network | 15 |
| `capability:code-exec` | Can execute arbitrary code | 15 |
| `capability:autonomous` | Operates without human approval | 10 |
| `kind:agent` | Full agent vs. framework-usage | 5 |

The final risk score is scaled by confidence — a low-confidence finding
produces a lower effective risk even if the risk factors are severe.

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
| Low | 0–24 |

Use `--fail-on` to gate CI pipelines on a minimum risk level.
