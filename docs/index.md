# ShadowScan

**Find the AI agents nobody registered.**

ShadowScan sweeps the six places agents hide — code repositories, identity
providers, LLM gateway logs, low-code platforms, SaaS apps, and cloud
accounts — fingerprints the frameworks and model providers they use, scores
their risk, and reconciles every discovery against your sanctioned inventory
of Agent Cards.

What is left over is *shadow*.

```
$ shadowscan scan -c shadowscan.yaml --inventory inventory/ --format html -o report.html

╭──────────────────────────────── ShadowScan ────────────────────────────────╮
│ 97 findings  •  94 shadow (inventory: 3 registered agents)                │
│ critical 14  high 47  medium 35  low 1  •  code 12 identity 21 cloud 27 … │
╰────────────────────────────────────────────────────────────────────────────╯
```

## Why ShadowScan?

Agents are no longer only Python scripts. They are Copilot Studio bots built
by HR, `n8n` flows with an AI Agent node, OAuth grants to meeting
note-takers, Bedrock Agents provisioned by Terraform, MCP servers wired into
every developer's editor, service principals with `Mail.ReadWrite` acting on
behalf of nobody, and JWTs carrying an `act` claim.

Each surface has its own discovery API and its own vocabulary. ShadowScan
normalizes all of them into one finding model with evidence, so you can
answer three questions for every agent in the estate:

1. **Who owns it?**
2. **What can it do?**
3. **Did anyone approve it?**

## Key capabilities

- **212 signatures / 990 signals** covering orchestrators, protocols, coding
  agents, platforms, model providers, and observability tools
- **27 connectors** across 6 surfaces, each with live API collection,
  offline export analysis, or both
- **Additive, explainable risk scoring** with evidence-backed confidence
- **Sanctioned inventory** reconciliation via Agent Cards
- **Multiple output formats**: table, JSON, SARIF, CSV, Markdown, HTML
- **Incremental scanning** for unchanged local checkouts and static exports

## Quick links

- [Installation](getting-started/install.md)
- [Quick start](getting-started/quickstart.md)
- [Connector reference](connectors.md)
- [Production deployment](production.md)
- [Contributing](contributing.md)
- [Changelog](changelog.md)
