# Configuration

ShadowScan is configured through a YAML file passed with `-c` / `--config`.
Environment variables are expanded using `${VAR}` syntax; missing required
values fail closed. An invalid configuration, like an invalid command-line
option, stops the command with exit code 1 before anything is scanned (see
[exit codes](../operations/ci.md#exit-code-handling)).

## Common options

This page shows the options most configurations use. `parallel`, `incremental`,
`state_dir`, `workdir`, `job_deadline_seconds`, `risk_basis` and `risk_weights`
are documented in the [README risk policy](https://github.com/aisecnomad/Project-Nexus/blob/main/README.md#risk-policy),
[scan semantics](../scanning.md) and [production deployment](../production.md).

```yaml
# shadowscan.yaml
inventory: [./inventory]              # Agent Cards, agents.yaml, or CSV
signatures: [./custom-signatures]     # optional extra or overriding packs
options:
  min_confidence: 0.3                 # finding threshold (0.0–1.0)
  fail_on: high                       # exit 2 if any finding reaches this level
  dump_records: ./exports             # sanitized records for offline re-runs
  connector_timeout_seconds: 120      # cooperative deadline per connector
  allow_private_origin: false         # permit non-global IP addresses
  allow_instance_credentials: false   # permit cloud instance-metadata credentials
  allow_credential_mixing: false      # permit repo + live tenant in one scan
  allow_signature_override: false     # permit custom sigs to replace built-in IDs
  plugins: []                         # exact-name allowlist for third-party connectors
  plugin_execution: thread            # or process: killable spawned plugin workers

connectors:
  - name: code.github
    org: acme
    token: ${GITHUB_TOKEN}
  # ... see docs/connectors.md for all connector keys
```

`llm_triage` is off unless `enabled: true`; it sends a redacted summary of
the highest-risk findings to a model you name and stores an advisory verdict.
See [LLM triage](../operations/llm-triage.md) for its keys and what is sent.

`plugin_execution: process` (or `--plugin-execution process`) runs each
allowlisted third-party connector in its own spawned worker that the scanner
can terminate at the connector deadline. Built-in connectors always use the
thread backend. Workers keep the scanner's privileges and credentials: this is
lifecycle isolation, not a sandbox. See
[third-party plugin execution](../connectors.md#third-party-plugin-execution).

## Trusted vendor registries

`options.trusted_registries` lists the vendor registry instances whose
approved records count as sanctioned inventory. It is empty by default: a
record that a vendor registry marks approved does not make a finding
sanctioned unless its registry is listed here.

```yaml
options:
  trusted_registries:
    - registry: aws-agent-registry      # registry type
      id: arn:aws:agent-registry:us-east-1:123456789012:registry/abcd1234abcd
```

Each entry names exactly one registry: `registry` is one of
`aws-agent-registry`, `aws-agentcore-registry`, `microsoft-agent-365`,
`entra-agent-registry`, `google-agent-registry`, `gemini-enterprise`,
`mcp-registry` or `a2a-card`, and `id` is that registry's exact identity as the
connector reports it in `registry_record.registry_id`. Wildcards (`*`, `?`,
`[`), surrounding whitespace, control characters, unknown keys, duplicate
entries, more than 64 entries and ids that report redaction would change are
rejected before anything is scanned. Trusting a registry type as a whole is not
possible. `${VAR}` expansion works in `id`. There is no command-line flag. See
[vendor registries as inventory sources](../inventory.md#vendor-registries-as-inventory-sources)
for what an approved record approves.

## Environment variable expansion

All string values support `${VAR}` expansion:

- `${VAR}` — required; fails if unset or empty
- `${VAR:-default}` — uses `default` if unset or empty

## Incremental scanning

Use `--incremental` to reuse completed scans of unchanged local checkouts and
static exports. Live APIs and gateway logs are refreshed on every run.

## Connector listing

```bash
shadowscan connectors                      # list all connectors with config keys
shadowscan connectors --surface code       # filter by surface
```

## Signature listing

```bash
shadowscan signatures list                         # show the installed signature set
shadowscan signatures test langchain               # test what a value matches
shadowscan signatures test sk-proj-abc...          # test a key format
```
