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
      allow_auto_approved: false        # optional, default false
      allow_registered_only: false      # optional, default false
```

Each entry names exactly one registry: `registry` is one of
`aws-agent-registry`, `aws-agentcore-registry`, `microsoft-agent-365`,
`google-agent-registry`, `gemini-enterprise`, `mcp-registry` or `a2a-card`
(the deprecated `entra-agent-registry` source cannot be trusted), and `id` is
that registry's exact identity as the connector reports it in
`registry_record.registry_id`. `allow_auto_approved` and
`allow_registered_only` must be YAML booleans; they accept auto-approved and
registered-only records of that registry. Wildcards (`*`, `?`,
`[`), surrounding whitespace, control characters, unknown keys, duplicate
entries, more than 64 entries and ids that report redaction would change are
rejected before anything is scanned. Trusting a registry type as a whole is not
possible. `${VAR}` expansion works in `id`. There is no command-line flag. See
[vendor registries as inventory sources](../inventory.md#vendor-registries-as-inventory-sources)
for what an approved record approves.

## MCP registry snapshots

`options.mcp_registries` pins MCP Registry snapshots that the scan matches
configured MCP servers against: where each server is published, whether its
pinned version is listed and current, and whether the registry marks it
deprecated or deleted. It is empty by default, and a scan never fetches a
registry. Produce a snapshot where direct HTTPS egress to the registry is
allowed:

```bash
shadowscan mcp-registry snapshot --output ./mcp-registry.json
```

The command lists every server version of the official registry
(`https://registry.modelcontextprotocol.io`), deleted versions included, writes
the file with mode 0600 and prints the SHA-256 to pin on standard output.
`--url` names another registry that serves the MCP Registry API v0.1, such as an
organisation's private catalog; `--ca-bundle` trusts a private CA and
`--allow-private-origin` allows a registry on a private address. The client
never uses a proxy, so run the command where the registry is reachable
directly. The listing is complete or nothing is written: a failed or refused
request, an invalid page, a repeated cursor, more than `--max-pages` pages
(default 5,000 pages of 100 versions), more than 500,000 versions or 256 MiB
exits with code 3. A snapshot keeps only what matching reads from each version:
its name and version, its packages (registry type, identifier, version and
registry base URL), its remote URLs, and the registry's status, latest flag and
publication time. A full official listing (about 145,000 versions in October
2026) is roughly 50 MB and takes the scan a few seconds and a few hundred MiB
of memory to load.

```yaml
options:
  mcp_registries:
    - id: official                      # 1-64 of a-z 0-9 . _ -, unique
      snapshot: ./mcp-registry.json     # resolved beside this configuration file
      sha256: <the SHA-256 the command printed>
    - id: corp-catalog
      snapshot: ./corp-mcp-catalog.json
      sha256: <its SHA-256>
      approved: true                    # the organisation's approved MCP catalog
```

At most 16 entries. `sha256` is 64 lowercase hexadecimal characters and
`approved` a YAML boolean (default false); unknown keys and repeated ids are
rejected before anything is scanned. Every scan reads each snapshot again
without following symbolic links and checks its pin. A snapshot that is
missing, changed, larger than 256 MiB, not strict JSON, not `complete`, of
another schema or API version, or that has an invalid entry (an unknown status,
a repeated name and version, an invalid name or version, a package or remote of
the wrong shape) is not used, and the scan is incomplete (`engine.mcp-registry`,
exit 3). A package or remote URL that nothing configured could match (a URL
that is templated, carries user information or does not parse, however long; a
package on another registry than its type's public one) is left out of the
index without rejecting the snapshot, so one publisher's entry cannot block
every snapshot. The ids, pins and approval flags
are part of the [collection scope](../scanning.md#comparing-reports) fingerprint when configured,
so a baseline taken with other snapshots is not comparable. See
[MCP registry provenance](../connectors/code.md#mcp-registry-provenance) for
what is matched and reported, and [risk scoring](../concepts/risk.md) for the
`mcp-not-in-approved-registry` governance factor an approved registry enables.

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
