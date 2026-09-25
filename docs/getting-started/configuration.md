# Configuration

ShadowScan is configured through a YAML file passed with `-c` / `--config`.
Environment variables are expanded using `${VAR}` syntax; missing required
values fail closed.

## Full reference

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

connectors:
  - name: code.github
    org: acme
    token: ${GITHUB_TOKEN}
  # ... see docs/connectors.md for all connector keys
```

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
shadowscan signatures list                         # show all 178 signatures
shadowscan signatures test langchain               # test what a value matches
shadowscan signatures test sk-proj-abc...          # test a key format
```
