# Quick start

## 1. Scan a local checkout

No credentials needed — scan a repository or directory:

```bash
shadowscan code . --inventory inventory/
```

## 2. Try the offline demo

Every connector also accepts offline exports. The bundled fixtures demonstrate
all surfaces without live credentials:

```bash
shadowscan scan -c examples/shadowscan.offline.yaml --format html -o report.html
```

Open `report.html` to explore findings with evidence drill-down.

## 3. Scan with live connectors

Create a configuration file with your credentials:

```yaml
# shadowscan.yaml
inventory: [./inventory]
options:
  fail_on: high
connectors:
  - name: code.github
    org: acme
    token: ${GITHUB_TOKEN}
  - name: identity.entra
    tenant_id: ${AZURE_TENANT_ID}
    client_id: ${AZURE_CLIENT_ID}
    client_secret: ${AZURE_CLIENT_SECRET}
  - name: saas.slack
    token: ${SLACK_TOKEN}
```

Then run:

```bash
shadowscan scan -c shadowscan.yaml --format sarif -o shadowscan.sarif --fail-on high
```

## 4. Analyze a single connector

```bash
shadowscan run identity.entra --set tenant_id=$AZURE_TENANT_ID
shadowscan run cloud.aws --set regions=us-east-1,eu-west-1 --dump-records ./exports
shadowscan run cloud.aws --input ./exports/cloud_aws.jsonl    # re-analyse later
```

## 5. Analyze tokens and logs

```bash
shadowscan gateway litellm-spend.jsonl bedrock-invocations/ egress-proxy.log
shadowscan jwt "$TOKEN" --jwks-url https://acme.okta.com/oauth2/default/v1/keys
```

## 6. Register what you found

```bash
shadowscan inventory stubs report.json -o inventory/pending/
shadowscan diff last-week.json today.json
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Completed scan, passed `--fail-on` threshold |
| `2`  | Completed scan, findings reached `--fail-on` level |
| `3`  | Incomplete scan (API failures, timeouts, permission denials) |

## Next steps

- [Configuration reference](configuration.md) for all options
- [Connector reference](../connectors.md) for credentials and scopes
- [Production deployment](../production.md) for CI and container usage
