# Security

ShadowScan is a **credential concentrator**. Config, environment variables,
`--dump-records` output, and HTML/JSON/SARIF reports are as sensitive as the
tokens you passed in.

## Trust boundary

The operator workstation or CI runner is trusted. Remote API responses,
scanned repositories, offline export directories, signature packs, and plugin
entry points are not.

## Rules

* Use dedicated read-only audit credentials. Never reuse a human PAT or an
  admin cloud role.
* `--dump-records` writes connector records after field-level redaction.
  Treat that directory as secret material. Use `--dump-raw` only on an
  air-gapped analyst machine.
* Findings redact secrets and identify JWTs by `sha256[:16]`. That is not a
  license to publish reports.
* `api_url` / `jwks_url` / pagination `next` links must stay on the
  configured origin. Link-local, loopback, and cloud-metadata hosts are
  blocked.
* Third-party `shadowscan.connectors` entry points cannot replace built-in
  names. Install plugins only from code you review.
* JWT classification decodes without verification. A token is only marked
  verified when the signature uses an allowlisted algorithm against a JWKS
  on the issuer host.

## Reporting

Open a private advisory or email the maintainer. Do not file a public issue
that includes tokens, dumps, or exploit details.
