# Security

ShadowScan is a **credential concentrator**. Config, environment variables,
`--dump-records` output, incremental cache, and HTML/JSON/SARIF reports are as
sensitive as the tokens you passed in.

## Trust boundary

The operator workstation or CI runner is trusted. Remote API responses,
scanned repositories, offline export directories, signature packs, and plugin
entry points are not.

## Rules

* Use dedicated read-only audit credentials. Never reuse a human PAT or an
  admin cloud role.
* `--dump-records` writes connector records after field-level redaction.
  Treat that directory as secret material. There is no `--dump-raw` flag;
  unsanitized connector records are never written to disk.
* Findings redact secrets and identify JWTs by `sha256[:16]`. That is not a
  license to publish reports.
* `api_url` / `jwks_url` / pagination `next` links must use HTTPS and stay on
  the configured origin. Link-local, loopback, unspecified, multicast, and
  cloud-metadata hosts are rejected by `validate_url`.
* Third-party `shadowscan.connectors` entry points can add new connector names.
  They cannot replace a built-in name. Install plugins only from code you review.
* JWT classification decodes without verification. A token is only marked
  verified when the signature uses an allowlisted algorithm (`RS256`/`PS256`/
  `ES256`/`EdDSA` and SHA-384/512 variants) against a JWKS fetched through
  `HttpClient` on the token issuer host.
* Offline export directories are walked without following symlinks. Individual
  files are opened with `O_NOFOLLOW` and a size cap.
* `git clone --branch` only accepts a conservative ref alphabet; values that
  look like switches are dropped.

## Reporting

Open a private advisory or email the maintainer. Do not file a public issue
that includes tokens, dumps, or exploit details.
