# Deployment and migration

This hardening release addresses the eight findings from the September 2026
review and completes the published PR #8 helper integration. It adds bounded
YAML/ownership processing, annotated-assignment redaction, exact generated
inventory bindings, per-instance record exports, deployed ECS revision discovery,
GCP basic-role visibility and correct AWS account initialization.

## Explicit security policy

```yaml
options:
  plugins: []
  allow_signature_override: false
  allow_private_origin: false
connectors:
  - name: identity.jwt
    input: ./tokens.json
    jwks_url: https://identity.example.com/keys
    expected_issuer: https://identity.example.com/
    allowed_algorithms: [RS256]
```

`plugins` contains exact connector names, not module paths or wildcard patterns.
Approved plugins still run trusted Python code. `shadowscan connectors` lists
installed plugin metadata without importing it. A plugin must be explicitly
allowed on each scan, even if a prior scan imported it.

Custom packs can add signatures by default. Replacing a built-in signature
requires explicit `allow_signature_override` approval. Enable private origins
only when the selected scan requires a trusted private HTTPS endpoint; keep
network-layer restrictions appropriate for that scan. Separate private-endpoint
scans from public collection when they need different trust policy.

All scan commands also expose `--allow-plugin`,
`--allow-signature-override/--deny-signature-override` and
`--allow-private-origin/--deny-private-origin`. Configured values are retained
unless explicitly overridden. Signature inspection commands expose the same
signature override opt-in. JWT CLI verification additionally accepts
`--expected-issuer` and repeatable `--jwt-algorithm`.

The shared HTTP transport enforces destination policy at connection time and
retains TLS hostname checks. HTTP proxies are unsupported; environment proxies
are ignored. Cloud SDK and Git transport behavior remains separate. Do not assume
that the shared client's policy controls every network connection in the process.

JWT verification is for analysis. The default scope is signature evidence;
configuring `expected_issuer` also binds the issuer. Neither mode authorizes a
request or substitutes for audience, expiry and application-policy validation in
an actual relying service.

## Resource limits and incomplete scans

YAML parsing checks input size, composed nodes, alias count, nesting, expanded
nodes/content and merge work before object construction. Sanitization has a
separate expanded-structure and total-work budget, so valid YAML aliases cannot
cause unbounded report serialization. CODEOWNERS patterns use bounded iterative
matching with a per-root work budget.

A limit hit is a diagnostic and incomplete coverage, not proof of absence. Exit 3
must remain a failed gate in CI. Exit 2 means a complete scan exceeded the chosen
risk threshold. Hosted CI has a job timeout as an additional containment boundary;
there is no claim of a universal deadline for all vendor SDKs.

Use disposable, resource-limited workers for untrusted repository scans. Keep
scanner state and output outside the repository under review. Avoid handing
production credentials to a job that executes repository-controlled build steps.

## Output and inventory migration

Reports and inventory stub files now use atomic 0600 writes. Inventory stub and
record-export directories are created as 0700; existing non-private directories
are rejected without changing their permissions. Use dedicated directories for
these outputs.

Dump filenames include the original connector configuration ordinal and a safe
label. Repeated names or normalization-colliding labels no longer overwrite each
other. Selecting a subset with `--only` retains the original ordinal. Use the
export manifest to locate each instance's file and completion status instead of
assuming a filename such as `cloud_aws.jsonl`. Exports remain sanitized and are
not lossless copies of upstream responses. JWTs are never included.

Generated resource patterns escape literal `*`, `?` and `[` characters. Review
previously generated cards for those characters and regenerate literal bindings
where necessary. Existing intentionally authored wildcard approvals remain valid.

## Cloud collection changes

AWS resolves its account before emitting account metadata. ECS discovery follows
exact definition ARNs referenced by running tasks and service deployments,
including referenced inactive revisions, and retains the latest active registered
revision of each family as a separate evidence category. Stopped tasks and unused
historical revisions are outside this collection scope. A registered-only label
does not prove a definition is undeployed when discovery is incomplete.
The per-region `max_ecs_api_calls` limit defaults
to 2000; exceeding it or encountering denied/partial calls marks coverage
incomplete. Add the read permissions listed in [connectors.md](connectors.md).

GCP Owner/Editor-only principals remain visible as privileged access findings.
Neither broad role grants nor ECS deployment references establish that AI code
actually executed. Use trusted runtime telemetry for additional attribution.

## Release verification

The CI workflow installs all cloud SDK extras and validates signatures, lint, typing, dependency advisories, tests
with a minimum 80% statement coverage, wheel creation and offline SARIF output.
Focused regressions cover the review findings, private-address enforcement,
public-key verification, plugin policy, artifact permissions and replay integrity.
Dependabot checks Python and GitHub Actions dependencies weekly.

Automated and mocked provider-contract checks do not validate a tenant's actual
permissions, enabled services, data retention or export trust chain. Before an
operational rollout, run a read-only canary in each target tenant, inspect complete
coverage and account identity, verify expected known resources, and compare live
results with the retained export. These environment-specific checks require
access to those tenants and are not performed by offline CI.
