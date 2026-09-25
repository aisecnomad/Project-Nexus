# Identity connectors

Identity connectors discover OAuth apps, consent grants, service principals,
managed identities, and JWT tokens related to AI services and agent frameworks.

!!! info "Live and offline"
    Identity connectors support live API collection and offline JSON export
    analysis. JWT analysis is always offline (supplied tokens).

### `identity.okta`
`/api/v1/apps` (+ `/grants`, `/tokens` for OIDC apps). Reports OAuth apps that
match AI SaaS signatures or hold privileged scopes, and service apps
(`application_type: service` / `client_credentials` / token-exchange).
Token: SSWS API token or OAuth bearer with `okta.apps.read`.

### `identity.entra`
Microsoft Graph: service principals, delegated `oauth2PermissionGrants`,
app-only `appRoleAssignments` (role ids resolved to names such as
`Mail.ReadWrite`), tenant app registrations, managed identities. First-party
Microsoft SPs are skipped unless they match AI signatures (Copilot).
Permissions (application): `Application.Read.All`, `DelegatedPermissionGrant.Read.All`,
`Directory.Read.All`. Or pass `access_token`.
Unresolved grant or role-assignment principals make collection incomplete while
preserving permission evidence for investigation. Such evidence cannot establish
an approved resource identity.
A service principal exported with conflicting records is reported the same way,
keeping AI evidence from up to 16 of its snapshots (64 evidence items).

### `identity.google-workspace`
Admin SDK `users/{id}/tokens` for every user, aggregated per OAuth client:
"Fireflies has Gmail + Calendar for 214 users". Auth: service account with
domain-wide delegation impersonating an admin (`service_account_file` +
`admin_email`; scopes `admin.directory.user.readonly`,
`admin.directory.user.security`, `admin.directory.customer.readonly`) or an
`access_token` with those scopes. Live collection resolves the authenticated
immutable customer ID with `customers.get` before listing users. A configured
concrete `customer` must match; `my_customer` and email domains are not identities.
Offline exports may contain individual token records or per-user objects such
as `{"user":"user@example.com","tokens":[...]}`. The latter retains user
attribution whether supplied as one object or inside an array. Offline runs must
set `customer` to a verified immutable customer ID. Missing or conflicting scope
makes collection incomplete and retained observations nonapprovable. Regenerate
older Google Workspace inventory cards with the explicit customer in
`discovery.accounts`; an accountless OAuth client binding cannot approve a grant.

### `identity.auth0`
Management API `clients` and `client-grants`: M2M applications, their
audiences and scopes, AI-named apps. Auth: M2M client for the Management API
(`read:clients`, `read:client_grants`) or `token`.

### `identity.jwt`
Decodes tokens (never stored) and classifies the holder as `human`, `service`,
`workload`, `delegated`, `agent` or `delegated-agent` using issuer-specific
conventions (Entra `idtyp=app`, Okta `cid == sub`, Auth0 `gty`, Google service
accounts, Cognito, Keycloak, SPIFFE) plus RFC 8693 `act` chains and
agent-related claims. Scopes/roles are classified by the policy signatures;
lifetime and algorithm hygiene are flagged. Optional `jwks_url` verification
fetches a bounded JWKS through the shared HTTPS client and accepts only RS256,
ES256, EdDSA and PS256 by default. `allowed_algorithms` may narrow that list.
`expected_issuer` binds verification to an operator-supplied exact issuer; the
unverified token's issuer does not choose or authorize a key source. The JWKS URL
is configured by the operator, so legitimate providers may host keys separately.
Audience and historical-token expiry are not authorization checks here. Read
`metadata.verified` as signature evidence, not permission to act.

CLI equivalents: `--jwks-url`, `--expected-issuer`, and repeatable
`--jwt-algorithm`. The latter two require `--jwks-url`.


See the [main connector reference](../connectors.md) for shared options and offline safety limits.
