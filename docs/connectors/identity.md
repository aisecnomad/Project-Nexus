# Identity connectors

Identity connectors discover OAuth apps, consent grants, service principals,
managed identities, and JWT tokens related to AI services and agent frameworks.

!!! info "Live and offline"
    Identity connectors support live API collection and offline JSON export
    analysis. JWT analysis is always offline (supplied tokens).

See the [shared connector entry guide](../connectors.md#connector-entry-guide)
for the common modes, permissions, options, fail-closed and evidence-limit
references.

## `identity.okta`
`/api/v1/apps` (+ `/grants`, `/tokens` for OIDC apps). Reports OAuth apps that
match AI SaaS signatures or hold privileged scopes, and service apps
(`application_type: service` / `client_credentials` / token-exchange).
Token: SSWS API token or OAuth bearer with `okta.apps.read`. A 429 is retried
after the window named by Okta's `X-Rate-Limit-Reset` header (bounded to 120 s
per wait); exhausted retries mark the scan incomplete.

## `identity.entra`
Microsoft Graph: service principals, delegated `oauth2PermissionGrants`,
app-only `appRoleAssignments` (role ids resolved to the names their resource
defines, such as `Mail.ReadWrite`), tenant app registrations, managed identities. First-party
Microsoft SPs are skipped unless they match AI signatures (Copilot).
Permissions (application): `Application.Read.All`, `DelegatedPermissionGrant.Read.All`,
`Directory.Read.All`. Or pass `access_token`.
Unresolved grant or role-assignment principals make collection incomplete while
preserving permission evidence for investigation. Such evidence cannot establish
an approved resource identity.
A service principal exported with conflicting records is reported the same way,
keeping AI evidence from up to 16 of its snapshots (64 evidence items).

### Microsoft Agent 365 packages (opt-in)

`include_agent_registry: true` lists the Microsoft Agent 365 catalog
(`GET /copilot/admin/catalog/packages`) and reads each package's details
(`GET /copilot/admin/catalog/packages/{id}`). `agent_registry_api` chooses the
Graph version: `v1.0` (default) or `beta`. Paging follows the opaque
`@odata.nextLink` until it is absent; a failed page or the page bound leaves the
listing incomplete. `max_package_lookups` (default 2000) caps the detail calls;
reaching it leaves details partial and the scan incomplete. Permission:
`CopilotPackages.Read.All`, as an application permission or delegated for a work
or school account. Microsoft documents the API for the global cloud only and
notes licensing prerequisites for package management. A 403 or 404 (no
licence, role or permission) makes the scan incomplete; it is never read as an
empty catalog.

Each package becomes a finding `entra:copilot-package:{id}` (resource type
`copilot-package`, account `tenant_id`). Its kind is `agent` when its
`elementTypes` include `bot`, `declarativeAgent` or `customEngineAgent`, or its
`governanceMetadata` is an agent class (every documented class except
`AIApp`), and `ai-app` otherwise. It carries a
[vendor registry record](../inventory.md#vendor-registries-as-inventory-sources)
with registry `microsoft-agent-365`, registry id `tenant_id`, descriptor type
`package`, and evidence `registry:microsoft-agent-365`:

| Package | Record status |
|---|---|
| `isBlocked: true` | `blocked` (tag `registry-blocked`) |
| `requestStatus: pending` | `pending` |
| `requestStatus: rejected` | `rejected` |
| `availableTo: allowedForNone` (or `none`) | `draft` |
| `isBlocked: false`, available to all or some users, and no request or an approved one | `approved` |
| any other combination, such as a missing `isBlocked` or an unknown enum member | `unknown` |

The rules apply in that order. Enum members are compared case-insensitively,
and both spellings Microsoft's pages use (`allowedForAll` and `all`,
`allowedForSome` and `some`) are accepted; unknown members are recorded as they
are and never approve. `approval_mode` is `manual` only for an organization's
own package (`type` `custom`, `shared` or `lob`) whose request was approved. Microsoft
and partner packages are vendor-published and get `unknown`, which a trusted
registry accepts for an `approved` package only when its entry sets
`allow_auto_approved`.

Bindings (provider `entra`, account `tenant_id`) name only objects the package
can own in this tenant, because the ids come from the package and an approved
package in a trusted tenant approves every object it binds:

- `entra:sp:{agentIdentityId}` only when that id is an agent identity the same
  export lists without conflicting records. A package that names any other
  service principal, or an agent identity that was not listed (for example
  without `include_agent_identities`), binds no service principal.
- `entra:app:{appId}` only for an organization's own package (`type` `custom`,
  `shared` or `lob`). Microsoft and partner packages, and unknown package types,
  never bind an app registration: their app is registered in the publisher's
  tenant, so an app registration of this tenant with that appId is not theirs.

A binding's coverage is `in-scope` only when the same run, or the run that
wrote the replayed export, collected that object type completely across the
tenant (an app-only listing); otherwise it is `unknown`. Service principals and
app registrations a package binds are reported even without AI signals of
their own (`metadata.registry_bound`), so the bindings can match them.
`listing_complete` is true only when an app-only listing and every detail call
finished without a warning, cap, conflicting or malformed record.
Without `tenant_id` the registry id is empty and the records can never be
trusted. With `tenant_id` set, a pre-issued app-only `access_token` (or
`GRAPH_ACCESS_TOKEN`) must be a JWT whose unverified `tid` claim equals
`tenant_id` (use the tenant ID, not a domain) before `include_agent_registry`
sends any request, so a token of another tenant never produces records
attributed to the configured one; a mismatch or an undecodable token skips the
connector (exit 3) with fixed text that names neither the token nor its claims.
Client credentials need no such check: their token is requested for
`tenant_id`. To let approved packages approve the objects they bind, list the
tenant in
[`trusted_registries`](../inventory.md#microsoft-agent-365).

Member lists (`allowedUsersAndGroups`, `acquireUsersAndGroups`,
`sharedWithUsersAndGroups`) are reduced to counts when collected and reported
as `allowed_principals`, `acquired_principals` and `shared_principals`; member
ids are never stored. The package file (`zipFile`) and element definitions are
not kept. `metadata.app_id` carries the package's appId, so an Azure Bot Service
finding with the same `msa_app_id` is linked. Package records with the same id
and different content are reported once with `identity_unresolved`, status
`unknown` and no bindings, and make the scan incomplete.

### Entra Agent ID agent identities (opt-in)

`include_agent_identities: true` lists agent identities from the Graph beta API
(`GET https://graph.microsoft.com/beta/servicePrincipals/microsoft.graph.agentIdentity`).
Microsoft documents agent identities in beta only, so this listing uses beta
whatever `agent_registry_api` says. An agent identity whose id is also a listed
service principal enriches that finding; otherwise it is its own finding
`entra:sp:{id}` with resource type `service-principal/AgentIdentity`. Both keep
the identity discriminator `service-principal`, so the finding id does not
change when the service principal listing starts returning the agent identity.
Agent identities are always reported, as `service-identity` findings with tag
`entra-agent-identity` and `metadata.agent_identity`,
`agent_identity_blueprint_id` and `created_by_app_id`. Their app-only
permissions come from `GET /servicePrincipals/{id}/appRoleAssignments`, read
for every listed agent identity that the service principal listing did not
return or skipped as first-party, within the same `max_app_role_lookups`
budget; reaching it leaves the permissions partial and the scan incomplete.
Agent identity records with the same id and different content give an
unresolved finding and make the scan incomplete. The Microsoft Graph pages these notes were checked against do
not name a dedicated read permission for the listing; confirm the
least-privileged permission on Microsoft's current beta reference before
granting one.

Beta APIs change without notice. A changed field shape makes the record
malformed and the scan incomplete; it never approves anything.

### Deprecated Entra agent registry (offline only)

Records exported from the deprecated beta `agentRegistry` (`agentInstance` and
`agentCardManifest`) are read from offline exports only and never collected
live. An instance becomes `entra:agent-registry-instance:{id}` with its embedded
card summarized in `metadata.agent_card`; a card that no exported instance
embeds becomes `entra:agent-registry-card:{id}`. Their registry records
(`entra-agent-registry`) have status `deprecated` and never approve, and the
configuration refuses to trust that registry type. Graph envelopes all use
`value`, so keep one kind per file or give each record a `_kind`.

### Coverage marker and replay

When an opt-in collection ran, live collection appends one
`agentRegistryCoverage` record (`packages`, `agentIdentities`: `complete`,
`incomplete` or `not-collected`; `applications`: `complete` or `incomplete`;
`listingScope`: `registry` or `caller`). It is exported with the other records,
so a replay keeps `listing_complete` and `in-scope` bindings and reports an
incomplete collection, or a package whose details were missing, as incomplete
again. An export without the marker, for example one taken from Graph by hand,
gives `listing_complete: false` and `unknown` binding coverage. The fixture
`tests/fixtures/identity/entra_agent_registry.json` is synthetic, modeled on
Microsoft's Graph reference pages, and has not been validated against a live
tenant.

### Delegated auth

`auth_mode: delegated` uses a signed-in user's Graph access token, read from the
environment variable named by `delegated_token_env` (default
`GRAPH_DELEGATED_TOKEN`). There is no configuration key for the token itself; do
not pass it through `${VAR}` expansion in a configuration file. Delegated mode
requires `tenant_id` and refuses `access_token`, `client_id` and
`client_secret`. It never falls back to `GRAPH_ACCESS_TOKEN` or the
`AZURE_CLIENT_*` variables and never calls the token endpoint.

Before any request, the token must be at most 16 KiB of token characters and an
unexpired JWT whose unverified claims show a tenant (`tid`) equal to
`tenant_id` (use the tenant ID, not a domain), a `scp` claim, and no
`idtyp: app`. A client cannot verify the signature of a Graph token, so these
checks bind the token to the configured scope; they do not authenticate it. A
failure names the variable, never the token or its claims, and skips the
connector (exit 3). The token is held only in the HTTP session headers, never
in records, findings, exports or diagnostics. It is not refreshed: a token
that expires during the scan (Microsoft access tokens usually last 60 to 90
minutes) returns HTTP 401 and the collection is incomplete.

The scan sees what the signed-in user may see. Grant the delegated
`CopilotPackages.Read.All` permission for packages, and have the operator who
signs in hold a Microsoft Entra role that can read the agent catalog, such as
AI Administrator; check Microsoft's current role guidance. Delegated package
listings are caller-scoped (`listing_scope: caller`): `listing_complete` is
always false, so they never mark findings `observed-not-registered`, and every
binding's coverage is `unknown`, so an object the user cannot see is never
reported `registered-not-observed`. Delegated and app-only
scans cover different scopes and are not comparable for drift; `auth_mode` is
recorded in the connector configuration. Every process the scanner starts,
including approved plugins in process mode, inherits the environment variable:
set it only for the duration of the scan.

### Live scope attestation

After authenticating, live collection reads `GET /organization?$select=id`
and attests the tenant the Graph returns, so `shadowscan diff` can resolve
findings between two complete live scans
([live collection scope](../scanning.md#live-collection-scope)). A `tenant_id`
that is a GUID must equal it, or the scan stops; a domain name in `tenant_id`
cannot be compared and the returned tenant is attested. The call needs
`Organization.Read.All` or `Directory.Read.All` for application tokens and
`User.Read` for delegated ones. It matters only for drift: when it is denied or
answers with anything but one tenant, the scan completes with an advisory
warning and its scope is not attested (`live principal could not be verified`).

The fingerprint covers `tenant_id`, `auth_mode`, `include_first_party`,
`max_app_role_lookups`, `include_agent_identities`, `include_agent_registry`,
`agent_registry_api` and `max_package_lookups`, never `client_id`, credentials
or the delegated token. Only app-only scans are attested: delegated listings
return what the signed-in user may see, so another user in the same tenant
could see less without any error. A delegated scan still verifies the tenant,
then completes with an advisory warning and an unattested scope. The
service principal, consent grant, application, agent identity and package
listings are the enumerations; each principal's `appRoleAssignments` and each
package's details are details, recorded per template and never fingerprinted,
and reaching `max_app_role_lookups` or `max_package_lookups` is recorded as a
truncation.

## `identity.google-workspace`
Admin SDK `users/{id}/tokens` for every user, aggregated per OAuth client:
"Fireflies has Gmail + Calendar for 214 users". Auth: service account with
domain-wide delegation impersonating an admin (`service_account_file` +
`admin_email`; scopes `admin.directory.user.readonly`,
`admin.directory.user.security`, `admin.directory.customer.readonly`) or an
`access_token` with those scopes. Live collection resolves the authenticated
immutable customer ID with `customers.get` before listing users. A configured
concrete `customer` must match; `my_customer` and email domains are not identities.
For service-account authentication, the signed assertion audience and token
exchange are fixed to `https://oauth2.googleapis.com/token`; a `token_uri` in
the key document cannot redirect the credential exchange.
Offline exports may contain individual token records or per-user objects such
as `{"user":"user@example.com","tokens":[...]}`. The latter retains user
attribution whether supplied as one object or inside an array. Offline runs must
set `customer` to a verified immutable customer ID. Missing or conflicting scope
makes collection incomplete and retained observations nonapprovable. Regenerate
older Google Workspace inventory cards with the explicit customer in
`discovery.accounts`; an accountless OAuth client binding cannot approve a grant.

## `identity.auth0`
Management API `clients` and `client-grants`: M2M applications, their
audiences and scopes, AI-named apps. Auth: M2M client for the Management API
(`read:clients`, `read:client_grants`) or `token`.

## `identity.jwt`
Decodes tokens (never stored) and classifies the holder as `human`, `service`,
`workload`, `delegated`, `agent` or `delegated-agent` using issuer-specific
conventions (Entra `idtyp=app`, Okta `cid == sub`, Auth0 `gty`, Google service
accounts, Cognito, Keycloak, SPIFFE) plus RFC 8693 `act` chains and
agent-related claims. GitHub Actions, Kubernetes service-account and GitLab CI
job tokens are `workload` identities; a `system:serviceaccount:` subject or
Kubernetes service-account claims make a `workload` whatever the issuer (GKE
included). A GitHub Actions `actor` or `triggering_actor` is an agent hint only
when it names an AI agent or product (`copilot-swe-agent[bot]`), not for a
person or an ordinary `[bot]` App login. An agent-related claim counts only with a
meaningful value: `bot: false`, `purpose: ""` or `tools: []` do not make an
agent. Scopes/roles are classified by the policy signatures;
lifetime and algorithm hygiene are flagged. Optional `jwks_url` verification
fetches a bounded JWKS through the shared HTTPS client and accepts only RS256,
ES256, EdDSA and PS256 by default. `allowed_algorithms` may narrow that list.
`expected_issuer` binds verification to an operator-supplied exact issuer; the
unverified token's issuer does not choose or authorize a key source. The JWKS URL
is configured by the operator, so legitimate providers may host keys separately.
Audience and historical-token expiry are not authorization checks here. Read
`metadata.verified` as signature evidence, not permission to act.
A token analyzed without `jwks_url`, or whose verification failed, carries
`metadata.signature_verified: false`, the `signature-unverified` tag and a
`jwt:signature` evidence item: its issuer family, identity type and privileged
scopes come from unauthenticated claims and can be forged. The marker does not
change confidence or risk. For a JWKS endpoint behind a private CA, set
`ca_bundle` to a PEM file; it replaces the default CA store for that fetch and
certificate verification stays on.

CLI equivalents: `--jwks-url`, `--expected-issuer`, and repeatable
`--jwt-algorithm`. The latter two require `--jwks-url`.


See the [main connector reference](../connectors.md) for shared options and offline safety limits.
