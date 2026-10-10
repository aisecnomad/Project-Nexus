"""Microsoft Entra ID (Azure AD) via Microsoft Graph.

Collects service principals (enterprise apps, managed identities, first-party
Copilot SPs), delegated OAuth2 permission grants, application (app-only) role
assignments and tenant-owned app registrations, then reports:

* third-party AI apps consented by users / admins (``oauth-grant``)
* machine identities holding Graph / Copilot / Azure OpenAI permissions (``service-identity``)
* app registrations that look like in-house agents (``service-identity``)

Opt-in collections (default off):

* ``include_agent_identities``: Entra Agent ID agent identities (Graph beta), which
  enrich the service principal finding of the same id or stand alone;
* ``include_agent_registry``: Microsoft Agent 365 catalog packages, reported as
  vendor registry records (``metadata.registry_record``, registry
  ``microsoft-agent-365``, see :mod:`shadowscan.registries`).

Records of the deprecated Entra agent registry (``agentInstance``,
``agentCardManifest``) are accepted from offline exports only; their registry
records (``entra-agent-registry``) are ``deprecated`` and never approve.

Auth (``auth_mode: app-only``, the default): client credentials (``tenant_id`` /
``client_id`` / ``client_secret``) with ``Application.Read.All`` +
``DelegatedPermissionGrant.Read.All`` + ``Directory.Read.All``, or a pre-issued
``access_token`` (whose ``tid`` must be ``tenant_id`` when Agent 365 records are
collected; with an opt-in collection, a decodable token must be issued for Microsoft
Graph, and one that is not app-only makes the agent listings caller-scoped).
``auth_mode: delegated`` reads a signed-in user's Graph token from the environment
variable named by ``delegated_token_env``; it is never refreshed. Caller-scoped agent
listings show one user's view, so they make the scan incomplete.

Offline export: any mix of Graph objects (servicePrincipal, oauth2PermissionGrant,
appRoleAssignment, application, agentIdentity, copilotPackage, agentInstance,
agentCardManifest); each record may carry ``_kind`` or is inferred from its shape.
"""

from __future__ import annotations

import re
import time
from collections.abc import Generator, Iterable, Iterator
from dataclasses import dataclass
from typing import Any, ClassVar
from urllib.parse import quote

from requests import RequestException

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError, _positive_limit
from shadowscan.connectors.common import config_boolean, failure_summary, finalize, scope_matches
from shadowscan.connectors.identity.common import assess_app, identity_kind_for, summarize_scopes
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.registries import (
    LISTING_SCOPES,
    MAX_IDENTIFIER_LENGTH,
    RECORD_KEY,
    RECORD_SCHEMA,
    registry_evidence,
)
from shadowscan.utils.http import HttpClient, HttpError
from shadowscan.utils.safe_json import strict_json_loads

GRAPH = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"
# Microsoft Agent 365 catalog; documented under v1.0 and beta.
COPILOT_PACKAGES = "/copilot/admin/catalog/packages"
AGENT_REGISTRY_APIS = {"v1.0": GRAPH, "beta": GRAPH_BETA}
# Entra Agent ID agent identities are a service principal subtype listed by an OData cast (beta only).
AGENT_IDENTITIES = f"{GRAPH_BETA}/servicePrincipals/microsoft.graph.agentIdentity"
AGENT_365 = "microsoft-agent-365"
DEPRECATED_REGISTRY = "entra-agent-registry"
AUTH_MODES = ("app-only", "delegated")
DEFAULT_DELEGATED_TOKEN_ENV = "GRAPH_DELEGATED_TOKEN"
MAX_DELEGATED_TOKEN_CHARS = 16 * 1024
# The audiences of a Microsoft Graph access token: v1 tokens name the resource URI, v2 tokens its appId.
GRAPH_AUDIENCES = frozenset(
    {"https://graph.microsoft.com", "https://graph.microsoft.com/", "00000003-0000-0000-c000-000000000000"}
)
# The coverage marker a live collection appends when an opt-in collection ran; it survives export,
# so a replay knows which collections were complete.
COVERAGE_KIND = "agentRegistryCoverage"
COVERAGE_STATES = ("complete", "incomplete", "not-collected")
PACKAGE_DETAIL_STATES = ("observed", "unavailable", "limit")
# Detail states of a package whose detail call failed or was capped: its request status is unknown.
_MISSING_DETAIL = frozenset({"unavailable", "limit"})
FIRST_PARTY_OWNER = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"  # Microsoft services tenant
MAX_CONFLICTING_SNAPSHOTS = 16
MAX_CONFLICTING_EVIDENCE = 64
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
_TOKEN_CHARACTERS = re.compile(r"[A-Za-z0-9._~+/=-]+")
# Package element types and governance classes that make a package an agent; enum spellings
# vary between the Graph reference and its examples, so they are compared case-insensitively.
_AGENT_ELEMENT_TYPES = frozenset({"bot", "bots", "declarativeagent", "customengineagent"})
_AGENT_CLASSES = frozenset({"promptagent", "hostedagent", "workflowagent", "managedagent", "unmanaged"})
# Package types an organization publishes itself; Microsoft and partner packages are vendor-published.
_ORG_PUBLISHED_TYPES = frozenset({"shared", "custom", "lob"})
_AVAILABLE = frozenset({"allowedforall", "all", "allowedforsome", "some"})
_AVAILABLE_TO_NONE = frozenset({"allowedfornone", "none"})
# User and group lists of a package; only their sizes are kept.
_ACCESS_LISTS = ("allowedUsersAndGroups", "acquireUsersAndGroups", "sharedWithUsersAndGroups")
# Never kept in a collected package record: member ids, the package file and element definitions.
_DROPPED_PACKAGE_FIELDS = frozenset({"zipFile", "elementDetails", "@odata.context", *_ACCESS_LISTS})
_PACKAGE_STRINGS = (
    "type",
    "shortDescription",
    "longDescription",
    "platform",
    "version",
    "manifestId",
    "manifestVersion",
    "assetId",
    "agentIdentityId",
    "governanceMetadata",
    "requestStatus",
    "requestType",
    "publisher",
    "availableTo",
    "deployedTo",
    "sensitivity",
    "createdDateTime",
    "lastModifiedDateTime",
    "lastUsedDateTime",
    "_detail",
)
_INSTANCE_STRINGS = (
    "agentIdentityId",
    "agentIdentityBlueprintId",
    "agentUserId",
    "url",
    "preferredTransport",
    "originatingStore",
    "sourceAgentId",
    "managedBy",
    "createdBy",
    "createdDateTime",
    "lastModifiedDateTime",
)
_CARD_STRINGS = (
    "id",
    "displayName",
    "description",
    "protocolVersion",
    "version",
    "documentationUrl",
    "iconUrl",
    "originatingStore",
    "managedBy",
    "createdBy",
    "createdDateTime",
    "lastModifiedDateTime",
)
# Typed Graph fields: a record whose field has another JSON type is rejected.
_STRING_FIELDS = (
    "_kind",
    "id",
    "appId",
    "displayName",
    "appDisplayName",
    "publisherName",
    "notes",
    "description",
    "servicePrincipalType",
    "appOwnerOrganizationId",
    "scope",
    "consentType",
    "principalId",
    "clientId",
    "appRoleId",
    "resourceId",
    "homepage",
    "loginUrl",
)
_ARRAY_FIELDS = (
    "appRoles",
    "oauth2PermissionScopes",
    "replyUrls",
    "requiredResourceAccess",
    "passwordCredentials",
    "keyCredentials",
    "tags",
)


class _GraphExport:
    """Graph records indexed by principal; conflicting principal snapshots are retained."""

    def __init__(self) -> None:
        self.sps: dict[str, dict[str, Any]] = {}
        self.grants: dict[str, list[dict[str, Any]]] = {}
        self.role_assignments: dict[str, list[dict[str, Any]]] = {}
        self.applications: list[dict[str, Any]] = []
        # App role and scope ids are unique per resource only, so labels are
        # kept per (resource principal id, role id) and (resource appId, role
        # id); roleMap labels name no resource. Every label seen is retained.
        self.resource_role_labels: dict[tuple[str, str], set[str]] = {}
        self.app_role_labels: dict[tuple[str, str], set[str]] = {}
        self.role_labels: dict[str, set[str]] = {}
        self.role_map_labels: dict[str, set[str]] = {}
        self.reported_role_conflicts: set[tuple[str | None, str]] = set()
        self.conflicting_sps: set[str] = set()
        self.conflicting_snapshots: dict[str, list[dict[str, Any]]] = {}
        self.truncated_snapshots: set[str] = set()
        # Agent ID, Agent 365 and deprecated agent registry records, by id. A second record
        # with the same id and another body makes the id conflicting; snapshots are bounded.
        self.agent_identities: dict[str, dict[str, Any]] = {}
        self.conflicting_agent_identities: set[str] = set()
        self.agent_identity_snapshots: dict[str, list[dict[str, Any]]] = {}
        self.packages: dict[str, dict[str, Any]] = {}
        self.conflicting_packages: set[str] = set()
        self.package_snapshots: dict[str, list[dict[str, Any]]] = {}
        self.agent_instances: dict[str, dict[str, Any]] = {}
        self.conflicting_instances: set[str] = set()
        self.card_manifests: dict[str, dict[str, Any]] = {}
        self.conflicting_cards: set[str] = set()
        self.coverage_markers: list[dict[str, Any]] = []
        # Whether any record was rejected: a listing missing a record is not complete.
        self.rejected = False

    def agent_identity_id(self, value: Any) -> str | None:
        """``value`` when it names a listed agent identity whose records do not conflict."""
        principal_id = _text(value)
        if (
            principal_id is None
            or principal_id not in self.agent_identities
            or principal_id in self.conflicting_agent_identities
            or principal_id in self.conflicting_sps
        ):
            return None
        return principal_id


@dataclass(frozen=True, slots=True)
class _Coverage:
    """Which collections of the run (or of the replayed export) finished complete."""

    packages: str = "unknown"
    agent_identities: str = "unknown"
    applications: str = "unknown"
    listing_scope: str = "registry"
    # A rejected record may be the object a binding names, so no binding is known to be in scope.
    rejected: bool = False
    # The export names another tenant than tenant_id: its records are not attributed to tenant_id.
    foreign_tenant: bool = False


class EntraConnector(BaseConnector):
    name: ClassVar[str] = "identity.entra"
    surface: ClassVar[Surface] = Surface.IDENTITY
    provider: ClassVar[str | None] = "entra"
    description: ClassVar[str] = (
        "Entra ID service principals, OAuth consent grants, app-only permissions, app registrations, "
        "Agent ID agent identities and Microsoft Agent 365 packages via Microsoft Graph."
    )
    # Agent 365 packages are registry records; deprecated Entra agent registry records are offline only.
    emits_registry_records: ClassVar[bool] = True
    registry_record_types: ClassVar[frozenset[str]] = frozenset({AGENT_365, DEPRECATED_REGISTRY})
    config_keys: ClassVar[dict[str, str]] = {
        "tenant_id": "env AZURE_TENANT_ID",
        "client_id": "env AZURE_CLIENT_ID",
        "client_secret": "env AZURE_CLIENT_SECRET",
        "access_token": (
            "pre-issued Graph token (env GRAPH_ACCESS_TOKEN) instead of client credentials; with "
            "include_agent_registry and tenant_id, its tid claim must equal tenant_id; with an opt-in "
            "agent collection, a decodable token must be a Microsoft Graph token (aud), and one that is "
            "not app-only (idtyp app, no scp) gives caller-scoped listings and an incomplete scan"
        ),
        "auth_mode": (
            "app-only (default: client credentials or access_token) or delegated (a signed-in user's Graph "
            "token read from the environment variable named by delegated_token_env; never refreshed)"
        ),
        "delegated_token_env": (
            "name of the environment variable that holds the delegated Graph token (default "
            "GRAPH_DELEGATED_TOKEN); the token itself is never configuration"
        ),
        "include_first_party": (
            "include Microsoft first-party service principals (default false, Copilot SPs always kept)"
        ),
        "max_app_role_lookups": (
            "cap on per-principal appRoleAssignments calls, agent identities included (default 2000)"
        ),
        "include_agent_identities": (
            "collect Entra Agent ID agent identities from the Graph beta API (default false)"
        ),
        "include_agent_registry": (
            "collect Microsoft Agent 365 catalog packages as registry records (default false; needs "
            "CopilotPackages.Read.All)"
        ),
        "agent_registry_api": "Graph version for the Agent 365 package catalog: v1.0 (default) or beta",
        "max_package_lookups": "cap on per-package detail calls (default 2000)",
        "input": "offline: JSON export of Graph objects",
    }

    def __init__(self, ctx: ConnectorContext):
        super().__init__(ctx)
        self.tenant = ctx.get("tenant_id", env="AZURE_TENANT_ID")
        self.include_first_party = config_boolean(
            ctx.get("include_first_party", False), "include_first_party"
        )
        self.max_lookups = _positive_limit(ctx.get("max_app_role_lookups", 2000), "max_app_role_lookups")
        self.include_agent_identities = config_boolean(
            ctx.get("include_agent_identities", False), "include_agent_identities"
        )
        self.include_agent_registry = config_boolean(
            ctx.get("include_agent_registry", False), "include_agent_registry"
        )
        self.registry_api = ctx.get("agent_registry_api", "v1.0")
        if self.registry_api not in AGENT_REGISTRY_APIS:
            raise ConnectorError("identity.entra: agent_registry_api must be v1.0 or beta")
        self.max_package_lookups = _positive_limit(
            ctx.get("max_package_lookups", 2000), "max_package_lookups"
        )
        self.auth_mode = ctx.get("auth_mode", "app-only")
        if self.auth_mode not in AUTH_MODES:
            raise ConnectorError("identity.entra: auth_mode must be app-only or delegated")
        token_env = ctx.get("delegated_token_env", DEFAULT_DELEGATED_TOKEN_ENV)
        if not isinstance(token_env, str) or not _ENV_NAME.fullmatch(token_env):
            raise ConnectorError("identity.entra: delegated_token_env must name an environment variable")
        self.delegated_token_env = token_env
        if self.auth_mode == "delegated":
            # A delegated scan uses exactly one credential: the signed-in user's token. Its
            # tenant binds the token (tid) and names the registry.
            configured = (
                ctx.config.get("access_token"),
                ctx.config.get("client_id"),
                ctx.config.get("client_secret"),
            )
            if any(value is not None for value in configured):
                raise ConnectorError(
                    "identity.entra: auth_mode delegated does not accept access_token, client_id or "
                    "client_secret"
                )
            if not isinstance(self.tenant, str) or not self.tenant.strip():
                raise ConnectorError("identity.entra: auth_mode delegated requires tenant_id")
        self.http: HttpClient | None = None
        # Whether agent listings show only what one user may see: always for a delegated token, and
        # for a pre-issued access_token that is not an app-only token.
        self._caller_scoped = self.auth_mode == "delegated"
        # The tenant the credential is bound to: a checked tid, or the tenant client credentials were
        # minted for. The coverage marker records it, so a replay cannot attribute records elsewhere.
        self._bound_tenant: str | None = None
        # Paths whose collection failed in this run.
        self._failed: set[str] = set()
        # Principals whose appRoleAssignments were requested; their number is capped by max_lookups.
        self._role_lookups: set[str] = set()
        self._role_lookups_capped = False

    # ----------------------------------------------------------------- auth
    def _auth(self) -> None:
        if self.auth_mode == "delegated":
            # Never falls back to GRAPH_ACCESS_TOKEN or client credentials from the environment.
            token = self._delegated_token()
            self.http = HttpClient(
                GRAPH, headers={"Authorization": f"Bearer {token}", "ConsistencyLevel": "eventual"}
            )
            return
        token = self.ctx.get("access_token", env="GRAPH_ACCESS_TOKEN")
        if token and (self.include_agent_registry or self.include_agent_identities):
            self._check_app_only_token(token)
        if not token:
            cid = self.ctx.get("client_id", env="AZURE_CLIENT_ID")
            secret = self.ctx.get("client_secret", env="AZURE_CLIENT_SECRET")
            if not (self.tenant and cid and secret):
                raise ConnectorError(
                    "identity.entra: tenant_id, client_id and client_secret (or access_token) are required"
                )
            client = HttpClient()
            resp = client.post(
                f"https://login.microsoftonline.com/{self.tenant}/oauth2/v2.0/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": cid,
                    "client_secret": secret,
                    "scope": "https://graph.microsoft.com/.default",
                },
            )
            token = client.read_json_response(resp)["access_token"]
            # Requested from the tenant's own token endpoint, so the token is bound to tenant_id.
            self._bound_tenant = str(self.tenant)
        self.http = HttpClient(
            GRAPH, headers={"Authorization": f"Bearer {token}", "ConsistencyLevel": "eventual"}
        )

    def _delegated_token(self) -> str:
        """The signed-in user's Graph token from ``delegated_token_env``, checked before any request.

        Graph access tokens cannot be signature-verified by a client, so the claims are read
        unverified and serve as scope bindings only: the token must be a delegated (``scp``,
        not ``idtyp: app``) Microsoft Graph token (``aud``) of ``tenant_id`` that has not
        expired. Failures use fixed text; neither the token nor its claims enter a message.
        The checked tenant becomes the bound tenant that the coverage marker records.
        """
        name = self.delegated_token_env
        token = self.ctx.secret_env(name)
        if not token:
            raise ConnectorError(f"identity.entra: environment variable {name} is not set")
        if len(token) > MAX_DELEGATED_TOKEN_CHARS or not _TOKEN_CHARACTERS.fullmatch(token):
            raise ConnectorError(
                f"identity.entra: environment variable {name} does not hold a usable access token"
            )
        claims = self._check_token_tenant(token, "the delegated token")
        _check_graph_audience(claims, "the delegated token")
        scopes = claims.get("scp")
        if claims.get("idtyp") == "app" or not isinstance(scopes, str) or not scopes.strip():
            raise ConnectorError("identity.entra: the delegated token is not a delegated user token")
        expires = claims.get("exp")
        if isinstance(expires, (int, float)) and not isinstance(expires, bool) and expires <= time.time():
            raise ConnectorError("identity.entra: the delegated token has expired")
        self._bound_tenant = claims["tid"]
        return token

    def _check_app_only_token(self, token: Any) -> None:
        """Bind a pre-issued ``access_token`` before an opt-in agent collection sends any request.

        Registry records are attributed to ``tenant_id``, which operators trust, so with
        ``include_agent_registry`` a token of another tenant must not produce them (a minted
        token is bound by its request). A decodable token must be a Microsoft Graph token. A
        token that is not app-only (it has ``scp``, its ``idtyp`` is not ``app``, or it cannot
        be decoded) lists only what its user may see: its agent listings are caller-scoped,
        never a complete registry.
        """
        if self.include_agent_registry and self._binding_account():
            claims: dict[str, Any] | None = self._check_token_tenant(token, "the access_token")
        else:
            claims = _unverified_claims(token) if isinstance(token, str) else None
        if claims is not None:
            _check_graph_audience(claims, "the access_token")
            tenant, account = claims.get("tid"), self._binding_account()
            if isinstance(tenant, str) and account and tenant.lower() == account.strip().lower():
                self._bound_tenant = tenant
        if claims is None or "scp" in claims or claims.get("idtyp") != "app":
            self._caller_scoped = True

    def _check_token_tenant(self, token: Any, label: str) -> dict[str, Any]:
        """The unverified claims of a pre-issued token whose tenant (``tid``) must be ``tenant_id``.

        ``label`` is fixed text naming the token; neither the token nor its claims enter a message.
        """
        claims = _unverified_claims(token) if isinstance(token, str) else None
        if claims is None:
            raise ConnectorError(f"identity.entra: {label} is not a decodable JWT")
        tenant = claims.get("tid")
        if not isinstance(tenant, str) or tenant.lower() != str(self.tenant).strip().lower():
            raise ConnectorError(
                f"identity.entra: the tenant (tid) of {label} does not match tenant_id (use the tenant ID)"
            )
        return claims

    def _pages(self, path: str, **kwargs: Any) -> Iterator[dict[str, Any]]:
        assert self.http
        try:
            yield from self.http.paginate_odata(path, **kwargs)
        except (HttpError, RequestException, RuntimeError, ValueError) as exc:
            self._failed.add(path)
            status = failure_summary(exc)
            if path.endswith("/appRoleAssignments"):
                self.ctx.warn(
                    f"identity.entra: appRoleAssignments unreadable for {path} ({status}); app-only "
                    "permission inventory incomplete"
                )
            else:
                self.ctx.warn(f"identity.entra: collection incomplete for {path} ({status})")

    # -------------------------------------------------------------- collect
    def collect(self) -> Iterable[dict[str, Any]]:
        self._auth()
        assert self.http
        sp_select = (
            "id,appId,displayName,appDisplayName,publisherName,servicePrincipalType,accountEnabled,"
            "createdDateTime,tags,appOwnerOrganizationId,homepage,replyUrls,signInAudience,verifiedPublisher,"
            "notes,appRoleAssignmentRequired,appRoles,oauth2PermissionScopes,description,loginUrl"
        )
        sps = list(self._pages("/servicePrincipals", params={"$select": sp_select, "$top": 999}))
        for sp in sps:
            sp["_kind"] = "servicePrincipal"
            yield sp
        for grant in self._pages("/oauth2PermissionGrants", params={"$top": 999}):
            grant["_kind"] = "oauth2PermissionGrant"
            yield grant
        yield from self._app_role_assignments(
            str(sp["id"])
            for sp in sps
            if sp.get("appOwnerOrganizationId") != FIRST_PARTY_OWNER or self.include_first_party
        )
        for app in self._pages(
            "/applications",
            params={
                "$select": (
                    "id,appId,displayName,createdDateTime,requiredResourceAccess,passwordCredentials,"
                    "keyCredentials,web,spa,publicClient,signInAudience,notes,tags,description"
                ),
                "$top": 999,
            },
        ):
            app["_kind"] = "application"
            yield app
        if not (self.include_agent_identities or self.include_agent_registry):
            return
        # What one user may see is never the whole registry: the scan must not look complete.
        if self.auth_mode == "delegated":
            self.ctx.warn(
                "identity.entra: auth_mode delegated lists only the agent identities and packages the "
                "signed-in user can see; agent registry coverage incomplete"
            )
        elif self._caller_scoped:
            self.ctx.warn(
                "identity.entra: the access_token is not a decodable app-only token, so agent listings "
                "show only what its user can see; agent registry coverage incomplete (use auth_mode: "
                "delegated for a signed-in user's token)"
            )
        identities = "not-collected"
        if self.include_agent_identities:
            agent_identities = list(self._pages(AGENT_IDENTITIES))
            for identity in agent_identities:
                yield {**identity, "_kind": "agentIdentity"}
            identities = "incomplete" if AGENT_IDENTITIES in self._failed else "complete"
            # Agent identities are always reported, so each one's app-only permissions are read,
            # including those the service principal listing did not return or skipped.
            yield from self._app_role_assignments(
                identity_id
                for identity in agent_identities
                if isinstance(identity_id := identity.get("id"), str) and identity_id.strip()
            )
        packages = "not-collected"
        if self.include_agent_registry:
            packages = "complete" if (yield from self._collect_packages()) else "incomplete"
        marker = {
            "_kind": COVERAGE_KIND,
            "packages": packages,
            "agentIdentities": identities,
            "applications": "incomplete" if "/applications" in self._failed else "complete",
            # The Graph returns what the signed-in user may see: never a complete registry listing.
            "listingScope": "caller" if self._caller_scoped else "registry",
        }
        if self._bound_tenant and len(self._bound_tenant) <= MAX_IDENTIFIER_LENGTH:
            marker["tenantId"] = self._bound_tenant
        yield marker

    def _app_role_assignments(self, principal_ids: Iterable[str]) -> Iterator[dict[str, Any]]:
        """Each principal's app role assignments, once per principal, within ``max_app_role_lookups``."""
        for principal_id in principal_ids:
            if principal_id in self._role_lookups:
                continue
            if len(self._role_lookups) >= self.max_lookups:
                if not self._role_lookups_capped:
                    self._role_lookups_capped = True
                    self.ctx.warn(
                        "identity.entra: max_app_role_lookups reached; app-only permissions partial"
                    )
                return
            self._role_lookups.add(principal_id)
            principal = quote(principal_id, safe="")
            for a in self._pages(f"/servicePrincipals/{principal}/appRoleAssignments", params={"$top": 999}):
                a["_kind"] = "appRoleAssignment"
                yield a

    def _collect_packages(self) -> Generator[dict[str, Any], None, bool]:
        """Agent 365 packages with their details; returns whether the listing finished complete.

        Member lists become counts (``_accessCounts``); the package file and element
        definitions are not kept. ``_detail`` records whether the detail call succeeded, so a
        replay of the export knows what was missing.
        """
        listing = AGENT_REGISTRY_APIS[self.registry_api] + COPILOT_PACKAGES
        complete = True
        capped = False
        lookups = 0
        for item in self._pages(listing):
            record = _package_record(item)
            package_id = item.get("id")
            if not isinstance(package_id, str) or not package_id.strip():
                # Analysis rejects the record; the listing is not complete without it.
                complete = False
                yield {**record, "_kind": "copilotPackage"}
                continue
            if lookups >= self.max_package_lookups:
                if not capped:
                    capped = True
                    self.ctx.warn("identity.entra: max_package_lookups reached; package details partial")
                complete = False
                yield {**record, "_kind": "copilotPackage", "_detail": "limit"}
                continue
            lookups += 1
            detail = self._package_detail(listing, package_id)
            if detail is None:
                complete = False
                yield {**record, "_kind": "copilotPackage", "_detail": "unavailable"}
            else:
                yield {**record, **_package_record(detail), "_kind": "copilotPackage", "_detail": "observed"}
        return complete and listing not in self._failed

    def _package_detail(self, listing: str, package_id: str) -> dict[str, Any] | None:
        assert self.http
        try:
            detail = self.http.get_json(f"{listing}/{quote(package_id, safe='')}")
        except (HttpError, RequestException, RuntimeError, ValueError) as exc:
            self.ctx.warn(
                f"identity.entra: package details unreadable ({failure_summary(exc)}); "
                "registry coverage incomplete"
            )
            return None
        if not isinstance(detail, dict) or detail.get("id") != package_id:
            self.ctx.warn(
                "identity.entra: package details do not describe the listed package; registry coverage "
                "incomplete"
            )
            return None
        return detail

    # -------------------------------------------------------------- analyze
    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        graph = self._index_records(records)
        coverage = self._coverage(graph)
        # Packages whose records bind objects: neither conflicting nor missing their details.
        packages = {
            package_id: package
            for package_id, package in graph.packages.items()
            if package_id not in graph.conflicting_packages and package.get("_detail") not in _MISSING_DETAIL
        }
        # Objects an Agent 365 package binds are reported even without AI signals of their own,
        # so its bindings can match them.
        bound_principals = {
            graph.agent_identity_id(package.get("agentIdentityId")) for package in packages.values()
        } - {None}
        bound_apps = {_bindable_app_id(package) for package in packages.values()} - {None}
        conflicting = graph.conflicting_sps | graph.conflicting_agent_identities
        sp_by_app_id = {sp.get("appId"): sp for sp_id, sp in graph.sps.items() if sp_id not in conflicting}
        for sp_id, sp in graph.sps.items():
            if sp_id in conflicting:
                continue
            self.ctx.examined()
            f = self._sp_finding(
                sp,
                graph.grants.get(sp_id, []),
                graph.role_assignments.get(sp_id, []),
                graph,
                agent_identity=graph.agent_identities.get(sp_id),
                keep=sp_id in bound_principals,
            )
            if f:
                yield f
        for sp_id, identity in graph.agent_identities.items():
            if sp_id in graph.sps or sp_id in conflicting:
                continue
            self.ctx.examined()
            f = self._sp_finding(
                identity,
                graph.grants.get(sp_id, []),
                graph.role_assignments.get(sp_id, []),
                graph,
                agent_identity=identity,
                sp_type="AgentIdentity",
            )
            if f:
                yield f
        # A missing principal must not silently erase observed consent or
        # application privileges. Keep the permission evidence, but do not
        # invent the missing application's identity or permit registry approval.
        principals = graph.sps.keys() | graph.agent_identities.keys()
        unresolved = ((graph.grants.keys() | graph.role_assignments.keys()) - principals) | conflicting
        for sp_id in sorted(unresolved):
            self.ctx.examined()
            self.ctx.warn(
                "identity.entra: evidence references an unresolved service principal; coverage incomplete"
            )
            f = self._unresolved_finding(sp_id, graph)
            if f:
                yield f
        for app in graph.applications:
            self.ctx.examined()
            f = self._app_registration_finding(
                app, sp_by_app_id.get(app.get("appId")), graph, keep=app.get("appId") in bound_apps
            )
            if f:
                yield f
        for package in graph.packages.values():
            self.ctx.examined()
            yield self._package_finding(package, graph, coverage)
        embedded_cards: set[str] = set()
        for instance in graph.agent_instances.values():
            self.ctx.examined()
            card = instance.get("agentCardManifest")
            if isinstance(card, dict) and isinstance(card.get("id"), str):
                embedded_cards.add(card["id"])
            yield self._instance_finding(instance, graph, coverage)
        for card_id, card in graph.card_manifests.items():
            self.ctx.examined()
            if card_id not in embedded_cards:
                yield self._card_finding(card, graph)

    def _index_records(self, records: Iterable[dict[str, Any]]) -> _GraphExport:
        graph = _GraphExport()
        for rec in records:
            kind = self._record_kind(rec)
            if kind is None:
                graph.rejected = True
                self.ctx.warn("identity.entra: unsupported or malformed Graph record; coverage incomplete")
                continue
            if kind == "roleMap":
                for role_id, value in (rec.get("roles") or {}).items():
                    graph.role_map_labels.setdefault(role_id, set()).add(value)
            elif kind == "servicePrincipal":
                self._add_principal(graph, rec)
            elif kind == "oauth2PermissionGrant":
                graph.grants.setdefault(rec.get("clientId", ""), []).append(rec)
            elif kind == "appRoleAssignment":
                graph.role_assignments.setdefault(rec.get("principalId", ""), []).append(rec)
            elif kind == "application":
                graph.applications.append(rec)
            elif kind == "agentIdentity":
                self._add_unique(
                    rec,
                    graph.agent_identities,
                    graph.conflicting_agent_identities,
                    graph.agent_identity_snapshots,
                    "agent identity",
                )
            elif kind == "copilotPackage":
                self._add_unique(
                    rec, graph.packages, graph.conflicting_packages, graph.package_snapshots, "package"
                )
            elif kind == "agentInstance":
                self._add_unique(
                    rec, graph.agent_instances, graph.conflicting_instances, {}, "agent instance"
                )
            elif kind == "agentCardManifest":
                self._add_unique(
                    rec, graph.card_manifests, graph.conflicting_cards, {}, "agent card manifest"
                )
            elif kind == COVERAGE_KIND:
                graph.coverage_markers.append(rec)
        return graph

    def _add_unique(
        self,
        rec: dict[str, Any],
        items: dict[str, dict[str, Any]],
        conflicts: set[str],
        snapshots: dict[str, list[dict[str, Any]]],
        label: str,
    ) -> None:
        """Index a record by id; a second record of that id with another body makes it conflicting."""
        record_id = rec["id"]
        existing = items.get(record_id)
        if existing is not None and existing != rec:
            if record_id not in conflicts:
                conflicts.add(record_id)
                self.ctx.warn(f"identity.entra: conflicting {label} records; coverage incomplete")
            kept = snapshots.setdefault(record_id, [existing])
            if len(kept) < MAX_CONFLICTING_SNAPSHOTS:
                kept.append(rec)
        items[record_id] = rec

    def _coverage(self, graph: _GraphExport) -> _Coverage:
        """Combine the export's coverage markers; replays re-report incomplete collections.

        Without a marker (an export written by hand, or by a run without opt-in collections)
        nothing is known to be complete. Markers that disagree count as incomplete. A marker
        naming another tenant (``tenantId``) than ``tenant_id`` leaves the records unattributed;
        an older marker without it is attributed to ``tenant_id`` as before.
        """
        markers = graph.coverage_markers
        if not markers:
            return _Coverage(rejected=graph.rejected)

        def combined(field: str) -> str:
            values = {marker[field] for marker in markers}
            return values.pop() if len(values) == 1 else "incomplete"

        account = self._binding_account()
        tenants = {m["tenantId"].strip().lower() for m in markers if isinstance(m.get("tenantId"), str)}
        coverage = _Coverage(
            packages=combined("packages"),
            agent_identities=combined("agentIdentities"),
            applications=combined("applications"),
            listing_scope="caller" if any(m["listingScope"] == "caller" for m in markers) else "registry",
            rejected=graph.rejected,
            foreign_tenant=account is not None and any(t != account.strip().lower() for t in tenants),
        )
        if coverage.foreign_tenant:
            self.ctx.warn(
                "identity.entra: the export was collected from another tenant than tenant_id; its "
                "registry records are not attributed to tenant_id and coverage is incomplete"
            )
        if self.offline:
            # Live collection warned already; a replay must not look complete.
            for state, collection in (
                (coverage.packages, "Agent 365 package listing"),
                (coverage.agent_identities, "agent identity collection"),
                (coverage.applications, "app registration collection"),
            ):
                if state == "incomplete":
                    self.ctx.warn(
                        f"identity.entra: exported {collection} was incomplete; coverage incomplete"
                    )
            if any(package.get("_detail") in _MISSING_DETAIL for package in graph.packages.values()):
                self.ctx.warn(
                    "identity.entra: exported package details were unavailable or capped; registry "
                    "coverage incomplete"
                )
            if coverage.listing_scope == "caller":
                self.ctx.warn(
                    "identity.entra: exported agent listings were caller-scoped (one user's view); "
                    "agent registry coverage incomplete"
                )
        return coverage

    def _add_principal(self, graph: _GraphExport, rec: dict[str, Any]) -> None:
        """Index a service principal, keeping every conflicting snapshot of its id (bounded)."""
        sp_id = rec["id"]
        if sp_id in graph.sps and graph.sps[sp_id] != rec:
            if sp_id not in graph.conflicting_sps:
                graph.conflicting_sps.add(sp_id)
                self.ctx.warn(
                    "identity.entra: conflicting service principal records; identity coverage incomplete"
                )
            snapshots = graph.conflicting_snapshots.setdefault(sp_id, [graph.sps[sp_id]])
            if len(snapshots) < MAX_CONFLICTING_SNAPSHOTS:
                snapshots.append(rec)
            elif sp_id not in graph.truncated_snapshots:
                graph.truncated_snapshots.add(sp_id)
                self.ctx.warn(
                    "identity.entra: conflicting principal snapshot limit reached; "
                    "evidence coverage incomplete"
                )
        graph.sps[sp_id] = rec
        for role in (rec.get("appRoles") or []) + (rec.get("oauth2PermissionScopes") or []):
            if role.get("id") and role.get("value"):
                self._remember_role_name(graph, rec, role["id"], role["value"])

    @staticmethod
    def _remember_role_name(graph: _GraphExport, resource: dict[str, Any], role_id: str, value: str) -> None:
        """Record a permission label that the resource principal ``resource`` defines."""
        graph.resource_role_labels.setdefault((resource["id"], role_id), set()).add(value)
        if resource.get("appId"):
            graph.app_role_labels.setdefault((resource["appId"], role_id), set()).add(value)
        graph.role_labels.setdefault(role_id, set()).add(value)

    def _role_label(
        self,
        graph: _GraphExport,
        role_id: str,
        *,
        resource: str | None = None,
        resource_app: str | None = None,
    ) -> str:
        """Label ``role_id`` of the resource principal ``resource`` (or appId ``resource_app``).

        App role ids are unique per resource only: another principal's label
        for the same id never names a known resource's role, so a hostile
        principal cannot relabel a privileged grant. Labels come from that
        resource and from roleMap records. A reference without any resource
        (older exports) may use any principal's label. An unknown pair keeps
        its unresolved id; conflicting labels also keep the id and are
        reported, because a later definition must not silently relabel one.
        """
        labels = set(graph.role_map_labels.get(role_id, ()))
        if resource:
            labels |= graph.resource_role_labels.get((resource, role_id), set())
        elif resource_app:
            labels |= graph.app_role_labels.get((resource_app, role_id), set())
        else:
            labels |= graph.role_labels.get(role_id, set())
        if len(labels) == 1:
            return next(iter(labels))
        conflict = (resource or resource_app, role_id)
        if labels and conflict not in graph.reported_role_conflicts:
            graph.reported_role_conflicts.add(conflict)
            self.ctx.warn("identity.entra: conflicting role labels; permission-name coverage incomplete")
        return role_id

    def _unresolved_finding(self, sp_id: str, graph: _GraphExport) -> Finding | None:
        """Permission evidence for a principal missing from, or conflicting within, the export."""
        f = self._sp_finding(
            {"id": sp_id, "displayName": "Unresolved principal"},
            graph.grants.get(sp_id, []),
            graph.role_assignments.get(sp_id, []),
            graph,
        )
        f, truncated_evidence = self._merge_conflicting_snapshots(f, sp_id, graph)
        if not f:
            return None
        # Nothing is known about a principal missing from the export:
        # never report a type, publisher or first-party status for it.
        f.metadata.update(
            dict.fromkeys(
                (
                    "app_id",
                    "service_principal_type",
                    "publisher",
                    "verified_publisher",
                    "first_party",
                    "owner_tenant",
                    "account_enabled",
                )
            )
        )
        for evidence in f.evidence:
            if evidence.signal == "entra:service-principal" and not evidence.description.startswith(
                "Conflicting snapshot"
            ):
                evidence.description = (
                    f"Service principal {sp_id} referenced by grants or role assignments is missing "
                    "from the export; its type, publisher and owner are unknown"
                )
        f.title = "Entra evidence for unresolved service principal"
        f.resource = f"entra:unresolved-principal:{sp_id}"
        f.resource_type = "unresolved-principal"
        f.identity_discriminator = "unresolved-principal"
        f.metadata.update({"identity_unresolved": True, "principal_id": sp_id})
        if sp_id in graph.conflicting_sps:
            f.metadata["conflicting_principal_snapshots"] = len(graph.conflicting_snapshots[sp_id])
            if sp_id in graph.truncated_snapshots or truncated_evidence:
                f.metadata["conflicting_principal_evidence_truncated"] = True
        if _agent_identity_snapshots(sp_id, graph):
            f.metadata["agent_identity"] = True
        if sp_id in graph.conflicting_agent_identities:
            f.metadata["conflicting_agent_identity_snapshots"] = len(graph.agent_identity_snapshots[sp_id])
            if truncated_evidence:
                f.metadata["conflicting_principal_evidence_truncated"] = True
        f.add_tag("unresolved-identity")
        kind = f.kind
        finalize(f, self.index)
        f.kind = kind
        f.id = f.compute_id()
        return f

    def _merge_conflicting_snapshots(
        self, f: Finding | None, sp_id: str, graph: _GraphExport
    ) -> tuple[Finding | None, bool]:
        """Fold AI signals of every conflicting snapshot into *f*; report evidence truncation.

        Agent identity records of the principal are folded too: an agent identity is never
        dropped for lacking AI signals, so its evidence survives an unresolved identity.
        """
        seen_evidence: set[tuple[str, str]] = set()
        truncated_evidence = False
        snapshots: list[tuple[dict[str, Any], dict[str, Any] | None]] = [
            (snapshot, None) for snapshot in graph.conflicting_snapshots.get(sp_id, [])
        ]
        snapshots += [(snapshot, snapshot) for snapshot in _agent_identity_snapshots(sp_id, graph)]
        for snapshot, identity in snapshots:
            self.ctx.check_deadline()
            observed = self._sp_finding(snapshot, [], [], graph, agent_identity=identity)
            if observed is None:
                continue
            if f is None:
                f = Finding(
                    surface=Surface.IDENTITY,
                    connector=self.name,
                    kind=observed.kind,
                    title="Entra unresolved service principal evidence",
                    resource=f"entra:unresolved-principal:{sp_id}",
                    resource_type="unresolved-principal",
                    provider="entra",
                    account=self.tenant,
                )
            # Preserve meaningful AI signals from every conflicting snapshot
            # without selecting one snapshot's appId, owner, or enabled state.
            for framework in observed.frameworks:
                f.add_framework(framework)
            for provider in observed.model_providers:
                f.add_model_provider(provider)
            for capability in observed.capabilities:
                f.add_capability(capability)
            for tag in observed.tags:
                if tag != "disabled":
                    f.add_tag(tag)
            for evidence in observed.evidence:
                description = "Conflicting snapshot: " + evidence.description
                evidence_key = (evidence.signal, description)
                if evidence_key in seen_evidence:
                    continue
                if len(seen_evidence) >= MAX_CONFLICTING_EVIDENCE:
                    if not truncated_evidence:
                        self.ctx.warn(
                            "identity.entra: conflicting principal evidence limit reached; "
                            "evidence coverage incomplete"
                        )
                        truncated_evidence = True
                    break
                seen_evidence.add(evidence_key)
                evidence.description = description
                evidence.attributes["confidence_group"] = f"entra-conflicting-snapshot:{evidence.signal}"
                f.add_evidence(evidence)
        return f, truncated_evidence

    def _record_kind(self, rec: dict[str, Any]) -> str | None:
        if not self._record_fields_valid(
            rec,
            strings=_STRING_FIELDS,
            mappings=("verifiedPublisher", "web", "spa", "publicClient", "roles"),
            arrays=_ARRAY_FIELDS,
        ):
            return None
        kind = rec.get("_kind") or _infer_kind(rec)
        required = {
            "servicePrincipal": ("id",),
            "application": ("appId",),
            "oauth2PermissionGrant": ("clientId",),
            "appRoleAssignment": ("principalId", "appRoleId"),
            "roleMap": (),
            "agentIdentity": ("id",),
            "copilotPackage": ("id",),
            "agentInstance": ("id",),
            "agentCardManifest": ("id",),
            COVERAGE_KIND: (),
        }
        if kind not in required or not self._record_fields_valid(rec, required=required[kind]):
            return None
        validators = {
            "agentIdentity": self._valid_agent_identity,
            "copilotPackage": self._valid_package,
            "agentInstance": self._valid_instance,
            "agentCardManifest": self._valid_card,
            COVERAGE_KIND: _valid_coverage,
        }
        if kind in validators and not validators[kind](rec):
            return None
        if kind == "oauth2PermissionGrant" and not isinstance(rec.get("scope"), str):
            return None
        if kind == "roleMap":
            roles = rec.get("roles")
            if not isinstance(roles, dict) or any(
                not isinstance(k, str) or not isinstance(v, str) for k, v in roles.items()
            ):
                return None
        if not self._record_fields_valid(rec.get("verifiedPublisher") or {}, strings=("displayName",)):
            return None
        if rec.get("accountEnabled") is not None and not isinstance(rec["accountEnabled"], bool):
            return None
        if any(not isinstance(url, str) for url in rec.get("replyUrls") or []):
            return None
        for field in ("appRoles", "oauth2PermissionScopes"):
            if any(
                not self._record_fields_valid(role, strings=("id", "value")) for role in rec.get(field) or []
            ):
                return None
        for field in ("web", "spa", "publicClient"):
            config = rec.get(field) or {}
            if not self._record_fields_valid(config, arrays=("redirectUris",)) or any(
                not isinstance(uri, str) for uri in config.get("redirectUris") or []
            ):
                return None
        for access in rec.get("requiredResourceAccess") or []:
            if not self._record_fields_valid(access, strings=("resourceAppId",), arrays=("resourceAccess",)):
                return None
            if any(
                not self._record_fields_valid(permission, strings=("id", "type"))
                for permission in access.get("resourceAccess") or []
            ):
                return None
        return kind

    def _valid_agent_identity(self, rec: dict[str, Any]) -> bool:
        return (
            self._record_fields_valid(
                rec,
                strings=(
                    "agentIdentityBlueprintId",
                    "createdByAppId",
                    "disabledByMicrosoftStatus",
                    "createdDateTime",
                ),
                arrays=("managerApplications",),
            )
            and _strings(rec.get("managerApplications"))
            and _bounded_ids(rec, "id")
        )

    def _valid_package(self, rec: dict[str, Any]) -> bool:
        if not self._record_fields_valid(
            rec,
            strings=_PACKAGE_STRINGS,
            arrays=("elementTypes", "supportedHosts", "categories", *_ACCESS_LISTS),
            mappings=("_accessCounts",),
        ):
            return False
        counts = rec.get("_accessCounts") or {}
        return (
            (rec.get("isBlocked") is None or isinstance(rec["isBlocked"], bool))
            and all(_strings(rec.get(field)) for field in ("elementTypes", "supportedHosts", "categories"))
            and all(isinstance(item, dict) for field in _ACCESS_LISTS for item in rec.get(field) or [])
            and all(name in _ACCESS_LISTS and _count(value) for name, value in counts.items())
            and all(
                rec.get(field) is None or _count(rec[field]) for field in ("activeUsers", "totalSessions")
            )
            and rec.get("_detail") in (None, *PACKAGE_DETAIL_STATES)
            and _bounded_ids(rec, "id", "appId", "agentIdentityId", "publisher")
        )

    def _valid_instance(self, rec: dict[str, Any]) -> bool:
        if not self._record_fields_valid(
            rec,
            strings=_INSTANCE_STRINGS,
            arrays=("ownerIds", "additionalInterfaces", "signatures"),
            mappings=("agentCardManifest",),
        ):
            return False
        card = rec.get("agentCardManifest")
        return (
            _strings(rec.get("ownerIds"))
            and all(
                self._record_fields_valid(interface, strings=("url", "transport"))
                for interface in rec.get("additionalInterfaces") or []
            )
            and all(isinstance(signature, dict) for signature in rec.get("signatures") or [])
            and (card is None or self._valid_card(card))
            and _bounded_ids(rec, "id", "agentIdentityId")
        )

    def _valid_card(self, rec: dict[str, Any]) -> bool:
        if not self._record_fields_valid(
            rec,
            strings=_CARD_STRINGS,
            mappings=("provider", "capabilities", "securitySchemes"),
            arrays=("skills", "defaultInputModes", "defaultOutputModes", "security", "ownerIds"),
        ):
            return False
        return (
            self._record_fields_valid(rec.get("provider") or {}, strings=("organization", "url"))
            and all(
                self._record_fields_valid(skill, strings=("id", "name", "description"))
                for skill in rec.get("skills") or []
            )
            and all(
                _strings(rec.get(field)) for field in ("defaultInputModes", "defaultOutputModes", "ownerIds")
            )
            and _bounded_ids(rec, "id")
        )

    def _sp_finding(
        self,
        sp: dict[str, Any],
        grants: list[dict[str, Any]],
        roles: list[dict[str, Any]],
        graph: _GraphExport,
        *,
        agent_identity: dict[str, Any] | None = None,
        keep: bool = False,
        sp_type: str | None = None,
    ) -> Finding | None:
        """The finding for a service principal, or None when it shows nothing AI-related.

        An agent identity (``agent_identity``: its Agent ID record) and a principal an Agent 365
        package names (``keep``) are always reported. A standalone agent identity passes
        ``sp_type`` ``AgentIdentity``; the identity discriminator stays ``service-principal``,
        so its finding id does not change when the service principal listing also returns it.
        """
        first_party = sp.get("appOwnerOrganizationId") == FIRST_PARTY_OWNER
        sp_type = sp_type or sp.get("servicePrincipalType") or "Application"
        retained = keep or agent_identity is not None
        delegated, principals, admin_consented = _grant_consent(grants)
        app_perms = sorted(
            {
                self._role_label(graph, role_id, resource=r.get("resourceId"))
                for r in roles
                if isinstance(role_id := r.get("appRoleId"), str) and role_id
            }
        )
        machine = sp_type == "ManagedIdentity" or bool(app_perms) or agent_identity is not None
        user_consented = bool(principals) or admin_consented
        kind = identity_kind_for(user_consented=user_consented, machine=machine)
        name = sp.get("displayName") or sp.get("appDisplayName") or sp.get("appId")
        if agent_identity is not None:
            # An agent's own identity, whatever consent it holds; the grants stay as evidence.
            kind = Kind.SERVICE_IDENTITY
            label = "agent identity"
        else:
            label = "managed identity" if sp_type == "ManagedIdentity" else "service principal"
        f = Finding(
            surface=Surface.IDENTITY,
            connector=self.name,
            kind=kind,
            title=f"Entra {label}: {name}",
            resource=f"entra:sp:{sp.get('id')}",
            resource_type=f"service-principal/{sp_type}",
            provider="entra",
            # appOwnerOrganizationId is the publisher's tenant, not the scanned one.
            account=self.tenant,
            first_seen=sp.get("createdDateTime"),
        )
        assess_app(
            self.index,
            f,
            name=name,
            publisher=sp.get("publisherName") or ((sp.get("verifiedPublisher") or {}).get("displayName")),
            description=" ".join(x for x in [sp.get("notes"), sp.get("description")] if x),
            urls=[sp.get("homepage"), sp.get("loginUrl"), *(sp.get("replyUrls") or [])],
            # Sets iterate in hash order; sort so reports are reproducible across runs.
            scopes=sorted(delegated) + app_perms,
            client_id=sp.get("appId"),
        )
        if not retained and first_party and not f.frameworks and not self.include_first_party:
            return None
        if (
            not retained
            and not f.frameworks
            and not delegated
            and not app_perms
            and sp_type != "ManagedIdentity"
        ):
            return None
        f.add_evidence(
            Evidence(
                signal="entra:service-principal",
                description=(
                    f"{sp_type} '{name}' (appId {sp.get('appId')}), publisher "
                    f"{sp.get('publisherName') or 'unknown'}, "
                    f"{'first-party' if first_party else 'third-party/tenant'}; "
                    f"enabled={sp.get('accountEnabled')}"
                ),
                location=(
                    "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/"
                    f"~/Overview/objectId/{sp.get('id')}"
                ),
                weight=0.15 if not machine else 0.3,
            )
        )
        _permission_evidence(f, delegated, principals, admin_consented, app_perms)
        if sp_type == "ManagedIdentity":
            f.add_tag("managed-identity")
        if sp.get("accountEnabled") is False:
            f.add_tag("disabled")
        f.metadata.update(
            {
                "app_id": sp.get("appId"),
                "service_principal_type": sp_type,
                "publisher": sp.get("publisherName"),
                "verified_publisher": (sp.get("verifiedPublisher") or {}).get("displayName"),
                "first_party": first_party,
                "owner_tenant": sp.get("appOwnerOrganizationId"),
                "account_enabled": sp.get("accountEnabled"),
                "sign_in_audience": sp.get("signInAudience"),
                "tags": sp.get("tags"),
                "delegated_scopes": summarize_scopes(delegated),
                "application_permissions": app_perms[:40],
                "consenting_users": len(principals),
                "admin_consent": admin_consented,
                "reply_urls": (sp.get("replyUrls") or [])[:10],
            }
        )
        if agent_identity is not None:
            self._agent_identity_details(f, agent_identity, name)
        if keep:
            f.metadata["registry_bound"] = True
        finalize(f, self.index)
        f.kind = kind
        return f

    @staticmethod
    def _agent_identity_details(f: Finding, identity: dict[str, Any], name: Any) -> None:
        """Agent ID evidence, tag and metadata for a principal that is an agent identity."""
        blueprint = identity.get("agentIdentityBlueprintId")
        creator = identity.get("createdByAppId")
        f.add_evidence(
            Evidence(
                signal="entra:agent-identity",
                description=(
                    f"Entra Agent ID agent identity '{name}' (blueprint appId {blueprint or 'unknown'}, "
                    f"created by appId {creator or 'unknown'})"
                ),
                location=(
                    "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/"
                    f"~/Overview/objectId/{identity.get('id')}"
                ),
                weight=0.4,
            )
        )
        f.add_tag("entra-agent-identity")
        f.metadata.update(
            {
                "agent_identity": True,
                "agent_identity_blueprint_id": blueprint,
                "created_by_app_id": creator,
                "disabled_by_microsoft_status": identity.get("disabledByMicrosoftStatus"),
                "manager_applications": (identity.get("managerApplications") or [])[:10],
            }
        )

    def _app_registration_finding(
        self, app: dict[str, Any], sp: dict[str, Any] | None, graph: _GraphExport, *, keep: bool = False
    ) -> Finding | None:
        """The finding for a tenant app registration; ``keep`` reports one an Agent 365 package names."""
        name = app.get("displayName") or app.get("appId")
        requested_roles: set[str] = set()
        requested_scopes: set[str] = set()
        requested_untyped: set[str] = set()
        for rra in app.get("requiredResourceAccess") or []:
            for ra in rra.get("resourceAccess") or []:
                permission_id = ra.get("id")
                if not permission_id:
                    continue
                permission = self._role_label(
                    graph, str(permission_id), resource_app=rra.get("resourceAppId")
                )
                if ra.get("type") == "Role":
                    requested_roles.add(permission)
                elif ra.get("type") == "Scope":
                    requested_scopes.add(permission)
                else:
                    requested_untyped.add(permission)
        requested = sorted(requested_roles | requested_scopes | requested_untyped)
        f = Finding(
            surface=Surface.IDENTITY,
            connector=self.name,
            kind=Kind.SERVICE_IDENTITY,
            title=f"Entra app registration: {name}",
            resource=f"entra:app:{app.get('appId')}",
            resource_type="app-registration",
            provider="entra",
            account=self.tenant,
            first_seen=app.get("createdDateTime"),
        )
        redirect_uris = [
            *((app.get("web") or {}).get("redirectUris") or []),
            *((app.get("spa") or {}).get("redirectUris") or []),
            *((app.get("publicClient") or {}).get("redirectUris") or []),
        ]
        # requiredResourceAccess declares what an app *asks* for. Only the
        # service principal's grants/assignments prove permissions were granted.
        assess_app(
            self.index,
            f,
            name=name,
            description=" ".join(x for x in [app.get("notes"), app.get("description")] if x),
            urls=redirect_uris,
            client_id=app.get("appId"),
        )
        requested_classes = sorted({m.signature_id for m in scope_matches(self.index, requested)})
        secrets = app.get("passwordCredentials") or []
        certs = app.get("keyCredentials") or []
        if (
            not keep
            and not f.frameworks
            and not set(requested_classes)
            & {
                "policy.llm-access-scopes",
                "policy.privileged-scopes",
                "policy.data-access-scopes",
            }
        ):
            return None
        f.add_evidence(
            Evidence(
                signal="entra:app-registration",
                description=(
                    f"Tenant-owned app registration '{name}' with {len(secrets)} client secret(s), "
                    f"{len(certs)} certificate(s); requested permissions (grant not verified): "
                    f"{', '.join(requested)[:300]}"
                ),
                location=(
                    "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/"
                    f"~/Overview/appId/{app.get('appId')}"
                ),
                weight=0.3,
            )
        )
        if requested:
            f.add_tag("permissions-requested")
        if secrets:
            f.add_tag("client-secret")
        f.metadata.update(
            {
                "app_id": app.get("appId"),
                "requested_permissions": requested[:40],
                "requested_application_permissions": sorted(requested_roles)[:40],
                "requested_delegated_scopes": sorted(requested_scopes)[:40],
                "requested_untyped_permissions": sorted(requested_untyped)[:40],
                "requested_permission_classes": requested_classes,
                "client_secrets": len(secrets),
                "certificates": len(certs),
                "sign_in_audience": app.get("signInAudience"),
                "tags": app.get("tags"),
                "has_service_principal": sp is not None,
            }
        )
        if keep:
            f.metadata["registry_bound"] = True
        finalize(f, self.index)
        f.kind = Kind.SERVICE_IDENTITY
        return f

    # ------------------------------------------------------ registry records
    def _binding_account(self) -> str | None:
        return self.tenant if isinstance(self.tenant, str) and self.tenant else None

    def _registry_record(
        self,
        registry: str,
        record_id: str,
        status: str,
        descriptor_type: str,
        bindings: list[dict[str, Any]],
        *,
        listing_complete: bool = False,
        approval_mode: str = "unknown",
        listing_scope: str = "registry",
        publisher: Any = None,
        updated_at: Any = None,
        attributed: bool = True,
    ) -> dict[str, Any]:
        """A ``shadowscan.registry-record/v1`` block; the registry id is the tenant.

        It is "" when the tenant is unknown or the records are not ``attributed`` to it (an
        export collected from another tenant).
        """
        tenant = (
            self.tenant
            if attributed and isinstance(self.tenant, str) and len(self.tenant) <= MAX_IDENTIFIER_LENGTH
            else ""
        )
        record: dict[str, Any] = {
            "schema": RECORD_SCHEMA,
            "registry": registry,
            # Without a tenant the registry is unidentified, so its records can never be trusted.
            "registry_id": tenant,
            "record_id": record_id,
            "status": status,
            "descriptor_type": descriptor_type,
            "bindings": bindings,
            "listing_complete": listing_complete,
            "approval_mode": approval_mode,
            "listing_scope": listing_scope,
        }
        if isinstance(publisher, str) and publisher.strip():
            record["publisher"] = publisher
        if isinstance(updated_at, str) and len(updated_at) <= MAX_IDENTIFIER_LENGTH:
            record["updated_at"] = updated_at
        return record

    def _principal_binding(
        self, principal_id: Any, graph: _GraphExport, coverage: _Coverage
    ) -> list[dict[str, Any]]:
        """A binding to the service principal finding of an agent identity.

        Only a listed agent identity is bound: a record naming any other service principal
        (a privileged application, say) must not approve it.
        """
        principal = graph.agent_identity_id(principal_id)
        if principal is None:
            return []
        return [
            {
                "resource": f"entra:sp:{principal}",
                "provider": "entra",
                "account": self._binding_account(),
                # In scope only when this run (or the replayed one) listed agent identities completely.
                "coverage": _binding_coverage(coverage.agent_identities, coverage),
            }
        ]

    def _package_finding(self, package: dict[str, Any], graph: _GraphExport, coverage: _Coverage) -> Finding:
        """An Agent 365 catalog package as a ``microsoft-agent-365`` registry record finding."""
        package_id = package["id"]
        conflicting = package_id in graph.conflicting_packages
        snapshots = graph.package_snapshots.get(package_id, [package]) if conflicting else [package]
        agentic = any(_agentic_package(snapshot) for snapshot in snapshots)
        kind = Kind.AGENT if agentic else Kind.AI_APP
        name = package.get("displayName") or package_id
        f = Finding(
            surface=Surface.IDENTITY,
            connector=self.name,
            kind=kind,
            title=(
                f"Microsoft 365 package with conflicting records: {package_id}"
                if conflicting
                else f"Microsoft 365 {'agent' if agentic else 'app'} package: {name}"
            ),
            # The resource type is constant so the identity does not depend on the package type.
            resource=f"entra:copilot-package:{package_id}",
            resource_type="copilot-package",
            provider="entra",
            account=self.tenant,
            first_seen=None if conflicting else package.get("createdDateTime"),
            last_seen=None if conflicting else package.get("lastUsedDateTime"),
        )
        location = f"{GRAPH}{COPILOT_PACKAGES}/{quote(package_id, safe='')}"
        if conflicting:
            # No snapshot's name, publisher, status or bindings is chosen: nothing here approves.
            f.add_evidence(
                registry_evidence(
                    AGENT_365,
                    f"Agent 365 package {package_id} was exported with {len(snapshots)} conflicting records",
                    location=location,
                )
            )
            f.add_tag("registry-record")
            f.add_tag("unresolved-identity")
            f.metadata.update(
                {
                    "identity_unresolved": True,
                    "conflicting_package_snapshots": len(snapshots),
                    RECORD_KEY: self._registry_record(
                        AGENT_365,
                        package_id,
                        "unknown",
                        "package",
                        [],
                        attributed=not coverage.foreign_tenant,
                    ),
                }
            )
            finalize(f, self.index)
            f.kind = kind
            return f
        status = _package_status(package)
        package_type = _enum(package.get("type"))
        org_published = package_type in _ORG_PUBLISHED_TYPES
        assess_app(
            self.index,
            f,
            name=name,
            publisher=package.get("publisher"),
            description=" ".join(
                x for x in (package.get("shortDescription"), package.get("longDescription")) if x
            ),
            client_id=package.get("appId"),
        )
        # A package whose details are missing has an unknown status and binds nothing.
        detailed = package.get("_detail") not in _MISSING_DETAIL
        bindings = (
            self._principal_binding(package.get("agentIdentityId"), graph, coverage) if detailed else []
        )
        app_id = _bindable_app_id(package) if detailed else None
        if app_id:
            bindings.append(
                {
                    "resource": f"entra:app:{app_id}",
                    "provider": "entra",
                    "account": self._binding_account(),
                    "coverage": _binding_coverage(coverage.applications, coverage),
                }
            )
        # A caller-scoped listing shows what the signed-in user may see: never the whole registry.
        listing_complete = (
            coverage.listing_scope == "registry"
            and coverage.packages == "complete"
            and not graph.conflicting_packages
            and not graph.rejected
        )
        access = _access_counts(package)
        f.add_evidence(
            registry_evidence(
                AGENT_365,
                (
                    f"Agent 365 catalog package '{name}' (type {package.get('type') or 'unknown'}, publisher "
                    f"{package.get('publisher') or 'unknown'}): status {status}, blocked="
                    f"{package.get('isBlocked')}, available to {package.get('availableTo') or 'unknown'}, "
                    f"deployed to {package.get('deployedTo') or 'unknown'}"
                ),
                location=location,
            )
        )
        f.add_tag("registry-record")
        if status == "blocked":
            f.add_tag("registry-blocked")
        f.metadata.update(
            {
                "app_id": package.get("appId"),
                "agent_identity_id": package.get("agentIdentityId"),
                "package_type": package.get("type"),
                "element_types": (package.get("elementTypes") or [])[:20],
                "supported_hosts": (package.get("supportedHosts") or [])[:20],
                "platform": package.get("platform"),
                "version": package.get("version"),
                "manifest_id": package.get("manifestId"),
                "manifest_version": package.get("manifestVersion"),
                "governance_class": package.get("governanceMetadata"),
                "is_blocked": package.get("isBlocked"),
                "available_to": package.get("availableTo"),
                "deployed_to": package.get("deployedTo"),
                "request_status": package.get("requestStatus"),
                "request_type": package.get("requestType"),
                "publisher": package.get("publisher"),
                "categories": (package.get("categories") or [])[:20],
                "sensitivity": package.get("sensitivity"),
                # Member lists are counted, never listed.
                "allowed_principals": access.get("allowedUsersAndGroups"),
                "acquired_principals": access.get("acquireUsersAndGroups"),
                "shared_principals": access.get("sharedWithUsersAndGroups"),
                "active_users": package.get("activeUsers"),
                "total_sessions": package.get("totalSessions"),
                "package_detail": package.get("_detail", "unspecified"),
                RECORD_KEY: self._registry_record(
                    AGENT_365,
                    package_id,
                    status,
                    "package",
                    bindings,
                    listing_complete=listing_complete,
                    approval_mode="manual"
                    if status == "approved"
                    and org_published
                    and _enum(package.get("requestStatus")) == "approved"
                    else "unknown",
                    listing_scope=coverage.listing_scope,
                    publisher=package.get("publisher"),
                    updated_at=package.get("lastModifiedDateTime"),
                    attributed=not coverage.foreign_tenant,
                ),
            }
        )
        finalize(f, self.index)
        f.kind = kind
        return f

    def _instance_finding(
        self, instance: dict[str, Any], graph: _GraphExport, coverage: _Coverage
    ) -> Finding:
        """A deprecated Entra agent registry instance (offline import): ``deprecated``, never approving."""
        instance_id = instance["id"]
        conflicting = instance_id in graph.conflicting_instances
        card = instance.get("agentCardManifest") if not conflicting else None
        name = instance_id if conflicting else instance.get("displayName") or instance_id
        f = Finding(
            surface=Surface.IDENTITY,
            connector=self.name,
            kind=Kind.AGENT,
            title=f"Entra agent registry instance (deprecated source): {name}",
            resource=f"entra:agent-registry-instance:{instance_id}",
            resource_type="agent-registry-instance",
            provider="entra",
            account=self.tenant,
            first_seen=None if conflicting else instance.get("createdDateTime"),
        )
        location = f"{GRAPH_BETA}/agentRegistry/agentInstances/{quote(instance_id, safe='')}"
        if conflicting:
            f.add_evidence(
                registry_evidence(
                    DEPRECATED_REGISTRY,
                    f"Deprecated Entra agent registry instance {instance_id} was exported with "
                    "conflicting records",
                    location=location,
                )
            )
            f.add_tag("unresolved-identity")
            bindings: list[dict[str, Any]] = []
            f.metadata["identity_unresolved"] = True
        else:
            assess_app(
                self.index,
                f,
                name=name,
                description=(card or {}).get("description"),
                urls=[instance.get("url")],
            )
            f.add_evidence(
                registry_evidence(
                    DEPRECATED_REGISTRY,
                    (
                        f"Deprecated Entra agent registry instance '{name}' from "
                        f"{instance.get('originatingStore') or 'an unknown store'}"
                    ),
                    location=location,
                )
            )
            bindings = self._principal_binding(instance.get("agentIdentityId"), graph, coverage)
            f.metadata.update(
                {
                    "endpoint": instance.get("url"),
                    "preferred_transport": instance.get("preferredTransport"),
                    "transports": sorted(
                        {
                            i["transport"]
                            for i in instance.get("additionalInterfaces") or []
                            if i.get("transport")
                        }
                    )[:10],
                    "originating_store": instance.get("originatingStore"),
                    "source_agent_id": instance.get("sourceAgentId"),
                    "agent_identity_id": instance.get("agentIdentityId"),
                    "agent_identity_blueprint_id": instance.get("agentIdentityBlueprintId"),
                    "agent_user_id": instance.get("agentUserId"),
                    "managed_by": instance.get("managedBy"),
                    "owners": len(instance.get("ownerIds") or []),
                    "signatures": len(instance.get("signatures") or []),
                    "agent_card": _card_summary(card) if isinstance(card, dict) else None,
                }
            )
        f.add_tag("registry-record")
        f.metadata[RECORD_KEY] = self._registry_record(
            DEPRECATED_REGISTRY, instance_id, "deprecated", "agent", bindings
        )
        finalize(f, self.index)
        f.kind = Kind.AGENT
        return f

    def _card_finding(self, card: dict[str, Any], graph: _GraphExport) -> Finding:
        """A deprecated Entra agent registry card manifest that no exported instance embeds."""
        card_id = card["id"]
        conflicting = card_id in graph.conflicting_cards
        name = card_id if conflicting else card.get("displayName") or card_id
        f = Finding(
            surface=Surface.IDENTITY,
            connector=self.name,
            kind=Kind.AGENT,
            title=f"Entra agent registry card (deprecated source): {name}",
            resource=f"entra:agent-registry-card:{card_id}",
            resource_type="agent-registry-card",
            provider="entra",
            account=self.tenant,
        )
        if conflicting:
            f.add_tag("unresolved-identity")
            f.metadata["identity_unresolved"] = True
            description = (
                f"Deprecated Entra agent registry card {card_id} was exported with conflicting records"
            )
        else:
            assess_app(self.index, f, name=name, description=card.get("description"))
            f.metadata["agent_card"] = _card_summary(card)
            description = f"Deprecated Entra agent registry card '{name}'"
        f.add_evidence(registry_evidence(DEPRECATED_REGISTRY, description))
        f.add_tag("registry-record")
        f.metadata[RECORD_KEY] = self._registry_record(DEPRECATED_REGISTRY, card_id, "deprecated", "a2a", [])
        finalize(f, self.index)
        f.kind = Kind.AGENT
        return f


def _grant_consent(grants: list[dict[str, Any]]) -> tuple[set[str], set[str], bool]:
    """Delegated scopes, consenting users and whether an admin consented for all users."""
    delegated: set[str] = set()
    principals: set[str] = set()
    admin_consented = False
    for g in grants:
        delegated.update((g.get("scope") or "").split())
        if g.get("consentType") == "AllPrincipals":
            admin_consented = True
        elif g.get("principalId"):
            principals.add(g["principalId"])
    return delegated, principals, admin_consented


def _permission_evidence(
    f: Finding, delegated: set[str], principals: set[str], admin_consented: bool, app_perms: list[str]
) -> None:
    """Evidence for delegated consent and granted app-only permissions."""
    if delegated:
        consenters = "admin, all users" if admin_consented else f"{len(principals)} user(s)"
        f.add_evidence(
            Evidence(
                signal="entra:delegated-consent",
                description=f"Delegated consent ({consenters}): {' '.join(sorted(delegated))[:400]}",
                weight=0.25,
            )
        )
    if app_perms:
        f.add_evidence(
            Evidence(
                signal="entra:application-permissions",
                description=f"Application (app-only) permissions: {', '.join(app_perms)[:400]}",
                weight=0.35,
            )
        )
        f.add_tag("app-only-permissions")


def _unverified_claims(token: str) -> dict[str, Any] | None:
    """A JWT's claims without signature verification; None when it is not a strict JWT."""
    import jwt as pyjwt

    try:
        # Duplicate claim names would make the tenant binding ambiguous.
        for segment in token.split(".")[:2]:
            strict_json_loads(pyjwt.utils.base64url_decode(segment))
        claims = pyjwt.decode(
            token,
            options={
                "verify_signature": False,
                "verify_exp": False,
                "verify_nbf": False,
                "verify_iat": False,
                "verify_aud": False,
            },
        )
    except (pyjwt.PyJWTError, RecursionError, ValueError):
        return None
    return claims if isinstance(claims, dict) else None


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _enum(value: Any) -> str | None:
    """An evolvable Graph enum member, compared case-insensitively."""
    return value.strip().lower() if isinstance(value, str) and value.strip() else None


def _strings(value: Any) -> bool:
    return value is None or (isinstance(value, list) and all(isinstance(item, str) for item in value))


def _count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _bounded_ids(rec: dict[str, Any], *fields: str) -> bool:
    """Identities that fit a registry record once prefixed (``entra:sp:``) as binding resources."""
    return all(len(rec.get(field) or "") <= MAX_IDENTIFIER_LENGTH // 2 for field in fields)


def _valid_coverage(rec: dict[str, Any]) -> bool:
    tenant = rec.get("tenantId")
    return (
        rec.get("packages") in COVERAGE_STATES
        and rec.get("agentIdentities") in COVERAGE_STATES
        and rec.get("applications") in ("complete", "incomplete")
        and rec.get("listingScope") in LISTING_SCOPES
        # Optional: an older export names no tenant.
        and (tenant is None or (isinstance(tenant, str) and 0 < len(tenant.strip()) <= MAX_IDENTIFIER_LENGTH))
    )


def _package_record(item: dict[str, Any]) -> dict[str, Any]:
    """A collected package without member ids, the package file or element definitions."""
    record = {key: value for key, value in item.items() if key not in _DROPPED_PACKAGE_FIELDS}
    counts = {field: len(item[field]) for field in _ACCESS_LISTS if isinstance(item.get(field), list)}
    if counts:
        record["_accessCounts"] = counts
    return record


def _access_counts(package: dict[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = dict(package.get("_accessCounts") or {})
    for field in _ACCESS_LISTS:
        if isinstance(package.get(field), list):
            counts[field] = len(package[field])
    return counts


def _package_status(package: dict[str, Any]) -> str:
    """The registry status of an Agent 365 package.

    Blocked, then a package whose details are missing (its request status is unknown), then
    an open or rejected request, then a package available to nobody (draft). Otherwise a
    package explicitly not blocked and available to all or some users is approved when its
    request was approved. With no request, an organization's own package (shared, custom,
    lob) is only registered, since no person is known to have approved it, and a vendor
    package is approved (made available by the tenant). Any other combination (a missing
    flag, an unknown enum member) is unknown.
    """
    if package.get("isBlocked") is True:
        return "blocked"
    if package.get("_detail") in _MISSING_DETAIL:
        return "unknown"
    request = _enum(package.get("requestStatus"))
    if request == "pending":
        return "pending"
    if request == "rejected":
        return "rejected"
    available = _enum(package.get("availableTo"))
    if available in _AVAILABLE_TO_NONE:
        return "draft"
    if package.get("isBlocked") is False and available in _AVAILABLE:
        if request == "approved":
            return "approved"
        if request is None:
            return "registered" if _enum(package.get("type")) in _ORG_PUBLISHED_TYPES else "approved"
    return "unknown"


def _bindable_app_id(package: dict[str, Any]) -> str | None:
    """The appId of an organization's own package; a vendor package's app is registered elsewhere.

    Microsoft and partner packages are registered in the publisher's tenant, so an app
    registration of this tenant with that appId is not theirs and is never bound.
    """
    return _text(package.get("appId")) if _enum(package.get("type")) in _ORG_PUBLISHED_TYPES else None


def _binding_coverage(state: str, coverage: _Coverage) -> str:
    """``in-scope`` only for a collection that finished complete over the whole tenant.

    Any rejected record leaves coverage unknown: the bound object may be the one rejected.
    """
    if state == "complete" and coverage.listing_scope == "registry" and not coverage.rejected:
        return "in-scope"
    return "unknown"


def _check_graph_audience(claims: dict[str, Any], label: str) -> None:
    """Refuse a token issued for another resource; ``label`` is fixed text, claims are never shown."""
    audience = claims.get("aud")
    if not isinstance(audience, str) or audience not in GRAPH_AUDIENCES:
        raise ConnectorError(f"identity.entra: {label} is not a Microsoft Graph token (aud)")


def _agentic_package(package: dict[str, Any]) -> bool:
    elements = {_enum(element) for element in package.get("elementTypes") or []}
    return bool(elements & _AGENT_ELEMENT_TYPES) or _enum(package.get("governanceMetadata")) in _AGENT_CLASSES


def _card_summary(card: dict[str, Any]) -> dict[str, Any]:
    """A bounded summary of an A2A agent card manifest; scheme definitions are named, not copied."""
    provider = card.get("provider") or {}
    skills = card.get("skills") or []
    return {
        "id": card.get("id"),
        "name": card.get("displayName"),
        "description": (card.get("description") or "")[:300] or None,
        "protocol_version": card.get("protocolVersion"),
        "version": card.get("version"),
        "provider": provider.get("organization"),
        "skills": [name for skill in skills if (name := skill.get("name") or skill.get("id"))][:25],
        "input_modes": (card.get("defaultInputModes") or [])[:10],
        "output_modes": (card.get("defaultOutputModes") or [])[:10],
        "capabilities": sorted(
            str(name) for name, value in (card.get("capabilities") or {}).items() if value is True
        )[:10],
        "security_schemes": sorted(str(name) for name in card.get("securitySchemes") or {})[:10],
        "documentation_url": card.get("documentationUrl"),
    }


def _agent_identity_snapshots(sp_id: str, graph: _GraphExport) -> list[dict[str, Any]]:
    """Every agent identity record of a principal: its conflicting snapshots, or the one record."""
    if sp_id in graph.conflicting_agent_identities:
        return graph.agent_identity_snapshots[sp_id]
    identity = graph.agent_identities.get(sp_id)
    return [identity] if identity is not None else []


# Graph casts of the agent-related kinds; a record's @odata.type names its kind exactly.
_ODATA_KINDS = {
    "agentidentity": "agentIdentity",
    "copilotpackage": "copilotPackage",
    "copilotpackagedetail": "copilotPackage",
    "agentinstance": "agentInstance",
    "agentcardmanifest": "agentCardManifest",
}


def _infer_kind(rec: dict[str, Any]) -> str:
    odata = str(rec.get("@odata.type", "")).lower()
    cast = odata.rsplit(".", 1)[-1].lstrip("#")
    if cast in _ODATA_KINDS:
        return _ODATA_KINDS[cast]
    if not odata:
        # Shapes of untyped agent records. Agent identities also carry servicePrincipalType, and
        # agent instances an agentIdentityBlueprintId, so these come before the older shapes.
        if {"elementTypes", "supportedHosts", "isBlocked"} & rec.keys():
            return "copilotPackage"
        if {"preferredTransport", "agentUserId", "agentIdentityId"} & rec.keys():
            return "agentInstance"
        if {"protocolVersion", "skills"} <= rec.keys():
            return "agentCardManifest"
        if "agentIdentityBlueprintId" in rec:
            return "agentIdentity"
    if "serviceprincipal" in odata or "servicePrincipalType" in rec:
        return "servicePrincipal"
    if "permissiongrant" in odata or "consentType" in rec:
        return "oauth2PermissionGrant"
    if "approleassignment" in odata or "appRoleId" in rec:
        return "appRoleAssignment"
    if "application" in odata or "requiredResourceAccess" in rec or "passwordCredentials" in rec:
        return "application"
    if "roles" in rec and len(rec) == 1:
        return "roleMap"
    return "unknown"
