"""Microsoft Entra ID (Azure AD) via Microsoft Graph.

Collects service principals (enterprise apps, managed identities, first-party
Copilot SPs), delegated OAuth2 permission grants, application (app-only) role
assignments and tenant-owned app registrations, then reports:

* third-party AI apps consented by users / admins (``oauth-grant``)
* machine identities holding Graph / Copilot / Azure OpenAI permissions (``service-identity``)
* app registrations that look like in-house agents (``service-identity``)

Auth: client credentials (``tenant_id`` / ``client_id`` / ``client_secret``) with
``Application.Read.All`` + ``DelegatedPermissionGrant.Read.All`` +
``Directory.Read.All``, or a pre-issued ``access_token``.

Offline export: any mix of Graph objects (servicePrincipal, oauth2PermissionGrant,
appRoleAssignment, application); each record may carry ``_kind`` or is inferred
from its shape.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any, ClassVar

from requests import RequestException

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.connectors.common import finalize
from shadowscan.connectors.identity.common import assess_app, identity_kind_for, summarize_scopes
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.utils.http import HttpClient, HttpError

GRAPH = "https://graph.microsoft.com/v1.0"
MS_GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
FIRST_PARTY_OWNER = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"  # Microsoft services tenant


class EntraConnector(BaseConnector):
    name: ClassVar[str] = "identity.entra"
    surface: ClassVar[Surface] = Surface.IDENTITY
    provider: ClassVar[str | None] = "entra"
    description: ClassVar[str] = "Entra ID service principals, OAuth consent grants, app-only permissions and app registrations via Microsoft Graph."
    config_keys: ClassVar[dict[str, str]] = {
        "tenant_id": "env AZURE_TENANT_ID",
        "client_id": "env AZURE_CLIENT_ID",
        "client_secret": "env AZURE_CLIENT_SECRET",
        "access_token": "pre-issued Graph token (env GRAPH_ACCESS_TOKEN) instead of client credentials",
        "include_first_party": "include Microsoft first-party service principals (default false, Copilot SPs always kept)",
        "max_app_role_lookups": "cap on per-SP appRoleAssignments calls (default 2000)",
        "input": "offline: JSON export of Graph objects",
    }

    def __init__(self, ctx: ConnectorContext):
        super().__init__(ctx)
        self.tenant = ctx.get("tenant_id", env="AZURE_TENANT_ID")
        self.include_first_party = bool(ctx.get("include_first_party", False))
        self.max_lookups = int(ctx.get("max_app_role_lookups", 2000))
        self.http: HttpClient | None = None

    # ----------------------------------------------------------------- auth
    def _auth(self) -> None:
        token = self.ctx.get("access_token", env="GRAPH_ACCESS_TOKEN")
        if not token:
            cid = self.ctx.get("client_id", env="AZURE_CLIENT_ID")
            secret = self.ctx.get("client_secret", env="AZURE_CLIENT_SECRET")
            if not (self.tenant and cid and secret):
                raise ConnectorError("identity.entra: tenant_id, client_id and client_secret (or access_token) are required")
            resp = HttpClient().post(
                f"https://login.microsoftonline.com/{self.tenant}/oauth2/v2.0/token",
                data={"grant_type": "client_credentials", "client_id": cid, "client_secret": secret, "scope": "https://graph.microsoft.com/.default"},
            )
            token = resp.json()["access_token"]
        self.http = HttpClient(GRAPH, headers={"Authorization": f"Bearer {token}", "ConsistencyLevel": "eventual"})

    def _pages(self, path: str, **kwargs: Any) -> Iterator[dict[str, Any]]:
        assert self.http
        try:
            yield from self.http.paginate_odata(path, **kwargs)
        except (HttpError, RequestException, RuntimeError, ValueError) as exc:
            status = f"HTTP {exc.status}" if isinstance(exc, HttpError) else type(exc).__name__
            self.ctx.warn(f"identity.entra: collection incomplete for {path} ({status})")

    # -------------------------------------------------------------- collect
    def collect(self) -> Iterable[dict[str, Any]]:
        self._auth()
        assert self.http
        sp_select = "id,appId,displayName,appDisplayName,publisherName,servicePrincipalType,accountEnabled,createdDateTime,tags,appOwnerOrganizationId,homepage,replyUrls,signInAudience,verifiedPublisher,notes,appRoleAssignmentRequired,appRoles,oauth2PermissionScopes,description,loginUrl"
        sps = list(self._pages("/servicePrincipals", params={"$select": sp_select, "$top": 999}))
        role_names: dict[str, str] = {}
        for sp in sps:
            for role in sp.get("appRoles") or []:
                if role.get("id") and role.get("value"):
                    role_names[role["id"]] = role["value"]
        yield {"_kind": "roleMap", "roles": role_names}
        for sp in sps:
            sp["_kind"] = "servicePrincipal"
            sp.pop("appRoles", None)
            sp.pop("oauth2PermissionScopes", None)
            yield sp
        for grant in self._pages("/oauth2PermissionGrants", params={"$top": 999}):
            grant["_kind"] = "oauth2PermissionGrant"
            yield grant
        lookups = 0
        for sp in sps:
            if sp.get("appOwnerOrganizationId") == FIRST_PARTY_OWNER and not self.include_first_party:
                continue
            if lookups >= self.max_lookups:
                self.ctx.warn("identity.entra: max_app_role_lookups reached; app-only permissions partial")
                break
            lookups += 1
            for a in self._pages(f"/servicePrincipals/{sp['id']}/appRoleAssignments", params={"$top": 999}):
                a["_kind"] = "appRoleAssignment"
                yield a
        for app in self._pages("/applications", params={"$select": "id,appId,displayName,createdDateTime,requiredResourceAccess,passwordCredentials,keyCredentials,web,spa,publicClient,signInAudience,notes,tags,description", "$top": 999}):
            app["_kind"] = "application"
            yield app

    # -------------------------------------------------------------- analyze
    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        sps: dict[str, dict[str, Any]] = {}
        grants: dict[str, list[dict[str, Any]]] = {}
        role_assignments: dict[str, list[dict[str, Any]]] = {}
        applications: list[dict[str, Any]] = []
        role_names: dict[str, str] = {}
        for rec in records:
            kind = rec.get("_kind") or _infer_kind(rec)
            if kind == "roleMap":
                role_names.update(rec.get("roles") or {})
            elif kind == "servicePrincipal":
                sps[rec["id"]] = rec
                for role in rec.get("appRoles") or []:
                    if role.get("id") and role.get("value"):
                        role_names[role["id"]] = role["value"]
            elif kind == "oauth2PermissionGrant":
                grants.setdefault(rec.get("clientId", ""), []).append(rec)
            elif kind == "appRoleAssignment":
                role_assignments.setdefault(rec.get("principalId", ""), []).append(rec)
            elif kind == "application":
                applications.append(rec)
        sp_by_app_id = {sp.get("appId"): sp for sp in sps.values()}
        for sp_id, sp in sps.items():
            self.ctx.examined()
            f = self._sp_finding(sp, grants.get(sp_id, []), role_assignments.get(sp_id, []), role_names)
            if f:
                yield f
        for app in applications:
            self.ctx.examined()
            f = self._app_registration_finding(app, sp_by_app_id.get(app.get("appId")), role_names)
            if f:
                yield f

    def _sp_finding(self, sp: dict[str, Any], grants: list[dict[str, Any]], roles: list[dict[str, Any]], role_names: dict[str, str]) -> Finding | None:
        first_party = sp.get("appOwnerOrganizationId") == FIRST_PARTY_OWNER
        sp_type = sp.get("servicePrincipalType") or "Application"
        delegated: set[str] = set()
        principals: set[str] = set()
        admin_consented = False
        for g in grants:
            delegated.update((g.get("scope") or "").split())
            if g.get("consentType") == "AllPrincipals":
                admin_consented = True
            elif g.get("principalId"):
                principals.add(g["principalId"])
        app_perms = sorted({role_names.get(role_id, role_id) for r in roles if isinstance(role_id := r.get("appRoleId"), str) and role_id})
        machine = sp_type == "ManagedIdentity" or bool(app_perms)
        user_consented = bool(principals) or admin_consented
        kind = identity_kind_for(user_consented=user_consented, machine=machine)
        name = sp.get("displayName") or sp.get("appDisplayName") or sp.get("appId")
        f = Finding(
            surface=Surface.IDENTITY,
            connector=self.name,
            kind=kind,
            title=f"Entra {'managed identity' if sp_type == 'ManagedIdentity' else 'service principal'}: {name}",
            resource=f"entra:sp:{sp.get('id')}",
            resource_type=f"service-principal/{sp_type}",
            provider="entra",
            account=self.tenant or sp.get("appOwnerOrganizationId"),
            first_seen=sp.get("createdDateTime"),
        )
        assess_app(
            self.index,
            f,
            name=name,
            publisher=sp.get("publisherName") or ((sp.get("verifiedPublisher") or {}).get("displayName")),
            description=" ".join(x for x in [sp.get("notes"), sp.get("description")] if x),
            urls=[sp.get("homepage"), sp.get("loginUrl"), *(sp.get("replyUrls") or [])],
            scopes=list(delegated) + app_perms,
            client_id=sp.get("appId"),
        )
        if first_party and not f.frameworks and not self.include_first_party:
            return None
        if not f.frameworks and not delegated and not app_perms and sp_type != "ManagedIdentity":
            return None
        f.add_evidence(
            Evidence(
                signal="entra:service-principal",
                description=f"{sp_type} '{name}' (appId {sp.get('appId')}), publisher {sp.get('publisherName') or 'unknown'}, {'first-party' if first_party else 'third-party/tenant'}; enabled={sp.get('accountEnabled')}",
                location=f"https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/{sp.get('id')}",
                weight=0.15 if not machine else 0.3,
            )
        )
        if delegated:
            f.add_evidence(Evidence(signal="entra:delegated-consent", description=f"Delegated consent ({'admin, all users' if admin_consented else f'{len(principals)} user(s)'}): {' '.join(sorted(delegated))[:400]}", weight=0.25))
        if app_perms:
            f.add_evidence(Evidence(signal="entra:application-permissions", description=f"Application (app-only) permissions: {', '.join(app_perms)[:400]}", weight=0.35))
            f.add_tag("app-only-permissions")
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
        finalize(f, self.index)
        f.kind = kind
        return f

    def _app_registration_finding(self, app: dict[str, Any], sp: dict[str, Any] | None, role_names: dict[str, str]) -> Finding | None:
        name = app.get("displayName") or app.get("appId")
        requested: list[str] = []
        for rra in app.get("requiredResourceAccess") or []:
            for ra in rra.get("resourceAccess") or []:
                requested.append(role_names.get(ra.get("id"), ra.get("id")))
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
        redirect_uris = [*((app.get("web") or {}).get("redirectUris") or []), *((app.get("spa") or {}).get("redirectUris") or []), *((app.get("publicClient") or {}).get("redirectUris") or [])]
        assess_app(self.index, f, name=name, description=" ".join(x for x in [app.get("notes"), app.get("description")] if x), urls=redirect_uris, scopes=requested, client_id=app.get("appId"))
        secrets = app.get("passwordCredentials") or []
        certs = app.get("keyCredentials") or []
        if not f.frameworks and not any(t in {"policy.llm-access-scopes", "policy.privileged-scopes", "policy.data-access-scopes"} for t in f.tags):
            return None
        f.add_evidence(Evidence(signal="entra:app-registration", description=f"Tenant-owned app registration '{name}' with {len(secrets)} client secret(s), {len(certs)} certificate(s); requested permissions: {', '.join(str(r) for r in requested)[:300]}", location=f"https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Overview/appId/{app.get('appId')}", weight=0.3))
        if secrets:
            f.add_tag("client-secret")
        f.metadata.update({"app_id": app.get("appId"), "requested_permissions": requested[:40], "client_secrets": len(secrets), "certificates": len(certs), "sign_in_audience": app.get("signInAudience"), "tags": app.get("tags"), "has_service_principal": sp is not None})
        finalize(f, self.index)
        f.kind = Kind.SERVICE_IDENTITY
        return f


def _infer_kind(rec: dict[str, Any]) -> str:
    odata = str(rec.get("@odata.type", "")).lower()
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
