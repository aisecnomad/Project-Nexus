"""Auth0 tenant: applications (clients), machine-to-machine client grants.

Live: Management API v2 (``read:clients``, ``read:client_grants``).
Offline export: list of client objects (``/api/v2/clients``) and client-grant objects.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Iterator
from typing import Any, ClassVar

from requests import RequestException

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError, _positive_limit
from shadowscan.connectors.common import finalize
from shadowscan.connectors.identity.common import assess_app, identity_kind_for, summarize_scopes
from shadowscan.models import Evidence, Finding, Surface
from shadowscan.utils.http import HttpClient, HttpError


class Auth0Connector(BaseConnector):
    name: ClassVar[str] = "identity.auth0"
    surface: ClassVar[Surface] = Surface.IDENTITY
    provider: ClassVar[str | None] = "auth0"
    description: ClassVar[str] = "Auth0 applications and machine-to-machine client grants."
    config_keys: ClassVar[dict[str, str]] = {
        "domain": "tenant domain, e.g. acme.eu.auth0.com (env AUTH0_DOMAIN)",
        "client_id": "M2M app client id for the Management API (env AUTH0_CLIENT_ID)",
        "client_secret": "env AUTH0_CLIENT_SECRET",
        "token": "pre-issued Management API token (env AUTH0_MGMT_TOKEN)",
        "max_pages": "maximum pages per collection, capped at 1000 (default 1000)",
        "input": "offline: JSON export of clients / client-grants",
    }

    def __init__(self, ctx: ConnectorContext):
        super().__init__(ctx)
        self.domain = str(ctx.get("domain", env="AUTH0_DOMAIN") or "").replace("https://", "").rstrip("/")
        self.http: HttpClient | None = None

    def _auth(self) -> None:
        if not self.domain:
            raise ConnectorError("identity.auth0: domain is required")
        token = self.ctx.get("token", env="AUTH0_MGMT_TOKEN")
        if not token:
            cid = self.ctx.get("client_id", env="AUTH0_CLIENT_ID")
            secret = self.ctx.get("client_secret", env="AUTH0_CLIENT_SECRET")
            if not (cid and secret):
                raise ConnectorError("identity.auth0: client_id + client_secret (or token) required")
            client = HttpClient()
            resp = client.post(f"https://{self.domain}/oauth/token", json={"grant_type": "client_credentials", "client_id": cid, "client_secret": secret, "audience": f"https://{self.domain}/api/v2/"})
            token = client.read_json_response(resp)["access_token"]
        self.http = HttpClient(f"https://{self.domain}", headers={"Authorization": f"Bearer {token}"})

    def collect(self) -> Iterable[dict[str, Any]]:
        self._auth()
        assert self.http
        yield from self._pages(
            "/api/v2/clients", "client",
            include_fields="true",
            fields="client_id,name,description,app_type,grant_types,callbacks,allowed_origins,web_origins,initiate_login_uri,client_metadata,is_first_party,token_endpoint_auth_method,logo_uri,sso",
        )
        yield from self._pages("/api/v2/client-grants", "client_grant")

    def _pages(self, path: str, kind: str, **params: Any) -> Iterator[dict[str, Any]]:
        """Bound pagination and retain collected identities when enrichment fails."""
        assert self.http
        seen: set[str] = set()
        max_pages = min(_positive_limit(self.ctx.get("max_pages", 1000), "max_pages"), 1000)
        for page in range(max_pages):
            try:
                batch = self.http.get_json(path, params={**params, "per_page": 100, "page": page})
            except (HttpError, RequestException, RuntimeError, ValueError) as exc:
                status = f"HTTP {exc.status}" if isinstance(exc, HttpError) else type(exc).__name__
                self.ctx.warn(f"identity.auth0: collection incomplete for {path} ({status})")
                return
            if not isinstance(batch, list):
                self.ctx.warn(f"identity.auth0: invalid collection response for {path}")
                return
            fingerprint = hashlib.sha256(json.dumps(batch, sort_keys=True).encode()).hexdigest()
            if fingerprint in seen:
                self.ctx.warn(f"identity.auth0: repeated pagination page for {path}")
                return
            seen.add(fingerprint)
            for record in batch:
                if not isinstance(record, dict):
                    self.ctx.warn(f"identity.auth0: invalid record in {path}; coverage incomplete")
                    continue
                yield {**record, "_kind": kind}
            if len(batch) < 100:
                return
        self.ctx.warn(f"identity.auth0: pagination limit reached for {path}")

    def _record_kind(self, rec: Any) -> str | None:
        if not self._record_fields_valid(
            rec, required=("client_id",), strings=("_kind", "name", "description", "app_type", "initiate_login_uri", "logo_uri", "token_endpoint_auth_method"),
            mappings=("client_metadata",), arrays=("grant_types", "callbacks", "allowed_origins", "web_origins"),
        ):
            return None
        kind = rec.get("_kind") or ("client_grant" if "audience" in rec and "scope" in rec else "client")
        if kind not in {"client", "client_grant"}:
            return None
        for field in ("grant_types", "callbacks", "allowed_origins", "web_origins"):
            if any(not isinstance(value, str) for value in rec.get(field) or []):
                return None
        return kind

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        clients: list[dict[str, Any]] = []
        grants: dict[str, list[dict[str, Any]]] = {}
        for rec in records:
            kind = self._record_kind(rec)
            if kind is None:
                self.ctx.warn("identity.auth0: malformed client or grant record; coverage incomplete")
                continue
            if kind == "client_grant":
                grants.setdefault(rec.get("client_id", ""), []).append(rec)
            else:
                clients.append(rec)
        for c in clients:
            self.ctx.examined()
            f = self._client_finding(c, grants.get(c.get("client_id", ""), []))
            if f:
                yield f

    def _client_finding(self, c: dict[str, Any], grants: list[dict[str, Any]]) -> Finding | None:
        name = c.get("name") or c.get("client_id")
        grant_types = c.get("grant_types") or []
        machine = c.get("app_type") == "non_interactive" or "client_credentials" in grant_types or bool(grants)
        scope_names: set[str] = set()
        for grant in grants:
            raw_scopes = grant.get("scope") or []
            if isinstance(raw_scopes, str):
                raw_scopes = raw_scopes.split()
            if not isinstance(raw_scopes, list):
                self.ctx.warn("identity.auth0: client grant has invalid scopes")
                continue
            for scope in raw_scopes:
                if not isinstance(scope, str) or not scope.strip():
                    self.ctx.warn("identity.auth0: client grant has invalid scope entry")
                    continue
                scope_names.add(scope.strip())
        scopes = sorted(scope_names)
        api_audiences: set[str] = set()
        for grant in grants:
            audience = grant.get("audience")
            if not isinstance(audience, str) or not audience.strip():
                self.ctx.warn("identity.auth0: client grant has no valid audience identifier")
                continue
            api_audiences.add(audience)
        audiences = sorted(api_audiences)
        kind = identity_kind_for(user_consented=not machine, machine=machine)
        f = Finding(
            surface=Surface.IDENTITY,
            connector=self.name,
            kind=kind,
            title=f"Auth0 {'M2M application' if machine else 'application'}: {name}",
            resource=f"auth0:client:{c.get('client_id')}",
            resource_type=f"auth0-client/{c.get('app_type') or 'unknown'}",
            provider="auth0",
            account=self.domain or None,
        )
        assess_app(
            self.index,
            f,
            name=name,
            description=c.get("description"),
            urls=[c.get("initiate_login_uri"), c.get("logo_uri"), *(c.get("callbacks") or []), *(c.get("allowed_origins") or []), *(c.get("web_origins") or []), *audiences],
            scopes=scopes,
            client_id=c.get("client_id"),
            grant_types=grant_types,
            auth_method=c.get("token_endpoint_auth_method"),
        )
        meta = c.get("client_metadata") or {}
        if meta:
            from shadowscan.connectors.common import apply_matches, name_matches

            apply_matches(f, name_matches(self.index, " ".join(f"{k}={v}" for k, v in meta.items())), weight_scale=0.6)
        if not f.frameworks and not machine:
            return None
        f.add_evidence(Evidence(signal="auth0:client", description=f"{c.get('app_type') or 'app'} '{name}', grant types {', '.join(grant_types) or 'n/a'}, {'first-party' if c.get('is_first_party') else 'third-party'}; {len(grants)} client grant(s) to {', '.join(audiences)[:200] or 'no API'}", weight=0.3 if machine else 0.15))
        f.metadata.update({"client_id": c.get("client_id"), "app_type": c.get("app_type"), "grant_types": grant_types, "audiences": audiences, "scopes": summarize_scopes(scopes), "is_first_party": c.get("is_first_party"), "client_metadata": meta})
        finalize(f, self.index)
        f.kind = kind
        return f
