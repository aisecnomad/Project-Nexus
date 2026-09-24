"""Google Workspace: third-party OAuth apps authorised by users (Admin SDK tokens).

For every user, ``GET /admin/directory/v1/users/{user}/tokens`` lists the
OAuth clients that hold refresh tokens with their scopes. Results are
aggregated per client id so a single finding represents "Otter.ai has Gmail +
Calendar access for 214 users".

Auth: a service-account key with domain-wide delegation (impersonating an
admin, ``admin_email``) or a pre-issued ``access_token`` with
``admin.directory.user.readonly`` + ``admin.directory.user.security`` scopes.

Offline export: list of token objects (each with ``userKey`` / ``userEmail``)
or per-user dicts ``{"user": ..., "tokens": [...]}``.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any, ClassVar

from requests import RequestException

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.connectors.common import finalize
from shadowscan.connectors.identity.common import assess_app, summarize_scopes
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.utils.http import HttpClient, HttpError

SCOPES = "https://www.googleapis.com/auth/admin.directory.user.readonly https://www.googleapis.com/auth/admin.directory.user.security"


class GoogleWorkspaceConnector(BaseConnector):
    name: ClassVar[str] = "identity.google-workspace"
    surface: ClassVar[Surface] = Surface.IDENTITY
    provider: ClassVar[str | None] = "google-workspace"
    description: ClassVar[str] = "OAuth apps authorised by Google Workspace users (Admin SDK tokens), aggregated per client."
    config_keys: ClassVar[dict[str, str]] = {
        "service_account_file": "SA key JSON with domain-wide delegation (env GOOGLE_APPLICATION_CREDENTIALS)",
        "admin_email": "admin user to impersonate (env GOOGLE_ADMIN_EMAIL)",
        "access_token": "pre-issued token instead of SA (env GOOGLE_ACCESS_TOKEN)",
        "customer": "customer id (default my_customer)",
        "max_users": "cap on users enumerated (default 10000)",
        "input": "offline: JSON export of token objects",
    }

    def __init__(self, ctx: ConnectorContext):
        super().__init__(ctx)
        self.customer = ctx.get("customer", "my_customer")
        self.max_users = int(ctx.get("max_users", 10_000))
        self.http: HttpClient | None = None

    def _auth(self) -> None:
        token = self.ctx.get("access_token", env="GOOGLE_ACCESS_TOKEN")
        if not token:
            sa_file = self.ctx.get("service_account_file", env="GOOGLE_APPLICATION_CREDENTIALS")
            admin = self.ctx.get("admin_email", env="GOOGLE_ADMIN_EMAIL")
            if not (sa_file and admin):
                raise ConnectorError("identity.google-workspace: service_account_file + admin_email (or access_token) required")
            token = _dwd_token(Path(sa_file), admin, SCOPES)
        self.http = HttpClient("https://admin.googleapis.com", headers={"Authorization": f"Bearer {token}"})

    def collect(self) -> Iterable[dict[str, Any]]:
        self._auth()
        assert self.http
        count = 0
        token_errors: dict[str, int] = {}
        try:
            for user in self.http.paginate_token(
                "/admin/directory/v1/users",
                params={"customer": self.customer, "maxResults": 500, "projection": "basic"},
                items_key="users", expected_empty_kind="admin#directory#users",
            ):
                count += 1
                if count > self.max_users:
                    self.ctx.warn("identity.google-workspace: max_users reached")
                    break
                if not isinstance(user, dict):
                    self.ctx.warn("identity.google-workspace: invalid user record")
                    continue
                email = user.get("primaryEmail")
                if user.get("suspended"):
                    continue
                if not isinstance(email, str) or not email:
                    self.ctx.warn("identity.google-workspace: user record missing primaryEmail")
                    continue
                try:
                    data = self.http.get_json(f"/admin/directory/v1/users/{email}/tokens")
                except (HttpError, RequestException, ValueError) as exc:
                    status = f"HTTP {exc.status}" if isinstance(exc, HttpError) else type(exc).__name__
                    token_errors[status] = token_errors.get(status, 0) + 1
                    continue
                # Google omits empty repeated fields, but only an identified
                # token-list envelope can establish that the user has no tokens.
                if (not isinstance(data, dict) or self._is_error_record(data)
                        or ("items" not in data and data.get("kind") != "admin#directory#tokenList")
                        or not isinstance(data.get("items", []), list)):
                    self.ctx.warn(f"identity.google-workspace: invalid token response for {email}")
                    continue
                for tok in data.get("items", []):
                    if not isinstance(tok, dict):
                        self.ctx.warn(f"identity.google-workspace: invalid token record for {email}")
                        continue
                    yield {**tok, "userEmail": email}
        except (HttpError, RequestException, RuntimeError, ValueError) as exc:
            status = f"HTTP {exc.status}" if isinstance(exc, HttpError) else type(exc).__name__
            self.ctx.warn(f"identity.google-workspace: user enumeration incomplete ({status})")
        if token_errors:
            details = ", ".join(f"{status}: {total}" for status, total in sorted(token_errors.items()))
            self.ctx.warn(f"identity.google-workspace: OAuth tokens unreadable for {sum(token_errors.values())} user(s) ({details}); app inventory incomplete")

    @staticmethod
    def _is_native_offline_record(data: dict[str, Any]) -> bool:
        # A user and its tokens form one provider record. Unwrapping only the
        # token array here would discard the granting user's attribution.
        return ("tokens" in data and any(key in data for key in ("user", "userEmail", "userKey"))) or BaseConnector._is_native_offline_record(data)

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        apps: dict[str, dict[str, Any]] = {}
        for rec in records:
            if not self._record_fields_valid(rec, strings=("user", "userEmail", "userKey")):
                self.ctx.warn("identity.google-workspace: malformed token record or provider error; coverage incomplete")
                continue
            if "tokens" in rec and not isinstance(rec["tokens"], list):
                self.ctx.warn("identity.google-workspace: user tokens must be an array; coverage incomplete")
                continue
            tokens = rec.get("tokens", [rec])
            user = rec.get("user") or rec.get("userEmail") or rec.get("userKey")
            if "tokens" in rec and not user:
                self.ctx.warn("identity.google-workspace: per-user token export is missing user identity")
            for tok in tokens:
                if not self._record_fields_valid(tok, required=("clientId",), strings=("displayText", "userEmail", "userKey"), arrays=("scopes",)):
                    self.ctx.warn("identity.google-workspace: invalid token record or missing clientId; coverage incomplete")
                    continue
                scopes = tok.get("scopes") or []
                if any(not isinstance(scope, str) or not scope.strip() for scope in scopes):
                    self.ctx.warn("identity.google-workspace: invalid token scope; coverage incomplete")
                    scopes = [scope for scope in scopes if isinstance(scope, str) and scope.strip()]
                cid = tok["clientId"]
                self.ctx.examined()
                agg = apps.setdefault(cid, {"clientId": cid, "displayText": tok.get("displayText"), "scopes": set(), "users": set(), "anonymous": tok.get("anonymous"), "nativeApp": tok.get("nativeApp")})
                agg["scopes"].update(scopes)
                u = tok.get("userEmail") or tok.get("userKey") or user
                if u:
                    agg["users"].add(u)
                if tok.get("displayText") and not agg["displayText"]:
                    agg["displayText"] = tok["displayText"]
        for agg in apps.values():
            f = self._app_finding(agg)
            if f:
                yield f

    def _app_finding(self, agg: dict[str, Any]) -> Finding | None:
        name = agg.get("displayText") or agg["clientId"]
        scopes = sorted(agg["scopes"])
        f = Finding(
            surface=Surface.IDENTITY,
            connector=self.name,
            kind=Kind.OAUTH_GRANT,
            title=f"Google Workspace OAuth app: {name}",
            resource=f"google-workspace:oauth-client:{agg['clientId']}",
            resource_type="oauth-client",
            provider="google-workspace",
            account=self.customer if self.customer != "my_customer" else None,
        )
        assess_app(self.index, f, name=name, scopes=scopes, client_id=agg["clientId"])
        interesting = bool(f.frameworks) or any(t.startswith("policy.") for t in f.tags)
        if not interesting:
            return None
        users = agg["users"]
        f.add_evidence(Evidence(signal="google:oauth-token", description=f"{len(users)} user(s) granted '{name}' ({agg['clientId']}) scopes: {' '.join(scopes)[:400]}", weight=0.2 + min(0.3, len(users) / 200)))
        if agg.get("anonymous"):
            f.add_tag("anonymous-client")
        if agg.get("nativeApp"):
            f.add_tag("native-app")
        f.metadata.update({"client_id": agg["clientId"], "scopes": summarize_scopes(scopes), "user_count": len(users), "users_sample": sorted(users)[:10], "anonymous": agg.get("anonymous"), "native_app": agg.get("nativeApp")})
        finalize(f, self.index)
        f.kind = Kind.OAUTH_GRANT
        return f


def _dwd_token(sa_file: Path, subject: str, scopes: str) -> str:
    """Mint a domain-wide-delegation access token from a service-account key (no google-auth needed)."""
    try:
        import jwt  # PyJWT
    except ImportError as exc:  # pragma: no cover
        raise ConnectorError("identity.google-workspace: PyJWT with cryptography is required") from exc
    info = json.loads(sa_file.read_text(encoding="utf-8"))
    now = int(time.time())
    assertion = jwt.encode(
        {"iss": info["client_email"], "sub": subject, "scope": scopes, "aud": info.get("token_uri", "https://oauth2.googleapis.com/token"), "iat": now, "exp": now + 3600},
        info["private_key"],
        algorithm="RS256",
        headers={"kid": info.get("private_key_id")},
    )
    client = HttpClient()
    resp = client.post(info.get("token_uri", "https://oauth2.googleapis.com/token"), data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion})
    return client.read_json_response(resp)["access_token"]
