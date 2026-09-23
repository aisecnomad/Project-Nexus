"""Slack: installed apps, bot users and their scopes.

Live (bot/user token with ``users:read``; org admin token for the ``admin.apps.*`` methods):

* ``users.list``                 – bot users (``is_bot``) with their app ids
* ``admin.apps.approved.list``   – approved apps with scopes (Enterprise Grid / admin API)
* ``admin.apps.restricted.list`` – restricted apps
* ``admin.apps.requests.list``   – pending install requests (shadow demand)
* ``team.integrationLogs``       – who installed what, when (admin)

Offline export: any mix of the above objects (``_kind`` optional; inferred from shape).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, ClassVar

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.connectors.common import finalize
from shadowscan.connectors.identity.common import assess_app, summarize_scopes
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.utils.http import HttpClient, HttpError
from shadowscan.utils.text import get_path, parse_timestamp, to_iso


class SlackConnector(BaseConnector):
    name: ClassVar[str] = "saas.slack"
    surface: ClassVar[Surface] = Surface.SAAS
    provider: ClassVar[str | None] = "slack"
    description: ClassVar[str] = "Slack apps, bot users, approved/restricted apps and install logs."
    config_keys: ClassVar[dict[str, str]] = {
        "token": "xoxb/xoxp token (env SLACK_TOKEN); admin.apps.* need an org admin user token",
        "team_id": "workspace id for admin.apps calls on Enterprise Grid",
        "input": "offline: JSON export of users / apps / integration logs",
    }

    def __init__(self, ctx: ConnectorContext):
        super().__init__(ctx)
        self.team_id = ctx.get("team_id", env="SLACK_TEAM_ID")

    def collect(self) -> Iterable[dict[str, Any]]:
        token = self.ctx.get("token", env="SLACK_TOKEN")
        if not token:
            raise ConnectorError("saas.slack: token required")
        http = HttpClient("https://slack.com/api", headers={"Authorization": f"Bearer {token}"})
        info = self._api(http, "/team.info") or {}
        team = (info.get("team") or {})
        yield {"_kind": "team", **team}
        for u in self._cursor(http, "/users.list", {"limit": 200}, "members"):
            if u.get("is_bot") or u.get("is_app_user"):
                u["_kind"] = "bot_user"
                yield u
        params = {"limit": 100}
        if self.team_id:
            params["team_id"] = self.team_id
        for method, kind, key in (("admin.apps.approved.list", "approved_app", "approved_apps"), ("admin.apps.restricted.list", "restricted_app", "restricted_apps"), ("admin.apps.requests.list", "app_request", "app_requests")):
            for item in self._cursor(http, f"/{method}", params, key):
                item["_kind"] = kind
                yield item
        page = 1
        while page <= 1000:
            data = self._api(http, "/team.integrationLogs", {"count": 1000, "page": page})
            if data is None:
                return
            for entry in data.get("logs", []) or []:
                yield {"_kind": "integration_log", **entry}
            paging = data.get("paging") or {}
            if page >= int(paging.get("pages", 1)):
                return
            page += 1
        self.ctx.warn("saas.slack: integration log page limit reached", incomplete=True)

    def _api(self, http: HttpClient, path: str, params: dict[str, Any] | None = None) -> dict[str, Any] | None:
        try:
            data = http.get_json(path, params=params)
        except HttpError as exc:
            self.ctx.warn(f"saas.slack: {path}: HTTP {exc.status}; coverage unknown", incomplete=True)
            return None
        if not isinstance(data, dict) or data.get("ok") is not True:
            error = data.get("error", "invalid response") if isinstance(data, dict) else "invalid response"
            self.ctx.warn(f"saas.slack: {path}: {error}; coverage unknown", incomplete=True)
            return None
        return data

    def _cursor(self, http: HttpClient, path: str, params: dict[str, Any], key: str) -> Iterable[dict[str, Any]]:
        params = dict(params)
        seen: set[str] = set()
        for _ in range(1000):
            data = self._api(http, path, params)
            if data is None:
                return
            yield from data.get(key, []) or []
            cursor = str((data.get("response_metadata") or {}).get("next_cursor") or "").strip()
            if not cursor:
                return
            if cursor in seen:
                self.ctx.warn(f"saas.slack: repeated cursor for {path}", incomplete=True)
                return
            seen.add(cursor)
            params["cursor"] = cursor
        self.ctx.warn(f"saas.slack: page limit for {path}", incomplete=True)

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        team_name: str | None = None
        bots: dict[str, dict[str, Any]] = {}
        apps: dict[str, dict[str, Any]] = {}
        logs: dict[str, list[dict[str, Any]]] = {}
        requests: list[dict[str, Any]] = []
        for rec in records:
            kind = rec.get("_kind") or _infer(rec)
            if kind == "team":
                team_name = rec.get("name") or rec.get("domain")
            elif kind == "bot_user":
                app_id = get_path(rec, "profile.api_app_id") or rec.get("id")
                bots[str(app_id)] = rec
            elif kind in {"approved_app", "restricted_app"}:
                app = rec.get("app") or rec
                app_id = app.get("id") or app.get("app_id") or app.get("name")
                entry = apps.setdefault(str(app_id), {"app": app, "scopes": [], "status": kind.replace("_app", ""), "last_resolved_by": None, "date_updated": None})
                entry["scopes"] = rec.get("scopes") or app.get("scopes") or []
                entry["last_resolved_by"] = get_path(rec, "last_resolved_by.actor_id", "last_resolved_by.actor_type")
                entry["date_updated"] = rec.get("date_updated")
            elif kind == "app_request":
                requests.append(rec)
            elif kind == "integration_log":
                key = rec.get("app_id") or rec.get("service_id") or rec.get("app_type") or rec.get("service_type")
                logs.setdefault(str(key), []).append(rec)
        seen: set[str] = set()
        for app_id, entry in apps.items():
            self.ctx.examined()
            seen.add(app_id)
            f = self._app_finding(app_id, entry["app"], entry["scopes"], entry["status"], bots.get(app_id), logs.get(app_id, []), team_name)
            if f:
                yield f
        for app_id, bot in bots.items():
            if app_id in seen:
                continue
            self.ctx.examined()
            app = {"id": app_id, "name": get_path(bot, "profile.real_name", "real_name", "name"), "description": get_path(bot, "profile.title")}
            f = self._app_finding(app_id, app, [], "installed", bot, logs.get(app_id, []), team_name)
            if f:
                yield f
        for req in requests:
            self.ctx.examined()
            app = req.get("app") or {}
            f = self._app_finding(str(app.get("id") or app.get("name")), app, [s.get("name") if isinstance(s, dict) else s for s in req.get("scopes") or []], "requested", None, [], team_name, requester=get_path(req, "user.email", "user.name", "user.id"), message=req.get("message"))
            if f:
                f.add_tag("pending-request")
                yield f

    def _app_finding(self, app_id: str, app: dict[str, Any], scopes: list[Any], status: str, bot: dict[str, Any] | None, logs: list[dict[str, Any]], team: str | None, requester: str | None = None, message: str | None = None) -> Finding | None:
        name = app.get("name") or get_path(bot or {}, "profile.real_name", "real_name") or app_id
        scope_names = [s.get("name") if isinstance(s, dict) else str(s) for s in scopes if s]
        installer = None
        installed_at = None
        for log in sorted(logs, key=lambda l: str(l.get("date", ""))):
            if log.get("change_type") in {"added", "enabled", "expanded", None}:
                installer = log.get("user_name") or log.get("user_id")
                installed_at = to_iso(parse_timestamp(log.get("date")))
            if log.get("scope"):
                scope_names.extend(str(log["scope"]).split(","))
        f = Finding(
            surface=Surface.SAAS,
            connector=self.name,
            kind=Kind.BOT_APP,
            title=f"Slack app{' (bot)' if bot else ''}: {name}",
            resource=f"slack:app:{app_id}",
            resource_type="slack-app",
            provider="slack",
            account=team,
            owner=installer or requester,
            first_seen=installed_at,
            last_seen=to_iso(parse_timestamp((bot or {}).get("updated"))),
        )
        assess_app(self.index, f, name=name, publisher=app.get("publisher") or get_path(app, "app_homepage_url"), description=app.get("description") or app.get("additional_info"), urls=[app.get("app_homepage_url"), app.get("privacy_policy_url"), get_path(app, "app_directory_url")], scopes=scope_names)
        interesting = bool(f.frameworks) or any(t.startswith("policy.") for t in f.tags) or status == "requested"
        if not interesting and not (bot and scope_names):
            return None
        f.add_evidence(Evidence(signal="slack:app", description=f"App '{name}' ({status}){' with bot user' if bot else ''}; scopes: {', '.join(sorted(set(scope_names)))[:400] or 'unknown'}" + (f"; requested by {requester}: {message}" if requester else ""), weight=0.3 if bot else 0.2))
        if bot:
            f.add_tag("bot-user")
        if app.get("is_app_directory_approved") is False:
            f.add_tag("not-directory-approved")
        f.metadata.update({"app_id": app_id, "status": status, "scopes": summarize_scopes(scope_names), "bot_user_id": (bot or {}).get("id"), "is_directory_approved": app.get("is_app_directory_approved"), "install_logs": len(logs), "homepage": app.get("app_homepage_url")})
        finalize(f, self.index)
        f.kind = Kind.BOT_APP
        return f


def _infer(rec: dict[str, Any]) -> str:
    if rec.get("is_bot") or rec.get("is_app_user"):
        return "bot_user"
    if "app" in rec and ("scopes" in rec or "last_resolved_by" in rec):
        return "approved_app"
    if "app" in rec and "user" in rec and "message" in rec:
        return "app_request"
    if "change_type" in rec or "service_type" in rec or ("app_type" in rec and "user_id" in rec):
        return "integration_log"
    if "domain" in rec and "name" in rec and "id" in rec and "is_bot" not in rec:
        return "team"
    return "approved_app" if "scopes" in rec else "unknown"
