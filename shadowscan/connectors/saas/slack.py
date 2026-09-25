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

import re
from collections.abc import Iterable
from typing import Any, ClassVar

from requests import RequestException

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.connectors.common import finalize
from shadowscan.connectors.identity.common import assess_app, summarize_scopes
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.utils.http import HttpClient, HttpError
from shadowscan.utils.text import get_path, parse_timestamp, to_iso


class SlackConnector(BaseConnector):
    name: ClassVar[str] = "saas.slack"
    _OFFLINE_COLLECTION_KINDS: ClassVar[dict[str, str]] = {
        "approved_apps": "approved_app", "restricted_apps": "restricted_app", "app_requests": "app_request",
    }
    surface: ClassVar[Surface] = Surface.SAAS
    provider: ClassVar[str | None] = "slack"
    description: ClassVar[str] = "Slack apps, bot users, approved/restricted apps and install logs."
    config_keys: ClassVar[dict[str, str]] = {
        "token": "xoxb/xoxp token (env SLACK_TOKEN); admin.apps.* need an org admin user token",
        "team_id": "expected workspace id for live collection; required for offline exports without a team record",
        "input": "offline: JSON export of users / apps / integration logs",
    }

    def __init__(self, ctx: ConnectorContext):
        super().__init__(ctx)
        self.team_id = ctx.get("team_id", env="SLACK_TEAM_ID")
        if self.team_id is not None and not self._workspace_id_valid(self.team_id):
            raise ConnectorError("saas.slack: team_id must be a Slack workspace ID")

    @staticmethod
    def _workspace_id_valid(value: Any) -> bool:
        return isinstance(value, str) and re.fullmatch(r"T[A-Z0-9]+", value) is not None

    def collect(self) -> Iterable[dict[str, Any]]:
        token = self.ctx.get("token", env="SLACK_TOKEN")
        if not token:
            raise ConnectorError("saas.slack: token required")
        http = HttpClient("https://slack.com/api", headers={"Authorization": f"Bearer {token}"})
        info = self._api(http, "/team.info")
        if info is None:
            return
        team = info.get("team")
        if not isinstance(team, dict) or not self._record_fields_valid(team, required=("id",), strings=("name", "domain")) or not self._workspace_id_valid(team["id"]):
            self.ctx.warn("saas.slack: invalid team.info response; workspace identity and coverage unknown")
            return
        if self.team_id is not None and team["id"] != self.team_id:
            self.ctx.warn("saas.slack: authenticated workspace does not match configured team_id; inventory not collected")
            return
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
            entries = data.get("logs")
            if not isinstance(entries, list):
                self.ctx.warn("saas.slack: invalid integration logs collection; coverage unknown")
                return
            for entry in entries:
                if not isinstance(entry, dict):
                    self.ctx.warn("saas.slack: invalid integration log record; coverage unknown")
                    continue
                yield {"_kind": "integration_log", **entry}
            paging = data.get("paging")
            pages = paging.get("pages") if isinstance(paging, dict) else None
            if type(pages) is not int or pages < 0 or (pages == 0 and entries):
                self.ctx.warn("saas.slack: invalid integration log pagination; coverage unknown")
                return
            if page >= pages:
                return
            page += 1
        self.ctx.warn("saas.slack: integration log page limit reached", incomplete=True)

    def _api(self, http: HttpClient, path: str, params: dict[str, Any] | None = None) -> dict[str, Any] | None:
        try:
            data = http.get_json(path, params=params)
        except (HttpError, RequestException, RuntimeError, ValueError) as exc:
            reason = f"HTTP {exc.status}" if isinstance(exc, HttpError) else type(exc).__name__
            self.ctx.warn(f"saas.slack: {path}: {reason}; coverage unknown", incomplete=True)
            return None
        if not isinstance(data, dict) or data.get("ok") is not True:
            error = data.get("error") if isinstance(data, dict) else None
            # Keep machine-readable denial codes, never arbitrary provider text.
            if not isinstance(error, str) or error not in {
                "missing_scope", "not_allowed_token_type", "restricted_action",
                "invalid_auth", "not_authed", "token_revoked", "account_inactive",
                "team_access_not_granted", "org_login_required", "not_allowed",
            }:
                error = "invalid or failed response"
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
            items = data.get(key)
            if not isinstance(items, list):
                self.ctx.warn(f"saas.slack: invalid {key} collection for {path}; coverage unknown")
                return
            for item in items:
                if not isinstance(item, dict):
                    self.ctx.warn(f"saas.slack: invalid {key} record for {path}; coverage unknown")
                    continue
                yield item
            metadata = data.get("response_metadata", {})
            if not isinstance(metadata, dict) or not isinstance(metadata.get("next_cursor", ""), str):
                self.ctx.warn(f"saas.slack: invalid cursor for {path}; coverage unknown")
                return
            cursor = metadata.get("next_cursor", "").strip()
            if not cursor:
                return
            if cursor in seen:
                self.ctx.warn(f"saas.slack: repeated cursor for {path}", incomplete=True)
                return
            seen.add(cursor)
            params["cursor"] = cursor
        self.ctx.warn(f"saas.slack: page limit for {path}", incomplete=True)

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        teams: dict[str, str | None] = {}
        record_teams: set[str] = set()
        invalid_scope = False
        bots: dict[str, dict[str, Any]] = {}
        apps: dict[str, dict[str, Any]] = {}
        logs: dict[str, list[dict[str, Any]]] = {}
        requests: list[dict[str, Any]] = []
        for rec in records:
            kind = self._record_kind(rec)
            if kind is None:
                self.ctx.warn("saas.slack: unsupported or malformed provider record; coverage incomplete")
                if rec.get("_kind") == "team" or _infer(rec) == "team":
                    invalid_scope = True
                continue
            for field in ("team_id", "team") if kind == "bot_user" else ("team_id",):
                if field in rec:
                    if not self._workspace_id_valid(rec[field]):
                        invalid_scope = True
                    else:
                        record_teams.add(rec[field])
            if kind == "team":
                teams[rec["id"]] = rec.get("name") or rec.get("domain")
            elif kind == "bot_user":
                app_id = get_path(rec, "profile.api_app_id") or rec.get("id")
                bots[str(app_id)] = rec
            elif kind in {"approved_app", "restricted_app"}:
                app = rec.get("app") or rec
                app_id = app.get("id") or app.get("app_id")
                entry = apps.setdefault(str(app_id), {"app": app, "scopes": [], "status": kind.replace("_app", ""), "last_resolved_by": None, "date_updated": None})
                entry["scopes"] = rec.get("scopes") or app.get("scopes") or []
                entry["last_resolved_by"] = get_path(rec, "last_resolved_by.actor_id", "last_resolved_by.actor_type")
                entry["date_updated"] = rec.get("date_updated")
            elif kind == "app_request":
                requests.append(rec)
            elif kind == "integration_log":
                key = rec.get("app_id") or rec.get("service_id") or rec.get("app_type") or rec.get("service_type")
                logs.setdefault(str(key), []).append(rec)
        # App IDs are shared across workspaces. Resolve the entire export before
        # emitting findings so a later conflicting team cannot relabel earlier
        # records. Names are presentation metadata, never identity.
        if invalid_scope or len(teams) > 1 or (teams and self.team_id is not None and self.team_id not in teams):
            self.ctx.warn("saas.slack: conflicting or malformed workspace identity; findings not attributed")
            return
        team_id = next(iter(teams), None)
        scope_source = "team-record"
        if team_id is None and self.offline and self.team_id is not None:
            team_id = self.team_id
            scope_source = "operator-configured"
        if team_id is None:
            self.ctx.warn("saas.slack: workspace identity missing; supply team_id for an offline export")
            return
        if record_teams - {team_id}:
            self.ctx.warn("saas.slack: record workspace does not match declared workspace; findings not attributed")
            return
        team_name = teams.get(team_id)
        seen: set[str] = set()
        for app_id, entry in apps.items():
            self.ctx.examined()
            seen.add(app_id)
            f = self._app_finding(app_id, entry["app"], entry["scopes"], entry["status"], bots.get(app_id), logs.get(app_id, []), team_id)
            if f:
                f.metadata.update(workspace_name=team_name, workspace_scope_source=scope_source)
                yield f
        for app_id, bot in bots.items():
            if app_id in seen:
                continue
            self.ctx.examined()
            app = {"id": app_id, "name": get_path(bot, "profile.real_name", "real_name", "name"), "description": get_path(bot, "profile.title")}
            f = self._app_finding(app_id, app, [], "installed", bot, logs.get(app_id, []), team_id)
            if f:
                f.metadata.update(workspace_name=team_name, workspace_scope_source=scope_source)
                yield f
        for req in requests:
            self.ctx.examined()
            app = req.get("app") or {}
            f = self._app_finding(str(app.get("id") or app.get("app_id")), app, req.get("scopes") or [], "requested", None, [], team_id, requester=get_path(req, "user.email", "user.name", "user.id"), message=req.get("message"))
            if f:
                f.add_tag("pending-request")
                f.metadata.update(workspace_name=team_name, workspace_scope_source=scope_source)
                yield f

    def _record_kind(self, rec: dict[str, Any]) -> str | None:
        if not self._record_fields_valid(
            rec, strings=("_kind", "id", "name", "real_name", "domain", "app_id", "service_id", "app_type", "service_type", "change_type", "scope", "user_name", "user_id", "message"),
            mappings=("profile", "app", "user", "last_resolved_by"),
        ):
            return None
        if any(rec.get(key) is not None and not isinstance(rec[key], bool) for key in ("is_bot", "is_app_user")):
            return None
        kind = rec.get("_kind") or _infer(rec)
        if kind in {"team", "user", "bot_user"}:
            if not self._record_fields_valid(rec, required=("id",)):
                return None
            if kind == "team" and not self._workspace_id_valid(rec["id"]):
                return None
            profile = rec.get("profile") or {}
            if not self._record_fields_valid(profile, strings=("api_app_id", "real_name", "title")):
                return None
        elif kind in {"approved_app", "restricted_app", "app_request"}:
            app = rec.get("app") if "app" in rec else rec
            if not isinstance(app, dict) or not self._record_fields_valid(app, strings=("id", "app_id", "name", "description", "additional_info", "publisher", "app_homepage_url", "privacy_policy_url", "app_directory_url")):
                return None
            if not (isinstance(app.get("id"), str) and app["id"].strip() or isinstance(app.get("app_id"), str) and app["app_id"].strip()):
                return None
            if kind == "app_request" and not isinstance(rec.get("app"), dict):
                return None
        elif kind == "integration_log":
            if not any(isinstance(rec.get(key), str) and rec[key].strip() for key in ("app_id", "service_id", "app_type", "service_type")):
                return None
        else:
            return None
        return kind

    def _app_finding(self, app_id: str, app: dict[str, Any], scopes: list[Any], status: str, bot: dict[str, Any] | None, logs: list[dict[str, Any]], team: str | None, requester: str | None = None, message: str | None = None) -> Finding | None:
        name = app.get("name") or get_path(bot or {}, "profile.real_name", "real_name") or app_id
        scope_names: list[str] = []
        if not isinstance(scopes, list):
            self.ctx.warn("saas.slack: app scopes must be a list; scope coverage unknown")
            scopes = []
        for scope in scopes:
            scope_name = scope.get("name") if isinstance(scope, dict) else scope
            if not isinstance(scope_name, str) or not scope_name.strip():
                self.ctx.warn("saas.slack: invalid app scope entry; scope coverage unknown")
                continue
            scope_names.append(scope_name.strip())
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
    if "app" in rec and "user" in rec and "message" in rec:
        return "app_request"
    if "app" in rec and ("scopes" in rec or "last_resolved_by" in rec):
        return "approved_app"
    if rec.get("is_bot") is False or rec.get("is_app_user") is False:
        return "user"
    if "change_type" in rec or "service_type" in rec or ("app_type" in rec and "user_id" in rec):
        return "integration_log"
    if "domain" in rec and "name" in rec and "id" in rec and "is_bot" not in rec:
        return "team"
    return "approved_app" if "scopes" in rec else "unknown"
