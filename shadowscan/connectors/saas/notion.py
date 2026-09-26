"""Notion: integrations (bot users) connected to a workspace.

Live: ``GET /v1/users`` with an internal integration token (``read user information``
capability) lists people and bots; every ``type == "bot"`` user is an integration
(internal or public) with access to the pages it was shared with.

Offline export: ``/v1/users`` response or list of user objects.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, ClassVar

from shadowscan.connectors.base import BaseConnector, ConnectorError, _positive_limit
from shadowscan.connectors.common import finalize
from shadowscan.connectors.identity.common import assess_app
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.signatures.matcher import MatchTimeoutError
from shadowscan.utils.http import HttpClient
from shadowscan.utils.text import get_path


class NotionConnector(BaseConnector):
    name: ClassVar[str] = "saas.notion"
    surface: ClassVar[Surface] = Surface.SAAS
    provider: ClassVar[str | None] = "notion"
    description: ClassVar[str] = "Notion integrations (bot users) connected to the workspace."
    config_keys: ClassVar[dict[str, str]] = {
        "token": "internal integration secret (env NOTION_TOKEN)",
        "max_pages": "maximum live /v1/users pages, capped at 1000 (default 1000)",
        "input": "offline: /v1/users JSON",
    }

    def collect(self) -> Iterable[dict[str, Any]]:
        token = self.ctx.get("token", env="NOTION_TOKEN")
        if not token:
            raise ConnectorError("saas.notion: token required")
        http = HttpClient("https://api.notion.com", headers={"Authorization": f"Bearer {token}", "Notion-Version": "2022-06-28"})
        max_pages = min(_positive_limit(self.ctx.get("max_pages", 1000), "max_pages"), 1000)
        cursor: str | None = None
        seen: set[str] = set()
        for _ in range(max_pages):
            params: dict[str, Any] = {"page_size": 100}
            if cursor:
                params["start_cursor"] = cursor
            data = http.get_json("/v1/users", params=params)
            if not isinstance(data, dict) or not isinstance(data.get("results"), list):
                self.ctx.warn("saas.notion: invalid users page; collection incomplete")
                return
            yield from data["results"]
            if not isinstance(data.get("has_more"), bool):
                self.ctx.warn("saas.notion: invalid has_more in users page; collection incomplete")
                return
            if not data["has_more"]:
                return
            next_cursor = data.get("next_cursor")
            if not isinstance(next_cursor, str) or not next_cursor.strip():
                self.ctx.warn("saas.notion: users page has_more without next_cursor; collection incomplete")
                return
            if next_cursor in seen:
                self.ctx.warn("saas.notion: repeated users cursor; collection incomplete")
                return
            seen.add(next_cursor)
            cursor = next_cursor
        self.ctx.warn("saas.notion: users page limit reached; collection incomplete")

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        for u in records:
            if not self._valid_user_record(u):
                self.ctx.warn("saas.notion: unsupported or malformed user record or provider error; coverage incomplete")
                continue
            if u.get("type") != "bot" and "bot" not in u:
                continue
            self.ctx.examined()
            try:
                f = self._bot_finding(u)
            except (AttributeError, TypeError, ValueError, KeyError, RecursionError, MatchTimeoutError) as exc:
                detail = f": {exc}" if isinstance(exc, MatchTimeoutError) else ""
                self.ctx.warn(f"saas.notion: skipped a malformed integration record ({type(exc).__name__}){detail}")
                continue
            if f:
                yield f

    def _valid_user_record(self, u: Any) -> bool:
        # Error bodies are {"object": "error", "status": ..., "code": ..., "message": ...}
        # and must never pass as an empty inventory.
        return (
            self._record_fields_valid(u, strings=("object", "type", "id", "name", "avatar_url"), mappings=("bot", "person"))
            and u.get("object") in (None, "user")
            and any(isinstance(u.get(key), str) and u[key].strip() for key in ("id", "name"))
        )

    def _bot_finding(self, u: dict[str, Any]) -> Finding | None:
        name = u.get("name") or u.get("id")
        bot = u.get("bot") or {}
        owner_type = get_path(bot, "owner.type")
        owner = get_path(bot, "owner.user.person.email", "owner.user.name")
        f = Finding(
            surface=Surface.SAAS,
            connector=self.name,
            kind=Kind.BOT_APP,
            title=f"Notion integration: {name}",
            resource=f"notion:bot:{u.get('id') or name}",
            resource_type="notion-integration",
            provider="notion",
            account=bot.get("workspace_name"),
            owner=owner,
        )
        assess_app(self.index, f, name=name)
        f.add_evidence(Evidence(signal="notion:bot", description=f"Integration '{name}' owned by {owner_type or 'unknown'}{' (' + str(owner) + ')' if owner else ''}; workspace {bot.get('workspace_name') or '?'}", weight=0.35 if owner_type == "workspace" else 0.25))
        if owner_type == "user":
            f.add_tag("user-owned-integration")
        f.metadata.update({"owner_type": owner_type, "workspace": bot.get("workspace_name"), "avatar": u.get("avatar_url")})
        finalize(f, self.index)
        f.kind = Kind.BOT_APP
        return f
