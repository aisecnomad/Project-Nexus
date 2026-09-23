"""Notion: integrations (bot users) connected to a workspace.

Live: ``GET /v1/users`` with an internal integration token (``read user information``
capability) lists people and bots; every ``type == "bot"`` user is an integration
(internal or public) with access to the pages it was shared with.

Offline export: ``/v1/users`` response or list of user objects.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, ClassVar

from shadowscan.connectors.base import BaseConnector, ConnectorError
from shadowscan.connectors.common import finalize
from shadowscan.connectors.identity.common import assess_app
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.utils.http import HttpClient
from shadowscan.utils.text import get_path


class NotionConnector(BaseConnector):
    name: ClassVar[str] = "saas.notion"
    surface: ClassVar[Surface] = Surface.SAAS
    provider: ClassVar[str | None] = "notion"
    description: ClassVar[str] = "Notion integrations (bot users) connected to the workspace."
    config_keys: ClassVar[dict[str, str]] = {"token": "internal integration secret (env NOTION_TOKEN)", "input": "offline: /v1/users JSON"}

    def collect(self) -> Iterable[dict[str, Any]]:
        token = self.ctx.get("token", env="NOTION_TOKEN")
        if not token:
            raise ConnectorError("saas.notion: token required")
        http = HttpClient("https://api.notion.com", headers={"Authorization": f"Bearer {token}", "Notion-Version": "2022-06-28"})
        cursor: str | None = None
        while True:
            params: dict[str, Any] = {"page_size": 100}
            if cursor:
                params["start_cursor"] = cursor
            data = http.get_json("/v1/users", params=params) or {}
            for u in data.get("results", []):
                yield u
            if not data.get("has_more"):
                break
            cursor = data.get("next_cursor")

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        for u in records:
            if u.get("type") != "bot" and "bot" not in u:
                continue
            self.ctx.examined()
            f = self._bot_finding(u)
            if f:
                yield f

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
