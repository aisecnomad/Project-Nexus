"""GitHub organisation: installed AI GitHub Apps (reviewers, coding agents) and Copilot enablement.

An installation is reported when it matches an AI signature or has an AI-like
name. Other write-capable apps (dependency, deploy and CI bots) are reported
only with ``include_unrecognized_apps``, capped at possible confidence.

Live: ``GET /orgs/{org}/installations`` (org admin), ``GET /orgs/{org}/copilot/billing`` (optional),
``GET /orgs/{org}/personal-access-tokens`` (fine-grained PATs approved for the org, optional).

Offline export: installations JSON (``installations`` array or list).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any, ClassVar

from requests import RequestException

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.connectors.common import cap_confidence, finalize
from shadowscan.connectors.identity.common import assess_app, summarize_scopes
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.utils.http import HttpClient, HttpError

# An installation reported only because it can write (include_unrecognized_apps)
# is a candidate for review, never a confirmed or likely AI agent.
UNRECOGNISED_APP_MAX_CONFIDENCE = 0.3
_SLUG_SEPARATORS = re.compile(r"[-_]+")


class GitHubAppsConnector(BaseConnector):
    name: ClassVar[str] = "saas.github-apps"
    surface: ClassVar[Surface] = Surface.SAAS
    provider: ClassVar[str | None] = "github"
    description: ClassVar[str] = "GitHub Apps installed on an organisation (AI reviewers, coding agents), Copilot seats and approved fine-grained PATs."
    config_keys: ClassVar[dict[str, str]] = {
        "org": "organisation login (env GITHUB_ORG)",
        "token": "org admin token (env GITHUB_TOKEN)",
        "api_url": "default https://api.github.com",
        "input": "offline: installations JSON",
        "include_unrecognized_apps": "also report write-capable apps with no AI signature or AI-like name, capped at possible confidence (default false)",
    }

    def __init__(self, ctx: ConnectorContext):
        super().__init__(ctx)
        self.org = ctx.get("org", env="GITHUB_ORG")
        self.api_url = str(ctx.get("api_url", "https://api.github.com", env="GITHUB_API_URL")).rstrip("/")
        self.include_unrecognized = ctx.get("include_unrecognized_apps", False)
        if not isinstance(self.include_unrecognized, bool):
            raise ConnectorError("saas.github-apps: include_unrecognized_apps must be a boolean")

    def collect(self) -> Iterable[dict[str, Any]]:
        token = self.ctx.get("token", env="GITHUB_TOKEN")
        if not (self.org and token):
            raise ConnectorError("saas.github-apps: org and token required")
        http = HttpClient(self.api_url, headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}, on_warning=lambda msg: self.ctx.warn(msg, incomplete=True))
        try:
            for inst in http.paginate_link(f"/orgs/{self.org}/installations", params={"per_page": 100}, item_key="installations"):
                yield {**inst, "_kind": "installation"}
        except (HttpError, RequestException, ValueError, RuntimeError) as exc:
            self._collection_warning("installation inventory", exc)
        try:
            billing = http.try_get_json(f"/orgs/{self.org}/copilot/billing", ok_statuses={404})
            if billing is not None:
                if isinstance(billing, dict):
                    yield {**billing, "_kind": "copilot_billing"}
                else:
                    self.ctx.warn("saas.github-apps: invalid Copilot billing response; coverage incomplete")
        except (HttpError, RequestException, ValueError, RuntimeError) as exc:
            self._collection_warning("Copilot billing", exc)
        try:
            for pat in http.paginate_link(f"/orgs/{self.org}/personal-access-tokens", params={"per_page": 100}):
                yield {**pat, "_kind": "pat"}
        except (HttpError, RequestException, ValueError, RuntimeError) as exc:
            self._collection_warning("fine-grained PAT inventory", exc)

    def _collection_warning(self, source: str, exc: Exception) -> None:
        # Sources need different grants. Keep findings from available sources,
        # report incomplete coverage, and never echo a provider's response body.
        reason = f"HTTP {exc.status}" if isinstance(exc, HttpError) else type(exc).__name__
        self.ctx.warn(f"saas.github-apps: {source} unavailable ({reason}); coverage incomplete")

    @staticmethod
    def _identifier(value: Any) -> bool:
        return (isinstance(value, str) and bool(value.strip())) or (type(value) is int and value > 0)

    def _valid_provider_record(self, rec: dict[str, Any], kind: Any) -> bool:
        if kind == "installation":
            if not self._record_fields_valid(
                rec,
                strings=("app_slug", "target_type", "html_url", "repository_selection", "created_at", "updated_at", "suspended_at"),
                mappings=("permissions", "account"), arrays=("events",),
            ):
                return False
            perms = rec.get("permissions") or {}
            account = rec.get("account") or {}
            return (
                any(self._identifier(rec.get(key)) for key in ("id", "app_id", "app_slug"))
                and all(rec.get(key) is None or self._identifier(rec[key]) for key in ("id", "app_id", "client_id"))
                and self._record_fields_valid(account, strings=("login",))
                and all(isinstance(k, str) and isinstance(v, str) for k, v in perms.items())
                and all(isinstance(event, str) for event in (rec.get("events") or []))
            )
        if kind == "pat":
            if not self._record_fields_valid(
                rec,
                strings=("token_name", "repository_selection", "access_granted_at", "token_last_used_at", "token_expires_at"),
                mappings=("owner", "permissions"),
            ):
                return False
            return (
                any(self._identifier(rec.get(key)) for key in ("token_id", "token_name"))
                and (rec.get("token_id") is None or self._identifier(rec["token_id"]))
                and self._record_fields_valid(rec.get("owner") or {}, strings=("login",))
                and all(
                    isinstance(group, dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in group.items())
                    for group in (rec.get("permissions") or {}).values()
                )
            )
        if kind == "copilot_billing":
            return self._record_fields_valid(rec, strings=("plan_type",), mappings=("seat_breakdown",)) and isinstance(rec.get("seat_breakdown"), dict)
        return False

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        for rec in records:
            kind = (rec.get("_kind") or ("copilot_billing" if "seat_breakdown" in rec else "pat" if "token_id" in rec else "installation")) if isinstance(rec, dict) else None
            if not self._valid_provider_record(rec, kind):
                self.ctx.warn("saas.github-apps: unsupported or malformed provider record; coverage incomplete")
                continue
            self.ctx.examined()
            if kind == "installation":
                f = self._installation_finding(rec)
                if f:
                    yield f
            elif kind == "copilot_billing":
                yield self._copilot_finding(rec)
            elif kind == "pat":
                f = self._pat_finding(rec)
                if f:
                    yield f

    def _installation_finding(self, inst: dict[str, Any]) -> Finding | None:
        slug = inst.get("app_slug") or str(inst.get("app_id"))
        perms = inst.get("permissions") or {}
        scopes = [f"{k}:{v}" for k, v in perms.items()]
        events = inst.get("events") or []
        f = Finding(
            surface=Surface.SAAS,
            connector=self.name,
            kind=Kind.BOT_APP,
            title=f"GitHub App installed: {slug}",
            resource=f"github:installation:{inst.get('id') or slug}",
            resource_type="github-app-installation",
            provider="github",
            account=self.org or (inst.get("account") or {}).get("login"),
            first_seen=inst.get("created_at"),
            last_seen=inst.get("updated_at"),
        )
        # Slugs join words with hyphens ("amazon-q-developer"); name signatures
        # are written for display names, so the words are matched as well.
        assess_app(self.index, f, name=slug, aliases=[_SLUG_SEPARATORS.sub(" ", slug)], description=str(inst.get("target_type")),
                   urls=[inst.get("html_url")], scopes=scopes, client_id=str(inst.get("client_id") or ""))
        write_perms = [k for k, v in perms.items() if v in {"write", "admin"}]
        # Permissions describe what an app may do, not whether it is an AI
        # agent. Dependency, deploy and CI bots hold the same scopes, so an
        # app needs a recognised AI signature or an AI-like name to be one.
        recognised = bool(f.frameworks) or "ai-name-hint" in f.tags
        if not recognised and not (self.include_unrecognized and write_perms):
            return None
        f.add_evidence(Evidence(signal="github:installation", description=f"App '{slug}' on {inst.get('repository_selection')} repositories; permissions {', '.join(scopes)[:300]}; events {', '.join(events)[:200]}", location=inst.get("html_url"), weight=0.3))
        if inst.get("repository_selection") == "all":
            f.add_tag("all-repositories")
        if write_perms:
            f.add_tag("write-access")
            f.add_capability("saas-actions")
        # Changing workflows or dispatching runs executes code with the
        # repository's CI credentials. Writing files or pull requests alone
        # does not: that remains a SaaS write action.
        if "workflows" in write_perms or "actions" in write_perms:
            f.add_capability("code-exec")
        if inst.get("suspended_at"):
            f.add_tag("suspended")
        f.metadata.update({"app_id": inst.get("app_id"), "app_slug": slug, "repository_selection": inst.get("repository_selection"), "permissions": perms, "write_permissions": write_perms, "events": events[:30], "suspended_at": inst.get("suspended_at")})
        finalize(f, self.index)
        if not recognised:
            f.add_tag("unrecognized-app")
            cap_confidence(f, UNRECOGNISED_APP_MAX_CONFIDENCE)
        f.kind = Kind.BOT_APP
        return f

    def _copilot_finding(self, rec: dict[str, Any]) -> Finding:
        seats = rec.get("seat_breakdown") or {}
        f = Finding(
            surface=Surface.SAAS,
            connector=self.name,
            kind=Kind.AGENT_CONFIG,
            title=f"GitHub Copilot enabled for organisation {self.org or ''}".strip(),
            resource=f"github:{self.org}/copilot",
            resource_type="copilot-billing",
            provider="github",
            account=self.org,
        )
        f.add_framework("coding-agent.github-copilot")
        f.add_capability("code-exec")
        f.add_evidence(Evidence(signal="github:copilot", description=f"Copilot plan {rec.get('plan_type')}, {seats.get('total', 0)} seats ({seats.get('active_this_cycle', 0)} active); seat management {rec.get('seat_management_setting')}; public code suggestions {rec.get('public_code_suggestions')}; IDE chat {rec.get('ide_chat')}; platform chat {rec.get('platform_chat')}; CLI {rec.get('cli')}", weight=0.9, signature="coding-agent.github-copilot"))
        f.metadata.update({k: v for k, v in rec.items() if not k.startswith("_")})
        finalize(f, self.index)
        f.kind = Kind.AGENT_CONFIG
        return f

    def _pat_finding(self, pat: dict[str, Any]) -> Finding | None:
        owner = (pat.get("owner") or {}).get("login")
        perms = pat.get("permissions") or {}
        scopes = [f"{scope}/{k}:{v}" for scope, d in perms.items() if isinstance(d, dict) for k, v in d.items()]
        name = pat.get("token_name") or f"pat-{pat.get('token_id')}"
        f = Finding(
            surface=Surface.SAAS,
            connector=self.name,
            kind=Kind.SERVICE_IDENTITY,
            title=f"Fine-grained PAT approved for org: {name} ({owner})",
            resource=f"github:pat:{pat.get('token_id') or name}",
            resource_type="fine-grained-pat",
            provider="github",
            account=self.org,
            owner=owner,
            first_seen=pat.get("access_granted_at"),
            last_seen=pat.get("token_last_used_at"),
        )
        assess_app(self.index, f, name=name, scopes=[s.split("/", 1)[-1] for s in scopes])
        if not f.frameworks and not any(t.startswith("policy.") for t in f.tags):
            return None
        f.add_evidence(Evidence(signal="github:pat", description=f"Fine-grained PAT '{name}' owned by {owner}; {pat.get('repository_selection')} repositories; expires {pat.get('token_expires_at') or 'never'}", weight=0.25))
        f.metadata.update({"token_id": pat.get("token_id"), "repository_selection": pat.get("repository_selection"), "expires_at": pat.get("token_expires_at"), "permissions": summarize_scopes(scopes)})
        finalize(f, self.index)
        f.kind = Kind.SERVICE_IDENTITY
        return f
