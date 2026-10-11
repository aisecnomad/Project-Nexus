"""Google Agent Registry and Gemini Enterprise catalogs in cloud.gcp: collection, records, reconciliation.

The fixtures and transports are synthetic, modeled on the published discovery documents; nothing
here was validated against a live project.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from shadowscan.config import ConfigValidationError, ConnectorSpec, ScanConfig
from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.base import ConnectorError
from shadowscan.connectors.cloud import gcp_registry
from shadowscan.connectors.cloud.gcp import GcpConnector
from shadowscan.engine import Engine
from shadowscan.models import Finding, Kind, ScanResult, ScanStats
from shadowscan.registries import RECONCILIATION_KEY, RECORD_KEY, parse_registry_record
from shadowscan.utils.http import HttpError

P, N = "acme-ml", "123"
AR_ID = f"projects/{P}/locations/global"
ENGINE = f"projects/{N}/locations/global/collections/default_collection/engines/acme-assist"
GE_ID = f"projects/{P}/locations/global/collections/default_collection/engines/acme-assist"
ASSISTANT = f"{ENGINE}/assistants/default_assistant"
RE_OK = f"projects/{N}/locations/us-central1/reasoningEngines/456"
RE_SHADOW = f"projects/{N}/locations/us-central1/reasoningEngines/789"
AR_BASE = f"https://agentregistry.googleapis.com/v1/projects/{P}"
SERVICES = f"https://serviceusage.googleapis.com/v1/projects/{P}/services"
VERTEX = f"https://us-central1-aiplatform.googleapis.com/v1/projects/{P}/locations/us-central1"
ENGINES = f"https://discoveryengine.googleapis.com/v1/projects/{P}/locations/global/collections/default_collection/engines"
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "cloud"
REGISTRY_FIXTURE = FIXTURES / "gcp_registry_records.jsonl"


def userinfo_url(scheme: str, userinfo: str, rest: str) -> str:
    """A URL with credentials in its userinfo, assembled at runtime (no credential-shaped literal)."""
    return scheme + userinfo + "@" + rest


def context(index: Any, **config: Any) -> ConnectorContext:
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="cloud.gcp", started_at="2026-10-10")
    return ctx


class FakeGoogle:
    """Answer GETs by exact URL (query excluded); unknown URLs return an empty page."""

    def __init__(self, routes: dict[str, Any]) -> None:
        self.routes = routes
        self.gets: list[tuple[str, dict[str, Any]]] = []

    def get_json(self, url: str, params: dict[str, Any] | None = None) -> Any:
        params = dict(params or {})
        self.gets.append((url, params))
        answer = self.routes.get(url, {})
        if isinstance(answer, Exception):
            raise answer
        return answer(params) if callable(answer) else answer

    def post_json(self, url: str, json: dict[str, Any] | None = None) -> Any:
        return {}

    @property
    def urls(self) -> list[str]:
        return [url for url, _ in self.gets]


def enabled(*names: str) -> dict[str, Any]:
    return {"services": [{"config": {"name": name}} for name in names]}


def connector(index: Any, routes: dict[str, Any], **config: Any) -> tuple[GcpConnector, FakeGoogle]:
    scanner = GcpConnector(context(index, projects=[P], locations=["us-central1"], **config))
    fake = FakeGoogle(routes)
    scanner.http = fake  # type: ignore[assignment]
    return scanner, fake


def registry_routes(**overrides: Any) -> dict[str, Any]:
    routes: dict[str, Any] = {
        SERVICES: enabled("aiplatform.googleapis.com", "agentregistry.googleapis.com"),
        f"https://cloudresourcemanager.googleapis.com/v1/projects/{P}": {"projectId": P, "projectNumber": N},
        f"{VERTEX}/reasoningEngines": {"reasoningEngines": [{"name": RE_OK, "displayName": "negotiator"}]},
        f"{AR_BASE}/locations": {"locations": [{"name": AR_ID, "locationId": "global"}]},
        f"{AR_BASE}/locations/global/agents": {
            "agents": [
                {
                    "name": f"projects/{N}/locations/global/agents/negotiator",
                    "displayName": "negotiator",
                    "attributes": {
                        "agentregistry.googleapis.com/system/RuntimeReference": {
                            "uri": f"//aiplatform.googleapis.com/projects/{P}/locations/us-central1/reasoningEngines/456"
                        }
                    },
                }
            ]
        },
    }
    routes.update(overrides)
    return routes


def kinds(records: list[dict[str, Any]], kind: str) -> list[dict[str, Any]]:
    return [record for record in records if record["_kind"] == kind]


def coverage(records: list[dict[str, Any]], catalog: str, collection: str) -> list[dict[str, Any]]:
    return [
        record
        for record in kinds(records, "registry-coverage")
        if (record["catalog"], record["collection"]) == (catalog, collection)
    ]


def by_resource(findings: list[Finding]) -> dict[str, Finding]:
    return {finding.resource: finding for finding in findings}


def scan(index: Any, path: Path | str, **options: Any) -> ScanResult:
    config = ScanConfig(connectors=[ConnectorSpec("cloud.gcp", {"input": str(path)})], **options)
    return Engine(config, index).run()


def write_records(tmp_path: Path, records: list[dict[str, Any]], name: str = "export.jsonl") -> Path:
    path = tmp_path / name
    path.write_text("".join(json.dumps(record) + "\n" for record in records))
    return path


def fixture_records() -> list[dict[str, Any]]:
    return [json.loads(line) for line in REGISTRY_FIXTURE.read_text().splitlines()]


def status(finding: Finding) -> str:
    return finding.metadata[RECONCILIATION_KEY]["status"]


# ------------------------------------------------------------------ configuration


@pytest.mark.parametrize(
    "config,message",
    [
        ({"agent_registry_version": "v1beta"}, "agent_registry_version"),
        ({"agent_registry_version": ["v1"]}, "agent_registry_version"),
        ({"agent_registry": "yes"}, "agent_registry must be a boolean"),
        ({"gemini_enterprise": 1}, "gemini_enterprise must be a boolean"),
        ({"agent_registry_locations": ["../global"]}, "agent_registry_locations"),
        ({"agent_registry_locations": 5}, "agent_registry_locations"),
        ({"discovery_collections": ["default_collection/engines"]}, "discovery_collections"),
    ],
)
def test_invalid_catalog_options_are_refused(index, config, message):
    with pytest.raises(ConnectorError, match=message):
        GcpConnector(context(index, **config))


def test_catalog_options_default_off(index):
    scanner = GcpConnector(context(index))
    assert (scanner.agent_registry, scanner.gemini_enterprise, scanner.agent_registry_version) == (
        False,
        False,
        "v1",
    )
    assert scanner.discovery_collections == ["default_collection"]
    assert scanner.agent_registry_locations is None


# ------------------------------------------------------------------ collection


def test_without_opt_in_no_registry_or_v1alpha_call_is_made(index):
    routes = registry_routes(
        **{
            SERVICES: enabled(
                "aiplatform.googleapis.com", "agentregistry.googleapis.com", "discoveryengine.googleapis.com"
            )
        },
        **{ENGINES: {"engines": [{"name": ENGINE, "appType": "APP_TYPE_INTRANET"}]}},
    )
    scanner, fake = connector(index, routes)
    records = list(scanner._collect_project(P))
    assert not [url for url in fake.urls if "agentregistry" in url or "/v1alpha/" in url]
    assert not [url for url in fake.urls if url.endswith(f"/v1/projects/{P}")]
    assert not kinds(records, "registry-coverage") and not kinds(records, "project-number")
    assert [record["_kind"] for record in records] == [
        "project",
        "reasoning-engine",
        "discovery-engine",
        "iam-policy",
    ]
    # Agent Registry counts as an AI API (in the order Service Usage lists them).
    assert records[0]["ai_services"] == [
        "aiplatform.googleapis.com",
        "agentregistry.googleapis.com",
        "discoveryengine.googleapis.com",
    ]


def test_opt_in_without_the_enabled_api_makes_no_registry_call(index):
    scanner, fake = connector(
        index, registry_routes(**{SERVICES: enabled("aiplatform.googleapis.com")}), agent_registry=True
    )
    records = list(scanner._collect_project(P))
    assert not [url for url in fake.urls if "agentregistry" in url]
    # Vertex coverage and the project number are still recorded for reconciliation.
    assert coverage(records, "vertex-ai", "reasoningEngines")[0]["complete"] is True
    assert kinds(records, "project-number") == [
        {"_kind": "project-number", "_project": P, "project_number": N}
    ]


@pytest.mark.parametrize("version", ["v1", "v1alpha"])
def test_agent_registry_urls_versions_and_paging(index, version):
    base = f"https://agentregistry.googleapis.com/{version}/projects/{P}"

    def agents(params: dict[str, Any]) -> dict[str, Any]:
        if params.get("pageToken") == "next":
            return {"agents": [{"name": f"projects/{N}/locations/global/agents/b"}]}
        return {"agents": [{"name": f"projects/{N}/locations/global/agents/a"}], "nextPageToken": "next"}

    routes = registry_routes(**{f"{base}/locations": registry_routes()[f"{AR_BASE}/locations"]})
    routes[f"{base}/locations/global/agents"] = agents
    scanner, fake = connector(index, routes, agent_registry=True, agent_registry_version=version)
    records = list(scanner._collect_project(P))
    registry_gets = [(url, params) for url, params in fake.gets if "agentregistry" in url]
    collections = ["agents", "mcpServers", "endpoints"] + (
        ["skills", "publishers"] if version == "v1alpha" else []
    )
    expected = [(f"{base}/locations", {})]
    for collection in collections:
        expected.append((f"{base}/locations/global/{collection}", {"pageSize": 100}))
        if collection == "agents":
            expected.append((f"{base}/locations/global/agents", {"pageSize": 100, "pageToken": "next"}))
    assert registry_gets == expected
    agents_listed = kinds(records, "agent-registry-agent")
    assert [record["name"].rsplit("/", 1)[-1] for record in agents_listed] == ["a", "b"]
    assert {record["_api_version"] for record in agents_listed} == {version}
    assert all(record["complete"] for record in kinds(records, "registry-coverage"))
    assert coverage(records, "google-agent-registry", "locations")[0]["locations"] == ["global"]
    assert not scanner.ctx.stats.incomplete


def test_configured_registry_locations_skip_enumeration(index):
    scanner, fake = connector(
        index, registry_routes(), agent_registry=True, agent_registry_locations=["global", "us-central1"]
    )
    records = list(scanner._collect_project(P))
    assert f"{AR_BASE}/locations" not in fake.urls
    assert f"{AR_BASE}/locations/us-central1/endpoints" in fake.urls
    assert not coverage(records, "google-agent-registry", "locations")
    findings = by_resource(list(scanner.analyze(records)))
    record = findings[f"projects/{N}/locations/global/agents/negotiator"].metadata[RECORD_KEY]
    # Without an enumerated location list a location may have been missed: never complete.
    assert record["listing_complete"] is False


@pytest.mark.parametrize(
    "failure",
    ["denied", "truncated", "repeated-token", "unreachable", "malformed-page", "invalid-response"],
)
def test_failed_registry_listing_keeps_items_and_records_incomplete_coverage(index, failure):
    first = {"name": f"projects/{N}/locations/global/agents/first"}

    def agents(params: dict[str, Any]) -> Any:
        if not params.get("pageToken"):
            page: dict[str, Any] = {"agents": [first], "nextPageToken": "t1"}
            if failure == "unreachable":
                page["unreachable"] = ["us-east1"]
            return page
        if failure == "denied":
            raise HttpError(403, "https://agentregistry.googleapis.com", "denied body with secret text")
        if failure == "repeated-token":
            return {"agents": [], "nextPageToken": "t1"}
        if failure == "malformed-page":
            return {"agents": {"name": "not a list"}}
        if failure == "invalid-response":
            return ["not", "a", "page"]
        return {"agents": []}

    routes = registry_routes(**{f"{AR_BASE}/locations/global/agents": agents})
    config: dict[str, Any] = {"agent_registry": True}
    if failure == "truncated":
        config["max_pages"] = 1
    scanner, _ = connector(index, routes, **config)
    records = list(scanner._collect_project(P))
    assert [record["name"] for record in kinds(records, "agent-registry-agent")] == [first["name"]]
    (agents_coverage,) = coverage(records, "google-agent-registry", "agents")
    assert agents_coverage["complete"] is False
    assert coverage(records, "google-agent-registry", "mcpServers")[0]["complete"] is True
    assert scanner.ctx.stats.incomplete
    assert "secret text" not in json.dumps(scanner.ctx.stats.warnings)
    findings = by_resource(list(scanner.analyze(records)))
    assert findings[first["name"]].metadata[RECORD_KEY]["listing_complete"] is False


def test_failed_location_listing_is_never_complete(index):
    routes = registry_routes(
        **{
            f"{AR_BASE}/locations": {
                "locations": [{"locationId": "global"}, {"locationId": "../escape"}, {"locationId": 7}]
            }
        }
    )
    scanner, fake = connector(index, routes, agent_registry=True)
    records = list(scanner._collect_project(P))
    assert not [url for url in fake.urls if "escape" in url or "/7/" in url]
    (locations,) = coverage(records, "google-agent-registry", "locations")
    assert locations["complete"] is False and locations["locations"] == ["global"]
    assert sum("invalid Agent Registry location" in warning for warning in scanner.ctx.stats.warnings) == 2


def ge_routes(engines: list[dict[str, Any]], **overrides: Any) -> dict[str, Any]:
    routes: dict[str, Any] = {
        SERVICES: enabled("discoveryengine.googleapis.com"),
        f"https://cloudresourcemanager.googleapis.com/v1/projects/{P}": {"projectId": P, "projectNumber": N},
        ENGINES: {"engines": engines},
        f"https://discoveryengine.googleapis.com/v1alpha/{ENGINE}/assistants": {
            "assistants": [{"name": ASSISTANT}]
        },
        f"https://discoveryengine.googleapis.com/v1alpha/{ASSISTANT}/agents": {
            "agents": [{"name": f"{ASSISTANT}/agents/a1", "displayName": "a1", "state": "ENABLED"}]
        },
    }
    routes.update(overrides)
    return routes


def test_gemini_enterprise_urls_and_caller_scoped_coverage(index):
    engines = [
        {"name": ENGINE, "appType": "APP_TYPE_INTRANET", "solutionType": "SOLUTION_TYPE_SEARCH"},
        # Plain search engines have no assistants: asking them would only fail.
        {"name": f"projects/{N}/locations/global/collections/default_collection/engines/site-search"},
    ]
    scanner, fake = connector(index, ge_routes(engines), gemini_enterprise=True)
    records = list(scanner._collect_project(P))
    v1alpha = [(url, params) for url, params in fake.gets if "/v1alpha/" in url]
    assert v1alpha == [
        (f"https://discoveryengine.googleapis.com/v1alpha/{ENGINE}/assistants", {"pageSize": 1000}),
        (f"https://discoveryengine.googleapis.com/v1alpha/{ASSISTANT}/agents", {"pageSize": 1000}),
    ]
    (agent,) = kinds(records, "gemini-enterprise-agent")
    assert (agent["_engine"], agent["_assistant"], agent["_project"], agent["_location"]) == (
        ENGINE,
        ASSISTANT,
        P,
        "global",
    )
    (agents_coverage,) = coverage(records, "gemini-enterprise", "agents")
    assert agents_coverage["listing_scope"] == "caller" and agents_coverage["parent"] == ASSISTANT
    # Assistant system instructions are never collected.
    assert "systemInstruction" not in json.dumps(records)
    findings = by_resource(list(scanner.analyze(records)))
    record = findings[agent["name"]].metadata[RECORD_KEY]
    assert (record["listing_scope"], record["listing_complete"], record["registry_id"]) == (
        "caller",
        False,
        GE_ID,
    )


@pytest.mark.parametrize(
    "engine",
    [
        f"projects/{N}/locations/global/collections/default_collection/engines/../../x",
        "projects/other-project/locations/global/collections/default_collection/engines/e",
        f"projects/{N}/locations/eu/collections/default_collection/engines/e",
        f"projects/{N}/locations/global/collections/other_collection/engines/e",
        "https://evil.example/engines/e",
        None,
    ],
)
def test_unsafe_engine_names_are_never_requested(index, engine):
    scanner, fake = connector(
        index, ge_routes([{"name": engine, "appType": "APP_TYPE_INTRANET"}]), gemini_enterprise=True
    )
    list(scanner._collect_project(P))
    assert not [url for url in fake.urls if "/v1alpha/" in url]
    assert any("invalid Discovery Engine engine name" in warning for warning in scanner.ctx.stats.warnings)
    assert scanner.ctx.stats.incomplete


@pytest.mark.parametrize(
    "assistant",
    [f"{ENGINE}/assistants/../../x", f"{ENGINE}-other/assistants/a", f"{ENGINE}/assistants/a/agents", 5],
)
def test_unsafe_assistant_names_are_never_requested(index, assistant):
    routes = ge_routes(
        [{"name": ENGINE, "appType": "APP_TYPE_INTRANET"}],
        **{
            f"https://discoveryengine.googleapis.com/v1alpha/{ENGINE}/assistants": {
                "assistants": [{"name": assistant}]
            }
        },
    )
    scanner, fake = connector(index, routes, gemini_enterprise=True)
    records = list(scanner._collect_project(P))
    assert not [url for url in fake.urls if url.endswith("/agents") and "/v1alpha/" in url]
    assert coverage(records, "gemini-enterprise", "assistants")[0]["complete"] is False
    assert scanner.ctx.stats.incomplete


def test_engine_names_with_the_project_id_need_no_number(index):
    engine = f"projects/{P}/locations/global/collections/default_collection/engines/e"
    routes = ge_routes(
        [{"name": engine, "solutionType": "SOLUTION_TYPE_CHAT"}],
        **{f"https://cloudresourcemanager.googleapis.com/v1/projects/{P}": HttpError(403, "u", "")},
    )
    scanner, fake = connector(index, routes, gemini_enterprise=True)
    records = list(scanner._collect_project(P))
    assert f"https://discoveryengine.googleapis.com/v1alpha/{engine}/assistants" in fake.urls
    assert not kinds(records, "project-number")
    # The project lookup failed, and that is reported.
    assert scanner.ctx.stats.incomplete


@pytest.mark.parametrize(
    "response",
    [
        {"projectId": "other", "projectNumber": N},
        {"projectId": P, "projectNumber": "12a"},
        {"projectId": P},
        [],
    ],
)
def test_invalid_project_lookup_leaves_the_number_unknown(index, response):
    routes = registry_routes(**{f"https://cloudresourcemanager.googleapis.com/v1/projects/{P}": response})
    scanner, _ = connector(index, routes, agent_registry=True)
    records = list(scanner._collect_project(P))
    assert not kinds(records, "project-number")
    assert any("project number unknown" in warning for warning in scanner.ctx.stats.warnings)


def test_discovered_projects_carry_their_numbers_without_a_lookup(index, monkeypatch):
    scanner = GcpConnector(context(index, locations=["us-central1"], agent_registry=True))
    fake = FakeGoogle(
        {
            "https://cloudresourcemanager.googleapis.com/v1/projects": {
                "projects": [{"projectId": P, "projectNumber": N}, {"projectId": "two", "projectNumber": 9}]
            }
        }
    )
    monkeypatch.setattr(scanner, "_auth", lambda: setattr(scanner, "http", fake))
    records = list(scanner.collect())
    assert kinds(records, "project-number") == [
        {"_kind": "project-number", "_project": P, "project_number": N}
    ]
    # A non-string number is not trusted; that project's number is looked up instead.
    assert [
        url for url in fake.urls if url.startswith("https://cloudresourcemanager.googleapis.com/v1/projects/")
    ] == ["https://cloudresourcemanager.googleapis.com/v1/projects/two"]


def test_discovery_collections_list_engines_in_each_collection(index):
    scanner, fake = connector(
        index,
        {SERVICES: enabled("discoveryengine.googleapis.com")},
        discovery_collections=["default_collection", "partner_apps"],
    )
    list(scanner._collect_project(P))
    listed = [url for url in fake.urls if url.endswith("/engines")]
    assert len(listed) == 6 and sum("/collections/partner_apps/" in url for url in listed) == 3


# ------------------------------------------------------------------ normalization


def test_collected_items_never_keep_cards_url_secrets_icons_or_authorization_values(index):
    secret = "opaque-" + "synthetic-credential-" + "q" * 12
    card = {
        "name": "Concierge",
        "url": userinfo_url(
            "https://", f"agent:{secret}", f"Concierge.Example:443/a2a?api_key={secret}#frag"
        ),
        "securitySchemes": {
            "partnerKey": {
                "apiKeySecurityScheme": {"name": "X-Key", "location": "header", "description": secret}
            }
        },
        "description": secret,
    }
    routes = ge_routes(
        [{"name": ENGINE, "appType": "APP_TYPE_INTRANET"}],
        **{
            f"https://discoveryengine.googleapis.com/v1alpha/{ASSISTANT}/agents": {
                "agents": [
                    {
                        "name": f"{ASSISTANT}/agents/a1",
                        "displayName": "Concierge",
                        "state": "ENABLED",
                        "a2aAgentDefinition": {"jsonAgentCard": json.dumps(card)},
                        "authorizationConfig": {
                            "agentAuthorization": secret,
                            "toolAuthorizations": [secret, secret],
                        },
                        "icon": {"content": secret, "uri": f"https://icons.example/i.png?sig={secret}"},
                        "starterPrompts": [{"text": secret}],
                    }
                ]
            }
        },
    )
    routes[SERVICES] = enabled("discoveryengine.googleapis.com", "agentregistry.googleapis.com")
    routes[f"{AR_BASE}/locations"] = {"locations": [{"locationId": "global"}]}
    routes[f"{AR_BASE}/locations/global/agents"] = {
        "agents": [
            {
                "name": f"projects/{N}/locations/global/agents/concierge",
                "protocols": [{"type": "A2A_AGENT", "interfaces": [{"url": card["url"]}]}],
                "card": {"type": "A2A_AGENT_CARD", "content": card},
                "attributes": {"custom/Secret": {"value": secret}},
            }
        ]
    }
    routes[f"{AR_BASE}/locations/global/mcpServers"] = {
        "mcpServers": [
            {"name": f"projects/{N}/locations/global/mcpServers/m", "interfaces": [{"url": card["url"]}]}
        ]
    }
    scanner, _ = connector(index, routes, agent_registry=True, gemini_enterprise=True)
    records = list(scanner._collect_project(P))
    findings = list(scanner.analyze(records))
    assert secret not in json.dumps(records)
    assert secret not in json.dumps([finding.to_dict() for finding in findings])
    assert secret not in json.dumps(scanner.ctx.stats.warnings)
    (ge,) = kinds(records, "gemini-enterprise-agent")
    assert ge["agent_card"]["url"] == "https://concierge.example/a2a"
    assert ge["agent_card"]["security_schemes"] == ["partnerKey"]
    assert ge["agent_card"]["security_scheme_types"] == ["apiKey"]
    assert ge["auth_config"] == {"agent_auth_required": True, "tool_auth_grants": 2}
    assert "icon" not in ge and "starterPrompts" not in ge
    (ar,) = kinds(records, "agent-registry-agent")
    assert ar["protocols"][0]["urls"] == ["https://concierge.example/a2a"] and "attributes" not in ar
    by_kind = {finding.resource_type: finding for finding in findings}
    assert by_kind["gemini-enterprise-agent"].metadata["catalog_presence"]["agent_registry"] == "present"
    assert "delegated-identity" in by_kind["gemini-enterprise-agent"].capabilities


@pytest.mark.parametrize(
    "value,expected",
    [
        ("HTTPS://Agent.Example:443/a2a?x=1#f", "https://agent.example/a2a"),
        ("http://agent.example:80", "http://agent.example"),
        (userinfo_url("https://", "user:pw", "agent.example:8443/p"), "https://agent.example:8443/p"),
        ("https://[2001:db8::1]:443/a", "https://[2001:db8::1]/a"),
        ("wss://agent.example/ws", "wss://agent.example/ws"),
        ("ftp://agent.example/a", None),
        ("https://agent.example:99999/", None),
        ("agent.example/a2a", None),
        ("", None),
        (7, None),
        ("https://" + "a" * 3000, None),
    ],
)
def test_normalize_url(value, expected):
    assert gcp_registry.normalize_url(value) == expected


def test_card_summaries_record_scheme_names_and_types_only():
    summary = gcp_registry.summarize_card(
        {
            "name": "x",
            "securitySchemes": {
                "legacy": {"type": "http", "scheme": "bearer"},
                "modern": {"oauth2SecurityScheme": {"flows": {}}},
                "odd": "nonsense",
            },
            "security": [{"legacy": []}],
            "signatures": [{"protected": "p", "signature": "s"}],
            "capabilities": {"streaming": "yes", "pushNotifications": True, "extensions": [{}, {}]},
            "additionalInterfaces": [{"url": "https://b.example/x?y"}, {"url": 3}],
            "skills": [{"id": "s1"}, {"name": "s2"}, "bad"],
        }
    )
    assert summary is not None
    assert summary["security_schemes"] == ["legacy", "modern", "odd"]
    assert summary["security_scheme_types"] == ["http", "oauth2", "unknown"]
    assert (summary["security_requirements"], summary["signatures"]) == (1, 1)
    assert summary["capabilities"] == {"streaming": None, "push_notifications": True, "extensions": 2}
    assert summary["additional_urls"] == ["https://b.example/x"]
    assert summary["skills"] == ["s1", "s2"]
    legacy = gcp_registry.summarize_card({"authentication": {"schemes": ["Bearer"]}})
    assert legacy is not None and legacy["security_schemes"] == ["Bearer"]
    assert gcp_registry.summarize_card("not a card") is None


@pytest.mark.parametrize(
    "value,status",
    [
        (None, None),
        (7, "invalid"),
        ("{not json", "invalid"),
        ('{"a": 1, "a": 2}', "invalid"),
        ("[1, 2]", "invalid"),
        pytest.param("[" * 50_000, "invalid", id="deeply-nested"),
        (json.dumps({"name": "x" * (gcp_registry.MAX_CARD_BYTES + 1)}), "too-large"),
        (json.dumps({"name": "ok"}), "parsed"),
    ],
)
def test_json_agent_cards_are_bounded_and_strict(value, status):
    summary, result = gcp_registry.parse_json_card(value)
    assert result == status and (summary is not None) == (status == "parsed")


def test_unreadable_gemini_enterprise_card_is_incomplete(index):
    record = {
        "_kind": "gemini-enterprise-agent",
        "_project": P,
        "_location": "global",
        "_engine": ENGINE,
        "_assistant": ASSISTANT,
        "name": f"{ASSISTANT}/agents/a",
        "definition": "a2a",
        "agent_card_status": "invalid",
    }
    scanner = GcpConnector(context(index))
    (finding,) = scanner.analyze([record])
    assert finding.metadata["agent_card_status"] == "invalid" and "no-auth-declared" not in finding.tags
    assert scanner.ctx.stats.incomplete
    assert any("agent card not readable (invalid)" in warning for warning in scanner.ctx.stats.warnings)


# ------------------------------------------------------------------ statuses


@pytest.mark.parametrize(
    "state,reasons,expected",
    [
        ("ENABLED", [], "approved"),
        ("PRIVATE", ["rejection"], "rejected"),
        ("PRIVATE", [], "draft"),
        ("CONFIGURED", [], "draft"),
        ("CREATING", [], "draft"),
        ("DEPLOYING", [], "draft"),
        ("DISABLED", [], "blocked"),
        ("SUSPENDED", ["suspension"], "blocked"),
        ("DEPLOYMENT_FAILED", ["deploymentFailure"], "unknown"),
        ("CREATION_FAILED", [], "unknown"),
        ("SOMETHING_NEW", [], "unknown"),
        (None, [], "unknown"),
    ],
)
def test_gemini_enterprise_states_map_to_record_statuses(state, reasons, expected):
    assert gcp_registry.ge_status(state, reasons) == expected


@pytest.mark.parametrize(
    "state,expected",
    [
        ("STATE_ACTIVE", "registered"),
        ("STATE_DRAFT", "draft"),
        ("STATE_CREATING", "draft"),
        ("STATE_DISABLED", "blocked"),
        ("STATE_DEPRECATED", "deprecated"),
        ("STATE_DECOMMISSIONED", "deprecated"),
        ("STATE_DELETING", "deprecated"),
        ("STATE_UNSPECIFIED", "unknown"),
        (3, "unknown"),
    ],
)
def test_skill_states_map_to_record_statuses(state, expected):
    assert gcp_registry.skill_status(state) == expected


# ------------------------------------------------------------------ reconciliation


def test_fixture_reconciles_registered_observed_and_shadow_agents(index):
    result = scan(index, REGISTRY_FIXTURE)
    assert result.complete and not [stats for stats in result.stats if stats.warnings]
    findings = by_resource(result.findings)
    engine, shadow = findings[RE_OK], findings[RE_SHADOW]
    # The registry names the engine by project id, Vertex by project number: one object.
    assert status(engine) == "registered-and-observed"
    assert {item["registry"] for item in engine.metadata[RECONCILIATION_KEY]["registries"]} == {
        "google-agent-registry",
        "gemini-enterprise",
    }
    assert status(shadow) == "observed-not-registered"
    assert shadow.metadata[RECONCILIATION_KEY]["registries"] == [
        {"registry": "google-agent-registry", "registry_id": AR_ID}
    ]
    assert shadow.metadata["effective_identity"].startswith("agents.global.org-4242.system.id.goog/")
    assert "effective_identity" in engine.metadata
    negotiator = findings[f"projects/{N}/locations/global/agents/negotiator"]
    record = negotiator.metadata[RECORD_KEY]
    assert parse_registry_record(record) is not None
    assert (record["registry_id"], record["status"], record["approval_mode"], record["listing_complete"]) == (
        AR_ID,
        "registered",
        "none",
        True,
    )
    assert record["bindings"] == [
        {"resource": RE_OK, "provider": "gcp", "account": P, "region": "us-central1", "coverage": "in-scope"}
    ]
    assert status(negotiator) == "registered-and-observed"
    assert negotiator.metadata["catalog_presence"] == {
        "agent_registry": "present",
        "gemini_enterprise": "present",
    }
    assert negotiator.metadata["evidence_class"] == "registry-record" and negotiator.confidence == 0.5
    retired = findings[f"projects/{N}/locations/global/agents/retired-bot"]
    assert status(retired) == "registered-not-observed"
    assert retired.metadata["catalog_presence"]["gemini_enterprise"] == "unknown"
    # The runtime identity matches another engine: a hint, never a binding.
    assert retired.metadata["registry_join_hints"] == [{"key": "runtime-identity", "resource": RE_SHADOW}]
    for name in ("mcpServers/crm-tools", "endpoints/gke-gateway", "skills/acme-contract-review"):
        finding = findings[f"projects/{N}/locations/global/{name}"]
        assert finding.metadata[RECONCILIATION_KEY]["reason"] == "no-usable-binding"
    skill = findings[f"projects/{N}/locations/global/skills/acme-contract-review"]
    assert skill.kind == Kind.AGENT_CONFIG
    assert skill.metadata[RECORD_KEY]["publisher"] == "Acme platform team"
    assert skill.metadata["publisher_tier"] == "PRIVATE"
    assert findings[f"projects/{N}/locations/global/mcpServers/crm-tools"].kind == Kind.MCP_SERVER


def test_fixture_gemini_enterprise_agents(index):
    findings = by_resource(scan(index, REGISTRY_FIXTURE).findings)
    agents = {
        finding.resource.rsplit("/", 1)[-1]: finding
        for finding in findings.values()
        if finding.resource_type == "gemini-enterprise-agent"
    }
    records = {name: finding.metadata[RECORD_KEY] for name, finding in agents.items()}
    assert {name: record["status"] for name, record in records.items()} == {
        "negotiator": "approved",
        "helpdesk": "draft",
        "travel": "approved",
        "forecaster": "blocked",
    }
    assert {record["registry_id"] for record in records.values()} == {GE_ID}
    assert all(
        (record["listing_scope"], record["listing_complete"], record["approval_mode"])
        == ("caller", False, "manual")
        for record in records.values()
    )
    assert status(agents["negotiator"]) == "registered-and-observed"
    # Only the draft helpdesk record binds this Dialogflow agent, and a draft registers nothing:
    # the complete Agent Registry listing of its project does not hold it.
    assert status(agents["helpdesk"]) == "not-comparable"
    assert status(findings[f"projects/{P}/locations/global/agents/abc"]) == "observed-not-registered"
    forecaster = agents["forecaster"]
    assert forecaster.metadata[RECONCILIATION_KEY] == {
        "status": "not-comparable",
        "observed": [],
        "reason": "record-status",
    }
    assert records["forecaster"]["bindings"][0]["coverage"] == "out-of-scope"
    # The associated registry was listed completely and does not hold these agents.
    assert agents["travel"].metadata["catalog_presence"] == {
        "agent_registry": "absent",
        "gemini_enterprise": "present",
    }
    assert "no-auth-declared" in agents["travel"].tags
    assert records["travel"]["descriptor_type"] == "a2a"
    assert agents["negotiator"].metadata["catalog_presence"]["agent_registry"] == "present"
    assert "framework.google-adk" in agents["negotiator"].frameworks
    engine = findings[ENGINE]
    assert engine.metadata["app_type"] == "APP_TYPE_INTRANET"
    assert engine.metadata["associated_agent_registry"] == f"projects/{N}/locations/global"


def test_gemini_enterprise_app_engines_are_never_observed_not_registered(index, tmp_path):
    """No record binds an engine, so a search-type app engine stays outside reconciliation."""
    result = scan(index, REGISTRY_FIXTURE)
    findings = by_resource(result.findings)
    # The registry listing of the engine's project is complete: unbound agents there are absent.
    assert status(findings[RE_SHADOW]) == "observed-not-registered"
    engine = findings[ENGINE]
    assert engine.kind == Kind.CLOUD_RESOURCE
    # So the control rule for observed-not-registered agents never applies to it.
    assert RECONCILIATION_KEY not in engine.metadata
    records = fixture_records()
    for record in records:
        if record["_kind"] == "discovery-engine":
            record.pop("solutionType")
    engine = by_resource(scan(index, write_records(tmp_path, records)).findings)[ENGINE]
    assert engine.kind == Kind.CLOUD_RESOURCE and RECONCILIATION_KEY not in engine.metadata


def test_gemini_enterprise_alone_never_claims_absence(index, tmp_path):
    records = [
        record
        for record in fixture_records()
        if not (
            record["_kind"].startswith("agent-registry")
            or (record["_kind"] == "registry-coverage" and record["catalog"] == "google-agent-registry")
        )
    ]
    findings = by_resource(scan(index, write_records(tmp_path, records)).findings)
    # Caller-scoped listings are never complete: nothing is observed-not-registered.
    assert RECONCILIATION_KEY not in findings[RE_SHADOW].metadata
    assert RECONCILIATION_KEY not in findings[ENGINE].metadata
    for finding in findings.values():
        if finding.resource_type == "gemini-enterprise-agent":
            assert finding.metadata["catalog_presence"]["agent_registry"] == "unknown"
            assert finding.metadata[RECORD_KEY]["listing_complete"] is False


def test_unknown_project_number_is_not_comparable(index, tmp_path):
    records = [record for record in fixture_records() if record["_kind"] != "project-number"]
    findings = by_resource(scan(index, write_records(tmp_path, records)).findings)
    negotiator = findings[f"projects/{N}/locations/global/agents/negotiator"].metadata[RECORD_KEY]
    # The registry's own name carries the number: its identity stays literal and incomplete.
    assert negotiator["registry_id"] == f"projects/{N}/locations/global"
    assert negotiator["listing_complete"] is False
    # The observed engine was listed under acme-ml, so the id-form reference still matches it.
    assert status(findings[RE_OK]) == "registered-and-observed"
    assert RECONCILIATION_KEY not in findings[RE_SHADOW].metadata
    forecaster = next(f for r, f in findings.items() if r.endswith("/agents/forecaster"))
    assert forecaster.metadata[RECORD_KEY]["bindings"][0]["coverage"] == "unknown"
    travel = next(f for r, f in findings.items() if r.endswith("/agents/travel"))
    assert travel.metadata["catalog_presence"]["agent_registry"] == "unknown"


def test_incomplete_registry_coverage_blocks_absence_claims(index, tmp_path):
    records = fixture_records()
    for record in records:
        if record["_kind"] == "registry-coverage" and record["collection"] == "endpoints":
            record["complete"] = False
    findings = by_resource(scan(index, write_records(tmp_path, records)).findings)
    assert RECONCILIATION_KEY not in findings[RE_SHADOW].metadata
    assert all(
        finding.metadata[RECORD_KEY]["listing_complete"] is False
        for finding in findings.values()
        if finding.metadata.get(RECORD_KEY, {}).get("registry") == "google-agent-registry"
    )
    travel = next(f for r, f in findings.items() if r.endswith("/agents/travel"))
    assert travel.metadata["catalog_presence"]["agent_registry"] == "unknown"


def test_incomplete_vertex_listing_makes_bindings_unknown(index, tmp_path):
    records = fixture_records()
    for record in records:
        if record["_kind"] == "registry-coverage" and record["catalog"] == "vertex-ai":
            record["complete"] = False
    findings = by_resource(scan(index, write_records(tmp_path, records)).findings)
    retired = findings[f"projects/{N}/locations/global/agents/retired-bot"]
    assert retired.metadata[RECORD_KEY]["bindings"][0]["coverage"] == "unknown"
    assert status(retired) == "not-comparable"


@pytest.mark.parametrize(
    "bad",
    [
        {"_kind": "registry-coverage", "_project": P, "_location": "global", "catalog": "vertex-ai"},
        {
            "_kind": "registry-coverage",
            "_project": P,
            "_location": "global",
            "catalog": "nope",
            "collection": "x",
        },
        {"_kind": "project-number", "_project": P, "project_number": 123},
        {"_kind": "project-number", "_project": P, "project_number": "999"},
        {"_kind": "agent-registry-agent", "_project": P, "_location": "global", "name": "agents/x"},
        {"_kind": "agent-registry-publisher", "_project": P, "_location": "global", "name": 5},
        {"_kind": "agent-registry-publisher", "name": "p", "publisherTier": ["FIRST_PARTY"]},
        {"_kind": "future-kind"},
    ],
)
def test_unreadable_records_taint_every_completeness_claim(index, tmp_path, bad):
    findings_result = scan(index, write_records(tmp_path, [*fixture_records(), bad]))
    assert not findings_result.complete
    findings = by_resource(findings_result.findings)
    assert RECONCILIATION_KEY not in findings[RE_SHADOW].metadata
    retired = findings[f"projects/{N}/locations/global/agents/retired-bot"]
    assert retired.metadata[RECORD_KEY]["listing_complete"] is False
    assert status(retired) == "not-comparable"
    travel = next(f for r, f in findings.items() if r.endswith("/agents/travel"))
    assert travel.metadata["catalog_presence"]["agent_registry"] == "unknown"


def _replace_line(lines: list[str], resource: str, line: str) -> list[str]:
    return [line if json.loads(item).get("name") == resource else item for item in lines]


@pytest.mark.parametrize(
    "replacement",
    [
        # An export line the loader cannot parse, and a provider error record it drops.
        lambda line: line[:40],
        lambda line: json.dumps({**json.loads(line), "error": {"code": 403, "status": "PERMISSION_DENIED"}}),
    ],
    ids=["invalid-json", "error-record"],
)
def test_records_the_offline_loader_drops_taint_every_completeness_claim(index, tmp_path, replacement):
    lines = REGISTRY_FIXTURE.read_text().splitlines()
    original = next(line for line in lines if json.loads(line).get("name") == RE_OK)
    path = tmp_path / "export.jsonl"
    path.write_text("\n".join(_replace_line(lines, RE_OK, replacement(original))) + "\n")
    result = scan(index, path)
    assert not result.complete
    findings = by_resource(result.findings)
    assert RE_OK not in findings
    negotiator = findings[f"projects/{N}/locations/global/agents/negotiator"]
    record = negotiator.metadata[RECORD_KEY]
    assert record["listing_complete"] is False
    assert [binding["coverage"] for binding in record["bindings"]] == ["unknown"]
    statuses = {status(finding) for finding in findings.values() if RECONCILIATION_KEY in finding.metadata}
    # No claim rests on completeness. (The only exact match left binds a draft, which registers
    # nothing.)
    assert statuses == {"not-comparable"}
    assert all(
        finding.metadata["catalog_presence"]["agent_registry"] != "absent"
        for finding in findings.values()
        if "catalog_presence" in finding.metadata
    )


VICTIM_RE = "projects/999/locations/us-central1/reasoningEngines/7"
VICTIM_ENGINE = "projects/999/locations/global/collections/default_collection/engines/acme-assist"


def _foreign_record(kind: str, **changes: Any) -> dict[str, Any]:
    return {**next(record for record in fixture_records() if record["_kind"] == kind), **changes}


@pytest.mark.parametrize(
    "foreign",
    [
        # Listed in acme-ml, named with another scanned project's number.
        _foreign_record(
            "agent-registry-agent",
            name="projects/999/locations/global/agents/x",
            runtime_reference=f"//aiplatform.googleapis.com/{VICTIM_RE}",
        ),
        # Listed in acme-ml, whose number this scan knows, named with an unknown number.
        _foreign_record("agent-registry-agent", name="projects/555/locations/global/agents/y"),
        _foreign_record(
            "gemini-enterprise-agent",
            name=f"{VICTIM_ENGINE}/assistants/default_assistant/agents/x",
            _engine=VICTIM_ENGINE,
            _assistant=f"{VICTIM_ENGINE}/assistants/default_assistant",
            reasoning_engine=VICTIM_RE,
        ),
    ],
    ids=["agent-registry", "agent-registry-unknown-number", "gemini-enterprise"],
)
def test_registry_names_of_another_project_are_rejected(index, tmp_path, foreign):
    victim = [
        {"_kind": "project-number", "_project": "victim", "project_number": "999"},
        {"_kind": "reasoning-engine", "_project": "victim", "_location": "us-central1", "name": VICTIM_RE},
    ]
    trusted = [
        {
            "registry": "google-agent-registry",
            "id": "projects/victim/locations/global",
            "allow_registered_only": True,
            "allow_offline_records": True,
        },
        {
            "registry": "gemini-enterprise",
            "id": VICTIM_ENGINE.replace("999", "victim", 1),
            "allow_offline_records": True,
        },
    ]
    path = write_records(tmp_path, [*fixture_records(), *victim, foreign])
    result = scan(index, path, trusted_registries=trusted)
    assert not result.complete
    warnings = next(stats.warnings for stats in result.stats if stats.connector == "cloud.gcp")
    assert any("name a project other than the one they were listed in" in warning for warning in warnings)
    findings = by_resource(result.findings)
    # The record is dropped: it neither claims the other project's registry nor approves its engine.
    assert foreign["name"] not in findings
    assert findings[VICTIM_RE].shadow is True
    assert all(
        "victim" not in finding.metadata[RECORD_KEY]["registry_id"]
        for finding in findings.values()
        if RECORD_KEY in finding.metadata
    )
    # Like any unreadable record, it makes every registry claim of the scan not comparable.
    assert RECONCILIATION_KEY not in findings[RE_SHADOW].metadata
    assert status(findings[f"projects/{N}/locations/global/agents/retired-bot"]) == "not-comparable"


VICTIM_RE_2 = "projects/999/locations/us-central1/reasoningEngines/8"


def _victim_project(**coverage: Any) -> list[dict[str, Any]]:
    """Another scanned project (payments-prod, number 999) with two observed reasoning engines."""
    return [
        {"_kind": "project", "project": "payments-prod", "ai_services": ["aiplatform.googleapis.com"]},
        {"_kind": "project-number", "_project": "payments-prod", "project_number": "999"},
        *(
            {
                "_kind": "reasoning-engine",
                "_project": "payments-prod",
                "_location": "us-central1",
                "name": name,
            }
            for name in (VICTIM_RE, VICTIM_RE_2)
        ),
        {
            "_kind": "registry-coverage",
            "_project": "payments-prod",
            "_location": "us-central1",
            "catalog": "vertex-ai",
            "collection": "reasoningEngines",
            "api_version": "v1",
            "complete": True,
            "listing_scope": "project",
        },
        *([{**coverage, "_kind": "registry-coverage", "_project": "payments-prod"}] if coverage else []),
    ]


@pytest.mark.parametrize("numbers_known", [True, False], ids=["numbers-known", "numbers-unknown"])
def test_a_trusted_gemini_enterprise_app_never_approves_another_projects_engine(
    index, tmp_path, numbers_known
):
    agent = _foreign_record(
        "gemini-enterprise-agent",
        name=f"{ASSISTANT}/agents/wired",
        state="ENABLED",
        reasoning_engine=VICTIM_RE,
    )
    records = [*fixture_records(), *_victim_project(), agent]
    if not numbers_known:
        # Neither number is known: the engine belongs to the project whose listing returned it.
        records = [record for record in records if record["_kind"] != "project-number"]
    registry_id = GE_ID if numbers_known else ENGINE
    result = scan(
        index,
        write_records(tmp_path, records),
        # The export is replayed offline, so the entry opts in to offline records: the
        # cross-project rule, not the offline default, must keep the victim unapproved.
        trusted_registries=[
            {"registry": "gemini-enterprise", "id": registry_id, "allow_offline_records": True}
        ],
    )
    # A reference to another project's engine is no coverage gap.
    assert result.complete
    findings = by_resource(result.findings)
    victim = findings[VICTIM_RE]
    assert victim.shadow is True and victim.registry_match is None
    wired = findings[agent["name"]]
    assert wired.metadata[RECORD_KEY]["registry_id"] == registry_id
    assert wired.metadata[RECORD_KEY]["bindings"] == []
    assert wired.metadata["registry_join_hints"] == [
        {"key": "cross-project-reference", "resource": VICTIM_RE}
    ]
    # The app's binding to its own project's engine still approves it.
    assert findings[RE_OK].shadow is False


@pytest.mark.parametrize(
    "segment,hinted",
    [
        ("payments-prod", VICTIM_RE),
        ("999", VICTIM_RE),
        # A number this scan does not know is another project's: acme-ml's number is known.
        ("555", "projects/555/locations/us-central1/reasoningEngines/7"),
    ],
)
@pytest.mark.parametrize("victim_registry_denied", [False, True], ids=["no-registry", "registry-denied"])
def test_agent_registry_records_never_bind_or_claim_another_projects_engines(
    index, tmp_path, segment, hinted, victim_registry_denied
):
    coverage = {}
    if victim_registry_denied:
        # payments-prod's own Agent Registry listing was denied.
        coverage = {
            "_location": None,
            "catalog": "google-agent-registry",
            "collection": "locations",
            "api_version": "v1alpha",
            "complete": False,
            "listing_scope": "project",
            "locations": [],
        }
    record = _foreign_record(
        "agent-registry-agent",
        name=f"projects/{N}/locations/global/agents/wired",
        runtime_reference=f"//aiplatform.googleapis.com/projects/{segment}/locations/us-central1/reasoningEngines/7",
    )
    # The export is replayed offline, so the entry opts in to offline records: the cross-project
    # rule, not the offline default, must keep the other project's engines unapproved.
    trusted = [
        {
            "registry": "google-agent-registry",
            "id": AR_ID,
            "allow_registered_only": True,
            "allow_offline_records": True,
        }
    ]
    result = scan(
        index,
        write_records(tmp_path, [*fixture_records(), *_victim_project(**coverage), record]),
        trusted_registries=trusted,
    )
    findings = by_resource(result.findings)
    wired = findings[record["name"]]
    assert wired.metadata[RECORD_KEY]["bindings"] == []
    assert wired.metadata["registry_join_hints"] == [{"key": "cross-project-reference", "resource": hinted}]
    for name in (VICTIM_RE, VICTIM_RE_2):
        # Neither approved by acme-ml's registry nor reported missing from it.
        assert findings[name].shadow is True
        assert RECONCILIATION_KEY not in findings[name].metadata
    # A registry that names another project's runtimes is never a complete listing of its own.
    assert all(
        finding.metadata[RECORD_KEY]["listing_complete"] is False
        for finding in findings.values()
        if finding.metadata.get(RECORD_KEY, {}).get("registry") == "google-agent-registry"
    )
    assert RECONCILIATION_KEY not in findings[RE_SHADOW].metadata
    assert status(findings[RE_OK]) == "registered-and-observed"
    # Positive control: the same trusted entry approves acme-ml's own bound engine.
    assert findings[RE_OK].shadow is False


@pytest.mark.parametrize(
    "changes,warning",
    [
        # Listed in another scanned project, named with acme-ml's number.
        ({}, "name a project other than the one they were listed in"),
        # Named with another project's id, or outside the location or collection it was listed in.
        ({"name": f"projects/{P}/locations/global/publishers/acme"}, "invalid"),
        ({"_project": P, "_location": "us-central1"}, "invalid"),
        ({"_project": P, "name": f"projects/{N}/locations/global/skills/acme"}, "invalid"),
    ],
    ids=["another-projects-number", "another-projects-id", "location", "collection"],
)
def test_publishers_speak_only_for_the_project_they_were_listed_in(index, tmp_path, changes, warning):
    spoof = _foreign_record(
        "agent-registry-publisher",
        **{
            "_project": "sandbox-dev",
            "displayName": "Security Team (verified)",
            "publisherTier": "FIRST_PARTY",
            **changes,
        },
    )
    result = scan(index, write_records(tmp_path, [*fixture_records(), spoof]))
    assert not result.complete
    warnings = next(stats.warnings for stats in result.stats if stats.connector == "cloud.gcp")
    assert any(warning in text for text in warnings)
    skill = by_resource(result.findings)[f"projects/{N}/locations/global/skills/acme-contract-review"]
    # The skill keeps the publisher its own project listed.
    assert skill.metadata[RECORD_KEY]["publisher"] == "Acme platform team"
    assert skill.metadata["publisher_tier"] == "PRIVATE"


def test_project_numbers_tell_whose_name_a_segment_is():
    numbers = gcp_registry.ProjectNumbers()
    assert numbers.names(P, "555") is None
    assert numbers.add(P, N) and numbers.add("victim", "999")
    assert numbers.names(P, N) is True and numbers.names(P, P) is True
    assert numbers.names(P, "999") is False and numbers.names(P, "555") is False
    assert numbers.names("unlisted", "555") is None


def test_associated_registry_scope_decides_absence(index, tmp_path):
    records = fixture_records()
    for record in records:
        if record.get("_agent_registry"):
            # The engine's registry is a location this scan did not list.
            record["_agent_registry"] = f"projects/{N}/locations/us-east1"
    findings = by_resource(scan(index, write_records(tmp_path, records)).findings)
    travel = next(f for r, f in findings.items() if r.endswith("/agents/travel"))
    assert travel.metadata["catalog_presence"]["agent_registry"] == "unknown"
    for record in records:
        if record.get("_agent_registry"):
            record["_agent_registry"] = "not a registry name"
    findings = by_resource(scan(index, write_records(tmp_path, records, "second.jsonl")).findings)
    travel = next(f for r, f in findings.items() if r.endswith("/agents/travel"))
    assert travel.metadata["catalog_presence"]["agent_registry"] == "unknown"


def test_endpoint_urls_hint_at_observed_cloud_run_services(index):
    service = {
        "_kind": "cloud-run-service",
        "_project": P,
        "name": f"projects/{P}/locations/us-central1/services/crew-runner",
        "uri": "https://crew-runner-xyz.a.run.app",
        "template": {
            "containers": [
                {
                    "image": "crew-runner:1",
                    "env": [
                        {"name": "OPENAI_API_KEY", "valueSource": {"secretKeyRef": {"secret": "openai"}}}
                    ],
                }
            ]
        },
    }
    endpoint = {
        "_kind": "agent-registry-endpoint",
        "_project": P,
        "_location": "global",
        "_api_version": "v1",
        "name": f"projects/{N}/locations/global/endpoints/crew",
        "urls": ["https://CREW-RUNNER-xyz.a.run.app:443?ignored=1"],
    }
    scanner = GcpConnector(context(index))
    findings = by_resource(list(scanner.analyze([service, endpoint])))
    hinted = findings[endpoint["name"]]
    assert hinted.metadata["urls"] == ["https://crew-runner-xyz.a.run.app"]
    assert hinted.metadata["registry_join_hints"] == [{"key": "endpoint-url", "resource": service["name"]}]
    # A hint is not a binding.
    assert hinted.metadata[RECORD_KEY]["bindings"] == []


def test_empty_complete_listing_is_complete_and_empty(index, fixtures):
    result = scan(index, fixtures / "cloud" / "gcp_registry_empty.jsonl")
    assert result.complete and result.findings == []
    assert not [stats for stats in result.stats if stats.warnings]


def test_standalone_handlers_emit_valid_records_without_claims(index):
    scanner = GcpConnector(context(index))
    by_kind = {record["_kind"]: record for record in fixture_records()}
    for kind in gcp_registry.RECORD_KINDS:
        finding = getattr(scanner, "_h_" + kind.replace("-", "_"))(by_kind[kind])
        record = finding.metadata[RECORD_KEY]
        assert parse_registry_record(record) is not None
        assert record["listing_complete"] is False
        assert all(binding["coverage"] != "in-scope" for binding in record["bindings"])
    assert not scanner.ctx.stats.incomplete


@pytest.mark.parametrize(
    "mutation",
    [
        {"name": f"projects/{N}/locations/us-central1/agents/negotiator"},
        {"name": "projects/other/locations/global/agents/negotiator"},
        {"name": f"projects/{N}/locations/global/mcpServers/negotiator"},
        {"name": f"projects/{N}/locations/global/agents/.."},
        {"_api_version": "v2"},
        {"_location": "Global"},
        {"_project": "../x"},
        {"protocols": [5]},
        {"displayName": ["list"]},
        {"agent_card": "text"},
        {"agentId": 5},
        {"version": ["1.0"]},
        {"hosting_location": {"region": "us"}},
    ],
)
def test_malformed_agent_registry_records_are_invalid(index, mutation):
    record = next(r for r in fixture_records() if r["_kind"] == "agent-registry-agent")
    scanner = GcpConnector(context(index))
    assert list(scanner.analyze([{**record, **mutation}])) == []
    assert scanner.ctx.stats.incomplete


@pytest.mark.parametrize(
    "mutation",
    [
        {"_engine": f"projects/{N}/locations/eu/collections/default_collection/engines/acme-assist"},
        {"_engine": "projects/other/locations/global/collections/default_collection/engines/acme-assist"},
        {"_assistant": f"{ENGINE}/assistants/other/x"},
        {"name": f"{ENGINE}/assistants/other/agents/x"},
        {"name": f"{ASSISTANT}/agents/x/y"},
        {"reasoning_engine": "projects/1/locations/us-central1/endpoints/2"},
        {"dialogflow_agent": "not a resource"},
        {"_agent_registry": 5},
        {"languageCode": 7},
        {"agent_card_status": ["invalid"]},
    ],
)
def test_malformed_gemini_enterprise_records_are_invalid(index, mutation):
    record = next(r for r in fixture_records() if r["_kind"] == "gemini-enterprise-agent")
    scanner = GcpConnector(context(index))
    assert list(scanner.analyze([{**record, **mutation}])) == []
    assert scanner.ctx.stats.incomplete


def test_replayed_tools_and_skills_keep_only_bounded_names_and_boolean_hints(index):
    """A replayed export may hold anything in nested lists; analysis keeps the collected shape."""
    records = {record["_kind"]: record for record in fixture_records()}
    server = {
        **records["agent-registry-mcp-server"],
        "tools": [
            {"name": {"nested": "value"}, "destructive": "yes", "read_only": True, "extra": "dropped"},
            "not a tool",
            {"name": "drop_table", "destructive": True},
        ],
    }
    agent = {**records["agent-registry-agent"], "skills": ["negotiate", {"id": "nested"}, 5]}
    scanner = GcpConnector(context(index))
    findings = {finding.resource_type: finding for finding in scanner.analyze([server, agent])}
    assert findings["agent-registry-mcp-server"].metadata["tools"] == [
        {"name": None, "read_only": True, "destructive": None, "open_world": None},
        {"name": "drop_table", "read_only": None, "destructive": True, "open_world": None},
    ]
    assert findings["agent-registry-agent"].metadata["skills"] == ["negotiate"]
    assert not scanner.ctx.stats.incomplete


# ------------------------------------------------------------------ trusted registries


def test_trusted_gemini_enterprise_approval_sanctions_the_bound_engine(index):
    # The fixture is an offline replay, whose records approve only for an entry that opts in.
    trusted = {"registry": "gemini-enterprise", "id": GE_ID, "allow_offline_records": True}
    result = scan(index, REGISTRY_FIXTURE, trusted_registries=[trusted])
    findings = by_resource(result.findings)
    engine = findings[RE_OK]
    assert engine.shadow is False
    assert engine.registry_match == f"gemini-enterprise:{ASSISTANT}/agents/negotiator"
    # A draft (PRIVATE) agent approves nothing: the Dialogflow agent stays shadow.
    assert findings[f"projects/{P}/locations/global/agents/abc"].shadow is True
    assert findings[RE_SHADOW].shadow is True


def test_agent_registry_records_approve_only_with_allow_registered_only(index):
    trusted = {"registry": "google-agent-registry", "id": AR_ID, "allow_offline_records": True}
    result = scan(index, REGISTRY_FIXTURE, trusted_registries=[trusted])
    findings = by_resource(result.findings)
    assert findings[RE_OK].shadow is True
    warnings = next(stats.warnings for stats in result.stats if stats.connector == "engine.inventory")
    assert any("registered-only" in warning for warning in warnings)
    result = scan(index, REGISTRY_FIXTURE, trusted_registries=[{**trusted, "allow_registered_only": True}])
    findings = by_resource(result.findings)
    assert findings[RE_OK].shadow is False
    assert (
        findings[RE_OK].registry_match
        == f"google-agent-registry:projects/{N}/locations/global/agents/negotiator"
    )
    assert findings[RE_SHADOW].shadow is True


# ------------------------------------------------------------------ dump and replay


def estate_routes(secret: str) -> dict[str, Any]:
    routes = registry_routes()
    routes[SERVICES] = enabled(
        "aiplatform.googleapis.com", "agentregistry.googleapis.com", "discoveryengine.googleapis.com"
    )
    routes[f"{VERTEX}/reasoningEngines"] = {
        "reasoningEngines": [
            {"name": RE_OK, "displayName": "negotiator"},
            {"name": RE_SHADOW, "displayName": "triage"},
        ]
    }
    routes[ENGINES] = {"engines": [{"name": ENGINE, "appType": "APP_TYPE_INTRANET"}]}
    routes[f"https://discoveryengine.googleapis.com/v1alpha/{ENGINE}/assistants"] = {
        "assistants": [{"name": ASSISTANT}]
    }
    routes[f"https://discoveryengine.googleapis.com/v1alpha/{ASSISTANT}/agents"] = {
        "agents": [
            {
                "name": f"{ASSISTANT}/agents/negotiator",
                "displayName": "negotiator",
                "state": "ENABLED",
                "adkAgentDefinition": {"provisionedReasoningEngine": {"reasoningEngine": RE_OK}},
                "authorizationConfig": {"agentAuthorization": secret},
            },
            {
                "name": f"{ASSISTANT}/agents/concierge",
                "displayName": "concierge",
                "state": "ENABLED",
                "a2aAgentDefinition": {
                    "jsonAgentCard": json.dumps(
                        {
                            "url": userinfo_url(
                                "https://", f"user:{secret}", f"concierge.example/a2a?token={secret}"
                            ),
                            "securitySchemes": {"k": {"apiKeySecurityScheme": {"description": secret}}},
                        }
                    )
                },
            },
        ]
    }
    routes[f"{AR_BASE}/locations/global/endpoints"] = {
        "endpoints": [
            {
                "name": f"projects/{N}/locations/global/endpoints/e",
                "interfaces": [{"url": f"https://e.example/x?key={secret}"}],
            }
        ]
    }
    return routes


def test_dump_then_replay_reproduces_findings_and_statuses(index, tmp_path, monkeypatch):
    secret = "opaque-" + "synthetic-credential-" + "z" * 12
    fake = FakeGoogle(estate_routes(secret))
    monkeypatch.setattr(GcpConnector, "_auth", lambda self: setattr(self, "http", fake))
    config = {
        "projects": [P],
        "locations": ["us-central1"],
        "agent_registry": True,
        "gemini_enterprise": True,
    }
    dumped = tmp_path / "dump"
    live = Engine(
        ScanConfig(connectors=[ConnectorSpec("cloud.gcp", config)], dump_records=str(dumped)), index
    ).run()
    (dump,) = dumped.glob("*.jsonl")
    replay = scan(index, dump)
    assert live.complete and replay.complete

    def outcome(result: ScanResult) -> dict[str, Any]:
        return {
            finding.id: (
                finding.kind,
                finding.tags,
                finding.metadata.get(RECORD_KEY),
                (finding.metadata.get(RECONCILIATION_KEY) or {}).get("status"),
                finding.metadata.get("catalog_presence"),
            )
            for finding in result.findings
        }

    assert outcome(live) == outcome(replay)
    statuses = {f.resource: status(f) for f in live.findings if RECONCILIATION_KEY in f.metadata}
    assert statuses[RE_OK] == "registered-and-observed"
    assert statuses[RE_SHADOW] == "observed-not-registered"
    for text in (live.to_json(), replay.to_json(), dump.read_text()):
        assert secret not in text


def _denied_second_page(params: dict[str, Any]) -> dict[str, Any]:
    if not params.get("pageToken"):
        return {"agents": [{"name": f"projects/{N}/locations/global/agents/first"}], "nextPageToken": "t1"}
    raise HttpError(403, "https://agentregistry.googleapis.com", "denied")


REPLAYED_GAP = "cloud.gcp: registry catalog listing incomplete in export; records may be missing"


@pytest.mark.parametrize(
    "failures",
    [
        {f"{AR_BASE}/locations/global/agents": _denied_second_page},
        {f"{VERTEX}/reasoningEngines": HttpError(403, "https://aiplatform.googleapis.com", "denied")},
        {
            f"{AR_BASE}/locations/global/agents": _denied_second_page,
            f"{VERTEX}/reasoningEngines": HttpError(403, "https://aiplatform.googleapis.com", "denied"),
        },
    ],
    ids=["agent-registry-page", "vertex-ai", "both"],
)
def test_replayed_dump_of_an_incomplete_scan_stays_incomplete(index, tmp_path, monkeypatch, failures):
    fake = FakeGoogle({**estate_routes("unused"), **failures})
    monkeypatch.setattr(GcpConnector, "_auth", lambda self: setattr(self, "http", fake))
    config = {"projects": [P], "locations": ["us-central1"], "agent_registry": True}
    dumped = tmp_path / "dump"
    live = Engine(
        ScanConfig(connectors=[ConnectorSpec("cloud.gcp", config)], dump_records=str(dumped)), index
    ).run()
    (dump,) = dumped.glob("*.jsonl")
    assert any(
        record["_kind"] == "registry-coverage" and record["complete"] is False
        for record in map(json.loads, dump.read_text().splitlines())
    )
    replay = scan(index, dump)
    # The export records that a listing failed: replaying it is as incomplete as the live scan.
    assert not live.complete and not replay.complete

    def warnings(result: ScanResult) -> list[str]:
        return next(stats.warnings for stats in result.stats if stats.connector == "cloud.gcp")

    # Once per replay, however many listings failed; live collection already warned for each.
    assert warnings(replay).count(REPLAYED_GAP) == 1
    assert REPLAYED_GAP not in warnings(live)

    def outcome(result: ScanResult) -> dict[str, Any]:
        return {
            finding.id: (finding.metadata.get(RECORD_KEY), finding.metadata.get(RECONCILIATION_KEY))
            for finding in result.findings
        }

    # The warning voids no claim that live analysis made about the listings that completed.
    assert outcome(live) == outcome(replay)
    assert all(
        RECONCILIATION_KEY not in finding.metadata or status(finding) != "observed-not-registered"
        for finding in replay.findings
    )


def test_the_documented_gcp_registry_example_is_valid(index):
    text = (Path(__file__).parents[2] / "docs" / "inventory.md").read_text(encoding="utf-8")
    section = text.split("### Example: Google Agent Registry and Gemini Enterprise", 1)[1]
    example = yaml.safe_load(section.split("```yaml\n", 1)[1].split("```", 1)[0])
    config = ScanConfig.from_dict(example)
    (spec,) = config.connectors
    scanner = GcpConnector(ConnectorContext(spec.config, index=index))
    assert scanner.agent_registry and scanner.gemini_enterprise
    assert [(item.registry, item.id) for item in config.trusted_registries] == [("gemini-enterprise", GE_ID)]


def test_catalog_switches_are_strict_configuration_booleans():
    connectors = [{"name": "cloud.gcp", "agent_registry": "TRUE", "gemini_enterprise": "false"}]
    (spec,) = ScanConfig.from_dict({"connectors": connectors}).connectors
    assert (spec.config["agent_registry"], spec.config["gemini_enterprise"]) == (True, False)
    with pytest.raises(ConfigValidationError, match="agent_registry"):
        ScanConfig.from_dict({"connectors": [{"name": "cloud.gcp", "agent_registry": "yes"}]})


@pytest.mark.parametrize(
    "reference,attributed",
    [
        ("//aiplatform.googleapis.com/projects/acme-ml/locations/us-central1/reasoningEngines/456", True),
        (
            "//us-central1-aiplatform.googleapis.com/projects/acme-ml/locations/us-central1/reasoningEngines/456",
            True,
        ),
        # The service name appearing anywhere else in the URI is not a Vertex AI reference.
        (
            "//evil.example/aiplatform.googleapis.com/projects/acme-ml/locations/us-central1/reasoningEngines/456",
            False,
        ),
        ("https://aiplatform.googleapis.com.evil.example/projects/p/locations/l/reasoningEngines/1", False),
        ("//dialogflow.googleapis.com/projects/acme-ml/locations/global/agents/9", False),
        ("//aiplatform.googleapis.com/projects/acme-ml/locations/us-central1/endpoints/1", False),
    ],
)
def test_only_a_vertex_reasoning_engine_reference_attributes_agent_engine(
    index, tmp_path, reference, attributed
):
    records = [
        {**record, "runtime_reference": reference}
        if record["_kind"] == "agent-registry-agent" and record.get("name", "").endswith("/negotiator")
        else record
        for record in fixture_records()
    ]
    findings = by_resource(scan(index, write_records(tmp_path, records)).findings)
    negotiator = findings["projects/123/locations/global/agents/negotiator"]
    assert ("cloud.gcp-vertex-agent-engine" in negotiator.frameworks) is attributed


UNRECOGNIZED = "cloud.gcp: Agent Registry runtime reference to Vertex AI or Dialogflow not recognized"


@pytest.mark.parametrize(
    "reference,recognized",
    [
        (f"//aiplatform.googleapis.com/v1/projects/{P}/locations/us-central1/reasoningEngines/789", False),
        (f"https://us-central1-aiplatform.googleapis.com/v1/{RE_SHADOW}", False),
        (f"//aiplatform.googleapis.com/{RE_SHADOW}/", False),
        (f"//AIPLATFORM.googleapis.com/{RE_SHADOW}", False),
        (f"//dialogflow.googleapis.com/projects/{P}/locations/global/agents/abc/flows/x", False),
        (f"//aiplatform.googleapis.com/{RE_SHADOW}/sessions/1", False),
        (
            f"//aiplatform.googleapis.com/projects/{P}/locations/us-central1/publishers/google/models/m/",
            False,
        ),
        (
            f"//aiplatform.googleapis.com/projects/{P}/locations/us-central1/endpoints/../reasoningEngines/1",
            False,
        ),
        # A plain resource name of a collection the scan does not observe names no engine.
        (f"//aiplatform.googleapis.com/projects/{P}/locations/us-central1/endpoints/1", True),
        # So does a nested plain name outside the observed collections (a publisher model).
        (
            f"//aiplatform.googleapis.com/projects/{P}/locations/us-central1"
            "/publishers/google/models/gemini-2.0-flash",
            True,
        ),
        (f"//aiplatform.googleapis.com/projects/{P}/locations/us-central1/ragCorpora/1/ragFiles/2", True),
        # Neither Vertex AI nor Dialogflow.
        (f"//container.googleapis.com/projects/{P}/locations/us-central1/clusters/c", True),
        (f"https://aiplatform.googleapis.com.evil.example/{RE_SHADOW}", True),
    ],
)
def test_unrecognized_vertex_or_dialogflow_runtime_references_are_never_complete(
    index, tmp_path, reference, recognized
):
    template = next(record for record in fixture_records() if record["_kind"] == "agent-registry-agent")
    added = [
        {**template, "name": f"projects/{N}/locations/global/agents/{name}", "runtime_reference": reference}
        for name in ("triage", "triage-copy")
    ]
    result = scan(index, write_records(tmp_path, [*fixture_records(), *added]))
    warnings = next(stats.warnings for stats in result.stats if stats.connector == "cloud.gcp")
    assert result.complete is recognized
    # One warning however many records hold such a reference.
    assert sum(warning.startswith(UNRECOGNIZED) for warning in warnings) == (0 if recognized else 1)
    findings = by_resource(result.findings)
    for record in added:
        assert findings[record["name"]].metadata[RECORD_KEY]["bindings"] == []
        assert findings[record["name"]].metadata[RECORD_KEY]["listing_complete"] is recognized
    # The engine such a reference may register is never reported missing from the registry.
    shadow = findings[RE_SHADOW].metadata.get(RECONCILIATION_KEY)
    assert (shadow is not None and shadow["status"] == "observed-not-registered") is recognized


def test_replayed_registry_strings_are_bounded_like_collected_ones(index):
    name, display, agent_id = f"projects/{N}/locations/global/agents/long", "d" * 5000, "a" * 5000
    framework, reference = "langgraph" + "f" * 5000, "//container.googleapis.com/" + "r" * 5000
    item = {
        "name": name,
        "displayName": display,
        "agentId": agent_id,
        "attributes": {
            "agentregistry.googleapis.com/system/Framework": {"framework": framework},
            "agentregistry.googleapis.com/system/RuntimeReference": {"uri": reference},
        },
    }
    scope = {"_kind": "agent-registry-agent", "_project": P, "_location": "global", "_api_version": "v1"}
    collected = {**gcp_registry.normalize_ar_item("agents", item), **scope}
    # An export written by hand (or by an older build) holds the same item unbounded.
    replayed = {
        "name": name,
        "displayName": display,
        "agentId": agent_id,
        "framework": framework,
        "runtime_reference": reference,
        **scope,
    }

    def analyzed(record: dict[str, Any]) -> Finding:
        scanner = GcpConnector(context(index))
        (finding,) = scanner.analyze([record])
        assert not scanner.ctx.stats.incomplete
        return finding

    live, replay = analyzed(collected), analyzed(replayed)
    assert replay.title == live.title == "Agent Registry agent: " + "d" * 199 + "…"
    for key, limit in (("agent_id", 256), ("framework", 512), ("runtime_reference", 512)):
        assert replay.metadata[key] == live.metadata[key]
        assert len(replay.metadata[key]) == limit
    assert replay.metadata[RECORD_KEY] == live.metadata[RECORD_KEY]
