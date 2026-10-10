"""Google Cloud project scanner (REST APIs with google-auth or a supplied access token).

Per project:

* enabled AI APIs (Service Usage)
* Vertex AI Agent Engine (reasoning engines) and endpoints per location
* Dialogflow CX agents, Discovery Engine / Agentspace engines
* Cloud Run services and Cloud Functions (images, env names, plaintext credentials, service accounts)
* IAM policy bindings granting Vertex / Dialogflow / Discovery Engine roles (``iam-grant``)
* service accounts (agent-like names, user-managed keys)
* API keys restricted to the Gemini API (``secret``), Secret Manager secret names
* optional: Cloud Audit Logs callers of ``aiplatform.googleapis.com`` (``gateway-caller``)
* opt-in: Google Agent Registry agents, MCP servers and endpoints (``agent_registry``) and Gemini
  Enterprise app agents (``gemini_enterprise``) as registry records (``shadowscan.registries``),
  bound to the reasoning engines and Dialogflow agents this scan observed (see ``gcp_registry``)

Offline export: JSONL of dumped records (``_kind`` per record).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Generator, Iterable, Iterator
from datetime import UTC, datetime, timedelta
from functools import partial
from typing import Any, ClassVar
from urllib.parse import urlsplit

from requests import RequestException, Session

from shadowscan.connectors.base import (
    BaseConnector,
    ConnectorContext,
    ConnectorError,
    _non_negative_limit,
    _positive_limit,
)
from shadowscan.connectors.cloud.common import (
    RECORD_ERRORS,
    InvalidPageTokenError,
    RecordDispatch,
    aggregate_caller_event,
    cloud_finding,
    credential_name_matches,
    done,
    first_tag,
    name_hint,
    next_page_token,
    scan_env,
    scan_iam_actions,
    string_list,
)
from shadowscan.connectors.cloud.credentials import allow_instance_credentials, require_local_adc
from shadowscan.connectors.cloud.gcp_registry import (
    AR_ALPHA_COLLECTIONS,
    AR_COLLECTIONS,
    AR_REGISTRY,
    AR_VERSIONS,
    COVERAGE_KIND,
    DIALOGFLOW_CATALOG,
    EXTRA_KINDS,
    GE_AGENT_KIND,
    GE_REGISTRY,
    PROJECT_NUMBER_KIND,
    RECORD_KINDS,
    VERTEX_CATALOG,
    RecordEntry,
    RegistryCatalogs,
    bound_strings,
    clean_card,
    clean_texts,
    clean_tools,
    engine_scope,
    is_assistant_of,
    is_ge_app,
    is_number,
    normalize_ar_item,
    normalize_ge_agent,
    record_entry,
    runtime_reference,
    urls,
    valid_location,
)
from shadowscan.connectors.common import (
    apply_matches,
    config_boolean,
    failure_outcome,
    failure_summary,
    max_pages_limit,
    model_matches,
)
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.registries import EVIDENCE_GROUP, registry_evidence
from shadowscan.utils.http import HttpClient, HttpError, validate_url
from shadowscan.utils.text import get_path, truncate

DEFAULT_LOCATIONS = [
    "us-central1",
    "us-east4",
    "us-west1",
    "europe-west1",
    "europe-west4",
    "asia-southeast1",
    "asia-northeast1",
]
MAX_LIST_PAGES = 500
AI_SERVICES = {
    "aiplatform.googleapis.com": "Vertex AI",
    "generativelanguage.googleapis.com": "Gemini API",
    "dialogflow.googleapis.com": "Dialogflow",
    "discoveryengine.googleapis.com": "Vertex AI Search / Agent Builder / Agentspace",
    "notebooks.googleapis.com": "Vertex AI Workbench",
    "speech.googleapis.com": "Speech",
    "documentai.googleapis.com": "Document AI",
    "contactcenteraiplatform.googleapis.com": "CCAI",
    "agentregistry.googleapis.com": "Agent Registry",
}
# Cloud Audit Logs entries for generative calls (services and method-name fragments).
_AUDIT_SERVICES = ("aiplatform.googleapis.com", "dialogflow.googleapis.com", "discoveryengine.googleapis.com")
_AUDIT_METHODS = (
    "Predict",
    "GenerateContent",
    "StreamGenerateContent",
    "Query",
    "DetectIntent",
    "Converse",
    "Answer",
)
_AUDIT_TEXT_FIELDS = ("principal", "method", "resource", "userAgent", "timestamp", "_project")
# Agent Engine ``agentFramework`` fragments and the framework signature each implies.
_AGENT_FRAMEWORK_HINTS = (
    ("adk", "framework.google-adk"),
    ("langgraph", "framework.langgraph"),
    ("langchain", "framework.langchain"),
    ("ag2", "framework.autogen"),
    ("autogen", "framework.autogen"),
    ("llama", "framework.llamaindex"),
    ("crewai", "framework.crewai"),
)
_BROAD_ROLES = {"roles/owner", "roles/editor"}
_CHAT_SOLUTIONS = {"SOLUTION_TYPE_CHAT", "SOLUTION_TYPE_GENERATIVE_CHAT"}
_LLM_SECRET_KEYWORDS = (
    "openai",
    "anthropic",
    "claude",
    "gemini",
    "llm",
    "huggingface",
    "mistral",
    "cohere",
    "groq",
    "langsmith",
    "langfuse",
    "pinecone",
    "tavily",
)
_RUN_LOCATION = re.compile(r"[a-z][a-z0-9-]*[0-9]")
_SERVICE_ACCOUNT_NAME = re.compile(r"projects/[A-Za-z0-9._:-]+/serviceAccounts/[^/?#\s]+")
_DISCOVERY_LOCATIONS = ("global", "us", "eu")
_PROJECTS = "https://cloudresourcemanager.googleapis.com/v1/projects"
# Path segments whose value an earlier response supplied: a request under one of them is a
# detail of the live scope, recorded by template and never fingerprinted.
_DISCOVERED_SEGMENTS = {"engines": "{engine}", "assistants": "{assistant}", "serviceAccounts": "{account}"}
# Registry record kinds: finding kind and title of each.
_RECORD_FINDINGS = {
    "agent-registry-agent": (Kind.AGENT, "Agent Registry agent"),
    "agent-registry-mcp-server": (Kind.MCP_SERVER, "Agent Registry MCP server"),
    "agent-registry-endpoint": (Kind.CLOUD_RESOURCE, "Agent Registry endpoint"),
    "agent-registry-skill": (Kind.AGENT_CONFIG, "Agent Registry skill"),
    GE_AGENT_KIND: (Kind.AGENT, "Gemini Enterprise agent"),
}


def _count(value: Any) -> int:
    """A nonnegative integer count from a record, 0 for anything else."""
    return value if type(value) is int and value >= 0 else 0


def _uses(services: Iterable[str | None], service: str) -> bool:
    """Whether ``service`` is one of ``services``: exact service names, never a URL substring."""
    return service in services


def _audit_filter(since: str) -> str:
    services = " OR ".join(f'"{service}"' for service in _AUDIT_SERVICES)
    methods = " OR ".join(f'"{method}"' for method in _AUDIT_METHODS)
    return (
        f"protoPayload.serviceName=({services}) AND (protoPayload.methodName:({methods})) "
        f'AND timestamp>="{since}"'
    )


def _location(name: str) -> str | None:
    """The location segment of ``projects/P/locations/L/...`` resource names."""
    return name.split("/locations/")[1].split("/")[0] if "/locations/" in name else None


def _api_host(service: str, location: str) -> str:
    """Google's documented host for a location: global uses ``<service>``, others ``<location>-<service>``."""
    return f"{service}.googleapis.com" if location == "global" else f"{location}-{service}.googleapis.com"


class GcpConnector(BaseConnector):
    name: ClassVar[str] = "cloud.gcp"
    _ENV_VALUES_ARE_CONFIGURATION: ClassVar[bool] = True
    surface: ClassVar[Surface] = Surface.CLOUD
    provider: ClassVar[str | None] = "gcp"
    requires: ClassVar[list[str]] = []
    description: ClassVar[str] = (
        "Vertex AI Agent Engine, Dialogflow CX, Agentspace/Discovery Engine, Cloud Run/Functions, "
        "IAM bindings, service accounts, Gemini API keys, secret names, audit-log callers; opt-in "
        "Agent Registry and Gemini Enterprise agent catalogs."
    )
    emits_registry_records: ClassVar[bool] = True
    registry_record_types: ClassVar[frozenset[str]] = frozenset({AR_REGISTRY, GE_REGISTRY})
    attests_live_scope: ClassVar[bool] = True
    scope_options: ClassVar[frozenset[str]] = frozenset(
        {
            "projects",
            "locations",
            "audit_days",
            "max_projects",
            "max_pages",
            "agent_registry",
            "agent_registry_version",
            "agent_registry_locations",
            "gemini_enterprise",
            "discovery_collections",
        }
    )
    config_keys: ClassVar[dict[str, str]] = {
        "projects": "list of project ids (default: all projects visible to the credentials)",
        "locations": f"Vertex/Dialogflow locations (default {DEFAULT_LOCATIONS})",
        "access_token": (
            "OAuth token (env GOOGLE_OAUTH_ACCESS_TOKEN); "
            "otherwise Application Default Credentials via google-auth"
        ),
        "credentials_file": (
            "explicit Google credentials file (env GOOGLE_APPLICATION_CREDENTIALS); "
            "otherwise local gcloud ADC"
        ),
        "allow_instance_credentials": (
            "allow metadata-based Application Default Credentials (default false; inherited from options)"
        ),
        "audit_days": (
            "look back N days in Cloud Audit Logs for Vertex callers, a non-negative integer "
            "(default 0 = off)"
        ),
        "max_projects": "cap on projects scanned, a positive integer (default 200)",
        "max_pages": (
            "maximum pages per paginated call, capped at 1000 (default 1000; resource lists stop at 500 "
            "pages and audit-log queries at 50 pages regardless)"
        ),
        "agent_registry": (
            "read Google Agent Registry agents, MCP servers and endpoints as registry records where "
            "agentregistry.googleapis.com is enabled (default false)"
        ),
        "agent_registry_version": (
            "Agent Registry API version: v1 (default) or v1alpha (experimental; adds skills and publishers)"
        ),
        "agent_registry_locations": (
            "Agent Registry locations to list (default: every location the API reports; when set, "
            "listings are never complete for reconciliation)"
        ),
        "gemini_enterprise": (
            "read the agents of Gemini Enterprise apps (Discovery Engine v1alpha, caller-scoped) as "
            "registry records (default false)"
        ),
        "discovery_collections": (
            'Discovery Engine collections whose engines are listed (default ["default_collection"])'
        ),
        "input": "offline: JSONL dump of records",
    }
    offline_formats: ClassVar[str] = "JSONL dump of records"

    def __init__(self, ctx: ConnectorContext):
        super().__init__(ctx)
        try:
            # Locations are interpolated into API hostnames.
            locations = string_list(ctx.get("locations"), "locations", pattern=r"[a-z0-9-]+")
            self.locations = locations or DEFAULT_LOCATIONS
            self._default_locations = not locations
            self.projects = string_list(ctx.get("projects"), "projects", pattern=r"[A-Za-z0-9._:-]+") or []
            # Agent Registry locations and Discovery Engine collections become request paths.
            self.agent_registry_locations = string_list(
                ctx.get("agent_registry_locations"), "agent_registry_locations", pattern=r"[a-z][a-z0-9-]*"
            )
            self.discovery_collections = string_list(
                ctx.get("discovery_collections"), "discovery_collections", pattern=r"[a-z0-9][a-z0-9_-]*"
            ) or ["default_collection"]
        except ValueError as exc:
            raise ConnectorError(f"cloud.gcp: {exc}") from None
        self.audit_days = _non_negative_limit(ctx.get("audit_days", 0), "audit_days")
        self.max_projects = _positive_limit(ctx.get("max_projects", 200), "max_projects")
        self.max_pages = max_pages_limit(ctx.get("max_pages", 1000))
        self.agent_registry = config_boolean(ctx.get("agent_registry", False), "agent_registry")
        self.gemini_enterprise = config_boolean(ctx.get("gemini_enterprise", False), "gemini_enterprise")
        version = ctx.get("agent_registry_version", "v1")
        if not isinstance(version, str) or version not in AR_VERSIONS:
            raise ConnectorError("cloud.gcp: agent_registry_version must be v1 or v1alpha")
        self.agent_registry_version = version
        self.http: HttpClient | None = None
        self._locations_noted = False
        # Project number -> id for registry reconciliation, from discovery or a project lookup.
        self._project_numbers: dict[str, str] = {}
        # Configured projects whose enabled-service listing completed in this run.
        self._verified_projects: set[str] = set()

    @property
    def _catalogs(self) -> bool:
        """Whether a registry catalog is read: only then are coverage and project-number records emitted."""
        return self.agent_registry or self.gemini_enterprise

    def _auth(self) -> None:
        token = self.ctx.get("access_token", env="GOOGLE_OAUTH_ACCESS_TOKEN")
        if not token:
            try:
                import google.auth
                import google.auth.transport.requests
            except ImportError as exc:
                raise ConnectorError(
                    "cloud.gcp: install google-auth (install '.[gcp]' from the "
                    "reviewed Project Nexus checkout) or provide access_token"
                ) from exc
            # google-auth otherwise uses its own 120-second transport default,
            # including discovery/refresh requests outside our HttpClient.
            allow_instance = allow_instance_credentials(self.ctx.get("allow_instance_credentials", False))

            class CredentialSession(Session):
                """Retain OAuth status bodies within the complete HTTP policy."""

                def __init__(self) -> None:
                    super().__init__()
                    self.trust_env = False
                    self.client = HttpClient(
                        allow_private_origin=allow_instance,
                        max_retries=0,
                        max_response_bytes=1024 * 1024,
                    )

                def request(self, method: Any, url: Any, *args: Any, **kwargs: Any) -> Any:
                    if args:
                        # google-auth supplies HTTP options by keyword.
                        raise TypeError("Credential transport requires keyword HTTP options")
                    if allow_instance and urlsplit(url).scheme == "http":
                        # IMDS requires HTTP. Opt-in permits that transport, but
                        # never redirects credentials and still bounds its body.
                        kwargs["allow_redirects"] = False
                        kwargs["stream"] = True
                        response = super().request(method, url, **kwargs)
                        if 300 <= response.status_code < 400:
                            response.close()
                            raise ValueError("Cloud credential endpoint redirects are refused")
                        response._content = self.client.read_response_bytes(response)
                        response._content_consumed = True  # type: ignore[attr-defined]
                        return response
                    kwargs["stream"] = False
                    return self.client.request(method, url, raise_for_status=False, **kwargs)

                def close(self) -> None:
                    self.client.session.close()
                    super().close()

            class BoundedRequest(google.auth.transport.requests.Request):
                def __call__(self, *args: Any, **kwargs: Any) -> Any:
                    if not allow_instance:
                        # A file-based workload identity can itself reference IMDS.
                        # Apply public destination/socket policy during refresh too.
                        validate_url(kwargs.get("url") or args[0], allow_private=False)
                    timeout = kwargs.pop("timeout", 30)
                    kwargs["timeout"] = min(float(timeout), 30) if timeout is not None else 30
                    return super().__call__(*args, **kwargs)

            request = BoundedRequest(session=CredentialSession())

            scopes = ["https://www.googleapis.com/auth/cloud-platform"]
            credentials_file = self.ctx.get("credentials_file", env="GOOGLE_APPLICATION_CREDENTIALS")
            if allow_instance and not credentials_file:
                creds, _ = google.auth.default(scopes=scopes, request=request)
            else:
                # Local-only mode never calls the default ADC chain, which may
                # silently fall through to instance metadata or external hooks.
                if not allow_instance:
                    credentials_file = require_local_adc(credentials_file)
                creds, _ = google.auth.load_credentials_from_file(
                    credentials_file,
                    scopes=scopes,
                    request=request,
                )
            creds.refresh(request)
            token = creds.token
        self.http = HttpClient(headers={"Authorization": f"Bearer {token}"})

    def _scope_operation(self, url: str, project: str | None = None) -> tuple[str, str, str | None, bool]:
        """One request as a live scope operation: (service, path template, partition, enumeration).

        Project and location path segments become placeholders and form the partition. A
        request under a resource an earlier response named (an engine, an assistant, a
        service account) is a detail, and so is every per-project request when the projects
        were discovered rather than configured: only the discovery itself is fingerprinted.
        """
        parts = urlsplit(url)
        service = (parts.hostname or "").split(".")[0].rsplit("-", 1)[-1]
        segments = parts.path.strip("/").split("/")
        location: str | None = None
        detail = False
        template = []
        for previous, segment in zip(["", *segments], segments, strict=False):
            value, colon, method = segment.partition(":")
            if previous == "projects":
                project, segment = value, "{project}" + colon + method
            elif previous == "locations":
                location, segment = value, "{location}" + colon + method
            elif previous in _DISCOVERED_SEGMENTS:
                detail, segment = True, _DISCOVERED_SEGMENTS[previous] + colon + method
            template.append(segment)
        enumeration = not detail and (project is None or bool(self.projects))
        partition = project if location is None or project is None else f"{project}/{location}"
        return service, "/" + "/".join(template), partition if enumeration else None, enumeration

    def _attest(self, url: str, outcome: str, project: str | None = None) -> None:
        service, operation, partition, enumeration = self._scope_operation(url, project)
        self.ctx.attest_operation(service, operation, partition, outcome, enumeration=enumeration)

    def _get(self, url: str, **params: Any) -> Any:
        assert self.http
        try:
            data = self.http.get_json(url, params=params or None)
            if data is None:
                self._attest(url, "failed")
                self.ctx.warn(f"cloud.gcp: empty response for {url.split('?')[0]}")
            else:
                self._attest(url, "ok")
            return data
        except (HttpError, RequestException, ValueError) as exc:
            self._attest(url, failure_outcome(exc))
            self.ctx.warn(f"cloud.gcp: collection failed for {url.split('?')[0]} ({failure_summary(exc)})")
            return None

    def _next_page_token(self, data: dict[str, Any], seen: set[str], *, warn: str) -> str | None:
        """Return the next page token, or None when pagination should stop.

        An absent or empty token stops pagination silently (normal
        termination); ``warn`` is only logged for an invalid or
        already-seen token. Used by ``_collect_audit`` (``_pages`` also needs
        to tell the two apart); the token contract itself lives in
        ``common.next_page_token``.
        """
        try:
            return next_page_token(data.get("nextPageToken"), seen)
        except InvalidPageTokenError:
            self.ctx.warn(warn)
            return None

    def _pages(self, url: str, items_key: str, **params: Any) -> Generator[dict[str, Any], None, bool]:
        """Yield the items of a paginated list; return True only when the listing ended cleanly.

        Every failure (denied or failed request, invalid page, unreachable locations, invalid
        or repeated token, page cap) is warned here as incomplete and returns False.
        """
        token: str | None = None
        seen: set[str] = set()
        complete = True
        for _ in range(min(MAX_LIST_PAGES, self.max_pages)):
            p = dict(params)
            if token:
                p["pageToken"] = token
            data = self._get(url, **p)
            if data is None:
                return False  # _get has already recorded the collection failure
            if not isinstance(data, dict) or "error" in data:
                self._attest(url, "failed")
                self.ctx.warn(f"cloud.gcp: invalid response for {url}")
                return False
            # Aggregated list APIs may succeed while omitting unavailable regions.
            # Keep reachable observations, but never turn partial success into a
            # complete inventory (Cloud Functions v2 and Cloud Run v2 contract).
            unreachable = data.get("unreachable", [])
            if not isinstance(unreachable, list) or any(
                not isinstance(loc, str) or not loc for loc in unreachable
            ):
                self._attest(url, "failed")
                self.ctx.warn(f"cloud.gcp: invalid unreachable locations for {url}")
                complete = False
            elif unreachable:
                self._attest(url, "unavailable")
                self.ctx.warn(
                    f"cloud.gcp: {len(unreachable)} unreachable location(s) for {url}; coverage unknown"
                )
                complete = False
            items = data.get(items_key, [])
            if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
                self._attest(url, "failed")
                self.ctx.warn(f"cloud.gcp: invalid {items_key} page for {url}")
                return False
            yield from items
            try:
                token = next_page_token(data.get("nextPageToken"), seen)
            except InvalidPageTokenError:
                self._attest(url, "failed")
                self.ctx.warn(f"cloud.gcp: invalid or repeated pagination token for {url}")
                return False
            if token is None:
                return complete
        self._attest(url, "truncated")
        self.ctx.warn(f"cloud.gcp: pagination limit reached for {url}")
        return False

    @staticmethod
    def _listing(
        pages: Iterator[dict[str, Any]],
        *,
        normalize: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
        sink: list[dict[str, Any]] | None = None,
        **collected: Any,
    ) -> Generator[dict[str, Any], None, bool]:
        """Re-yield listed items with the collector's keys written last; return whether the list completed.

        ``normalize`` reduces each item first; ``sink`` also receives every yielded record. A
        replacement ``_pages`` that is a plain iterator never reports completion.
        """
        while True:
            try:
                item = next(pages)
            except StopIteration as stop:
                return stop.value is True
            record = {**(normalize(item) if normalize else item), **collected}
            if sink is not None:
                sink.append(record)
            yield record

    @staticmethod
    def _drain(pages: Iterator[dict[str, Any]]) -> tuple[list[dict[str, Any]], bool]:
        """Every item of a listing, and whether it completed."""
        items: list[dict[str, Any]] = []
        while True:
            try:
                items.append(next(pages))
            except StopIteration as stop:
                return items, stop.value is True

    @staticmethod
    def _coverage(
        project: str,
        location: str | None,
        catalog: str,
        collection: str,
        api_version: str,
        complete: bool,
        *,
        scope: str = "project",
        **extra: Any,
    ) -> dict[str, Any]:
        """A ``registry-coverage`` record: whether one listing completed, for reconciliation."""
        return {
            "_kind": COVERAGE_KIND,
            "_project": project,
            "_location": location,
            "catalog": catalog,
            "collection": collection,
            "api_version": api_version,
            "complete": complete,
            "listing_scope": scope,
            **extra,
        }

    # -------------------------------------------------------------- collect
    def collect(self) -> Iterable[dict[str, Any]]:
        self._auth()
        self._verified_projects = set()
        projects: Iterable[str] = list(self.projects)
        discovery: list[bool] = []
        if not projects:
            listed = self._pages(_PROJECTS, "projects", filter="lifecycleState:ACTIVE")
            projects = self._project_ids(self._completion(listed, discovery))
        scanned: list[str] = []
        for i, project in enumerate(projects):
            if i >= self.max_projects:
                self.ctx.warn("cloud.gcp: max_projects reached")
                break
            scanned.append(project)
            yield from self._collect_project(project)
        self._attest_scope(discovery, scanned)

    def _attest_scope(self, discovery: list[bool], scanned: list[str]) -> None:
        """The live scope principal: configured projects the API answered for, or the discovered set.

        In discovery mode the principal is every project a complete ``projects.list`` returned,
        as for Azure's listed subscriptions. A project the credentials can no longer see then
        changes the scope (exit 3) rather than resolving its findings, and a new project needs a
        reviewed re-baseline. A listing that failed, or stopped at ``max_projects``, attests none.
        """
        self.ctx.attest_partition("locations", self.locations)
        if self.projects:
            self.ctx.attest_partition("projects", self.projects)
            if set(self.projects) <= self._verified_projects:
                principal = ",".join(sorted(set(self.projects)))
                self.ctx.attest_principal("gcp", "projects", principal, "serviceusage.services.list")
        elif discovery == [True] and scanned:
            visible = ",".join(sorted(set(scanned)))
            verified_by = "cloudresourcemanager.projects.list"
            self.ctx.attest_principal("gcp", "visible-projects", visible, verified_by)

    @staticmethod
    def _completion(
        pages: Generator[dict[str, Any], None, bool], sink: list[bool]
    ) -> Iterator[dict[str, Any]]:
        """Re-yield a listing and append whether it completed once it ends."""
        complete = yield from pages
        sink.append(complete is True)

    def _project_ids(self, projects: Iterable[dict[str, Any]]) -> Iterator[str]:
        """Validate discovered scope before it becomes an authenticated API path."""
        for project in projects:
            project_id = project.get("projectId")
            if (
                not isinstance(project_id, str)
                or project_id in {".", ".."}
                or not re.fullmatch(r"[A-Za-z0-9._:-]+", project_id)
            ):
                self.ctx.warn("cloud.gcp: invalid discovered project identifier; coverage unknown")
                continue
            number = project.get("projectNumber")
            if isinstance(number, str) and is_number(number):
                # Registry and Vertex resource names may carry the number instead of the id.
                self._project_numbers[project_id] = number
            yield project_id

    def _collect_project(self, project: str) -> Iterator[dict[str, Any]]:
        services, listed = self._drain(
            self._pages(
                f"https://serviceusage.googleapis.com/v1/projects/{project}/services",
                "services",
                filter="state:ENABLED",
                pageSize=200,
            )
        )
        if listed:
            # The project exists and the credentials can read it: a configured project is verified.
            self._verified_projects.add(project)
        enabled: list[str] = []
        for service in services:
            # Response shapes are untrusted: a service record without a config
            # name is a coverage gap for this project, not a failure of every
            # project and service that follows it.
            config = service.get("config") if isinstance(service, dict) else None
            name = config.get("name") if isinstance(config, dict) else None
            if isinstance(name, str):
                enabled.append(name)
            else:
                self.ctx.warn(
                    f"cloud.gcp: malformed service record in {project}; service coverage incomplete"
                )
        ai_enabled = [s for s in enabled if s in AI_SERVICES]
        yield {"_kind": "project", "project": project, "ai_services": ai_enabled}
        if self._catalogs:
            yield from self._project_number(project)
        if _uses(enabled, "aiplatform.googleapis.com") or _uses(enabled, "dialogflow.googleapis.com"):
            self._note_default_locations()
        if _uses(enabled, "aiplatform.googleapis.com"):
            yield from self._collect_vertex(project)
        if _uses(enabled, "dialogflow.googleapis.com"):
            for loc in dict.fromkeys(["global", *self.locations]):
                host = _api_host("dialogflow", loc)
                url = f"https://{host}/v3/projects/{project}/locations/{loc}/agents"
                listed = yield from self._listing(
                    self._pages(url, "agents"), _kind="dialogflow-agent", _project=project, _location=loc
                )
                if self._catalogs:
                    yield self._coverage(project, loc, DIALOGFLOW_CATALOG, "agents", "v3", listed)
        if _uses(enabled, "discoveryengine.googleapis.com"):
            yield from self._collect_discovery_engines(project)
        if self.agent_registry and _uses(enabled, "agentregistry.googleapis.com"):
            yield from self._collect_agent_registry(project)
        if _uses(enabled, "run.googleapis.com"):
            yield from self._collect_cloud_run(project)
        if _uses(enabled, "cloudfunctions.googleapis.com"):
            url = f"https://cloudfunctions.googleapis.com/v2/projects/{project}/locations/-/functions"
            for fn in self._pages(url, "functions"):
                yield {**fn, "_kind": "cloud-function", "_project": project}
        yield from self._collect_iam_policy(project)
        yield from self._collect_service_accounts(project)
        if _uses(enabled, "apikeys.googleapis.com"):
            url = f"https://apikeys.googleapis.com/v2/projects/{project}/locations/global/keys"
            for key in self._pages(url, "keys"):
                yield {**key, "_kind": "api-key", "_project": project}
        if _uses(enabled, "secretmanager.googleapis.com"):
            url = f"https://secretmanager.googleapis.com/v1/projects/{project}/secrets"
            for s in self._pages(url, "secrets"):
                yield {
                    "_kind": "secret-name",
                    "_project": project,
                    "name": s.get("name"),
                    "createTime": s.get("createTime"),
                    "labels": s.get("labels"),
                }
        if self.audit_days > 0 and _uses(enabled, "aiplatform.googleapis.com"):
            yield from self._collect_audit(project)

    def _note_default_locations(self) -> None:
        """Once per scan, say which locations a default (unset ``locations``) scan covered."""
        if not self._default_locations or self._locations_noted:
            return
        self._locations_noted = True
        # Informational: the operator chose no scope, so name what was and was not covered.
        self.ctx.warn(
            "cloud.gcp: no 'locations' option set; Vertex AI and Dialogflow CX were queried only in "
            f"the default locations ({', '.join(self.locations)}). Resources in other locations were "
            "not scanned. Set 'locations' to a list to change the scope",
            incomplete=False,
        )

    def _collect_vertex(self, project: str) -> Iterator[dict[str, Any]]:
        for loc in self.locations:
            base = f"https://{loc}-aiplatform.googleapis.com/v1/projects/{project}/locations/{loc}"
            listed = yield from self._listing(
                self._pages(f"{base}/reasoningEngines", "reasoningEngines"),
                _kind="reasoning-engine",
                _project=project,
                _location=loc,
            )
            if self._catalogs:
                yield self._coverage(project, loc, VERTEX_CATALOG, "reasoningEngines", "v1", listed)
            for ep in self._pages(f"{base}/endpoints", "endpoints"):
                yield {**ep, "_kind": "vertex-endpoint", "_project": project, "_location": loc}

    def _project_number(self, project: str) -> Iterator[dict[str, Any]]:
        """The project's number, so registry names that carry it can be compared with ids."""
        number = self._project_numbers.get(project)
        if number is None:
            data = self._get(f"https://cloudresourcemanager.googleapis.com/v1/projects/{project}")
            if data is None:
                return  # _get has already recorded the failure
            found = data.get("projectNumber") if isinstance(data, dict) else None
            if (
                not isinstance(data, dict)
                or data.get("projectId") != project
                or not isinstance(found, str)
                or not is_number(found)
            ):
                self.ctx.warn(f"cloud.gcp: invalid project response for {project}; project number unknown")
                return
            number = self._project_numbers[project] = found
        yield {"_kind": PROJECT_NUMBER_KIND, "_project": project, "project_number": number}

    def _collect_discovery_engines(self, project: str) -> Iterator[dict[str, Any]]:
        for loc in _DISCOVERY_LOCATIONS:
            host = _api_host("discoveryengine", loc)
            for collection in self.discovery_collections:
                url = f"https://{host}/v1/projects/{project}/locations/{loc}/collections/{collection}/engines"
                engines: list[dict[str, Any]] = []
                listed = yield from self._listing(
                    self._pages(url, "engines"),
                    sink=engines,
                    _kind="discovery-engine",
                    _project=project,
                    _location=loc,
                )
                if not self.gemini_enterprise:
                    continue
                yield self._coverage(project, loc, GE_REGISTRY, "engines", "v1", listed, parent=collection)
                for engine in engines:
                    # Search and recommendation engines have no assistants; asking would fail.
                    if is_ge_app(engine):
                        yield from self._collect_gemini_enterprise(project, loc, collection, engine)

    def _collect_gemini_enterprise(
        self, project: str, loc: str, collection: str, engine: dict[str, Any]
    ) -> Iterator[dict[str, Any]]:
        """The agents of one Gemini Enterprise app (v1alpha; the listing shows the caller's agents)."""
        name = engine.get("name")
        scope = engine_scope(name)
        if (
            scope is None
            or scope[1:] != (loc, collection)
            or scope[0]
            not in {
                project,
                self._project_numbers.get(project),
            }
        ):
            self.ctx.warn(
                f"cloud.gcp: invalid Discovery Engine engine name in {project}; "
                "Gemini Enterprise coverage unknown"
            )
            return
        engine_name = str(name)
        host = _api_host("discoveryengine", loc)
        associated = engine.get("associatedAgentRegistry")
        assistants, complete = self._drain(
            self._pages(f"https://{host}/v1alpha/{engine_name}/assistants", "assistants", pageSize=1000)
        )
        for assistant in assistants:
            assistant_name = assistant.get("name")
            if not is_assistant_of(assistant_name, engine_name):
                self.ctx.warn(
                    f"cloud.gcp: invalid Gemini Enterprise assistant name in {project}; coverage unknown"
                )
                complete = False
                continue
            listed = yield from self._listing(
                self._pages(f"https://{host}/v1alpha/{assistant_name}/agents", "agents", pageSize=1000),
                normalize=normalize_ge_agent,
                _kind=GE_AGENT_KIND,
                _project=project,
                _location=loc,
                _engine=engine_name,
                _assistant=assistant_name,
                _agent_registry=associated if isinstance(associated, str) and associated else None,
            )
            yield self._coverage(
                project, loc, GE_REGISTRY, "agents", "v1alpha", listed, scope="caller", parent=assistant_name
            )
        yield self._coverage(project, loc, GE_REGISTRY, "assistants", "v1alpha", complete, parent=engine_name)

    def _collect_agent_registry(self, project: str) -> Iterator[dict[str, Any]]:
        """Agent Registry agents, MCP servers and endpoints (plus skills and publishers in v1alpha)."""
        version = self.agent_registry_version
        base = f"https://agentregistry.googleapis.com/{version}/projects/{project}"
        locations = self.agent_registry_locations
        if locations is None:
            found, complete = self._drain(self._pages(f"{base}/locations", "locations"))
            locations = []
            for item in found:
                location = item.get("locationId")
                if not valid_location(location):
                    self.ctx.warn(
                        f"cloud.gcp: invalid Agent Registry location for {project}; coverage unknown"
                    )
                    complete = False
                elif location not in locations:
                    locations.append(location)
            # Only an enumerated location list can show that no registry location was missed.
            yield self._coverage(
                project, None, AR_REGISTRY, "locations", version, complete, locations=locations
            )
        collections = {**AR_COLLECTIONS, **(AR_ALPHA_COLLECTIONS if version == "v1alpha" else {})}
        for loc in locations:
            for collection, kind in collections.items():
                listed = yield from self._listing(
                    self._pages(f"{base}/locations/{loc}/{collection}", collection, pageSize=100),
                    normalize=partial(normalize_ar_item, collection),
                    _kind=kind,
                    _project=project,
                    _location=loc,
                    _api_version=version,
                )
                yield self._coverage(project, loc, AR_REGISTRY, collection, version, listed)

    def _collect_cloud_run(self, project: str) -> Iterator[dict[str, Any]]:
        # Cloud Run v2 services.list rejects the '-' wildcard. Enumerate
        # project-visible locations through the documented v1 locations API.
        seen_locations: set[str] = set()
        locations = self._pages(f"https://run.googleapis.com/v1/projects/{project}/locations", "locations")
        for location in locations:
            run_location = location.get("locationId")
            if not isinstance(run_location, str) or not _RUN_LOCATION.fullmatch(run_location):
                self.ctx.warn(f"cloud.gcp: invalid Cloud Run location for {project}; coverage unknown")
                continue
            if run_location in seen_locations:
                continue
            seen_locations.add(run_location)
            url = f"https://run.googleapis.com/v2/projects/{project}/locations/{run_location}/services"
            for svc in self._pages(url, "services"):
                yield {**svc, "_kind": "cloud-run-service", "_project": project, "_location": run_location}

    def _collect_iam_policy(self, project: str) -> Iterator[dict[str, Any]]:
        assert self.http
        url = f"https://cloudresourcemanager.googleapis.com/v1/projects/{project}:getIamPolicy"
        try:
            policy = self.http.post_json(url, json={"options": {"requestedPolicyVersion": 3}})
            if not isinstance(policy, dict) or "error" in policy:
                self._attest(url, "failed")
                self.ctx.warn(f"cloud.gcp: invalid IAM policy response for {project}")
            else:
                self._attest(url, "ok")
                yield {
                    "_kind": "iam-policy",
                    "_project": project,
                    "version": policy.get("version"),
                    "bindings": policy.get("bindings", []),
                }
        except (HttpError, RequestException, ValueError) as exc:
            self._attest(url, failure_outcome(exc))
            self.ctx.warn(f"cloud.gcp: IAM policy not readable for {project} ({failure_summary(exc)})")

    def _collect_service_accounts(self, project: str) -> Iterator[dict[str, Any]]:
        url = f"https://iam.googleapis.com/v1/projects/{project}/serviceAccounts"
        for sa in self._pages(url, "accounts"):
            name = sa.get("name")
            if not isinstance(name, str) or not _SERVICE_ACCOUNT_NAME.fullmatch(name):
                self.ctx.warn(
                    f"cloud.gcp: invalid service account identifier for {project}; coverage unknown"
                )
                continue
            keys = self._get(f"https://iam.googleapis.com/v1/{name}/keys", keyTypes="USER_MANAGED")
            key_list = keys.get("keys", []) if isinstance(keys, dict) and "error" not in keys else None
            count: int | None = None
            if isinstance(key_list, list) and all(isinstance(key, dict) for key in key_list):
                count = len(key_list)
            complete = count is not None
            if not complete:
                self.ctx.warn(
                    f"cloud.gcp: service account key inventory unavailable for {name}; coverage unknown"
                )
            # Access-denied and malformed responses must not be reported as zero keys.
            yield {
                **sa,
                "_kind": "service-account",
                "_project": project,
                "user_managed_keys": count,
                "key_coverage": "observed" if complete else "unknown",
            }

    def _collect_audit(self, project: str) -> Iterator[dict[str, Any]]:
        assert self.http
        since = (datetime.now(UTC) - timedelta(days=self.audit_days)).isoformat()
        body = {
            "resourceNames": [f"projects/{project}"],
            "filter": _audit_filter(since),
            "pageSize": 1000,
            "orderBy": "timestamp desc",
        }
        token: str | None = None
        seen: set[str] = set()
        url = "https://logging.googleapis.com/v2/entries:list"
        for _ in range(min(50, self.max_pages)):
            if token:
                body["pageToken"] = token
            try:
                data = self.http.post_json(url, json=body)
            except (HttpError, RequestException) as exc:
                self._attest(url, failure_outcome(exc), project)
                self.ctx.warn(f"cloud.gcp: audit logs not readable for {project} ({failure_summary(exc)})")
                return
            if not isinstance(data, dict) or "error" in data or not isinstance(data.get("entries", []), list):
                self._attest(url, "failed", project)
                self.ctx.warn(f"cloud.gcp: invalid audit log response for {project}")
                return
            self._attest(url, "ok", project)
            for e in data.get("entries", []):
                if not isinstance(e, dict) or not isinstance(e.get("protoPayload") or {}, dict):
                    self.ctx.warn(f"cloud.gcp: invalid audit log entry for {project}")
                    continue
                pp = e.get("protoPayload") or {}
                yield {
                    "_kind": "audit-event",
                    "_project": project,
                    "principal": get_path(pp, "authenticationInfo.principalEmail"),
                    "method": pp.get("methodName"),
                    "resource": pp.get("resourceName"),
                    "timestamp": e.get("timestamp"),
                    "userAgent": get_path(pp, "requestMetadata.callerSuppliedUserAgent"),
                    "ip": get_path(pp, "requestMetadata.callerIp"),
                    "delegation": get_path(pp, "authenticationInfo.serviceAccountDelegationInfo"),
                }
            token = self._next_page_token(
                data, seen, warn=f"cloud.gcp: invalid or repeated audit pagination token for {project}"
            )
            if token is None:
                return
        self._attest(url, "truncated", project)
        self.ctx.warn(f"cloud.gcp: audit pagination limit reached for {project}")

    # -------------------------------------------------------------- analyze
    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        callers: dict[tuple[str | None, str], dict[str, Any]] = {}
        # Registry records are completed after every record is read: their bindings, coverage
        # and listing completeness depend on observed resources and coverage records anywhere
        # in the stream.
        catalogs = RegistryCatalogs()
        dispatch = RecordDispatch(self, "audit-event", *EXTRA_KINDS)
        for rec in records:
            kind = dispatch.kind(rec)
            if kind is None:
                catalogs.taint()
                continue
            try:
                if kind == "audit-event":
                    for field in _AUDIT_TEXT_FIELDS:
                        if rec.get(field) is not None and not isinstance(rec[field], str):
                            raise ValueError("event field")
                    self._acc_caller(callers, rec)
                    continue
                if kind in EXTRA_KINDS:
                    catalogs.add(kind, rec)
                    continue
                if kind in RECORD_KINDS:
                    catalogs.defer(*self._registry_finding(kind, rec))
                    continue
                result = dispatch.handlers[kind](rec)
                if isinstance(result, Finding):
                    catalogs.observe(kind, rec, result)
                    yield result
                elif result:
                    yield from result
            except RECORD_ERRORS:
                # An unread record may be the agent or listing a completeness claim overlooks.
                catalogs.taint()
                dispatch.invalid()
        for (_, principal), agg in callers.items():
            try:
                yield self._caller_finding(principal, agg)
            except RECORD_ERRORS:
                self.ctx.warn("cloud.gcp: invalid aggregated caller fields")
        if self.offline and self.ctx.stats is not None and self.ctx.stats.incomplete:
            # The offline loader drops what it cannot read (an invalid JSON line, a provider
            # error record, a skipped file) before analysis sees it; live collection writes
            # such gaps into its coverage records instead.
            catalogs.taint()
        findings = catalogs.finish()
        if catalogs.foreign:
            self.ctx.warn(
                f"cloud.gcp: {catalogs.foreign} registry record(s) name a project other than the "
                "one they were listed in; registry claims not comparable"
            )
        # Warned after the replay check above: these gaps already void the claims of the listings
        # they concern, so a replay keeps the claims live analysis made about the others.
        if catalogs.unrecognized:
            self.ctx.warn(
                "cloud.gcp: Agent Registry runtime reference to Vertex AI or Dialogflow not recognized; "
                "that registry's listing is not complete"
            )
        if self.offline and catalogs.failed_listings:
            # Live collection warned when the listing failed; the export only records that it did.
            self.ctx.warn("cloud.gcp: registry catalog listing incomplete in export; records may be missing")
        yield from findings

    @staticmethod
    def _acc_caller(callers: dict[tuple[str | None, str], dict[str, Any]], rec: dict[str, Any]) -> None:
        # One principal may call multiple projects. Preserve the
        # resource project as part of each observation's identity.
        resource = re.sub(r"projects/[^/]+/", "", str(rec.get("resource") or ""))[:120]
        agg = aggregate_caller_event(
            callers,
            (rec.get("_project"), rec.get("principal") or "unknown"),
            time=rec.get("timestamp"),
            tally={"methods": rec.get("method"), "resources": resource},
            tally_present={"agents": rec.get("userAgent")},
            seed={"project": rec.get("_project"), "delegated": False},
        )
        if rec.get("delegation"):
            agg["delegated"] = True

    def _h_project(self, rec: dict[str, Any]) -> Finding | None:
        services = rec.get("ai_services") or []
        if not services:
            return None
        f = cloud_finding(
            self.name,
            "gcp",
            kind=Kind.CLOUD_RESOURCE,
            title=(
                f"AI APIs enabled in project {rec.get('project')}: "
                f"{', '.join(AI_SERVICES.get(s, s) for s in services)}"
            ),
            resource=f"projects/{rec.get('project')}/ai-apis",
            resource_type="enabled-apis",
            account=rec.get("project"),
        )
        for s in services:
            if s == "aiplatform.googleapis.com":
                f.add_model_provider("provider.google-vertex-ai")
            elif s == "generativelanguage.googleapis.com":
                f.add_model_provider("provider.google-gemini")
            elif s in {"dialogflow.googleapis.com", "discoveryengine.googleapis.com"}:
                f.add_framework("cloud.gcp-vertex-agent-engine")
        f.add_evidence(
            Evidence(
                signal="gcp:enabled-apis",
                description=f"Enabled: {', '.join(services)}",
                weight=0.3,
            )
        )
        f.metadata["services"] = services
        return done(f, self.index, Kind.CLOUD_RESOURCE)

    def _h_reasoning_engine(self, rec: dict[str, Any]) -> Finding:
        name = rec.get("name", "")
        f = cloud_finding(
            self.name,
            "gcp",
            kind=Kind.AGENT,
            title=f"Vertex AI Agent Engine: {rec.get('displayName') or name.rsplit('/', 1)[-1]}",
            resource=name,
            resource_type="reasoning-engine",
            account=rec.get("_project"),
            region=rec.get("_location"),
            first_seen=rec.get("createTime"),
            last_seen=rec.get("updateTime"),
        )
        f.add_framework("cloud.gcp-vertex-agent-engine")
        f.add_model_provider("provider.google-vertex-ai")
        f.add_capability("tool-use")
        spec = rec.get("spec") or {}
        pkg = spec.get("packageSpec") or {}
        deps = str(pkg.get("requirementsGcsUri") or "")
        class_methods = spec.get("classMethods") or []
        agent_framework = str(
            spec.get("agentFramework") or get_path(spec, "deploymentSpec.agentFramework") or ""
        )
        for key, sig in _AGENT_FRAMEWORK_HINTS:
            if key in agent_framework.lower():
                f.add_framework(sig)
        f.add_evidence(
            Evidence(
                signal="gcp:reasoning-engine",
                description=(
                    f"Agent Engine '{rec.get('displayName')}' framework={agent_framework or 'unknown'}, "
                    f"{len(class_methods)} exposed method(s), python {pkg.get('pythonVersion')}: "
                    f"{truncate(rec.get('description'), 120)}"
                ),
                location=name,
                weight=0.97,
                signature="cloud.gcp-vertex-agent-engine",
            )
        )
        name_hint(self.index, f, rec.get("displayName"), rec.get("description"))
        f.metadata.update(
            {
                "framework": agent_framework,
                "class_methods": [m.get("name") for m in class_methods if isinstance(m, dict)][:20],
                "requirements": deps,
                "python": pkg.get("pythonVersion"),
                "description": truncate(rec.get("description"), 300),
            }
        )
        identity = spec.get("effectiveIdentity")
        if isinstance(identity, str) and identity:
            # The identity the engine runs as; Agent Registry names it as a runtime principal.
            f.metadata["effective_identity"] = identity
        return done(f, self.index, Kind.AGENT)

    def _h_vertex_endpoint(self, rec: dict[str, Any]) -> Finding | None:
        models = rec.get("deployedModels") or []
        if not models:
            return None
        name = rec.get("name", "")
        f = cloud_finding(
            self.name,
            "gcp",
            kind=Kind.CLOUD_RESOURCE,
            title=f"Vertex AI endpoint: {rec.get('displayName')}",
            resource=name,
            resource_type="vertex-endpoint",
            account=rec.get("_project"),
            region=rec.get("_location"),
            first_seen=rec.get("createTime"),
            last_seen=rec.get("updateTime"),
        )
        f.add_model_provider("provider.google-vertex-ai")
        f.add_evidence(
            Evidence(
                signal="gcp:vertex-endpoint",
                description=(
                    f"Endpoint '{rec.get('displayName')}' serves {len(models)} model(s): "
                    f"{', '.join(str(m.get('displayName') or m.get('model')) for m in models[:5])}"
                ),
                location=name,
                weight=0.5,
            )
        )
        f.models = [str(m.get("model")) for m in models][:10]
        apply_matches(f, model_matches(self.index, *f.models), weight_scale=0.5)
        return done(f, self.index, Kind.CLOUD_RESOURCE)

    def _h_dialogflow_agent(self, rec: dict[str, Any]) -> Finding:
        name = rec.get("name", "")
        f = cloud_finding(
            self.name,
            "gcp",
            kind=Kind.AGENT,
            title=f"Dialogflow CX agent: {rec.get('displayName')}",
            resource=name,
            resource_type="dialogflow-cx-agent",
            account=rec.get("_project"),
            region=rec.get("_location"),
        )
        f.add_framework("cloud.gcp-vertex-agent-engine")
        gen = rec.get("genAppBuilderSettings") or rec.get("generativeSettings") or {}
        f.add_evidence(
            Evidence(
                signal="gcp:dialogflow",
                description=(
                    f"Dialogflow CX agent '{rec.get('displayName')}' ({rec.get('defaultLanguageCode')}), "
                    f"generative settings: {bool(gen)}, playbooks: {rec.get('startPlaybook') is not None}"
                ),
                location=name,
                weight=0.9,
                signature="cloud.gcp-vertex-agent-engine",
            )
        )
        if gen or rec.get("startPlaybook"):
            f.add_capability("tool-use")
        f.metadata.update(
            {
                "description": truncate(rec.get("description")),
                "generative": bool(gen),
                "start_playbook": rec.get("startPlaybook"),
                "enable_stackdriver_logging": rec.get("enableStackdriverLogging"),
            }
        )
        return done(f, self.index, Kind.AGENT)

    def _h_discovery_engine(self, rec: dict[str, Any]) -> Finding:
        name = rec.get("name", "")
        solution = rec.get("solutionType")
        # A Gemini Enterprise app (appType APP_TYPE_INTRANET) keeps the kind of its solution type:
        # its agents are the Gemini Enterprise records, which never bind the engine itself.
        f = cloud_finding(
            self.name,
            "gcp",
            kind=Kind.AGENT if solution in _CHAT_SOLUTIONS else Kind.CLOUD_RESOURCE,
            title=f"Vertex AI Search / Agentspace engine: {rec.get('displayName')}",
            resource=name,
            resource_type="discovery-engine",
            account=rec.get("_project"),
            region=rec.get("_location"),
            first_seen=rec.get("createTime"),
            last_seen=rec.get("updateTime"),
        )
        f.add_framework("cloud.gcp-vertex-agent-engine")
        f.add_capability("rag")
        f.add_evidence(
            Evidence(
                signal="gcp:discovery-engine",
                description=(
                    f"Engine '{rec.get('displayName')}' type {solution} industry "
                    f"{rec.get('industryVertical')} "
                    f"data stores {', '.join(rec.get('dataStoreIds') or [])[:200]}"
                ),
                location=name,
                weight=0.85,
                signature="cloud.gcp-vertex-agent-engine",
            )
        )
        f.metadata.update({"solution_type": solution, "data_stores": rec.get("dataStoreIds")})
        extra = {
            "app_type": rec.get("appType"),
            "associated_agent_registry": rec.get("associatedAgentRegistry"),
            "subscription_tier": get_path(rec, "searchEngineConfig.requiredSubscriptionTier"),
        }
        f.metadata.update({key: value for key, value in extra.items() if isinstance(value, str) and value})
        return done(f, self.index, f.kind)

    # ------------------------------------------------------------ registry records
    def _h_agent_registry_agent(self, rec: dict[str, Any]) -> Finding:
        return self._standalone_record("agent-registry-agent", rec)

    def _h_agent_registry_mcp_server(self, rec: dict[str, Any]) -> Finding:
        return self._standalone_record("agent-registry-mcp-server", rec)

    def _h_agent_registry_endpoint(self, rec: dict[str, Any]) -> Finding:
        return self._standalone_record("agent-registry-endpoint", rec)

    def _h_agent_registry_skill(self, rec: dict[str, Any]) -> Finding:
        return self._standalone_record("agent-registry-skill", rec)

    def _h_gemini_enterprise_agent(self, rec: dict[str, Any]) -> Finding:
        return self._standalone_record(GE_AGENT_KIND, rec)

    def _standalone_record(self, kind: str, rec: dict[str, Any]) -> Finding:
        """A record finding completed from its own record alone (``analyze`` completes it from the scan)."""
        catalogs = RegistryCatalogs()
        catalogs.defer(*self._registry_finding(kind, rec))
        (finding,) = catalogs.finish()
        return finding

    def _registry_finding(self, kind: str, rec: dict[str, Any]) -> tuple[Finding, RecordEntry]:
        """A registry record finding (its ``registry_record`` is written by ``RegistryCatalogs``)."""
        rec = bound_strings(rec)
        entry = record_entry(kind, rec)
        finding_kind, label = _RECORD_FINDINGS[kind]
        display = rec.get("displayName") or entry.name.rsplit("/", 1)[-1]
        f = cloud_finding(
            self.name,
            "gcp",
            kind=finding_kind,
            title=f"{label}: {display}",
            resource=entry.name,
            resource_type=kind,
            account=entry.project,
            region=entry.location,
            first_seen=rec.get("createTime"),
            last_seen=rec.get("updateTime"),
        )
        card = clean_card(rec.get("agent_card"))
        metadata: dict[str, Any] = {
            "evidence_class": EVIDENCE_GROUP,
            "description": truncate(rec.get("description"), 300),
        }
        if entry.registry == GE_REGISTRY:
            detail = self._gemini_enterprise_metadata(f, rec, metadata)
        else:
            detail = self._agent_registry_metadata(f, kind, rec, metadata)
        if card is not None:
            metadata["agent_card"] = card
            if not card["security_schemes"]:
                f.add_tag("no-auth-declared")
        description = f"{label} '{display}': {detail}"
        f.add_evidence(registry_evidence(entry.registry, description, location=entry.name))
        f.metadata.update(metadata)
        return done(f, self.index, finding_kind), entry

    def _agent_registry_metadata(
        self, f: Finding, kind: str, rec: dict[str, Any], metadata: dict[str, Any]
    ) -> str:
        framework = rec.get("framework")
        for key, sig in _AGENT_FRAMEWORK_HINTS:
            if framework and key in framework.lower():
                f.add_framework(sig)
        reference = rec.get("runtime_reference")
        # Only a well-formed Vertex AI reasoning engine reference, never a URI that merely
        # contains the service name somewhere, attributes the record to Agent Engine.
        runtime = runtime_reference(reference)
        if runtime is not None and runtime.kind == "reasoning-engine":
            f.add_framework("cloud.gcp-vertex-agent-engine")
        metadata.update(
            api_version=rec.get("_api_version"),
            runtime_reference=reference,
            runtime_identity=rec.get("runtime_identity"),
        )
        if kind == "agent-registry-agent":
            protocols = [
                {
                    "type": truncate(protocol.get("type"), 64),
                    "protocol_version": truncate(protocol.get("protocol_version"), 32),
                    "urls": urls(*(protocol.get("urls") or [])),
                }
                for protocol in rec.get("protocols") or []
            ][:10]
            metadata.update(
                agent_id=rec.get("agentId"),
                framework=framework,
                version=rec.get("version"),
                hosting_location=rec.get("hosting_location"),
                skills=clean_texts(rec.get("skills")),
                protocols=protocols,
            )
            types = sorted({str(protocol["type"]) for protocol in protocols if protocol["type"]})
            return f"protocols {', '.join(types) or 'unknown'}, framework {framework or 'unknown'}"
        if kind == "agent-registry-skill":
            metadata.update(
                skill_type=rec.get("type"),
                state=rec.get("state"),
                target_state=rec.get("targetState"),
                publisher=rec.get("publisher"),
                license=rec.get("license"),
            )
            return f"state {rec.get('state') or 'unknown'}"
        metadata["urls"] = urls(*(rec.get("urls") or []))
        if kind == "agent-registry-endpoint":
            metadata["endpoint_id"] = rec.get("endpointId")
            return f"{len(metadata['urls'])} interface(s)"
        tools = clean_tools(rec.get("tools"))
        metadata.update(mcp_server_id=rec.get("mcpServerId"), tools=tools)
        if tools:
            f.add_capability("tool-use")
        destructive = sum(tool["destructive"] is True for tool in tools)
        return f"{len(tools)} tool(s), {destructive} marked destructive"

    def _gemini_enterprise_metadata(self, f: Finding, rec: dict[str, Any], metadata: dict[str, Any]) -> str:
        definition = rec.get("definition")
        if definition in {"adk", "dialogflow"}:
            f.add_framework("cloud.gcp-vertex-agent-engine")
        if definition == "adk":
            f.add_framework("framework.google-adk")
        auth = rec.get("auth_config") or {}
        agent_auth = auth.get("agent_auth_required") is True
        tool_grants = _count(auth.get("tool_auth_grants"))
        if agent_auth or tool_grants:
            # The app passes the user's OAuth tokens to the agent and its tools.
            f.add_capability("delegated-identity")
        status = rec.get("agent_card_status")
        if status in {"invalid", "too-large"}:
            self.ctx.warn(
                f"cloud.gcp: Gemini Enterprise agent card not readable ({status}); card coverage unknown"
            )
        observability = rec.get("observability") or {}
        metadata.update(
            state=rec.get("state"),
            reasons=[str(reason)[:32] for reason in rec.get("reasons") or []][:4],
            sharing_scope=rec.get("sharing_scope"),
            definition=definition,
            reasoning_engine=rec.get("reasoning_engine"),
            dialogflow_agent=rec.get("dialogflow_agent"),
            agent_card_status=status if isinstance(status, str) else None,
            marketplace=rec.get("marketplace") is True,
            auth_config={"agent_auth_required": agent_auth, "tool_auth_grants": tool_grants},
            observability={
                key: observability.get(key) if isinstance(observability.get(key), bool) else None
                for key in ("enabled", "sensitive_logging")
            },
            engine=rec.get("_engine"),
            assistant=rec.get("_assistant"),
            associated_agent_registry=rec.get("_agent_registry"),
            language_code=rec.get("languageCode"),
        )
        return (
            f"state {rec.get('state') or 'unknown'}, {definition or 'unknown'} definition, "
            f"sharing {rec.get('sharing_scope') or 'unknown'}"
        )

    def _h_cloud_run_service(self, rec: dict[str, Any]) -> Finding | None:
        name = rec.get("name", "")
        tmpl = rec.get("template") or {}
        f = cloud_finding(
            self.name,
            "gcp",
            kind=Kind.CLOUD_RESOURCE,
            title=f"Cloud Run service: {name.rsplit('/', 1)[-1]}",
            resource=name,
            resource_type="cloud-run-service",
            account=rec.get("_project"),
            region=_location(name),
            first_seen=rec.get("createTime"),
            last_seen=rec.get("updateTime"),
        )
        for c in tmpl.get("containers") or []:
            if c.get("image"):
                apply_matches(f, self.index.match_image(c["image"]), location=name)
            env = {e.get("name"): e.get("value") for e in c.get("env") or [] if e.get("name")}
            scan_env(self.index, f, env, location=name)
            for e in c.get("env") or []:
                if e.get("valueSource") and e.get("name"):
                    apply_matches(f, self.index.match_env(e["name"]), location=name, weight_scale=0.6)
        name_hint(self.index, f, name.rsplit("/", 1)[-1], rec.get("description"))
        if not f.frameworks and not f.model_providers:
            return None
        images = ", ".join(str(c.get("image")) for c in tmpl.get("containers") or [])[:200]
        f.add_evidence(
            Evidence(
                signal="gcp:cloud-run",
                description=(
                    f"Service '{name.rsplit('/', 1)[-1]}' images {images}; "
                    f"service account {tmpl.get('serviceAccount')}; ingress {rec.get('ingress')}"
                ),
                location=rec.get("uri") or name,
                weight=0.25,
            )
        )
        if rec.get("ingress") == "INGRESS_TRAFFIC_ALL":
            f.add_tag("public-ingress")
        f.owner = (
            first_tag(rec.get("labels"), "owner", "team") or rec.get("lastModifier") or rec.get("creator")
        )
        f.metadata.update(
            {
                "service_account": tmpl.get("serviceAccount"),
                "uri": rec.get("uri"),
                "ingress": rec.get("ingress"),
                "images": [c.get("image") for c in tmpl.get("containers") or []],
                "labels": rec.get("labels"),
            }
        )
        return done(f, self.index, Kind.CLOUD_RESOURCE)

    def _h_cloud_function(self, rec: dict[str, Any]) -> Finding | None:
        name = rec.get("name", "")
        svc = rec.get("serviceConfig") or {}
        f = cloud_finding(
            self.name,
            "gcp",
            kind=Kind.CLOUD_RESOURCE,
            title=f"Cloud Function: {name.rsplit('/', 1)[-1]}",
            resource=name,
            resource_type="cloud-function",
            account=rec.get("_project"),
            region=_location(name),
            last_seen=rec.get("updateTime"),
        )
        scan_env(self.index, f, svc.get("environmentVariables"), location=name)
        for s in svc.get("secretEnvironmentVariables") or []:
            apply_matches(f, self.index.match_env(str(s.get("key"))), location=name, weight_scale=0.6)
        name_hint(self.index, f, name.rsplit("/", 1)[-1], rec.get("description"))
        if not f.frameworks and not f.model_providers:
            return None
        f.add_evidence(
            Evidence(
                signal="gcp:cloud-function",
                description=(
                    f"Function '{name.rsplit('/', 1)[-1]}' runtime {get_path(rec, 'buildConfig.runtime')} "
                    f"service account {svc.get('serviceAccountEmail')} ingress {svc.get('ingressSettings')}; "
                    f"trigger {get_path(rec, 'eventTrigger.eventType') or 'https'}"
                ),
                location=svc.get("uri") or name,
                weight=0.25,
            )
        )
        if rec.get("eventTrigger"):
            # Autonomy: initiation evidence (an event starts the function; metadata.trigger names
            # the event type), not approval-bypass evidence.
            f.add_capability("autonomous")
        f.metadata.update(
            {
                "runtime": get_path(rec, "buildConfig.runtime"),
                "service_account": svc.get("serviceAccountEmail"),
                "trigger": get_path(rec, "eventTrigger.eventType"),
                "uri": svc.get("uri"),
                "labels": rec.get("labels"),
            }
        )
        return done(f, self.index, Kind.CLOUD_RESOURCE)

    def _h_iam_policy(self, rec: dict[str, Any]) -> Iterator[Finding]:
        project = rec.get("_project")
        per_member: dict[str, list[str]] = {}
        member_bindings: dict[str, list[dict[str, Any]]] = {}
        degraded_members: set[str] = set()
        bindings = rec.get("bindings", [])
        if not isinstance(bindings, list):
            self.ctx.warn("cloud.gcp: invalid IAM bindings; coverage incomplete")
            return
        for b in bindings:
            if not isinstance(b, dict) or not isinstance(b.get("role"), str) or not b["role"].strip():
                self.ctx.warn("cloud.gcp: invalid IAM role binding; coverage incomplete")
                continue
            role = b["role"]
            members = b.get("members")
            if not isinstance(members, list) or not members:
                self.ctx.warn("cloud.gcp: IAM binding has no valid members; coverage incomplete")
                continue
            valid_members = [m for m in members if isinstance(m, str) and m.strip()]
            if len(valid_members) != len(members):
                self.ctx.warn("cloud.gcp: invalid IAM binding member; coverage incomplete")
            condition = b.get("condition")
            invalid_condition = "condition" in b and (
                not isinstance(condition, dict)
                or not isinstance(condition.get("expression"), str)
                or not condition["expression"].strip()
            )
            if invalid_condition:
                self.ctx.warn("cloud.gcp: invalid IAM condition; coverage incomplete")
            # Version 1 replaces conditional role names with *_withcond_<hash>
            # and removes their conditions. Retain potential access evidence,
            # but disclose that the constraint was not collected.
            degraded = "_withcond_" in role
            canonical_role = role.split("_withcond_", 1)[0] if degraded else role
            if degraded:
                self.ctx.warn("cloud.gcp: conditional IAM binding has no condition; coverage incomplete")
            if self.index.match_scope(canonical_role) or canonical_role in _BROAD_ROLES:
                for m in valid_members:
                    per_member.setdefault(m, []).append(role)
                    binding: dict[str, Any] = {"role": role}
                    if "condition" in b:
                        if invalid_condition:
                            degraded_members.add(m)
                        else:
                            binding["condition"] = condition
                    if degraded:
                        degraded_members.add(m)
                        binding["condition_coverage"] = "unknown"
                    member_bindings.setdefault(m, []).append(binding)
        for member, roles in per_member.items():
            roles = sorted(set(roles))
            canonical_roles = [role.split("_withcond_", 1)[0] for role in roles]
            broad_roles = sorted({role for role in canonical_roles if role in _BROAD_ROLES})
            f = cloud_finding(
                self.name,
                "gcp",
                kind=Kind.IAM_GRANT,
                title=f"IAM member with AI or broad project access in {project}: {member}",
                resource=f"projects/{project}/iam/{member}",
                resource_type="iam-binding",
                account=project,
                surface=Surface.IDENTITY,
            )
            llm = scan_iam_actions(self.index, f, canonical_roles, location=f"projects/{project}")
            f.permissions = roles
            if not llm and not broad_roles:
                continue
            f.add_evidence(
                Evidence(
                    signal="gcp:iam",
                    description=(
                        f"Recorded IAM bindings for {member}: {', '.join(roles)}, subject to any "
                        "conditions (not evaluated)"
                    ),
                    weight=0.45 if member.startswith("serviceAccount:") else 0.25,
                )
            )
            if broad_roles:
                f.add_tag("broad-project-access")
                f.add_evidence(
                    Evidence(
                        signal="gcp:iam-broad-role",
                        description=(
                            f"Broad project grant ({', '.join(broad_roles)}) can enable AI access, subject "
                            "to "
                            "applicable policies and service availability; this is access evidence, not "
                            "observed "
                            "AI execution."
                        ),
                        location=f"projects/{project}",
                        weight=0.25,
                    )
                )
            if member.startswith("serviceAccount:"):
                f.add_tag("service-account")
            if member.startswith(("allUsers", "allAuthenticatedUsers")):
                f.add_tag("public-principal")
            name_hint(self.index, f, member)
            f.metadata.update(
                {
                    "member": member,
                    "roles": roles,
                    "broad_roles": broad_roles,
                    "evidence_class": "access-grant",
                    "policy_version": rec.get("version"),
                    "iam_bindings": member_bindings[member],
                    "condition_coverage": "unknown" if member in degraded_members else "observed",
                }
            )
            yield done(f, self.index, Kind.IAM_GRANT)

    def _h_service_account(self, rec: dict[str, Any]) -> Finding | None:
        email = rec.get("email", "")
        f = cloud_finding(
            self.name,
            "gcp",
            kind=Kind.SERVICE_IDENTITY,
            title=f"Service account: {email}",
            resource=rec.get("name") or email,
            resource_type="service-account",
            account=rec.get("_project"),
            surface=Surface.IDENTITY,
        )
        name_hint(self.index, f, rec.get("displayName"), rec.get("description"), email.split("@")[0])
        if not f.frameworks:
            return None
        keys = rec.get("user_managed_keys")
        keys_known = (
            isinstance(keys, int)
            and not isinstance(keys, bool)
            and keys >= 0
            and rec.get("key_coverage") != "unknown"
        )
        key_description = (
            f"{keys} user-managed key(s)" if keys_known else "unknown user-managed key inventory"
        )
        f.add_evidence(
            Evidence(
                signal="gcp:service-account",
                description=(
                    f"Service account '{rec.get('displayName') or email}' with {key_description}; "
                    f"disabled={rec.get('disabled', False)}"
                ),
                weight=0.35,
            )
        )
        if isinstance(keys, int) and keys_known and keys > 0:
            f.add_tag("user-managed-keys")
        f.metadata.update(
            {
                "email": email,
                "keys": keys if keys_known else None,
                "key_coverage": "observed" if keys_known else "unknown",
                "disabled": rec.get("disabled"),
            }
        )
        return done(f, self.index, Kind.SERVICE_IDENTITY)

    def _h_api_key(self, rec: dict[str, Any]) -> Finding | None:
        targets = [t.get("service") for t in (rec.get("restrictions") or {}).get("apiTargets") or []]
        ai_targets = [t for t in targets if t in AI_SERVICES]
        unrestricted = not targets
        if not ai_targets and not unrestricted:
            return None
        scope = "for " + ", ".join(AI_SERVICES[t] for t in ai_targets) if ai_targets else "(unrestricted)"
        f = cloud_finding(
            self.name,
            "gcp",
            kind=Kind.SECRET,
            title=f"API key {scope}: {rec.get('displayName') or rec.get('uid')}",
            resource=str(rec.get("name") or rec.get("uid") or ""),
            resource_type="api-key",
            account=rec.get("_project"),
            first_seen=rec.get("createTime"),
            last_seen=rec.get("updateTime"),
        )
        if _uses(ai_targets, "generativelanguage.googleapis.com") or unrestricted:
            f.add_model_provider("provider.google-gemini")
        if _uses(ai_targets, "aiplatform.googleapis.com"):
            f.add_model_provider("provider.google-vertex-ai")
        f.add_evidence(
            Evidence(
                signal="gcp:api-key",
                description=(
                    f"API key '{rec.get('displayName')}' restricted to "
                    f"{', '.join(targets) or 'nothing (all APIs)'}"
                ),
                weight=0.5 if ai_targets else 0.25,
            )
        )
        if unrestricted:
            f.add_tag("unrestricted-api-key")
        restrictions = rec.get("restrictions") or {}
        f.metadata.update(
            {
                "targets": targets,
                "browser_restrictions": bool(restrictions.get("browserKeyRestrictions")),
                "server_restrictions": bool(restrictions.get("serverKeyRestrictions")),
            }
        )
        return done(f, self.index, Kind.SECRET)

    def _h_secret_name(self, rec: dict[str, Any]) -> Finding | None:
        name = str(rec.get("name", "")).rsplit("/", 1)[-1]
        matches = credential_name_matches(self.index, name, _LLM_SECRET_KEYWORDS)
        if matches is None:
            return None
        f = cloud_finding(
            self.name,
            "gcp",
            kind=Kind.SECRET,
            title=f"Secret Manager secret for LLM provider: {name}",
            resource=rec.get("name") or name,
            resource_type="secret-manager-secret",
            account=rec.get("_project"),
            first_seen=rec.get("createTime"),
        )
        apply_matches(f, matches, weight_scale=0.7)
        f.add_evidence(
            Evidence(
                signal="gcp:secret",
                description=f"Secret '{name}' looks like an LLM provider credential (name only)",
                weight=0.4,
            )
        )
        f.add_tag("managed-secret")
        f.metadata["labels"] = rec.get("labels")
        return done(f, self.index, Kind.SECRET)

    def _is_service_account_principal(self, principal: str) -> bool:
        raw = (principal or "").strip().lower()
        if not raw:
            return False
        if ":" in raw:
            raw = raw.split(":", 1)[1]
        host = raw
        if "@" in host:
            host = host.rsplit("@", 1)[1]
        elif "://" in host:
            parsed = urlsplit(host)
            host = parsed.hostname or ""
        host = host.strip(".")
        return host == "gserviceaccount.com" or host.endswith(".gserviceaccount.com")

    def _caller_finding(self, principal: str, agg: dict[str, Any]) -> Finding:
        f = cloud_finding(
            self.name,
            "gcp",
            kind=Kind.GATEWAY_CALLER,
            title=f"Vertex AI caller: {principal} — {agg['events']} call(s)",
            resource=f"audit:{principal}",
            resource_type="caller/principal",
            account=agg.get("project"),
            first_seen=agg["first"],
            last_seen=agg["last"],
            surface=Surface.GATEWAY,
        )
        f.add_model_provider("provider.google-vertex-ai")
        for ua in list(agg["agents"])[:10]:
            apply_matches(f, self.index.match_user_agent(ua))
        f.models = sorted(agg["resources"], key=lambda r: -agg["resources"][r])[:10]
        methods = ", ".join(f"{k}×{v}" for k, v in list(agg["methods"].items())[:5])
        is_service_account = self._is_service_account_principal(principal)
        f.add_evidence(
            Evidence(
                signal="gcp:audit",
                description=f"{agg['events']} call(s) ({methods}) by {principal}",
                weight=0.45 if is_service_account else 0.25,
            )
        )
        if is_service_account:
            f.add_tag("service-account")
        if agg.get("delegated"):
            f.add_tag("delegation")
            f.add_capability("delegated-identity")
        if any("reasoningEngines" in r for r in agg["resources"]):
            f.add_framework("cloud.gcp-vertex-agent-engine")
        name_hint(self.index, f, principal)
        f.metadata.update(
            {
                "principal": principal,
                "events": agg["events"],
                "methods": agg["methods"],
                "resources": dict(sorted(agg["resources"].items(), key=lambda kv: -kv[1])[:10]),
                "user_agents": dict(sorted(agg["agents"].items(), key=lambda kv: -kv[1])[:5]),
            }
        )
        return done(f, self.index, Kind.GATEWAY_CALLER)
