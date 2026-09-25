"""Oracle Cloud Infrastructure tenancy scanner (oci SDK).

Per region / compartment:

* Generative AI Agents (agents, endpoints, tools, knowledge bases), Digital Assistant instances
* Generative AI endpoints, dedicated AI clusters, custom models
* Data Science model deployments (LLM serving), Functions (config keys), Container Instances (images, env)
* IAM policies granting ``generative-ai*`` / ``oda*`` permissions (``iam-grant``), dynamic groups
* Vault secret names hinting LLM credentials

Auth: ``~/.oci/config`` profile (``profile``) or instance/resource principal (``auth: instance_principal``).
Offline export: JSONL of dumped records (``_kind`` per record).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from typing import Any, ClassVar

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.connectors.cloud.common import cloud_finding, done, name_hint, scan_env, string_list
from shadowscan.connectors.common import apply_matches, model_matches
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.utils.text import truncate

GENAI_POLICY_RX = re.compile(r"(?i)\b(?:allow)\b.*?\b(?:to\s+)?(manage|use|read|inspect)\s+(generative-ai[a-z-]*|oda[a-z-]*|data-science[a-z-]*|all-resources|ai-service[a-z-]*)\b")


def _resource_id(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("invalid OCI resource identifier")
    return value


class OciConnector(BaseConnector):
    name: ClassVar[str] = "cloud.oci"
    surface: ClassVar[Surface] = Surface.CLOUD
    provider: ClassVar[str | None] = "oci"
    requires: ClassVar[list[str]] = ["oci"]
    description: ClassVar[str] = "OCI Generative AI Agents, Digital Assistant, GenAI endpoints/clusters, Data Science deployments, Functions, Container Instances, IAM policies and Vault secret names."
    config_keys: ClassVar[dict[str, str]] = {
        "profile": "~/.oci/config profile (default DEFAULT)",
        "config_file": "path to OCI config (default ~/.oci/config)",
        "auth": "config | instance_principal | resource_principal (default config)",
        "allow_instance_credentials": "allow instance/resource principal credentials (default false; inherited from options)",
        "regions": "regions to scan (default: all subscribed)",
        "region": "session region for instance_principal auth (default: the signer's region); config auth uses the profile's region",
        "tenancy": "tenancy OCID (default: from the config profile or the principal signer)",
        "compartments": "compartment OCIDs (default: all active compartments in the tenancy)",
        "max_pages": "cap on pages per paginated list call, at least 1 (default 1000)",
        "input": "offline: JSONL dump of records",
    }
    offline_formats: ClassVar[str] = "JSONL dump of records"

    def __init__(self, ctx: ConnectorContext):
        super().__init__(ctx)
        self.max_pages = max(1, int(ctx.get("max_pages", 1000)))
        self._config: dict[str, Any] = {}
        self._signer: Any = None
        self._clients: dict[tuple[Any, str | None], Any] = {}
        try:
            self.compartments = string_list(ctx.get("compartments"), "compartments") or []
            self.regions = string_list(ctx.get("regions"), "regions", pattern=r"[a-z0-9-]+") or []
        except ValueError as exc:
            raise ConnectorError(f"cloud.oci: {exc}") from None
        self.tenancy: str | None = ctx.get("tenancy")

    # ------------------------------------------------------------- session
    def _init(self) -> None:
        import oci

        # A reused connector must not retain clients signed by an old session.
        self._clients.clear()
        auth = str(self.ctx.get("auth", "config"))
        if auth not in {"config", "instance_principal", "resource_principal"}:
            raise ConnectorError("cloud.oci: auth must be config, instance_principal or resource_principal")
        if auth != "config" and self.ctx.get("allow_instance_credentials", False) is not True:
            raise ConnectorError("cloud.oci: instance/resource credentials require options.allow_instance_credentials=true")
        if auth == "instance_principal":
            # SDK signer HTTP calls have finite transport timeouts; also bound
            # metadata certificate and federation token acquisition retries.
            self._signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner(
                retry_strategy=self._retry_strategy(),
                federation_client_retry_strategy=self._retry_strategy(),
            )
            self._config = {"region": self.ctx.get("region") or self._signer.region}
            self.tenancy = self.tenancy or self._signer.tenancy_id
        elif auth == "resource_principal":
            self._signer = oci.auth.signers.get_resource_principals_signer()
            self._config = {"region": self._signer.region}
            self.tenancy = self.tenancy or self._signer.tenancy_id
        else:
            self._config = oci.config.from_file(file_location=self.ctx.get("config_file", "~/.oci/config"), profile_name=self.ctx.get("profile", "DEFAULT"))
            self.tenancy = self.tenancy or self._config.get("tenancy")

    @staticmethod
    def _retry_strategy() -> Any:
        import oci

        return oci.retry.RetryStrategyBuilder(
            max_attempts=3, total_elapsed_time_seconds=120,
            retry_max_wait_between_calls_seconds=10,
        ).get_retry_strategy()

    def _client(self, cls: Any, region: str | None = None) -> Any:
        """One SDK client per (service, region); construction parses the signing key each time."""
        key = (cls, region)
        client = self._clients.get(key)
        if client is None:
            cfg = dict(self._config)
            if region:
                cfg["region"] = region
            kwargs: dict[str, Any] = {
                "timeout": (10, 30),
                "retry_strategy": self._retry_strategy(),
            }
            if self._signer:
                kwargs["signer"] = self._signer
            client = self._clients[key] = cls(cfg, **kwargs)
        return client

    def _all(self, fn: Any, *args: Any, **kwargs: Any) -> list[Any]:
        """Keep successful pages when a later OCI request fails or pagination stalls."""
        records: list[Any] = []
        seen: set[str] = set()
        operation = getattr(fn, "__name__", "list operation")
        for _ in range(self.max_pages):
            try:
                response = fn(*args, **kwargs)
                # OCI Response wraps either a list or a collection with .items.
                # Also accept direct collections returned by lightweight clients.
                data = getattr(response, "data", response)
                if isinstance(data, dict):
                    items = data.get("items")
                elif isinstance(data, (list, tuple)):
                    items = data
                else:
                    items = getattr(data, "items", None)
                if not isinstance(items, (list, tuple)):
                    self.ctx.warn(f"cloud.oci: invalid collection response for {operation}")
                    return records
                records.extend(items)
                if not getattr(response, "has_next_page", False):
                    return records
                token = getattr(response, "next_page", None)
                if not isinstance(token, str) or not token or token in seen:
                    self.ctx.warn(f"cloud.oci: invalid or repeated pagination token for {operation}")
                    return records
                seen.add(token)
                kwargs["page"] = token
            except Exception as exc:  # noqa: BLE001 - SDK errors must not erase successful pages
                status = getattr(exc, "status", None)
                detail = f"HTTP {status}" if isinstance(status, int) else type(exc).__name__
                self.ctx.warn(f"cloud.oci: {operation} collection failed ({detail})")
                return records
        self.ctx.warn(f"cloud.oci: pagination limit reached for {operation}")
        return records

    @staticmethod
    def _d(obj: Any) -> dict[str, Any]:
        import oci

        try:
            return oci.util.to_dict(obj)
        except Exception:  # noqa: BLE001
            return dict(getattr(obj, "__dict__", {}) or {})

    # -------------------------------------------------------------- collect
    def collect(self) -> Iterable[dict[str, Any]]:
        import oci

        self._init()
        identity = self._client(oci.identity.IdentityClient)
        compartments = list(self.compartments)
        if not compartments:
            compartments = [c for c in [self.tenancy] if c] + [c.id for c in self._all(identity.list_compartments, self.tenancy, compartment_id_in_subtree=True, lifecycle_state="ACTIVE")]
        regions = self.regions or [r.region_name for r in self._all(identity.list_region_subscriptions, self.tenancy)]
        yield {"_kind": "tenancy", "tenancy": self.tenancy, "compartments": len(compartments), "regions": regions}
        for pol in self._iter_policies(identity, compartments):
            yield pol
        for dg in self._all(identity.list_dynamic_groups, self.tenancy):
            yield {"_kind": "dynamic-group", **self._d(dg)}
        for region in regions:
            for comp in compartments:
                yield from self._collect_region_comp(region, comp)

    def _iter_policies(self, identity: Any, compartments: list[str]) -> Iterator[dict[str, Any]]:
        for comp in compartments:
            for p in self._all(identity.list_policies, comp):
                stmts = list(p.statements or [])
                if any(GENAI_POLICY_RX.search(s) for s in stmts):
                    yield {"_kind": "policy", "_compartment": comp, "id": p.id, "name": p.name, "description": p.description, "statements": stmts, "time_created": str(p.time_created), "lifecycle_state": p.lifecycle_state}

    def _collect_region_comp(self, region: str, comp: str) -> Iterator[dict[str, Any]]:
        import oci

        try:
            agents = self._client(oci.generative_ai_agent.GenerativeAiAgentClient, region)
            for a in self._all(agents.list_agents, compartment_id=comp):
                rec = self._d(a)
                rec.update({"_kind": "genai-agent", "_region": region, "_compartment": comp})
                if hasattr(agents, "list_tools"):
                    rec["_tools"] = [self._d(t) for t in self._all(agents.list_tools, compartment_id=comp, agent_id=a.id)]
                else:
                    self.ctx.warn("cloud.oci: list_tools unavailable in installed SDK", incomplete=True)
                    rec["_tools"] = []
                yield rec
            for e in self._all(agents.list_agent_endpoints, compartment_id=comp):
                yield {"_kind": "genai-agent-endpoint", "_region": region, "_compartment": comp, **self._d(e)}
            for kb in self._all(agents.list_knowledge_bases, compartment_id=comp):
                yield {"_kind": "genai-knowledge-base", "_region": region, "_compartment": comp, **self._d(kb)}
        except AttributeError:
            self.ctx.warn("cloud.oci: generative_ai_agent unavailable in installed SDK", incomplete=True)
        try:
            genai = self._client(oci.generative_ai.GenerativeAiClient, region)
            for ep in self._all(genai.list_endpoints, comp):
                yield {"_kind": "genai-endpoint", "_region": region, "_compartment": comp, **self._d(ep)}
            for cl in self._all(genai.list_dedicated_ai_clusters, comp):
                yield {"_kind": "genai-cluster", "_region": region, "_compartment": comp, **self._d(cl)}
            for m in self._all(genai.list_models, comp):
                d = self._d(m)
                if d.get("vendor") not in {"cohere", "meta", None} or "FINE_TUNE" in str(d.get("capabilities")) and d.get("base_model_id"):
                    if d.get("base_model_id"):
                        yield {"_kind": "genai-custom-model", "_region": region, "_compartment": comp, **d}
        except AttributeError:
            self.ctx.warn("cloud.oci: generative_ai unavailable in installed SDK", incomplete=True)
        try:
            oda = self._client(oci.oda.OdaClient, region)
            for inst in self._all(oda.list_oda_instances, comp):
                yield {"_kind": "oda-instance", "_region": region, "_compartment": comp, **self._d(inst)}
        except AttributeError:
            self.ctx.warn("cloud.oci: oda unavailable in installed SDK", incomplete=True)
        try:
            ds = self._client(oci.data_science.DataScienceClient, region)
            for md in self._all(ds.list_model_deployments, comp):
                yield {"_kind": "model-deployment", "_region": region, "_compartment": comp, **self._d(md)}
        except AttributeError:
            self.ctx.warn("cloud.oci: data_science unavailable in installed SDK", incomplete=True)
        try:
            fn = self._client(oci.functions.FunctionsManagementClient, region)
            yield from self._collect_functions(fn, region, comp)
        except AttributeError:
            self.ctx.warn("cloud.oci: functions unavailable in installed SDK", incomplete=True)
        try:
            ci = self._client(oci.container_instances.ContainerInstanceClient, region)
            for inst in self._all(ci.list_container_instances, comp):
                d = self._d(inst)
                containers = []
                for c in self._all(ci.list_containers, comp, container_instance_id=inst.id):
                    try:
                        cd = self._d(ci.get_container(c.id).data)
                    except Exception as exc:  # noqa: BLE001 - continue other containers
                        self.ctx.warn(f"cloud.oci: container detail collection failed ({type(exc).__name__})")
                        continue
                    containers.append({"display_name": cd.get("display_name"), "image_url": cd.get("image_url"), "environment_variables": cd.get("environment_variables") or {}})
                d["_containers"] = containers
                yield {"_kind": "container-instance", "_region": region, "_compartment": comp, **d}
        except AttributeError:
            self.ctx.warn("cloud.oci: container_instances unavailable in installed SDK", incomplete=True)
        try:
            vaults = self._client(oci.vault.VaultsClient, region)
            for s in self._all(vaults.list_secrets, comp):
                yield {"_kind": "secret-name", "_region": region, "_compartment": comp, "id": s.id, "secret_name": s.secret_name, "description": s.description, "time_created": str(s.time_created)}
        except AttributeError:
            self.ctx.warn("cloud.oci: vault unavailable in installed SDK", incomplete=True)

    def _function_detail(self, client: Any, kind: str, summary: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str], bool]:
        """List summaries omit config; retain known evidence when detail is denied."""
        try:
            detail = self._d(getattr(client, f"get_{kind}")(summary["id"]).data)
        except Exception as exc:  # noqa: BLE001 - detail failure must not erase listed functions
            status = getattr(exc, "status", None)
            reason = f"HTTP {status}" if isinstance(status, int) else type(exc).__name__
            self.ctx.warn(f"cloud.oci: {kind} detail collection failed ({reason}); configuration coverage unknown", incomplete=True)
            return summary, {}, False
        if not isinstance(detail, dict) or detail.get("id") != summary["id"] or "error" in detail:
            self.ctx.warn(f"cloud.oci: invalid {kind} detail response; configuration coverage unknown", incomplete=True)
            return summary, {}, False
        record = {**summary, **{key: value for key, value in detail.items() if key != "config" and value is not None}}
        config = detail.get("config")
        if "config" in detail and config is None:
            return record, {}, True
        if not isinstance(config, dict):
            self.ctx.warn(f"cloud.oci: invalid {kind} configuration; coverage unknown", incomplete=True)
            return record, {}, False
        valid = {key: value for key, value in config.items() if isinstance(key, str) and isinstance(value, str)}
        complete = len(valid) == len(config)
        if not complete:
            self.ctx.warn(f"cloud.oci: invalid {kind} configuration entries; coverage unknown", incomplete=True)
        return record, valid, complete

    def _collect_functions(self, client: Any, region: str, comp: str) -> Iterator[dict[str, Any]]:
        for app in self._all(client.list_applications, comp):
            app_summary = self._d(app)
            if not isinstance(app_summary, dict) or not isinstance(app_summary.get("id"), str) or not app_summary["id"].strip():
                self.ctx.warn("cloud.oci: invalid application summary; coverage unknown", incomplete=True)
                continue
            application, inherited, application_complete = self._function_detail(client, "application", app_summary)
            for func in self._all(client.list_functions, app_summary["id"]):
                summary = self._d(func)
                if not isinstance(summary, dict) or not isinstance(summary.get("id"), str) or not summary["id"].strip():
                    self.ctx.warn("cloud.oci: invalid function summary; coverage unknown", incomplete=True)
                    continue
                detail, overrides, function_complete = self._function_detail(client, "function", summary)
                # OCI passes application settings to every function; function settings win.
                # Environment-style storage redacts all configuration values in dumps.
                yield {**{k: v for k, v in detail.items() if k != "config"}, "environment": {**inherited, **overrides}, "_kind": "function", "_region": region,
                       "_compartment": comp, "_application": application.get("display_name"),
                       "_application_id": app_summary["id"],
                       "_config_coverage": {"application": "observed" if application_complete else "unknown",
                                            "function": "observed" if function_complete else "unknown"}}

    # -------------------------------------------------------------- analyze
    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        endpoints: dict[str, list[dict[str, Any]]] = {}
        agents: list[dict[str, Any]] = []
        others: list[dict[str, Any]] = []
        handlers = {name[3:].replace("_", "-"): getattr(self, name) for name in dir(type(self)) if name.startswith("_h_")}
        for rec in records:
            self.ctx.examined()
            kind = rec.get("_kind") if isinstance(rec, dict) else None
            if not isinstance(kind, str) or kind not in handlers.keys() | {"tenancy", "genai-agent", "genai-agent-endpoint"}:
                self.ctx.warn("cloud.oci: record has missing, invalid, or unsupported _kind")
                continue
            try:
                if kind == "tenancy":
                    if not isinstance(rec.get("tenancy"), str) or not rec["tenancy"]:
                        raise ValueError("tenancy")
                    self.tenancy = self.tenancy or rec["tenancy"]
                elif kind == "genai-agent":
                    agents.append(rec)
                elif kind == "genai-agent-endpoint":
                    if not isinstance(rec.get("agent_id"), str) or not rec["agent_id"]:
                        raise ValueError("agent_id")
                    endpoints.setdefault(rec["agent_id"], []).append(rec)
                else:
                    others.append(rec)
            except (ValueError, TypeError, KeyError, AttributeError):
                self.ctx.warn("cloud.oci: record has invalid fields for its _kind")
        for a in agents:
            try:
                yield self._agent_finding(a, endpoints.get(str(a.get("id")), []))
            except (ValueError, TypeError, KeyError, AttributeError):
                self.ctx.warn("cloud.oci: record has invalid agent fields")
        for rec in others:
            try:
                f = handlers[rec["_kind"]](rec)
                if f:
                    yield f
            except (ValueError, TypeError, KeyError, AttributeError):
                self.ctx.warn("cloud.oci: record has invalid fields for its _kind")

    def _base(self, rec: dict[str, Any]) -> dict[str, Any]:
        return {"account": rec.get("_compartment") or self.tenancy, "region": rec.get("_region"), "owner": ((rec.get("freeform_tags") or {}).get("owner") or (rec.get("freeform_tags") or {}).get("Owner") or ((rec.get("defined_tags") or {}).get("Oracle-Tags") or {}).get("CreatedBy")), "first_seen": rec.get("time_created"), "last_seen": rec.get("time_updated")}

    def _agent_finding(self, a: dict[str, Any], eps: list[dict[str, Any]]) -> Finding:
        f = cloud_finding(self.name, "oci", kind=Kind.AGENT, title=f"OCI Generative AI Agent: {a.get('display_name')}", resource=_resource_id(a.get("id") or a.get("display_name")), resource_type="genai-agent", **self._base(a))
        f.add_framework("cloud.oci-generative-ai-agents")
        f.add_model_provider("provider.oci-generative-ai")
        f.add_capability("tool-use")
        tools = a.get("_tools") or []
        tool_types = sorted({str(t.get("tool_config", {}).get("tool_config_type") if isinstance(t.get("tool_config"), dict) else t.get("type") or "?") for t in tools})
        f.add_evidence(Evidence(signal="oci:genai-agent", description=f"Agent '{a.get('display_name')}' ({a.get('lifecycle_state')}) with {len(a.get('knowledge_base_ids') or [])} knowledge base(s), {len(tools)} tool(s) [{', '.join(tool_types)}], {len(eps)} endpoint(s)", location=a.get("id"), weight=0.97, signature="cloud.oci-generative-ai-agents"))
        if a.get("knowledge_base_ids"):
            f.add_capability("rag")
        if any("SQL" in t or "FUNCTION" in t or "HTTP" in t for t in tool_types):
            f.add_capability("saas-actions")
        if any("FUNCTION" in t for t in tool_types):
            f.add_capability("code-exec")
        for ep in eps:
            if ep.get("should_enable_trace") is False:
                f.add_tag("tracing-disabled")
            if ep.get("content_moderation_config") in (None, {}) or (isinstance(ep.get("content_moderation_config"), dict) and not ep["content_moderation_config"].get("should_enable_on_input")):
                f.add_tag("no-content-moderation")
        name_hint(self.index, f, a.get("display_name"), a.get("description"))
        f.metadata.update({"state": a.get("lifecycle_state"), "description": truncate(a.get("description")), "knowledge_bases": a.get("knowledge_base_ids"), "tools": [{"name": t.get("display_name"), "type": (t.get("tool_config") or {}).get("tool_config_type") if isinstance(t.get("tool_config"), dict) else None} for t in tools][:30], "endpoints": [{"id": e.get("id"), "name": e.get("display_name"), "state": e.get("lifecycle_state"), "session": bool(e.get("session_config"))} for e in eps], "welcome_message": truncate(a.get("welcome_message"), 120), "tags": a.get("freeform_tags")})
        return done(f, self.index, Kind.AGENT)

    def _h_genai_knowledge_base(self, rec: dict[str, Any]) -> Finding:
        f = cloud_finding(self.name, "oci", kind=Kind.CLOUD_RESOURCE, title=f"OCI GenAI Agents knowledge base: {rec.get('display_name')}", resource=_resource_id(rec.get("id") or rec.get("display_name")), resource_type="genai-knowledge-base", **self._base(rec))
        f.add_framework("cloud.oci-generative-ai-agents")
        f.add_capability("rag")
        f.add_evidence(Evidence(signal="oci:knowledge-base", description=f"Knowledge base '{rec.get('display_name')}' ({rec.get('lifecycle_state')})", weight=0.6, signature="cloud.oci-generative-ai-agents"))
        return done(f, self.index, Kind.CLOUD_RESOURCE)

    def _h_genai_endpoint(self, rec: dict[str, Any]) -> Finding:
        f = cloud_finding(self.name, "oci", kind=Kind.CLOUD_RESOURCE, title=f"OCI Generative AI endpoint: {rec.get('display_name')}", resource=_resource_id(rec.get("id") or rec.get("display_name")), resource_type="genai-endpoint", **self._base(rec))
        f.add_model_provider("provider.oci-generative-ai")
        f.models = [str(rec.get("model_id"))] if rec.get("model_id") else []
        apply_matches(f, model_matches(self.index, rec.get("model_id")), weight_scale=0.4)
        f.add_evidence(Evidence(signal="oci:genai-endpoint", description=f"Dedicated endpoint '{rec.get('display_name')}' ({rec.get('lifecycle_state')}) for model {rec.get('model_id')} on cluster {rec.get('dedicated_ai_cluster_id')}", weight=0.6))
        f.metadata.update({"model_id": rec.get("model_id"), "cluster": rec.get("dedicated_ai_cluster_id"), "content_moderation": rec.get("content_moderation_config")})
        return done(f, self.index, Kind.CLOUD_RESOURCE)

    def _h_genai_cluster(self, rec: dict[str, Any]) -> Finding:
        f = cloud_finding(self.name, "oci", kind=Kind.CLOUD_RESOURCE, title=f"OCI dedicated AI cluster: {rec.get('display_name')}", resource=_resource_id(rec.get("id") or rec.get("display_name")), resource_type="genai-dedicated-cluster", **self._base(rec))
        f.add_model_provider("provider.oci-generative-ai")
        f.add_evidence(Evidence(signal="oci:genai-cluster", description=f"Dedicated AI cluster '{rec.get('display_name')}' type {rec.get('type')} units {rec.get('unit_count')} ({rec.get('lifecycle_state')})", weight=0.5))
        return done(f, self.index, Kind.CLOUD_RESOURCE)

    def _h_genai_custom_model(self, rec: dict[str, Any]) -> Finding:
        f = cloud_finding(self.name, "oci", kind=Kind.CLOUD_RESOURCE, title=f"OCI custom (fine-tuned) model: {rec.get('display_name')}", resource=_resource_id(rec.get("id") or rec.get("display_name")), resource_type="genai-custom-model", **self._base(rec))
        f.add_model_provider("provider.oci-generative-ai")
        f.add_evidence(Evidence(signal="oci:custom-model", description=f"Custom model '{rec.get('display_name')}' based on {rec.get('base_model_id')}", weight=0.5))
        return done(f, self.index, Kind.CLOUD_RESOURCE)

    def _h_oda_instance(self, rec: dict[str, Any]) -> Finding:
        f = cloud_finding(self.name, "oci", kind=Kind.AGENT, title=f"OCI Digital Assistant: {rec.get('display_name')}", resource=_resource_id(rec.get("id") or rec.get("display_name")), resource_type="oda-instance", **self._base(rec))
        f.add_framework("cloud.oci-generative-ai-agents")
        f.add_evidence(Evidence(signal="oci:oda", description=f"Digital Assistant instance '{rec.get('display_name')}' ({rec.get('lifecycle_state')}, shape {rec.get('shape_name')})", weight=0.85, signature="cloud.oci-generative-ai-agents"))
        return done(f, self.index, Kind.AGENT)

    def _h_model_deployment(self, rec: dict[str, Any]) -> Finding | None:
        f = cloud_finding(self.name, "oci", kind=Kind.CLOUD_RESOURCE, title=f"OCI Data Science model deployment: {rec.get('display_name')}", resource=_resource_id(rec.get("id") or rec.get("display_name")), resource_type="model-deployment", **self._base(rec))
        env = ((rec.get("model_deployment_configuration_details") or {}).get("environment_configuration_details") or {})
        image = env.get("image")
        if image:
            apply_matches(f, self.index.match_image(image), location=rec.get("id"))
        scan_env(self.index, f, env.get("environment_variables"), location=rec.get("id"))
        name_hint(self.index, f, rec.get("display_name"), rec.get("description"))
        llm = bool(f.frameworks or f.model_providers) or any(k in str(env).lower() for k in ("vllm", "tgi", "llm", "text-generation", "model_deploy_predict_endpoint"))
        if not llm:
            return None
        f.add_evidence(Evidence(signal="oci:model-deployment", description=f"Model deployment '{rec.get('display_name')}' ({rec.get('lifecycle_state')}) image {image or 'default'}", weight=0.5))
        f.metadata.update({"image": image, "model_id": (rec.get("model_deployment_configuration_details") or {}).get("model_configuration_details", {}).get("model_id")})
        return done(f, self.index, Kind.CLOUD_RESOURCE)

    def _h_function(self, rec: dict[str, Any]) -> Finding | None:
        f = cloud_finding(self.name, "oci", kind=Kind.CLOUD_RESOURCE, title=f"OCI Function: {rec.get('_application')}/{rec.get('display_name')}", resource=_resource_id(rec.get("id") or rec.get("display_name")), resource_type="function", **self._base(rec))
        config = rec.get("environment") if isinstance(rec.get("environment"), dict) else rec.get("config")
        scan_env(self.index, f, config, location=rec.get("id"))
        # New SDKs expose source_details.image; older SDKs / exports use image.
        source = rec.get("source_details")
        image = source.get("image") if isinstance(source, dict) else None
        image = image or rec.get("image")
        if image:
            apply_matches(f, self.index.match_image(image), location=rec.get("id"))
        name_hint(self.index, f, rec.get("display_name"))
        if not f.frameworks and not f.model_providers:
            return None
        f.add_evidence(Evidence(signal="oci:function", description=f"Function '{rec.get('display_name')}' image {image}", weight=0.25))
        f.metadata.update({"image": image, "application": rec.get("_application"), "config_keys": sorted((config or {}).keys())[:40]})
        if "_config_coverage" in rec:
            f.metadata["config_coverage"] = rec["_config_coverage"]
        return done(f, self.index, Kind.CLOUD_RESOURCE)

    def _h_container_instance(self, rec: dict[str, Any]) -> Finding | None:
        f = cloud_finding(self.name, "oci", kind=Kind.CLOUD_RESOURCE, title=f"OCI Container Instance: {rec.get('display_name')}", resource=_resource_id(rec.get("id") or rec.get("display_name")), resource_type="container-instance", **self._base(rec))
        for c in rec.get("_containers") or []:
            if c.get("image_url"):
                apply_matches(f, self.index.match_image(c["image_url"]), location=rec.get("id"))
            scan_env(self.index, f, c.get("environment_variables"), location=rec.get("id"))
        if not f.frameworks and not f.model_providers:
            return None
        f.add_evidence(Evidence(signal="oci:container-instance", description=f"Container instance '{rec.get('display_name')}' images {', '.join(str(c.get('image_url')) for c in rec.get('_containers') or [])[:200]}", weight=0.25))
        return done(f, self.index, Kind.CLOUD_RESOURCE)

    def _h_secret_name(self, rec: dict[str, Any]) -> Finding | None:
        name = str(rec.get("secret_name") or "")
        norm = "".join(ch if ch.isalnum() else "_" for ch in name).upper().strip("_")
        matches = self.index.match_env(norm)
        if not matches and not any(k in name.lower() for k in ("openai", "anthropic", "claude", "gemini", "llm", "genai", "cohere", "huggingface", "mistral", "langsmith", "langfuse")):
            return None
        f = cloud_finding(self.name, "oci", kind=Kind.SECRET, title=f"OCI Vault secret for LLM provider: {name}", resource=rec.get("id") or name, resource_type="vault-secret", **self._base(rec))
        apply_matches(f, matches, weight_scale=0.7)
        f.add_evidence(Evidence(signal="oci:vault-secret", description=f"Secret '{name}' looks like an LLM provider credential (name only)", weight=0.4))
        f.add_tag("managed-secret")
        return done(f, self.index, Kind.SECRET)

    def _h_policy(self, rec: dict[str, Any]) -> Finding:
        stmts = rec.get("statements") or []
        f = cloud_finding(self.name, "oci", kind=Kind.IAM_GRANT, title=f"OCI IAM policy granting AI permissions: {rec.get('name')}", resource=_resource_id(rec.get("id") or rec.get("name")), resource_type="iam-policy", account=rec.get("_compartment") or self.tenancy, first_seen=rec.get("time_created"), surface=Surface.IDENTITY)
        subjects: list[str] = []
        for s in stmts:
            m = GENAI_POLICY_RX.search(s)
            if m:
                verb, family = m.group(1).lower(), m.group(2).lower()
                apply_matches(f, self.index.match_scope(family) + self.index.match_scope(f"{verb} {family}"), weight_scale=0.6)
                subj = re.search(r"(?i)allow\s+(?:group|dynamic-group|service|any-user)\s+([^\s]+)", s)
                if subj:
                    subjects.append(subj.group(1))
                if family == "all-resources" and verb == "manage":
                    f.add_tag("wildcard-permissions")
        f.add_evidence(Evidence(signal="oci:policy", description=f"Policy '{rec.get('name')}' statements: {' | '.join(stmts)[:400]}", weight=0.45))
        if any("dynamic-group" in s.lower() for s in stmts):
            f.add_tag("workload-identity")
        f.permissions.extend(stmts[:20])
        f.metadata.update({"subjects": sorted(set(subjects)), "statements": stmts[:20], "description": rec.get("description")})
        return done(f, self.index, Kind.IAM_GRANT)

    def _h_dynamic_group(self, rec: dict[str, Any]) -> Finding | None:
        rule = str(rec.get("matching_rule") or "")
        name = rec.get("name") or ""
        f = cloud_finding(self.name, "oci", kind=Kind.SERVICE_IDENTITY, title=f"OCI dynamic group: {name}", resource=rec.get("id") or name, resource_type="dynamic-group", account=self.tenancy, surface=Surface.IDENTITY)
        name_hint(self.index, f, name, rec.get("description"))
        if not f.frameworks and not any(k in rule.lower() for k in ("genai", "generativeai", "datasciencemodeldeployment", "fnfunc", "computecontainerinstance")):
            return None
        f.add_evidence(Evidence(signal="oci:dynamic-group", description=f"Dynamic group '{name}' matching {truncate(rule, 200)}", weight=0.3))
        f.add_tag("workload-identity")
        f.metadata.update({"matching_rule": rule, "description": rec.get("description")})
        return done(f, self.index, Kind.SERVICE_IDENTITY)
