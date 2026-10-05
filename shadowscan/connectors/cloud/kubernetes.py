"""Offline Kubernetes and OpenShift workload inventory analysis."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from typing import Any, ClassVar

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.connectors.common import apply_matches, finalize
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.utils.redaction import sanitize_text

_AI_IMAGE_MARKERS = (
    "ollama/ollama",
    "vllm/vllm-openai",
    "ggerganov/llama.cpp",
    "text-generation-inference",
    "localai",
    "lmstudio",
    "litellm",
    "langgraph",
    "flowise",
    "dify",
    "open-webui",
    "mcp/",
    "mcp-server",
    "kagent",
)
_AI_RESOURCE_NAME = re.compile(r"(?:llm|model|agent|mcp|inference|ollama|vllm)", re.IGNORECASE)
_ENV_MARKERS = ("API_KEY", "TOKEN", "BASE_URL", "ENDPOINT", "MODEL")
_RECOGNIZED = {
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "Job",
    "CronJob",
    "Pod",
    "Service",
    "Ingress",
    "ServiceAccount",
    "RoleBinding",
    "ClusterRoleBinding",
    "NetworkPolicy",
    "InferenceService",
    "ServingRuntime",
    "RayService",
    "Agent",
    "ToolServer",
    "ModelConfig",
    "Notebook",
    "LeaderWorkerSet",
}
_OPENSHIFT = {
    "DeploymentConfig",
    "Route",
    "ImageStream",
    "DataScienceCluster",
    "DSCInitialization",
    "DataSciencePipelinesApplication",
    "OdhDashboardConfig",
}
_AI_RESOURCE_KINDS = {
    "InferenceService",
    "ServingRuntime",
    "RayService",
    "Agent",
    "ToolServer",
    "ModelConfig",
    "Notebook",
    "LeaderWorkerSet",
    "DataScienceCluster",
    "DSCInitialization",
    "DataSciencePipelinesApplication",
    "OdhDashboardConfig",
}
_WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "DeploymentConfig"}
_MAX_OBJECTS = 10_000


def _name(obj: dict[str, Any]) -> str:
    metadata = obj.get("metadata")
    if not isinstance(metadata, dict):
        return ""
    value = metadata.get("name")
    return value[:160] if isinstance(value, str) else ""


def _namespace(obj: dict[str, Any]) -> str:
    metadata = obj.get("metadata")
    if not isinstance(metadata, dict):
        return "default"
    value = metadata.get("namespace", "default")
    return value[:160] if isinstance(value, str) else "default"


def _kind(obj: dict[str, Any]) -> str:
    value = obj.get("kind")
    return value[:100] if isinstance(value, str) else ""


def _workload_images(obj: dict[str, Any]) -> list[str]:
    spec = obj.get("spec")
    if not isinstance(spec, dict):
        return []
    template = spec.get("template", spec)
    if not isinstance(template, dict):
        return []
    pod_spec = template.get("spec", template)
    if not isinstance(pod_spec, dict):
        return []
    containers = pod_spec.get("containers", [])
    if not isinstance(containers, list):
        return []
    return [
        image[:300]
        for container in containers[:100]
        if isinstance(container, dict) and isinstance((image := container.get("image")), str) and image
    ]


class KubernetesConnector(BaseConnector):
    name = "cloud.kubernetes"
    surface = Surface.CLOUD
    provider = "kubernetes"
    description = "Analyze Kubernetes workload and control-plane inventory exports."
    offline_formats = "kubectl get -o json List envelope / JSONL / YAML export"
    config_keys: ClassVar[dict[str, str]] = {
        "cluster": "Required stable cluster label for offline resource identities.",
        "input": "Offline kubectl JSON / JSONL / YAML inventory export.",
    }

    def __init__(self, ctx: ConnectorContext) -> None:
        super().__init__(ctx)
        self.cluster = ctx.get("cluster")

    def collect(self) -> Iterable[dict[str, Any]]:
        raise ConnectorError(
            "cloud.kubernetes: live API collection is unavailable; provide an offline kubectl export"
        )

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        cluster = self.cluster
        if not isinstance(cluster, str) or not cluster.strip():
            raise ConnectorError("cloud.kubernetes: cluster is required for offline resource identity")
        accepted: list[dict[str, Any]] = []
        egress_policies: set[str] = set()
        for record in records:
            if "items" in record:
                items = record["items"]
                if not isinstance(items, list):
                    self.ctx.warn("cloud.kubernetes: malformed object list")
                    continue
                for item in items:
                    if len(accepted) >= _MAX_OBJECTS:
                        self.ctx.warn("cloud.kubernetes: object limit reached")
                        break
                    if not isinstance(item, dict):
                        self.ctx.warn("cloud.kubernetes: malformed object")
                        continue
                    accepted.append(item)
                if len(accepted) >= _MAX_OBJECTS:
                    break
                continue
            if len(accepted) >= _MAX_OBJECTS:
                self.ctx.warn("cloud.kubernetes: object limit reached")
                break
            accepted.append(record)
        for obj in accepted:
            if _kind(obj) == "NetworkPolicy":
                spec = obj.get("spec") if isinstance(obj.get("spec"), dict) else {}
                policy_types = spec.get("policyTypes", []) if isinstance(spec, dict) else []
                if isinstance(spec, dict) and (
                    (isinstance(policy_types, list) and "Egress" in policy_types) or "egress" in spec
                ):
                    egress_policies.add(_namespace(obj))
        for obj in accepted:
            kind = _kind(obj)
            if kind not in _RECOGNIZED | (_OPENSHIFT if self.name == "cloud.openshift" else set()):
                continue
            metadata_value = obj.get("metadata")
            if not isinstance(metadata_value, dict):
                self.ctx.warn(f"{self.name}: object has malformed metadata")
                continue
            resource_name = _name(obj)
            if not resource_name:
                self.ctx.warn(f"{self.name}: object without metadata.name")
                continue
            namespace = _namespace(obj)
            spec_value = obj.get("spec")
            if spec_value is not None and not isinstance(spec_value, dict):
                self.ctx.warn(f"{self.name}: object has malformed spec")
                continue
            workload_spec = spec_value if isinstance(spec_value, dict) else {}
            if kind in _WORKLOAD_KINDS and not isinstance(workload_spec.get("template"), dict):
                self.ctx.warn(f"{self.name}: workload has malformed pod template")
                continue
            if kind in _WORKLOAD_KINDS:
                pod_template = workload_spec["template"]
                if not isinstance(pod_template.get("spec"), dict):
                    self.ctx.warn(f"{self.name}: workload has malformed pod spec")
                    continue
            if kind == "Pod" and not isinstance(spec_value, dict):
                self.ctx.warn(f"{self.name}: pod has malformed spec")
                continue
            images = _workload_images(obj)
            selected = [
                image for image in images if any(marker in image.lower() for marker in _AI_IMAGE_MARKERS)
            ]
            tags: list[str] = []
            capabilities: list[str] = []
            if selected:
                tags.append("ai-workload")
            template = workload_spec.get("template")
            pod_spec_value = (
                template.get("spec", {})
                if isinstance(template, dict)
                else workload_spec
                if kind == "Pod"
                else {}
            )
            pod_spec = pod_spec_value if isinstance(pod_spec_value, dict) else {}
            if "containers" in pod_spec and not isinstance(pod_spec["containers"], list):
                self.ctx.warn(f"{self.name}: workload has malformed containers")
                continue
            if "imagePullSecrets" in pod_spec and not isinstance(pod_spec["imagePullSecrets"], list):
                self.ctx.warn(f"{self.name}: workload has malformed image pull secrets")
                continue
            if pod_spec.get("hostNetwork") is True:
                tags.append("privileged-pod")
            pod_security = pod_spec.get("securityContext")
            if isinstance(pod_security, dict) and pod_security.get("privileged") is True:
                tags.append("privileged-pod")
            containers = pod_spec.get("containers", [])
            if isinstance(containers, list):
                if len(containers) > 100:
                    self.ctx.warn(f"{self.name}: container limit reached")
                for container in containers[:100]:
                    if not isinstance(container, dict):
                        self.ctx.warn(f"{self.name}: malformed container")
                        continue
                    if "image" in container and not isinstance(container["image"], str):
                        self.ctx.warn(f"{self.name}: container has malformed image")
                    security = container.get("securityContext")
                    if isinstance(security, dict) and security.get("privileged") is True:
                        tags.append("privileged-pod")
                    envs = container.get("env", [])
                    if not isinstance(envs, list):
                        self.ctx.warn(f"{self.name}: workload has malformed environment")
                        continue
                    if len(envs) > 1000:
                        self.ctx.warn(f"{self.name}: environment limit reached")
                    for env in envs[:1000]:
                        if not isinstance(env, dict):
                            self.ctx.warn(f"{self.name}: workload has malformed environment entry")
                            continue
                        key = env.get("name")
                        if isinstance(key, str) and any(marker in key.upper() for marker in _ENV_MARKERS):
                            tags.append("provider-config-present")
                    resources = container.get("resources")
                    requests = resources.get("requests") if isinstance(resources, dict) else {}
                    if isinstance(requests, dict) and requests.get("nvidia.com/gpu"):
                        tags.append("gpu-workload")
            volumes = pod_spec.get("volumes", [])
            if not isinstance(volumes, list):
                self.ctx.warn(f"{self.name}: workload has malformed volumes")
                continue
            if len(volumes) > 100:
                self.ctx.warn(f"{self.name}: volume limit reached")
            if any(isinstance(volume, dict) and "hostPath" in volume for volume in volumes[:100]):
                tags.append("privileged-pod")
            if kind in {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod"} and selected:
                if namespace not in egress_policies:
                    tags.append("no-egress-policy")
            if kind == "Service":
                svc_type = workload_spec.get("type")
                metadata = obj.get("metadata")
                labels = metadata.get("labels", {}) if isinstance(metadata, dict) else {}
                selector = workload_spec.get("selector", {})
                service_context = " ".join(
                    [
                        resource_name,
                        (json.dumps(labels, sort_keys=True, default=str) if isinstance(labels, dict) else ""),
                        (
                            json.dumps(selector, sort_keys=True, default=str)
                            if isinstance(selector, dict)
                            else ""
                        ),
                    ]
                )
                if svc_type in {"LoadBalancer", "NodePort"} and _AI_RESOURCE_NAME.search(service_context):
                    tags.append("exposed-llm-server")
            exposure_context = " ".join(
                (
                    resource_name,
                    str(workload_spec.get("backend", "")),
                    str(workload_spec.get("to", "")),
                )
            )
            if kind in {"Ingress", "Route"} and _AI_RESOURCE_NAME.search(exposure_context):
                tags.append("exposed-llm-server")
            if kind in {"RoleBinding", "ClusterRoleBinding"}:
                role_ref = obj.get("roleRef")
                subjects = obj.get("subjects", [])
                if (
                    isinstance(role_ref, dict)
                    and role_ref.get("name") == "cluster-admin"
                    and isinstance(subjects, list)
                    and any(
                        isinstance(subject, dict) and subject.get("kind") == "ServiceAccount"
                        for subject in subjects
                    )
                ):
                    tags.append("cluster-admin")
            if kind in {"Agent", "ToolServer"}:
                capabilities.append("tool-use")
            if not tags and not selected and kind not in _AI_RESOURCE_KINDS:
                self.ctx.examined()
                continue
            if len(selected) > 20:
                self.ctx.warn(f"{self.name}: reported image limit reached")
            resource = f"k8s:{cluster}/{namespace}/{kind}/{resource_name}"
            finding = Finding(
                surface=Surface.CLOUD,
                connector=self.name,
                kind=Kind.AGENT if selected or kind in _AI_RESOURCE_KINDS else Kind.CLOUD_RESOURCE,
                title=f"Kubernetes {kind} {resource_name}",
                resource=resource,
                resource_type=f"kubernetes/{kind}",
                provider="kubernetes",
                account=sanitize_text(cluster)[:160],
                confidence=0.8 if selected else 0.65,
                tags=list(dict.fromkeys(tags)),
                capabilities=capabilities,
                metadata={"namespace": namespace, "images": selected[:20]},
            )
            finding.add_evidence(
                Evidence(
                    signal=f"kubernetes:{kind}",
                    description=f"Exported Kubernetes {kind} resource",
                    weight=0.75,
                )
            )
            image_matches = [match for image in selected for match in self.index.match_image(image)]
            apply_matches(finding, image_matches, weight_scale=0.75)
            self.ctx.examined()
            yield finalize(finding, self.index)


class OpenShiftConnector(KubernetesConnector):
    name = "cloud.openshift"
    provider = "openshift"
    description = "Analyze Kubernetes, OpenShift, and OpenShift AI inventory exports."
