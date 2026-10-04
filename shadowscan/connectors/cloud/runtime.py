"""Offline-first Kubernetes, OpenShift, and runtime-flow connectors.

Live mode shells out to ``kubectl`` or ``oc`` with a fixed argument list. It
does not install a DaemonSet, load an eBPF program, or mutate the cluster.
Missing binaries, RBAC, or exports mark the scan incomplete or raise
ConnectorError before any finding is treated as complete coverage.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections.abc import Iterable, Iterator
from typing import Any, ClassVar

from shadowscan.connectors.base import BaseConnector, ConnectorError
from shadowscan.connectors.common import apply_matches, blob_matches, finalize, model_matches, name_matches
from shadowscan.models import Evidence, Finding, Kind, Surface

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
_AI_IMAGE = re.compile(
    r"ollama|vllm|sglang|llama[-.]?cpp|text-generation|localai|xinference|"
    r"open-webui|flowise|langflow|dify|agentgateway|mcp|bedrock-agent|"
    r"inference-service|kserve|openvino|nim|tgi",
    re.I,
)
_GGUF = re.compile(r"\.gguf\b", re.I)
_MCP = re.compile(r"\bmcp\b|modelcontextprotocol", re.I)
_MAX_OBJECTS = 5000
_K8S_RESOURCES = (
    "pods",
    "deployments",
    "jobs",
    "cronjobs",
    "services",
    "configmaps",
)
_OPENSHIFT_RESOURCES = _K8S_RESOURCES + (
    "routes",
    "imagestreams",
    "deployments.apps",
    "servingruntimes.serving.kserve.io",
    "inferenceservices.serving.kserve.io",
)


def _token(value: Any, name: str) -> str:
    text = str(value or "").strip()
    if not text or not _NAME.match(text):
        raise ConnectorError(f"{name} must be a single DNS-like token")
    return text


def _texts(obj: Any) -> list[str]:
    found: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, str):
            found.append(value)
        elif isinstance(value, dict):
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(obj)
    return found


def _containers(record: dict[str, Any]) -> list[dict[str, Any]]:
    spec = record.get("spec") if isinstance(record.get("spec"), dict) else {}
    template = spec.get("template") if isinstance(spec.get("template"), dict) else {}
    pod_spec = template.get("spec") if isinstance(template.get("spec"), dict) else spec
    containers = pod_spec.get("containers") if isinstance(pod_spec, dict) else None
    if not isinstance(containers, list):
        containers = record.get("containers") if isinstance(record.get("containers"), list) else []
    return [item for item in containers if isinstance(item, dict)]


class KubernetesConnector(BaseConnector):
    """Read-only Kubernetes workload inventory for AI agents, MCP, and local models."""

    name: ClassVar[str] = "cloud.kubernetes"
    surface: ClassVar[Surface] = Surface.CLOUD
    provider: ClassVar[str | None] = "kubernetes"
    description: ClassVar[str] = (
        "Kubernetes pods, jobs, and services that look like AI agents, MCP servers, "
        "Ollama/vLLM/llama.cpp, or GGUF model mounts. Offline JSON first; live mode "
        "is a read-only kubectl list."
    )
    config_keys: ClassVar[dict[str, str]] = {
        "input": "offline: kubectl/oc JSON or JSONL export",
        "context": "live: kubeconfig context name",
        "namespace": "live: namespace (default all namespaces)",
        "binary": "live: kubectl binary name (default kubectl)",
        "max_objects": "maximum workload objects examined (default 5000)",
    }
    offline_formats: ClassVar[str] = "kubectl JSON list, JSONL workload objects"
    resources: ClassVar[tuple[str, ...]] = _K8S_RESOURCES

    def collect(self) -> Iterable[dict[str, Any]]:
        binary = str(self.ctx.get("binary") or "kubectl")
        if not _NAME.match(binary) or shutil.which(binary) is None:
            raise ConnectorError(
                f"{self.name}: live mode needs {binary} on PATH; pass input for an offline export"
            )
        namespace = self.ctx.get("namespace")
        context = self.ctx.get("context")
        if namespace:
            namespace = _token(namespace, "namespace")
        if context:
            context = _token(context, "context")
        limit = int(self.ctx.get("max_objects") or _MAX_OBJECTS)
        emitted = 0
        for resource in self.resources:
            self.ctx.check_deadline()
            command = [binary, "get", resource, "-o", "json"]
            if context:
                command.extend(["--context", context])
            command.extend(["-n", namespace] if namespace else ["-A"])
            try:
                completed = subprocess.run(
                    command,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                self.ctx.warn(f"{resource} list failed: {type(exc).__name__}")
                continue
            if completed.returncode != 0:
                self.ctx.warn(f"{resource} list was not readable (exit {completed.returncode})")
                continue
            try:
                payload = json.loads(completed.stdout or "{}")
            except json.JSONDecodeError:
                self.ctx.warn(f"{resource} list was not JSON")
                continue
            items = payload.get("items") if isinstance(payload, dict) else None
            if not isinstance(items, list):
                self.ctx.warn(f"{resource} list had no items array")
                continue
            for item in items:
                if emitted >= limit:
                    self.ctx.warn(f"object limit {limit} reached")
                    return
                if isinstance(item, dict):
                    emitted += 1
                    yield item

    def load_offline(self, path: str) -> Iterator[dict[str, Any]]:
        for record in super().load_offline(path):
            items = record.get("items") if isinstance(record, dict) else None
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict):
                        yield item
                continue
            if isinstance(record, dict):
                yield record

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        for record in records:
            self.ctx.examined()
            finding = self._finding(record)
            if finding is not None:
                yield finding

    def _finding(self, record: dict[str, Any]) -> Finding | None:
        meta = record.get("metadata") if isinstance(record.get("metadata"), dict) else {}
        name = str(meta.get("name") or record.get("name") or "unknown")
        namespace = str(meta.get("namespace") or record.get("namespace") or "default")
        kind = str(record.get("kind") or record.get("resource") or "Workload")
        images = [
            str(container.get("image"))
            for container in _containers(record)
            if container.get("image")
        ]
        blob = "\n".join(_texts(record)[:400])
        interesting = bool(_AI_IMAGE.search(blob) or _GGUF.search(blob) or _MCP.search(blob))
        matches = [
            *name_matches(self.index, name, blob[:500]),
            *blob_matches(self.index, blob[:8000]),
            *model_matches(self.index, *(images[:8])),
        ]
        if not interesting and not matches:
            return None
        resource = f"k8s:{namespace}/{kind}/{name}"
        finding = Finding(
            surface=self.surface,
            connector=self.name,
            kind=Kind.MCP_SERVER if _MCP.search(blob) else Kind.CLOUD_RESOURCE,
            title=f"{kind} {namespace}/{name}",
            resource=resource,
            resource_type=kind.lower(),
            provider=self.provider,
            account=namespace,
            owner=str(meta.get("owner") or "") or None,
        )
        if images:
            finding.add_evidence(
                Evidence(
                    signal="image:kubernetes",
                    description="container image " + images[0],
                    location=resource,
                    weight=0.7 if _AI_IMAGE.search(images[0]) else 0.4,
                )
            )
        if _GGUF.search(blob):
            finding.add_evidence(
                Evidence(
                    signal="file:gguf",
                    description="GGUF model artifact referenced by the workload",
                    location=resource,
                    weight=0.85,
                )
            )
            finding.add_model_provider("provider.llama-cpp")
            finding.add_tag("gguf")
        if _MCP.search(blob):
            finding.add_evidence(
                Evidence(
                    signal="protocol:mcp",
                    description="MCP annotation, port, or argument on the workload",
                    location=resource,
                    weight=0.8,
                )
            )
            finding.add_tag("mcp")
        apply_matches(finding, matches, location=resource)
        return finalize(finding, self.index)


class OpenShiftConnector(KubernetesConnector):
    """OpenShift and OpenShift AI / KServe resources, same read-only contract."""

    name: ClassVar[str] = "cloud.openshift"
    provider: ClassVar[str | None] = "openshift"
    description: ClassVar[str] = (
        "OpenShift Routes, ImageStreams, and KServe/OpenShift AI serving objects "
        "plus the Kubernetes workload types. Offline oc/kubectl JSON, or read-only oc."
    )
    resources: ClassVar[tuple[str, ...]] = _OPENSHIFT_RESOURCES

    def collect(self) -> Iterable[dict[str, Any]]:
        if not self.ctx.get("binary"):
            self.ctx.config["binary"] = "oc"
        return super().collect()


class RuntimeFlowConnector(BaseConnector):
    """Analyze exported eBPF or process-to-domain observations. No kernel probe."""

    name: ClassVar[str] = "cloud.runtime-flows"
    surface: ClassVar[Surface] = Surface.CLOUD
    provider: ClassVar[str | None] = "runtime-flows"
    description: ClassVar[str] = (
        "Offline analyzer for Tetragon process events and process-to-domain exports "
        "(AgentSonar-style). Does not load eBPF or require CAP_BPF."
    )
    config_keys: ClassVar[dict[str, str]] = {
        "input": "offline: Tetragon JSON/JSONL or process/domain records",
    }
    offline_formats: ClassVar[str] = "Tetragon JSON, process-domain JSONL"

    def collect(self) -> Iterable[dict[str, Any]]:
        raise ConnectorError(
            f"{self.name}: live capture is not implemented; export Tetragon or process-domain JSON and set input"
        )

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        for record in records:
            self.ctx.examined()
            process = record.get("process")
            domain = record.get("domain") or record.get("dst") or record.get("sni")
            binary = None
            pod = None
            if isinstance(process, dict):
                binary = process.get("binary") or process.get("name")
                pod = process.get("pod") if isinstance(process.get("pod"), dict) else None
            elif isinstance(process, str):
                binary = process
            exec_event = record.get("process_exec")
            if isinstance(exec_event, dict):
                inner = exec_event.get("process") if isinstance(exec_event.get("process"), dict) else {}
                binary = binary or inner.get("binary")
                pod = pod or (inner.get("pod") if isinstance(inner.get("pod"), dict) else None)
            blob = "\n".join(_texts(record)[:200])
            if not binary and not domain and not _AI_IMAGE.search(blob):
                continue
            name = str(binary or domain or "runtime-flow")
            ns = str((pod or {}).get("namespace") or record.get("namespace") or "host")
            resource = f"flow:{ns}/{name}/{domain or 'local'}"
            finding = Finding(
                surface=self.surface,
                connector=self.name,
                kind=Kind.GATEWAY_CALLER if domain else Kind.AGENT,
                title=f"Runtime flow {name} -> {domain or 'local'}",
                resource=resource,
                resource_type="runtime-flow",
                provider=self.provider,
                account=ns,
            )
            finding.add_evidence(
                Evidence(
                    signal="runtime:flow",
                    description=f"exported runtime observation for {name}",
                    location=resource,
                    weight=0.75 if domain else 0.55,
                )
            )
            if domain:
                finding.metadata["domain"] = str(domain)
            apply_matches(finding, blob_matches(self.index, blob[:8000]), location=resource)
            apply_matches(finding, name_matches(self.index, name, str(domain or "")), location=resource)
            yield finalize(finding, self.index)
