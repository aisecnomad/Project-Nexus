"""Offline Kubernetes workload inventory for shadow AI signals.

Reads kubectl-style JSON or JSONL exports. Does not talk to a cluster and does
not ship an eBPF probe. A missing export is an incomplete scan, not an empty cluster.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any, ClassVar

from shadowscan.connectors.base import BaseConnector, ConnectorError
from shadowscan.connectors.common import finalize
from shadowscan.models import Evidence, Finding, Kind, Surface

_AI_IMAGE = re.compile(
    r"(ollama/ollama|vllm|llama\.cpp|sglang|text-generation-inference|localai|mcp[-/])",
    re.IGNORECASE,
)
_GGUF = re.compile(r"\.gguf$", re.IGNORECASE)
_AI_ENV = {"OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OLLAMA_HOST", "OLLAMA_MODELS", "GEMINI_API_KEY"}


def ai_signals(obj: dict[str, Any]) -> list[tuple[str, str, float]]:
    signals: list[tuple[str, str, float]] = []
    spec = obj.get("spec") if isinstance(obj.get("spec"), dict) else {}
    template = spec.get("template") if isinstance(spec.get("template"), dict) else {}
    pod_spec = template.get("spec") if isinstance(template.get("spec"), dict) else spec
    containers = []
    if isinstance(pod_spec, dict):
        for key in ("containers", "initContainers"):
            items = pod_spec.get(key) or []
            if isinstance(items, list):
                containers.extend(item for item in items if isinstance(item, dict))
    for container in containers:
        image = container.get("image")
        if isinstance(image, str) and (_AI_IMAGE.search(image) or _GGUF.search(image)):
            signals.append(("k8s:image", f"AI-related container image {image}", 0.8))
        for item in container.get("env") or []:
            if isinstance(item, dict) and item.get("name") in _AI_ENV:
                signals.append(("k8s:env", f"model-provider environment name {item['name']} (value not collected)", 0.55))
        for mount in container.get("volumeMounts") or []:
            path = mount.get("mountPath") if isinstance(mount, dict) else None
            if isinstance(path, str) and (_GGUF.search(path) or path.rstrip("/").endswith("ollama")):
                signals.append(("k8s:gguf-mount", f"volume mount looks like a local model store: {path}", 0.6))
    meta = obj.get("metadata") if isinstance(obj.get("metadata"), dict) else {}
    labels = meta.get("labels") if isinstance(meta.get("labels"), dict) else {}
    annotations = meta.get("annotations") if isinstance(meta.get("annotations"), dict) else {}
    for key, value in {**labels, **annotations}.items():
        if re.search(r"mcp|ollama|gguf|vllm|inference", f"{key}={value}", re.I):
            signals.append(("k8s:label", f"AI annotation or label {key}", 0.5))
    return signals


class KubernetesConnector(BaseConnector):
    name: ClassVar[str] = "cloud.kubernetes"
    surface: ClassVar[Surface] = Surface.CLOUD
    provider: ClassVar[str | None] = "kubernetes"
    description: ClassVar[str] = (
        "Offline Kubernetes inventory of workloads and services. Matches AI images, "
        "model env names, GGUF mounts and MCP annotations. Not a live client and not an eBPF probe."
    )
    offline_formats: ClassVar[str] = "kubectl JSON / JSONL export"
    config_keys: ClassVar[dict[str, str]] = {
        "input": "path to a kubectl JSON/JSONL export",
        "cluster": "cluster name recorded on findings (label only)",
    }

    def collect(self) -> Iterable[dict[str, Any]]:
        path = self.ctx.get("input")
        if not isinstance(path, str) or not path:
            self.ctx.warn(
                "cloud.kubernetes: no input export; live API collection is not implemented",
                incomplete=True,
            )
            return
        yielded = False
        for record in self.load_offline(path):
            yielded = True
            if record.get("kind") == "List" and isinstance(record.get("items"), list):
                for item in record["items"]:
                    if isinstance(item, dict):
                        yield item
                continue
            yield record
        if not yielded:
            self.ctx.warn("cloud.kubernetes: export contained no objects", incomplete=True)

    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        cluster = self.ctx.get("cluster") if isinstance(self.ctx.get("cluster"), str) else None
        for obj in records:
            if not isinstance(obj, dict):
                self.ctx.warn("cloud.kubernetes: skipped a non-object record", incomplete=True)
                continue
            self.ctx.examined()
            signals = ai_signals(obj)
            if not signals:
                continue
            meta = obj.get("metadata") if isinstance(obj.get("metadata"), dict) else {}
            kind = str(obj.get("kind") or "Workload")
            name = str(meta.get("name") or "unknown")
            namespace = str(meta.get("namespace") or "default")
            finding = Finding(
                surface=self.surface,
                connector=self.name,
                kind=Kind.CLOUD_RESOURCE,
                title=f"{kind} {namespace}/{name} has AI workload signals",
                resource=f"k8s:{cluster or 'cluster'}:{namespace}:{kind}:{name}",
                resource_type=kind.lower(),
                provider=self.provider,
                account=cluster,
                region=namespace,
                tags=["runtime", "kubernetes", "offline-export"],
                metadata={"evidence_source": "kubernetes-export", "execution_proven": False},
            )
            if any(signal.startswith("k8s:gguf") for signal, _, _ in signals):
                finding.model_providers.append("provider.llama-cpp")
                finding.tags.append("gguf")
            if any("ollama" in description.lower() for _, description, _ in signals):
                finding.model_providers.append("provider.ollama")
            for signal, description, weight in signals:
                finding.add_evidence(Evidence(signal=signal, description=description, weight=weight))
            yield finalize(finding, self.index)
