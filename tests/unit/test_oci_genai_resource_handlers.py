"""Coverage for the three OCI GenAI resource handlers with no dedicated test:
dedicated endpoints, dedicated AI clusters, and Agents knowledge bases. These
were the narrower, still-genuine gap left after test_oci_live_contracts.py's
coverage of _h_model_deployment/_h_genai_custom_model (which only run when the
optional ``oci`` SDK is installed)."""

from __future__ import annotations

import pytest

from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.cloud.oci import OciConnector
from shadowscan.models import Kind, ScanStats

pytest.importorskip("oci")


def _context(index, **config):
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="test", started_at="2026-01-01")
    return ctx


def test_oci_genai_endpoint_handler_flags_model_and_cluster(index):
    connector = OciConnector(_context(index))
    rec = {
        "_kind": "genai-endpoint",
        "_region": "us-ashburn-1",
        "_compartment": "ocid1.compartment.oc1..demo",
        "id": "ocid1.generativeaiendpoint.oc1..demo",
        "display_name": "support-endpoint",
        "lifecycle_state": "ACTIVE",
        "model_id": "ocid1.generativeaimodel.oc1..cohere-command",
        "dedicated_ai_cluster_id": "ocid1.generativeaidedicatedaicluster.oc1..demo",
    }
    finding = connector._h_genai_endpoint(rec)
    assert finding.kind == Kind.CLOUD_RESOURCE
    assert finding.resource_type == "genai-endpoint"
    assert "provider.oci-generative-ai" in finding.model_providers
    assert finding.models == ["ocid1.generativeaimodel.oc1..cohere-command"]
    assert finding.metadata["cluster"] == "ocid1.generativeaidedicatedaicluster.oc1..demo"


def test_oci_genai_cluster_handler_flags_dedicated_cluster(index):
    connector = OciConnector(_context(index))
    rec = {
        "_kind": "genai-cluster",
        "_region": "us-ashburn-1",
        "_compartment": "ocid1.compartment.oc1..demo",
        "id": "ocid1.generativeaidedicatedaicluster.oc1..demo",
        "display_name": "prod-cluster",
        "lifecycle_state": "ACTIVE",
        "type": "HOSTING",
        "unit_count": 2,
    }
    finding = connector._h_genai_cluster(rec)
    assert finding.kind == Kind.CLOUD_RESOURCE
    assert finding.resource_type == "genai-dedicated-cluster"
    assert "provider.oci-generative-ai" in finding.model_providers


def test_oci_genai_knowledge_base_handler_flags_rag_capability(index):
    connector = OciConnector(_context(index))
    rec = {
        "_kind": "genai-knowledge-base",
        "_region": "us-ashburn-1",
        "_compartment": "ocid1.compartment.oc1..demo",
        "id": "ocid1.generativeaiagentknowledgebase.oc1..demo",
        "display_name": "support-docs-kb",
        "lifecycle_state": "ACTIVE",
    }
    finding = connector._h_genai_knowledge_base(rec)
    assert finding.kind == Kind.CLOUD_RESOURCE
    assert finding.resource_type == "genai-knowledge-base"
    assert "rag" in finding.capabilities
    assert "cloud.oci-generative-ai-agents" in finding.frameworks
