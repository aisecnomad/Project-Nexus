"""A finding's confidence is the one its own evidence supports.

Confidence and likelihood drive ``--min-confidence`` filtering and the report.
A connector that finalizes a finding and then attaches more evidence reports a
stale score until an engine merge happens to recompute it, so the same object
would score differently depending on whether it had a duplicate.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from shadowscan.config import ScanConfig
from shadowscan.engine import Engine
from shadowscan.models import Finding

ROOT = Path(__file__).resolve().parents[2]
# Low-code, cloud, identity and SaaS connectors; their findings can sit on
# other surfaces (IAM grants on identity, CloudTrail callers on gateway).
CONNECTOR_FAMILIES = {"lowcode", "cloud", "identity", "saas"}


@pytest.fixture(scope="module")
def demo_findings(index) -> list[Finding]:
    config = ScanConfig.from_yaml(ROOT / "examples" / "shadowscan.offline.yaml")
    return Engine(config, index).run().findings


def test_offline_demo_confidence_matches_recomputed_evidence(demo_findings):
    findings = [f for f in demo_findings if f.connector.split(".", 1)[0] in CONNECTOR_FAMILIES]
    # Automation findings attach model and step-name hints; keep them in scope.
    assert {"lowcode.n8n", "lowcode.make", "lowcode.zapier"} <= {f.connector for f in findings}
    stale = []
    for finding in findings:
        # Recomputing respects capped weights and confidence groups, unlike a raw noisy-OR.
        expected = copy.deepcopy(finding)
        expected.recompute_confidence()
        if (finding.confidence, finding.likelihood) != (expected.confidence, expected.likelihood):
            stale.append((finding.connector, finding.title, finding.confidence, expected.confidence))
        if "_evidence_counts" in finding.metadata:
            stale.append((finding.connector, finding.title, "evidence attached after finalize", None))
    assert not stale
