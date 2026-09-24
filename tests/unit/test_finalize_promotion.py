"""Promotion from framework-usage to agent requires strong indicators."""

from __future__ import annotations

from shadowscan.connectors.common import finalize
from shadowscan.models import Finding, Kind, Surface


def _finding(**kwargs) -> Finding:
    values = dict(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.FRAMEWORK_USAGE,
        title="LangChain project",
        resource="repo",
        resource_type="project",
    )
    values.update(kwargs)
    return Finding(**values)


def test_single_import_indicator_stays_framework_usage():
    finding = _finding(metadata={"agent_indicators": 1, "_indicator_types": ["import"]})
    finalize(finding)
    assert finding.kind is Kind.FRAMEWORK_USAGE
    assert "agent-indicator-weak" in finding.tags
    assert finding.metadata.get("indicator_types") == ["import"]


def test_code_indicator_promotes_to_agent():
    finding = _finding(metadata={"agent_indicators": 1, "_indicator_types": ["code"]})
    finalize(finding)
    assert finding.kind is Kind.AGENT
    assert "promoted-from-framework-usage" in finding.tags


def test_two_weak_indicators_promote_to_agent():
    finding = _finding(metadata={"agent_indicators": 2, "_indicator_types": ["import", "dependency"]})
    finalize(finding)
    assert finding.kind is Kind.AGENT
