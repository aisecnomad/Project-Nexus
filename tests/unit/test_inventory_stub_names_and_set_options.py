"""Generated inventory stubs carry readable names; --set keeps identifiers intact."""

from __future__ import annotations

from shadowscan.config import parse_set_options
from shadowscan.models import Finding, Kind, Surface
from shadowscan.registry import card_stub_for


def test_card_stub_names_come_from_record_members_not_python_reprs():
    finding = Finding(surface=Surface.CODE, connector="code.filesystem", kind=Kind.AGENT_CONFIG, title="Claude Code configured",
                      resource="repo", resource_type="coding-agent-config")
    finding.metadata["agent_definitions"] = [{"file": ".claude/agents/reviewer.md", "name": "Reviewer"}]
    finding.metadata["agents"] = [{"name": "Planner"}, "Helper"]
    names = card_stub_for(finding)["discovery"]["names"]
    assert names == ["Helper", "Planner", "Reviewer"]
    assert not any("{" in name for name in names)


def test_set_options_preserve_identifiers_with_leading_zeros():
    parsed = parse_set_options(["tenant_id=0123", "limit=123", "zero=0", "neg=-5", "regions=us-east-1,eu-west-1"])
    assert parsed == {"tenant_id": "0123", "limit": 123, "zero": 0, "neg": -5, "regions": ["us-east-1", "eu-west-1"]}
