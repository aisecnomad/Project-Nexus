"""Independent coding-agent products must survive the engine's ID merge."""

from __future__ import annotations

from pathlib import Path

from shadowscan.engine import merge
from shadowscan.models import Kind


def test_distinct_coding_agent_configs_in_one_project_do_not_merge(tmp_path: Path, run_connector):
    (tmp_path / "AGENTS.md").write_text("General repository instructions.\n")
    (tmp_path / "CLAUDE.md").write_text("Claude-specific instructions.\n")
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text('{"permissions": {}}')

    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, label="github:acme/example")
    assert not ctx.stats.errors
    configs = [finding for finding in findings if finding.kind == Kind.AGENT_CONFIG]
    assert len(configs) == 2
    by_signature = {finding.frameworks[0]: finding for finding in configs}
    assert set(by_signature) == {"coding-agent.agents-md", "coding-agent.claude-code"}
    assert by_signature["coding-agent.agents-md"].metadata["files"] == ["AGENTS.md"]
    assert by_signature["coding-agent.claude-code"].metadata["files"] == [".claude/settings.json", "CLAUDE.md"]
    assert {finding.resource for finding in configs} == {"github:acme/example"}
    assert len({finding.id for finding in configs}) == len(configs)
    assert all(finding.id == finding.compute_id() for finding in configs)
    assert len([finding for finding in merge(findings) if finding.kind == Kind.AGENT_CONFIG]) == 2

    # Content edits to instructions do not change identity, and repeated
    # observations of one signature retain the same product finding.
    (tmp_path / "CLAUDE.md").write_text("Updated Claude instructions.\n")
    rescanned, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, label="github:acme/example")
    assert not ctx.stats.errors
    assert {
        finding.frameworks[0]: finding.id
        for finding in rescanned if finding.kind == Kind.AGENT_CONFIG
    } == {signature: finding.id for signature, finding in by_signature.items()}
