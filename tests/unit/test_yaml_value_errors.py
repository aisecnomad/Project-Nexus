"""SafeLoader's plain ValueError is malformed YAML, like any YAMLError.

PyYAML constructs a timestamp with ``datetime.date`` and an integer with
``int``, so an impossible date (``2024-02-30``) or an integer longer than
Python's 4,300-digit conversion limit raises ``ValueError``, not a
``YAMLError``. Every YAML load must report such a document the way it reports
any other malformed one instead of letting the exception escape its handler.
"""

from __future__ import annotations

import pytest

from shadowscan.config import ConfigValidationError, ScanConfig
from shadowscan.connectors.code.manifests import parse_conda_env, parse_manifest
from shadowscan.registry import Inventory, InventoryValidationError

INVALID_SCALARS = {
    "impossible-date": "created: 2024-02-30",
    "over-long-integer": "size: " + "1" * 5000,
}


@pytest.mark.parametrize("line", INVALID_SCALARS.values(), ids=list(INVALID_SCALARS))
def test_conda_environment_with_invalid_scalar_is_invalid_yaml(line):
    text = f"name: demo\n{line}\ndependencies:\n  - openai\n"
    result = parse_conda_env(text)
    assert result.errors == ["invalid YAML"]
    assert not result.deps
    # The dispatcher keeps the parser's diagnostic instead of a generic failure.
    dispatched = parse_manifest("environment.yml", text)
    assert dispatched is not None and dispatched.errors == ["invalid YAML"]


@pytest.mark.parametrize("line", INVALID_SCALARS.values(), ids=list(INVALID_SCALARS))
def test_agent_definition_with_invalid_scalar_keeps_the_rest_of_the_file(tmp_path, run_connector, line):
    agents = tmp_path / ".claude" / "agents"
    agents.mkdir(parents=True)
    (agents / "reviewer.md").write_text(f"---\nname: reviewer\n{line}\ntools: Bash\n---\nReview code.\n")
    (tmp_path / "agent.py").write_text("from crewai import Agent\nAgent(role='r')\n")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    # Same diagnostic as any malformed front matter; the file's analysis
    # completes, so the definition is still listed by its file name.
    assert ctx.stats.incomplete
    assert ctx.stats.errors == ["code.filesystem: .claude/agents/reviewer.md: invalid agent definition YAML"]
    definitions = [item for finding in findings for item in finding.metadata.get("agent_definitions", [])]
    assert {"file": ".claude/agents/reviewer.md", "name": "reviewer"} in definitions
    assert any("framework.crewai" in finding.frameworks for finding in findings)


@pytest.mark.parametrize("line", INVALID_SCALARS.values(), ids=list(INVALID_SCALARS))
def test_scan_config_with_invalid_scalar_is_invalid_yaml(tmp_path, line):
    path = tmp_path / "shadowscan.yaml"
    path.write_text(f"connectors: []\n{line}\n")
    with pytest.raises(ConfigValidationError, match="invalid YAML syntax"):
        ScanConfig.from_yaml(path)


def test_scan_config_keeps_its_own_validation_messages(tmp_path):
    path = tmp_path / "shadowscan.yaml"
    path.write_text("connectors: []\nconnectors: []\n")
    with pytest.raises(ConfigValidationError, match="duplicate configuration mapping key"):
        ScanConfig.from_yaml(path)


@pytest.mark.parametrize("line", INVALID_SCALARS.values(), ids=list(INVALID_SCALARS))
def test_inventory_with_invalid_scalar_is_invalid_syntax(tmp_path, line):
    path = tmp_path / "inventory.yaml"
    path.write_text(f"agents:\n  - id: reviewer\n    name: Reviewer\n    {line}\n")
    with pytest.raises(InventoryValidationError, match="invalid syntax"):
        Inventory.load([path])
