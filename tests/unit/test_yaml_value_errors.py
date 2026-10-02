"""SafeLoader's plain ValueError is malformed YAML, like any YAMLError.

PyYAML constructs a timestamp with ``datetime.date`` and an integer with
``int``, so an impossible date (``2024-02-30``) or an integer longer than
Python's 4,300-digit conversion limit raises ``ValueError``, not a
``YAMLError``. Every YAML load must report such a document the way it reports
any other malformed one instead of letting the exception escape its handler.
"""

from __future__ import annotations

import functools

import pytest
import yaml
from click.testing import CliRunner

from shadowscan.cli import main
from shadowscan.config import ConfigValidationError, ScanConfig
from shadowscan.connectors.code.manifests import parse_conda_env, parse_manifest
from shadowscan.connectors.code.semantic_config import parse_agent_manifest
from shadowscan.registry import Inventory, InventoryValidationError
from shadowscan.signatures.loader import SignaturePackError, load_signature_file
from shadowscan.utils.safe_yaml import (
    BoundedSafeLoader,
    YAMLConstructionError,
    YAMLResourceLimitError,
    bounded_safe_load,
    bounded_safe_load_all,
    strict_bounded_safe_load,
    strict_bounded_safe_load_all,
)

# The scalar stands in for a credential or address that must never be echoed.
PRIVATE = "alice.smith@corp.example"
# An explicit tag makes SafeConstructor leak KeyError, IndexError,
# AttributeError or a ValueError that quotes the scalar.
EXPLICIT_TAGS = {
    "bool": f"!!bool {PRIVATE}",
    "int": "!!int >",
    "timestamp": "!!timestamp ---",
    "float": f"!!float {PRIVATE}",
    "set": "!!set 3",
}
INVALID_SCALARS = {
    "impossible-date": "created: 2024-02-30",
    "over-long-integer": "size: " + "1" * 5000,
    **{f"explicit-{name}": f"value: {tagged}" for name, tagged in EXPLICIT_TAGS.items()},
}
LOADERS = {
    "bounded": bounded_safe_load,
    "bounded-all": bounded_safe_load_all,
    "strict": strict_bounded_safe_load,
    "strict-config-keys": functools.partial(strict_bounded_safe_load, require_string_keys=False),
    "strict-all": strict_bounded_safe_load_all,
    "strict-all-config-keys": functools.partial(strict_bounded_safe_load_all, require_string_keys=False),
}


@pytest.mark.parametrize("load", LOADERS.values(), ids=list(LOADERS))
@pytest.mark.parametrize("tagged", EXPLICIT_TAGS.values(), ids=list(EXPLICIT_TAGS))
def test_explicit_tag_failures_are_value_free_yaml_errors(load, tagged):
    with pytest.raises(yaml.YAMLError) as caught:
        load(f"name: demo\nvalue: {tagged}\n")
    message = str(caught.value)
    assert PRIVATE not in message and repr(caught.value).count(PRIVATE) == 0
    # A traceback must not print the leaked exception that quoted the value.
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None or caught.value.__suppress_context__
    if isinstance(caught.value, YAMLConstructionError):
        assert "line 2, column 8" in message


@pytest.mark.parametrize("load", LOADERS.values(), ids=list(LOADERS))
def test_lenient_binary_tag_never_raises_a_non_yaml_error(load):
    try:
        load("value: !!binary '!!'\n")
    except yaml.YAMLError:
        pass


def test_loader_subclass_diagnostics_pass_through_and_recursion_is_a_limit():
    class Deliberate(ValueError):
        pass

    class Loader(BoundedSafeLoader):
        pass

    def deliberate(loader, node):
        raise Deliberate("loader diagnostic")

    def recursion(loader, node):
        raise RecursionError

    Loader.add_constructor("!deliberate", deliberate)
    Loader.add_constructor("!deep", recursion)
    with pytest.raises(Deliberate, match="loader diagnostic"):
        yaml.load("a: !deliberate x", Loader=Loader)
    with pytest.raises(YAMLResourceLimitError, match="nesting"):
        yaml.load("a: !deep x", Loader=Loader)


def test_poison_offline_export_keeps_valid_neighbours_and_is_incomplete(tmp_path, run_connector):
    exports = tmp_path / "exports"
    exports.mkdir()
    record = '- id: "{n}"\n  title: AI workflow {n}\n  steps: [OpenAI]\n'
    (exports / "a.yaml").write_text(record.format(n=1))
    (exports / "b.yaml").write_text(record.format(n=2) + f"  paused: !!bool {PRIVATE}\n")
    (exports / "c.yaml").write_text(record.format(n=3))
    findings, ctx = run_connector("lowcode.zapier", input=str(exports))
    assert sorted(finding.resource for finding in findings) == ["zapier:zap:1", "zapier:zap:3"]
    assert ctx.stats.incomplete
    assert ctx.stats.errors == ["lowcode.zapier: invalid YAML export"]
    assert PRIVATE not in str(ctx.stats.errors)


def test_scan_config_explicit_tag_error_names_position_never_value(tmp_path):
    path = tmp_path / "shadowscan.yaml"
    path.write_text(f"connectors: []\noptions:\n  incremental: !!bool {PRIVATE}\n")
    with pytest.raises(ConfigValidationError, match=r"invalid YAML syntax.*\(line 3, column 16\)") as caught:
        ScanConfig.from_yaml(path)
    assert PRIVATE not in str(caught.value)
    result = CliRunner().invoke(main, ["scan", "-c", str(path)])
    assert result.exit_code == 1 and "invalid scan configuration" in result.output
    assert not isinstance(result.exception, KeyError)
    assert PRIVATE not in result.output and "Traceback" not in result.output


@pytest.mark.parametrize("tagged", EXPLICIT_TAGS.values(), ids=list(EXPLICIT_TAGS))
def test_signature_pack_with_explicit_tag_error_is_a_pack_error(tmp_path, tagged):
    pack = tmp_path / "pack.yaml"
    pack.write_text(f"id: custom.example\ncategory: framework\nagent_indicator: {tagged}\nsignals: []\n")
    with pytest.raises(SignaturePackError, match="invalid YAML syntax") as caught:
        load_signature_file(pack)
    assert PRIVATE not in str(caught.value)


@pytest.mark.parametrize("line", INVALID_SCALARS.values(), ids=list(INVALID_SCALARS))
def test_agent_manifest_with_invalid_scalar_is_invalid_syntax(line):
    result = parse_agent_manifest(
        "agents/langgraph.yaml", f"graphs:\n  agent: app.py:graph\n{line}\n", "langgraph"
    )
    assert result.errors == ["invalid agent manifest syntax"]


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
