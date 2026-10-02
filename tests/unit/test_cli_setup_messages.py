"""First-run commands work as documented, and connector diagnostics read once, not twice."""

from __future__ import annotations

import json
import re
import shlex
from pathlib import Path

import pytest
from click.testing import CliRunner

from shadowscan.cli import main

QUICKSTART = Path(__file__).parents[2] / "docs" / "getting-started" / "quickstart.md"


def _flat(text: str) -> str:
    return " ".join(text.split())


def test_first_quickstart_command_runs_on_a_fresh_checkout(tmp_path, monkeypatch):
    block = re.search(r"```bash\n(.*?)```", QUICKSTART.read_text(encoding="utf-8"), re.S)
    assert block is not None
    first = shlex.split(block.group(1).splitlines()[0])
    assert first[:2] == ["shadowscan", "code"]
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(main, first[1:])

    assert result.exit_code == 0, result.output


def test_missing_inventory_path_message_says_how_to_fix_it(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    missing = tmp_path / "inventory"

    result = CliRunner().invoke(main, ["code", str(source), "-i", str(missing)])

    assert result.exit_code == 1, result.output
    text = _flat(result.output)
    assert f"inventory path not found: {missing}" in text
    assert "omit" in text and "agent-card.yaml" in text


def _incomplete_json(tmp_path, config_text: str) -> dict:
    config = tmp_path / "scan.yaml"
    config.write_text(config_text, encoding="utf-8")
    out = tmp_path / "report.json"
    result = CliRunner().invoke(main, ["scan", "-c", str(config), "-f", "json", "-o", str(out)])
    assert result.exit_code == 3, result.output
    return json.loads(out.read_text(encoding="utf-8"))


def test_unknown_connector_reason_is_not_a_quoted_keyerror(tmp_path):
    report = _incomplete_json(tmp_path, "connectors:\n  - name: code.nope\n")

    (error,) = report["stats"][0]["errors"]
    assert error.startswith("code.nope: unknown connector 'code.nope'. Known: ")
    assert "KeyError" not in error and '"' not in error[:40]


def test_output_file_with_table_format_says_it_is_json(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    out = tmp_path / "report.table"

    result = CliRunner().invoke(main, ["code", str(source), "-o", str(out)])

    assert result.exit_code == 0, result.output
    assert json.loads(out.read_text(encoding="utf-8"))["summary"]
    text = _flat(result.output)
    assert "wrote json report to" in text and "table format saves JSON" in text


@pytest.mark.parametrize("fmt", ["table", "markdown"])
def test_connector_prefix_is_not_repeated_in_reports(tmp_path, fmt):
    config = tmp_path / "scan.yaml"
    config.write_text(f"connectors:\n  - name: code.filesystem\n    path: {tmp_path / 'gone'}\n")

    result = CliRunner().invoke(main, ["scan", "-c", str(config), "-f", fmt])

    assert result.exit_code == 3, result.output
    text = _flat(result.output)
    assert "path not found" in text
    assert "code.filesystem: code.filesystem" not in text and "code.filesystem:** code.filesystem" not in text
