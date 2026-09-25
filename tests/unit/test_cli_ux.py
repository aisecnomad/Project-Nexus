"""CLI diagnostics: literal rendering, printable setup errors and plugin registry warnings."""

from __future__ import annotations

import json
from types import SimpleNamespace

from click.testing import CliRunner

from shadowscan.cli import main

BAD_PACK = (
    "signatures:\n"
    "  - id: custom.bad\n"
    "    category: nonsense\n"
    "    signals: [{type: dependency, ecosystem: pypi, names: [private-package-name]}]\n"
)


def _flat(text: str) -> str:
    """Collapse Rich line wrapping so message substrings can be asserted."""
    return " ".join(text.split())


# ------------------------------------------------------------- connectors
def test_connectors_table_renders_key_names_literally():
    result = CliRunner().invoke(main, ["connectors", "--surface", "identity"])
    assert result.exit_code == 0, result.output
    assert "[bold]" not in result.output and "[/bold]" not in result.output
    assert "[dim]" not in result.output and "[/dim]" not in result.output
    assert "org_url" in result.output and "fetch_tokens" in result.output


def test_connectors_table_keeps_requirements_and_bracketed_descriptions_literal():
    result = CliRunner().invoke(main, ["connectors", "--surface", "cloud"])
    assert result.exit_code == 0, result.output
    assert "requires:" in result.output and "[dim]" not in result.output

    result = CliRunner().invoke(main, ["connectors", "--surface", "code"])
    assert result.exit_code == 0, result.output
    assert "repos: [owner/name, ...]" in _flat(result.output)


def test_connectors_reports_plugin_registry_problems_on_stderr(monkeypatch):
    monkeypatch.setattr("shadowscan.connectors.entry_points", lambda **kwargs: [
        SimpleNamespace(name="identity.okta", value="must_never_import:Connector"),
        SimpleNamespace(name="custom.twice", value="first_plugin:Connector"),
        SimpleNamespace(name="custom.twice", value="second_plugin:Connector"),
    ])
    result = CliRunner().invoke(main, ["connectors", "--json"])
    assert result.exit_code == 0, result.output
    rows = json.loads(result.stdout)
    assert "custom.twice" not in {row["name"] for row in rows}
    warnings = _flat(result.stderr)
    assert "plugin 'identity.okta' cannot replace a built-in connector" in warnings
    assert "plugin 'custom.twice' is defined more than once" in warnings


def test_scan_logs_plugin_registry_problems_as_warnings(tmp_path, monkeypatch):
    monkeypatch.setattr("shadowscan.connectors.entry_points", lambda **kwargs: [
        SimpleNamespace(name="identity.okta", value="must_never_import:Connector"),
    ])
    source = tmp_path / "src"
    source.mkdir()
    result = CliRunner().invoke(main, ["code", str(source), "--format", "json"])
    assert result.exit_code == 0, result.output
    assert "plugin 'identity.okta' cannot replace a built-in connector" in _flat(result.stderr)


# ----------------------------------------------------------- setup errors
def test_missing_inventory_path_is_named(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    missing = tmp_path / "inventory-does-not-exist"
    result = CliRunner().invoke(main, ["code", str(source), "-i", str(missing)])
    assert result.exit_code == 1, result.output
    assert f"inventory path not found: {missing}" in _flat(result.output)
    assert "scan setup failed" not in result.output and "Traceback" not in result.output


def test_missing_signature_directory_is_named(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    missing = tmp_path / "packs-do-not-exist"
    result = CliRunner().invoke(main, ["code", str(source), "-s", str(missing)])
    assert result.exit_code == 1, result.output
    assert f"signature directory not found: {missing}" in _flat(result.output)
    assert "scan setup failed" not in result.output and "Traceback" not in result.output


def test_malformed_signature_pack_names_the_file_but_not_signal_values(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    packs = tmp_path / "packs"
    packs.mkdir()
    bad = packs / "bad.yaml"
    bad.write_text(BAD_PACK, encoding="utf-8")
    result = CliRunner().invoke(main, ["code", str(source), "-s", str(packs)])
    assert result.exit_code == 1, result.output
    flat = _flat(result.output)
    assert f"{bad}: document 1: custom.bad: invalid category 'nonsense'" in flat
    assert "private-package-name" not in flat and "Traceback" not in flat


def test_pack_yaml_syntax_error_reports_position_without_source_text(tmp_path):
    packs = tmp_path / "packs"
    packs.mkdir()
    (packs / "broken.yaml").write_text("signatures:\n  - id: [private-secret-value\n", encoding="utf-8")
    result = CliRunner().invoke(main, ["signatures", "list", "-s", str(packs)])
    assert result.exit_code == 1, result.output
    assert isinstance(result.exception, SystemExit)
    assert "broken.yaml: invalid YAML syntax (line" in _flat(result.output)
    assert "private-secret-value" not in result.output and "Traceback" not in result.output


def test_unexpected_exception_during_setup_is_masked_even_when_verbose(tmp_path, monkeypatch):
    class ExplodingEngine:
        def __init__(self, *args, **kwargs):
            raise RuntimeError("plugin failure token=private-value-do-not-echo")

    monkeypatch.setattr("shadowscan.cli.Engine", ExplodingEngine)
    result = CliRunner().invoke(main, ["-vv", "code", str(tmp_path)])
    assert result.exit_code == 1, result.output
    assert isinstance(result.exception, SystemExit)
    flat = _flat(result.output)
    assert "scan setup failed" in flat and "RuntimeError" in flat
    # -vv adds frame locations for bug reports, never the exception text or source lines.
    assert "test_cli_ux.py:" in flat
    assert "private-value-do-not-echo" not in flat and "plugin failure" not in flat and "Traceback" not in flat


def test_scan_config_yaml_error_reports_position_without_source_text(tmp_path):
    config = tmp_path / "scan.yaml"
    config.write_text("options:\n  parallel: 2\n  fail_on: [private-value-do-not-echo\n", encoding="utf-8")
    result = CliRunner().invoke(main, ["scan", "-c", str(config)])
    assert result.exit_code == 1, result.output
    assert "invalid YAML syntax or structural limits exceeded (line" in result.output
    assert "private-value-do-not-echo" not in result.output


def test_credential_mixing_policy_error_is_printed_verbatim(tmp_path):
    source = tmp_path / "src"
    source.mkdir()
    config = tmp_path / "scan.yaml"
    config.write_text(
        f"connectors:\n  - name: code.filesystem\n    path: {source}\n"
        "  - name: identity.okta\n    org_url: https://acme.okta.com\n",
        encoding="utf-8",
    )
    result = CliRunner().invoke(main, ["scan", "-c", str(config)])
    assert result.exit_code == 1, result.output
    assert "code scanning and live credentialed connectors require separate scans" in _flat(result.output)


def test_inventory_check_names_missing_path(tmp_path):
    missing = tmp_path / "inventory-does-not-exist.yaml"
    result = CliRunner().invoke(main, ["inventory", "check", str(missing)])
    assert result.exit_code == 1, result.output
    assert f"inventory path not found: {missing}" in _flat(result.output)


# -------------------------------------------------------------- run --set
def test_run_rejects_unknown_set_key_as_usage_error():
    result = CliRunner().invoke(main, ["run", "identity.okta", "--set", "fetch_tokenz=true"])
    assert result.exit_code == 2, result.output
    assert "does not accept 'fetch_tokenz'" in result.output
    assert "did you mean 'fetch_tokens'" in result.output


def test_run_rejects_reserved_internal_keys_without_echoing_values():
    result = CliRunner().invoke(main, ["run", "identity.okta", "--set", "_dump_path=/private/anywhere"])
    assert result.exit_code == 2, result.output
    assert "reserved for internal use" in result.output
    assert "/private/anywhere" not in result.output


# ------------------------------------------------------------- signatures
def test_signatures_test_with_invalid_pack_is_a_usage_error_not_a_traceback(tmp_path):
    packs = tmp_path / "packs"
    packs.mkdir()
    (packs / "bad.yaml").write_text(BAD_PACK, encoding="utf-8")
    result = CliRunner().invoke(main, ["signatures", "test", "openai", "-s", str(packs)])
    assert result.exit_code == 1, result.output
    assert isinstance(result.exception, SystemExit)
    assert "custom.bad: invalid category 'nonsense'" in _flat(result.output)
    assert "Traceback" not in result.output


def test_signatures_test_auto_mode_reports_dependency_hits_across_ecosystems():
    result = CliRunner().invoke(main, ["signatures", "test", "openai"])
    assert result.exit_code == 0, result.output
    hits = [line for line in result.output.splitlines() if line.startswith("dependency")]
    assert any("provider.openai" in line and "(pypi)" in line for line in hits)
    assert any("provider.openai" in line and "(npm)" in line for line in hits)
    assert len(hits) == len(set(hits))


def test_signatures_test_dependency_kind_defaults_to_every_ecosystem():
    result = CliRunner().invoke(main, ["signatures", "test", "openai", "--kind", "dependency"])
    assert result.exit_code == 0, result.output
    assert "(pypi)" in result.output and "(npm)" in result.output

    result = CliRunner().invoke(main, ["signatures", "test", "openai", "--kind", "dependency", "--ecosystem", "npm"])
    assert result.exit_code == 0, result.output
    assert "(npm)" in result.output and "(pypi)" not in result.output
