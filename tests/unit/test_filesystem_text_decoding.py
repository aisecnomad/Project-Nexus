"""Files the scanner used to skip for their bytes are analyzed, and the scan is complete."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from shadowscan.cli import main


def _scan(path):
    result = CliRunner().invoke(main, ["code", str(path), "--format", "json"])
    return result, json.loads(result.stdout)


def _messages(report) -> list[str]:
    return [message for stat in report["stats"] for key in ("errors", "warnings") for message in stat[key]]


def test_a_typescript_module_with_a_nul_cache_key_separator_is_analyzed(tmp_path):
    source = (
        'import OpenAI from "openai";\n'
        "const client = new OpenAI();\n"
        + "// a module with enough ordinary text around the byte below to be a source file\n" * 8
        + "const cacheKey = `${provider}\x00${modelId}`;\n"
    )
    (tmp_path / "cost.ts").write_bytes(source.encode())

    result, report = _scan(tmp_path)

    assert result.exit_code == 0, result.output
    assert report["summary"]["complete"] is True
    assert any("provider.openai" in finding["model_providers"] for finding in report["findings"])
    assert any(
        "analyzed in full with a note (stray NUL bytes in text, read as text): cost.ts" in m
        for m in _messages(report)
    )


def test_a_binary_blob_with_an_analyzable_name_is_still_an_incomplete_scan(tmp_path):
    (tmp_path / "blob.ts").write_bytes(b"\x01\x02\x00\x03" * 400)
    (tmp_path / "real.py").write_text(
        "from crewai import Agent\nAgent(role='a', goal='b')\n", encoding="utf-8"
    )

    result, report = _scan(tmp_path)

    assert result.exit_code == 3, result.output
    assert report["summary"]["complete"] is False
    assert any("blob.ts" in m and "binary or undecodable" in m for m in _messages(report))
    assert any("framework.crewai" in finding["frameworks"] for finding in report["findings"])


def test_a_latin1_requirements_file_is_analyzed(tmp_path):
    (tmp_path / "requirements.txt").write_bytes(b"# d\xe9pendances\nlangchain==0.2.0\n")

    result, report = _scan(tmp_path)

    assert result.exit_code == 0, result.output
    assert report["summary"]["complete"] is True
    assert any("framework.langchain" in finding["frameworks"] for finding in report["findings"])
    assert any(
        "analyzed in full with a note (not valid UTF-8, the bytes that are not were replaced): requirements.txt"
        in m
        for m in _messages(report)
    )


def test_a_legacy_encoded_document_does_not_hide_the_key_it_holds(tmp_path):
    key = "sk-ant-api03-" + "Zq4Xw8Lm2Rt6Vb9Nc3Hd7Kf1Jg5Sp0Ya"
    (tmp_path / "LEIAME.TXT").write_bytes(f"Configura\xe7\xe3o\nANTHROPIC_API_KEY={key}\n".encode("latin-1"))

    result, report = _scan(tmp_path)

    assert report["summary"]["complete"] is True
    secrets = [finding for finding in report["findings"] if finding["kind"] == "secret"]
    assert secrets and "provider.anthropic" in secrets[0]["model_providers"]
    assert key not in result.stdout


def test_strict_coverage_treats_a_noted_file_as_a_gap(tmp_path):
    (tmp_path / "requirements.txt").write_bytes(b"# d\xe9pendances\nlangchain==0.2.0\n")
    result = CliRunner().invoke(main, ["code", str(tmp_path), "--format", "json", "--strict-coverage"])
    report = json.loads(result.stdout)
    assert result.exit_code == 3, result.output
    assert report["summary"]["complete"] is False
    assert any("requirements.txt" in m and "strict_coverage" in m for m in _messages(report))


def test_notes_are_one_warning_per_kind_however_many_files_carry_them(tmp_path):
    for n in range(30):
        (tmp_path / f"req{n}.txt").write_bytes(b"# d\xe9p\nlangchain==0.2.0\n")
    result, report = _scan(tmp_path)
    assert result.exit_code == 0, result.output
    noted = [m for m in _messages(report) if "analyzed in full with a note" in m]
    assert len(noted) == 1
    assert "30 file(s)" in noted[0] and "and 25 more" in noted[0]


def test_a_random_byte_config_file_is_still_an_incomplete_scan(tmp_path):
    import random

    rng = random.Random(7)
    (tmp_path / "config.yaml").write_bytes(bytes(rng.randrange(0x80, 0x100) for _ in range(20_000)))
    result, report = _scan(tmp_path)
    assert result.exit_code == 3, result.output
    assert any("config.yaml" in m and "binary or undecodable" in m for m in _messages(report))


def test_codeowners_with_invalid_bytes_is_an_error_because_an_owner_name_may_have_changed(tmp_path):
    (tmp_path / "CODEOWNERS").write_bytes(b"* @team-caf\xe9\n")
    (tmp_path / "agent.py").write_text(
        "from crewai import Agent\nAgent(role='a', goal='b')\n", encoding="utf-8"
    )
    result, report = _scan(tmp_path)
    assert result.exit_code == 3, result.output
    assert any("CODEOWNERS" in m and "ownership may be wrong" in m for m in _messages(report))


@pytest.mark.parametrize("suffix", [b"\xff" * 20_000, b"\x01\xff"], ids=["binary-body", "control-body"])
def test_ascii_prefix_cannot_hide_an_undecodable_or_control_character_body(tmp_path, suffix):
    (tmp_path / "config.txt").write_bytes(b"# ordinary text\n" * 600 + suffix)
    result, report = _scan(tmp_path)
    assert result.exit_code == 3, result.output
    assert report["summary"]["complete"] is False
    assert any("config.txt" in m and "binary or undecodable" in m for m in _messages(report))


@pytest.mark.parametrize("name", ["source.py", "source.ipynb"])
def test_utf8_bom_does_not_allow_invalid_source_or_notebook_bytes(tmp_path, name):
    if name.endswith(".py"):
        source = b"# invalid comment: \xff\nimport openai\n"
    else:
        source = b'{"cells":[{"cell_type":"code","source":["# \xff\\nimport openai"],"metadata":{}}]}'
    (tmp_path / name).write_bytes(b"\xef\xbb\xbf" + source)
    result, report = _scan(tmp_path)
    assert result.exit_code == 3, result.output
    assert report["summary"]["complete"] is False
    assert any(name in m and "binary or undecodable" in m for m in _messages(report))
