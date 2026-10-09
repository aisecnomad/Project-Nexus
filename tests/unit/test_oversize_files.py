"""Files over max_file_size: data read in full, binaries skipped, test code by policy.

The real-world benchmark left 26 of 183 scans incomplete because of files over
max_file_size: API specifications, datasets and changelogs, compiled binaries
without an extension, and test fixtures. Documentation and data files are now
read in full up to max_data_file_size, a recognised binary is skipped as a
smaller one is, and test code follows the test-code policy.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shadowscan.models import Kind
from shadowscan.signatures import matcher

KEY = "sk-ant-api03-" + "Zx9Kq2Lm7Np4Rt8Vw3Ys6Bc1Df5Gh0Jk" * 2 + "-AbCdEfGhAA"
OTHER_KEY = "sk-ant-api03-" + "Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk9Lz0Xc" * 2 + "-ZyXwVuTsAA"
ENDPOINT = "https://api.openai.com/v1/chat/completions"


def _scan(run_connector, tmp_path: Path, **config):
    return run_connector("code.filesystem", path=str(tmp_path), use_git=False, **config)


def test_data_file_over_max_file_size_is_analyzed_in_full(tmp_path: Path, run_connector) -> None:
    padding = "x" * 5_000
    (tmp_path / "settings.json").write_text(
        json.dumps({"padding": padding, "endpoint": ENDPOINT, "notes": padding}, indent=1)
    )
    findings, ctx = _scan(run_connector, tmp_path, max_file_size=1_000)
    assert not ctx.stats.incomplete and not ctx.stats.warnings
    assert any("provider.openai" in f.model_providers for f in findings)


def test_data_file_over_max_data_file_size_is_a_coverage_gap(tmp_path: Path, run_connector) -> None:
    (tmp_path / "settings.json").write_text(json.dumps({"padding": "x" * 5_000, "endpoint": ENDPOINT}))
    _, ctx = _scan(run_connector, tmp_path, max_file_size=1_000, max_data_file_size=2_000)
    assert ctx.stats.incomplete
    assert any("settings.json: skipped, file exceeds max_data_file_size" in w for w in ctx.stats.warnings)
    _, strict = _scan(
        run_connector, tmp_path, max_file_size=1_000, max_data_file_size=2_000, strict_coverage=True
    )
    assert any("settings.json: file exceeds max_data_file_size" in e for e in strict.stats.errors)


def test_source_file_keeps_max_file_size(tmp_path: Path, run_connector) -> None:
    (tmp_path / "app.py").write_text("from openai import OpenAI\n" + "# padding\n" * 500)
    _, ctx = _scan(run_connector, tmp_path, max_file_size=1_000)
    assert ctx.stats.incomplete
    assert any("app.py: skipped, file exceeds max_file_size" in w for w in ctx.stats.warnings)


def test_max_data_file_size_is_validated(tmp_path: Path, run_connector) -> None:
    from shadowscan.connectors.base import ConnectorError

    with pytest.raises(ConnectorError, match="max_data_file_size"):
        _scan(run_connector, tmp_path, max_data_file_size=True)


def test_oversize_binary_without_extension_is_skipped(tmp_path: Path, run_connector) -> None:
    (tmp_path / "mcp-publisher").write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 5_000)
    findings, ctx = _scan(run_connector, tmp_path, max_file_size=1_000)
    assert findings == [] and not ctx.stats.incomplete
    assert any("mcp-publisher: skipped binary file over max_file_size" in w for w in ctx.stats.warnings)


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("deploy", b"#!/bin/sh\n" + b"echo deploy\n" * 500),  # a script without an extension
        ("tool.py", b"\x7fELF\x02\x01\x01" + b"\x00" * 5_000),  # binary bytes under a source name
    ],
)
def test_other_oversize_files_stay_coverage_gaps(tmp_path: Path, run_connector, name, content) -> None:
    (tmp_path / name).write_bytes(content)
    _, ctx = _scan(run_connector, tmp_path, max_file_size=1_000)
    assert ctx.stats.incomplete


def test_oversize_test_file_is_scanned_for_credentials_only(tmp_path: Path, run_connector) -> None:
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_client.py").write_text(
        f'from openai import OpenAI\nKEY = "{KEY}"\n' + "# fixture\n" * 500
    )
    findings, ctx = _scan(run_connector, tmp_path, max_file_size=1_000)
    assert not ctx.stats.incomplete
    assert any("test_client.py: test file exceeds max_file_size; scanned for credentials only" in w
               for w in ctx.stats.warnings)  # fmt: skip
    assert [f.kind for f in findings] == [Kind.SECRET]
    assert KEY not in json.dumps([f.to_dict() for f in findings])
    _, strict = _scan(run_connector, tmp_path, max_file_size=1_000, strict_coverage=True)
    assert strict.stats.incomplete
    _, included = _scan(run_connector, tmp_path, max_file_size=1_000, include_tests=True)
    assert included.stats.incomplete


def test_oversize_test_file_without_credential_scanning_is_not_read(tmp_path: Path, run_connector) -> None:
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_client.py").write_text("from openai import OpenAI\n" + "# fixture\n" * 500)
    _, ctx = _scan(run_connector, tmp_path, max_file_size=1_000, scan_secrets=False)
    assert not ctx.stats.incomplete
    assert any("test_client.py: skipped, test file exceeds max_file_size; not analyzed" in w
               for w in ctx.stats.warnings)  # fmt: skip


def test_test_file_too_large_for_a_credential_scan_is_a_gap(tmp_path: Path, run_connector) -> None:
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_client.py").write_text("# fixture\n" * 500)
    _, ctx = _scan(run_connector, tmp_path, max_file_size=1_000, max_data_file_size=1_000)
    assert ctx.stats.incomplete


def test_structured_limit_in_test_code_follows_the_test_code_policy(tmp_path: Path, run_connector) -> None:
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "fixture.json").write_text(
        json.dumps({"OPENAI_API_KEY": KEY, "values": list(range(110_000))})
    )
    findings, ctx = _scan(run_connector, tmp_path)
    assert not ctx.stats.incomplete
    assert any("excerpts withheld" in w for w in ctx.stats.warnings)
    secret = next(f for f in findings if f.kind == Kind.SECRET)
    assert all(not e.snippet for e in secret.evidence)
    assert KEY not in json.dumps([f.to_dict() for f in findings])
    _, included = _scan(run_connector, tmp_path, include_tests=True)
    assert included.stats.incomplete and any("excerpts withheld" in e for e in included.stats.errors)


def _line_of(text: str, value: str) -> int:
    return text[: text.index(value)].count("\n") + 1


def test_credentials_in_large_text_are_matched_across_windows(index) -> None:
    filler = "x" * 99 + "\n"
    lines_per_window = matcher._SECRET_WINDOW // len(filler)
    # The first key crosses the first window boundary; the second lies inside
    # the overlap that the first window also reads.
    text = (
        filler * (lines_per_window - 1)
        + "x" * 80
        + f' k = "{KEY}"\n'
        + filler * 3
        + f'k2 = "{OTHER_KEY}"\n'
        + filler * (2 * lines_per_window)
    )
    assert len(text) > 2 * matcher._SECRET_WINDOW
    matches = [m for m in index.match_secrets(text) if m.signature_id == "provider.anthropic"]
    assert sorted((m.value, m.line) for m in matches) == sorted(
        [(KEY, _line_of(text, KEY)), (OTHER_KEY, _line_of(text, OTHER_KEY))]
    )


def test_credentials_on_one_long_line_are_matched_across_windows(index) -> None:
    text = "a" * (matcher._SECRET_WINDOW - 20) + f' "{KEY}" ' + "b" * (2 * matcher._SECRET_WINDOW)
    matches = [m for m in index.match_secrets(text) if m.signature_id == "provider.anthropic"]
    assert [(m.value, m.line) for m in matches] == [(KEY, 1)]


@pytest.mark.parametrize("directory", ["test_resources", "test-resources"])
def test_test_resource_directories_are_test_code(tmp_path: Path, run_connector, directory: str) -> None:
    (tmp_path / directory).mkdir()
    (tmp_path / directory / "browsers.py").write_text("from openai import OpenAI\n" + "# fixture\n" * 500)
    _, ctx = _scan(run_connector, tmp_path, max_file_size=1_000)
    assert not ctx.stats.incomplete
    assert any("test file exceeds max_file_size" in w for w in ctx.stats.warnings)
