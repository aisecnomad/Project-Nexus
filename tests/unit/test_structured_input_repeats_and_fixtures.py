"""Repository YAML that repeats a field with the same value, and malformed test fixtures.

Both used to make real repository scans incomplete (exit 3) although nothing
was left unread: an evaluation task listing one metadata field twice, and test
suites that keep invalid manifests on purpose.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shadowscan.utils.safe_yaml import YAMLIntegrityError, strict_bounded_safe_load


@pytest.mark.parametrize(
    "text",
    [
        "task: math\nmetadata:\n  canonical: base\n  version: 1\n  canonical: base\n",
        "k: v\nk: 'v'\n",
        'k: {a: 1, b: [x, "y"]}\nk: {a: 1, b: [x, y]}\n',
        "base: &b {a: 1}\nk: *b\nk: *b\n",
    ],
    ids=["scalar", "quoted-scalar", "mapping", "alias"],
)
def test_repository_yaml_accepts_a_field_repeated_with_the_same_value(text: str) -> None:
    assert strict_bounded_safe_load(text, require_string_keys=False)


@pytest.mark.parametrize(
    "text",
    [
        "k: v\nk: w\n",
        "k: 1\nk: true\n",
        "k: 1\nk: 1.0\n",
        "k: 01\nk: 1\n",
        "k: {a: 1, b: 2}\nk: {b: 2, a: 1}\n",
        "k: [1, 2]\nk: [1, 2, 3]\n",
        "base: &b {a: 1}\nother: &o {a: 1}\nm:\n  <<: *b\n  <<: *o\n",
    ],
    ids=["text", "int-bool", "int-float", "spelling", "order", "length", "merge"],
)
def test_repository_yaml_rejects_a_field_repeated_with_another_value(text: str) -> None:
    with pytest.raises(YAMLIntegrityError, match="Duplicate YAML field"):
        strict_bounded_safe_load(text, require_string_keys=False)


def test_offline_yaml_rejects_every_repeated_field() -> None:
    with pytest.raises(YAMLIntegrityError, match="Duplicate YAML field"):
        strict_bounded_safe_load("k: v\nk: v\n")


def test_comparing_repeated_values_is_bounded() -> None:
    items = ", ".join(str(n) for n in range(12_000))
    with pytest.raises(YAMLIntegrityError, match="Duplicate YAML field"):
        strict_bounded_safe_load(f"k: [{items}]\nk: [{items}]\n", require_string_keys=False)


def test_identical_repeat_keeps_a_repository_scan_complete(tmp_path: Path, run_connector) -> None:
    (tmp_path / "task.yaml").write_text("task: math\nmetadata:\n  canonical: base\n  canonical: base\n")
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert not ctx.stats.incomplete


def test_conflicting_repeat_still_makes_a_repository_scan_incomplete(tmp_path: Path, run_connector) -> None:
    (tmp_path / "task.yaml").write_text("task: math\nmetadata:\n  canonical: base\n  canonical: other\n")
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert any("YAMLIntegrityError" in error for error in ctx.stats.errors)


MALFORMED_MANIFEST = '{"name": "fixture", "dependencies": {'


def test_malformed_fixture_in_test_code_is_a_warning(tmp_path: Path, run_connector) -> None:
    fixtures = tmp_path / "tests" / "fixtures"
    fixtures.mkdir(parents=True)
    (fixtures / "package.json").write_text(MALFORMED_MANIFEST)
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors
    assert not ctx.stats.incomplete
    assert any("tests/fixtures/package.json: invalid JSON" in warning for warning in ctx.stats.warnings)


def test_malformed_manifest_outside_test_code_is_still_an_error(tmp_path: Path, run_connector) -> None:
    (tmp_path / "package.json").write_text(MALFORMED_MANIFEST)
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert any("package.json: invalid JSON" in error for error in ctx.stats.errors)


@pytest.mark.parametrize("option", ["include_tests", "strict_coverage"])
def test_test_code_options_keep_a_malformed_fixture_a_coverage_gap(
    tmp_path: Path, run_connector, option: str
) -> None:
    fixtures = tmp_path / "tests" / "fixtures"
    fixtures.mkdir(parents=True)
    (fixtures / "package.json").write_text(MALFORMED_MANIFEST)
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, **{option: True})
    assert ctx.stats.incomplete
