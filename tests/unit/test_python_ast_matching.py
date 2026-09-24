"""Python AST confirmation drops comment/string lexical hits."""

from __future__ import annotations

from types import SimpleNamespace

from shadowscan.connectors.code.ast_python import filter_python_matches, parse_python_units


def _match(signal_type: str, value: str, line: int):
    return SimpleNamespace(
        signal=SimpleNamespace(type=signal_type),
        value=value,
        line=line,
        extra={},
    )


def test_comment_import_is_dropped():
    source = "x = 1\n# import langchain\n"
    matches = [_match("import", "import langchain", 2)]
    kept, units = filter_python_matches(source, matches)
    assert units.parse_ok
    assert kept == []


def test_real_import_is_kept():
    source = "import langchain\n"
    matches = [_match("import", "import langchain", 1)]
    kept, units = filter_python_matches(source, matches)
    assert units.parse_ok
    assert len(kept) == 1


def test_unparseable_python_keeps_matches():
    source = "def broken(\n"
    matches = [_match("import", "import langchain", 1)]
    kept, units = filter_python_matches(source, matches)
    assert not units.parse_ok
    assert len(kept) == 1
