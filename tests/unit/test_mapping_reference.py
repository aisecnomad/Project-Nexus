"""The generated mapping reference lists every catalog, entry and rule as literal Markdown."""

from __future__ import annotations

import pytest

from shadowscan.mappings import load_mappings
from tools import mapping_reference
from tools.mapping_reference import _text, render


@pytest.mark.parametrize(
    ("value", "markdown"),
    [
        ("Tool Misuse & Exploitation", "Tool Misuse & Exploitation"),
        ("a | b * c _d_ [e] {f}", "a \\| b \\* c \\_d\\_ \\[e\\] \\{f\\}"),
        ("<script>", "&lt;script&gt;"),
        ("quote ` here", "quote \\` here"),
        ("line one\n  line two", "line one line two"),
    ],
)
def test_values_are_literal_markdown(value, markdown):
    assert _text(value) == markdown


def test_every_catalog_entry_and_rule_is_listed():
    page = render()
    index = load_mappings()
    for catalog in index.catalogs:
        assert f"### `{catalog.prefix}`" in page
        assert catalog.source_url in page
        for entry in catalog.entries:
            assert f"| `{entry.ref}` |" in page
    for rule in index.rules:
        assert f"| `{rule.id}` |" in page
    assert "not compliance determinations" in page
    assert "`metadata.autonomy.floor` at least 4" in page
    assert "shadow (not in the inventory)" in page
    assert "`workflow`; and no owner recorded |" in page


def test_check_reports_a_stale_page(monkeypatch, tmp_path, capsys):
    page = tmp_path / "mappings-reference.md"
    monkeypatch.setattr(mapping_reference, "REFERENCE", page)
    assert mapping_reference.main(["--check"]) == 1
    assert "is stale" in capsys.readouterr().err
    assert mapping_reference.main([]) == 0
    assert page.read_text(encoding="utf-8") == render()
    assert mapping_reference.main(["--check"]) == 0
    assert mapping_reference.main(["--write"]) == 2
