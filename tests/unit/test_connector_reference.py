"""The generated connector reference escapes descriptions for the docs Markdown stack."""

from __future__ import annotations

import pytest

from tools.connector_reference import _text, render


@pytest.mark.parametrize(
    ("description", "markdown"),
    [
        # attr_list would read braces as attributes and swallow the text.
        ("mapping {name: 'App Name'}", "mapping \\{name: 'App Name'\\}"),
        # Python-Markdown has no backslash escape for "<".
        ("https://<org>.okta.com", "https://&lt;org&gt;.okta.com"),
        ("a | b * c _d_ [e]", "a \\| b \\* c \\_d\\_ \\[e\\]"),
        # Code spans stay verbatim; a pipe inside one does not split the cell.
        ("use `a|b` or `max_files`", "use `a|b` or `max_files`"),
        # An unbalanced backtick is escaped once, not twice.
        ("quote ` here", "quote \\` here"),
        ("line one\n  line two", "line one line two"),
    ],
)
def test_descriptions_are_literal_markdown(description, markdown):
    assert _text(description) == markdown


def test_every_built_in_connector_has_a_section():
    from shadowscan.connectors import builtin_connector_names

    page = render()
    for name in builtin_connector_names():
        assert f"### `{name}`" in page
