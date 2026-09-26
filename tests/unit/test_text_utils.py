"""host_of() must name the actual host, never a URL's embedded credentials."""

from __future__ import annotations

import pytest

from shadowscan.utils.text import host_of


@pytest.mark.parametrize("url, host", [
    ("https://api.openai.com/v1", "api.openai.com"),
    ("https://api.openai.com:8443/v1", "api.openai.com"),
    ("api.openai.com", "api.openai.com"),
    ("api.openai.com:8080", "api.openai.com"),
    # A gateway upstream configured with embedded basic-auth credentials must
    # still resolve to the real host, not the username before the '@'.
    ("https://svc-account:hunter2@example.com/v1", "example.com"),
    ("https://svc-account:hunter2@example.com:8443/v1", "example.com"),
    ("http://user@example.com/v1", "example.com"),
    ("postgres://user:p%40ss@db.example.com:5432/app", "db.example.com"),
    # A userinfo-looking '@' after the authority (in the path) is not one.
    ("https://example.com/@handle", "example.com"),
])
def test_host_of_ignores_embedded_userinfo(url, host):
    assert host_of(url) == host


def test_host_of_accepts_none_and_empty():
    assert host_of(None) is None
    assert host_of("") is None
