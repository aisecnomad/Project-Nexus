"""TLS policy cannot be disabled through requests' other falsy settings."""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from shadowscan.utils.http import HttpClient


@pytest.mark.parametrize("setting", [False, 0, "", []])
def test_falsy_per_request_tls_settings_never_reach_transport(setting):
    session = Mock(headers={}, verify=True)
    client = HttpClient("https://8.8.8.8", session=session)
    with pytest.raises(ValueError, match="TLS certificate verification"):
        client.get("/items", verify=setting)
    session.request.assert_not_called()


@pytest.mark.parametrize("setting", [False, None, 0, "", []])
def test_falsy_session_tls_settings_never_reach_transport(setting):
    session = Mock(headers={}, verify=setting)
    client = HttpClient("https://8.8.8.8", session=session)
    with pytest.raises(ValueError, match="TLS certificate verification"):
        client.get("/items")
    session.request.assert_not_called()
