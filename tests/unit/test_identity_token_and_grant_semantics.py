"""Token endpoint responses fail closed; interactive grants are not machine identities."""

from __future__ import annotations

import pytest

from shadowscan.connectors.base import ConnectorError
from shadowscan.connectors.identity.common import MACHINE_GRANT_TYPES, access_token


def test_token_response_without_an_access_token_is_a_connector_error():
    with pytest.raises(ConnectorError, match="did not include an access token"):
        access_token({"error": "invalid_client"}, "identity.entra")
    with pytest.raises(ConnectorError):
        access_token(["not", "a", "mapping"], "identity.auth0")
    with pytest.raises(ConnectorError):
        access_token({"access_token": ""}, "identity.google-workspace")
    assert access_token({"access_token": "abc", "expires_in": 60}, "identity.entra") == "abc"


def test_device_code_grant_requires_a_person_and_is_not_machine_only():
    assert "urn:ietf:params:oauth:grant-type:device_code" not in MACHINE_GRANT_TYPES
    assert "client_credentials" in MACHINE_GRANT_TYPES
