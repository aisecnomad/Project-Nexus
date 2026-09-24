"""Credential discovery must not silently claim a host's cloud identity."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from shadowscan.connectors.base import ConnectorContext, ConnectorError
from shadowscan.connectors.cloud.aws import AwsConnector
from shadowscan.connectors.cloud.azure import AzureConnector
from shadowscan.connectors.cloud.gcp import GcpConnector
from shadowscan.connectors.cloud.oci import OciConnector


@pytest.fixture
def aws_environment(monkeypatch, tmp_path):
    pytest.importorskip("boto3")
    config = tmp_path / "config"
    config.write_text("")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(config))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "credentials"))
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_PROFILE", raising=False)
    return config


@pytest.mark.parametrize("allow", [False, True])
def test_aws_metadata_providers_require_opt_in(index, monkeypatch, aws_environment, allow):
    import boto3

    created = []
    session = Mock()
    session.client.return_value.get_caller_identity.return_value = {"Account": "123456789012"}

    def create_session(**kwargs):
        created.append(kwargs["botocore_session"])
        return session

    monkeypatch.setattr(boto3, "Session", create_session)
    connector = AwsConnector(ConnectorContext(index=index, config={"allow_instance_credentials": allow, "account_id": 123456789012}))
    connector._session_()
    sdk = created[0]
    methods = {provider.METHOD for provider in sdk.get_component("credential_provider").providers}
    assert ("iam-role" in methods) is allow
    assert ("container-role" in methods) is allow
    assert "env" in methods
    assert "shared-credentials-file" in methods
    connector._client("lambda", "us-east-1")
    for call in session.client.call_args_list:
        config = call.kwargs["config"]
        assert config.connect_timeout == 10
        assert config.read_timeout == 30
        assert config.retries["total_max_attempts"] == 3
    assert sdk.get_default_client_config().read_timeout == 30


@pytest.mark.parametrize("source", ["Ec2InstanceMetadata", "EcsContainer"])
def test_aws_nested_role_profile_cannot_bypass_credential_policy(index, monkeypatch, aws_environment, source):
    import boto3

    aws_environment.write_text(
        "[profile target]\nrole_arn=arn:aws:iam::123456789012:role/target\nsource_profile=source\n"
        f"[profile source]\nrole_arn=arn:aws:iam::123456789012:role/source\ncredential_source={source}\n"
    )
    session = Mock()
    monkeypatch.setattr(boto3, "Session", session)
    connector = AwsConnector(ConnectorContext(index=index, config={"profile": "target"}))
    with pytest.raises(ConnectorError, match="allow_instance_credentials"):
        connector._session_()
    session.assert_not_called()


def test_gcp_does_not_probe_metadata_without_local_credentials(index, monkeypatch, tmp_path):
    auth = pytest.importorskip("google.auth")
    from google.auth import _cloud_sdk

    default = Mock(side_effect=AssertionError("metadata discovery is forbidden"))
    monkeypatch.setattr(auth, "default", default)
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.delenv("GOOGLE_OAUTH_ACCESS_TOKEN", raising=False)
    monkeypatch.setattr(_cloud_sdk, "get_application_default_credentials_path", lambda: str(tmp_path / "absent"))
    with pytest.raises(ConnectorError, match="allow_instance_credentials"):
        GcpConnector(ConnectorContext(index=index))._auth()
    default.assert_not_called()


@pytest.mark.parametrize("allow", [False, True])
def test_gcp_local_credentials_and_opted_in_discovery_use_bounded_refresh(index, monkeypatch, allow):
    auth = pytest.importorskip("google.auth")
    import google.auth.transport.requests

    creds = Mock(token="test-token")
    load = Mock(return_value=(creds, "project"))
    default = Mock(return_value=(creds, "project"))
    transport = Mock()
    monkeypatch.setattr(auth, "load_credentials_from_file", load)
    monkeypatch.setattr(auth, "default", default)
    monkeypatch.setattr(google.auth.transport.requests.Request, "__call__", transport)
    monkeypatch.delenv("GOOGLE_OAUTH_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    config = {"allow_instance_credentials": True} if allow else {"credentials_file": "operator.json"}
    GcpConnector(ConnectorContext(index=index, config=config))._auth()
    selected = default if allow else load
    selected.assert_called_once()
    request = selected.call_args.kwargs["request"]
    assert creds.refresh.call_args.args == (request,)
    if allow:
        request(url="http://metadata.google.internal", timeout=120)
        assert transport.call_args.kwargs["timeout"] == 30
    else:
        default.assert_not_called()
        with pytest.raises(ValueError):
            request(url="http://metadata.google.internal", timeout=120)
        transport.assert_not_called()


@pytest.mark.parametrize("allow", [False, True])
def test_azure_managed_identity_policy_and_transport_bounds(index, monkeypatch, allow):
    identity = pytest.importorskip("azure.identity")
    constructor = Mock()
    constructor.return_value.get_token.return_value = SimpleNamespace(token="token")
    monkeypatch.setattr(identity, "DefaultAzureCredential", constructor)
    monkeypatch.delenv("AZURE_ACCESS_TOKEN", raising=False)
    connector = AzureConnector(ConnectorContext(index=index, config={"allow_instance_credentials": allow}))
    connector._auth()
    options = constructor.call_args.kwargs
    assert options["exclude_managed_identity_credential"] is not allow
    assert options["connection_timeout"] == 10
    assert options["read_timeout"] == 30
    assert options["retry_total"] == 2
    assert options["process_timeout"] == 10
    assert connector._foundry() == "token"


@pytest.mark.parametrize("auth", ["instance_principal", "resource_principal"])
def test_oci_principals_require_opt_in_before_sdk_auth(index, monkeypatch, auth):
    oci = pytest.importorskip("oci")
    instance = Mock()
    resource = Mock()
    monkeypatch.setattr(oci.auth.signers, "InstancePrincipalsSecurityTokenSigner", instance)
    monkeypatch.setattr(oci.auth.signers, "get_resource_principals_signer", resource)
    connector = OciConnector(ConnectorContext(index=index, config={"auth": auth}))
    with pytest.raises(ConnectorError, match="allow_instance_credentials"):
        connector._init()
    instance.assert_not_called()
    resource.assert_not_called()


def test_oci_opted_in_instance_auth_and_clients_have_bounded_retries(index, monkeypatch):
    oci = pytest.importorskip("oci")
    signer = Mock(return_value=SimpleNamespace(region="us-ashburn-1", tenancy_id="tenancy"))
    monkeypatch.setattr(oci.auth.signers, "InstancePrincipalsSecurityTokenSigner", signer)
    connector = OciConnector(ConnectorContext(index=index, config={
        "auth": "instance_principal", "allow_instance_credentials": True,
    }))
    connector._init()
    assert set(signer.call_args.kwargs) == {"retry_strategy", "federation_client_retry_strategy"}
    constructor = Mock()
    connector._client(constructor)
    assert constructor.call_args.kwargs["timeout"] == (10, 30)
    assert constructor.call_args.kwargs["retry_strategy"] is not None
    assert constructor.call_args.kwargs["signer"] is connector._signer


@pytest.mark.parametrize("account", [123456789012, "123456789012", "012345678901"])
def test_aws_account_id_configuration_preserves_canonical_identity(index, account):
    connector = AwsConnector(ConnectorContext(index=index, config={"account_id": account}))
    assert connector.account == str(account)


@pytest.mark.parametrize("account", [True, 123, 123456789012.0, " 123456789012", "１２３４５６７８９０１２"])
def test_aws_invalid_account_id_configuration_is_rejected(index, account):
    with pytest.raises(ConnectorError, match="12 ASCII digits"):
        AwsConnector(ConnectorContext(index=index, config={"account_id": account}))


def test_aws_offline_account_labels_remain_supported(index):
    connector = AwsConnector(ConnectorContext(index=index, config={"input": "export.jsonl", "account_id": "lab-account"}))
    assert connector.account == "lab-account"


def _gcp_refresh_request(index, monkeypatch, allow=False):
    auth = pytest.importorskip("google.auth")
    creds = Mock(token="token")
    monkeypatch.setattr(auth, "load_credentials_from_file", Mock(return_value=(creds, "project")))
    monkeypatch.delenv("GOOGLE_OAUTH_ACCESS_TOKEN", raising=False)
    connector = GcpConnector(ConnectorContext(index=index, config={"credentials_file": "local.json", "allow_instance_credentials": allow}))
    connector._auth()
    return creds.refresh.call_args.args[0]


def _response(status, body=b"", headers=None):
    from io import BytesIO

    from requests import Response

    response = Response()
    response.status_code = status
    response.headers.update(headers or {})
    response.raw = BytesIO(body)
    return response


@pytest.mark.parametrize("allow", [False, True])
def test_gcp_refresh_never_forwards_post_credentials_across_redirect_origin(index, monkeypatch, allow):
    from shadowscan.utils.http import _DestinationPolicyAdapter

    request = _gcp_refresh_request(index, monkeypatch, allow)
    sent = []

    def send(_self, prepared, **kwargs):
        sent.append(prepared)
        assert kwargs["stream"] is True
        response = _response(307, headers={"Location": "https://attacker.example/collect"})
        response.request = prepared
        return response

    monkeypatch.setattr(_DestinationPolicyAdapter, "send", send)
    with pytest.raises(ValueError, match="origin"):
        request("https://oauth2.googleapis.com/token", method="POST", body=b"refresh_token=secret")
    assert len(sent) == 1
    assert sent[0].url == "https://oauth2.googleapis.com/token"


def test_gcp_refresh_response_size_is_bounded(index, monkeypatch):
    from shadowscan.utils.http import _DestinationPolicyAdapter

    request = _gcp_refresh_request(index, monkeypatch)
    monkeypatch.setattr(_DestinationPolicyAdapter, "send", lambda *args, **kwargs: _response(200, b"x" * (1024 * 1024 + 1)))
    with pytest.raises(ValueError, match="byte limit"):
        request("https://oauth2.googleapis.com/token", method="POST", body=b"refresh_token=secret")


def test_gcp_refresh_preserves_oauth_error_status_and_body(index, monkeypatch):
    from shadowscan.utils.http import _DestinationPolicyAdapter

    request = _gcp_refresh_request(index, monkeypatch)
    error = b'{"error":"invalid_grant"}'
    monkeypatch.setattr(_DestinationPolicyAdapter, "send", lambda *args, **kwargs: _response(400, error))
    response = request("https://oauth2.googleapis.com/token", method="POST", body=b"refresh_token=expired")
    assert response.status == 400
    assert response.data == error


def test_http_status_policy_option_requires_boolean():
    from shadowscan.utils.http import HttpClient

    with pytest.raises(TypeError, match="raise_for_status"):
        HttpClient().request("GET", "https://example.com", raise_for_status="false")


def test_gcp_opted_in_metadata_http_remains_bounded_and_refuses_redirects(index, monkeypatch):
    from requests.adapters import HTTPAdapter

    request = _gcp_refresh_request(index, monkeypatch, allow=True)
    calls = []

    def send(_self, prepared, **kwargs):
        calls.append(prepared.url)
        assert kwargs["stream"] is True
        response = _response(200, b'{"access_token":"metadata-token"}') if len(calls) == 1 else _response(307, headers={"Location": "http://other.example/"})
        response.request = prepared
        return response

    monkeypatch.setattr(HTTPAdapter, "send", send)
    url = "http://metadata.google.internal/computeMetadata/v1/token"
    response = request(url, headers={"Metadata-Flavor": "Google"})
    assert response.status == 200
    assert response.data == b'{"access_token":"metadata-token"}'
    with pytest.raises(ValueError, match="redirects are refused"):
        request(url)
    assert calls == [url, url]
