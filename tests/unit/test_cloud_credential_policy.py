"""Session-scoped cloud credential policy residuals for 0.1.1."""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from shadowscan.connectors.base import ConnectorContext, ConnectorError
from shadowscan.connectors.cloud import credentials as creds
from shadowscan.connectors.cloud.aws import AwsConnector
from shadowscan.connectors.cloud.gcp import GcpConnector
from shadowscan.signatures import SignatureIndex


def test_adc_prefers_explicit_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    explicit = tmp_path / "adc.json"
    explicit.write_text("{}", encoding="utf-8")
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "missing-home")
    assert creds.application_default_credentials_path(str(explicit)) == explicit


def test_adc_uses_env_then_well_known(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env_file = tmp_path / "env.json"
    env_file.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(env_file))
    assert creds.application_default_credentials_path() == env_file


def test_explicit_or_environment_adc_does_not_fall_back_after_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    well_known = tmp_path / ".config" / "gcloud" / "application_default_credentials.json"
    well_known.parent.mkdir(parents=True)
    well_known.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(tmp_path / "missing-env.json"))
    assert creds.application_default_credentials_path() is None
    assert creds.application_default_credentials_path(str(tmp_path / "missing-explicit.json")) is None
    with pytest.raises(ConnectorError, match="allow_instance_credentials"):
        creds.require_local_adc(str(tmp_path / "missing-explicit.json"))
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS")
    assert creds.application_default_credentials_path() == well_known


def test_adc_skips_symlinks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "secret.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "adc.json"
    link.symlink_to(target)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(link))
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "missing-home")
    monkeypatch.delenv("APPDATA", raising=False)
    with pytest.raises(ConnectorError):
        creds.require_local_adc()


def test_require_local_adc_fail_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    monkeypatch.delenv("APPDATA", raising=False)
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "empty")
    with pytest.raises(ConnectorError, match="allow_instance_credentials"):
        creds.require_local_adc()


class _Resolver:
    def __init__(self) -> None:
        self.removed: list[str] = []

    def remove(self, name: str) -> None:
        self.removed.append(name)


class _Session:
    def __init__(self) -> None:
        self.vars: dict[str, object] = {}
        self.resolver = _Resolver()
        self.full_config = {"profiles": {"default": {}}}

    def set_config_variable(self, key: str, value: object) -> None:
        self.vars[key] = value

    def get_component(self, name: str) -> object:
        assert name == "credential_provider"
        return self.resolver

    def get_config_variable(self, name: str) -> str:
        return "default"


def test_aws_session_disables_imds_when_instance_creds_denied() -> None:
    session = _Session()
    creds.configure_aws_session(session, allow_instance=False)
    assert session.vars["metadata_service_num_attempts"] == 0
    assert session.vars["metadata_service_timeout"] == 3
    assert session.resolver.removed == ["iam-role", "container-role"]


def test_aws_session_keeps_imds_when_opted_in() -> None:
    session = _Session()
    creds.configure_aws_session(session, allow_instance=True)
    assert session.vars["metadata_service_num_attempts"] == 1
    assert session.resolver.removed == []


def test_aws_rejects_profile_instance_source() -> None:
    session = _Session()
    session.full_config = {
        "profiles": {"audit": {"credential_source": "Ec2InstanceMetadata"}},
    }
    with pytest.raises(ConnectorError, match="allow_instance_credentials"):
        creds.reject_instance_profile_sources(session, "audit")


def test_aws_denied_provider_removal_fails_closed() -> None:
    session = _Session()
    session.resolver.remove = Mock(side_effect=RuntimeError("private diagnostic"))  # type: ignore[method-assign]
    with pytest.raises(ConnectorError, match="cannot enforce instance credential policy") as error:
        creds.configure_aws_session(session, allow_instance=False)
    assert "private diagnostic" not in str(error.value)


def test_aws_connector_applies_policy_to_real_botocore_session(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("botocore")
    from botocore.session import Session as BotocoreSession

    sdk_sessions = []
    sts = Mock()
    sts.get_caller_identity.return_value = {"Account": "123456789012"}
    fake = Mock()
    fake.client.return_value = sts

    def fake_boto_session(*, botocore_session):
        assert isinstance(botocore_session, BotocoreSession)
        sdk_sessions.append(botocore_session)
        return fake

    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.setitem(sys.modules, "boto3", SimpleNamespace(Session=fake_boto_session))
    ctx = ConnectorContext(config={"allow_instance_credentials": False}, index=SignatureIndex([]))
    AwsConnector(ctx)._session_()
    sdk = sdk_sessions[0]
    assert sdk.get_config_variable("metadata_service_num_attempts") == 0
    names = {provider.METHOD for provider in sdk.get_component("credential_provider").providers}
    assert "iam-role" not in names and "container-role" not in names


def test_gcp_connector_only_uses_explicit_local_adc_when_instance_denied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    google_auth = pytest.importorskip("google.auth")
    local = tmp_path / "local-adc.json"
    local.write_text("{}", encoding="utf-8")
    refresh = Mock()
    load = Mock(return_value=(SimpleNamespace(token="synthetic", refresh=refresh), "project"))
    monkeypatch.setattr(google_auth, "load_credentials_from_file", load)
    monkeypatch.setattr(google_auth, "default", Mock(side_effect=AssertionError("default ADC chain must not run")))
    ctx = ConnectorContext(config={"credentials_file": str(local), "allow_instance_credentials": False},
                           index=SignatureIndex([]))
    GcpConnector(ctx)._auth()
    assert load.call_args.args == (str(local),)
    refresh.assert_called_once()


def test_gcp_connector_rejects_missing_local_adc_without_default_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    google_auth = pytest.importorskip("google.auth")
    load = Mock(side_effect=AssertionError("no file should be loaded"))
    default = Mock(side_effect=AssertionError("default ADC chain must not run"))
    monkeypatch.setattr(google_auth, "load_credentials_from_file", load)
    monkeypatch.setattr(google_auth, "default", default)
    ctx = ConnectorContext(config={"credentials_file": str(tmp_path / "missing.json"),
                                   "allow_instance_credentials": False}, index=SignatureIndex([]))
    with pytest.raises(ConnectorError, match="allow_instance_credentials"):
        GcpConnector(ctx)._auth()
    load.assert_not_called()
    default.assert_not_called()
