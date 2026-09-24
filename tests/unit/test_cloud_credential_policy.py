"""Session-scoped cloud credential policy residuals for 0.1.1."""

from __future__ import annotations

from pathlib import Path

import pytest

from shadowscan.connectors.base import ConnectorError
from shadowscan.connectors.cloud import credentials as creds


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
