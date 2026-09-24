from __future__ import annotations

import pytest

from shadowscan.config import ScanConfig, expand_env, validate_connector_timeout


def test_missing_secret_env_fails_closed(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    with pytest.raises(ValueError, match="missing required environment variable GITHUB_TOKEN"):
        ScanConfig.from_dict({"connectors": [{"name": "code.github", "token": "${GITHUB_TOKEN}"}]})


def test_empty_secret_value_fails_closed():
    with pytest.raises(ValueError, match="missing required secret"):
        expand_env("", key="token")
    with pytest.raises(ValueError, match="missing required secret"):
        ScanConfig.from_dict({"connectors": [{"name": "code.github", "token": "   "}]})


def test_secret_default_and_nonsecret_empty_remain_allowed(monkeypatch):
    monkeypatch.delenv("MISSING_TOKEN", raising=False)
    cfg = ScanConfig.from_dict({"connectors": [{"name": "code.github", "token": "${MISSING_TOKEN:-none}", "org": "${MISSING_ORG}"}]})
    assert cfg.connectors[0].config["token"] == "none"
    assert cfg.connectors[0].config["org"] == ""


def test_connector_timeout_bounds():
    assert validate_connector_timeout("30") == 30
    with pytest.raises(ValueError, match="connector_timeout"):
        validate_connector_timeout(0)
    with pytest.raises(ValueError, match="connector_timeout"):
        ScanConfig.from_dict({"options": {"connector_timeout": 0}})
