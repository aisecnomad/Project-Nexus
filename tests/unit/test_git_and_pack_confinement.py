"""Git clone hardening and confined signature/inventory walks."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from shadowscan.connectors.code import github as github_mod
from shadowscan.registry import Inventory, InventoryValidationError
from shadowscan.signatures.loader import load_signatures
from shadowscan.utils.git import clone_environment, git_argv_prefix, safe_git_env, validate_git_ref


@pytest.mark.parametrize(
    "name,ok",
    [
        ("main", True),
        ("release/1.2.3", True),
        ("feature_foo-bar", True),
        ("-u", False),
        ("--upload-pack=evil", False),
        ("../etc/passwd", False),
        ("foo/../bar", False),
        ("foo//bar", False),
        ("foo@{0}", False),
        ("foo bar", False),
        ("", False),
        (None, False),
        ("a" * 256, False),
        (".lock", False),
        ("heads.lock", False),
    ],
)
def test_validate_git_ref(name, ok):
    assert (validate_git_ref(name) is not None) is ok
    if ok:
        assert validate_git_ref(name) == name


def test_clone_environment_ignores_system_config_and_sets_hooks(monkeypatch):
    monkeypatch.setenv("GIT_DIR", "/tmp/hostile.git")
    monkeypatch.setenv("GIT_REPLACE_REF_BASE", "refs/replace")
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", "core.hooksPath=/tmp/hooks")
    env = clone_environment("https://github.com", "token", "x-access-token")
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["GIT_CONFIG_GLOBAL"] == os.devnull
    assert "GIT_DIR" not in env
    assert "GIT_REPLACE_REF_BASE" not in env
    assert "GIT_CONFIG_PARAMETERS" not in env
    values = [env[k] for k in env if k.startswith("GIT_CONFIG_VALUE_")]
    keys = [env[k] for k in env if k.startswith("GIT_CONFIG_KEY_")]
    assert "core.hooksPath" in keys
    assert os.devnull in values
    assert any(k.startswith("http.https://github.com/.extraheader") for k in keys)
    assert git_argv_prefix()[1:3] == ["-c", f"core.hooksPath={os.devnull}"]


def test_github_clone_skips_hostile_branch(index, monkeypatch):
    from shadowscan.connectors.base import ConnectorContext
    from shadowscan.connectors.code.github import GitHubConnector

    ctx = ConnectorContext(config={"org": "acme", "mode": "clone"}, index=index)
    connector = GitHubConnector(ctx)
    captured: dict[str, list[str]] = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = list(cmd)

        class R:
            returncode = 0

        return R()

    monkeypatch.setattr(github_mod.subprocess, "run", fake_run)
    monkeypatch.setattr(github_mod.shutil, "which", lambda _: "/usr/bin/git")
    assert connector._clone(
        {"full_name": "acme/app", "clone_url": "https://github.com/acme/app.git", "default_branch": "--upload-pack=evil"},
        "/tmp/dest",
    )
    assert "--branch" not in captured["cmd"]
    assert captured["cmd"][:3] == ["git", "-c", f"core.hooksPath={os.devnull}"]


def test_signature_extra_pack_cannot_override_builtin(tmp_path):
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "override.yaml").write_text(
        "id: framework.langchain\nname: Hostile\ncategory: framework\n"
        "signals:\n  - type: dependency\n    ecosystem: pypi\n    names: [langchain]\n"
    )
    with pytest.raises(ValueError, match="reserved by a built-in"):
        load_signatures(extra_dirs=[pack])
    loaded = load_signatures(extra_dirs=[pack], allow_override=True)
    assert any(s.id == "framework.langchain" and s.name == "Hostile" for s in loaded)


def test_signature_loader_skips_symlinked_pack_files(tmp_path):
    pack = tmp_path / "pack"
    pack.mkdir()
    outside = tmp_path / "outside.yaml"
    outside.write_text(
        "id: hostile.pack\nname: Hostile\ncategory: framework\n"
        "signals:\n  - type: dependency\n    ecosystem: pypi\n    names: [hostile]\n"
    )
    (pack / "link.yaml").symlink_to(outside)
    (pack / "ok.yaml").write_text(
        "id: extra.ok\nname: Ok\ncategory: framework\n"
        "signals:\n  - type: dependency\n    ecosystem: pypi\n    names: [okpkg]\n"
    )
    loaded = load_signatures(extra_dirs=[pack], include_builtin=False)
    assert {s.id for s in loaded} == {"extra.ok"}


def test_inventory_directory_skips_symlinked_files(tmp_path):
    inv = tmp_path / "inv"
    inv.mkdir()
    outside = tmp_path / "outside.yaml"
    outside.write_text("id: hostile\nresources: ['*']\n")
    (inv / "link.yaml").symlink_to(outside)
    (inv / "ok.yaml").write_text("id: approved\nresources: ['github:acme/ok']\n")
    loaded = Inventory.load([inv])
    assert [e.agent_id for e in loaded.entries] == ["approved"]
