"""Git clone hardening and confined signature/inventory walks."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from shadowscan.connectors.code import github as github_mod
from shadowscan.connectors.code import remote as remote_mod
from shadowscan.registry import Inventory
from shadowscan.signatures.loader import load_signatures, signature_source_digest
from shadowscan.utils import files as files_mod
from shadowscan.utils.files import policy_files
from shadowscan.utils.git import clone_environment, git_argv_prefix, validate_git_ref


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

    def fake_clone(cmd, env, ctx, timeout, *, destination, max_bytes):
        captured["cmd"] = list(cmd)
        assert destination == "/tmp/dest"
        assert max_bytes == connector.clone_max_bytes
        return True

    monkeypatch.setattr(remote_mod, "run_bounded_clone", fake_clone)
    monkeypatch.setattr(github_mod.shutil, "which", lambda _: "/usr/bin/git")
    assert connector._clone(
        {
            "full_name": "acme/app",
            "clone_url": "https://github.com/acme/app.git",
            "default_branch": "--upload-pack=evil",
        },
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


def test_inventory_directory_rejects_symlinked_files(tmp_path):
    inv = tmp_path / "inv"
    inv.mkdir()
    outside = tmp_path / "outside.yaml"
    outside.write_text("id: hostile\nresources: ['*']\n")
    (inv / "link.yaml").symlink_to(outside)
    (inv / "ok.yaml").write_text("id: approved\nresources: ['github:acme/ok']\n")
    with pytest.raises(ValueError, match="symbolic link"):
        Inventory.load([inv])


@pytest.mark.parametrize("reader", ["signatures", "signature_digest", "inventory"])
@pytest.mark.parametrize("deny_root", [False, True])
def test_policy_directory_readers_fail_closed_when_walk_is_denied(tmp_path, monkeypatch, reader, deny_root):
    """A requested policy tree must not silently lose inaccessible subtrees."""
    root = tmp_path / "policies"
    blocked = root if deny_root else root / "blocked"
    blocked.mkdir(parents=True)
    policy = "id: approved\nresources: ['github:acme/app']\n"
    if reader != "inventory":
        policy = (
            "id: extra.hidden\nname: Hidden\ncategory: framework\n"
            "signals:\n  - type: dependency\n    ecosystem: pypi\n    names: [hiddenpkg]\n"
        )
    (blocked / "policy.yaml").write_text(policy)
    scandir = os.scandir

    def deny_selected_directory(path):
        if Path(path) == blocked:
            raise PermissionError("denied policy subtree")
        return scandir(path)

    monkeypatch.setattr(files_mod.os, "scandir", deny_selected_directory)
    with pytest.raises(ValueError, match="^policy directory could not be read$"):
        if reader == "signatures":
            load_signatures(extra_dirs=[root], include_builtin=False)
        elif reader == "signature_digest":
            signature_source_digest(extra_dirs=[root], include_builtin=False)
        else:
            Inventory.load([root])


def test_policy_directory_limit_applies_to_empty_directories(tmp_path, monkeypatch):
    """An entry budget must stop directory-only trees before any file is found."""
    (tmp_path / "first").mkdir()
    (tmp_path / "second").mkdir()
    monkeypatch.setattr(files_mod, "MAX_POLICY_FILES", 1)

    with pytest.raises(ValueError, match="limit"):
        list(policy_files(tmp_path, {".yaml"}))
