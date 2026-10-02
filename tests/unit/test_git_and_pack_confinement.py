"""Git clone hardening and confined signature/inventory walks."""

from __future__ import annotations

import os

import pytest

from shadowscan.connectors.code import github as github_mod
from shadowscan.connectors.code import remote as remote_mod
from shadowscan.registry import Inventory
from shadowscan.signatures.loader import load_signatures
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


def test_inventory_directory_skips_symlinked_files(tmp_path):
    inv = tmp_path / "inv"
    inv.mkdir()
    outside = tmp_path / "outside.yaml"
    outside.write_text("id: hostile\nresources: ['*']\n")
    (inv / "link.yaml").symlink_to(outside)
    (inv / "ok.yaml").write_text("id: approved\nresources: ['github:acme/ok']\n")
    loaded = Inventory.load([inv])
    assert [e.agent_id for e in loaded.entries] == ["approved"]


PACK = (
    "id: extra.ok\nname: Ok\ncategory: framework\n"
    "signals:\n  - type: dependency\n    ecosystem: pypi\n    names: [okpkg]\n"
    "# private-pack-content\n"
)


def _pack_layout(tmp_path, layout):
    pack = tmp_path / "pack"
    pack.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "pack.yaml").write_text(PACK)
    if layout == "unsupported-names":
        (pack / "pack.yamll").write_text(PACK)
        (pack / "pack.json").write_text(PACK)
    elif layout == "symlinked-file":
        (pack / "link.yaml").symlink_to(outside / "pack.yaml")
    elif layout == "symlinked-directory":
        (pack / "linked").symlink_to(outside, target_is_directory=True)
    return pack


SKIPPED = {
    "empty": [],
    "unsupported-names": ["pack.json (unsupported file type)", "pack.yamll (unsupported file type)"],
    "symlinked-file": ["link.yaml (symbolic link)"],
    "symlinked-directory": ["linked (symbolic link)"],
}


@pytest.mark.parametrize(("layout", "listed"), SKIPPED.items(), ids=list(SKIPPED))
def test_custom_pack_directory_without_packs_fails_closed(tmp_path, capsys, layout, listed):
    from click.testing import CliRunner

    from shadowscan.cli import main
    from shadowscan.signatures.loader import SignaturePackError
    from shadowscan.signatures.validate import main as validate

    pack = _pack_layout(tmp_path, layout)
    for include_builtin in (True, False):
        with pytest.raises(SignaturePackError, match="contains no .yaml or .yml signature packs") as caught:
            load_signatures(extra_dirs=[pack], include_builtin=include_builtin)
        message = str(caught.value)
        assert str(pack) in message and "private-pack-content" not in message
        assert all(name in message for name in listed)
    assert validate([str(pack)]) == 1
    assert "contains no .yaml or .yml signature packs" in capsys.readouterr().err
    for args in (
        ["signatures", "list", "-s", str(pack)],
        ["code", str(tmp_path / "outside"), "-s", str(pack)],
    ):
        result = CliRunner().invoke(main, args)
        assert result.exit_code == 1 and "contains no .yaml or .yml signature packs" in result.output


def test_skipped_pack_symlinks_are_named_in_a_warning(tmp_path, caplog):
    pack = _pack_layout(tmp_path, "symlinked-file")
    (pack / "ok.yaml").write_text(PACK)
    with caplog.at_level("WARNING", logger="shadowscan.signatures"):
        loaded = load_signatures(extra_dirs=[pack], include_builtin=False)
    assert [s.id for s in loaded] == ["extra.ok"]
    assert [record.getMessage() for record in caplog.records] == [
        f"signature directory {pack}: skipped symbolic link link.yaml"
    ]


@pytest.mark.parametrize("glob", [False, True])
def test_skipped_inventory_symlinks_are_reported(tmp_path, index, glob):
    from click.testing import CliRunner

    from shadowscan.cli import main
    from shadowscan.config import ConnectorSpec, ScanConfig
    from shadowscan.engine import Engine

    inv = tmp_path / "inv"
    inv.mkdir()
    (tmp_path / "outside.yaml").write_text("id: hostile\nresources: ['github:acme/hostile']\n")
    (inv / "link.yaml").symlink_to(tmp_path / "outside.yaml")
    (inv / "ok.yaml").write_text("id: approved\nresources: ['github:acme/ok']\n")
    path = str(inv / "*.yaml") if glob else str(inv)
    loaded = Inventory.load([path])
    assert [e.agent_id for e in loaded.entries] == ["approved"]
    assert loaded.skipped_links == [str(inv / "link.yaml")]
    warning = f"inventory {inv / 'link.yaml'}: symbolic link skipped (links are not followed)"
    source = tmp_path / "src"
    source.mkdir()
    config = ScanConfig(
        connectors=[ConnectorSpec("code.filesystem", {"path": str(source)})], inventory=[path]
    )
    result = Engine(config, index).run()
    assert [w for s in result.stats if s.connector == "engine.inventory" for w in s.warnings] == [warning]
    assert result.complete
    checked = CliRunner().invoke(main, ["inventory", "check", path])
    assert checked.exit_code == 0 and warning in " ".join(checked.output.split())


@pytest.mark.parametrize("pattern", ["inv/**", "invv/*.yaml", "inv/*.yml"])
def test_inventory_glob_matching_nothing_is_an_error_like_a_missing_path(tmp_path, pattern):
    from click.testing import CliRunner

    from shadowscan.cli import main
    from shadowscan.errors import SetupPathError

    (tmp_path / "inv").mkdir()
    (tmp_path / "inv" / "agents.yaml").write_text("id: approved\nresources: ['github:acme/ok']\n")
    with pytest.raises(SetupPathError, match="inventory glob matched no files"):
        Inventory.load([tmp_path / pattern])
    result = CliRunner().invoke(main, ["code", str(tmp_path / "inv"), "--inventory", str(tmp_path / pattern)])
    assert result.exit_code == 1 and "inventory glob matched no files" in result.output
