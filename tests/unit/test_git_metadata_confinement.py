"""Real local repositories cannot redirect or amplify history enrichment."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import zlib
from pathlib import Path

import pytest

from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.utils.git import read_git_snapshot, read_gitlink_paths, safe_git_env


def _git(root: Path, *args: str, data: bytes | None = None) -> bytes:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        env=safe_git_env(),
        input=data,
        capture_output=True,
        check=True,
    ).stdout


def _repository(root: Path) -> Path:
    root.mkdir()
    _git(root, "init", "--quiet", "-b", "main")
    (root / "agent.py").write_text("from crewai import Agent\n")
    _git(root, "add", "agent.py")
    _git(
        root,
        "-c",
        "user.name=Synthetic Outside Author",
        "-c",
        "user.email=synthetic-outside@example.test",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "--quiet",
        "-m",
        "synthetic source",
    )
    return root


@pytest.mark.parametrize(
    "redirect",
    [
        "commondir",
        "alternate-objects",
        "uppercase-alternates",
        "http-alternates",
        "objects-link",
        "refs-link",
        "config-link",
    ],
)
def test_history_readers_reject_external_metadata_and_keep_source_findings(tmp_path, index, redirect):
    outside = _repository(tmp_path / "outside")
    root = _repository(tmp_path / "scanned")
    marker = root / ".git"
    external = outside / ".git"
    if redirect == "commondir":
        (marker / "commondir").write_text(str(external) + "\n")
    elif redirect in {"alternate-objects", "uppercase-alternates", "http-alternates"}:
        name = {
            "alternate-objects": "alternates",
            "uppercase-alternates": "ALTERNATES",
            "http-alternates": "http-alternates",
        }[redirect]
        (marker / "objects" / "info" / name).write_text(str(external / "objects") + "\n")
    else:
        name = redirect.removesuffix("-link")
        target = marker / name
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink()
        target.symlink_to(external / name, target_is_directory=(external / name).is_dir())

    assert read_git_snapshot(root) is None
    assert read_gitlink_paths(root) is None
    connector = FilesystemConnector(
        ConnectorContext(config={"path": str(root), "use_git": True}, index=index)
    )
    findings = connector.run()
    assert any("framework.crewai" in finding.frameworks for finding in findings)
    assert connector.ctx.stats.incomplete
    assert all(finding.owner is None for finding in findings)
    assert "synthetic-outside@example.test" not in repr([finding.to_dict() for finding in findings])


def test_compressed_commit_with_large_author_cannot_expand_report_metadata(tmp_path, index):
    root = _repository(tmp_path / "large-author")
    tree = _git(root, "rev-parse", "HEAD^{tree}").strip().decode("ascii")
    author = b"A" * (2 * 1024 * 1024)
    commit = (
        f"tree {tree}\nauthor ".encode()
        + author
        + b" <large-author@example.test> 1700000000 +0000\n"
        + b"committer Synthetic <synthetic@example.test> 1700000000 +0000\n\nprobe\n"
    )
    obj = b"commit " + str(len(commit)).encode("ascii") + b"\0" + commit
    object_id = hashlib.sha1(obj, usedforsecurity=False).hexdigest()
    compressed = zlib.compress(obj)
    assert len(compressed) < 4096  # the disk-size guard cannot bound this output
    target = root / ".git" / "objects" / object_id[:2] / object_id[2:]
    target.parent.mkdir(exist_ok=True)
    target.write_bytes(compressed)
    (root / ".git" / "refs" / "heads" / "main").write_text(object_id + "\n")

    connector = FilesystemConnector(
        ConnectorContext(config={"path": str(root), "use_git": True}, index=index)
    )
    findings = connector.run()
    assert findings and connector.ctx.stats.incomplete
    assert any("metadata output limit" in warning for warning in connector.ctx.stats.warnings)
    assert all("last_author" not in finding.metadata for finding in findings)
    assert len(repr([finding.to_dict() for finding in findings])) < 64 * 1024


@pytest.mark.parametrize(
    "layout",
    [
        "include",
        "include-casing",
        "include-comment",
        "include-quoted-subsection",
        "include-deprecated-subsection",
        "includeif",
        "includeif-casing",
        "includeif-deprecated-subsection",
        "continued-path",
        "continued-header",
        "malformed-header",
        "unterminated-subsection",
        "quoted-section",
        "worktree-include",
        "worktree-includeif",
        "worktree-malformed",
        "uppercase-config",
        "oversized",
        "invalid-utf8",
        "control-character",
        "multiline-value",
        "continued-value",
    ],
)
def test_local_config_indirections_are_rejected_before_any_git_command(tmp_path, index, monkeypatch, layout):
    root = _repository(tmp_path / "scanned")
    outside = tmp_path / "outside.gitconfig"
    outside.write_text("[user]\n name = Outside Configuration\n email = outside@example.test\n")
    declarations = {
        "include": f'[include]\n path = "{outside}"\n',
        "include-casing": f'[InClUdE]\n pAtH = "{outside}"\n',
        "include-comment": f'[include] # ordinary-looking local settings\n path = "{outside}"\n',
        "include-quoted-subsection": f'[include "external"]\n path = "{outside}"\n',
        "include-deprecated-subsection": f'[include.external]\n path = "{outside}"\n',
        "includeif": f'[includeIf "gitdir:{root}/"]\n path = "{outside}"\n',
        "includeif-casing": f'[InClUdEiF "gitdir/i:{root}/"]\n pAtH = "{outside}"\n',
        "includeif-deprecated-subsection": f'[includeIf.external]\n path = "{outside}"\n',
        "continued-path": f'[include]\n path = "{outside.parent}/\\\n outside.gitconfig"\n',
        "continued-header": f'[inc\\\nlude]\n path = "{outside}"\n',
        "malformed-header": f'[include\n path = "{outside}"\n',
        "unterminated-subsection": f'[includeIf "gitdir:{root}/]\n path = "{outside}"\n',
        "quoted-section": f'["include"]\n path = "{outside}"\n',
        "worktree-include": f'[include]\n path = "{outside}"\n',
        "worktree-includeif": f'[includeIf "gitdir:{root}/"]\n path = "{outside}"\n',
        "worktree-malformed": f'[include\n path = "{outside}"\n',
        "uppercase-config": f'[include]\n path = "{outside}"\n',
        "oversized": "# " + "A" * (1024 * 1024) + "\n",
        "control-character": '[core]\n description = "sensitive-config\x00value"\n',
        "multiline-value": '[core]\n description = "sensitive-config\nvalue"\n',
        "continued-value": '[core]\n description = "sensitive-config\\\nvalue"\n',
    }
    config = root / ".git" / "config"
    if layout.startswith("worktree-"):
        config.write_text(config.read_text() + "\n[extensions]\n worktreeConfig = true\n")
        (root / ".git" / "config.worktree").write_text(declarations[layout])
    elif layout == "invalid-utf8":
        config.write_bytes(config.read_bytes() + b'\n[core]\n description = "sensitive-config\xffvalue"\n')
    else:
        config.write_text(config.read_text() + "\n" + declarations[layout])
        if layout == "uppercase-config":
            config.rename(config.with_name("CONFIG"))

    def unexpected_git(*args, **kwargs):
        pytest.fail("Unsafe local Git configuration must be rejected before executing Git")

    # Both subprocess entry points are guarded: validation must not itself ask
    # native Git to parse an include before deciding whether it is acceptable.
    monkeypatch.setattr(subprocess, "run", unexpected_git)
    monkeypatch.setattr(subprocess, "Popen", unexpected_git)
    assert read_git_snapshot(root) is None
    assert read_gitlink_paths(root) is None
    connector = FilesystemConnector(
        ConnectorContext(config={"path": str(root), "use_git": True}, index=index)
    )
    assert connector._git_info(root, ".") == {}
    findings = connector.run()
    assert any("framework.crewai" in finding.frameworks for finding in findings)
    assert connector.ctx.stats.incomplete
    assert all("last_author" not in finding.metadata for finding in findings)
    assert "sensitive-config" not in repr(connector.ctx.stats.warnings)


@pytest.mark.requires_git_2_45
@pytest.mark.parametrize(
    "ordinary_config",
    [
        "",
        '# [include]\n; [includeIf "gitdir:*"]\n',
        '[core]\n description = "Documentation mentions [include] and \\"quotes\\""\n',
        '[remote "include"]\n url = https://example.test/include.git\n',
        "[remote.include]\n url = https://example.test/include.git\n",
        "[extensions]\n worktreeConfig = true\n",
        "utf8-bom",
    ],
)
def test_ordinary_local_configuration_still_allows_history_enrichment(tmp_path, index, ordinary_config):
    root = _repository(tmp_path / "ordinary")
    config = root / ".git" / "config"
    if ordinary_config == "utf8-bom":
        config.write_text("\ufeff" + config.read_text())
    else:
        config.write_text(config.read_text() + "\n" + ordinary_config)
        if "worktreeConfig" in ordinary_config:
            (root / ".git" / "config.worktree").write_text(
                '[core]\n description = "A regular worktree configuration"\n'
            )

    assert read_git_snapshot(root) is not None
    assert read_gitlink_paths(root) == []
    connector = FilesystemConnector(
        ConnectorContext(config={"path": str(root), "use_git": True}, index=index)
    )
    findings = connector.run()
    assert findings and not connector.ctx.stats.incomplete
    assert any(finding.owner == "synthetic-outside@example.test" for finding in findings)


def test_config_inspection_consumes_the_shared_metadata_deadline(tmp_path, monkeypatch):
    root = _repository(tmp_path / "deadline")
    config = root / ".git" / "config"
    # A valid but unusually large local comment stays below the config-size
    # cap. Decoding and inspecting it must still consume the caller's budget.
    config.write_text(config.read_text() + "\n# " + "A" * (800 * 1024) + "\n")

    def unexpected_git(*args, **kwargs):
        pytest.fail("An exhausted config-inspection budget must not start Git")

    monkeypatch.setattr(subprocess, "Popen", unexpected_git)
    assert read_git_snapshot(root, timeout=0.001) is None
    assert read_gitlink_paths(root, timeout=0.001) is None
