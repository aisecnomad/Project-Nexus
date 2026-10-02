"""Local import names cannot establish third-party SDK provenance."""

import os
from pathlib import Path

import pytest

from shadowscan.connectors.code.import_provenance import (
    MAX_MODULE_LENGTH,
    MAX_NAMESPACE_DEPTH,
    MAX_NAMESPACE_ENTRIES,
    MAX_PATH_COMPONENTS,
    ImportProvenanceError,
    local_module_conflict,
)


def conflict(root, source=None, project=None, module="agents"):
    return local_module_conflict(
        module,
        scan_root=root,
        source_path=source or root / "app.py",
        project_root=project or root,
    )


@pytest.mark.parametrize("location", ["agents.py", "agents/__init__.py", "src/agents/__init__.py"])
def test_local_module_or_package_conflicts_without_executing_source(tmp_path, location):
    path = tmp_path / location
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('raise RuntimeError("must never run")\n')
    assert conflict(tmp_path)


@pytest.mark.parametrize(
    "location", ["agents/tools/helpers.py", "src/agents/helpers.py", "agents/a/b/c/d/mod.py"]
)
def test_namespace_package_with_python_source_conflicts(tmp_path, location):
    # No __init__.py: still local code when modules sit inside, however deep (within the bound).
    path = tmp_path / location
    path.parent.mkdir(parents=True)
    path.write_text("VALUE = 1\n")
    assert conflict(tmp_path)


@pytest.mark.parametrize("module", ["openai", "agents", "langchain", "crewai.tools"])
def test_empty_directory_named_like_an_sdk_is_not_a_local_package(tmp_path, module):
    # Python ignores a namespace directory when the real package is installed,
    # so empty directories must not hide every import of that SDK.
    for name in ("openai", "agents", "langchain", "crewai"):
        (tmp_path / name).mkdir()
        (tmp_path / "src" / name).mkdir(parents=True)
    assert not conflict(tmp_path, module=module)


def test_directory_of_data_files_is_not_a_local_package(tmp_path):
    package = tmp_path / "agents"
    (package / "prompts" / "v1").mkdir(parents=True)
    for name in (
        "config.json",
        "README.md",
        "model.pyi",
        "notes.py.txt",
        "agents.pyc",
        "prompts/v1/system.txt",
    ):
        (package / name).write_text("x\n")
    (package / "dir.py").mkdir()  # a directory named like a module is not source
    assert not conflict(tmp_path)


def test_package_marker_decides_before_any_look_inside(tmp_path):
    package = tmp_path / "agents"
    package.mkdir()
    (package / "__init__.py").touch()
    assert conflict(tmp_path)


def test_empty_package_directory_of_an_earlier_candidate_does_not_hide_a_later_module(tmp_path):
    (tmp_path / "agents").mkdir()  # the scan root's empty directory
    project = tmp_path / "services" / "worker"
    project.mkdir(parents=True)
    (project / "agents.py").touch()
    assert conflict(tmp_path, source=project / "app.py", project=project)


def test_provider_module_collision(tmp_path):
    (tmp_path / "openai.py").write_text("class OpenAI: pass\n")
    assert conflict(tmp_path, module="openai.resources.chat")
    assert not conflict(tmp_path, module="crewai")


@pytest.mark.parametrize("location", ["agents.py", "src/agents/__init__.py", "nested/agents.py"])
def test_nearest_nested_project_and_source_directory(tmp_path, location):
    project = tmp_path / "services" / "worker"
    source = project / "nested" / "app.py"
    source.parent.mkdir(parents=True)
    local = project / location
    local.parent.mkdir(parents=True, exist_ok=True)
    local.touch()
    assert conflict(tmp_path, source=source, project=project)


def test_unrelated_monorepo_project_does_not_suppress_sdk(tmp_path):
    first = tmp_path / "services" / "one"
    second = tmp_path / "services" / "two"
    (first / "src" / "agents").mkdir(parents=True)
    (first / "src" / "agents" / "__init__.py").touch()
    second.mkdir(parents=True)
    assert not conflict(tmp_path, source=second / "app.py", project=second)
    assert conflict(tmp_path, source=first / "app.py", project=first)


def test_scan_root_module_can_shadow_nested_project(tmp_path):
    project = tmp_path / "services" / "worker"
    project.mkdir(parents=True)
    (tmp_path / "agents.py").touch()
    assert conflict(tmp_path, source=project / "app.py", project=project)


def test_unrelated_filename_and_stub_are_not_runtime_module(tmp_path):
    (tmp_path / "agents.pyi").touch()
    (tmp_path / "agents.py.txt").touch()
    (tmp_path / "agents_other.py").touch()
    assert not conflict(tmp_path)


@pytest.mark.parametrize("location", ["agents.py", "agents", "src"])
def test_symlinks_are_reported_without_following_them(tmp_path, location, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "agents.py").touch()
    (root / location).symlink_to(outside, target_is_directory=True)
    original = Path.lstat

    def checked_lstat(path, *args, **kwargs):
        assert not path.is_relative_to(outside)
        assert path == root / location or not path.is_relative_to(root / location)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", checked_lstat)
    with pytest.raises(ImportProvenanceError, match="symbolic link"):
        conflict(root)


def test_symlinked_scan_ancestor_is_rejected(tmp_path):
    real = tmp_path / "real"
    (real / "repo").mkdir(parents=True)
    (tmp_path / "alias").symlink_to(real, target_is_directory=True)
    with pytest.raises(ImportProvenanceError, match="symbolic link"):
        conflict(tmp_path / "alias" / "repo")


def test_permission_error_is_not_external_provenance(tmp_path, monkeypatch):
    original = Path.lstat

    def denied(path, *args, **kwargs):
        if path == tmp_path / "agents.py":
            raise PermissionError("denied")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", denied)
    with pytest.raises(ImportProvenanceError, match="could not inspect"):
        conflict(tmp_path)


@pytest.mark.parametrize("module", ["", ".agents", "agents..sdk", "../agents", "a" * (MAX_MODULE_LENGTH + 1)])
def test_invalid_module_names_fail_explicitly(tmp_path, module):
    with pytest.raises(ImportProvenanceError, match="module name"):
        conflict(tmp_path, module=module)


def test_paths_outside_scope_and_parent_traversal_are_rejected(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    with pytest.raises(ImportProvenanceError, match="outside the scan root"):
        conflict(root, source=tmp_path / "app.py")
    with pytest.raises(ImportProvenanceError, match="outside its project root"):
        conflict(root, project=root / "project")
    with pytest.raises(ImportProvenanceError, match="path depth"):
        conflict(root, source=root / "nested" / ".." / "app.py")


def test_path_depth_budget_is_explicit(tmp_path):
    source = tmp_path.joinpath(*(["nested"] * MAX_PATH_COMPONENTS), "app.py")
    with pytest.raises(ImportProvenanceError, match="path depth"):
        conflict(tmp_path, source=source)


def test_namespace_directory_probe_is_bounded_and_explicit(tmp_path):
    crowded = tmp_path / "crowded" / "agents"
    crowded.mkdir(parents=True)
    for number in range(MAX_NAMESPACE_ENTRIES + 1):
        (crowded / f"data{number}.json").write_text("{}\n")
    with pytest.raises(ImportProvenanceError, match="too large"):
        conflict(tmp_path / "crowded")
    nested = tmp_path / "nested" / "agents"
    nested.joinpath(*(["level"] * (MAX_NAMESPACE_DEPTH + 1))).mkdir(parents=True)
    with pytest.raises(ImportProvenanceError, match="nested too deeply"):
        conflict(tmp_path / "nested")


def test_a_link_inside_a_namespace_directory_is_reported_not_followed(tmp_path):
    root = tmp_path / "repo"
    package = root / "agents"
    package.mkdir(parents=True)
    outside = tmp_path / "outside.py"
    outside.write_text("VALUE = 1\n")
    (package / "linked.py").symlink_to(outside)
    with pytest.raises(ImportProvenanceError, match="symbolic link"):
        conflict(root)


@pytest.mark.skipif(os.geteuid() == 0, reason="root can list any directory")
def test_unlistable_namespace_directory_is_not_external_provenance(tmp_path):
    package = tmp_path / "agents"
    package.mkdir()
    package.chmod(0)
    try:
        with pytest.raises(ImportProvenanceError, match="could not inspect"):
            conflict(tmp_path)
    finally:
        package.chmod(0o755)


def test_probe_count_is_independent_of_repository_file_count(tmp_path, monkeypatch):
    for number in range(100):
        (tmp_path / f"unrelated{number}.py").touch()
    count = 0
    original = Path.lstat

    def counted(path, *args, **kwargs):
        nonlocal count
        count += 1
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", counted)
    assert not conflict(tmp_path)
    assert count <= len(tmp_path.parts) + 3
