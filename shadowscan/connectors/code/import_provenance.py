"""Bounded filesystem checks for ambiguous absolute Python imports.

A familiar import name is not proof of an installed SDK: a repository can
provide that same name. These checks only inspect path metadata; they never
import modules, execute source, read package initializers, or enumerate trees
(beyond a small bounded look for Python source inside a directory that has no
``__init__.py``).
They ``lstat`` paths rather than use open directories, so their answer holds
only for a checkout that does not change during the scan: unlike the
filesystem connector's file reads, which stay below the opened scan root, a
directory replaced between two probes can mislead them. Concurrent directory
replacement requires filesystem/container isolation.
"""

from __future__ import annotations

import os
import stat
from collections import deque
from pathlib import Path

MAX_PATH_COMPONENTS = 128
MAX_MODULE_LENGTH = 512
# A directory without ``__init__.py`` is a local package only if Python source
# sits somewhere inside it: this many directory entries and levels are examined.
MAX_NAMESPACE_ENTRIES = 256
MAX_NAMESPACE_DEPTH = 8


class ImportProvenanceError(ValueError):
    """Local import provenance could not be safely established."""


class _LinkProvenanceError(ImportProvenanceError):
    """A probed path component is a symbolic link."""


def local_module_conflict(
    module: str,
    *,
    scan_root: Path,
    source_path: Path,
    project_root: Path,
    source_dir: Path | None = None,
) -> bool:
    """Whether an absolute import might refer to repository-local Python code.

    Probe only the scan root, the source's own directory, the nearest project
    root, and that project's conventional ``src`` directory. A sibling project
    is not a candidate import location. A matching module file, a directory with
    an ``__init__.py`` and a directory holding Python source (a namespace package
    with modules) are evidence of local code. An empty directory, or one of data
    files, is not: Python ignores such a directory when the real package is
    installed, so it must not hide every import of that SDK. This is not a
    complete recreation of Python's runtime ``sys.path`` or import machinery.

    ``source_dir`` replaces the source's own directory for a file analyzed at
    a link's path: the real directory that holds what a copy's directory would.
    A module or package that is itself a link inside the scan root stands for
    its target, as a copy would.

    Other symlinks, inaccessible paths, invalid paths and limits raise
    explicitly; callers must not interpret an error as proof of external SDK
    provenance. The number of probes is bounded by path depth, not repository
    file count.
    """
    if (
        not module
        or len(module) > MAX_MODULE_LENGTH
        or not all(part.isidentifier() for part in module.split("."))
    ):
        raise ImportProvenanceError("invalid or oversized absolute Python module name")
    name = module.split(".", 1)[0]

    def absolute(path: Path) -> Path:
        path = Path(path).absolute()
        if ".." in path.parts or len(path.parts) > MAX_PATH_COMPONENTS:
            raise ImportProvenanceError("unsafe or excessive import provenance path depth")
        return path

    root = absolute(scan_root)
    project = absolute(project_root)
    if source_dir is None:
        source = absolute(source_path)
        if not source.is_relative_to(root) or not project.is_relative_to(root):
            raise ImportProvenanceError("import provenance path is outside the scan root")
        if not source.is_relative_to(project):
            raise ImportProvenanceError("source path is outside its project root")
        directory_of_source = source.parent
    else:
        directory_of_source = absolute(source_dir)
        if not directory_of_source.is_relative_to(root) or not project.is_relative_to(root):
            raise ImportProvenanceError("import provenance path is outside the scan root")
    real_root = Path(os.path.realpath(root))

    # Validate each ancestor before probing a descendant. lstat does not follow
    # the final component, so a link is rejected before it can be traversed.
    # A per-call metadata cache avoids repeated ancestor probes without stale
    # state surviving between scans or retaining all repository path names.
    modes: dict[Path, int | None] = {}

    def mode(path: Path) -> int | None:
        if path in modes:
            return modes[path]
        if path != path.parent:
            parent_mode = mode(path.parent)
            if parent_mode is None or not stat.S_ISDIR(parent_mode):
                modes[path] = None
                return None
        try:
            result = path.lstat().st_mode
        except FileNotFoundError:
            result = None
        except OSError as exc:
            raise ImportProvenanceError("could not inspect local import provenance") from exc
        if result is not None and stat.S_ISLNK(result):
            raise _LinkProvenanceError("local import provenance must not traverse a symbolic link")
        modes[path] = result
        return result

    root_mode = mode(root)
    if root_mode is None or not stat.S_ISDIR(root_mode):
        raise ImportProvenanceError("local import provenance requires a directory scan root")

    def candidate(path: Path) -> tuple[Path, int | None]:
        """A module or package path and its mode; a link inside the root stands for its target."""
        try:
            return path, mode(path)
        except _LinkProvenanceError:
            pass
        try:
            target = path.resolve(strict=True)
        except FileNotFoundError:
            return path, None  # a dangling link: no module there, as for a copy
        except (OSError, RuntimeError) as exc:
            raise ImportProvenanceError("could not inspect local import provenance") from exc
        if target != real_root and real_root not in target.parents:
            raise ImportProvenanceError("local import provenance symbolic link leaves the scan root")
        return target, mode(target)

    candidates = dict.fromkeys((root, project, project / "src", directory_of_source))
    for directory in candidates:
        directory_mode = mode(directory)
        if directory_mode is None or not stat.S_ISDIR(directory_mode):
            continue
        _, module_mode = candidate(directory / f"{name}.py")
        if module_mode is not None and stat.S_ISREG(module_mode):
            return True
        package, package_mode = candidate(directory / name)
        if package_mode is None or not stat.S_ISDIR(package_mode):
            continue
        init_mode = mode(package / "__init__.py")
        if (init_mode is not None and stat.S_ISREG(init_mode)) or _holds_python_source(package):
            return True
    return False


def _holds_python_source(package: Path) -> bool:
    """Whether a directory without ``__init__.py`` holds a ``.py`` file, looking only a bounded way in.

    Breadth first, so shallow source is found first. Links are not followed: one
    inside the directory, like any other limit exceeded, raises rather than guess.
    """
    pending = deque([(package, 0)])
    examined = 0
    while pending:
        directory, depth = pending.popleft()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    examined += 1
                    if examined > MAX_NAMESPACE_ENTRIES:
                        raise ImportProvenanceError(
                            "local import provenance directory is too large to inspect"
                        )
                    if entry.is_symlink():
                        raise ImportProvenanceError(
                            "local import provenance must not traverse a symbolic link"
                        )
                    if entry.is_dir(follow_symlinks=False):
                        if depth >= MAX_NAMESPACE_DEPTH:
                            raise ImportProvenanceError(
                                "local import provenance directory is nested too deeply"
                            )
                        pending.append((Path(entry.path), depth + 1))
                    elif entry.name.endswith(".py") and entry.is_file(follow_symlinks=False):
                        return True
        except OSError as exc:
            raise ImportProvenanceError("could not inspect local import provenance") from exc
    return False
