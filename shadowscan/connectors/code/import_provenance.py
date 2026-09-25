"""Bounded filesystem checks for ambiguous absolute Python imports.

A familiar import name is not proof of an installed SDK: a repository can
provide that same name. These checks only inspect path metadata; they never
import modules, execute source, read package initializers, or enumerate trees.
As with the filesystem connector, callers must scan an immutable checkout.
Concurrent directory replacement requires filesystem/container isolation.
"""

from __future__ import annotations

import stat
from pathlib import Path

MAX_PATH_COMPONENTS = 128
MAX_MODULE_LENGTH = 512


class ImportProvenanceError(ValueError):
    """Local import provenance could not be safely established."""


def local_module_conflict(
    module: str,
    *,
    scan_root: Path,
    source_path: Path,
    project_root: Path,
) -> bool:
    """Whether an absolute import might refer to repository-local Python code.

    Probe only the scan root, the source's own directory, the nearest project
    root, and that project's conventional ``src`` directory. A sibling project
    is not a candidate import location. Any matching directory is conservative
    evidence of a possible package, including a namespace package. This is not
    a complete recreation of Python's runtime ``sys.path`` or import machinery.

    Symlinks, inaccessible paths, invalid paths and limits raise explicitly;
    callers must not interpret an error as proof of external SDK provenance.
    The number of probes is bounded by path depth, not repository file count.
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
    source = absolute(source_path)
    project = absolute(project_root)
    if not source.is_relative_to(root) or not project.is_relative_to(root):
        raise ImportProvenanceError("import provenance path is outside the scan root")
    if not source.is_relative_to(project):
        raise ImportProvenanceError("source path is outside its project root")

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
            raise ImportProvenanceError("local import provenance must not traverse a symbolic link")
        modes[path] = result
        return result

    root_mode = mode(root)
    if root_mode is None or not stat.S_ISDIR(root_mode):
        raise ImportProvenanceError("local import provenance requires a directory scan root")

    candidates = dict.fromkeys((root, project, project / "src", source.parent))
    for directory in candidates:
        directory_mode = mode(directory)
        if directory_mode is None or not stat.S_ISDIR(directory_mode):
            continue
        module_mode = mode(directory / f"{name}.py")
        if module_mode is not None and stat.S_ISREG(module_mode):
            return True
        package_mode = mode(directory / name)
        if package_mode is not None and stat.S_ISDIR(package_mode):
            return True
    return False
