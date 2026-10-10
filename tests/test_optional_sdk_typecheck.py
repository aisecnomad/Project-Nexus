"""`make typecheck` passes without the optional cloud SDKs installed.

`make install-dev` installs the dev extra only, so mypy must accept every import
of an SDK that pyproject.toml lets it import untyped. Importing ``google.auth``
also binds the ``google`` namespace package, which mypy resolves as a module of
its own; an override that names only ``google.auth`` passes in CI, where the
locks install the SDKs, and fails on a dev-only checkout.

The test type-checks those import statements, copied from the source, with the
repository's mypy configuration and ``--no-site-packages``. That hides every
installed SDK, so the run reproduces a dev-only environment wherever it runs.
mypy runs in a subprocess: its ``main()`` raises the recursion limit and the
garbage-collector thresholds for the rest of the process, which would change
how later tests in the same pytest run behave.
"""

from __future__ import annotations

import ast
import importlib.util
import re
import subprocess
import sys
import textwrap
import tomllib
from collections.abc import Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
# What `make typecheck` and CI pass to mypy.
TYPECHECKED = ("shadowscan", "tools")


def _untyped_module_patterns() -> list[re.Pattern[str]]:
    """The modules pyproject.toml lets mypy import without stubs, as mypy matches them.

    A ``*`` component stands for zero or more components, so ``boto3.*`` also
    covers ``boto3`` (mypy's ``Options.compile_glob``).
    """
    mypy_config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["tool"]["mypy"]
    patterns = []
    for override in mypy_config.get("overrides", []):
        if not override.get("ignore_missing_imports"):
            continue
        modules = override["module"]
        for module in [modules] if isinstance(modules, str) else modules:
            first, *rest = module.split(".")
            expression = ".*" if first == "*" else re.escape(first)
            expression += "".join(r"(\..*)?" if part == "*" else re.escape("." + part) for part in rest)
            patterns.append(re.compile(expression + r"\Z"))
    return patterns


def _imported_modules(node: ast.Import | ast.ImportFrom) -> Iterator[str]:
    if isinstance(node, ast.Import):
        yield from (alias.name for alias in node.names)
    elif node.level == 0 and node.module:
        yield node.module
        # `from google import auth` may import the submodule google.auth.
        yield from (f"{node.module}.{alias.name}" for alias in node.names)


def _import_statements(source: str, filename: str = "<source>") -> Iterator[tuple[list[str], str]]:
    """Yield each import statement's absolute modules and its source text.

    The text is the statement alone, so code sharing its line (``if
    TYPE_CHECKING: import boto3``, ``import boto3; x = 1``) is left behind. A
    ``# type: ignore`` on its last line travels with it.
    """
    # mypy parses with type comments too, so this reads its `# type: ignore`s.
    tree = ast.parse(source, filename=filename, type_comments=True)
    ignores = {ignore.lineno: ignore.tag for ignore in tree.type_ignores}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        statement = ast.get_source_segment(source, node)
        assert statement is not None
        if node.end_lineno in ignores:
            statement += f"  # type: ignore{ignores[node.end_lineno]}"
        yield list(_imported_modules(node)), statement


def test_import_statements_leave_code_sharing_their_line() -> None:
    source = textwrap.dedent("""\
        import oci; x = 1  # type: ignore[name-defined]
        if TYPE_CHECKING: import boto3
        def f() -> None:
            from google.auth import (
                default,  # the credential
            )  # type: ignore[import-untyped]
        """)
    assert list(_import_statements(source)) == [
        (["oci"], "import oci  # type: ignore[name-defined]"),
        (["boto3"], "import boto3"),
        (
            ["google.auth", "google.auth.default"],
            "from google.auth import (\n        default,  # the credential\n    )  # type: ignore[import-untyped]",
        ),
    ]


def _untyped_imports() -> list[str]:
    """Each distinct import statement of a module that may be imported untyped."""
    patterns = _untyped_module_patterns()
    statements: dict[str, None] = {}
    for path in sorted(path for directory in TYPECHECKED for path in (ROOT / directory).rglob("*.py")):
        for modules, statement in _import_statements(path.read_text(encoding="utf-8"), str(path)):
            third_party = [
                module
                for module in modules
                # The type-checked directories are the first-party packages.
                if module.partition(".")[0] not in {*TYPECHECKED, *sys.stdlib_module_names}
            ]
            if any(pattern.match(module) for module in third_party for pattern in patterns):
                statements[statement] = None
    return list(statements)


def test_optional_sdk_imports_typecheck_without_the_sdks_installed(tmp_path: Path) -> None:
    if importlib.util.find_spec("mypy") is None:
        pytest.skip("mypy is not installed")
    imports = _untyped_imports()
    assert imports, "found no import of a module pyproject.toml lets mypy import untyped"
    # One module per statement: two imports binding the same name in different
    # source files must not collide here.
    files = []
    for number, statement in enumerate(imports):
        path = tmp_path / f"optional_import_{number}.py"
        path.write_text(statement + "\n", encoding="utf-8")
        files.append(str(path))
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "mypy",
            "--config-file",
            str(ROOT / "pyproject.toml"),
            "--no-site-packages",
            "--cache-dir",
            str(tmp_path / "mypy-cache"),
            *files,
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    listing = "\n".join(
        f"{Path(file).name}: {statement}" for file, statement in zip(files, imports, strict=True)
    )
    assert result.returncode == 0, (
        f"{result.stdout}{result.stderr}\nchecked without site-packages:\n{listing}"
    )
