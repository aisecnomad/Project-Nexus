from __future__ import annotations

import time

import pytest

from shadowscan.connectors.code import filesystem, python_reexports
from shadowscan.models import Kind


def _scan(tmp_path, run_connector, files):
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return run_connector("code.filesystem", path=str(tmp_path), git_metadata=False)


def _agents(findings):
    return [finding for finding in findings if finding.kind == Kind.AGENT]


def test_blank_file_prefilter_has_bounded_cost():
    # An anchored whitespace expression must not rescan the remaining suffix
    # once for every newline. The former cross-line pattern took seconds here.
    start = time.monotonic()
    assert not python_reexports.has_local_import("\n" * 128_000, lambda _: False)
    assert time.monotonic() - start < 2.0


def test_prefilter_accepts_parenthesized_crlf_imports():
    assert python_reexports.has_local_import("from sdk import(\r\n Agent,\r\n)\r\n", lambda _: True)


def test_import_only_reexport_fixture(run_connector, fixtures):
    findings, ctx = run_connector(
        "code.filesystem", path=str(fixtures / "python_reexports"), git_metadata=False
    )
    agents = _agents(findings)
    assert len(agents) == 1
    assert agents[0].frameworks == ["framework.openai-agents-sdk"]
    assert not ctx.stats.incomplete


@pytest.mark.parametrize("manifest", [False, True])
def test_chained_reexport_is_scoped_to_manifest_project(tmp_path, run_connector, manifest):
    prefix = "service/" if manifest else ""
    files = {
        prefix + "app.py": 'from middle import PublicAgent\na = PublicAgent(name="helper")\n',
        prefix + "middle.py": "from sdk import RuntimeAgent as PublicAgent\n",
        prefix + "sdk.py": "from agents import Agent as RuntimeAgent\n",
    }
    if manifest:
        files[prefix + "pyproject.toml"] = '[project]\nname="service"\nversion="0.0.0"\n'
    findings, ctx = _scan(tmp_path, run_connector, files)
    assert len(_agents(findings)) == 1
    assert not ctx.stats.incomplete


@pytest.mark.parametrize(
    "shim",
    [
        "from agents import Agent as RuntimeAgent\nRuntimeAgent = object\n",
        "from agents import Agent as RuntimeAgent\nfrom builtins import object as RuntimeAgent\n",
        "if enabled:\n    from agents import Agent as RuntimeAgent\n",
        "from agents import *\n",
        "from .agents import Agent as RuntimeAgent\n",
        'from agents import Agent as RuntimeAgent\n__all__ = ["RuntimeAgent"]\n',
        "from agents import Agent as RuntimeAgent\nexec(payload)\n",
        "from agents import Agent as RuntimeAgent\ndef mutate():\n    global RuntimeAgent\n    RuntimeAgent = object\n",
        "from middle import RuntimeAgent\n",
    ],
)
def test_uncertain_or_cyclic_exports_do_not_establish_agent(tmp_path, run_connector, shim):
    findings, ctx = _scan(
        tmp_path,
        run_connector,
        {
            "sdk.py": shim,
            "middle.py": "from sdk import RuntimeAgent\n",
            "app.py": 'from sdk import RuntimeAgent\na = RuntimeAgent(name="helper")\n',
        },
    )
    assert not _agents(findings)
    assert not ctx.stats.incomplete


@pytest.mark.parametrize(
    "consumer",
    [
        'from sdk import RuntimeAgent\nRuntimeAgent = object\na = RuntimeAgent(name="helper")\n',
        'from sdk import RuntimeAgent\ndef f(RuntimeAgent):\n    return RuntimeAgent(name="helper")\n',
        'from sdk import RuntimeAgent\nif False:\n    a = RuntimeAgent(name="helper")\n',
    ],
)
def test_consumer_shadowing_and_dead_code_remain_unproven(tmp_path, run_connector, consumer):
    findings, ctx = _scan(
        tmp_path,
        run_connector,
        {"sdk.py": "from agents import Agent as RuntimeAgent\n", "app.py": consumer},
    )
    assert not _agents(findings)
    assert not ctx.stats.incomplete


@pytest.mark.parametrize("collision", ["agents.py", "agents/__init__.py", "sdk/__init__.py"])
def test_local_library_or_shim_package_collision_cannot_supply_library_identity(
    tmp_path, run_connector, collision
):
    findings, ctx = _scan(
        tmp_path,
        run_connector,
        {
            "sdk.py": "from agents import Agent as RuntimeAgent\n",
            "app.py": 'from sdk import RuntimeAgent\na = RuntimeAgent(name="helper")\n',
            collision: "class Agent:\n    pass\n",
        },
    )
    assert not _agents(findings)
    assert not ctx.stats.incomplete


def test_sibling_projects_do_not_share_exports(tmp_path, run_connector):
    findings, ctx = _scan(
        tmp_path,
        run_connector,
        {
            "one/pyproject.toml": '[project]\nname="one"\nversion="0.0.0"\n',
            "two/pyproject.toml": '[project]\nname="two"\nversion="0.0.0"\n',
            "one/sdk.py": "from agents import Agent as RuntimeAgent\n",
            "two/sdk.py": "class RuntimeAgent:\n    pass\n",
            "two/app.py": 'from sdk import RuntimeAgent\na = RuntimeAgent(name="helper")\n',
        },
    )
    assert not _agents(findings)
    assert not ctx.stats.incomplete


@pytest.mark.parametrize("budget", ["MAX_PENDING_BYTES", "MAX_PENDING_FILES"])
def test_pending_source_budget_is_incomplete(tmp_path, run_connector, monkeypatch, budget):
    monkeypatch.setattr(filesystem, budget, 0)
    findings, ctx = _scan(
        tmp_path,
        run_connector,
        {
            "sdk.py": "from agents import Agent as RuntimeAgent\n",
            "app.py": 'from sdk import RuntimeAgent\na = RuntimeAgent(name="helper")\n',
        },
    )
    assert not _agents(findings)
    assert ctx.stats.incomplete
    assert any("re-export source budget" in error for error in ctx.stats.errors)


@pytest.mark.parametrize("budget", ["MAX_CHAIN", "MAX_SHIM_BYTES", "MAX_EXPORTS", "MAX_SHIMS"])
def test_resolution_budget_is_incomplete(tmp_path, run_connector, monkeypatch, budget):
    monkeypatch.setattr(python_reexports, budget, 0)
    findings, ctx = _scan(
        tmp_path,
        run_connector,
        {
            "sdk.py": "from agents import Agent as RuntimeAgent\n",
            "app.py": 'from sdk import RuntimeAgent\na = RuntimeAgent(name="helper")\n',
        },
    )
    assert not _agents(findings)
    assert ctx.stats.incomplete
    assert any("re-export" in error and "budget" in error for error in ctx.stats.errors)


def test_symlink_export_is_never_followed(tmp_path, run_connector):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "external.py"
    outside.write_text("from agents import Agent as RuntimeAgent\n")
    (root / "sdk.py").symlink_to(outside)
    findings, ctx = _scan(
        root,
        run_connector,
        {"app.py": 'from sdk import RuntimeAgent\na = RuntimeAgent(name="helper")\n'},
    )
    assert not _agents(findings)
    assert ctx.stats.incomplete
