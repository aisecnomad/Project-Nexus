from __future__ import annotations

import time

import pytest

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.code import filesystem, python_reexports
from shadowscan.engine import Engine
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


_OPENAI_CONSUMER = (
    "from helpers import helper\n"
    "from openai import OpenAI\n"
    "client = OpenAI()\n"
    'client.chat.completions.create(model="gpt-4o", messages=[])\n'
)


def _uses_openai(findings):
    return any("provider.openai" in finding.model_providers for finding in findings)


def test_large_ordinary_local_module_leaves_its_consumers_complete(tmp_path, run_connector):
    # A module over the shim byte budget that is not import-only cannot be a
    # shim, so importing it neither limits resolution nor changes evidence.
    helpers = "def helper():\n    return 1\n" + "".join(f"VALUE_{n} = {n}\n" for n in range(8000))
    assert len(helpers.encode("utf-8")) > python_reexports.MAX_SHIM_BYTES
    findings, ctx = _scan(tmp_path, run_connector, {"helpers.py": helpers, "app.py": _OPENAI_CONSUMER})
    assert _uses_openai(findings)
    assert not ctx.stats.incomplete, ctx.stats.errors


@pytest.mark.parametrize(
    ("text", "limited"),
    [
        ("from agents import Agent\n", True),
        (
            '"""Docstring."""\n# comment\n\nfrom agents import (\n    Agent,\n    Runner as R,\n)\n'
            "from openai import \\\n    OpenAI\n",
            True,
        ),
        ("from agents import Agent;\n", True),
        ("import agents\n", False),
        ("from agents import Agent; Agent = object\n", False),
        ("from agents import Agent\nclass Agent:\n    pass\n", False),
        ('"""One."""\n"""Two."""\nfrom agents import Agent\n', False),
        ("if True:\n    from agents import Agent\n", False),
        ("from agents import Agent\n'unterminated\n", False),
        ('"""Only a docstring."""\n# and a comment\n', False),
    ],
)
def test_oversize_module_is_limited_only_if_it_may_be_import_only(monkeypatch, text, limited):
    monkeypatch.setattr(python_reexports, "MAX_SHIM_BYTES", 0)
    graph = python_reexports.PythonReexports()
    graph.add(".", "sdk.py", text)
    assert ((".", "sdk") in graph.limited) is limited
    assert not graph.modules


def test_export_budget_applies_only_to_import_only_modules(tmp_path, run_connector, monkeypatch):
    # Names imported at the top of an ordinary module are not exports of a shim.
    monkeypatch.setattr(python_reexports, "MAX_EXPORTS", 0)
    findings, ctx = _scan(
        tmp_path,
        run_connector,
        {
            "helpers.py": "from os import path\n\ndef helper():\n    return path\n",
            "app.py": _OPENAI_CONSUMER,
        },
    )
    assert _uses_openai(findings)
    assert not ctx.stats.incomplete, ctx.stats.errors


_LARGE_BODY = "".join(f"value_{n} = helper({n})\n" for n in range(400))


def test_unresolved_local_import_keeps_the_single_file_bindability_proof(tmp_path, run_connector):
    # No import resolves through a shim, so the proof that the binder can
    # yield nothing still holds: a root consumer over the AST budget remains
    # complete, as it is without the local import or in a nested directory.
    files = {
        "helpers.py": "def helper(value):\n    return value\n",
        "app.py": "from helpers import helper\n" + _LARGE_BODY,
    }
    for name, text in files.items():
        (tmp_path / name).write_text(text)
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), git_metadata=False, max_ast_nodes=1000)
    assert not ctx.stats.incomplete, ctx.stats.errors


def test_resolved_import_keeps_the_binder_and_its_ast_budget(tmp_path, run_connector):
    files = {
        "sdk.py": "from agents import Agent as RuntimeAgent\n",
        "app.py": 'from sdk import RuntimeAgent\nhelper = RuntimeAgent\na = RuntimeAgent(name="helper")\n'
        + _LARGE_BODY,
    }
    for name, text in files.items():
        (tmp_path / name).write_text(text)
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), git_metadata=False, max_ast_nodes=1000)
    assert ctx.stats.incomplete
    assert any("app.py: import-bound analysis skipped" in error for error in ctx.stats.errors)


# The walk reads smaller source files first. Filler projects larger than the
# consumers keep the consumers ahead of them, as these deadline scenarios need.
_FILLER_AGENT = "from langchain import agents\n" + "# filler\n" * 40


def _fake_clock(monkeypatch) -> list[float]:
    """Freeze ``time.monotonic`` and advance it by one second for every file the scanner reads."""
    clock = [1000.0]
    monkeypatch.setattr(filesystem.time, "monotonic", lambda: clock[0])
    read_text = filesystem.read_text

    def slow_read(path, max_bytes, errors=None, **options):
        clock[0] += 1.0
        return read_text(path, max_bytes, errors, **options)

    monkeypatch.setattr(filesystem, "read_text", slow_read)
    return clock


def test_queued_consumers_keep_the_walk_deadline_margin(tmp_path, index, monkeypatch):
    # The walk stops early enough to emit what it found. The queued consumer
    # must not then start without its budget and that margin: overrunning the
    # deadline makes the engine discard every finding of the connector.
    (tmp_path / "a_app.py").write_text(_OPENAI_CONSUMER.replace("helpers", "b_helpers"))
    (tmp_path / "b_helpers.py").write_text("def helper():\n    return 1\n")
    for number in range(3):
        (tmp_path / f"z_agent_{number}.py").write_text(_FILLER_AGENT)
    clock = _fake_clock(monkeypatch)
    bind = filesystem.bound_source_matches

    def slow_bind(*args, **options):
        # Resolved analysis uses its whole matching budget.
        if options.get("resolve_import") is not None:
            clock[0] += 2.0
        return bind(*args, **options)

    monkeypatch.setattr(filesystem, "bound_source_matches", slow_bind)
    config = ScanConfig(
        connectors=[ConnectorSpec("code.filesystem", {"path": str(tmp_path), "use_git": False})],
        connector_timeout_seconds=5.5,
        parallel=1,
    )
    result = Engine(config, index).run()
    stats = result.stats[0]
    assert not result.complete and not stats.skipped
    assert any("framework.langchain" in finding.frameworks for finding in result.findings)
    assert any("a_app.py" in error and "re-export" in error for error in stats.errors)


def test_a_queued_binders_wall_time_stops_short_of_the_deadline_margin(tmp_path, index, monkeypatch):
    # The matching budget is the thread's CPU time, so a binder descheduled
    # under contention is ended only by its wall cap. As in the walk, that cap
    # must not run into the margin the connector keeps to emit its findings.
    (tmp_path / "a_app.py").write_text(_OPENAI_CONSUMER.replace("helpers", "b_helpers"))
    (tmp_path / "b_helpers.py").write_text("def helper():\n    return 1\n")
    clock = _fake_clock(monkeypatch)
    deadline = clock[0] + 30.0
    resolve = filesystem.FilesystemConnector._resolve_reexport_sources
    caps = []
    expected = []

    def late_resolve(self, scan):
        # The walk leaves the consumer just its budget and the margin.
        clock[0] = deadline - (self.scan_timeout + scan.margin + 0.05)
        expected.append(deadline - clock[0] - scan.margin)
        scan_budget = self.index.scan_budget

        def recording(*args, **options):
            caps.append(options)
            return scan_budget(*args, **options)

        monkeypatch.setattr(self.index, "scan_budget", recording)
        return resolve(self, scan)

    monkeypatch.setattr(filesystem.FilesystemConnector, "_resolve_reexport_sources", late_resolve)
    ctx = ConnectorContext(config={"path": str(tmp_path), "use_git": False}, index=index, deadline=deadline)
    findings = filesystem.FilesystemConnector(ctx).run()
    assert _uses_openai(findings)
    assert len(caps) == 1 and caps[0]["chars"] == len((tmp_path / "a_app.py").read_bytes())
    assert caps[0]["wall_seconds"] <= expected[0]


def test_queued_consumers_are_redacted_in_the_walk_not_after_it(tmp_path, index, monkeypatch):
    # The walk accounts for every file's redaction against the deadline. A
    # queued consumer is redacted there too, so neither the re-export pass nor
    # emit, after the last deadline check, redacts a whole file, whether the
    # pass reaches the consumer or not.
    for name in ("a_app.py", "b_app.py"):
        (tmp_path / name).write_text(_OPENAI_CONSUMER.replace("helpers", "c_helpers"))
    (tmp_path / "c_helpers.py").write_text("def helper():\n    return 1\n")
    redact = filesystem._redacted_source
    queued = []
    late = []

    def counting(text, structure):
        if queued:
            late.append(text[:40])
        return redact(text, structure)

    resolve = filesystem.FilesystemConnector._resolve_reexport_sources

    def marking(self, scan):
        queued.extend(source.file.rel for source in scan.reexport_files)
        assert all(source.file.excerpts.safe_lines is not None for source in scan.reexport_files)
        return resolve(self, scan)

    monkeypatch.setattr(filesystem, "_redacted_source", counting)
    monkeypatch.setattr(filesystem.FilesystemConnector, "_resolve_reexport_sources", marking)
    ctx = ConnectorContext(config={"path": str(tmp_path), "use_git": False}, index=index)
    findings = filesystem.FilesystemConnector(ctx).run()
    assert sorted(queued) == ["a_app.py", "b_app.py"]
    assert late == []
    # Their evidence, model identifiers included, still carries its excerpts.
    snippets = {(e.location, e.signal): e.snippet for f in findings for e in f.evidence}
    call = 'client.chat.completions.create(model="gpt-4o", messages=[])'
    assert snippets[("a_app.py:4", "code:provider.openai")] == call
    assert snippets[("b_app.py:4", "model:provider.openai")] == call


def test_queued_consumer_whose_budget_does_not_fit_is_skipped_alone(tmp_path, index, monkeypatch):
    # The walk reads the 900 KiB consumer last (smaller files first) and
    # finishes with 8 s left: that consumer's 8 s budget plus the margin no
    # longer fits, but an ordinary queued consumer's still does. The skipped
    # consumer keeps the imports the walk matched.
    large = "from b_helpers import helper\nimport anthropic\n" + "x = 1\n" * (900 * 1024 // 6)
    (tmp_path / "a_large.py").write_text(large)
    (tmp_path / "a_small.py").write_text(_OPENAI_CONSUMER.replace("helpers", "b_helpers"))
    (tmp_path / "b_helpers.py").write_text("def helper():\n    return 1\n")
    for number in range(4):
        (tmp_path / f"z_agent_{number}.py").write_text(_FILLER_AGENT)
    clock = _fake_clock(monkeypatch)
    ctx = ConnectorContext(
        config={"path": str(tmp_path), "use_git": False}, index=index, deadline=clock[0] + 15.0
    )
    findings = filesystem.FilesystemConnector(ctx).run()
    assert ctx.stats.objects_examined == 7 and ctx.stats.incomplete
    assert [error for error in ctx.stats.errors if "deadline" in error] == [
        "code.filesystem: a_large.py: Python re-export analysis skipped; the remaining connector deadline "
        "cannot cover its 8s matching budget; lexical evidence retained"
    ]
    assert _uses_openai(findings)
    assert any("provider.anthropic" in finding.model_providers for finding in findings)


def test_queued_consumer_left_unbound_keeps_its_lexical_evidence(tmp_path, index, monkeypatch):
    # The walk reads and matches the consumer under its own budget. When the
    # binding pass after the walk no longer fits, the imports and code
    # patterns it matched remain evidence, as they would without the queue.
    (tmp_path / "a_app.py").write_text(_OPENAI_CONSUMER.replace("helpers", "b_helpers"))
    (tmp_path / "b_helpers.py").write_text("def helper():\n    return 1\n")
    for number in range(3):
        (tmp_path / f"z_agent_{number}.py").write_text(_FILLER_AGENT)
    clock = _fake_clock(monkeypatch)
    ctx = ConnectorContext(
        config={"path": str(tmp_path), "use_git": False}, index=index, deadline=clock[0] + 5.5
    )
    findings = filesystem.FilesystemConnector(ctx).run()
    assert ctx.stats.incomplete
    assert any("a_app.py" in error and "re-export" in error for error in ctx.stats.errors)
    assert _uses_openai(findings)
    assert any("framework.langchain" in finding.frameworks for finding in findings)


def test_retained_lexical_evidence_stops_at_half_the_margin(tmp_path, index, monkeypatch):
    # Recording the stopped consumers must leave the emission its time, as
    # the walk's own final count does.
    for name in ("a_app.py", "b_app.py"):
        (tmp_path / name).write_text(_OPENAI_CONSUMER.replace("helpers", "c_helpers"))
    (tmp_path / "c_helpers.py").write_text("def helper():\n    return 1\n")
    for number in range(2):
        (tmp_path / f"z_agent_{number}.py").write_text(_FILLER_AGENT)
    clock = _fake_clock(monkeypatch)
    record = filesystem.FilesystemConnector._record_source
    recorded = []

    def slow_record(self, source, bound, unbound):
        if source.file.rel in {"a_app.py", "b_app.py"}:
            recorded.append(source.file.rel)
            clock[0] += 1.4
        return record(self, source, bound, unbound)

    monkeypatch.setattr(filesystem.FilesystemConnector, "_record_source", slow_record)
    ctx = ConnectorContext(
        config={"path": str(tmp_path), "use_git": False}, index=index, deadline=clock[0] + 5.5
    )
    filesystem.FilesystemConnector(ctx).run()
    assert recorded == ["a_app.py"]
    assert ctx.stats.incomplete
    assert any("a_app.py and 1 other queued files" in error for error in ctx.stats.errors)
