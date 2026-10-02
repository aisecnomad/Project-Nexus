"""A connector raising SystemExit or another BaseException is a connector failure, not a process exit."""

from __future__ import annotations

import json
import sys
from importlib.metadata import EntryPoint

import pytest
from click.testing import CliRunner

import shadowscan.connectors as registry
import shadowscan.engine as engine_module
from shadowscan.cli import main
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine
from shadowscan.models import Finding, Kind, ScanStats, Surface, now_iso
from shadowscan.signatures import SignatureIndex

SECRET = "sk-proj-" + "b" * 40


class _Hard(BaseException):
    """Neither Exception nor KeyboardInterrupt: what a careless SDK may raise."""


def _connector(raiser):
    class Connector:
        def __init__(self, ctx):
            self.ctx = ctx

        def run(self):
            label = self.ctx.config["label"]
            if label == "bad":
                raiser()
            self.ctx.stats = ScanStats(
                connector="code.filesystem", started_at=now_iso(), finished_at=now_iso()
            )
            return [Finding(Surface.CODE, "code.filesystem", Kind.AGENT, label, label, "repository")]

    return Connector


def _config(parallel: int = 1) -> ScanConfig:
    return ScanConfig(
        connectors=[
            ConnectorSpec("code.filesystem", label="good"),
            ConnectorSpec("code.filesystem", label="bad"),
        ],
        parallel=parallel,
    )


def _exit_zero():
    raise SystemExit(0)


def _exit_text():
    raise SystemExit(f"fatal: Authorization: Bearer {SECRET}")


def _exit_none():
    raise SystemExit


def _hard():
    raise _Hard(f"token={SECRET}")


@pytest.mark.parametrize("parallel", [1, 2])
@pytest.mark.parametrize("raiser", [_exit_zero, _exit_text, _exit_none, _hard])
def test_connector_baseexception_marks_scan_incomplete_and_keeps_siblings(monkeypatch, raiser, parallel):
    monkeypatch.setattr(engine_module, "get_connector_class", lambda name: _connector(raiser))

    result = Engine(_config(parallel), SignatureIndex([])).run()

    assert not result.complete
    assert [finding.title for finding in result.findings] == ["good"]
    failed = [st for st in result.stats if st.errors]
    assert len(failed) == 1 and failed[0].incomplete
    assert SECRET not in json.dumps([st.errors for st in result.stats])


@pytest.mark.parametrize("raiser", [_exit_zero, _hard])
def test_cli_reports_exit_3_with_a_report_when_a_connector_exits(monkeypatch, tmp_path, raiser):
    monkeypatch.setattr(engine_module, "get_connector_class", lambda name: _connector(raiser))
    config = tmp_path / "scan.yaml"
    config.write_text(
        "connectors:\n"
        "  - name: code.filesystem\n    label: good\n"
        "  - name: code.filesystem\n    label: bad\n",
        encoding="utf-8",
    )
    out = tmp_path / "report.json"

    result = CliRunner().invoke(main, ["scan", "-c", str(config), "-f", "json", "-o", str(out)])

    assert result.exit_code == 3, result.output
    assert "Traceback" not in result.output and SECRET not in result.output
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["summary"]["complete"] is False
    assert [finding["title"] for finding in report["findings"]] == ["good"]


def test_keyboard_interrupt_still_aborts_the_scan(monkeypatch):
    def interrupt():
        raise KeyboardInterrupt

    monkeypatch.setattr(engine_module, "get_connector_class", lambda name: _connector(interrupt))
    with pytest.raises(KeyboardInterrupt):
        Engine(_config(), SignatureIndex([])).run()


def test_engine_gives_http_clients_the_connector_deadline_and_cancellation(monkeypatch):
    from shadowscan.utils.http import HttpClient

    seen = {}

    class Connector:
        def __init__(self, ctx):
            self.ctx = ctx

        def run(self):
            client = HttpClient()
            seen["deadline"], seen["cancelled"] = client.deadline, client.cancelled
            self.ctx.stats = ScanStats(
                connector="code.filesystem", started_at=now_iso(), finished_at=now_iso()
            )
            return []

    monkeypatch.setattr(engine_module, "get_connector_class", lambda name: Connector)

    Engine(ScanConfig(connectors=[ConnectorSpec("code.filesystem", label="x")]), SignatureIndex([])).run()

    assert seen["deadline"] is not None and seen["cancelled"] is not None
    # The worker context is reset afterwards: clients made outside a connector have no limits.
    assert HttpClient().deadline is None and HttpClient().cancelled is None


# A third-party plugin runs its own code when it is imported, and when the
# engine asks its class about caching and credential approval, before
# collection starts. A BaseException there is a connector failure too.

PLUGIN = "code.acme-exit"


@pytest.fixture
def plugin_registry(monkeypatch):
    monkeypatch.setattr(registry, "_cache", {})
    monkeypatch.setattr(registry, "_load_errors", {})
    monkeypatch.setattr(registry, "_listing_errors", [])


def _install_plugin(monkeypatch, tmp_path, module, source):
    """Install ``source`` as module ``module`` and publish it as the PLUGIN entry point."""
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    (plugins / f"{module}.py").write_text(source, encoding="utf-8")
    monkeypatch.syspath_prepend(str(plugins))
    monkeypatch.delitem(sys.modules, module, raising=False)
    entry = EntryPoint(name=PLUGIN, value=f"{module}:Connector", group="shadowscan.connectors")
    monkeypatch.setattr(registry, "entry_points", lambda **kwargs: [entry])


def _repository(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "requirements.txt").write_text("langchain\nopenai\n", encoding="utf-8")
    return repo


def _scan(tmp_path, plugin_options="", extra_options=""):
    config = tmp_path / "scan.yaml"
    config.write_text(
        "options:\n"
        f"  plugins: [{PLUGIN}]\n"
        "  allow_credential_mixing: true\n"
        f"{extra_options}"
        "connectors:\n"
        f"  - name: code.filesystem\n    path: {_repository(tmp_path)}\n"
        f"  - name: {PLUGIN}\n{plugin_options}",
        encoding="utf-8",
    )
    out = tmp_path / "report.json"
    result = CliRunner().invoke(main, ["scan", "-c", str(config), "-f", "json", "-o", str(out)])
    return result, out


def _assert_plugin_incomplete(result, out, *expected):
    assert result.exit_code == 3, (result.exit_code, result.output, result.exception)
    assert "Traceback" not in result.output and SECRET not in result.output
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["summary"]["complete"] is False
    assert SECRET not in json.dumps(report)
    stats = {entry["connector"]: entry for entry in report["stats"]}
    sibling, plugin = stats["code.filesystem"], stats[PLUGIN]
    assert not sibling["incomplete"] and not sibling["errors"]
    assert any(finding["connector"] == "code.filesystem" for finding in report["findings"])
    assert plugin["incomplete"] and plugin["skipped"]
    (error,) = plugin["errors"]
    assert PLUGIN in error and all(text in error for text in expected), error
    return error


_IMPORT_EXITS = {
    "exit-0": ("import sys\nsys.exit(0)\n", "SystemExit"),
    "exit-1": ("import sys\nsys.exit(1)\n", "SystemExit"),
    "exit-text": (f"raise SystemExit('fatal: Authorization: Bearer {SECRET}')\n", "SystemExit"),
    "baseexception": (
        f"class Fatal(BaseException):\n    pass\n\nraise Fatal('token={SECRET}')\n",
        "Fatal",
    ),
}


@pytest.mark.parametrize("case", sorted(_IMPORT_EXITS))
def test_plugin_exiting_at_import_is_an_incomplete_connector(monkeypatch, tmp_path, plugin_registry, case):
    source, exception = _IMPORT_EXITS[case]
    module = f"acme_exit_plugin_{case.replace('-', '_')}"
    _install_plugin(monkeypatch, tmp_path, module, source)

    result, out = _scan(tmp_path)

    error = _assert_plugin_incomplete(result, out, "could not be imported", exception)
    assert module not in sys.modules
    (diagnostic,) = registry.plugin_registry_errors()
    assert diagnostic.entry == PLUGIN and diagnostic.rule == "load-failed"
    assert diagnostic.message in error and SECRET not in diagnostic.message


def test_keyboard_interrupt_at_plugin_import_still_aborts_the_scan(monkeypatch, tmp_path, plugin_registry):
    _install_plugin(monkeypatch, tmp_path, "acme_interrupt_plugin", "raise KeyboardInterrupt\n")
    repository = ConnectorSpec("code.filesystem", {"path": str(_repository(tmp_path))})
    config = ScanConfig(
        connectors=[repository, ConnectorSpec(PLUGIN)],
        plugins=[PLUGIN],
        allow_credential_mixing=True,
    )
    with pytest.raises(KeyboardInterrupt):
        Engine(config, SignatureIndex([])).run()


_PLUGIN_CLASS = """
import sys

from shadowscan.connectors.base import BaseConnector, ConnectorError
from shadowscan.models import Surface

constructed = False
collected = False


class Meta(type(BaseConnector)):
    {meta}


class Connector(BaseConnector, metaclass=Meta):
    name = "code.acme-exit"
    surface = Surface.CODE
    description = "Exits from an engine hook."
    config_keys = {{"paths": "roots"}}

    @classmethod
    def {hook}(cls, *args, **kwargs):
        {body}

    def __init__(self, ctx):
        global constructed
        constructed = True
        super().__init__(ctx)

    def collect(self):
        global collected
        collected = True
        yield from ()

    def analyze(self, records):
        yield from ()
"""

_HOOK_EXITS = {
    "approval-exit-0": ("inherits_instance_credentials_approval", "sys.exit(0)", "SystemExit"),
    "approval-exit-text": (
        "inherits_instance_credentials_approval",
        f"raise SystemExit('token={SECRET}')",
        "SystemExit",
    ),
    "split-exit-0": ("cache_roots_separately", "sys.exit(0)", "SystemExit"),
    "split-error": ("cache_roots_separately", f"raise ValueError('token={SECRET}')", "ValueError"),
    "split-connector-error": (
        "cache_roots_separately",
        f"raise ConnectorError('opaque {SECRET}')",
        "ConnectorError",
    ),
}


@pytest.mark.parametrize("case", sorted(_HOOK_EXITS))
def test_plugin_exiting_from_an_engine_hook_is_an_incomplete_connector(
    monkeypatch, tmp_path, plugin_registry, case
):
    hook, body, exception = _HOOK_EXITS[case]
    source = _PLUGIN_CLASS.format(meta="pass", hook=hook, body=body)
    module = f"acme_hook_plugin_{case.replace('-', '_')}"
    _install_plugin(monkeypatch, tmp_path, module, source)
    roots = [tmp_path / "roots" / name for name in ("one", "two")]
    for root in roots:
        root.mkdir(parents=True)

    result, out = _scan(
        tmp_path,
        plugin_options=f"    paths: [{roots[0]}, {roots[1]}]\n",
        extra_options=f"  incremental: true\n  state_dir: {tmp_path / 'state'}\n",
    )

    error = _assert_plugin_incomplete(result, out, f"{hook}() raised {exception}")
    assert error == f"{PLUGIN}: {hook}() raised {exception}"
    assert not sys.modules[module].constructed and not sys.modules[module].collected


@pytest.mark.parametrize(
    "invalid_config,expected",
    [
        ({"duplicate_paths": True}, "labeled paths must resolve to distinct scan roots"),
        ({"root_ids": ["only-one"]}, "root_ids must contain exactly one ID per path"),
    ],
)
def test_failed_builtin_cache_hook_preserves_validation_diagnostics(tmp_path, invalid_config, expected):
    roots = [tmp_path / name for name in ("one", "two")]
    for root in roots:
        root.mkdir()
    config = {"paths": [str(root) for root in roots]}
    if invalid_config.get("duplicate_paths"):
        config["paths"] = [str(roots[0]), str(roots[0])]
    else:
        config.update(invalid_config)
    result = Engine(
        ScanConfig(
            connectors=[ConnectorSpec("code.filesystem", config, label="repository")],
            incremental=True,
            state_dir=str(tmp_path / "state"),
        ),
        SignatureIndex([]),
    ).run()

    assert not result.complete and not result.findings
    (stats,) = result.stats
    assert stats.incomplete and stats.skipped
    assert stats.errors == [f"code.filesystem: {expected}"]


def test_plugin_exiting_while_its_class_is_verified_is_an_incomplete_connector(
    monkeypatch, tmp_path, plugin_registry
):
    # The registry reads the declared attributes; a metaclass property runs plugin code there.
    meta = "@property\n    def description(cls):\n        sys.exit(0)"
    source = _PLUGIN_CLASS.format(meta=meta, hook="cache_roots_separately", body="return False")
    _install_plugin(monkeypatch, tmp_path, "acme_verify_plugin", source)

    result, out = _scan(tmp_path)

    _assert_plugin_incomplete(result, out, "connector lookup raised SystemExit")
