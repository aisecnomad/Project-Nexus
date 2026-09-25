"""Keep every configuration key a connector reads visible in its documentation.

``shadowscan connectors`` (and docs/connectors.md, which defers to it) renders
each class's ``config_keys`` plus the shared offline limits declared once on
``BaseConnector.shared_config_keys``. These tests scan the connector sources,
so an undocumented ``ctx.get("key")`` or a stale documented key fails the
suite instead of silently drifting away from the listing.
"""

from __future__ import annotations

import ast
import json
import re
import sys
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path

import pytest
from click.testing import CliRunner

import shadowscan.connectors
from shadowscan.cli import main
from shadowscan.connectors import builtin_connector_names, get_connector_class
from shadowscan.connectors.base import BaseConnector

PACKAGE = Path(shadowscan.connectors.__file__).resolve().parent
CONNECTORS = sorted(builtin_connector_names())
KEY_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")
# Injected by the engine for its own bookkeeping; never user configuration.
ENGINE_PRIVATE_KEYS = {"_dump_path", "_shared_label_roots", "_root_id"}
# Consumed by ConnectorContext (input_path) rather than by the connector class.
CONTEXT_KEYS = {"input"}
# Offline input is a code checkout, bounded by the scanner's own limits.
CHECKOUT_CONNECTORS = {"code.filesystem", "code.github", "code.gitlab"}


@dataclass
class _ModuleReads:
    """Config keys read per class body, plus reads outside any class."""

    classes: dict[str, set[str]] = field(default_factory=dict)
    module_level: set[str] = field(default_factory=set)
    non_literal: list[str] = field(default_factory=list)


def _is_ctx(node: ast.AST) -> bool:
    """``ctx`` or ``<receiver>.ctx`` (``self.ctx``, ``conn.ctx``)."""
    return (isinstance(node, ast.Name) and node.id == "ctx") or (isinstance(node, ast.Attribute) and node.attr == "ctx")


def _is_ctx_config(node: ast.AST) -> bool:
    return isinstance(node, ast.Attribute) and node.attr == "config" and _is_ctx(node.value)


def _string_constants(node: ast.AST) -> set[str]:
    return {sub.value for sub in ast.walk(node) if isinstance(sub, ast.Constant) and isinstance(sub.value, str)}


def _collect(node: ast.AST, keys: set[str], non_literal: list[str]) -> None:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
            # ctx.get("key"), ctx.require("key"), ctx.config.get("key")
            receiver = sub.func.value
            if sub.func.attr in {"get", "require"} and (_is_ctx(receiver) or _is_ctx_config(receiver)):
                if sub.args and isinstance(sub.args[0], ast.Constant) and isinstance(sub.args[0].value, str):
                    keys.add(sub.args[0].value)
                else:
                    non_literal.append(f"line {sub.lineno}: {ast.unparse(sub)}")
        elif isinstance(sub, ast.Subscript) and _is_ctx_config(sub.value):
            # ctx.config["key"]
            if isinstance(sub.slice, ast.Constant) and isinstance(sub.slice.value, str):
                keys.add(sub.slice.value)
            else:
                non_literal.append(f"line {sub.lineno}: {ast.unparse(sub)}")
        elif isinstance(sub, ast.comprehension):
            # {k: v for k, v in ctx.config.items() if k in {"a", "b"}}
            it = sub.iter
            if isinstance(it, ast.Call) and isinstance(it.func, ast.Attribute) and it.func.attr == "items" and _is_ctx_config(it.func.value):
                for condition in sub.ifs:
                    keys |= _string_constants(condition)


@cache
def _scan(path: Path) -> _ModuleReads:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    reads = _ModuleReads()
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            keys: set[str] = set()
            _collect(node, keys, reads.non_literal)
            reads.classes[node.name] = keys
        else:
            _collect(node, reads.module_level, reads.non_literal)
    return reads


def _module_path(cls: type) -> Path | None:
    module = sys.modules.get(cls.__module__)
    file = getattr(module, "__file__", None)
    if not file:
        return None
    path = Path(file).resolve()
    return path if PACKAGE in path.parents else None


def _keys_read_by(cls: type[BaseConnector]) -> set[str]:
    """Keys read by the connector class and its in-package bases (not BaseConnector)."""
    read: set[str] = set()
    for klass in cls.__mro__:
        if klass is BaseConnector:
            continue
        path = _module_path(klass)
        if path is None:
            continue
        scanned = _scan(path)
        read |= scanned.classes.get(klass.__name__, set())
        read |= scanned.module_level
    return read


def _declared(cls: type[BaseConnector]) -> set[str]:
    return set(cls.config_keys) | set(cls.shared_config_keys)


def test_shared_config_keys_cover_base_connector_reads():
    base = _scan(PACKAGE / "base.py")
    read = base.classes["BaseConnector"] | base.module_level
    public = {key for key in read if not key.startswith("_")}
    assert public == set(BaseConnector.shared_config_keys)
    assert {key for key in read if key.startswith("_")} <= ENGINE_PRIVATE_KEYS
    assert not base.non_literal


def test_every_connector_source_is_scanned_with_literal_keys():
    problems = []
    for path in sorted(PACKAGE.rglob("*.py")):
        reads = _scan(path)
        problems.extend(f"{path.relative_to(PACKAGE)}: {entry}" for entry in reads.non_literal)
    assert not problems, "config keys must be string literals so the listing stays complete:\n" + "\n".join(problems)


def test_helper_modules_do_not_read_undeclared_config():
    """Reads outside a connector class cannot be attributed to any listing."""
    connector_modules = {_module_path(get_connector_class(name)) for name in CONNECTORS}
    for path in sorted(PACKAGE.rglob("*.py")):
        if path in connector_modules or path.name == "base.py":
            continue
        reads = _scan(path)
        stray = reads.module_level | set().union(*reads.classes.values())
        assert not stray, f"{path.relative_to(PACKAGE)} reads config keys {sorted(stray)} outside a connector class"


@pytest.mark.parametrize("name", CONNECTORS)
def test_read_keys_are_declared(name):
    cls = get_connector_class(name)
    read = _keys_read_by(cls)
    private = {key for key in read if key.startswith("_")}
    assert private <= ENGINE_PRIVATE_KEYS, f"{name} reads unknown private keys {sorted(private - ENGINE_PRIVATE_KEYS)}"
    undeclared = read - private - _declared(cls)
    assert not undeclared, f"{name} reads {sorted(undeclared)} but does not document them in config_keys"


@pytest.mark.parametrize("name", CONNECTORS)
def test_declared_keys_are_read(name):
    cls = get_connector_class(name)
    stale = set(cls.config_keys) - _keys_read_by(cls) - CONTEXT_KEYS
    assert not stale, f"{name} documents {sorted(stale)} but never reads them"


@pytest.mark.parametrize("name", CONNECTORS)
def test_config_keys_are_identifiers_with_plain_descriptions(name):
    cls = get_connector_class(name)
    for key, text in {**cls.config_keys, **cls.shared_config_keys}.items():
        assert KEY_PATTERN.match(key), f"{name}: config key {key!r} is not a YAML-friendly identifier"
        assert isinstance(text, str) and text.strip(), f"{name}: config key {key!r} has no description"
        assert "—" not in text, f"{name}: config key {key!r} description uses an em-dash"


@pytest.mark.parametrize("name", CONNECTORS)
def test_shared_keys_are_declared_once_per_export_connector(name):
    cls = get_connector_class(name)
    shared = set(BaseConnector.shared_config_keys)
    assert shared == {"max_input_bytes", "max_input_file_bytes", "max_input_files"}
    assert not shared & set(cls.config_keys), f"{name} repeats shared offline keys in config_keys"
    if name in CHECKOUT_CONNECTORS:
        assert cls.shared_config_keys == {}, f"{name} scans checkouts; export limits do not apply"
    else:
        assert "input" in cls.config_keys, f"{name} accepts offline exports and must document `input`"
        assert cls.shared_config_keys == BaseConnector.shared_config_keys


def test_connectors_listing_merges_shared_keys():
    result = CliRunner().invoke(main, ["connectors", "--json"])
    assert result.exit_code == 0, result.output
    rows = {row["name"]: row for row in json.loads(result.output)}
    shared = BaseConnector.shared_config_keys
    okta = rows["identity.okta"]["config"]
    assert "bearer" in okta
    assert list(okta)[-len(shared):] == list(shared), "shared keys follow the connector's own keys"
    assert all(okta[key] == text for key, text in shared.items())
    gateway = rows["gateway.logs"]["config"]
    assert {"label", "gateway_name", *shared} <= set(gateway)
    for name in CHECKOUT_CONNECTORS:
        assert not set(shared) & set(rows[name]["config"]), f"{name} must not advertise export limits"
    assert {"max_pages", "tenancy", "region"} <= set(rows["cloud.oci"]["config"])
    assert {"organization_id", "max_pages"} <= set(rows["lowcode.make"]["config"])
    assert {"github_token", "user", "repos", "exclude"} <= set(rows["code.github"]["config"])


def test_connectors_table_renders_shared_keys():
    result = CliRunner().invoke(main, ["connectors", "--surface", "identity"])
    assert result.exit_code == 0, result.output
    assert "max_input_files" in result.output
    assert "identity.okta" in result.output


def test_filesystem_owner_description_matches_precedence(run_connector, fixtures):
    """A configured `owner` wins over CODEOWNERS, as its config_keys entry says."""
    text = get_connector_class("code.filesystem").config_keys["owner"]
    assert "overrides CODEOWNERS" in text and "fallback" not in text
    path = str(fixtures / "sample_repo")

    findings, _ = run_connector("code.filesystem", path=path, label="fixture")
    by_path = {f.metadata["path"]: f for f in findings if f.resource_type == "project"}
    assert by_path["services/research-agent"].owner == "@acme/data-science"

    findings, _ = run_connector("code.filesystem", path=path, label="fixture", owner="platform-team")
    assert findings and all(f.owner == "platform-team" for f in findings)
