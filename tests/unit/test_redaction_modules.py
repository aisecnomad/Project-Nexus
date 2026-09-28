"""The redaction modules behave as the one module they were split from.

``shadowscan.utils.redaction`` drives the ``redaction_*`` modules and is their
public face: every name they define reads through it, a name replaced there
is replaced in every module that binds it, and ``policy_token()`` sees a rule
replaced in any single module.
"""

from __future__ import annotations

import ast
import copy
import inspect
import types

import pytest

from shadowscan.utils import (
    redaction,
    redaction_assignments,
    redaction_calls,
    redaction_commands,
    redaction_formats,
    redaction_markup,
    redaction_rules,
    redaction_statements,
)
from shadowscan.utils.redaction import REDACTED, sanitize_text

SPLIT = [
    redaction_rules,
    redaction_formats,
    redaction_statements,
    redaction_assignments,
    redaction_calls,
    redaction_commands,
    redaction_markup,
]
MODULES = [redaction, *SPLIT]


def _defined(module: types.ModuleType) -> set[str]:
    """The names a module's own top-level statements define (not its imports)."""
    names: set[str] = set()
    for node in ast.parse(inspect.getsource(module)).body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                elements = target.elts if isinstance(target, ast.Tuple) else [target]
                names.update(element.id for element in elements if isinstance(element, ast.Name))
    return names


def _bound() -> set[str]:
    """Every non-dunder name some split module binds, except imported modules."""
    return {
        name
        for module in SPLIT
        for name, value in vars(module).items()
        if not name.startswith("__") and not isinstance(value, types.ModuleType)
    }


def test_every_name_is_defined_by_exactly_one_module():
    owners: dict[str, list[str]] = {}
    for module in MODULES:
        for name in _defined(module):
            owners.setdefault(name, []).append(module.__name__)
    assert {name: found for name, found in owners.items() if len(found) > 1} == {}


def test_the_modules_bind_each_name_to_one_object():
    # A name imported from its defining module is the same object everywhere,
    # so the modules together still form one namespace.
    for name in _bound() | {name for name in vars(redaction) if not name.startswith("__")}:
        objects = {id(vars(module)[name]) for module in MODULES if name in vars(module)}
        assert len(objects) == 1, name


@pytest.mark.parametrize("module", SPLIT, ids=lambda module: module.__name__.rsplit(".", 1)[-1])
def test_every_name_a_module_defines_reads_through_the_public_module(module):
    for name in _defined(module):
        assert getattr(redaction, name) is vars(module)[name], name
    with pytest.raises(AttributeError):
        redaction.no_such_redaction_rule  # noqa: B018


def test_a_name_replaced_through_the_public_module_is_replaced_in_every_binding(monkeypatch):
    sentinel = object()
    names = sorted(_bound())
    assert len(names) > 150
    for name in names:
        binders = [module for module in MODULES if name in vars(module)]
        original = vars(binders[0])[name]
        with monkeypatch.context() as patch:
            patch.setattr(redaction, name, sentinel)
            assert getattr(redaction, name) is sentinel
            assert all(vars(module)[name] is sentinel for module in binders), name
            assert not any(name in vars(module) for module in MODULES if module not in binders), name
        assert all(vars(module)[name] is original for module in binders), name


@pytest.mark.parametrize("name", ["_CLI_WORD", "_MAX_REDACTION_WORK"])
def test_a_name_deleted_through_the_public_module_is_deleted_everywhere(monkeypatch, name):
    # '_MAX_REDACTION_WORK' is also bound by the public module itself.
    binders = [module for module in MODULES if name in vars(module)]
    assert len(binders) > 1
    original = getattr(redaction, name)
    with monkeypatch.context() as patch:
        patch.delattr(redaction, name)
        assert not hasattr(redaction, name)
        assert not any(name in vars(module) for module in MODULES)
    assert all(vars(module)[name] is original for module in binders)
    with pytest.raises(AttributeError):
        del redaction.no_such_redaction_rule


# One form per pass module; each names 'newsecretformat', which is ordinary
# until the sensitive-name list is replaced through the public module.
_NEW_NAME_FORMS = {
    "assignments": "newsecretformat=opaque-plain-value",
    "mapping": '{"newsecretformat": ["opaque-mapping-value"]}',
    "statements": 'newsecretformat = (\n    "opaque-statement-value"\n    + suffix\n)\n',
    "calls": 'os.environ.setdefault("newsecretformat", "opaque-call-value")',
    "commands": "tool --newsecretformat opaque-option-value-2 --verbose",
    "markup-element": "<newsecretformat>opaque-element-value</newsecretformat>",
    "markup-attribute": '<add key="newsecretformat" value="opaque-attribute-value"/>',
    "records": "{name: newsecretformat, value: opaque-record-value}",
    "formats": "https://example.com/hook?newsecretformat=opaque-query-value&page=2",
}


@pytest.mark.parametrize("form", sorted(_NEW_NAME_FORMS))
def test_a_rule_replaced_through_the_public_module_reaches_every_pass(monkeypatch, form):
    source = _NEW_NAME_FORMS[form]
    assert sanitize_text(source) == source
    monkeypatch.setattr(redaction, "_SENSITIVE_NAMES", redaction._SENSITIVE_NAMES | {"newsecretformat"})
    safe = sanitize_text(source)
    assert "opaque-" not in safe and REDACTED in safe, safe


@pytest.mark.parametrize("module", MODULES, ids=lambda module: module.__name__.rsplit(".", 1)[-1])
def test_policy_token_sees_a_rule_replaced_in_any_single_module(monkeypatch, module):
    # Every rule, pattern, limit and helper a module binds, including the
    # names it imports from another redaction module, is part of the token.
    machinery = {"_POLICY_BINDINGS", "_policy_value", "policy_token"}  # what computes the token
    policies = [
        name
        for name, value in vars(module).items()
        if not name.startswith("__") and redaction._is_policy(value) and name not in machinery
    ]
    assert policies
    unchanged = redaction.policy_token()
    for name in policies:
        with monkeypatch.context() as patch:
            if module is redaction:
                patch.setitem(vars(module), name, object())
            else:
                patch.setattr(module, name, object())
            assert redaction.policy_token() != unchanged, (module.__name__, name)
        assert redaction.policy_token() == unchanged, (module.__name__, name)


def test_every_defined_rule_is_part_of_the_policy_token():
    covered = {(id(namespace), name) for namespace, name in redaction._POLICY_BINDINGS}
    for module in MODULES:
        for name in _defined(module) - {"_POLICY_BINDINGS"}:
            if redaction._is_policy(vars(module)[name]):
                assert (id(vars(module)), name) in covered, (module.__name__, name)


def test_policy_token_can_be_copied_with_a_finding():
    # Findings keep the token beside their verified-clean digest, and
    # dataclasses.asdict() deep-copies it: no module object may be in it.
    token = redaction.policy_token()
    assert copy.deepcopy(token) == token
