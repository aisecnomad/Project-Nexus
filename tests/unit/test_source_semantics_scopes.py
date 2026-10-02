"""Python binding scopes: conditional branches merge their own assignments only."""

from __future__ import annotations

import ast
import time

from shadowscan.connectors.code.source_semantics import _Binding, _PythonBindings


def _bindings(text: str) -> dict[str, _Binding | None]:
    binder = _PythonBindings(text)
    binder.visit(ast.parse(text))
    return dict(binder.scopes[-1])


def test_only_bindings_identical_after_both_branches_survive():
    text = (
        "import openai\n"
        "if flag:\n"
        "    from anthropic import Anthropic as Client\n"
        "    keep = openai\n"
        "else:\n"
        "    from openai import OpenAI as Client\n"
        "    keep = openai\n"
        "Client()\n"
    )
    scope = _bindings(text)
    assert scope["openai"] == _Binding("openai", "")  # untouched by either branch
    assert scope["Client"] is None  # differs between the branches
    assert scope["keep"] == _Binding("openai", "")  # identical in both


def test_nested_branches_merge_into_the_enclosing_scope():
    text = (
        "import openai\n"
        "if a:\n"
        "    if b:\n"
        "        from openai import OpenAI\n"
        "    else:\n"
        "        from openai import OpenAI\n"
        "    from openai import AsyncOpenAI\n"
        "else:\n"
        "    from openai import OpenAI, AsyncOpenAI\n"
    )
    scope = _bindings(text)
    assert scope["openai"] == _Binding("openai", "")
    assert scope["OpenAI"] == _Binding("openai", "OpenAI")
    assert scope["AsyncOpenAI"] == _Binding("openai", "AsyncOpenAI")


def test_star_import_on_one_branch_clobbers_every_binding():
    text = "import openai\nif c:\n    from somewhere import *\nelse:\n    pass\n"
    scope = _bindings(text)
    # The star import rebinds every name on its branch, so nothing is certain
    # afterwards; the branch's whole scope is its outcome.
    assert scope["openai"] is None


def test_many_top_level_names_and_branches_bind_in_linear_time():
    names = "\n".join(f"name{number} = {number}" for number in range(8000))
    branches = "\n".join(
        f"if flag{number}:\n    name{number} = None\nelse:\n    pass" for number in range(8000)
    )
    started = time.monotonic()
    scope = _bindings(names + "\n" + branches + "\n")
    # Copying the whole scope per ``if`` took tens of seconds at this size.
    assert time.monotonic() - started < 10
    assert len(scope) == 8000
