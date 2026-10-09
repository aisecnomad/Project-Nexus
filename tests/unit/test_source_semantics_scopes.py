"""Python binding scopes: conditional branches merge their own assignments only."""

from __future__ import annotations

import ast
import time

import pytest

from shadowscan.connectors.code.source_semantics import MAX_AST_NODES, _Binding, _PythonBindings
from shadowscan.models import Kind


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


@pytest.mark.parametrize("syntax", ["except", "except*"])
@pytest.mark.parametrize("handler", ["Agent = object", "from agents import Agent"])
def test_try_paths_do_not_take_the_last_handlers_binding(syntax, handler):
    body = "from agents import Agent" if handler == "Agent = object" else "Agent = object"
    scope = _bindings(f"from agents import Agent\ntry:\n    {body}\n{syntax} Exception:\n    {handler}\n")
    assert scope["Agent"] is None


def test_trivial_try_cannot_enter_a_handler_and_else_keeps_its_binding():
    scope = _bindings(
        "from agents import Agent\ntry:\n    pass\nexcept Exception:\n    Agent = object\n"
        "else:\n    alias = Agent\n"
    )
    assert scope["Agent"] == _Binding("agents", "Agent")
    assert scope["alias"] == _Binding("agents", "Agent")


def test_try_else_and_handlers_can_agree_on_a_new_binding():
    scope = _bindings(
        "try:\n    operation()\nexcept ValueError:\n    from agents import Agent\n"
        "except TypeError:\n    from agents import Agent\nelse:\n    from agents import Agent\n"
    )
    assert scope["Agent"] == _Binding("agents", "Agent")


def test_finally_overrides_the_joined_normal_and_handler_bindings():
    scope = _bindings(
        "try:\n    Agent = object\nexcept Exception:\n    Agent = dict\n"
        "finally:\n    from agents import Agent\n"
    )
    assert scope["Agent"] == _Binding("agents", "Agent")


def test_exception_alias_is_deleted_even_when_reimported_in_the_handler():
    scope = _bindings(
        "from agents import Agent\ntry:\n    operation()\nexcept Exception as Agent:\n"
        "    from agents import Agent\n"
    )
    assert scope["Agent"] is None


@pytest.mark.parametrize(
    "source",
    [
        "from agents import Agent\ntry:\n    Agent = object\n    operation()\n"
        "    from agents import Agent\nexcept Exception:\n    Agent()\n",
        "from agents import Agent\ntry:\n    Agent = object\n    operation()\n"
        "    from agents import Agent\nfinally:\n    Agent()\n",
        "from agents import Agent\ntry:\n    operation()\nexcept* ValueError:\n"
        "    Agent = object\nexcept* TypeError:\n    Agent()\n",
        "from agents import Agent\ntry:\n    operation()\nexcept Exception:\n"
        "    Agent = object\n    operation()\n    from agents import Agent\nfinally:\n    Agent()\n",
        "from agents import Agent\ntry:\n    pass\nexcept Exception:\n    pass\nelse:\n"
        "    Agent = object\n    operation()\n    from agents import Agent\nfinally:\n    Agent()\n",
        "from agents import Agent\ntry:\n    raise TypeError()\nexcept (Agent := ValueError):\n"
        "    pass\nexcept TypeError:\n    Agent()\n",
    ],
)
def test_exception_and_finally_calls_do_not_inherit_the_successful_body_state(source):
    binder = _PythonBindings(source)
    binder.visit(ast.parse(source))
    assert not any(call.binding == _Binding("agents", "Agent") for call in binder.calls)


def test_terminating_handler_does_not_poison_the_normal_continuation():
    text = (
        "def build():\n    from agents import Agent\n    try:\n        operation()\n"
        "    except Exception:\n        Agent = object\n        return None\n    Agent()\n"
    )
    binder = _PythonBindings(text)
    binder.visit(ast.parse(text))
    assert any(call.binding == _Binding("agents", "Agent") for call in binder.calls)


@pytest.mark.parametrize(
    "cases",
    [
        "    case 'local':\n        Agent = object\n    case 'ai':\n        from agents import Agent\n",
        "    case 'ai':\n        from agents import Agent\n    case 'local':\n        Agent = object\n",
        "    case 'ai':\n        from agents import Agent\n",
        "    case _ if enabled:\n        from agents import Agent\n",
    ],
)
def test_match_cases_and_the_unmatched_path_do_not_leak_bindings(cases):
    scope = _bindings("Agent = object\nmatch mode:\n" + cases)
    assert scope["Agent"] is None


def test_exhaustive_match_cases_can_agree_on_a_new_binding():
    scope = _bindings(
        "match mode:\n    case 'ai':\n        from agents import Agent\n"
        "    case _:\n        from agents import Agent\n"
    )
    assert scope["Agent"] == _Binding("agents", "Agent")


@pytest.mark.parametrize("guard", ["False", "None", "0", "''"])
def test_false_match_guard_keeps_captures_but_does_not_visit_its_body(guard):
    text = (
        "from agents import Agent\nmatch mode:\n"
        f"    case {{'factory': Agent}} if {guard}:\n        from agents import Agent\n"
        "        Agent()\n    case _:\n        Agent()\n"
    )
    binder = _PythonBindings(text)
    binder.visit(ast.parse(text))
    assert not any(call.binding == _Binding("agents", "Agent") for call in binder.calls)


def test_match_guard_assignment_is_uncertain_on_the_next_case():
    text = (
        "from agents import Agent\nmatch mode:\n    case 'ai' if (Agent := object):\n"
        "        pass\n    case _:\n        Agent()\n"
    )
    binder = _PythonBindings(text)
    binder.visit(ast.parse(text))
    assert not any(call.binding == _Binding("agents", "Agent") for call in binder.calls)


@pytest.mark.parametrize("subject", ["'ai'", "True", "1", "None"])
def test_direct_literal_match_excludes_other_cases(subject):
    scope = _bindings(
        f"match {subject}:\n    case {subject}:\n        from agents import Agent\n"
        "    case _:\n        Agent = object\n"
    )
    assert scope["Agent"] == _Binding("agents", "Agent")


@pytest.mark.parametrize(
    ("subject", "pattern"),
    [("1", "True"), ("True", "1"), ("'ai'", "'local' | 'ai'")],
)
def test_literal_match_respects_singleton_identity_numeric_equality_and_or(subject, pattern):
    text = (
        f"match {subject}:\n    case {pattern}:\n        from agents import Agent\n"
        "    case _:\n        Agent = object\n"
    )
    scope = _bindings(text)
    expected = None if pattern == "True" else _Binding("agents", "Agent")
    assert scope["Agent"] == expected


@pytest.mark.parametrize(
    ("body", "agent_expected"),
    [
        ("try:\n    Agent = object\nexcept Exception:\n    from agents import Agent\nAgent()\n", False),
        ("try:\n    pass\nexcept Exception:\n    Agent = object\nAgent()\n", True),
        (
            "try:\n    raise TypeError()\nexcept (Agent := ValueError):\n    pass\n"
            "except TypeError:\n    Agent()\n",
            False,
        ),
        (
            "match mode:\n    case 'local':\n        Agent = object\n"
            "    case 'ai':\n        from agents import Agent\nAgent()\n",
            False,
        ),
        (
            "match 'ai':\n    case 'ai':\n        pass\n    case 'local':\n        Agent = object\nAgent()\n",
            True,
        ),
        (
            "try:\n    operation()\nexcept Exception:\n    Agent = object\n"
            "finally:\n    from agents import Agent\nAgent()\n",
            True,
        ),
        (
            "def build():\n    try:\n        return None\n    finally:\n        pass\n    Agent()\n",
            False,
        ),
        (
            "def build():\n    match mode:\n        case 'ai':\n            return None\n"
            "        case _:\n            return None\n    Agent()\n",
            False,
        ),
    ],
)
def test_branch_binding_changes_reach_the_real_connector(tmp_path, run_connector, body, agent_expected):
    (tmp_path / "app.py").write_text("from agents import Agent\n" + body)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), scan_secrets=False, use_git=False)
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert any(finding.kind == Kind.AGENT for finding in findings) is agent_expected


def test_many_try_and_match_statements_do_not_copy_the_whole_module_scope():
    names = "\n".join(f"name{number} = {number}" for number in range(8000))
    branches = "\n".join(
        f"try:\n    name{number} = None\nexcept Exception:\n    pass\n"
        f"match flag{number}:\n    case True:\n        name{number} = None\n    case _:\n        pass"
        for number in range(4000)
    )
    started = time.monotonic()
    scope = _bindings(names + "\n" + branches + "\n")
    assert time.monotonic() - started < 10
    assert len(scope) == 8000


def test_sparse_branch_join_checks_prior_bindings_once_per_written_name():
    class CountedBindings(dict):
        lookups = 0

        def get(self, *args):
            self.lookups += 1
            return super().get(*args)

    before = CountedBindings()
    outcomes = [{f"alias{number}": _Binding("agents", "Agent")} for number in range(9000)]
    _PythonBindings._join_outcomes(before, outcomes)
    assert before.lookups == 9000
    assert len(before) == 9000
    assert all(binding is None for binding in before.values())


def test_sparse_join_retains_only_explicit_and_implicit_agreement():
    agent = _Binding("agents", "Agent")
    before = {"unchanged": agent, "changed": agent}
    _PythonBindings._join_outcomes(
        before,
        [{"unchanged": agent, "changed": None, "new": agent}, {"new": agent}],
    )
    assert before == {"unchanged": agent, "changed": None, "new": agent}


def test_wide_match_with_disjoint_writes_stays_fast_within_the_ast_budget():
    text = "match mode:\n" + "".join(
        f"    case {number}:\n        from agents import Agent as alias{number}\n" for number in range(9000)
    )
    tree = ast.parse(text)
    assert sum(1 for _ in ast.walk(tree)) < MAX_AST_NODES
    binder = _PythonBindings(text)
    started = time.monotonic()
    binder.visit(tree)
    # Before sparse aggregation, the join alone crossed every alias with every
    # case despite the file fitting the normal AST budget (about 81M checks).
    assert time.monotonic() - started < 3
    assert len(binder.scopes[-1]) == 9000
    assert all(binding is None for binding in binder.scopes[-1].values())


@pytest.mark.parametrize(
    "source",
    [
        "try:\n    from agents import Agent\nexcept ImportError:\n    pass\n"
        "worker = Agent(name='w', tools=[])\n",
        "import sys\ntry:\n    from agents import Agent\nexcept ImportError:\n"
        "    print('install openai-agents')\n    sys.exit(1)\nworker = Agent(name='w', tools=[])\n",
        "try:\n    from agents import Agent\nexcept ImportError:\n    exit('pip install openai-agents')\n"
        "worker = Agent(name='w', tools=[])\n",
        "try:\n    from agents import Agent\nexcept ImportError:\n    quit()\n"
        "worker = Agent(name='w', tools=[])\n",
        "import logging, sys\nlog = logging.getLogger()\ntry:\n    from agents import Agent\n"
        "except ImportError:\n    log.error('missing')\n    sys.exit(2)\nworker = Agent(name='w', tools=[])\n",
        "import os\ntry:\n    from agents import Agent\nexcept ImportError:\n    os._exit(1)\n"
        "worker = Agent(name='w', tools=[])\n",
        "from sys import exit as stop\ntry:\n    from agents import Agent\nexcept ImportError:\n    stop(1)\n"
        "worker = Agent(name='w', tools=[])\n",
        "try:\n    from crewai import Agent\nexcept ImportError:\n    from crewai.agent import Agent\n"
        "worker = Agent(role='r', goal='g', backstory='b', tools=[])\n",
        "class Settings:\n    try:\n        from agents import Agent\n    except ImportError:\n        pass\n"
        "    worker = Agent(name='w', tools=[])\n",
        "def build():\n    try:\n        from agents import Agent\n    except ImportError:\n        return None\n"
        "    return Agent(name='w', tools=[])\n",
        "def build():\n    try:\n        from agents import Agent\n    except ImportError:\n        pass\n"
        "    return Agent(name='w', tools=[])\n",
    ],
)
def test_guarded_sdk_imports_keep_their_agent_binding(tmp_path, run_connector, source):
    # Calling a name left unbound by a failed import raises NameError; it cannot
    # construct another object. Exiting handlers never reach the continuation.
    (tmp_path / "app.py").write_text(source)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), scan_secrets=False, use_git=False)
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert any(finding.kind == Kind.AGENT for finding in findings)


def test_guarded_provider_import_with_exiting_handler_keeps_tool_use(tmp_path, run_connector):
    (tmp_path / "app.py").write_text(
        "import sys\ntry:\n    from openai import OpenAI\nexcept ImportError:\n    sys.exit('pip install openai')\n"
        "client = OpenAI()\nclient.chat.completions.create(model='m', messages=[], "
        "tools=[{'type': 'function', 'function': {'name': 'f', 'parameters': {}}}])\n"
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), scan_secrets=False, use_git=False)
    assert not ctx.stats.incomplete, ctx.stats.errors
    assert any("tool-use" in finding.capabilities for finding in findings)


@pytest.mark.parametrize(
    "source",
    [
        # A prior binding survives the failed import: the call may construct it.
        "Agent = object\ntry:\n    from agents import Agent\nexcept ImportError:\n    pass\nAgent()\n",
        # A handler rebinding the name to a non-SDK value stays uncertain.
        "try:\n    from agents import Agent\nexcept ImportError:\n    Agent = object\nAgent()\n",
        "try:\n    from agents import Agent\nexcept ImportError:\n    from crewai import Agent\nAgent()\n",
        # Clause tests may assign the name before a later handler runs.
        "try:\n    from agents import Agent\nexcept (Agent := ImportError):\n    pass\n"
        "except Exception:\n    pass\nAgent()\n",
        # A star import may already provide the name.
        "from helpers import *\ntry:\n    from agents import Agent\nexcept ImportError:\n    pass\nAgent()\n",
        # A builtin of the same name remains callable after the failed import.
        "try:\n    from agents import input\nexcept ImportError:\n    pass\ninput()\n",
        # Shadowed exits are ordinary calls that continue.
        "def exit(code):\n    return code\ntry:\n    from agents import Agent\nexcept ImportError:\n"
        "    exit(1)\n    Agent = object\nAgent()\n",
        "import sys\nsys = object()\ntry:\n    from agents import Agent\nexcept ImportError:\n"
        "    sys.exit(1)\n    Agent = object\nAgent()\n",
        # A later iteration can reach the handler with the name another
        # statement bound; so can a function that declares it global.
        "for item in items:\n    try:\n        from agents import Agent\n    except ImportError:\n"
        "        pass\n    Agent()\n    Agent = object\n",
        "def setup():\n    global Agent\n    Agent = object\nsetup()\ntry:\n    from agents import Agent\n"
        "except ImportError:\n    pass\nAgent()\n",
    ],
)
def test_guarded_import_alternatives_that_may_differ_stay_uncertain(source):
    binder = _PythonBindings(source)
    binder.visit(ast.parse(source))
    assert not any(call.binding.module == "agents" for call in binder.calls)


def test_a_module_defined_exit_is_an_ordinary_call():
    # The module binds exit after main is defined; calling it returns.
    text = (
        "from agents import Agent\ndef main():\n    exit(1)\n    return Agent()\n"
        "def exit(code):\n    return code\n"
    )
    binder = _PythonBindings(text)
    binder.visit(ast.parse(text))
    assert any(call.binding == _Binding("agents", "Agent") for call in binder.calls)


@pytest.mark.parametrize(
    "terminator", ["sys.exit(1)", "exit(1)", "quit()", "os._exit(1)", "raise SystemExit(1)"]
)
def test_exiting_calls_do_not_reach_later_statements(terminator):
    text = f"import os, sys\nfrom agents import Agent\ndef main():\n    {terminator}\n    return Agent()\n"
    binder = _PythonBindings(text)
    binder.visit(ast.parse(text))
    assert not any(call.binding == _Binding("agents", "Agent") for call in binder.calls)
