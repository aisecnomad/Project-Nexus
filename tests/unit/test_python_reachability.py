"""Unreachable Python suites cannot construct agents or mutate proven bindings."""

from __future__ import annotations

from pathlib import Path

import pytest

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.engine import Engine
from shadowscan.models import Kind

IMPORT = "from agents import Agent\n"
CONSTRUCT = 'Agent(name="worker", instructions="Help")'


def scan(tmp_path: Path, source: str):
    (tmp_path / "app.py").write_text(source)
    config = ScanConfig(
        connectors=[
            ConnectorSpec(
                "code.filesystem",
                {"path": str(tmp_path), "use_git": False, "scan_secrets": False},
            )
        ]
    )
    result = Engine(config).run()
    assert result.complete, [stats.errors for stats in result.stats]
    return result.findings


@pytest.mark.parametrize("condition", ["False", "0", "None", "''"])
def test_false_while_body_is_not_agent_construction(tmp_path, condition):
    findings = scan(tmp_path, IMPORT + f"while {condition}:\n    {CONSTRUCT}\n")
    assert findings and all(f.kind == Kind.FRAMEWORK_USAGE for f in findings)
    assert all(f.metadata["agent_indicators"] == 0 for f in findings)


@pytest.mark.parametrize(
    "body",
    [
        f"while False:\n    Agent = dict\n{CONSTRUCT}\n",
        f"while False:\n    Agent = dict\nelse:\n    {CONSTRUCT}\n",
        f"while False:\n    {CONSTRUCT}\nelse:\n    Agent = dict\n{CONSTRUCT}\n",
    ],
)
def test_false_while_preserves_binding_but_visits_else(tmp_path, body):
    findings = scan(tmp_path, IMPORT + body)
    expected = Kind.FRAMEWORK_USAGE if "else:\n    Agent = dict" in body else Kind.AGENT
    assert len(findings) == 1 and findings[0].kind == expected


def test_false_while_else_construction_remains_detectable(tmp_path):
    findings = scan(tmp_path, IMPORT + f"while False:\n    pass\nelse:\n    {CONSTRUCT}\n")
    assert len(findings) == 1 and findings[0].kind == Kind.AGENT


@pytest.mark.parametrize(
    "body",
    [
        f"while True:\n    break\nelse:\n    {CONSTRUCT}\n",
        f"while True:\n    pass\n{CONSTRUCT}\n",
        f"while True:\n    if False:\n        break\n{CONSTRUCT}\n",
        f"while True:\n    for item in items:\n        break\n{CONSTRUCT}\n",
        f"while True:\n    while True:\n        break\n    else:\n        break\n{CONSTRUCT}\n",
        f"while True:\n    continue\n    break\n{CONSTRUCT}\n",
        f"while True:\n    raise RuntimeError()\n    break\n{CONSTRUCT}\n",
        f"while True:\n    while True:\n        pass\n    break\n{CONSTRUCT}\n",
        f"for Agent in []:\n    {CONSTRUCT}\n",
        f"for Agent in ():\n    {CONSTRUCT}\n",
        f"for Agent in {{}}:\n    {CONSTRUCT}\n",
        f"for Agent in '':\n    {CONSTRUCT}\n",
    ],
)
def test_unreachable_loop_calls_remain_supporting_evidence(tmp_path, body):
    findings = scan(tmp_path, IMPORT + body)
    assert findings and all(f.kind == Kind.FRAMEWORK_USAGE for f in findings)


@pytest.mark.parametrize(
    "body",
    [
        f"while enabled:\n    Agent = dict\n{CONSTRUCT}\n",
        f"for item in items:\n    Agent = dict\n{CONSTRUCT}\n",
        f"for Agent in items:\n    pass\n{CONSTRUCT}\n",
        f"while enabled:\n    Agent = dict\n    break\nelse:\n    from agents import Agent\n{CONSTRUCT}\n",
        f"for item in items:\n    Agent = dict\n    break\nelse:\n    from agents import Agent\n{CONSTRUCT}\n",
        f"while enabled:\n    if condition:\n        Agent = dict\n        break\n    from agents import Agent\n{CONSTRUCT}\n",
        f"for item in items:\n    if condition:\n        Agent = dict\n        continue\n    from agents import Agent\n{CONSTRUCT}\n",
    ],
)
def test_unknown_loop_mutations_cannot_leave_a_proven_factory_binding(tmp_path, body):
    findings = scan(tmp_path, IMPORT + body)
    assert findings and all(f.kind == Kind.FRAMEWORK_USAGE for f in findings)


@pytest.mark.parametrize(
    "body",
    [
        f"while enabled:\n    pass\n{CONSTRUCT}\n",
        f"for item in items:\n    pass\n{CONSTRUCT}\n",
        f"for Agent in []:\n    Agent = dict\nelse:\n    {CONSTRUCT}\n",
        f"while enabled:\n    Agent = dict\nelse:\n    from agents import Agent\n{CONSTRUCT}\n",
        f"for item in items:\n    Agent = dict\nelse:\n    from agents import Agent\n{CONSTRUCT}\n",
        f"while True:\n    {CONSTRUCT}\n    break\n",
        f"while enabled:\n    for item in items:\n        break\nelse:\n    from agents import Agent\n{CONSTRUCT}\n",
        f"while True:\n    for item in []:\n        pass\n    else:\n        break\n{CONSTRUCT}\n",
        f"while True:\n    while False:\n        pass\n    else:\n        break\n{CONSTRUCT}\n",
    ],
)
def test_reachable_loop_or_else_construction_remains_detectable(tmp_path, body):
    findings = scan(tmp_path, IMPORT + body)
    assert len(findings) == 1 and findings[0].kind == Kind.AGENT


@pytest.mark.parametrize(
    "body",
    [
        f"def build():\n    return None\n    {CONSTRUCT}\n",
        f"def build():\n    raise RuntimeError()\n    {CONSTRUCT}\n",
        f"def build():\n    if True:\n        return None\n    {CONSTRUCT}\n",
        f"def build():\n    if enabled:\n        return None\n    else:\n        return None\n    {CONSTRUCT}\n",
        f"while enabled:\n    break\n    {CONSTRUCT}\n",
        f"while enabled:\n    continue\n    {CONSTRUCT}\n",
        f"def build():\n    try:\n        return None\n        {CONSTRUCT}\n    finally:\n        pass\n",
        f"def build():\n    for item in items:\n        pass\n    else:\n        return None\n    {CONSTRUCT}\n",
        f"def build():\n    while enabled:\n        pass\n    else:\n        return None\n    {CONSTRUCT}\n",
    ],
)
def test_calls_after_explicit_block_transfer_are_not_construction(tmp_path, body):
    findings = scan(tmp_path, IMPORT + body)
    assert findings and all(f.kind == Kind.FRAMEWORK_USAGE for f in findings)


@pytest.mark.parametrize(
    "body",
    [
        f"def build():\n    return {CONSTRUCT}\n",
        f"def build():\n    if enabled:\n        return None\n    return {CONSTRUCT}\n",
        f"def build():\n    if enabled:\n        return None\n    else:\n        from agents import Agent\n    return {CONSTRUCT}\n",
        f"def build():\n    from agents import Agent\n    while False:\n        Agent = dict\n    return {CONSTRUCT}\n",
        f"def build():\n    try:\n        return None\n    finally:\n        {CONSTRUCT}\n",
        f"with manager():\n    raise RuntimeError()\n{CONSTRUCT}\n",
        f"def build():\n    for item in items:\n        break\n    else:\n        return None\n    {CONSTRUCT}\n",
        f"def build():\n    while enabled:\n        break\n    else:\n        return None\n    {CONSTRUCT}\n",
    ],
)
def test_reachable_return_finally_and_possible_suppression_keep_construction(tmp_path, body):
    findings = scan(tmp_path, IMPORT + body)
    assert len(findings) == 1 and findings[0].kind == Kind.AGENT


def test_unreachable_assignment_still_declares_a_python_function_local(tmp_path):
    # Python determines local names lexically. An unreachable assignment must
    # not make an unbound function local resolve to the module's SDK import.
    findings = scan(
        tmp_path, IMPORT + f"def build():\n    while False:\n        Agent = dict\n    return {CONSTRUCT}\n"
    )
    assert findings and all(f.kind == Kind.FRAMEWORK_USAGE for f in findings)


@pytest.mark.parametrize(
    "expression",
    [
        f"[{CONSTRUCT} for item in []]",
        f"{{{CONSTRUCT} for item in ()}}",
        f"{{item: {CONSTRUCT} for item in {{}}}}",
        f"{{{CONSTRUCT}: item for item in ''}}",
        f"({CONSTRUCT} for item in b'')",
        f"[{CONSTRUCT} for item in [] if {CONSTRUCT}]",
        f"[{CONSTRUCT} for item in [1] for other in []]",
        f"[{CONSTRUCT} for item in [1] for other in () if {CONSTRUCT}]",
        f"[{CONSTRUCT} for item in [] for other in [{CONSTRUCT}]]",
        f"[{CONSTRUCT} for item in [1] if False for other in [{CONSTRUCT}]]",
        f"[{CONSTRUCT} for item in [1] if False if {CONSTRUCT}]",
    ],
)
def test_empty_comprehension_paths_do_not_construct_agents(tmp_path, expression):
    findings = scan(tmp_path, IMPORT + f"result = {expression}\n")
    assert findings and all(f.kind == Kind.FRAMEWORK_USAGE for f in findings)
    assert all(f.metadata["agent_indicators"] == 0 for f in findings)


@pytest.mark.parametrize("condition", ["False", "0", "None", "''", "[]", "()", "{}"])
@pytest.mark.parametrize(
    "template",
    [
        "[CONSTRUCT for item in [1] if CONDITION]",
        "{CONSTRUCT for item in [1] if CONDITION}",
        "{item: CONSTRUCT for item in [1] if CONDITION}",
        "(CONSTRUCT for item in [1] if CONDITION)",
    ],
)
def test_false_comprehension_filters_do_not_construct_agents(tmp_path, template, condition):
    expression = template.replace("CONSTRUCT", CONSTRUCT).replace("CONDITION", condition)
    findings = scan(tmp_path, IMPORT + f"result = {expression}\n")
    assert findings and all(f.kind == Kind.FRAMEWORK_USAGE for f in findings)


@pytest.mark.parametrize(
    "expression",
    [
        f"[{CONSTRUCT} for item in [1]]",
        f"{{{CONSTRUCT} for item in [1]}}",
        f"{{item: {CONSTRUCT} for item in [1]}}",
        f"({CONSTRUCT} for item in [1])",
        f"[{CONSTRUCT} for item in inputs]",
        f"[{CONSTRUCT} for item in range(0)]",
        f"[{CONSTRUCT} for item in [*inputs]]",
        f"[{CONSTRUCT} for item in {{**inputs}}]",
        f"[{CONSTRUCT} for item in [] + []]",
        f"[{CONSTRUCT} for item in [1] if enabled]",
        f"[{CONSTRUCT} for item in [1] if True]",
        f"[{CONSTRUCT} for item in [1] if [*inputs]]",
        f"[None for Agent in [{CONSTRUCT}] if False]",
        f"(None for Agent in [{CONSTRUCT}] if False)",
        f"[None for item in [1] if {CONSTRUCT} if False]",
        f"[None for item in [1] if {CONSTRUCT} for other in []]",
        f"[None for item in [1] for other in [{CONSTRUCT}] if False]",
    ],
)
def test_potential_comprehension_and_evaluated_prefix_calls_remain_detectable(tmp_path, expression):
    # As with a function definition, a generator body is potential static
    # construction evidence. Finding it does not assert the generator was run.
    findings = scan(tmp_path, IMPORT + f"result = {expression}\n")
    assert len(findings) == 1 and findings[0].kind == Kind.AGENT


@pytest.mark.parametrize(
    "body",
    [
        f"[Agent for Agent in []]\n{CONSTRUCT}\n",
        f"[{CONSTRUCT} for Agent in [dict]]\n{CONSTRUCT}\n",
        f"[{CONSTRUCT} for item in []]\n{CONSTRUCT}\n",
        f"[{CONSTRUCT} for item in [1] if False]\n{CONSTRUCT}\n",
    ],
)
def test_comprehension_locals_and_early_exit_preserve_enclosing_imports(tmp_path, body):
    findings = scan(tmp_path, IMPORT + body)
    assert len(findings) == 1 and findings[0].kind == Kind.AGENT


@pytest.mark.parametrize(
    "expression",
    [
        f"[{CONSTRUCT} for item in [1] if {CONSTRUCT} for Agent in builders]",
        f"[item for item in [1] for Agent in [{CONSTRUCT}]]",
        f"({CONSTRUCT} for item in [1] if {CONSTRUCT} for Agent in builders)",
    ],
)
def test_later_comprehension_target_is_local_in_earlier_filters_and_iterables(tmp_path, expression):
    findings = scan(tmp_path, IMPORT + f"result = {expression}\n")
    assert findings and all(f.kind == Kind.FRAMEWORK_USAGE for f in findings)


@pytest.mark.parametrize(
    "expression",
    [
        f"[{CONSTRUCT} async for item in []]",
        f"({CONSTRUCT} async for item in [])",
        f"[{CONSTRUCT} async for item in stream]",
    ],
)
def test_async_comprehension_does_not_assume_synchronous_iterability(tmp_path, expression):
    findings = scan(tmp_path, IMPORT + f"async def build():\n    return {expression}\n")
    assert len(findings) == 1 and findings[0].kind == Kind.AGENT


def test_false_async_comprehension_filter_removes_result_construction(tmp_path):
    findings = scan(
        tmp_path,
        IMPORT + f"async def build():\n    return [{CONSTRUCT} async for item in stream if False]\n",
    )
    assert findings and all(f.kind == Kind.FRAMEWORK_USAGE for f in findings)
