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
