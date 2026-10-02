"""Confidence groups correlated evidence before the noisy-OR combination.

Repeated matches of one signal describe one observation. Outside the code
surface, evidence without an explicit ``confidence_group`` forms a group by
signal, so repeated matches cannot raise the score above their strongest
weight; distinct signals still reinforce each other.
"""

from __future__ import annotations

import json

import pytest

from shadowscan.engine import merge
from shadowscan.models import Evidence, Finding, Kind, Likelihood, Surface

SYSTEM_PROMPTS = (
    "You are a helpful assistant for invoice questions.",
    "You are an autonomous agent that files tickets.",
    "You are a friendly bot for HR questions.",
)


def _finding(*evidence: Evidence) -> Finding:
    finding = Finding(
        surface=Surface.LOWCODE,
        connector="lowcode.n8n",
        kind=Kind.WORKFLOW,
        title="n8n workflow: prompts",
        resource="n8n:workflow:1",
        resource_type="workflow",
        evidence=list(evidence),
    )
    finding.recompute_confidence()
    return finding


def test_repeated_matches_of_one_signal_count_once():
    repeated = _finding(
        *(Evidence("code:heuristic.system-prompt", f"prompt {i}", weight=0.3) for i in range(3))
    )
    assert repeated.confidence == 0.3 and repeated.likelihood == Likelihood.POSSIBLE


def test_strongest_repeated_match_represents_its_signal():
    finding = _finding(
        Evidence("scope:policy.data-access-scopes", "files:read", weight=0.2),
        Evidence("scope:policy.data-access-scopes", "mail:read", weight=0.4),
        Evidence("slack:app", "installed app", weight=0.2),
    )
    assert finding.confidence == round(1 - 0.6 * 0.8, 3)


def test_distinct_signals_still_reinforce_each_other():
    finding = _finding(*(Evidence(f"signal:{i}", "independent", weight=0.3) for i in range(3)))
    assert finding.confidence == round(1 - 0.7**3, 3) and finding.likelihood == Likelihood.LIKELY


def test_explicit_confidence_group_takes_precedence_over_the_signal():
    finding = _finding(
        # One group across different signals of a technology...
        Evidence("dependency:framework.x", "dep", weight=0.9, attributes={"confidence_group": "framework.x"}),
        Evidence("import:framework.x", "import", weight=0.8, attributes={"confidence_group": "framework.x"}),
        # ...and distinct groups for one signal that a connector judged independent.
        Evidence("env:provider.y", "a", weight=0.5, attributes={"confidence_group": "a"}),
        Evidence("env:provider.y", "b", weight=0.5, attributes={"confidence_group": "b"}),
    )
    assert finding.confidence == round(1 - 0.1 * 0.5 * 0.5, 3)


def test_single_file_code_findings_keep_distinct_patterns_as_corroboration():
    # A Dify app export matching three different structural patterns is
    # stronger evidence than one pattern; source analysis sets explicit groups
    # where code matches are correlated.
    patterns = ("mode: agent-chat", "kind: app", "agent_mode: enabled")
    export = Finding(
        surface=Surface.CODE,
        connector="code.filesystem",
        kind=Kind.WORKFLOW,
        title="Exported AI workflow (Dify): app.yml",
        resource="repo/app.yml",
        resource_type="workflow-export",
        evidence=[Evidence("code:platform.dify", pattern, weight=0.6) for pattern in patterns],
    )
    export.recompute_confidence()
    assert export.confidence == round(1 - 0.4**3, 3) and export.likelihood == Likelihood.STRONG


def test_merging_duplicate_observations_does_not_inflate_a_repeated_signal():
    first = _finding(Evidence("gateway:api-key", "export a: 10 requests", weight=0.35))
    second = _finding(Evidence("gateway:api-key", "export b: 12 requests", weight=0.35))
    merged = merge([first, second])[0]
    assert len(merged.evidence) == 2 and merged.confidence == 0.35


@pytest.mark.parametrize("prompts", [1, 3])
def test_n8n_system_prompts_are_one_supporting_signal(tmp_path, run_connector, prompts):
    workflow = {
        "id": "wf-1",
        "name": "Prompt library",
        "nodes": [
            {"name": f"Set {i}", "type": "n8n-nodes-base.set", "parameters": {"value": prompt}}
            for i, prompt in enumerate(SYSTEM_PROMPTS[:prompts])
        ],
    }
    export = tmp_path / "workflows.json"
    export.write_text(json.dumps([workflow]))
    findings, ctx = run_connector("lowcode.n8n", input=str(export))
    assert not ctx.stats.incomplete and len(findings) == 1
    assert len(findings[0].evidence) == prompts
    assert findings[0].confidence == 0.3 and findings[0].likelihood == Likelihood.POSSIBLE
