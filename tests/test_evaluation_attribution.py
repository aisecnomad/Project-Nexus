"""Explicit finding-kind and attribution labels catch errors binary targets miss."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.evaluation.evaluate import (
    DEFAULT_CORPUS,
    CorpusError,
    _exact_finding_set,
    _finding_checks,
    evaluate,
    load_corpus,
)


def _sample(tmp_path: Path, assertions: dict) -> Path:
    path = tmp_path / "labels.json"
    path.write_text(
        json.dumps(
            {
                "schema": 1,
                "metadata": {"name": "test", "type": "synthetic", "provenance": "unit test"},
                "cases": [
                    {
                        "id": "langgraph-provider",
                        "family": "agent",
                        "description": "LangGraph agent using an OpenAI model integration",
                        "files": {
                            "agent.py": (
                                "from langchain_openai import ChatOpenAI\n"
                                "from langgraph.prebuilt import create_react_agent\n"
                                'agent = create_react_agent(ChatOpenAI(model="m"), tools=[])\n'
                            )
                        },
                        "target": {"kind": "agent", "signature": "provider.openai"},
                        "present": True,
                        "assertions": assertions,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_binary_tp_cannot_hide_wrong_kind_product_or_provider(tmp_path: Path) -> None:
    path = _sample(
        tmp_path,
        {
            "expected_findings": [
                {"kind": "agent", "product_signature": "framework.langgraph"},
                {"kind": "agent", "product_signature": "framework.crewai"},
                {"kind": "agent", "provider_signature": "provider.anthropic"},
                {"kind": "workflow"},
            ],
            "forbidden_findings": [
                {"kind": "agent", "product_signature": "framework.langchain"},
                {
                    "kind": "agent",
                    "product_signature": "framework.langchain",
                    "provider_signature": "provider.openai",
                },
                {"kind": "infra"},
            ],
        },
    )
    report = evaluate(path)
    row = report["cases"][0]
    assert report["metrics"]["all"]["tp"] == 1
    assert row["predicted"] and not row["correct"] and not report["passed"]
    assert row["findings"][0]["frameworks"] == ["framework.langchain", "framework.langgraph"]
    assert row["findings"][0]["model_providers"] == ["provider.openai"]
    assert len(row["assertion_failures"]) == 5
    assert report["finding_assertions"]["expected_findings"] == {"checks": 4, "passed": 1, "failed": 3}
    assert report["finding_assertions"]["forbidden_findings"] == {"checks": 3, "passed": 1, "failed": 2}
    assert report["finding_assertions"]["cases_with_checks"] == 1


def test_attribution_must_be_on_the_same_finding_and_in_its_proper_field(tmp_path: Path) -> None:
    _, cases, _ = load_corpus(
        _sample(
            tmp_path,
            {
                "expected_findings": [
                    {
                        "kind": "agent",
                        "product_signature": "framework.langgraph",
                        "provider_signature": "provider.openai",
                    }
                ]
            },
        )
    )
    split = [
        {"kind": "agent", "frameworks": ["framework.langgraph"], "model_providers": []},
        {"kind": "agent", "frameworks": [], "model_providers": ["provider.openai"]},
    ]
    assert not _finding_checks(cases[0], split)[0]["passed"]
    swapped = [
        {"kind": "agent", "frameworks": ["provider.openai"], "model_providers": ["framework.langgraph"]}
    ]
    assert not _finding_checks(cases[0], swapped)[0]["passed"]
    correct = [
        {"kind": "agent", "frameworks": ["framework.langgraph"], "model_providers": ["provider.openai"]}
    ]
    assert _finding_checks(cases[0], correct)[0]["passed"]


def test_capability_selector_is_exact_and_cannot_borrow_from_another_finding(tmp_path: Path) -> None:
    _, cases, _ = load_corpus(
        _sample(
            tmp_path,
            {
                "expected_findings": [
                    {"kind": "agent", "product_signature": "framework.langgraph", "capabilities": []},
                    {
                        "kind": "agent",
                        "product_signature": "framework.crewai",
                        "capabilities": ["tool-use", "multi-agent"],
                    },
                ],
                "forbidden_findings": [{"kind": "agent", "capabilities": ["code-exec"]}],
            },
        )
    )
    findings = [
        {"kind": "agent", "frameworks": ["framework.langgraph"], "capabilities": []},
        {"kind": "agent", "frameworks": ["framework.crewai"], "capabilities": ["multi-agent", "tool-use"]},
    ]
    assert all(check["passed"] for check in _finding_checks(cases[0], findings))
    findings[0]["capabilities"] = ["code-exec"]
    findings[1]["capabilities"] = []
    assert not any(check["passed"] for check in _finding_checks(cases[0], findings))
    findings[0].pop("capabilities")
    assert not _finding_checks(cases[0], findings)[0]["passed"]  # Missing evidence is not an empty set.
    assert not _finding_checks(cases[0], findings)[2][
        "passed"
    ]  # A forbidden selector cannot treat it as absent.


def test_binary_tp_cannot_hide_incorrect_capabilities(tmp_path: Path) -> None:
    baseline = evaluate(_sample(tmp_path, {}))
    capabilities = baseline["cases"][0]["findings"][0]["capabilities"]
    assert isinstance(capabilities, list)
    report = evaluate(
        _sample(
            tmp_path,
            {
                "expected_findings": [
                    {"kind": "agent", "capabilities": sorted([*capabilities, "unsupported-test-capability"])}
                ]
            },
        )
    )
    assert report["metrics"]["all"]["tp"] == 1
    assert report["cases"][0]["predicted"]
    assert not report["cases"][0]["correct"] and not report["passed"]
    assert report["finding_assertions"]["capabilities"] == {"checks": 1, "passed": 0, "failed": 1}


def test_exact_finding_set_catches_unlisted_product_and_extra_findings(tmp_path: Path) -> None:
    path = _sample(
        tmp_path,
        {
            "expected_findings": [{"kind": "agent", "product_signature": "framework.langgraph"}],
            "exact_findings": [
                {
                    "kind": "agent",
                    "product_signatures": ["framework.langgraph"],
                    "provider_signatures": ["provider.openai"],
                }
            ],
        },
    )
    report = evaluate(path)
    row = report["cases"][0]
    assert row["finding_checks"][0]["passed"] is True
    assert row["exact_finding_set"]["passed"] is False
    assert report["finding_assertions"]["exact_finding_sets"] == {"checks": 1, "passed": 0, "failed": 1}
    assert row["assertion_failures"][0].startswith("exact findings differ")

    _, cases, _ = load_corpus(path)
    output = [
        {"kind": "agent", "frameworks": ["framework.langgraph"], "model_providers": ["provider.openai"]}
    ]
    exact = _exact_finding_set(cases[0], output)
    assert exact is not None and exact["passed"] is True
    output.append({"kind": "infra", "frameworks": [], "model_providers": []})
    exact = _exact_finding_set(cases[0], output)
    assert exact is not None and exact["passed"] is False


@pytest.mark.parametrize(
    "assertions",
    [
        {"expected_findings": {}},
        {"expected_findings": [{"kind": "agent"}] * 21},
        {"expected_findings": [{"kind": "unknown"}]},
        {"expected_findings": [{"kind": "agent", "extra": "field"}]},
        {"expected_findings": [{"kind": "agent", "provider_signature": "framework.langgraph"}]},
        {"expected_findings": [{"kind": "agent", "product_signature": "provider.openai"}]},
        {"expected_findings": [{"kind": "agent", "product_signature": None}]},
        {"forbidden_findings": [{"kind": "agent", "provider_signature": None}]},
        {"expected_findings": [{"kind": "agent"}, {"kind": "agent"}]},
        {"expected_findings": [{"kind": "agent", "capabilities": None}]},
        {"expected_findings": [{"kind": "agent", "capabilities": "tool-use"}]},
        {"expected_findings": [{"kind": "agent", "capabilities": [True]}]},
        {"expected_findings": [{"kind": "agent", "capabilities": ["Tool Use"]}]},
        {"expected_findings": [{"kind": "agent", "capabilities": ["tool-use"] * 2}]},
        {"expected_findings": [{"kind": "agent", "capabilities": [f"cap-{i}" for i in range(21)]}]},
        {
            "expected_findings": [
                {"kind": "agent", "capabilities": ["tool-use", "multi-agent"]},
                {"kind": "agent", "capabilities": ["multi-agent", "tool-use"]},
            ]
        },
        {
            "expected_findings": [{"kind": "agent", "capabilities": []}],
            "forbidden_findings": [{"kind": "agent"}],
        },
        {"expected_findings": [{"kind": "agent"}], "forbidden_findings": [{"kind": "agent"}]},
        {
            "expected_findings": [{"kind": "agent", "product_signature": "framework.langgraph"}],
            "forbidden_findings": [{"kind": "agent"}],
        },
        {"exact_findings": {}},
        {"exact_findings": [{"kind": "agent", "product_signatures": []}]},
        {
            "exact_findings": [
                {"kind": "agent", "product_signatures": ["provider.openai"], "provider_signatures": []}
            ]
        },
        {
            "exact_findings": [
                {"kind": "agent", "product_signatures": [], "provider_signatures": ["framework.langgraph"]}
            ]
        },
        {
            "exact_findings": [
                {
                    "kind": "agent",
                    "product_signatures": [],
                    "provider_signatures": ["provider.openai", "provider.openai"],
                }
            ]
        },
    ],
)
def test_finding_selector_schema_rejects_invalid_or_contradictory_labels(
    tmp_path: Path, assertions: dict
) -> None:
    with pytest.raises(CorpusError):
        load_corpus(_sample(tmp_path, assertions))


def test_bundled_authored_attribution_gaps_are_visible_without_relabeling_independent_corpus() -> None:
    authored = evaluate(DEFAULT_CORPUS.with_name("attribution_corpus.json"))
    assert authored["passed"]
    assert authored["metrics"]["all"] | {"tp": 12, "fp": 0, "fn": 0, "tn": 5} == authored["metrics"]["all"]
    assert authored["finding_assertions"]["provider_signature"]["checks"] >= 4
    assert authored["finding_assertions"]["forbidden_findings"] == {
        "checks": 13,
        "passed": 12,
        "failed": 1,
    }
    assert authored["finding_assertions"]["exact_finding_sets"] == {
        "checks": 17,
        "passed": 16,
        "failed": 1,
    }
    assert authored["finding_assertions"]["capabilities"] == {"checks": 13, "passed": 13, "failed": 0}
    # The one remaining gap is waived by the corpus's bounded policy; a passing
    # flagged case fails the run so the waiver cannot outlive the defect.
    assert set(authored["known_gaps"]["failing"]) == {"n8n-compose-workflow"}
    assert authored["known_gaps"]["passing"] == []
    assert all(not case.assertions.get("expected_findings") for case in load_corpus(DEFAULT_CORPUS)[1])
    assert all(
        not case.assertions.get("expected_findings")
        for case in load_corpus(DEFAULT_CORPUS.with_name("realistic_corpus.json"))[1]
    )
    _, independent, _ = load_corpus(DEFAULT_CORPUS.with_name("independent_corpus.json"))
    assert all(not case.assertions.get("expected_findings") for case in independent)
    assert all(not case.assertions.get("forbidden_findings") for case in independent)
