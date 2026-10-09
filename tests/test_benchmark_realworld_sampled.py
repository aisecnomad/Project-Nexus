"""Tests for the real-world benchmark: the labelling oracle, its registry, and scoring helpers."""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import pytest

from tools.benchmark.realworld import frames, oracle

REGISTRY = Path(oracle.__file__).parent / "registry" / "ai_registry.json"
MANIFEST = Path(oracle.__file__).parent / "manifest.jsonl"


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/github.com/team/repo",
        "https://evil.example/?next=https://github.com/team/repo",
        "https://evil.example/gitlab.com/team/repo",
        "https://evil.example/?next=https://gitlab.com/team/repo",
        "https://notgithub.com/team/repo",
        "https://github.com.evil.example/team/repo",
        "https://gitlab.com.evil.example/team/repo",
        "https://github.com@evil.example/team/repo",
        "https://evil.example@github.com/team/repo",
        "https://github.com:8443/team/repo",
        "https://gitlab.com/group/../repo",
        "https://github.com/team/%2e%2e",
        "https://gitlab.com/group/repo\\other",
        "https://github.com/team/repo\n",
        "file://github.com/team/repo",
    ],
)
def test_candidate_urls_require_an_exact_allowed_host(url):
    assert frames.canonical(url, "test") is None


@pytest.mark.parametrize(
    "url, expected",
    [
        ("https://github.com/team/repo.git", "https://github.com/team/repo"),
        ("git+https://github.com/team/repo.git", "https://github.com/team/repo"),
        ("git@github.com:team/repo.git", "https://github.com/team/repo"),
        ("ssh://git@github.com/team/repo.git", "https://github.com/team/repo"),
        ("github.com/team/repo", "https://github.com/team/repo"),
        ("https://GITHUB.COM/team/repo/tree/main", "https://github.com/team/repo"),
        ("https://gitlab.com/group/sub/repo.git", "https://gitlab.com/group/sub/repo"),
        ("https://gitlab.com/group/sub/repo/-/tree/main", "https://gitlab.com/group/sub/repo"),
    ],
)
def test_candidate_urls_preserve_supported_repository_forms(url, expected):
    candidate = frames.canonical(url, "test")
    assert candidate is not None and candidate.url == expected


def test_go_candidates_validate_hosts_and_ignore_non_string_paths(tmp_path, monkeypatch):
    http = frames.Http(tmp_path / "cache")
    paths = [
        "github.com/team/agent/v2",
        "gitlab.com/group/repo",
        "evil.example/github.com/team/fake-agent",
        "github.com.evil.example/team/fake-agent",
        "evil.example/gitlab.com/group/fake-agent",
        {"bad": "shape"},
    ]
    raw = "\n".join(json.dumps({"Path": path}) for path in paths).encode()
    monkeypatch.setattr(http, "get", lambda *args, **kwargs: raw)
    ai, other = frames.go_candidates(http, 7, 1, "2026-01-01", "2026-02-01")
    assert {c.url for c in [*ai, *other]} == {
        "https://github.com/team/agent",
        "https://gitlab.com/group/repo",
    }


@pytest.fixture(scope="module")
def index() -> oracle.Index:
    return oracle.load_index(REGISTRY)


def make_repo(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return root


def label(root: Path, index: oracle.Index, files: dict[str, str]) -> dict[str, object]:
    return oracle.label_repo(make_repo(root, files), index)


def labels(result: dict[str, object]) -> dict[str, object]:
    out = result["labels"]
    assert isinstance(out, dict)
    return out


def test_python_import_is_parsed_from_the_ast_not_from_comments(tmp_path: Path, index: oracle.Index) -> None:
    result = label(
        tmp_path,
        index,
        {
            "app/main.py": "from langchain_openai import ChatOpenAI\nllm = ChatOpenAI()\n",
            "app/other.py": "# import anthropic\nx = '''import openai'''\n",
        },
    )
    assert labels(result)["state"] == "positive"
    assert labels(result)["agent_strict"] is True
    assert result["techs"] == ["langchain"]
    paths = {e["path"] for e in result["evidence"]}  # type: ignore[attr-defined]
    assert paths == {"app/main.py"}


def test_dev_only_dependency_is_not_a_clean_positive(tmp_path: Path, index: oracle.Index) -> None:
    result = label(tmp_path, index, {"package.json": json.dumps({"devDependencies": {"openai": "^4"}})})
    state = labels(result)
    assert state["state"] == "ambiguous"
    assert state["ai_loose"] is True
    assert state["ai_strict"] is False


def test_runtime_dependency_is_a_dep_only_positive(tmp_path: Path, index: oracle.Index) -> None:
    result = label(tmp_path, index, {"requirements.txt": "openai==1.3.0\nrequests\n"})
    state = labels(result)
    assert state["state"] == "positive"
    assert state["dep_only"] is True
    assert state["llm_strict"] is True
    assert state["agent_strict"] is False


def test_requirements_files_are_not_mistaken_for_documentation(tmp_path: Path, index: oracle.Index) -> None:
    result = label(tmp_path, index, {"requirements.txt": "anthropic\n"})
    assert result["evidence"][0]["ctx"] == "src"  # type: ignore[index]


def test_dev_requirements_and_test_directories_count_as_tests(tmp_path: Path, index: oracle.Index) -> None:
    result = label(
        tmp_path,
        index,
        {"requirements-dev.txt": "openai\n", "tests/test_x.py": "import anthropic\n"},
    )
    assert labels(result)["state"] == "ambiguous"
    assert {e["ctx"] for e in result["evidence"]} == {"test"}  # type: ignore[attr-defined]


def test_mcp_configuration_and_coding_agent_files_are_agent_evidence(
    tmp_path: Path, index: oracle.Index
) -> None:
    result = label(tmp_path, index, {".mcp.json": "{}", "CLAUDE.md": "# notes\n", ".cursor/rules/a.mdc": "x"})
    assert labels(result)["state"] == "positive"
    assert labels(result)["agent_strict"] is True
    assert {e["tech"] for e in result["evidence"]} == {"mcp-config", "claude-code", "cursor"}  # type: ignore[attr-defined]


def test_symlinked_agent_instructions_still_count_by_name(tmp_path: Path, index: oracle.Index) -> None:
    make_repo(tmp_path, {"AGENTS.md": "rules\n"})
    (tmp_path / "CLAUDE.md").symlink_to("AGENTS.md")
    result = oracle.label_repo(tmp_path, index)
    assert {e["tech"] for e in result["evidence"]} == {"agents-md", "claude-code"}
    assert result["inventory"]["symlinks"] == 1


def test_agents_md_is_case_sensitive(tmp_path: Path, index: oracle.Index) -> None:
    result = label(tmp_path, index, {"docs/agents.md": "monitoring agents\n", "agents.md": "x"})
    assert labels(result)["state"] == "negative"


def test_generic_import_names_need_a_matching_dependency(tmp_path: Path, index: oracle.Index) -> None:
    local = label(tmp_path / "a", index, {"agents/__init__.py": "", "main.py": "from agents import Agent\n"})
    assert labels(local)["state"] == "negative"
    declared = label(
        tmp_path / "b",
        index,
        {"requirements.txt": "openai-agents\n", "main.py": "from agents import Agent\n"},
    )
    assert labels(declared)["agent_strict"] is True
    mcp_local = label(tmp_path / "c", index, {"mcp/server.py": "import mcp\n"})
    assert labels(mcp_local)["state"] == "negative"
    mcp_declared = label(
        tmp_path / "d", index, {"requirements.txt": "mcp\n", "s.py": "from mcp.server import Server\n"}
    )
    assert {e["kind"] for e in mcp_declared["evidence"]} == {"dep", "import"}  # type: ignore[attr-defined]


def test_prose_and_lexical_collisions_stay_negative(tmp_path: Path, index: oracle.Index) -> None:
    result = label(
        tmp_path,
        index,
        {
            "README.md": "import openai\nWe use goose for DB migrations; claude.ai is unrelated; GPTBot is blocked.\n",
            "cmd/main.go": 'package main\nimport (\n\t"github.com/pressly/goose/v3"\n\t"database/sql"\n)\n',
            "notes.txt": "OPENAI_API_KEY=sk-not-real\n",
        },
    )
    assert labels(result)["state"] == "negative"


def test_weak_evidence_alone_is_ambiguous(tmp_path: Path, index: oracle.Index) -> None:
    result = label(tmp_path, index, {".env.example": "OPENAI_API_KEY=\n"})
    state = labels(result)
    assert state["state"] == "ambiguous"
    assert state["weak_only"] is True
    assert result["evidence"][0]["detail"] == "OPENAI_API_KEY"  # type: ignore[index]


def test_classical_ml_is_a_clean_negative(tmp_path: Path, index: oracle.Index) -> None:
    result = label(
        tmp_path, index, {"train.py": "import sklearn\nimport torch\n", "requirements.txt": "scikit-learn\n"}
    )
    state = labels(result)
    assert state["state"] == "negative"
    assert state["ml_present"] is True


def test_adjacent_tooling_is_ambiguous_not_negative(tmp_path: Path, index: oracle.Index) -> None:
    result = label(tmp_path, index, {"requirements.txt": "chromadb\n", "app.py": "import chromadb\n"})
    assert labels(result)["state"] == "ambiguous"
    assert labels(result)["adjacent_only"] is True


def test_notebook_pip_install_and_imports_are_notebook_evidence(tmp_path: Path, index: oracle.Index) -> None:
    nb = {"cells": [{"cell_type": "code", "source": ["%pip install openai\n", "import openai\n"]}]}
    result = label(tmp_path, index, {"demo.ipynb": json.dumps(nb)})
    assert labels(result)["state"] == "positive"
    assert {e["ctx"] for e in result["evidence"]} == {"notebook"}  # type: ignore[attr-defined]
    assert labels(result)["ai_core"] is False


def test_ai_libraries_are_flagged_by_their_own_project_name(tmp_path: Path, index: oracle.Index) -> None:
    py = label(
        tmp_path / "py",
        index,
        {"pyproject.toml": '[project]\nname = "langchain-foo"\ndependencies = ["openai"]\n'},
    )
    assert labels(py)["role"] == "ai-library"
    js = label(
        tmp_path / "js",
        index,
        {"package.json": json.dumps({"name": "@langchain/foo", "dependencies": {"openai": "1"}})},
    )
    assert labels(js)["role"] == "ai-library"
    app = label(
        tmp_path / "app",
        index,
        {"package.json": json.dumps({"name": "my-app", "dependencies": {"openai": "1"}})},
    )
    assert labels(app)["role"] == "consumer"


def test_workflow_exports_and_ci_agents_are_content_evidence(tmp_path: Path, index: oracle.Index) -> None:
    n8n = label(
        tmp_path / "n8n", index, {"flows/a.json": '{"nodes":[{"type":"@n8n/n8n-nodes-langchain.agent"}]}'}
    )
    assert labels(n8n)["agent_strict"] is True
    ci = label(
        tmp_path / "ci",
        index,
        {".github/workflows/x.yml": "steps:\n  - uses: anthropics/claude-code-action@v1\n"},
    )
    assert labels(ci)["agent_strict"] is True


def test_go_rust_java_and_csharp_imports(tmp_path: Path, index: oracle.Index) -> None:
    result = label(
        tmp_path,
        index,
        {
            "main.go": 'package main\nimport (\n\topenai "github.com/sashabaranov/go-openai"\n)\n',
            "Cargo.toml": '[package]\nname = "x"\n[dependencies]\nrig-core = "0.1"\n',
            "src/lib.rs": "use rig::completion::Prompt;\n",
            "A.java": "import dev.langchain4j.model.openai.OpenAiChatModel;\n",
            "B.cs": "using Microsoft.SemanticKernel;\n",
        },
    )
    techs = {e["tech"] for e in result["evidence"]}  # type: ignore[attr-defined]
    assert {"openai", "rust-agent-misc", "langchain4j", "semantic-kernel"} <= techs


def test_vendored_directories_are_ignored(tmp_path: Path, index: oracle.Index) -> None:
    result = label(
        tmp_path, index, {"node_modules/openai/index.js": "import 'openai'", "vendor/x.py": "import openai"}
    )
    assert labels(result)["state"] == "negative"


def test_evidence_is_capped_and_never_stores_values(tmp_path: Path, index: oracle.Index) -> None:
    files = {f"src/m{i}.py": "import openai\n" for i in range(20)}
    files[".env"] = "OPENAI_API_KEY=sk-secret-value-123\n"
    result = label(tmp_path, index, files)
    imports = [e for e in result["evidence"] if e["kind"] == "import"]  # type: ignore[attr-defined]
    assert len(imports) == oracle.MAX_EVIDENCE_PER_KEY
    assert "sk-secret-value-123" not in json.dumps(result)


def test_unparseable_files_do_not_abort_labelling(tmp_path: Path, index: oracle.Index) -> None:
    result = label(
        tmp_path,
        index,
        {
            "py2.py": "print 'x'\nimport openai\n",
            "bad.json": "{",
            "package.json": "not json",
            "b.bin": "x\x00y",
        },
    )
    assert labels(result)["state"] == "positive"


def test_oracle_is_independent_of_shadowscan_and_the_tools_under_test() -> None:
    source = Path(oracle.__file__).read_text(encoding="utf-8")
    roots = {m.split(".")[0] for m in re.findall(r"(?m)^\s*(?:from|import)\s+([\w.]+)", source)}
    # Standard library only: no ShadowScan, no benchmark helpers, no third-party package.
    assert roots <= set(sys.stdlib_module_names)
    assert "shadowscan" not in roots


def test_registry_is_internally_consistent(index: oracle.Index) -> None:
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    ids = [t["id"] for t in registry["technologies"]]
    assert len(ids) == len(set(ids))
    known_tiers = {t for tiers in registry["classes"].values() for t in tiers}
    for tech in registry["technologies"]:
        assert tech["tier"] in known_tiers
    for rule in [*registry["path_rules"], *registry["content_markers"]]:
        assert rule["tier"] in known_tiers
        for key in ("regex", "path_regex"):
            if key in rule:
                re.compile(rule[key])
    assert index.pypi_dist("LangChain_OpenAI") == "langchain"
    assert index.pypi_dist("langgraph-prebuilt") == "langgraph"
    assert index.npm_pkg("@langchain/langgraph") == "langgraph"
    assert index.py_import("google.genai.types") == ("google-genai", False)
    assert index.py_import("numpy") is None


# --- scoring ----------------------------------------------------------------

from tools.benchmark.realworld import score  # noqa: E402


def test_wilson_interval_matches_known_values() -> None:
    assert score.wilson(0, 0) is None
    p, lo, hi = score.wilson(50, 100) or (0, 0, 0)
    assert (round(p, 3), round(lo, 3), round(hi, 3)) == (0.5, 0.404, 0.596)
    assert (score.wilson(0, 10) or (0, 1, 1))[1] == 0.0
    assert (score.wilson(10, 10) or (0, 0, 0))[2] == pytest.approx(1.0)


def test_mcnemar_exact_is_two_sided_and_symmetric() -> None:
    assert score.mcnemar_exact(0, 0) == 1.0
    assert score.mcnemar_exact(5, 0) == pytest.approx(2 / 32)
    assert score.mcnemar_exact(3, 7) == score.mcnemar_exact(7, 3)
    assert score.mcnemar_exact(5, 5) == 1.0


def test_holm_adjustment_is_monotone_and_capped() -> None:
    adjusted = score.holm({"a": 0.01, "b": 0.04, "c": 0.03})
    assert adjusted == {"a": pytest.approx(0.03), "c": pytest.approx(0.06), "b": pytest.approx(0.06)}
    assert score.holm({"x": 0.9, "y": 0.8}) == {"x": 1.0, "y": 1.0}  # 2 * 0.8 caps at 1, then monotone
    assert max(score.holm({"x": 0.9, "y": 0.8}).values()) <= 1.0


def test_error_policy_never_turns_a_crash_into_a_clean_result() -> None:
    ok = {"status": "ok", "detected": True}
    error = {"status": "error", "detected": False}
    assert score.decide(ok, True) == "TP" and score.decide(ok, False) == "FP"
    assert score.decide({"status": "ok", "detected": False}, True) == "FN"
    assert score.decide(error, True) == "ERR_POS"
    assert score.decide(error, False) == "ERR_NEG"
    assert score.decide(error, False, errors="clean") == "TN"
    assert score.decide(None, True) == "MISSING"


def test_error_on_a_negative_is_excluded_from_specificity() -> None:
    total, per_owner = score.tally(
        [("o1", "TN"), ("o1", "ERR_NEG"), ("o2", "FP"), ("o2", "ERR_POS"), ("o3", "TP")]
    )
    assert (total.tn, total.fp, total.fn, total.tp, total.err_pos, total.err_neg) == (1, 1, 1, 1, 1, 1)
    assert (
        score.summarize(total)["specificity"][0] == 0.5
    )  # 1 of (1 TN + 1 FP): the errored negative is not counted
    assert set(per_owner) == {"o1", "o2", "o3"}


def make_label(state: str, **flags: object) -> dict[str, object]:
    base = {"state": state, "ai_strict": False, "ai_core": False, "ai_loose": False, "dep_only": False,
            "role": "consumer", "agent_strict": False, "app_strict": False, "llm_strict": False,
            "devcfg_only": False, "weak_only": False, "adjacent_only": False}  # fmt: skip
    return {"labels": {**base, **flags}, "techs": [], "evidence": []}


def test_truth_variants_and_exclusions() -> None:
    clean_pos = make_label("positive", ai_strict=True, ai_core=True, ai_loose=True)
    example_only = make_label("positive", ai_strict=True, ai_loose=True)
    dep_only = make_label("positive", ai_strict=True, ai_core=True, ai_loose=True, dep_only=True)
    test_only = make_label("ambiguous", ai_loose=True)
    weak_only = make_label("ambiguous")
    negative = make_label("negative")
    library = make_label("positive", ai_strict=True, ai_core=True, ai_loose=True, role="ai-library")
    assert score.truth(clean_pos, "strict") is True and score.truth(negative, "strict") is False
    assert score.truth(example_only, "core") is None and score.truth(example_only, "strict") is True
    assert score.truth(dep_only, "no-dep-only") is None and score.truth(dep_only, "strict") is True
    assert score.truth(test_only, "strict") is None and score.truth(test_only, "loose") is True
    assert score.truth(weak_only, "strict") is None and score.truth(weak_only, "loose") is None
    assert score.truth(library, "strict") is None and score.truth(library, "with-libraries") is True
    assert score.truth(weak_only, "strict", {"ai": True}) is True  # an adjudicated override wins


def test_cluster_bootstrap_is_deterministic() -> None:
    per_owner = {f"o{i}": score.Counts(tp=i % 3, fp=i % 2, fn=1, tn=2) for i in range(12)}
    first = score.cluster_bootstrap(per_owner, reps=200, seed=1)
    second = score.cluster_bootstrap(per_owner, reps=200, seed=1)
    assert first == second
    lo, hi = first["f1"] or (0, 0)
    assert 0 <= lo <= hi <= 1


def test_prevalence_ppv_falls_as_prevalence_falls() -> None:
    ppv = score.prevalence_ppv((0.9, 0.85, 0.95), (0.95, 0.9, 0.98))
    assert ppv["20%"][0] > ppv["5%"][0] > ppv["1%"][0]
    assert ppv["1%"][0] == pytest.approx(0.9 * 0.01 / (0.9 * 0.01 + 0.05 * 0.99))


def test_score_end_to_end_on_a_tiny_corpus() -> None:
    manifest = [
        {
            "id": f"r{i}",
            "frame": "pypi-ai" if i < 2 else "pypi-other",
            "owner": f"o{i}",
            "host": "github.com",
            "bytes": 10,
        }
        for i in range(4)
    ]
    labels = {
        "r0": {**make_label("positive", ai_strict=True, ai_core=True, ai_loose=True, agent_strict=True),
               "inventory": {"primary_language": "python"}},
        "r1": {**make_label("positive", ai_strict=True, ai_core=True, ai_loose=True), "inventory": {"primary_language": "go"}},
        "r2": {**make_label("negative"), "inventory": {"primary_language": "python"}},
        "r3": {**make_label("negative"), "inventory": {"primary_language": "python"}},
    }  # fmt: skip

    def row(rid: str, detected: bool, status: str = "ok") -> dict[str, object]:
        return {
            "id": rid,
            "status": status,
            "detected": detected,
            "agentic": detected,
            "variants": {},
            "seconds": 1.0,
            "names": [],
        }

    results = {
        "good": {r: row(r, r in {"r0", "r1"}) for r in labels},
        "noisy": {
            "r0": row("r0", True),
            "r1": row("r1", False),
            "r2": row("r2", True),
            "r3": row("r3", False, "error"),
        },
    }
    summary = score.score(manifest, labels, results, reps=50)
    good = summary["tools"]["good"]["scopes"]["all"]["primary"]
    noisy = summary["tools"]["noisy"]["scopes"]["all"]["primary"]
    assert summary["tools"]["good"]["scopes"]["probability"]["primary"] == good  # both frames are probability
    assert (good["tp"], good["fp"], good["fn"], good["tn"]) == (2, 0, 0, 2)
    assert (noisy["tp"], noisy["fp"], noisy["fn"], noisy["tn"], noisy["errors_on_negatives"]) == (
        1,
        1,
        1,
        0,
        1,
    )
    assert summary["pairwise"]["all"]["good|noisy"]["a_right_b_wrong"] == 2
    assert summary["unique_finds"]["good"] == ["r1"]
    assert summary["sets"]["primary"] == {"repositories": 4, "positives": 2, "negatives": 2}


def test_claude_plugins_raw_mcp_servers_and_directory_manifests_are_agent_evidence(
    tmp_path: Path, index: oracle.Index
) -> None:
    plugin = label(tmp_path / "plugin", index, {".claude-plugin/plugin.json": "{}", "go.mod": "module x\n"})
    assert labels(plugin)["state"] == "positive"
    raw = label(
        tmp_path / "raw",
        index,
        {
            "index.js": "if (req.method === 'tools/list') { return tools }\n",
            "package.json": json.dumps({"name": "s"}),
        },
    )
    assert labels(raw)["agent_strict"] is True
    listing = label(tmp_path / "glama", index, {"glama.json": "{}", "index.js": "console.log(1)"})
    assert labels(listing)["agent_strict"] is True
    prose = label(tmp_path / "prose", index, {"notes.js": "// the tools list is long\nconst a = 1;\n"})
    assert labels(prose)["state"] == "negative"


def test_developer_tooling_config_is_separated_from_application_integration(
    tmp_path: Path, index: oracle.Index
) -> None:
    config_only = labels(
        label(tmp_path / "cfg", index, {"AGENTS.md": "x", "CLAUDE.md": "y", "a.py": "print(1)"})
    )
    assert config_only["state"] == "positive"
    assert config_only["app_strict"] is False and config_only["devcfg_only"] is True
    app = labels(label(tmp_path / "app", index, {"requirements.txt": "openai\n", "CLAUDE.md": "y"}))
    assert app["app_strict"] is True and app["devcfg_only"] is False
    mcp_cfg = labels(label(tmp_path / "mcp", index, {".mcp.json": "{}"}))
    assert mcp_cfg["devcfg_only"] is True  # a project MCP config wires developer tooling


def test_app_only_variant_excludes_config_only_repositories() -> None:
    config_only = make_label("positive", ai_strict=True, ai_core=True, ai_loose=True, app_strict=False)
    app = make_label("positive", ai_strict=True, ai_core=True, ai_loose=True, app_strict=True)
    assert score.truth(config_only, "app-only") is None
    assert score.truth(config_only, "strict") is True
    assert score.truth(app, "app-only") is True
    assert score.truth(make_label("negative"), "app-only") is False


# --- adjudication ------------------------------------------------------------

from tools.benchmark.realworld import adjudicate  # noqa: E402


def test_kappa_matches_a_hand_computed_value() -> None:
    pairs = [(True, True), (False, False), (True, False), (False, False)]
    assert adjudicate.cohen_kappa(pairs) == pytest.approx(0.5)
    assert adjudicate.cohen_kappa([]) is None
    assert adjudicate.cohen_kappa([(True, True), (True, True)]) == 1.0


def test_cards_redact_secret_looking_text_and_truncate() -> None:
    line = (
        'key = "sk-'
        + "abcdefghijklmnopqrstuvwxyz0123"
        + '" token=ghp_'
        + "abcdefghijklmnopqrstuvwxyz0123456789 "
        + "x" * 300
    )
    cleaned = adjudicate.clean_line(line)
    assert "sk-abc" not in cleaned and "ghp_abc" not in cleaned and "<redacted>" in cleaned
    assert len(cleaned) <= 180


def test_rulings_parse_from_fenced_replies() -> None:
    reply = 'Here you go:\n```json\n[{"card": "A001", "ai": "yes"}, {"note": "x"}]\n```'
    assert adjudicate.parse_rulings(reply) == [{"card": "A001", "ai": "yes"}]
    assert adjudicate.parse_rulings("no json at all") == []


def test_merge_uses_the_third_ruling_only_on_disagreement() -> None:
    key = {"A001": "r1", "A002": "r2", "A003": "r3", "A004": "r4"}
    first = [
        {"card": "A001", "ai": "yes"},
        {"card": "A002", "ai": "yes"},
        {"card": "A003", "ai": "unclear"},
        {"card": "A004", "ai": "no"},
    ]
    second = [
        {"card": "A001", "ai": "yes"},
        {"card": "A002", "ai": "no"},
        {"card": "A003", "ai": "no"},
        {"card": "A004", "ai": "no"},
    ]
    third = [{"card": "A002", "ai": "no"}]
    merged = adjudicate.merge(key, first, second, third)
    by_id = {r["id"]: r["ai"] for r in merged["rows"]}
    assert by_id == {"r1": True, "r2": False, "r3": None, "r4": False}
    assert merged["pairs"] == 3


def test_selection_covers_ambiguous_flagged_negatives_and_missed_positives() -> None:
    def lab(state: str) -> dict[str, object]:
        return {"labels": {"state": state, "role": "consumer"}}

    manifest = [{"id": f"r{i}"} for i in range(6)]
    labels = {"r0": lab("ambiguous"), "r1": lab("negative"), "r2": lab("negative"), "r3": lab("positive"),
              "r4": lab("positive"), "r5": lab("negative")}  # fmt: skip

    def res(*detected: bool) -> dict[str, dict[str, object]]:
        return {f"r{i}": {"status": "ok", "detected": d} for i, d in enumerate(detected)}

    results = {
        "t1": res(False, True, False, False, True, False),
        "t2": res(False, False, False, False, True, False),
        "t3": res(False, False, False, False, True, False),
        "grep-any": res(True, True, True, True, True, True),
    }
    chosen = adjudicate.select(manifest, labels, results)["repositories"]
    assert chosen["r0"]["reason"] == "ambiguous"
    assert chosen["r1"]["reason"] == "negative-flagged-by-a-tool"
    assert chosen["r3"]["reason"] == "positive-missed-by-most"
    assert "r2" not in chosen or chosen["r2"]["reason"] == "random-sample-of-agreement"


def test_partial_scans_are_errors_in_the_headline_and_detections_in_the_sensitivity_policy() -> None:
    partial = {"status": "ok", "detected": True, "partial": True}
    assert score.decide(partial, True) == "ERR_POS"  # strict is the default: an incomplete scan is no result
    assert score.decide(partial, False) == "ERR_NEG"
    assert score.decide(partial, True, partial="detected") == "TP"
    assert (
        score.decide(partial, False, partial="detected") == "FP"
    )  # a finding is a false alarm on a negative
    assert score.decide({"status": "ok", "detected": True}, True) == "TP"


def _escaping_links(root: Path) -> list[str]:
    """Symlinks under ``root`` whose physical resolution leaves it."""
    real = os.path.realpath(root)
    bad = []
    for current, dirs, files in os.walk(root, followlinks=False):
        for name in [*dirs, *files]:
            path = Path(current) / name
            if path.is_symlink():
                resolved = os.path.realpath(path)
                if not (resolved == real or resolved.startswith(real + os.sep)):
                    bad.append(str(path.relative_to(root)))
    return bad


def test_symlink_neutraliser_defeats_chained_links(tmp_path: Path) -> None:
    from tools.benchmark.realworld.fetch import _neutralize_symlinks

    outside = tmp_path / "outside-secret.txt"
    outside.write_text("host data")
    root = tmp_path / "snap"
    (root / "sub").mkdir(parents=True)
    (root / "src").mkdir()
    (root / "AGENTS.md").write_text("rules")
    (root / "CLAUDE.md").symlink_to("AGENTS.md")  # legitimate, must survive
    (root / "docs").mkdir()
    (root / "docs" / "code").symlink_to("../src")  # a sibling directory, must survive
    # the reviewer's attack: a lexical check accepts both, the kernel resolves l1 above the snapshot
    (root / "sub" / "l2").symlink_to("..")
    (root / "l1").symlink_to("sub/l2/../..")
    (root / "deep").symlink_to("sub/l2/../../../outside-secret.txt")
    (root / "direct").symlink_to("../outside-secret.txt")
    (root / "absolute").symlink_to(str(outside))
    (root / "loop").symlink_to(".")
    total, neutralized = _neutralize_symlinks(root)
    assert total == 8
    assert _escaping_links(root) == []
    assert (root / "CLAUDE.md").is_symlink() and (root / "docs" / "code").is_symlink()
    for name in ("l1", "deep", "direct", "absolute", "loop"):
        assert not (root / name).is_symlink(), name
    assert "removed by the benchmark" in (root / "direct").read_text()
    assert neutralized == 6  # the five above and sub/l2 (it points at an ancestor)
    assert outside.read_text() == "host data"


def test_symlink_neutraliser_is_a_fixpoint(tmp_path: Path) -> None:
    from tools.benchmark.realworld.fetch import _neutralize_symlinks

    root = tmp_path / "snap"
    (root / "a" / "b").mkdir(parents=True)
    (root / "a" / "b" / "up").symlink_to("../../..")  # climbs out of the snapshot
    (root / "ok").symlink_to("a/b")
    (root / "via").symlink_to("ok/up")  # resolves through the first link
    _neutralize_symlinks(root)
    assert _escaping_links(root) == []
    assert _neutralize_symlinks(root)[1] == 0  # a second pass changes nothing


# --- frames, overrides, variants and exclusions -----------------------------------------------------


def test_every_sampled_frame_has_a_class_and_only_random_draws_are_probability() -> None:
    manifest_frames = {
        json.loads(line)["frame"] for line in MANIFEST.read_text().splitlines() if line.strip()
    }
    classes = {f: score.frame_class(f) for f in manifest_frames}
    assert set(classes.values()) <= set(score.CLASS_ORDER)
    assert (
        classes["npm-ai"] == "search"
        and classes["npm-other"] == "search"
        and classes["gitlab-ai"] == "search"
    )
    assert classes["list-mcp"] == "list" and classes["hard-negative"] == "challenge"
    assert {f for f, c in classes.items() if c == "probability"} == {
        "pypi-ai", "pypi-other", "go-ai", "go-random", "gitlab-random",
    }  # fmt: skip


def test_adjudicated_overrides_decide_the_label_and_unclear_rulings_exclude_the_repository() -> None:
    weak = make_label("ambiguous")
    assert score.truth(weak, "strict", {"ai": True, "app": True}) is True
    assert score.truth(weak, "strict", {"ai": False}) is False
    assert score.truth(weak, "strict", {"ai": None}) is None  # the adjudicators could not decide
    config_only = make_label("positive", ai_strict=True, app_strict=False)
    assert score.truth(config_only, "app-only", {"ai": True, "app": True}) is True
    assert score.truth(config_only, "app-only", {"ai": True, "app": False}) is None
    assert score.truth(make_label("negative"), "app-only", {"ai": False, "app": True}) is False


def test_shared_vocabulary_variant_drops_positives_that_rest_on_shadowscan_only_technologies() -> None:
    both = {**make_label("positive", ai_strict=True), "techs": ["openai", "letta"]}
    only = {**make_label("positive", ai_strict=True), "techs": ["letta"]}
    shared = frozenset({"openai"})
    assert score.truth(both, "shared-vocab", None, shared) is True
    assert score.truth(only, "shared-vocab", None, shared) is None
    assert score.truth(only, "strict", None, shared) is True
    assert score.truth(make_label("negative"), "shared-vocab", None, shared) is False
    assert score.truth(both, "shared-vocab", None, None) is None  # no vocabulary file: nothing is shared


def test_excluded_repositories_and_configuration_variants_stay_out_of_every_comparison() -> None:
    manifest = [
        {"id": f"r{i}", "frame": "pypi-ai", "owner": f"o{i}", "host": "github.com", "bytes": 10}
        for i in range(3)
    ]
    labels = {
        f"r{i}": {**make_label("positive", ai_strict=True, ai_core=True, ai_loose=True),
                  "inventory": {"primary_language": "python"}}
        for i in range(3)
    }  # fmt: skip
    ok = {"status": "ok", "detected": True, "agentic": True, "variants": {}, "seconds": 1.0, "names": []}
    results = {
        name: {rid: {"id": rid, **ok} for rid in labels}
        for name in ("a", "shadowscan", "shadowscan-bigfiles")
    }
    summary = score.score(manifest, labels, results, reps=20, excluded=frozenset({"r2"}))
    assert summary["sets"]["primary"]["repositories"] == 2 and summary["sets"]["excluded"] == ["r2"]
    names = {n for key in summary["pairwise"]["all"] for n in key.split("|")}
    assert "shadowscan-bigfiles" not in names and "shadowscan" in names
    assert "shadowscan-bigfiles" not in summary["unique_finds"]
    assert summary["tools"]["shadowscan-bigfiles"]["variant_of"] == "shadowscan"


def test_adapter_registry_matches_the_scorer_and_the_oracle_tiers() -> None:
    from tools.benchmark.realworld import adapters

    names = [a.name for a in adapters.ADAPTERS]
    assert len(names) == len(set(names))
    assert set(score.CONFIG_VARIANTS) <= set(names) and set(names) >= score.BASELINES
    registry = json.loads(REGISTRY.read_text())
    wanted = {t: c for c, tiers in registry["classes"].items() for t in tiers if c in {"agent", "llm"}}
    assert wanted == score.AI_TIER_CLASSES  # score.py hard-codes the tier classes


def test_published_rows_hold_no_raw_output_and_no_key_shaped_names() -> None:
    from tools.benchmark.realworld import adapters
    from tools.benchmark.realworld.sandbox import RunResult

    leak = "Traceback (most recent call last):\nKeyError: 'sk-" + "abcdefghijklmnopqrstuvwxyz0123456789'\n"
    out = adapters.fail(RunResult(1, "", leak, 1.0, False), "scan failed")
    assert "sk-" not in out.note and "abcdef" not in out.note
    assert "exit 1" in out.note and "KeyError" in out.note
    timed = adapters.fail(RunResult(124, "", leak, 600.0, True), "no report")
    assert timed.note.startswith("no report: timeout")
    names = adapters.clean_names(
        ["OpenAI", "sk-abcdefghijklmnop", "a=b", "x" * 80, "ghp_" + "a" * 30, "ab-" * 30, "  spaced   name "]
    )
    assert names == ["OpenAI", ("ab-" * 30)[:60], "spaced name"]  # long hyphenated names stay, long tokens go
    assert adapters.Outcome("error", note="n" * 500).to_json()["note"] == "n" * 300


def test_cisco_noise_types_are_the_ml_lifecycle_group_of_its_own_enumeration() -> None:
    from tools.benchmark.realworld.adapters import CiscoAIBOM

    assert {"dataset", "training_run", "hyperparameter", "model_artifact", "ml_pipeline"} <= CiscoAIBOM.NOISE
    assert not CiscoAIBOM.NOISE & {"model", "agent", "tool", "mcp_server", "llm_endpoint", "dependency"}


def test_vet_counts_crewai_signatures_that_carry_no_ai_tag() -> None:
    from tools.benchmark.realworld.adapters import SafeDepVet

    assert SafeDepVet.AI_TAGS & {"agent", "crewai"} and "ai" in SafeDepVet.AI_TAGS
    assert not SafeDepVet.AI_TAGS & {"cryptography", "capability", "paas", "pubsub"}


def test_vocabulary_matching_is_whole_token() -> None:
    from tools.benchmark.realworld import vocab_overlap

    text = "supports langgraph-supervisor and the openai-agents sdk; autogenstudio"
    assert vocab_overlap.mentioned("langgraph-supervisor", text)
    assert vocab_overlap.mentioned("openai-agents", text)
    assert not vocab_overlap.mentioned("autogen", text)  # a prefix of another word is not a mention
    assert vocab_overlap.names_of({"id": "x", "name": "X", "tier": "t", "pypi": ["xlib", "xlib-"]}) == [
        "xlib"
    ]


def test_contamination_search_finds_repositories_named_in_tool_files() -> None:
    from tools.benchmark.realworld import contamination

    rows = [
        {
            "id": "a",
            "owner": "Acme",
            "host": "github.com",
            "url": "https://github.com/Acme/widget-agent",
            "frame": "f",
        },
        {
            "id": "b",
            "owner": "Other",
            "host": "github.com",
            "url": "https://github.com/Other/thing",
            "frame": "f",
        },
    ]
    texts = {"packs/x.yaml": "see https://github.com/acme/widget-agent for docs", "readme.md": "nothing"}
    found = contamination.find(rows, texts)
    assert list(found) == ["a"] and found["a"]["files"] == ["packs/x.yaml"]


def test_freeze_detects_a_changed_file(tmp_path: Path) -> None:
    from tools.benchmark.realworld import freeze

    record = tmp_path / "freeze.json"
    freeze.main(["--write", str(record)])
    assert freeze.check(record) == []
    recorded = json.loads(record.read_text())
    recorded["files"]["oracle.py"] = "0" * 64
    record.write_text(json.dumps(recorded))
    assert freeze.check(record) == ["oracle.py: changed since the freeze"]
    first = freeze.tree_sha256(tmp_path)
    (tmp_path / "a.py").write_text("x = 1\n")
    assert freeze.tree_sha256(tmp_path) != first


# --- sandbox -----------------------------------------------------------------------------------------


def test_jail_script_exposes_only_listed_paths(tmp_path: Path) -> None:
    from tools.benchmark.realworld.sandbox import Session

    session = object.__new__(Session)  # no root, cgroups or copy needed to look at the script
    session.jail, session.root, session.expose = tmp_path / "jail", tmp_path / "run", (tmp_path / "tools",)
    script = session.jail_script()
    assert "pivot_root" in script and "umount -l /.oldroot" in script
    assert str(tmp_path / "tools") in script and str(tmp_path / "run") in script
    for host_path in ("/home", "/root", "/var", "/mnt"):
        assert host_path not in script.replace(str(tmp_path), "")


def _can_sandbox() -> bool:
    import pwd
    import shutil

    try:
        pwd.getpwnam("rwb")
    except KeyError:
        return False
    return os.geteuid() == 0 and all(shutil.which(c) for c in ("unshare", "setpriv", "prlimit", "pivot_root"))


@pytest.mark.skipif(not _can_sandbox(), reason="needs root, util-linux and a user named rwb")
def test_sandbox_hides_the_host_and_the_network(tmp_path: Path) -> None:
    from tools.benchmark.realworld.sandbox import Sandbox

    scratch = tmp_path / "scratch"
    box = Sandbox(scratch, timeout=60)
    assert box.selftest() == []
    outside = tmp_path / "secret.txt"
    outside.write_text("host data")
    outside.chmod(0o644)
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "a.txt").write_text("x")
    with box.session(tree) as session:
        probe = (
            f"import os; print(os.path.exists({str(outside)!r})); print(os.listdir({str(session.tree)!r}))"
        )
        result = session.run(["python3", "-I", "-c", probe])
    assert result.code == 0 and result.stdout.splitlines()[0] == "False"
    assert "a.txt" in result.stdout
    assert not list(scratch.iterdir())  # every session directory and jail mount point is removed


def _evidence(kind: str, tier: str, ctx: str = "src") -> dict[str, object]:
    return {"kind": kind, "tier": tier, "ctx": ctx, "path": "x", "line": 1, "detail": "d", "tech": "t"}


def test_evidence_families_vocabulary_split_and_ambiguous_table_in_the_summary() -> None:
    def labelled(state: str, techs: list[str], evidence: list[dict[str, object]], **flags: object) -> dict:
        base = make_label(state, **flags)
        return {**base, "techs": techs, "evidence": evidence, "inventory": {"primary_language": "python"}}

    labels = {
        "r0": labelled("positive", ["openai"], [_evidence("dep", "llm_sdk"), _evidence("import", "llm_sdk")],
                       ai_strict=True, ai_core=True, ai_loose=True, llm_strict=True),
        "r1": labelled("positive", ["letta"], [_evidence("import", "agent_framework")],
                       ai_strict=True, ai_core=True, ai_loose=True, agent_strict=True),
        "r2": labelled("positive", ["claude-code"], [_evidence("path", "coding_agent")],
                       ai_strict=True, ai_core=True, ai_loose=True, agent_strict=True, devcfg_only=True),
        "r3": labelled("negative", [], []),
        "r4": labelled("ambiguous", [], [_evidence("import", "llm_sdk", "test")], ai_loose=True),
    }  # fmt: skip
    manifest = [
        {"id": rid, "frame": "pypi-ai", "owner": f"o{rid}", "host": "github.com", "bytes": 1}
        for rid in labels
    ]

    def row(rid: str, detected: bool) -> dict[str, object]:
        return {
            "id": rid,
            "status": "ok",
            "detected": detected,
            "agentic": detected,
            "variants": {},
            "seconds": 1.0,
        }

    # "vocab" detects only what other tools' vocabularies cover; "wide" detects everything
    results = {
        "vocab": {rid: row(rid, rid in {"r0", "r2"}) for rid in labels},
        "wide": {rid: row(rid, rid != "r3" and rid != "r4") for rid in labels},
    }
    summary = score.score(manifest, labels, results, reps=20, shared=frozenset({"openai", "claude-code"}))
    assert summary["sets"]["vocabulary_split"] == {"shared": 2, "shadowscan-only-or-unmentioned": 1}
    by_vocab = summary["tools"]["vocab"]["recall_by_vocabulary"]
    assert by_vocab["shared"][0] == 1.0 and by_vocab["shadowscan-only-or-unmentioned"][0] == 0.0
    ev = summary["tools"]["wide"]["by_evidence"]
    assert (
        ev["dep"][0] == 1.0
        and ev["path"][0] == 1.0
        and ev["agent-type"][0] == 1.0
        and ev["llm-only"][0] == 1.0
    )
    assert summary["tools"]["vocab"]["devcfg_only_recall"][0] == 1.0
    assert summary["ambiguous"]["r4"]["tools"] == {"vocab": "-", "wide": "-"}
    assert summary["ambiguous"]["r4"]["kind"] == "tests-or-docs-only"
    assert summary["tools"]["vocab"]["decisions"]["misses"] == ["r1"]
    variant = summary["tools"]["wide"]["scopes"]["all"]["label_variants"]["shared-vocab"]
    assert (variant["tp"], variant["fn"]) == (2, 0)  # r1 rests on a technology no other tool mentions
