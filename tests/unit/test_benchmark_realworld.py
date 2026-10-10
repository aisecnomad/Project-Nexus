"""Unit tests for the real-world shadow-AI benchmark: guards, labels, manifest rules and scoring."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tools.benchmark import adapters as synthetic_adapters
from tools.benchmark.adapters import copy_checkout, set_run_as
from tools.benchmark_realworld.adapters import TOOL_PINS
from tools.benchmark_realworld.cases import (
    LABELS,
    ManifestError,
    home_view_label,
    redact,
    sanitize_note,
    validate_manifest,
)
from tools.benchmark_realworld.score import agreement, by_stratum, cohen_kappa, paired, scored

ROOT = Path(__file__).resolve().parents[2]
INSTALL = ROOT / "tools" / "benchmark_realworld" / "install_tools.sh"


def _entry(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": "rw-01-example",
        "repo": "owner/example",
        "url": "https://github.com/owner/example",
        "dir": "owner/example",
        "sha": "a" * 40,
        "license": "MIT",
        "stratum": "ai-app",
        "label": "agent",
        "confidence": "high",
        "labels": {"A": "agent", "B": "agent"},
        "evidence": ["src/agent.py: tool loop"],
    }
    base.update(overrides)
    return base


def test_copy_checkout_skips_git_and_symbolic_links(tmp_path: Path) -> None:
    src = tmp_path / "src"
    (src / ".git").mkdir(parents=True)
    (src / ".git" / "config").write_text("[core]\n", encoding="utf-8")
    (src / "app").mkdir()
    (src / "app" / "main.py").write_text("print('ok')\n", encoding="utf-8")
    secret = tmp_path / "outside-secret.txt"
    secret.write_text("host file\n", encoding="utf-8")
    (src / "link.txt").symlink_to(secret)
    (src / "linked-dir").symlink_to(tmp_path)

    dst = tmp_path / "dst"
    counts = copy_checkout(src, dst)

    assert (dst / "app" / "main.py").read_text(encoding="utf-8") == "print('ok')\n"
    assert not (dst / ".git").exists()
    assert not (dst / "link.txt").exists()
    assert not (dst / "linked-dir").exists()
    assert counts["files"] == 1
    assert counts["skipped_links"] == 2


def test_home_view_label_follows_protocol_paths(tmp_path: Path) -> None:
    assert home_view_label(tmp_path) == "none"

    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "mcp.json").write_text("", encoding="utf-8")
    assert home_view_label(tmp_path) == "none", "an empty file does not count"

    (tmp_path / ".cursor" / "mcp.json").write_text('{"mcpServers": {}}', encoding="utf-8")
    assert home_view_label(tmp_path) == "client"

    other = tmp_path / "other"
    other.mkdir()
    (other / ".claude").mkdir()  # an empty agents folder would count only when it has entries
    (other / ".claude" / "agents").mkdir()
    assert home_view_label(other) == "none"

    linked = tmp_path / "linked"
    linked.mkdir()
    (linked / ".claude.json").symlink_to(tmp_path / ".cursor" / "mcp.json")
    assert home_view_label(linked) == "none", "symbolic links are never followed"


def test_project_scope_files_are_not_home_view_positives(tmp_path: Path) -> None:
    (tmp_path / ".mcp.json").write_text('{"mcpServers": {}}', encoding="utf-8")
    assert home_view_label(tmp_path) == "none"


def test_manifest_accepts_a_valid_entry() -> None:
    assert len(validate_manifest({"repos": [_entry()]})) == 1


@pytest.mark.parametrize(
    "override",
    [
        {"sha": "not-a-sha"},
        {"label": "maybe"},
        {"stratum": "unknown"},
        {"dir": "/abs/path"},
        {"dir": "../escape"},
        {"labels": {"A": "agent"}},
        {"labels": {"A": "agent", "B": "magic"}},
        {"license": ""},
    ],
)
def test_manifest_rejects_bad_entries(override: dict[str, object]) -> None:
    with pytest.raises(ManifestError):
        validate_manifest({"repos": [_entry(**override)]})


def test_manifest_rejects_duplicate_ids() -> None:
    with pytest.raises(ManifestError, match="duplicate"):
        validate_manifest({"repos": [_entry(), _entry()]})


def test_redaction_removes_secret_shapes_and_paths() -> None:
    text = "key sk-abcdefghijklmnopqrstuv in /opt/rwbench/work/tool-123/repo"
    cleaned = sanitize_note(text, paths=("/opt/rwbench/work/tool-123",))
    assert "sk-abcdef" not in cleaned
    assert "[redacted]" in cleaned
    assert "/opt/rwbench/work/tool-123" not in cleaned
    assert redact("AKIA1234567890ABCDEF") == "[redacted]"
    assert len(sanitize_note("x" * 500)) == 200


def test_run_as_prefix_is_opt_in() -> None:
    try:
        set_run_as(("setpriv", "--reuid=65534"))
        assert synthetic_adapters._RUN_AS == ("setpriv", "--reuid=65534")
    finally:
        set_run_as(())
    assert synthetic_adapters._RUN_AS == ()


def test_install_script_matches_the_pins_in_code() -> None:
    script = INSTALL.read_text(encoding="utf-8")
    for name, version in TOOL_PINS.items():
        if name == "safedep-vet":
            assert f"github.com/safedep/vet@{version}" in script
            continue
        pattern = re.compile(rf"venv \w+ '?{re.escape(name)}(\[[^\]']+\])?=={re.escape(version)}'?")
        assert pattern.search(script), f"{name}=={version} is not pinned in install_tools.sh"


def test_cohen_kappa_known_values() -> None:
    assert cohen_kappa([("agent", "agent"), ("none", "none")]) == 1.0
    # 3 of 4 agree, with balanced marginals: observed 0.75, expected 0.5, kappa 0.5
    pairs = [("agent", "agent"), ("agent", "agent"), ("none", "none"), ("agent", "none")]
    assert cohen_kappa(pairs) == pytest.approx(0.5)
    assert cohen_kappa([]) is None


def test_agreement_lists_disagreements() -> None:
    repos = [
        {"id": "rw-01-a", "labels": {"A": "agent", "B": "agent"}},
        {"id": "rw-02-b", "labels": {"A": "llm", "B": "none"}},
    ]
    result = agreement(repos)
    assert result["disagreements"] == ["rw-02-b"]
    assert result["exact_agreement"] == 0.5


def _row(
    case: str, surface: str, family: str, label: str, status: str = "ok", detected: bool = False
) -> dict:
    return {
        "case": case,
        "repo": case.split(":")[0],
        "surface": surface,
        "family": family,
        "label": label,
        "status": status,
        "detected": detected,
        "items": 1 if detected else 0,
        "agentic": detected,
        "seconds": 0.1,
        "note": "",
    }


def test_scoring_excludes_ambiguous_and_unsupported_rows() -> None:
    rows = [
        _row("rw-01:repo", "repo", "ai-app", "agent", detected=True),
        _row("rw-02:repo", "repo", "hard-negative", "none", detected=True),
        _row("rw-03:repo", "repo", "ai-app", "ambiguous", detected=True),
        _row("rw-04:repo", "repo", "ordinary", "none", status="n/a"),
    ]
    kept = scored(rows, "repo")
    assert [r["case"] for r in kept] == ["rw-01:repo", "rw-02:repo"]
    assert [r["case"] for r in scored(rows, "repo", exclude_families=("hard-negative",))] == ["rw-01:repo"]


def test_stratum_counts_separate_detections_from_false_positives() -> None:
    rows = [
        _row("rw-01:repo", "repo", "ai-app", "agent", detected=True),
        _row("rw-02:repo", "repo", "ai-app", "llm", detected=False),
        _row("rw-03:repo", "repo", "hard-negative", "none", detected=True),
        _row("rw-04:repo", "repo", "ordinary", "none", detected=False),
    ]
    counts = by_stratum(rows)
    assert counts["ai-app"] == {"positives": 2, "detected_positives": 1, "negatives": 0, "false_positives": 0}
    assert counts["hard-negative"]["false_positives"] == 1
    assert counts["ordinary"]["negatives"] == 1


def test_paired_test_uses_only_shared_supported_cases() -> None:
    shadowscan = [_row("rw-01:repo", "repo", "ai-app", "agent", detected=True)]
    other = [
        _row("rw-01:repo", "repo", "ai-app", "agent", detected=False),
        _row("rw-02:repo", "repo", "ai-app", "llm", status="n/a"),
    ]
    result = paired({"shadowscan": shadowscan, "other": other}, "repo")
    assert result["other"]["n"] == 1
    assert result["other"]["reference_only_right"] == 1
    assert result["other"]["tool_only_right"] == 0


def test_label_vocabulary_is_closed() -> None:
    assert frozenset({"agent", "llm", "none", "ambiguous"}) == LABELS
