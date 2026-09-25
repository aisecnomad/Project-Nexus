"""Scanner performance guards: cooperative deadlines, oversize files, budgets and domain prefilters."""

from __future__ import annotations

import fnmatch
import json
import os
import re
import threading
from bisect import bisect_left, bisect_right
from pathlib import Path

import pytest

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors.base import ConnectorContext, ConnectorError
from shadowscan.connectors.code import filesystem as filesystem_module
from shadowscan.connectors.code.filesystem import (
    DEADLINE_MARGIN_MIN_SECONDS,
    DEFAULT_OVERSIZE_SKIP_GLOBS,
    FilesystemConnector,
    deadline_margin,
    scan_timeout_for_size,
)
from shadowscan.engine import Engine
from shadowscan.signatures import SignatureIndex
from shadowscan.signatures.matcher import (
    _HOST_TOKEN_RX,
    language_for_path,
    plain_host_hints,
    required_literal,
    required_literals,
)
from shadowscan.utils.redaction import sanitize_text

REPO = Path(__file__).resolve().parents[2]
LANGCHAIN = "from langchain import agents\n"


# ------------------------------------------------------------ deadlines
def _fake_clock(monkeypatch, *, step: float) -> list[float]:
    """Freeze ``time.monotonic`` and advance it by ``step`` for every file the scanner reads.

    ``filesystem_module.time`` is the ``time`` module itself, so the engine,
    the connector context and the signature matcher all observe the same clock.
    """
    clock = [1000.0]
    monkeypatch.setattr(filesystem_module.time, "monotonic", lambda: clock[0])
    original = filesystem_module.read_text

    def read_text(path, max_bytes, errors=None):
        clock[0] += step
        return original(path, max_bytes, errors)

    monkeypatch.setattr(filesystem_module, "read_text", read_text)
    return clock


def _tree(root: Path, count: int = 10) -> None:
    for number in range(count):
        (root / f"agent_{number}.py").write_text(LANGCHAIN)


def test_cooperative_deadline_returns_partial_findings_with_one_error(tmp_path, index, monkeypatch):
    _tree(tmp_path)
    clock = _fake_clock(monkeypatch, step=1.0)
    # Budget 2 s per tiny file plus a 0.275 s margin: files may start while the
    # clock is at most 1003.225, so four of the ten files are analyzed.
    ctx = ConnectorContext(config={"path": str(tmp_path), "use_git": False}, index=index, deadline=clock[0] + 5.5)
    findings = FilesystemConnector(ctx).run()
    assert ctx.stats.objects_examined == 4
    assert len(ctx.stats.errors) == 1
    assert re.search(r"connector deadline reached after 4 of 10 files under .*; results incomplete", ctx.stats.errors[0])
    assert ctx.stats.incomplete and not ctx.stats.skipped and not ctx.stats.warnings
    assert any("framework.langchain" in finding.frameworks for finding in findings)


def test_engine_keeps_results_returned_before_the_deadline(tmp_path, index, monkeypatch):
    _tree(tmp_path)
    _fake_clock(monkeypatch, step=1.0)
    cfg = ScanConfig(connectors=[ConnectorSpec("code.filesystem", {"path": str(tmp_path), "use_git": False})],
                     connector_timeout_seconds=5.5, parallel=1)
    result = Engine(cfg, index).run()
    assert not result.complete
    stats = result.stats[0]
    assert stats.objects_examined == 4 and not stats.skipped and not stats.cached
    assert len(stats.errors) == 1 and "deadline reached after 4 of 10 files" in stats.errors[0]
    assert not stats.warnings, "an accepted result must not carry the abandoned-worker warning"
    assert any("framework.langchain" in finding.frameworks for finding in result.findings)


def test_root_starting_inside_the_margin_records_the_error_for_every_file(tmp_path, index, monkeypatch):
    _tree(tmp_path, count=3)
    clock = _fake_clock(monkeypatch, step=1.0)
    ctx = ConnectorContext(config={"path": str(tmp_path), "use_git": False}, index=index, deadline=clock[0] + 1.0)
    findings = FilesystemConnector(ctx).run()
    assert not findings and ctx.stats.objects_examined == 0
    assert len(ctx.stats.errors) == 1 and "after 0 of 3 files" in ctx.stats.errors[0]


def test_remaining_count_is_bounded_by_max_files(tmp_path, index, monkeypatch):
    _tree(tmp_path, count=8)
    clock = _fake_clock(monkeypatch, step=1.0)
    ctx = ConnectorContext(config={"path": str(tmp_path), "use_git": False, "max_files": 6}, index=index,
                           deadline=clock[0] + 5.5)
    FilesystemConnector(ctx).run()
    # Counting stops before the walk would record a second, max_files error.
    assert len(ctx.stats.errors) == 1 and "after 4 of at least 6 files" in ctx.stats.errors[0]


def test_cancellation_mid_walk_is_not_reported_per_file(tmp_path, index, monkeypatch):
    _tree(tmp_path)
    cancelled = threading.Event()
    original = filesystem_module.read_text

    def read_text(path, max_bytes, errors=None):
        cancelled.set()
        return original(path, max_bytes, errors)

    monkeypatch.setattr(filesystem_module, "read_text", read_text)
    ctx = ConnectorContext(config={"path": str(tmp_path), "use_git": False}, index=index, cancelled=cancelled)
    FilesystemConnector(ctx).run()
    assert ctx.stats.skipped and ctx.stats.errors == ["connector completion deadline exceeded"]


def test_deadline_margin_is_a_bounded_fraction_of_the_remaining_budget():
    assert deadline_margin(120.0) == pytest.approx(6.0)
    assert deadline_margin(1.0) == DEADLINE_MARGIN_MIN_SECONDS
    assert deadline_margin(-5.0) == DEADLINE_MARGIN_MIN_SECONDS


# ---------------------------------------------------------- file budgets
@pytest.mark.parametrize("base, size, expected", [
    (2.0, 0, 2.0),
    (2.0, 256 * 1024 - 1, 2.0),
    (2.0, 256 * 1024, 4.0),
    (2.0, 971 * 1024, 8.0),
    (2.0, 1_000_000, 8.0),
    (2.0, 5 * 1024 * 1024, 10.0),
    (0.2, 1_000_000, 0.8),
    (20.0, 5 * 1024 * 1024, 20.0),
    (60.0, 10**9, 60.0),
])
def test_scan_timeout_scales_with_file_size_and_is_capped(base, size, expected):
    assert scan_timeout_for_size(base, size) == pytest.approx(expected)


def test_scan_tree_opens_a_size_scaled_budget_per_file(tmp_path, index, monkeypatch):
    (tmp_path / "small.py").write_text(LANGCHAIN)
    (tmp_path / "index.json").write_text(json.dumps({"entries": ["x" * 100] * 3200}))  # about 330 KiB
    recorded: list[float] = []
    original = SignatureIndex.scan_budget

    def scan_budget(self, seconds=2.0):
        recorded.append(seconds)
        return original(self, seconds=seconds)

    monkeypatch.setattr(SignatureIndex, "scan_budget", scan_budget)
    ctx = ConnectorContext(config={"path": str(tmp_path), "use_git": False, "scan_timeout": 1.0}, index=index)
    FilesystemConnector(ctx).run()
    assert not ctx.stats.errors
    assert sorted(recorded)[0] == 1.0 and 2.0 in recorded


# --------------------------------------------------------- oversize files
def _engine_config(tmp_path: Path, **connector) -> ScanConfig:
    config = {"path": str(tmp_path), "use_git": False, "max_file_size": 100, **connector}
    return ScanConfig(connectors=[ConnectorSpec("code.filesystem", config)], parallel=1)


def test_oversize_lockfile_is_a_warning_and_the_scan_stays_complete(tmp_path, index):
    (tmp_path / "agent.py").write_text("from crewai import Agent\n")
    (tmp_path / "yarn.lock").write_text("x" * 200)
    (tmp_path / "poetry.lock").write_text("small")
    (tmp_path / "data.csv").write_text("a,b\n" * 60)
    (tmp_path / "LOGO.PNG").write_bytes(b"\x89PNG" + b"\0" * 200)
    result = Engine(_engine_config(tmp_path), index).run()
    assert result.complete and result.findings
    stats = result.stats[0]
    assert not stats.errors and stats.objects_examined == 1
    named = sorted(warning.split(": ")[1] for warning in stats.warnings)
    assert named == ["LOGO.PNG", "data.csv", "yarn.lock"]
    assert all("over max_file_size" in warning for warning in stats.warnings)


def test_oversize_source_file_is_a_warning_unless_strict_coverage(tmp_path, index):
    (tmp_path / "agent.py").write_text("from crewai import Agent\n")
    (tmp_path / "big.py").write_text("x" * 200)
    result = Engine(_engine_config(tmp_path), index).run()
    assert result.complete and result.findings
    assert not result.stats[0].errors
    assert any("big.py: skipped, file exceeds max_file_size" in warning for warning in result.stats[0].warnings)
    # Enforcement gates opt back into fail-closed coverage.
    strict = Engine(_engine_config(tmp_path, strict_coverage=True), index).run()
    assert not strict.complete and strict.findings
    assert any("big.py: file exceeds max_file_size" in error for error in strict.stats[0].errors)
    assert not strict.stats[0].warnings


def test_oversize_skip_globs_is_configurable_and_validated(tmp_path, index, run_connector):
    (tmp_path / "big.py").write_text("x" * 200)
    (tmp_path / "data.csv").write_text("a,b\n" * 60)
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, max_file_size=100,
                           oversize_skip_globs=["*.PY", "*.csv"])
    assert not ctx.stats.incomplete and not ctx.stats.errors
    assert sorted(warning.split(": ")[1] for warning in ctx.stats.warnings) == ["big.py", "data.csv"]
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, max_file_size=100,
                           oversize_skip_globs=[])
    assert not ctx.stats.incomplete and not ctx.stats.errors and len(ctx.stats.warnings) == 2
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, max_file_size=100,
                           oversize_skip_globs=[], strict_coverage=True)
    assert ctx.stats.incomplete and not ctx.stats.warnings
    assert sorted(error.split(": ")[1] for error in ctx.stats.errors) == ["big.py", "data.csv"]
    with pytest.raises(ConnectorError, match="oversize_skip_globs"):
        FilesystemConnector(ConnectorContext(config={"path": str(tmp_path), "oversize_skip_globs": "*.csv"}, index=index))
    assert "yarn.lock" in DEFAULT_OVERSIZE_SKIP_GLOBS and "*.pyc" in DEFAULT_OVERSIZE_SKIP_GLOBS
    assert "oversize_skip_globs" in FilesystemConnector.config_keys


@pytest.mark.skipif(os.name != "posix", reason="POSIX flock is required for incremental state")
def test_incremental_cache_hits_a_tree_with_an_oversize_lockfile(tmp_path, index, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "agent.py").write_text("from crewai import Agent\n")
    (repo / "yarn.lock").write_text("x" * 4096)
    # A hash budget below the lockfile's size proves its content is never read.
    monkeypatch.setattr("shadowscan.incremental._MAX_HASH_BYTES", 2048)
    cfg = ScanConfig(
        connectors=[ConnectorSpec("code.filesystem", {"path": str(repo), "use_git": False, "max_file_size": 1024})],
        incremental=True, state_dir=str(tmp_path / "state"), parallel=1,
    )
    first = Engine(cfg, index).run()
    assert first.complete and first.findings and not first.stats[0].cached
    assert any("yarn.lock" in warning for warning in first.stats[0].warnings)
    second = Engine(cfg, index).run()
    assert second.complete and second.stats[0].cached and second.stats[0].objects_examined == 0
    assert any("yarn.lock" in warning for warning in second.stats[0].warnings), "warnings are replayed"
    assert [f.to_dict() for f in second.findings] == [f.to_dict() for f in first.findings]
    (repo / "yarn.lock").write_text("y" * 8192)
    third = Engine(cfg, index).run()
    assert third.complete and not third.stats[0].cached


# ------------------------------------------------------- domain prefilter
def _reference_domain_matches(index: SignatureIndex, text: str) -> list[tuple[str, int, str, float, int]]:
    """Every domain value over every token: the naive matcher the prefilter must reproduce."""
    out = []
    seen: set[str] = set()
    newlines = [m.start() for m in re.finditer("\n", text)]
    for m in _HOST_TOKEN_RX.finditer(text):
        host = m.group(0).lower().strip(".")
        if host in seen or len(host) > 253 or "." not in host:
            continue
        seen.add(host)
        labels = host.split(".")
        if len(labels[-1]) < 2 or not labels[-1].isalpha() or any(
            not label or len(label) > 63 or not label[0].isalnum() or not label[-1].isalnum()
            for label in labels
        ):
            continue
        found = list(index._domains.get(host, []))
        found += [(sig, s) for suffix, sig, s in index._domain_suffixes if host.endswith(suffix) or host == suffix.lstrip(".")]
        found += [(sig, s) for rx, sig, s in index._domain_regex if rx.search(host)]
        matched: set[str] = set()
        line = bisect_right(newlines, m.start()) + 1
        for sig, s in found:
            if sig.id in matched:
                continue
            matched.add(sig.id)
            out.append((sig.id, sig.signals.index(s), host, s.weight, line))
    return out


def _corpus_texts() -> list[tuple[str, str]]:
    texts = []
    for path in sorted((REPO / "tests" / "fixtures").rglob("*")):
        if path.is_file():
            raw = path.read_bytes()
            if b"\0" not in raw[:8192]:
                texts.append((str(path.relative_to(REPO)), raw.decode("utf-8", errors="replace")))
    for name in ("corpus.json", "public_corpus.json"):
        raw = (REPO / "tools" / "evaluation" / name).read_text(encoding="utf-8")
        texts.append((name, raw))
        for case in json.loads(raw)["cases"]:
            for filename, content in case.get("files", {}).items():
                texts.append((f"{name}:{case['id']}:{filename}", content))
    return texts


SYNTHETIC_HOSTS = """
https://api.anthropic.com/v1 bedrock-runtime.eu-west-1.amazonaws.com bedrock-agent-runtime.us-east-1.amazonaws.com
acme.openai.azure.com mcp.example.io MCP.Example.IO notmcp.example.io x.dynamics.com crm9.dynamics.com dynamics.com
foo.svc.us-east1.pinecone.io hook.eu1.make.com eu2.make.com integromat.com sub.integromat.com x.retool.com retool.com
api.cloudflare.com notapi.cloudflare.com cloudflare.com bedrock-mantle.us-east-1.api.aws gateway.ai.cloudflare.com
localhost:11434 127.0.0.1:1234 example.com:4000 ..weird..host.com.. a-.b.com -a.b.com trailing.dot.com. -
""" + "x" * 70 + ".com " + "label." * 60 + "com K.dynamics.com ſoo.retool.com api.anthropic.com\n"


def test_prefiltered_domain_matching_equals_the_exhaustive_reference(index):
    texts = _corpus_texts() + [("synthetic", SYNTHETIC_HOSTS)]
    assert len(texts) > 40
    hits = 0
    for name, text in texts:
        with index.scan_budget(seconds=60):
            fast = [(m.signature_id, m.signature.signals.index(m.signal), m.value, m.weight, m.line)
                    for m in index.match_domains_in_text(text)]
        assert fast == _reference_domain_matches(index, text), name
        hits += len(fast)
    assert hits > 20


@pytest.mark.parametrize("host", [
    "localhost:11434", "http://x.retool.com:8443/v1", "foo.bar:x.retool.com", "x.dynamics.com\n.",
    "K.dynamics.com", "acme.openai.azure.com:443", "EU3.make.com", "mcp.example.io",
])
def test_match_domain_with_ports_paths_and_unusual_characters_matches_every_value(index, host):
    h = host.lower().strip().rstrip(".")
    h = h.split("://", 1)[1] if "://" in h else h
    with_port = h.split("/", 1)[0]
    bare = with_port.split(":", 1)[0]
    expected = [(sig.id, sig.signals.index(s)) for sig, s in index._domains.get(bare, [])]
    expected += [(sig.id, sig.signals.index(s)) for suffix, sig, s in index._domain_suffixes
                 if bare.endswith(suffix) or bare == suffix.lstrip(".")]
    expected += [(sig.id, sig.signals.index(s)) for rx, sig, s in index._domain_regex
                 if rx.search(bare) or rx.search(with_port)]
    assert [(m.signature_id, m.signature.signals.index(m.signal)) for m in index.match_domain(host)] == expected


@pytest.mark.parametrize("pattern, expected", [
    (r".*\.dynamics\.com$", (False, "dynamics.com", None)),
    (r".*\.crm[0-9]*\.dynamics\.com$", (False, "dynamics.com", None)),
    (r"^api\.cloudflare\.com$", (False, "cloudflare.com", "api")),
    (r"^mcp\.[a-z0-9-]+\.[a-z]+$", (False, None, "mcp")),
    (r"^(?:eu|us)\d*\.make\.com$", (False, "make.com", None)),
    (r"(?i)^a\.b$", (False, "a.b", None)),
    (r".*\.DYNAMICS\.COM$", (False, "dynamics.com", None)),
    (r".*:11434$", (True, None, None)),
    (r".*:8080/v1$", (True, None, None)),
    (r"foo\.com|bar\.net$", (False, None, None)),
    (r"(?:a|b)\.dynamics\.com$", (False, "dynamics.com", None)),
    (r"\.com$", (False, None, None)),
    (r"dynamics\.com$", (False, None, None)),
    (r".*\.dynamics\.com\b$", (False, None, None)),
    (r".*\.dynamics\.com", (False, None, None)),
    (r".*\.dynamics\.com\$", (False, None, None)),
    (r".*\\.dynamics\.com$", (False, None, None)),
    (r"[.]dynamics\.com$", (False, None, None)),
    (r"^mcp\.?foo\.com$", (False, None, None)),
    (r"^mcp?\.foo\.com$", (False, "foo.com", None)),
    (r"(?x) .*\.dynamics\.com$", (False, None, None)),
    (r"(?:foo){e<=1}\.dynamics\.com$", (False, None, None)),
    (r"[[:alpha:]]\.dynamics\.com$", (False, None, None)),
    (r"^localhost$", (False, None, None)),
])
def test_plain_host_hints_are_conservative(pattern, expected):
    assert tuple(plain_host_hints(pattern)) == expected


# ------------------------------------------------------ literal prefilter
def _reference_regex_matches(index: SignatureIndex, signal_type: str, text: str, language: str | None = None,
                             max_per_signal: int = 3) -> list[tuple[str, int, str, float, int]]:
    """Every pattern of every signal over the text: the matcher the literal prefilter must reproduce."""
    out = []
    newlines = [m.start() for m in re.finditer("\n", text)]
    for sig, s in index._by_type.get(signal_type, []):
        if language and s.languages and language not in s.languages:
            continue
        hits = 0
        for rx in s.bounded_compiled:
            hints = required_literals(rx.pattern)
            for m in rx.finditer(text):
                # Depth-zero literals are consumed by every match, so one
                # alternative of every group must appear inside the matched
                # text itself, not just somewhere in the input.
                matched = m.group(0).casefold() if hints.fold else m.group(0)
                assert all(any(alternative in matched for alternative in group) for group in hints.groups), (
                    rx.pattern, hints, m.group(0),
                )
                line = bisect_left(newlines, m.start()) + 1
                value = m.group(0) if signal_type == "secret" else sanitize_text(m.group(0))[:200]
                out.append((sig.id, sig.signals.index(s), value, s.weight, line))
                hits += 1
                if hits >= max_per_signal:
                    break
            if hits >= max_per_signal:
                break
    return out


def _flatten(matches) -> list[tuple[str, int, str, float, int]]:
    return [(m.signature_id, m.signature.signals.index(m.signal), m.value, m.weight, m.line) for m in matches]


def test_prefiltered_regex_signals_equal_the_exhaustive_reference(index):
    texts = _corpus_texts()
    assert len(texts) > 40
    hits = 0
    for name, text in texts:
        language = language_for_path(name.rsplit(":", 1)[-1])
        with index.scan_budget(seconds=60):
            code = _flatten(index.match_code(text, language))
            imports = _flatten(index.match_imports(text, language))
            secrets = _flatten(index.match_secrets(text))
        assert code == _reference_regex_matches(index, "code", text, language), name
        assert imports == _reference_regex_matches(index, "import", text, language), name
        assert secrets == _reference_regex_matches(index, "secret", text, max_per_signal=5), name
        hits += len(code) + len(imports) + len(secrets)
    assert hits > 50


@pytest.mark.parametrize("pattern, expected", [
    (r"\bStateGraph\s*\(", "StateGraph"),
    (r"uses:\s*anthropics/claude-code-action", "anthropics/claude-code-action"),
    (r"^[^\S\r\n]*(?:from|import)\s+langgraph\b", "langgraph"),
    (r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{20,}\b", "sk-ant-"),
    (r"\.env\.local", ".env.local"),
    (r"a\nb", "a\nb"),
    (r"abc[def]ghi", "abc"),
    (r"ab?c", "a"),
    (r"ab*c", "a"),
    (r"ab+c", "ab"),
    (r"a{2}b", "a"),
    (r"a{0,2}b", "b"),
    (r"(?:foo){2}bar", "foo"),
    (r"(?:foo)?bar+?x", "bar"),
    (r"x\<y", "x"),
    (r"(?i)\bYOLO\b", None),
    (r"(?i:yolo)bar", None),
    (r"\b(?:a|b)\b", None),
    (r"foo|bar", None),
    (r"\x41bc", None),
    (r"(?:foo){e<=1}bar", None),
])
def test_required_literal_is_conservative(pattern, expected):
    assert required_literal(pattern) == expected


@pytest.mark.parametrize("pattern, expected", [
    (r"\b(?:LlmAgent|SequentialAgent)\s*\(", (False, (("LlmAgent", "SequentialAgent"), ("(",)))),
    (r"^[^\S\r\n]*(?:from|import)\s+(?:mcp|fastmcp)\b", (False, (("from", "import"), ("mcp", "fastmcp")))),
    (r"(a|b)c", (False, (("a", "b"), ("c",)))),
    (r"(?:a|b)+c", (False, (("a", "b"), ("c",)))),
    (r"(?:a|b){2}c", (False, (("a", "b"), ("c",)))),
    (r"(?:a|b)?c", (False, (("c",),))),
    (r"(?:a|b)*c", (False, (("c",),))),
    (r"(?:a|b){0,2}c", (False, (("c",),))),
    (r"(?:a|)b", (False, (("b",),))),
    (r"(?=foo)bar", (False, (("bar",),))),
    (r"(?:a(b)|c)d", (False, (("d",),))),
    (r"(?:a[bc]|d)e", (False, (("e",),))),
    (r"(?:\(|\.from_tools)", (False, (("(", ".from_tools"),))),
    (r"(?i)\bYOLO\b", (True, (("yolo",),))),
    (r"(?is)you are (?:a|an) (?:helpful )?agent", (True, (("you are ",), ("a", "an"), (" ",), ("agent",)))),
    (r"(?i)a(?i:b)", (False, ())),
    (r"a(?i)b", (False, ())),
    (r"foo|bar", (False, ())),
])
def test_required_literals_groups_and_case_folding(pattern, expected):
    assert tuple(required_literals(pattern)) == expected


def test_shipped_packs_mostly_have_required_literals(index):
    """The prefilter only pays off when most shipped patterns carry literals; guard against regressions."""
    for signal_type, minimum in (("code", 0.99), ("import", 1.0), ("secret", 1.0), ("image", 1.0)):
        patterns = [rx.pattern for sig, s in index._by_type[signal_type] for rx in s.bounded_compiled]
        covered = sum(bool(required_literals(pattern).groups) for pattern in patterns)
        assert covered >= minimum * len(patterns), (signal_type, covered, len(patterns))


def test_case_insensitive_literals_use_full_case_folding(index):
    """Full folding on both sides is a superset of the engine's simple folding: matches are never skipped."""
    text = "YOU ARE AN autonomous AGENT\nstraße and ſoo and Kelvin\n"
    with index.scan_budget(seconds=60):
        assert "heuristic.system-prompt" in {m.signature_id for m in index.match_code(text)}
    assert _flatten(index.match_code(text)) == _reference_regex_matches(index, "code", text)


# ------------------------------------------------------ file glob prefilter
def _reference_file_matches(index: SignatureIndex, relpath: str) -> list[tuple[str, int]]:
    rel = relpath.replace("\\", "/")
    base = rel.rsplit("/", 1)[-1]
    out = []
    for sig, s in index._files:
        for g in s.globs:
            if fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(base, g) or (g.startswith("**/") and fnmatch.fnmatch(rel, g[3:])):
                out.append((sig.id, sig.signals.index(s)))
                break
    return out


def test_precompiled_file_globs_equal_fnmatch(index):
    paths = [str(p.relative_to(REPO)) for p in (REPO / "tests" / "fixtures").rglob("*") if p.is_file()]
    paths += [g.replace("**/", "nested/deep/").replace("*", "value") for sig, s in index._files for g in s.globs]
    paths += [
        "CLAUDE.md", "a/b/CLAUDE.md", ".claude/settings.json", "pkg/.claude/agents/reviewer.md", ".cursorrules",
        "server.json", "x/server.json", "Foo.PY", ".copilot/deep/file.txt", "src/.github/workflows/copilot-setup-steps.yml",
        "unrelated.py", "docs/readme.md", "", ".", "a\\b\\CLAUDE.md",
    ]
    matched = 0
    for path in paths:
        got = [(m.signature_id, m.signature.signals.index(m.signal)) for m in index.match_file(path)]
        assert got == _reference_file_matches(index, path), path
        matched += bool(got)
    assert matched > 50
    assert all(m.value == "a/b/CLAUDE.md" for m in index.match_file("a\\b\\CLAUDE.md"))


def test_unreadable_entries_reserve_no_deadline_budget(tmp_path, index, monkeypatch):
    # An oversize, non-skippable source file first in walk order must not end
    # the walk: it is never read, so it reserves no matching budget.
    (tmp_path / "a_big.py").write_bytes(b"#" * (2 * 1024 * 1024))
    for number in range(3):
        (tmp_path / f"z_agent_{number}.py").write_text(LANGCHAIN)
    clock = _fake_clock(monkeypatch, step=1.0)
    ctx = ConnectorContext(config={"path": str(tmp_path), "use_git": False, "strict_coverage": True}, index=index, deadline=clock[0] + 5.5)
    findings = FilesystemConnector(ctx).run()
    assert ctx.stats.objects_examined >= 2
    assert any("a_big.py" in error and "max_file_size" in error for error in ctx.stats.errors)
    assert not any("deadline reached after 0 of" in error for error in ctx.stats.errors)
    assert any("framework.langchain" in finding.frameworks for finding in findings)


def test_one_large_file_that_does_not_fit_is_skipped_without_ending_the_walk(tmp_path, index, monkeypatch):
    # A 900 KiB source file needs more budget than a short deadline allows; the
    # walk skips it with its own error and still analyzes the ordinary files.
    (tmp_path / "a_large.py").write_text("x = 1\n" * (900 * 1024 // 6))
    for number in range(2):
        (tmp_path / f"z_agent_{number}.py").write_text(LANGCHAIN)
    clock = _fake_clock(monkeypatch, step=0.5)
    ctx = ConnectorContext(config={"path": str(tmp_path), "use_git": False}, index=index, deadline=clock[0] + 6.0)
    findings = FilesystemConnector(ctx).run()
    assert any("a_large.py: skipped; the remaining connector deadline cannot cover" in error for error in ctx.stats.errors)
    assert ctx.stats.objects_examined >= 1 and ctx.stats.incomplete
    assert any("framework.langchain" in finding.frameworks for finding in findings)
