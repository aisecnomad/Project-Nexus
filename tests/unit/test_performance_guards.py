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
    WALL_BUDGET_FACTOR,
    MatchTimeoutError,
    keep_file_matches,
    keep_secret_matches,
    language_for_path,
    plain_host_hints,
    required_literal,
    required_literals,
)
from shadowscan.utils.redaction import SanitizationLimitError, sanitize_text

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

    def read_text(path, max_bytes, errors=None, **options):
        clock[0] += step
        return original(path, max_bytes, errors, **options)

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
    ctx = ConnectorContext(
        config={"path": str(tmp_path), "use_git": False}, index=index, deadline=clock[0] + 5.5
    )
    findings = FilesystemConnector(ctx).run()
    assert ctx.stats.objects_examined == 4
    assert len(ctx.stats.errors) == 1
    assert re.search(
        r"connector deadline reached after 4 of 10 files under .*; results incomplete", ctx.stats.errors[0]
    )
    assert ctx.stats.incomplete and not ctx.stats.skipped and not ctx.stats.warnings
    assert any("framework.langchain" in finding.frameworks for finding in findings)


def test_engine_keeps_results_returned_before_the_deadline(tmp_path, index, monkeypatch):
    _tree(tmp_path)
    _fake_clock(monkeypatch, step=1.0)
    cfg = ScanConfig(
        connectors=[ConnectorSpec("code.filesystem", {"path": str(tmp_path), "use_git": False})],
        connector_timeout_seconds=5.5,
        parallel=1,
    )
    result = Engine(cfg, index).run()
    assert not result.complete
    stats = result.stats[0]
    assert stats.objects_examined == 4 and not stats.skipped and not stats.cached
    assert len(stats.errors) == 1 and "deadline reached after 4 of 10 files" in stats.errors[0]
    assert not stats.warnings, "an accepted result must not carry the abandoned-worker warning"
    assert any("framework.langchain" in finding.frameworks for finding in result.findings)


def test_root_starting_inside_the_margin_lists_nothing_and_records_one_error(tmp_path, index, monkeypatch):
    # 1 s left: less than the 0.25 s margin plus a 2 s matching budget, so no
    # file can start and the root's directories are never read.
    _tree(tmp_path, count=3)
    clock = _fake_clock(monkeypatch, step=1.0)
    listed: list[str] = []
    walk_directories = filesystem_module._walk_directories

    def recorded_walk_directories(top, onerror, *, budget=None):
        for dirpath, dirnames, filenames in walk_directories(top, onerror, budget=budget):
            listed.append(dirpath)
            yield dirpath, dirnames, filenames

    monkeypatch.setattr(filesystem_module, "_walk_directories", recorded_walk_directories)
    ctx = ConnectorContext(
        config={"path": str(tmp_path), "use_git": False}, index=index, deadline=clock[0] + 1.0
    )
    findings = FilesystemConnector(ctx).run()
    assert not findings and ctx.stats.objects_examined == 0 and not listed
    assert len(ctx.stats.errors) == 1
    assert "connector deadline: listing stopped after 0 entries; results incomplete" in ctx.stats.errors[0]


def test_deadline_remainder_is_exact_within_max_files(tmp_path, index, monkeypatch):
    _tree(tmp_path, count=8)
    clock = _fake_clock(monkeypatch, step=1.0)
    ctx = ConnectorContext(
        config={"path": str(tmp_path), "use_git": False, "max_files": 6}, index=index, deadline=clock[0] + 5.5
    )
    FilesystemConnector(ctx).run()
    # The buffered walk records both truths distinctly: enumeration stopped at
    # max_files, and the deadline left an exactly-counted remainder of the
    # entries that were enumerated (never the lazy walk's "at least N").
    assert len(ctx.stats.errors) == 2
    assert any("max_files (6) reached" in error for error in ctx.stats.errors)
    assert any("after 4 of 6 files" in error for error in ctx.stats.errors)


def test_listing_stops_in_time_to_scan_the_listed_files(tmp_path, index, monkeypatch):
    # Listing alone would cross the deadline: each entry costs 1 s and the
    # tree has 30. Files may start until 1017 (20 s minus a 1 s margin and a
    # 2 s matching budget); listing takes half of that window (until
    # 1008.5), so 9 entries are listed and every one of them is scanned.
    _tree(tmp_path, count=30)
    clock = _fake_clock(monkeypatch, step=0.0)
    count_entry = FilesystemConnector._count_entry

    def slow_count_entry(self, walk, root):
        clock[0] += 1.0
        return count_entry(self, walk, root)

    monkeypatch.setattr(FilesystemConnector, "_count_entry", slow_count_entry)
    ctx = ConnectorContext(
        config={"path": str(tmp_path), "use_git": False}, index=index, deadline=clock[0] + 20.0
    )
    findings = FilesystemConnector(ctx).run()
    assert not ctx.stats.skipped and ctx.stats.incomplete
    assert ctx.stats.objects_examined == 9
    assert len(ctx.stats.errors) == 1
    assert re.search(r"connector deadline: listing stopped after 9 entries", ctx.stats.errors[0])
    assert any("framework.langchain" in finding.frameworks for finding in findings)


def test_root_without_time_to_scan_lists_nothing_and_keeps_earlier_roots(tmp_path, index, monkeypatch):
    # The first root stops starting files at 1008.15 (10 s deadline, 0.5 s
    # margin, 2 s matching budget), so the second root starts with 1.85 s
    # left: less than its 0.25 s margin plus a matching budget, so none of
    # its files can start. Listing it anyway would only spend the margin, and
    # sorting what it listed (charged per sort key, as listing is per entry)
    # would cross the deadline, so the engine would discard the first root's
    # findings with the whole connector.
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    _tree(first)
    for number in range(400):
        (second / f"data_{number}.txt").write_text("x")
    clock = _fake_clock(monkeypatch, step=1.0)
    deadline = clock[0] + 10.0
    second_listed_at: list[float] = []
    count_entry = FilesystemConnector._count_entry
    scan_priority = filesystem_module._scan_priority

    def slow_count_entry(self, walk, root):
        clock[0] += 0.01
        if Path(root).name == "second":
            second_listed_at.append(clock[0])
        return count_entry(self, walk, root)

    def slow_scan_priority(rel, name):
        clock[0] += 0.005
        return scan_priority(rel, name)

    monkeypatch.setattr(FilesystemConnector, "_count_entry", slow_count_entry)
    monkeypatch.setattr(filesystem_module, "_scan_priority", slow_scan_priority)
    cfg = ScanConfig(
        connectors=[
            ConnectorSpec("code.filesystem", {"paths": [str(first), str(second)], "use_git": False}),
        ],
        connector_timeout_seconds=10.0,
        parallel=1,
    )
    result = Engine(cfg, index).run()
    stats = result.stats[0]
    assert not result.complete and not stats.skipped
    assert all(at < deadline - DEADLINE_MARGIN_MIN_SECONDS for at in second_listed_at)
    assert any("deadline reached after 8 of 10 files" in error for error in stats.errors)
    assert any("connector deadline: listing stopped after 0 entries" in error for error in stats.errors)
    assert any("framework.langchain" in finding.frameworks for finding in result.findings)


def test_cancellation_mid_walk_is_not_reported_per_file(tmp_path, index, monkeypatch):
    _tree(tmp_path)
    cancelled = threading.Event()
    original = filesystem_module.read_text

    def read_text(path, max_bytes, errors=None, **options):
        cancelled.set()
        return original(path, max_bytes, errors, **options)

    monkeypatch.setattr(filesystem_module, "read_text", read_text)
    ctx = ConnectorContext(config={"path": str(tmp_path), "use_git": False}, index=index, cancelled=cancelled)
    FilesystemConnector(ctx).run()
    assert ctx.stats.skipped and ctx.stats.errors == ["connector completion deadline exceeded"]


def test_deadline_margin_is_a_bounded_fraction_of_the_remaining_budget():
    assert deadline_margin(120.0) == pytest.approx(6.0)
    assert deadline_margin(1.0) == DEADLINE_MARGIN_MIN_SECONDS
    assert deadline_margin(-5.0) == DEADLINE_MARGIN_MIN_SECONDS


# ---------------------------------------------------------- file budgets
@pytest.mark.parametrize(
    "base, size, expected",
    [
        (2.0, 0, 2.0),
        (2.0, 192 * 1024 - 1, 2.0),
        (2.0, 192 * 1024, 4.0),
        (2.0, 256 * 1024 - 1, 4.0),
        (2.0, 256 * 1024, 4.0),
        (2.0, 971 * 1024, 8.0),
        (2.0, 1_000_000, 8.0),
        (2.0, 5 * 1024 * 1024, 10.0),
        (0.2, 1_000_000, 0.8),
        (20.0, 5 * 1024 * 1024, 20.0),
        (60.0, 10**9, 60.0),
    ],
)
def test_scan_timeout_scales_with_file_size_and_is_capped(base, size, expected):
    assert scan_timeout_for_size(base, size) == pytest.approx(expected)


def test_scan_tree_opens_a_size_scaled_budget_per_file(tmp_path, index, monkeypatch):
    (tmp_path / "small.py").write_text(LANGCHAIN)
    (tmp_path / "index.json").write_text(json.dumps({"entries": ["x" * 100] * 3200}))  # about 330 KiB
    recorded: list[tuple[float, int | None]] = []
    original = SignatureIndex.scan_budget

    def scan_budget(self, seconds=2.0, *, chars=None, **options):
        recorded.append((seconds, chars))
        return original(self, seconds=seconds, chars=chars, **options)

    monkeypatch.setattr(SignatureIndex, "scan_budget", scan_budget)
    ctx = ConnectorContext(config={"path": str(tmp_path), "use_git": False, "scan_timeout": 1.0}, index=index)
    FilesystemConnector(ctx).run()
    assert not ctx.stats.errors
    seconds = sorted(budget for budget, _ in recorded)
    assert seconds[0] == 1.0 and 2.0 in seconds
    # The walk declares each file's size so the per-execution allowance scales.
    assert all(chars is not None and chars > 0 for _, chars in recorded)


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


def test_oversize_source_file_marks_coverage_incomplete_by_default(tmp_path, index):
    (tmp_path / "agent.py").write_text("from crewai import Agent\n")
    (tmp_path / "big.py").write_text("x" * 200)
    result = Engine(_engine_config(tmp_path), index).run()
    assert not result.complete and result.findings
    assert not result.stats[0].errors
    assert any(
        "big.py: skipped, file exceeds max_file_size" in warning for warning in result.stats[0].warnings
    )
    # Strict coverage keeps the error severity for callers that use it.
    strict = Engine(_engine_config(tmp_path, strict_coverage=True), index).run()
    assert not strict.complete and strict.findings
    assert any("big.py: file exceeds max_file_size" in error for error in strict.stats[0].errors)
    assert not strict.stats[0].warnings


def test_oversize_skip_globs_is_configurable_and_validated(tmp_path, index, run_connector):
    (tmp_path / "big.py").write_text("x" * 200)
    (tmp_path / "data.csv").write_text("a,b\n" * 60)
    _, ctx = run_connector(
        "code.filesystem",
        path=str(tmp_path),
        use_git=False,
        max_file_size=100,
        oversize_skip_globs=["*.PY", "*.csv"],
    )
    assert not ctx.stats.incomplete and not ctx.stats.errors
    assert sorted(warning.split(": ")[1] for warning in ctx.stats.warnings) == ["big.py", "data.csv"]
    _, ctx = run_connector(
        "code.filesystem", path=str(tmp_path), use_git=False, max_file_size=100, oversize_skip_globs=[]
    )
    assert ctx.stats.incomplete and not ctx.stats.errors and len(ctx.stats.warnings) == 2
    _, ctx = run_connector(
        "code.filesystem",
        path=str(tmp_path),
        use_git=False,
        max_file_size=100,
        oversize_skip_globs=[],
        strict_coverage=True,
    )
    assert ctx.stats.incomplete and not ctx.stats.warnings
    assert sorted(error.split(": ")[1] for error in ctx.stats.errors) == ["big.py", "data.csv"]
    with pytest.raises(ConnectorError, match="oversize_skip_globs"):
        FilesystemConnector(
            ConnectorContext(config={"path": str(tmp_path), "oversize_skip_globs": "*.csv"}, index=index)
        )
    assert "yarn.lock" in DEFAULT_OVERSIZE_SKIP_GLOBS and "*.pyc" in DEFAULT_OVERSIZE_SKIP_GLOBS
    assert "oversize_skip_globs" in FilesystemConnector.config_keys


def test_only_oversize_agent_source_does_not_yield_a_clean_empty_result(tmp_path, index):
    (tmp_path / "agent.py").write_text("from crewai import Agent\n" + " " * 1_000_000)
    config = ScanConfig(
        connectors=[ConnectorSpec("code.filesystem", {"path": str(tmp_path), "use_git": False})], parallel=1
    )
    result = Engine(config, index).run()
    assert not result.complete and result.findings == []
    assert result.stats[0].incomplete
    assert any(
        "agent.py: skipped, file exceeds max_file_size; coverage incomplete" in warning
        for warning in result.stats[0].warnings
    )


def test_explicit_oversize_source_exclusion_keeps_result_complete(tmp_path, index):
    (tmp_path / "agent.py").write_text("from crewai import Agent\n" + " " * 200)
    result = Engine(_engine_config(tmp_path, oversize_skip_globs=["agent.py"]), index).run()
    assert result.complete and result.findings == []
    assert any("agent.py" in warning and "never analyzed" in warning for warning in result.stats[0].warnings)


@pytest.mark.skipif(os.name != "posix", reason="POSIX flock is required for incremental state")
def test_incremental_cache_hits_a_tree_with_an_oversize_lockfile(tmp_path, index, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "agent.py").write_text("from crewai import Agent\n")
    (repo / "yarn.lock").write_text("x" * 4096)
    # A hash budget below the lockfile's size proves its content is never read.
    monkeypatch.setattr("shadowscan.incremental._MAX_HASH_BYTES", 2048)
    cfg = ScanConfig(
        connectors=[
            ConnectorSpec("code.filesystem", {"path": str(repo), "use_git": False, "max_file_size": 1024})
        ],
        incremental=True,
        state_dir=str(tmp_path / "state"),
        parallel=1,
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
        if (
            len(labels[-1]) < 2
            or not labels[-1].isalpha()
            or any(
                not label or len(label) > 63 or not label[0].isalnum() or not label[-1].isalnum()
                for label in labels
            )
        ):
            continue
        found = list(index._domains.get(host, []))
        found += [
            (sig, s)
            for suffix, sig, s in index._domain_suffixes
            if host.endswith(suffix) or host == suffix.lstrip(".")
        ]
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


SYNTHETIC_HOSTS = (
    """
https://api.anthropic.com/v1 bedrock-runtime.eu-west-1.amazonaws.com bedrock-agent-runtime.us-east-1.amazonaws.com
acme.openai.azure.com mcp.example.io MCP.Example.IO notmcp.example.io x.dynamics.com crm9.dynamics.com dynamics.com
foo.svc.us-east1.pinecone.io hook.eu1.make.com eu2.make.com integromat.com sub.integromat.com x.retool.com retool.com
api.cloudflare.com notapi.cloudflare.com cloudflare.com bedrock-mantle.us-east-1.api.aws gateway.ai.cloudflare.com
localhost:11434 127.0.0.1:1234 example.com:4000 ..weird..host.com.. a-.b.com -a.b.com trailing.dot.com. -
"""
    + "x" * 70
    + ".com "
    + "label." * 60
    + "com K.dynamics.com ſoo.retool.com api.anthropic.com\n"
)


def test_prefiltered_domain_matching_equals_the_exhaustive_reference(index):
    texts = _corpus_texts() + [("synthetic", SYNTHETIC_HOSTS)]
    assert len(texts) > 40
    hits = 0
    for name, text in texts:
        with index.scan_budget(seconds=60):
            fast = [
                (m.signature_id, m.signature.signals.index(m.signal), m.value, m.weight, m.line)
                for m in index.match_domains_in_text(text)
            ]
        assert fast == _reference_domain_matches(index, text), name
        hits += len(fast)
    assert hits > 20


@pytest.mark.parametrize(
    "host",
    [
        "localhost:11434",
        "http://x.retool.com:8443/v1",
        "foo.bar:x.retool.com",
        "x.dynamics.com\n.",
        "K.dynamics.com",
        "acme.openai.azure.com:443",
        "EU3.make.com",
        "mcp.example.io",
    ],
)
def test_match_domain_with_ports_paths_and_unusual_characters_matches_every_value(index, host):
    h = host.lower().strip().rstrip(".")
    h = h.split("://", 1)[1] if "://" in h else h
    with_port = h.split("/", 1)[0]
    bare = with_port.split(":", 1)[0]
    expected = [(sig.id, sig.signals.index(s)) for sig, s in index._domains.get(bare, [])]
    expected += [
        (sig.id, sig.signals.index(s))
        for suffix, sig, s in index._domain_suffixes
        if bare.endswith(suffix) or bare == suffix.lstrip(".")
    ]
    expected += [
        (sig.id, sig.signals.index(s))
        for rx, sig, s in index._domain_regex
        if rx.search(bare) or rx.search(with_port)
    ]
    assert [
        (m.signature_id, m.signature.signals.index(m.signal)) for m in index.match_domain(host)
    ] == expected


@pytest.mark.parametrize(
    "pattern, expected",
    [
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
    ],
)
def test_plain_host_hints_are_conservative(pattern, expected):
    assert tuple(plain_host_hints(pattern)) == expected


# ------------------------------------------------------ literal prefilter
def _reference_regex_matches(
    index: SignatureIndex, signal_type: str, text: str, language: str | None = None, max_per_signal: int = 3
) -> list[tuple[str, int, str, float, int]]:
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
                    rx.pattern,
                    hints,
                    m.group(0),
                )
                line = bisect_left(newlines, m.start()) + 1
                value = m.group(0) if signal_type == "secret" else sanitize_text(m.group(0))[:200]
                out.append((sig.id, sig.signals.index(s), value, s.weight, line))
                hits += 1
                if hits >= max_per_signal:
                    break
            if hits >= max_per_signal:
                break
    if signal_type == "secret":
        # match_secrets applies the same deterministic post-filter after the regex pass.
        keep = keep_secret_matches([(sig_id, value, line) for sig_id, _, value, _, line in out])
        out = [item for item, kept in zip(out, keep, strict=True) if kept]
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


@pytest.mark.parametrize(
    "pattern, expected",
    [
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
    ],
)
def test_required_literal_is_conservative(pattern, expected):
    assert required_literal(pattern) == expected


@pytest.mark.parametrize(
    "pattern, expected",
    [
        (r"\b(?:LlmAgent|SequentialAgent)\s*\(", (False, (("LlmAgent", "SequentialAgent"), ("(",)))),
        (
            r"^[^\S\r\n]*(?:from|import)\s+(?:mcp|fastmcp)\b",
            (False, (("from", "import"), ("mcp", "fastmcp"))),
        ),
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
        (
            r"(?is)you are (?:a|an) (?:helpful )?agent",
            (True, (("you are ",), ("a", "an"), (" ",), ("agent",))),
        ),
        (r"(?i)a(?i:b)", (False, ())),
        (r"a(?i)b", (False, ())),
        (r"foo|bar", (False, ())),
    ],
)
def test_required_literals_groups_and_case_folding(pattern, expected):
    assert tuple(required_literals(pattern)) == expected


def test_shipped_packs_mostly_have_required_literals(index):
    """The prefilter only pays off when most shipped patterns carry literals; guard against regressions."""
    for signal_type, minimum in (("code", 1.0), ("import", 1.0), ("secret", 1.0), ("image", 1.0)):
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
            if (
                fnmatch.fnmatch(rel, g)
                or fnmatch.fnmatch(base, g)
                or (g.startswith("**/") and fnmatch.fnmatch(rel, g[3:]))
            ):
                out.append((sig, sig.signals.index(s)))
                break
    keep = keep_file_matches([sig for sig, _ in out])
    return [(sig.id, position) for (sig, position), kept in zip(out, keep, strict=True) if kept]


def test_precompiled_file_globs_equal_fnmatch(index):
    paths = [str(p.relative_to(REPO)) for p in (REPO / "tests" / "fixtures").rglob("*") if p.is_file()]
    paths += [
        g.replace("**/", "nested/deep/").replace("*", "value") for sig, s in index._files for g in s.globs
    ]
    paths += [
        "CLAUDE.md",
        "a/b/CLAUDE.md",
        ".claude/settings.json",
        "pkg/.claude/agents/reviewer.md",
        ".cursorrules",
        "server.json",
        "x/server.json",
        "Foo.PY",
        ".copilot/deep/file.txt",
        "src/.github/workflows/copilot-setup-steps.yml",
        "unrelated.py",
        "docs/readme.md",
        "",
        ".",
        "a\\b\\CLAUDE.md",
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
    ctx = ConnectorContext(
        config={"path": str(tmp_path), "use_git": False, "strict_coverage": True},
        index=index,
        deadline=clock[0] + 5.5,
    )
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
    ctx = ConnectorContext(
        config={"path": str(tmp_path), "use_git": False}, index=index, deadline=clock[0] + 6.0
    )
    findings = FilesystemConnector(ctx).run()
    assert any(
        "a_large.py: skipped; the remaining connector deadline cannot cover" in error
        for error in ctx.stats.errors
    )
    assert ctx.stats.objects_examined >= 1 and ctx.stats.incomplete
    assert any("framework.langchain" in finding.frameworks for finding in findings)


# ------------------------------------------------------------ lazy excerpts
def _count_redactions(monkeypatch) -> list[str]:
    """Record the files whose whole text is redacted for excerpts."""
    redacted: list[str] = []
    original = filesystem_module._redacted_source

    def counting(text, structure):
        redacted.append(text)
        return original(text, structure)

    monkeypatch.setattr(filesystem_module, "_redacted_source", counting)
    return redacted


def test_dropped_matches_redact_their_file_once_and_emit_nothing(tmp_path, index, monkeypatch):
    # A code pattern without the library's import anywhere in the project is
    # uncorroborated: nothing is reported. The file is still redacted once when
    # its analysis ends, only so a sanitization limit fails the scan closed.
    (tmp_path / "shape.py").write_text("response = client.chat.completions.create(model=model)\n")
    redacted = _count_redactions(monkeypatch)
    ctx = ConnectorContext(config={"path": str(tmp_path), "use_git": False}, index=index)
    findings = FilesystemConnector(ctx).run()
    assert not any(f.resource_type == "project" for f in findings)
    assert len(redacted) == 1
    assert not ctx.stats.errors


def test_sanitization_limit_marks_the_scan_incomplete_even_when_every_match_is_dropped(
    tmp_path, index, monkeypatch
):
    # Whether redaction exceeds a limit is known only by redacting. A file that
    # recorded excerpted evidence is redacted when its analysis ends, so the
    # limit error is recorded, and the scan incomplete, exactly as the eager
    # excerpts did, even when no match of the file reaches the report.
    (tmp_path / "shape.py").write_text("response = client.chat.completions.create(model=model)\n")
    attempted: list[str] = []

    def failing(text, structure):
        attempted.append(text)
        raise SanitizationLimitError("credential replacement work limit exceeded")

    monkeypatch.setattr(filesystem_module, "_redacted_source", failing)
    ctx = ConnectorContext(config={"path": str(tmp_path), "use_git": False}, index=index)
    findings = FilesystemConnector(ctx).run()
    assert not any(f.resource_type == "project" for f in findings)
    assert len(attempted) == 1
    assert ctx.stats.errors == [
        "code.filesystem: shape.py: structured sanitization incomplete (SanitizationLimitError); "
        "excerpts withheld"
    ]
    assert ctx.stats.incomplete


def test_sanitization_limit_on_a_retained_file_withholds_its_excerpts(tmp_path, index, monkeypatch):
    (tmp_path / "agent.py").write_text(LANGCHAIN + "agent = agents.AgentExecutor()\n")

    def failing(text, structure):
        raise SanitizationLimitError("credential replacement work limit exceeded")

    monkeypatch.setattr(filesystem_module, "_redacted_source", failing)
    ctx = ConnectorContext(config={"path": str(tmp_path), "use_git": False}, index=index)
    findings = FilesystemConnector(ctx).run()
    project = next(f for f in findings if f.resource_type == "project")
    assert "framework.langchain" in project.frameworks
    assert all(not e.snippet for e in project.evidence)
    assert ctx.stats.errors == [
        "code.filesystem: agent.py: structured sanitization incomplete (SanitizationLimitError); "
        "excerpts withheld"
    ]
    assert ctx.stats.incomplete


def test_retained_evidence_is_excerpted_once_per_file_and_sanitized(tmp_path, index, monkeypatch):
    secret = "sk-proj-aP9rVv3qN4zY7bC2hJ8Lm5Qw6Dt0KsX1eR7uT4p"
    (tmp_path / "agent.py").write_text(
        f"from crewai import Agent  # token {secret}\nfrom crewai import Task\nagent = Agent()\n"
    )
    redacted = _count_redactions(monkeypatch)
    ctx = ConnectorContext(config={"path": str(tmp_path), "use_git": False}, index=index)
    findings = FilesystemConnector(ctx).run()
    project = next(f for f in findings if f.resource_type == "project")
    # The credential observation keeps no excerpt on the project finding, as before;
    # synthetic corroboration evidence has no source location to excerpt.
    snippets = [e.snippet for e in project.evidence if not e.signal.startswith(("secret:", "corroboration:"))]
    assert len(snippets) >= 3 and all(snippet for snippet in snippets)
    assert secret not in json.dumps([f.to_dict() for f in findings])
    assert len(redacted) == 1  # several retained matches, one redaction of the file


def _settled_sources(monkeypatch) -> list:
    """Record each file's excerpt source as its analysis settles it."""
    sources: list = []
    original = FilesystemConnector._settle_excerpts

    def recording(self, file):
        original(self, file)
        sources.append(file.excerpts)

    monkeypatch.setattr(FilesystemConnector, "_settle_excerpts", recording)
    return sources


def test_settled_files_keep_only_their_excerpt_lines(tmp_path, index, monkeypatch):
    # Excerpts are cut at emit time, but a settled file must not keep every
    # redacted line until then: memory would grow with the total size of all
    # matched files rather than with the number of excerpts.
    body = "".join(f"value_{n} = {n}\n" for n in range(5000))
    (tmp_path / "agent.py").write_text(f"{LANGCHAIN}{body}agent = agents.AgentExecutor()\n")
    sources = _settled_sources(monkeypatch)
    ctx = ConnectorContext(config={"path": str(tmp_path), "use_git": False}, index=index)
    findings = FilesystemConnector(ctx).run()
    (source,) = [s for s in sources if s.rel == "agent.py"]
    retained = len(source.safe_lines or ()) + len(getattr(source, "kept", None) or ())
    assert 0 < retained <= 4 and source.text is None
    project = next(f for f in findings if f.resource_type == "project")
    snippets = {e.snippet for e in project.evidence if e.location and e.location.startswith("agent.py")}
    assert "agent = agents.AgentExecutor()" in snippets
    assert not ctx.stats.errors


def test_deferred_reexport_consumer_evidence_keeps_its_excerpts(tmp_path, index):
    # A root-level consumer of a local re-export is analyzed after the walk;
    # its evidence is excerpted from the file like any other.
    (tmp_path / "app.py").write_text('from middle import PublicAgent\na = PublicAgent(name="helper")\n')
    (tmp_path / "middle.py").write_text("from sdk import RuntimeAgent as PublicAgent\n")
    (tmp_path / "sdk.py").write_text("from agents import Agent as RuntimeAgent\n")
    ctx = ConnectorContext(config={"path": str(tmp_path), "use_git": False}, index=index)
    findings = FilesystemConnector(ctx).run()
    # Synthetic corroboration evidence shares a location but excerpts nothing.
    snippets = {
        e.location: e.snippet
        for f in findings
        for e in f.evidence
        if e.location and not e.attributes.get("synthetic")
    }
    assert snippets["app.py:2"] == 'a = PublicAgent(name="helper")'
    assert snippets["app.py:1"] == "from middle import PublicAgent"
    assert not ctx.stats.errors and not ctx.stats.incomplete


def test_shared_literal_scan_equals_the_per_pass_scan(index):
    for name, text in _corpus_texts():
        language = language_for_path(name.rsplit(":", 1)[-1])
        with index.scan_budget(seconds=60):
            scan = index.literal_scan(text, language)
            shared = (
                _flatten(index.match_code(text, language, scan=scan)),
                _flatten(index.match_imports(text, language, scan=scan)),
                _flatten(index.match_secrets(text, scan=scan)),
            )
            separate = (
                _flatten(index.match_code(text, language)),
                _flatten(index.match_imports(text, language)),
                _flatten(index.match_secrets(text)),
            )
        assert shared == separate, name


def test_shared_literal_scan_keeps_overlapping_literals(monkeypatch):
    from shadowscan.signatures.loader import signature_from_dict

    def signature(sig_id, pattern):
        return signature_from_dict(
            {"id": sig_id, "category": "framework", "signals": [{"type": "code", "patterns": [pattern]}]}
        )

    # One literal is a prefix of another, one is nested inside a third, one is
    # case-insensitive: every pattern whose literal occurs must still run.
    custom = SignatureIndex(
        [
            signature("custom.short", r"openai\("),
            signature("custom.long", r"openai\.chat\.create"),
            signature("custom.inner", r"penai\.ch"),
            signature("custom.folded", r"(?i)OPENAI\.CHAT"),
            signature("custom.absent", r"anthropic\.messages"),
        ]
    )
    text = "x = openai(1)\ny = openai.chat.create()\n"
    scan = custom.literal_scan(text, "python")
    assert set(scan.present) == {"openai(", "openai.chat.create", "penai.ch"}
    assert set(scan.folded_present) == {"openai.chat"}
    with custom.scan_budget(seconds=60):
        found = sorted(m.signature_id for m in custom.match_code(text, "python", scan=scan))
    assert found == ["custom.folded", "custom.inner", "custom.long", "custom.short"]
    assert found == sorted(m.signature_id for m in custom.match_code(text, "python"))


def test_shared_literal_scan_memo_of_an_absent_literal_selects_no_candidate(monkeypatch):
    from shadowscan.signatures import matcher
    from shadowscan.signatures.loader import signature_from_dict

    def signature(sig_id, signal_type, pattern):
        return signature_from_dict(
            {"id": sig_id, "category": "framework", "signals": [{"type": signal_type, "patterns": [pattern]}]}
        )

    # The import pass memoises ``beta`` (a remaining-group literal) as absent;
    # the code pass, whose own first-group literal it is, must not read that
    # memo entry as presence and run a pattern that cannot match.
    custom = SignatureIndex(
        [signature("custom.pair", "import", r"alpha.*beta"), signature("custom.single", "code", r"beta\s*=")]
    )
    text = "x = alpha here\n"
    attempted: list[str] = []
    original = matcher._finditer

    def recording(rx, *args, **options):
        attempted.append(rx.pattern)
        return original(rx, *args, **options)

    monkeypatch.setattr(matcher, "_finditer", recording)
    with custom.scan_budget(seconds=60):
        scan = custom.literal_scan(text, "python")
        assert custom.match_imports(text, "python", scan=scan) == []
        assert scan.present == {"alpha": True, "beta": False}
        assert custom.match_code(text, "python", scan=scan) == []
    assert attempted == []


# ------------------------------------------------------------- binder gates
def _binder_sources() -> list[tuple[str, str, str]]:
    """Fixture and corpus sources (which bind) and the connector's own modules (which do not)."""
    sources = []
    for name, text in _corpus_texts():
        language = language_for_path(name.rsplit(":", 1)[-1])
        if language in {"python", "javascript"}:
            sources.append((name, text, language))
    for path in sorted((REPO / "shadowscan" / "connectors" / "code").glob("*.py")):
        sources.append((path.relative_to(REPO).as_posix(), path.read_text(encoding="utf-8"), "python"))
    return sources


def test_binder_gates_are_lossless_on_every_fixture_source(index, monkeypatch):
    from shadowscan.connectors.code import source_semantics

    sources = _binder_sources()
    assert len(sources) > 40
    gated = skipped = 0
    for name, text, language in sources:
        ignored, _ = filesystem_module.noncode_ranges(text, language, "." + name.rsplit(".", 1)[-1])
        results = []
        for gate in (True, False):
            monkeypatch.setattr(source_semantics, "_GATE_BINDERS", gate)
            try:
                with index.scan_budget(seconds=60):
                    found = source_semantics.bound_source_matches(index, text, language, list(ignored))
                results.append(_flatten(found))
            except Exception as exc:  # noqa: BLE001 - the two runs must fail alike
                results.append(type(exc).__name__)
        assert results[0] == results[1], name  # the gate skips the walk, never the parse
        if language == "python":
            monkeypatch.setattr(source_semantics, "_GATE_BINDERS", True)
            gated += 1
            skipped += not source_semantics.python_may_bind(index, text)
    assert 0 < skipped < gated


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("import os\nos.path.join('a')\n", False),
        ("print('openai')\n", False),  # no import statement at all
        ("import openai\nopenai.OpenAI()\n", True),
        ("from langchain.agents import AgentExecutor\n", True),
        ("import langchain.agents\nx = langchain.agents.AgentExecutor()\n", True),
        ("from openai \\\n    import OpenAI\n", True),  # backslash continuation before ``import``
        ("from\x0copenai\x0cimport OpenAI\n", True),  # form feeds as whitespace
        ("import \\\n    openai\n", True),
        ("from os \\\n    import path\n", True),  # a continued import line keeps the binder
        ("import os; from openai import OpenAI\n", True),
        ("import os\nx = 1; y = 2\n", False),  # a ``;`` on a line without an import is modelled
        ("import os\n" + "from a import (\n" + "    b,\n" * 3000 + ")\n", True),  # unbounded: kept
    ],
)
def test_python_binder_gate_follows_import_statements(index, text, expected):
    from shadowscan.connectors.code.source_semantics import python_may_bind

    assert python_may_bind(index, text) is expected


# ------------------------------------------------------- CPU-aware budgets
def _fake_budget_clocks(monkeypatch) -> dict[str, float]:
    clocks = {"wall": 1000.0, "cpu": 10.0}
    matcher = filesystem_module.MatchTimeoutError.__module__
    monkeypatch.setattr(f"{matcher}.time.monotonic", lambda: clocks["wall"])
    monkeypatch.setattr(f"{matcher}.time.thread_time", lambda: clocks["cpu"])
    return clocks


@pytest.mark.production_budgets
def test_a_descheduled_thread_keeps_its_input_budget(index, monkeypatch):
    clocks = _fake_budget_clocks(monkeypatch)
    with index.scan_budget(seconds=2.0):
        clocks["wall"] += 2.0 * WALL_BUDGET_FACTOR - 0.5  # waited, within the wall cap
        clocks["cpu"] += 0.5
        assert index.match_imports("from crewai import Agent", "python")


@pytest.mark.production_budgets
@pytest.mark.parametrize("spent", ["cpu", "wall"])
def test_input_budget_fails_on_cpu_or_the_wall_cap_and_reports_both(index, monkeypatch, spent):
    clocks = _fake_budget_clocks(monkeypatch)
    with (
        pytest.raises(
            MatchTimeoutError, match=r"input execution budget \(cpu .*s of 2\.00s, wall .*s of 8\.00s\)"
        ),
        index.scan_budget(seconds=2.0),
    ):
        clocks[spent] += 2.0 * WALL_BUDGET_FACTOR if spent == "wall" else 2.0
        index.match_imports("from crewai import Agent", "python")


def test_nested_budget_never_outlives_the_outer_one(index, monkeypatch):
    clocks = _fake_budget_clocks(monkeypatch)
    # The inner budget is clipped to the outer one, and the diagnostic names
    # the budget that ended the input: the outer second, not the inner five.
    with (
        pytest.raises(MatchTimeoutError, match=r"cpu 1\.10s of 1\.00s"),
        index.scan_budget(seconds=1.0),
    ):
        clocks["cpu"] += 0.9
        with index.scan_budget(seconds=5.0):
            clocks["cpu"] += 0.2
            index.match_imports("from crewai import Agent", "python")


def test_wall_cap_is_validated():
    with (
        pytest.raises(ValueError, match="wall cap"),
        SignatureIndex([]).scan_budget(seconds=2, wall_seconds=1),
    ):
        pass


def test_scan_tree_opens_a_wall_cap_within_the_connector_deadline(tmp_path, index, monkeypatch):
    (tmp_path / "small.py").write_text(LANGCHAIN)
    recorded: list[tuple[float, float | None]] = []
    original = SignatureIndex.scan_budget

    def scan_budget(self, seconds=2.0, wall_seconds=None, **options):
        recorded.append((seconds, wall_seconds))
        return original(self, seconds=seconds, wall_seconds=wall_seconds, **options)

    monkeypatch.setattr(SignatureIndex, "scan_budget", scan_budget)
    ctx = ConnectorContext(config={"path": str(tmp_path), "use_git": False}, index=index)
    FilesystemConnector(ctx).run()
    assert (2.0, 2.0 * WALL_BUDGET_FACTOR) in recorded
    recorded.clear()
    clock = _fake_clock(monkeypatch, step=0.0)
    ctx = ConnectorContext(
        config={"path": str(tmp_path), "use_git": False}, index=index, deadline=clock[0] + 5.0
    )
    FilesystemConnector(ctx).run()
    # 5 s remain less the 0.25 s margin: the cap is clipped below the 8 s default.
    assert recorded[0][0] == 2.0 and 2.0 <= recorded[0][1] <= 5.0 - DEADLINE_MARGIN_MIN_SECONDS


# -------------------------------------------------------------- determinism
def test_two_scans_of_a_tree_produce_identical_findings_and_diagnostics(index, fixtures):
    def scan():
        ctx = ConnectorContext(config={"path": str(fixtures / "sample_repo"), "use_git": False}, index=index)
        findings = FilesystemConnector(ctx).run()
        return [f.to_dict() for f in findings], ctx.stats.errors, ctx.stats.warnings, ctx.stats.incomplete

    first, second = scan(), scan()
    assert first[0] and first == second
