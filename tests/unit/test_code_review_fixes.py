"""Regressions from the 2026-09-24 review of the code connectors.

All credentials below are synthetic.
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import threading
import time
from pathlib import Path

import pytest

from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.code import filesystem as fs_module
from shadowscan.connectors.code import source_ranges
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.connectors.code.github import GitHubConnector
from shadowscan.connectors.code.manifests import is_manifest_name, parse_manifest
from shadowscan.connectors.code.source_ranges import noncode_ranges
from shadowscan.models import Kind, ScanStats, now_iso

SECRET = "sk-proj-aP9rVv3qN4zY7bC2hJ8Lm5Qw6Dt0KsX1eR7uT4p"


def _scan(index, root: Path, **config):
    ctx = ConnectorContext(config={"path": str(root), **config}, index=index)
    return FilesystemConnector(ctx).run(), ctx


def test_cancellation_stops_the_tree_walk(tmp_path, index):
    for i in range(300):
        directory = tmp_path / f"d{i % 10}"
        directory.mkdir(exist_ok=True)
        (directory / f"f{i}.py").write_text("import openai\n")
    cancelled = threading.Event()
    ctx = ConnectorContext(config={"path": str(tmp_path)}, index=index, cancelled=cancelled)
    connector = FilesystemConnector(ctx)
    walked = 0
    original = connector._iter_entries

    def counting(root):
        nonlocal walked
        for item in original(root):
            walked += 1
            if walked == 10:
                cancelled.set()
            yield item

    connector._iter_entries = counting  # type: ignore[method-assign]
    assert connector.run() == []
    assert walked == 10 and ctx.stats is not None and ctx.stats.skipped
    assert len(ctx.stats.errors) == 1 and "deadline" in ctx.stats.errors[0]


def test_credentials_are_reported_when_a_content_pass_times_out(tmp_path, index, monkeypatch):
    (tmp_path / "app.js").write_text(f'const k = "{SECRET}"; const model = "gpt-4";\n')
    # Force a failure after the independent credential pass. Wall-clock timing
    # depends on the machine and on #47's optimized matchers.
    def exhausted(*args, **kwargs):
        raise TimeoutError("simulated content budget")

    monkeypatch.setattr(index, "match_domains_in_text", exhausted)
    findings, ctx = _scan(index, tmp_path, scan_timeout=60)
    assert any(f.kind == Kind.SECRET for f in findings)
    assert ctx.stats is not None and ctx.stats.incomplete
    assert SECRET not in json.dumps([f.to_dict() for f in findings])


def test_credentials_are_reported_when_structured_sanitization_exceeds_its_budget(tmp_path, index):
    (tmp_path / "fixture.json").write_text(json.dumps({"OPENAI_API_KEY": SECRET, "values": list(range(110_000))}))
    findings, ctx = _scan(index, tmp_path)
    secret = next(f for f in findings if f.kind == Kind.SECRET)
    assert ctx.stats is not None and any("excerpts withheld" in e for e in ctx.stats.errors)
    assert all(not e.snippet for e in secret.evidence)
    assert SECRET not in json.dumps([f.to_dict() for f in findings])


def test_multiline_structured_secret_keeps_excerpt_lines_aligned(tmp_path, index):
    (tmp_path / "config.toml").write_text(
        '[llm]\npassword = """\nabcdefgh\nijklmnop"""\nendpoint = "https://api.openai.com/v1"\nmodel_name = "unrelated-line-six"\n'
    )
    findings, ctx = _scan(index, tmp_path)
    domain_evidence = [e for f in findings for e in f.evidence if e.signal.startswith("domain:")]
    expected = 'endpoint = "https://api.openai.com/v1"'
    assert domain_evidence and all(e.location == "config.toml:5" and e.snippet == expected for e in domain_evidence)
    assert "abcdefgh" not in json.dumps([f.to_dict() for f in findings])


def test_directory_exclusion_names_do_not_skip_files(tmp_path, index):
    (tmp_path / "build").write_text(f"#!/bin/sh\nexport OPENAI_API_KEY={SECRET}\n")
    for config in ({}, {"exclude": ["*.log"]}):
        findings, ctx = _scan(index, tmp_path, **config)
        assert any(f.kind == Kind.SECRET for f in findings) and ctx.stats.objects_examined == 1
    (tmp_path / "build").unlink()
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "out.py").write_text(f"KEY = '{SECRET}'\n")
    findings, _ = _scan(index, tmp_path)
    assert not findings, "the build directory itself is still excluded"


def test_containerfile_is_parsed_like_a_dockerfile():
    text = "FROM ghcr.io/berriai/litellm:main-latest\nENV OPENAI_API_KEY=\n"
    assert is_manifest_name("Containerfile")
    assert [(a.kind, a.value) for a in parse_manifest("Containerfile", text).artifacts] == \
        [(a.kind, a.value) for a in parse_manifest("Dockerfile", text).artifacts]


def test_notebook_outputs_and_markdown_cells_are_scanned_for_credentials(tmp_path, index):
    notebook = {"cells": [
        {"cell_type": "code", "source": ["import os\n"], "outputs": [{"output_type": "stream", "name": "stdout", "text": [SECRET + "\n"]}]},
        {"cell_type": "markdown", "source": ["Use key `" + SECRET + "` for the demo\n"]},
    ], "metadata": {}, "nbformat": 4, "nbformat_minor": 5}
    (tmp_path / "demo.ipynb").write_text(json.dumps(notebook))
    findings, ctx = _scan(index, tmp_path)
    secret = next(f for f in findings if f.kind == Kind.SECRET)
    assert secret.metadata["count"] == 1 and not ctx.stats.errors
    assert SECRET not in json.dumps([f.to_dict() for f in findings])


def test_agent_definition_and_manifest_aggregates_are_bounded(tmp_path, index):
    agents = tmp_path / ".claude" / "agents"
    agents.mkdir(parents=True)
    for i in range(60):
        (agents / f"a{i}.md").write_text("---\nname: a\ntools:\n" + "".join(f"  - t{j}\n" for j in range(300)) + "---\nbody\n")
    (tmp_path / "app.py").write_text("import openai\n")
    (tmp_path / "secrets.env").write_text(f"OPENAI_API_KEY={SECRET}\n")
    findings, ctx = _scan(index, tmp_path)
    project = next(f for f in findings if f.resource_type == "project")
    assert len(project.metadata["agent_definitions"]) == 50
    assert all(len(d["tools"]) == 50 for d in project.metadata["agent_definitions"])
    assert any("agent definition limit" in e for e in ctx.stats.errors)
    assert any(f.kind == Kind.SECRET for f in findings)


def test_ruby_block_comments_scan_in_linear_time():
    block = "=begin\nnote\n=end\nx = 1\n"
    small, large = block * 2_000, block * 32_000
    started = time.perf_counter()
    noncode_ranges(small, "ruby")
    small_time = time.perf_counter() - started
    started = time.perf_counter()
    noncode_ranges(large, "ruby")
    large_time = time.perf_counter() - started
    # Sixteen times the input must not cost more than 64 times the time (a
    # quadratic scan would cost 256 times); no absolute bound, since coverage
    # tracing on CI runners slows the loop by an interpreter-dependent factor.
    assert large_time < max(small_time, 0.005) * 64


def test_git_author_containing_the_separator_cannot_forge_fields(tmp_path, index, monkeypatch):
    (tmp_path / ".git").mkdir()
    ctx = ConnectorContext(config={"path": str(tmp_path), "use_git": True}, index=index)
    ctx.stats = ScanStats(connector="code.filesystem", started_at=now_iso())
    connector = FilesystemConnector(ctx)
    forged = "Eve|forged@example.com|2001-01-01T00:00:00+00:00\x00a@b.c\x002026-01-01T00:00:00+00:00"

    def fake_run(argv, **kwargs):
        assert "--format=%an%x00%ae%x00%cI" in argv
        return subprocess.CompletedProcess(argv, 0, stdout=forged, stderr="")

    monkeypatch.setattr(fs_module.subprocess, "run", fake_run)
    info = connector._git_info(tmp_path, ".")
    assert info == {"last_author": "Eve|forged@example.com|2001-01-01T00:00:00+00:00", "last_author_email": "a@b.c",
                    "last_commit": "2026-01-01T00:00:00+00:00"}
    monkeypatch.setattr(fs_module.subprocess, "run", lambda argv, **kw: subprocess.CompletedProcess(argv, 0, stdout="a\x00b\x00not-a-date", stderr=""))
    assert connector._git_info(tmp_path, ".") == {} and ctx.stats.warnings


def _blob(content: bytes) -> tuple[str, str]:
    sha = hashlib.sha1(b"blob %d\0" % len(content) + content).hexdigest()
    return sha, base64.b64encode(content).decode()


def test_api_mode_skips_an_unsafe_tree_path_instead_of_the_repository(tmp_path, index):
    good_sha, good_b64 = _blob(b"import openai\nclient = openai.OpenAI()\n")
    weird_sha, weird_b64 = _blob(b"print('hi')\n")
    tree = {"sha": "a" * 40, "truncated": False, "tree": [
        {"path": "src/app.py", "type": "blob", "mode": "100644", "size": 40, "sha": good_sha},
        {"path": "src\\legacy.py", "type": "blob", "mode": "100644", "size": 12, "sha": weird_sha},
    ]}
    blobs = {good_sha: {"encoding": "base64", "content": good_b64}, weird_sha: {"encoding": "base64", "content": weird_b64}}
    ctx = ConnectorContext(config={"repos": ["acme/demo"], "mode": "api", "token": "x", "use_git": False}, index=index, workdir=str(tmp_path))
    ctx.stats = ScanStats(connector="code.github", started_at=now_iso())
    connector = GitHubConnector(ctx)

    def fake_get(path, *args, **kwargs):
        if path.startswith("/repos/acme/demo/git/trees/"):
            return tree
        if path.startswith("/repos/acme/demo/git/blobs/"):
            return blobs[path.rsplit("/", 1)[-1]]
        raise AssertionError(path)

    connector.http.try_get_json = fake_get  # type: ignore[method-assign]
    connector.http.paginate_link = lambda *a, **k: iter([])  # type: ignore[method-assign]
    connector.mode = "api"
    repo = {"full_name": "acme/demo", "default_branch": "main", "owner": {"login": "acme"}, "html_url": "https://github.com/acme/demo"}
    findings = list(connector.analyze([repo]))
    assert [f.resource for f in findings] == ["github:acme/demo"] and not ctx.stats.errors
    tree["tree"][1]["path"] = "../escape.py"
    with pytest.raises(RuntimeError):
        connector._fetch_via_api(repo, str(tmp_path / "again"))
    assert any("unusual repository tree path skipped" in w for w in ctx.stats.warnings) and ctx.stats.incomplete


def test_api_mode_skips_a_path_directory_collision_instead_of_the_repository(tmp_path, index):
    # An untrusted tree listing is not guaranteed to be a real git tree: it
    # can list a path and a descendant of that same path as two separate
    # blobs. Writing the first as a file, then resolving the second's parent
    # directory, must cost only the second file, not the whole repository.
    parent_sha, parent_b64 = _blob(b"print('hi')\n")
    good_sha, good_b64 = _blob(b"import openai\nclient = openai.OpenAI()\n")
    nested_sha, nested_b64 = _blob(b"import openai\nclient = openai.OpenAI()\n")
    tree = {"sha": "a" * 40, "truncated": False, "tree": [
        {"path": "app.py", "type": "blob", "mode": "100644", "size": 12, "sha": parent_sha},
        {"path": "src/good.py", "type": "blob", "mode": "100644", "size": 40, "sha": good_sha},
        {"path": "app.py/nested.py", "type": "blob", "mode": "100644", "size": 40, "sha": nested_sha},
    ]}
    blobs = {
        parent_sha: {"encoding": "base64", "content": parent_b64},
        good_sha: {"encoding": "base64", "content": good_b64},
        nested_sha: {"encoding": "base64", "content": nested_b64},
    }
    ctx = ConnectorContext(config={"repos": ["acme/demo"], "mode": "api", "token": "x", "use_git": False}, index=index, workdir=str(tmp_path))
    ctx.stats = ScanStats(connector="code.github", started_at=now_iso())
    connector = GitHubConnector(ctx)

    def fake_get(path, *args, **kwargs):
        if path.startswith("/repos/acme/demo/git/trees/"):
            return tree
        if path.startswith("/repos/acme/demo/git/blobs/"):
            return blobs[path.rsplit("/", 1)[-1]]
        raise AssertionError(path)

    connector.http.try_get_json = fake_get  # type: ignore[method-assign]
    connector.http.paginate_link = lambda *a, **k: iter([])  # type: ignore[method-assign]
    connector.mode = "api"
    repo = {"full_name": "acme/demo", "default_branch": "main", "owner": {"login": "acme"}, "html_url": "https://github.com/acme/demo"}
    findings = list(connector.analyze([repo]))
    assert [f.resource for f in findings] == ["github:acme/demo"]
    assert any("cannot write fetched content" in w for w in ctx.stats.warnings) and ctx.stats.incomplete


def test_per_repository_contexts_share_the_diagnostic_cap(tmp_path, index):
    for name in ("acme__r1", "acme__r2", "acme__r3"):
        repo = tmp_path / name
        repo.mkdir()
        for i in range(1100):
            (repo / f"f{i}.py").write_text("ab")
    ctx = ConnectorContext(config={"input": str(tmp_path), "max_file_size": 1, "strict_coverage": True}, index=index)
    GitHubConnector(ctx).run()
    assert len(ctx.stats.errors) == ConnectorContext._MAX_DIAGNOSTICS + 1
    assert sum("diagnostic limit reached" in e for e in ctx.stats.errors) == 1


@pytest.mark.parametrize("source, ambiguous", [
    ("x = '''never closed\nimport openai\n", False),  # EOF in a multi-line literal masks the rest
    ("import openai\nx = (1,\n", False),
])
def test_python_eof_errors_remain_unambiguous(source, ambiguous):
    spans, flagged = noncode_ranges(source, "python")
    assert flagged is ambiguous


def test_unclosed_one_line_string_masks_only_its_line():
    # Python 3.11 tokenizes past an unclosed one-line literal (ERRORTOKEN);
    # 3.12+ raises TokenError there. Both must mask that line only and keep
    # scanning the rest of the file as complete coverage.
    source = (
        'a = "never closed; StateGraph(\n'
        'import openai\n'
        "b = 'also open\n"
        'from langgraph.graph import StateGraph\n'
    )
    spans, flagged = noncode_ranges(source, "python")
    assert flagged is False

    def masked(index: int) -> bool:
        return any(start <= index < end for start, end in spans)

    assert masked(source.index("StateGraph(")) and masked(source.index("also open"))
    assert not masked(source.index("import openai")) and not masked(source.index("from langgraph"))
    assert not masked(source.index("a = ")) and not masked(source.index("b = "))


def test_many_unclosed_one_line_strings_reuse_a_single_reader(monkeypatch):
    # Recreating StringIO from every remaining suffix makes malformed source
    # quadratic within the normal one-megabyte file limit.
    source = ('value = "never closed; StateGraph(\n' * 8_000) + 'import openai\n'
    original = source_ranges.io.StringIO
    allocations = []

    def tracked_reader(value):
        allocations.append(len(value))
        return original(value)

    with monkeypatch.context() as patch:
        patch.setattr(source_ranges.io, "StringIO", tracked_reader)
        spans, incomplete = noncode_ranges(source, "python")
    assert allocations == [len(source)]
    assert not incomplete and len(spans) == 8_000
    assert not any(start <= source.index("import openai") < end for start, end in spans)


def test_unclosed_python_quote_with_standalone_cr_preserves_later_code():
    # API-mode source bytes can contain CR-only line endings, even though
    # local text files normally get universal-newline conversion by open().
    source = 'x = "inert StateGraph(\rimport openai\r'
    spans, incomplete = noncode_ranges(source, "python")
    assert not incomplete
    assert any(start <= source.index("StateGraph(") < end for start, end in spans)
    assert not any(start <= source.index("import openai") < end for start, end in spans)


def test_resumed_python_lexing_keeps_offsets_after_unicode_separators():
    source = 'x = "inert\u2028junk\u2028junk2\nimport openai; API_KEY="opaque-credential"\n'
    spans, incomplete = noncode_ranges(source, "python")
    assert not incomplete
    assert not any(start <= source.index("import openai") < end for start, end in spans)
    secret_start = source.index("opaque-credential")
    assert any(start <= secret_start and secret_start + len("opaque-credential") <= end for start, end in spans)
