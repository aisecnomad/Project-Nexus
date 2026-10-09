"""Binary content: Git stores skipped, NULs in string literals and legacy code pages read as text.

The real-world benchmark marked 10 of 183 scans incomplete for binary content.
87 of the 96 files were objects of Git repositories kept in the tree under
another name (a bare `name.git` fixture, a test's `dotGit`); three were
TypeScript sources with a NUL character in a string literal; two were text in a
legacy code page; the rest were test fixtures.
"""

from __future__ import annotations

import zlib
from pathlib import Path

import pytest

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.code.filesystem import FilesystemConnector

AGENT_SOURCE = 'from openai import OpenAI\n\nOpenAI().chat.completions.create(model="gpt-4o", messages=[])\n'


def _scan(run_connector, tmp_path: Path, **config):
    return run_connector("code.filesystem", path=str(tmp_path), use_git=False, **config)


def _git_store(path: Path, head: bytes = b"ref: refs/heads/main\n") -> None:
    (path / "objects" / "ab").mkdir(parents=True)
    (path / "objects" / "pack").mkdir()
    (path / "refs" / "heads").mkdir(parents=True)
    (path / "HEAD").write_bytes(head)
    (path / "config").write_text("[core]\n\tbare = true\n")
    (path / "index").write_bytes(b"DIRC\x00\x00\x00\x02" + b"\x00" * 64)
    (path / "objects" / "ab" / "cdef0123456789").write_bytes(zlib.compress(b"blob 5\x00hello"))
    (path / "refs" / "heads" / "main").write_text("0" * 40 + "\n")


@pytest.mark.parametrize("name", ["fixtures/remote.git", "testdata/repos/small/dotGit"])
def test_git_repository_store_is_skipped(tmp_path: Path, run_connector, name: str) -> None:
    _git_store(tmp_path / name)
    (tmp_path / "app.py").write_text(AGENT_SOURCE)
    findings, ctx = _scan(run_connector, tmp_path, include_tests=True)
    assert findings and not ctx.stats.incomplete and not ctx.stats.errors
    assert any(f"{name}: skipped Git repository store" in w for w in ctx.stats.warnings)


def test_directory_with_other_entries_is_not_a_git_store(tmp_path: Path, run_connector) -> None:
    store = tmp_path / "remote.git"
    _git_store(store)
    (store / "agent.py").write_text(AGENT_SOURCE)
    findings, ctx = _scan(run_connector, tmp_path)
    assert any(f.metadata.get("path") == "remote.git" for f in findings) or any(
        any(e.location.startswith("remote.git/agent.py") for e in f.evidence) for f in findings
    )
    assert not any("skipped Git repository store" in w for w in ctx.stats.warnings)
    assert ctx.stats.incomplete  # its objects are still binary content


def test_git_store_needs_a_valid_head(tmp_path: Path, run_connector) -> None:
    _git_store(tmp_path / "remote.git", head=b"not a head\n")
    _, ctx = _scan(run_connector, tmp_path)
    assert not any("skipped Git repository store" in w for w in ctx.stats.warnings)
    assert ctx.stats.incomplete


def test_nul_in_a_string_literal_is_text(tmp_path: Path, run_connector) -> None:
    source = "import OpenAI from 'openai';\nconst client = new OpenAI();\nexport const key = ['a', 'b'].join('\x00');\n"
    (tmp_path / "planDock.ts").write_text(source)
    findings, ctx = _scan(run_connector, tmp_path)
    assert findings and not ctx.stats.incomplete


def test_utf16_without_a_byte_order_mark_stays_a_gap(tmp_path: Path, run_connector) -> None:
    (tmp_path / "agent.ts").write_bytes("import OpenAI from 'openai';\n".encode("utf-16-le"))
    _, ctx = _scan(run_connector, tmp_path)
    assert ctx.stats.incomplete
    assert any("binary or undecodable content" in e for e in ctx.stats.errors)


def test_legacy_code_page_text_is_analyzed(tmp_path: Path, run_connector) -> None:
    (tmp_path / "agent.py").write_bytes(("# Résumé générateur\n" + AGENT_SOURCE).encode("cp1252"))
    findings, ctx = _scan(run_connector, tmp_path)
    assert any("provider.openai" in f.model_providers for f in findings)
    assert not ctx.stats.incomplete
    assert any("agent.py: not valid UTF-8; undecodable bytes replaced" in w for w in ctx.stats.warnings)


def test_legacy_code_page_text_stays_a_gap_for_non_ascii_signatures(tmp_path: Path, index) -> None:
    (tmp_path / "agent.py").write_bytes(("# Résumé\n" + AGENT_SOURCE).encode("cp1252"))
    ctx = ConnectorContext(config={"path": str(tmp_path), "use_git": False}, index=index)
    connector = FilesystemConnector(ctx)
    connector._ascii_signatures = False  # as when a custom pack matches non-ASCII text
    connector.run()
    assert ctx.stats.incomplete
    assert any("binary or undecodable content" in e for e in ctx.stats.errors)


def test_binary_content_in_test_code_follows_the_test_code_policy(tmp_path: Path, run_connector) -> None:
    (tmp_path / "tests" / "data").mkdir(parents=True)
    (tmp_path / "tests" / "data" / "dhcp").write_bytes(b"\x01\x02" + b"\x00" * 300)
    (tmp_path / "tests" / "test_encryption.ts").write_bytes(b"\x00\x01\x02" * 300)
    _, ctx = _scan(run_connector, tmp_path)
    assert not ctx.stats.incomplete
    assert sum("binary or undecodable content" in w for w in ctx.stats.warnings) == 2
    _, included = _scan(run_connector, tmp_path, include_tests=True)
    assert included.stats.incomplete
