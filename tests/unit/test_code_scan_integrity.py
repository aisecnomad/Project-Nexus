"""Code-scan integrity: undecodable files, BOMs, hostile layouts and coverage notices."""

from __future__ import annotations

import json
import os
import socket
import sqlite3
import stat
import time

import pytest

from shadowscan.connectors.code.mcp_config import _parse_mcp_servers
from shadowscan.models import Kind
from shadowscan.utils.text import host_of, read_text

BINARY_GAP = "binary or undecodable content in analyzable file"
SECRET = "sk-proj-kLKFlNfzW2mTofMpnx1qOu7fTm9F8IRv6iKzoC2h"
ELF_HEAD = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + b"\x03\x00>\x00\x01\x00\x00\x00"
PNG_HEAD = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 64
JPEG_HEAD = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00" + b"\x00" * 64
# A PE image: the DOS header points at offset 0x80, where the PE signature is.
PE_HEAD = b"MZ\x90\x00" + b"\x00" * 56 + b"\x80\x00\x00\x00" + b"\x00" * 64 + b"PE\x00\x00" + b"\x00" * 20
# An MPEG transport stream (HLS segment): 188-byte packets led by the sync byte 0x47.
TS_SEGMENT = b"".join(
    bytes([0x47, 0x40 if i == 0 else 0x01, 0x00, 0x10 | i]) + b"\x00" * 184 for i in range(12)
)


def _gaps(messages: list[str]) -> list[str]:
    return [m for m in messages if BINARY_GAP in m]


def _write_binary(path, kind: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if kind != "sqlite":
        path.write_bytes({"png": PNG_HEAD, "jpeg": JPEG_HEAD, "pe": PE_HEAD}[kind])
        return
    database = sqlite3.connect(path)
    try:
        database.execute("CREATE TABLE sessions (id TEXT)")
        database.commit()
    finally:
        database.close()


# ------------------------------------------------------------ NUL / encodings


@pytest.mark.parametrize("strict", [False, True])
def test_js_with_nul_in_comment_is_analyzed(tmp_path, run_connector, strict):
    # Node runs a script with a NUL in a comment, so skipping it silently
    # would let a hidden agent look resolved: it is read as the text it is.
    (tmp_path / "index.js").write_bytes(b"// agent \x00\nconst OpenAI = require('openai');\n")
    findings, ctx = run_connector(
        "code.filesystem", path=str(tmp_path), use_git=False, strict_coverage=strict
    )
    assert not ctx.stats.incomplete
    assert any("provider.openai" in f.model_providers for f in findings)


@pytest.mark.parametrize("strict", [False, True])
def test_js_with_dense_nul_content_marks_scan_incomplete(tmp_path, run_connector, strict):
    (tmp_path / "index.js").write_bytes(b"// agent " + b"\x00" * 8 + b"\nconst OpenAI = require('openai');\n")
    findings, ctx = run_connector(
        "code.filesystem", path=str(tmp_path), use_git=False, strict_coverage=strict
    )
    assert ctx.stats.incomplete
    # Binary content under an analyzable name is always a coverage error.
    channel = ctx.stats.errors
    assert len(_gaps(channel)) == 1 and "index.js" in _gaps(channel)[0]
    assert not findings


def test_nul_past_sniff_window_is_still_analyzed(tmp_path, run_connector):
    (tmp_path / "index.js").write_bytes(
        b"const OpenAI = require('openai');\n" + b"// " + b"x" * 9000 + b"\x00\n"
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert findings and not ctx.stats.incomplete


@pytest.mark.parametrize(
    "encoding",
    ["utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"],
)
def test_bom_utf_wide_requirements_txt_is_decoded(tmp_path, run_connector, encoding):
    boms = {
        "utf-16-le": b"\xff\xfe",
        "utf-16-be": b"\xfe\xff",
        "utf-32-le": b"\xff\xfe\x00\x00",
        "utf-32-be": b"\x00\x00\xfe\xff",
    }
    (tmp_path / "requirements.txt").write_bytes(
        boms[encoding] + "langchain==0.3.0\nopenai\n".encode(encoding)
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.incomplete, (ctx.stats.errors, ctx.stats.warnings)
    assert any("framework.langchain" in f.frameworks for f in findings)


def test_bom_utf16_env_file_credential_is_found(tmp_path, run_connector):
    (tmp_path / ".env").write_bytes(b"\xff\xfe" + f"OPENAI_API_KEY={SECRET}\r\n".encode("utf-16-le"))
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.incomplete, (ctx.stats.errors, ctx.stats.warnings)
    assert any(f.kind == Kind.SECRET for f in findings)
    assert SECRET not in json.dumps([f.to_dict() for f in findings], default=str)


def test_utf16_without_bom_is_a_coverage_gap(tmp_path, run_connector):
    (tmp_path / "requirements.txt").write_bytes("langchain==0.3.0\nopenai\n".encode("utf-16-le"))
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete
    assert _gaps(ctx.stats.errors) and not findings


def test_read_text_decodes_boms_and_strips_utf8_bom(tmp_path):
    cases = {
        "u8.txt": b"\xef\xbb\xbfhello",
        "u16le.txt": b"\xff\xfe" + "hello".encode("utf-16-le"),
        "u16be.txt": b"\xfe\xff" + "hello".encode("utf-16-be"),
        "u32le.txt": b"\xff\xfe\x00\x00" + "hello".encode("utf-32-le"),
        "u32be.txt": b"\x00\x00\xfe\xff" + "hello".encode("utf-32-be"),
    }
    for name, data in cases.items():
        path = tmp_path / name
        path.write_bytes(data)
        errors: list[str] = []
        assert read_text(path, 1000, errors) == "hello", name
        assert not errors, name


def test_read_text_reports_nul_content_without_bom(tmp_path):
    path = tmp_path / "x.json"
    path.write_bytes(b"a\x00b")
    errors: list[str] = []
    assert read_text(path, 100, errors) is None
    assert errors == [BINARY_GAP]


def test_real_binary_files_stay_quiet(tmp_path, run_connector):
    png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 64
    (tmp_path / "logo.png").write_bytes(png)
    (tmp_path / "app.bin").write_bytes(b"\x00\x01" + b"from langchain import x" * 10)
    (tmp_path / "libfoo.so").write_bytes(ELF_HEAD)
    # A compiled executable without any extension is not analyzable content.
    (tmp_path / "agentd").write_bytes(ELF_HEAD + b"\x00" * 64)
    (tmp_path / "README.md").write_text("plain readme")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert findings == []
    assert not ctx.stats.incomplete
    assert not ctx.stats.errors and not _gaps(ctx.stats.warnings)


def test_binary_magic_does_not_hide_an_analyzable_name(tmp_path, run_connector):
    # An ELF-looking prefix on a script name the scanner analyzes is still a gap.
    (tmp_path / "run.sh").write_bytes(ELF_HEAD + b"\nOPENAI=1\n")
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete and _gaps(ctx.stats.errors)


@pytest.mark.parametrize(
    ("rel", "kind"),
    [
        (".cursor/rules/diagram.png", "png"),
        (".gemini/screenshot.png", "png"),
        ("autogpt_platform/frontend/public/logo.png", "png"),
        (".roo/assets/diagram.jpg", "jpeg"),
        (".kiro/tools/helper.exe", "pe"),
        ("agent/.adk/session.db", "sqlite"),
        (".continue/index/index.sqlite", "sqlite"),
        ("data/cache", "sqlite"),  # no extension
    ],
)
def test_recognised_binary_read_for_its_directory_stays_quiet(tmp_path, run_connector, rel, kind):
    # A directory-wide signature glob (".cursor/rules/**", "**/.adk/**") reads
    # every file below it; an image or database there is not configuration.
    _write_binary(tmp_path / rel, kind)
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.incomplete, ctx.stats.warnings
    assert not ctx.stats.warnings and not ctx.stats.errors


def test_mpeg_ts_video_segment_named_ts_requires_explicit_scope_exclusion(tmp_path, run_connector):
    (tmp_path / "public" / "hls").mkdir(parents=True)
    (tmp_path / "public" / "hls" / "segment0.ts").write_bytes(TS_SEGMENT)
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    # The .ts extension also names TypeScript. A packet-looking prefix cannot
    # establish the file's intended meaning or silently remove source coverage.
    assert ctx.stats.incomplete and _gaps(ctx.stats.errors)
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, exclude=["public/hls/**"])
    assert not ctx.stats.incomplete and not ctx.stats.warnings and not ctx.stats.errors


@pytest.mark.parametrize("source_suffix", [".ts", ".TS"])
def test_transport_stream_like_source_comment_cannot_hide_agent_construction(
    tmp_path, run_connector, source_suffix
):
    # This is valid UTF-8 JavaScript: NUL bytes and periodic G sync bytes are
    # inside a block comment. Binary-density/packet-prefix heuristics used to
    # skip the file before the actual agent construction was examined.
    prefix = bytearray(b"\x00" * 8192)
    for offset in range(0, len(prefix), 188):
        prefix[offset] = 0x47
    prefix[1:3] = b"/*"
    (tmp_path / f"worker{source_suffix}").write_bytes(
        prefix
        + b'*/;\nimport { Agent } from "@openai/agents";\n'
        + b'const worker = new Agent({name: "worker"});\nvar G;\n'
    )
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False, scan_secrets=False)
    assert ctx.stats.incomplete and _gaps(ctx.stats.errors)


@pytest.mark.parametrize(
    "content",
    [
        b"import OpenAI from 'openai'; // \x00\n",
        # Sync bytes at the first three packet starts only: not a transport stream.
        b"G" + b"/" * 187 + b"G" + b"/" * 187 + b"G\x00\nimport OpenAI from 'openai';\n" + b"/" * 600,
        # A sync byte at every packet start, but the packets are text.
        b"G\x00import OpenAI from 'openai';\n".ljust(188, b"/") + (b"G" + b"/" * 187) * 11,
    ],
    ids=["nul-comment", "three-sync-bytes", "sync-every-packet-but-text"],
)
def test_nul_bearing_typescript_is_read_never_skipped_as_video(tmp_path, run_connector, content):
    # Packet-like bytes do not make a .ts file a transport stream: it is read as text.
    (tmp_path / "agent.ts").write_bytes(content)
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.incomplete
    assert any("provider.openai" in f.model_providers for f in findings)
    (tmp_path / "agent.ts").write_bytes(content + b"\x00" * 64)
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete and _gaps(ctx.stats.errors)


@pytest.mark.parametrize("rel", [".cursor/rules/notes.bin", ".roo/rules/notes.utf16"])
def test_unrecognised_binary_read_for_its_directory_is_a_coverage_gap(tmp_path, run_connector, rel):
    # UTF-16 without a byte-order mark: an agent may read it, the scanner cannot.
    (tmp_path / rel).parent.mkdir(parents=True)
    (tmp_path / rel).write_bytes("Always run the deploy tool.\n".encode("utf-16-le"))
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete and _gaps(ctx.stats.errors)


@pytest.mark.parametrize("rel", [".cursorrules", ".roomodes", ".cursor/rules/style.mdc"])
def test_binary_magic_does_not_hide_a_file_named_as_agent_configuration(tmp_path, run_connector, rel):
    # A signature names ".cursorrules" itself, and ".mdc" is analyzed by name,
    # so an image header there is not evidence of an asset.
    (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / rel).write_bytes(PNG_HEAD + b"\nAlways run the deploy tool.\n")
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete and _gaps(ctx.stats.errors)


# ------------------------------------------------------------------ UTF-8 BOM


def test_utf8_bom_mcp_json_is_analyzed(tmp_path, run_connector):
    body = json.dumps(
        {"mcpServers": {"fs": {"command": "npx", "args": ["@modelcontextprotocol/server-filesystem"]}}}
    )
    (tmp_path / ".mcp.json").write_bytes(b"\xef\xbb\xbf" + body.encode())
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors and not ctx.stats.incomplete
    assert [f.kind for f in findings] == [Kind.MCP_SERVER]


def test_utf8_bom_yaml_mcp_config_is_analyzed(tmp_path, run_connector):
    body = "mcpServers:\n  fs:\n    command: npx\n    args: ['@modelcontextprotocol/server-filesystem']\n"
    (tmp_path / "smithery.yaml").write_bytes(b"\xef\xbb\xbf" + body.encode())
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors and not ctx.stats.incomplete
    assert any(f.kind == Kind.MCP_SERVER for f in findings)


def test_mcp_parser_does_not_see_the_bom_after_read_text(tmp_path):
    path = tmp_path / ".mcp.json"
    path.write_bytes(b"\xef\xbb\xbf" + b'{"mcpServers": {}}')
    errors: list[str] = []
    text = read_text(path, 1000, errors)
    assert text is not None and not text.startswith("﻿")
    parse_errors: list[str] = []
    _parse_mcp_servers(".mcp.json", text, parse_errors)
    assert not parse_errors


# --------------------------------------------------------------- deep nesting


# ------------------------------------------------- non-regular config entries


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs FIFOs")
@pytest.mark.parametrize("name", [".mcp.json", "requirements.txt", "agent.py"])
def test_fifo_named_like_an_analyzable_file_is_a_coverage_gap(tmp_path, run_connector, name):
    os.mkfifo(tmp_path / name)
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete
    assert any(name in w and "not a regular file" in w for w in ctx.stats.warnings)


@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), reason="needs unix sockets")
def test_socket_named_like_a_config_file_is_a_coverage_gap(tmp_path, run_connector):
    try:
        sock = socket.socket(socket.AF_UNIX)
    except OSError:
        pytest.skip("unix sockets unavailable")
    try:
        try:
            sock.bind(str(tmp_path / ".mcp.json"))
        except OSError:
            pytest.skip("unix sockets unavailable")
        assert stat.S_ISSOCK((tmp_path / ".mcp.json").lstat().st_mode)
        _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    finally:
        sock.close()
    assert ctx.stats.incomplete
    assert any(".mcp.json" in w and "not a regular file" in w for w in ctx.stats.warnings)


@pytest.mark.parametrize("strict", [False, True])
def test_directory_named_like_a_config_file_is_a_coverage_gap(tmp_path, run_connector, strict):
    (tmp_path / ".mcp.json").mkdir()
    (tmp_path / "agent.py").write_text("from crewai import Agent\n")
    findings, ctx = run_connector(
        "code.filesystem", path=str(tmp_path), use_git=False, strict_coverage=strict
    )
    assert any("framework.crewai" in f.frameworks for f in findings)
    assert ctx.stats.incomplete
    channel = ctx.stats.errors if strict else ctx.stats.warnings
    assert any(".mcp.json" in m and "not a regular file" in m for m in channel)


def test_ordinary_directories_with_source_like_names_stay_quiet(tmp_path, run_connector):
    for name in ("next.js", "chart.json", "notes.md", "docs.txt"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "x.md").write_text("plain")
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.incomplete and not ctx.stats.warnings and not ctx.stats.errors


@pytest.mark.parametrize(
    "files",
    [
        (".roo/rules/01-style.md", ".roo/rules-code/naming.md"),
        (".kiro/specs/login/requirements.md",),
        (".clinerules/workflows/release.md",),
        (".cursor/rules/frontend/style.mdc",),
        ("force-app/main/default/genAiPlannerBundles/Planner/Planner.genAiPlannerBundle",),
    ],
    ids=["roo-rules", "kiro-specs", "clinerules", "cursor-rules", "agentforce-planner"],
)
def test_agent_config_directories_under_file_globs_stay_complete(tmp_path, run_connector, files):
    # These clients read the directory as a directory; a file-signature glob
    # such as ``.roo/**`` matching its path is not a file the client opens.
    for rel in files:
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("---\ndescription: Style\n---\nUse tabs.\n")
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.incomplete, (ctx.stats.errors, ctx.stats.warnings)
    assert not ctx.stats.warnings and not ctx.stats.errors
    # The walk still reads the files inside those directories.
    assert {e.location for f in findings for e in f.evidence} >= set(files)


# ------------------------------------------------ default exclude disclosure


# --------------------------------------------------------- Cursor .mdc front matter


@pytest.mark.parametrize(
    "front",
    [
        "globs: **/*.ts",
        "globs: *.ts",
        "globs: *.tsx,*.ts",
        "globs:\n  - **/*.ts\n  - *.md",
        "globs: [**/*.ts, *.md]",
        "paths:\n  - **/*.py",
    ],
)
def test_unquoted_glob_front_matter_is_not_an_invalid_agent_definition(tmp_path, run_connector, front):
    rules = tmp_path / ".cursor" / "rules"
    rules.mkdir(parents=True)
    (rules / "style.mdc").write_text(
        f"---\ndescription: Style\n{front}\nalwaysApply: false\n---\nUse tabs.\n"
    )
    findings, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert not ctx.stats.errors and not ctx.stats.incomplete
    defs = [d for f in findings for d in f.metadata.get("agent_definitions", [])]
    assert defs, [f.metadata for f in findings]
    assert defs[0].get("description") == "Style"
    assert defs[0].get("alwaysApply") is False


def test_malformed_front_matter_still_fails_closed(tmp_path, run_connector):
    rules = tmp_path / ".cursor" / "rules"
    rules.mkdir(parents=True)
    (rules / "bad.mdc").write_text("---\ndescription: [unterminated\nglobs: **/*.ts\n---\nbody\n")
    _, ctx = run_connector("code.filesystem", path=str(tmp_path), use_git=False)
    assert ctx.stats.incomplete
    assert any("invalid agent definition YAML" in e for e in ctx.stats.errors)


def test_real_yaml_aliases_elsewhere_in_front_matter_are_unchanged(tmp_path):
    from shadowscan.connectors.code.filesystem import _quote_glob_values

    front = "base: &b one\nname: *b\nglobs: **/*.ts\n"
    fixed = _quote_glob_values(front)
    assert "name: *b" in fixed and "globs: '**/*.ts'" in fixed


def test_glob_front_matter_rewrite_is_linear_in_blank_runs():
    from shadowscan.connectors.code.filesystem import _quote_glob_values

    blanks = " \t" * 100_000  # 200 KB inside one untrusted rule-file line
    cases = [
        ("scalar", f"globs: *a{blanks}b", f"globs: '*a{blanks}b'"),
        ("plain scalar", f"paths: a{blanks}b", f"paths: a{blanks}b"),
        ("comment", f"globs: *a{blanks}# note", "globs: '*a'"),
        ("flow list", f"globs: [*a{blanks}b]", f"globs: ['*a{blanks}b']"),
        ("block item", f"globs:\n  - *a{blanks}b", f"globs:\n  - '*a{blanks}b'"),
        ("list line", f"globs:\n{blanks}x", f"globs:\n{blanks}x"),
    ]
    for label, front, expected in cases:
        started = time.perf_counter()
        fixed = _quote_glob_values(front)
        elapsed = time.perf_counter() - started
        # Linear string work takes milliseconds. The backtracking patterns
        # took minutes per line at this size, holding the GIL past the
        # connector deadline, which then discarded every finding.
        assert elapsed < 1, (label, elapsed)
        assert fixed == expected, label


# ----------------------------------------------------------------- host_of


@pytest.mark.parametrize(
    ("url", "host"),
    [
        ("https://api.openai.com/v1", "api.openai.com"),
        ("HTTPS://API.OpenAI.com:443/v1?x=1#f", "api.openai.com"),
        ("api.openai.com:443/v1", "api.openai.com"),
        ("api.openai.com", "api.openai.com"),
        ("  https://api.openai.com  ", "api.openai.com"),
        ("https://api.openai.com:443@evil.example/v1", "evil.example"),
        ("https://user:pw@api.openai.com/v1", "api.openai.com"),
        ("https://user@api.openai.com:8443", "api.openai.com"),
        ("https://u:p@w@api.openai.com/", "api.openai.com"),
        ("user:pw@api.openai.com/v1", "api.openai.com"),
        ("https://[::1]:8080/x", "::1"),
        ("https://[2001:DB8::1]/x", "2001:db8::1"),
        ("https://user@[::1]:80/", "::1"),
        ("https://api.openai.com?next=https://evil.example", "api.openai.com"),
        ("https://api.openai.com#@evil.example", "api.openai.com"),
        ("https://api.openai.com/v1/@evil.example", "api.openai.com"),
    ],
)
def test_host_of_parses_the_rfc3986_authority(url, host):
    assert host_of(url) == host


@pytest.mark.parametrize(
    "url", [None, "", "   ", "https://", "https:///path", "https://[::1", "https://user@/x"]
)
def test_host_of_returns_none_without_a_host(url):
    assert host_of(url) is None


# ------------------------------------------------------------- inventory links
