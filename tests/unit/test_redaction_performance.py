"""URL credentials stay private without retrying unbounded query prefixes."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from shadowscan.utils.redaction import REDACTED, sanitize_text

ROOT = Path(__file__).resolve().parents[2]
SECRET = "opaque-value-with-no-provider-prefix"


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        (
            f"https://example.test/path?%61pi%5Fkey={SECRET}&model=test#state=next",
            f"https://example.test/path?%61pi%5Fkey={REDACTED}&model=test#state=next",
        ),
        (
            f"https://example.test/#access_token={SECRET}&state=next",
            f"https://example.test/#access_token={REDACTED}&state=next",
        ),
        (
            f"https://user:{SECRET}@example.test?token={SECRET}&contact=a@b.test",
            f"https://{REDACTED}@example.test?token={REDACTED}&contact=a@b.test",
        ),
        (
            f"https://example.test?contact=a@b.test&signature={SECRET}",
            f"https://example.test?contact=a@b.test&signature={REDACTED}",
        ),
        (
            f"https://example.test?token={SECRET}?private-suffix&safe=a?b#code={SECRET}",
            f"https://example.test?token={REDACTED}&safe=a?b#code={REDACTED}",
        ),
        (
            f"https://example.test?token={SECRET}&token={SECRET}#%70assword={SECRET}",
            f"https://example.test?token={REDACTED}&token={REDACTED}#%70assword={REDACTED}",
        ),
        (
            "https://example.test/path?&&q=ordinary??text&flag#fragment",
            "https://example.test/path?&&q=ordinary??text&flag#fragment",
        ),
    ],
)
def test_url_redaction_preserves_structure_and_is_idempotent(url, expected):
    safe = sanitize_text(url)
    assert safe == expected
    assert SECRET not in safe
    assert sanitize_text(safe) == safe


PASSWORD_WITH_RESERVED = "Zq7?k3PzW9aLmQ"


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        # A password that holds a raw '?', '#' or '/' ends the authority early; the
        # userinfo runs to the last '@' that is followed by a host.
        (
            f'OpenAI(base_url="https://svc_llm:{PASSWORD_WITH_RESERVED}@llm-gw.corp.example/v1")',
            f'OpenAI(base_url="https://{REDACTED}@llm-gw.corp.example/v1")',
        ),
        ("postgres://u:Pass#word@h", f"postgres://{REDACTED}@h"),
        ("postgres://u:Pass#word@h/db", f"postgres://{REDACTED}@h/db"),
        ("redis://:p#w@h", f"redis://{REDACTED}@h"),
        ("redis://:1234#w@h", f"redis://{REDACTED}@h"),
        (
            "postgres://u:pa/ss@host:5432/db?sslmode=require",
            f"postgres://{REDACTED}@host:5432/db?sslmode=require",
        ),
        ("amqp://guest:g?u=e&st@broker:5672/vhost", f"amqp://{REDACTED}@broker:5672/vhost"),
        ("postgres://u:Pass#word@[::1]:5432/db", f"postgres://{REDACTED}@[::1]:5432/db"),
        # The userinfo of an ordinary URL is read as before.
        ("https://user:pw@host/p?next=x@y", f"https://{REDACTED}@host/p?next=x@y"),
    ],
)
def test_url_userinfo_with_reserved_characters_is_withheld(url, expected):
    safe = sanitize_text(url)
    assert safe == expected
    assert PASSWORD_WITH_RESERVED not in safe
    assert sanitize_text(safe) == safe


@pytest.mark.parametrize(
    "text",
    [
        # An '@' in the path, query or fragment of an ordinary authority is not userinfo.
        "https://host/path?x=a@b",
        "https://host:8080/path?x=a@b",
        "https://host/path@file",
        "https://host/#/users/@me",
        "https://example.com/profile/@alice",
        "https://[::1]:8080/x?y=a@b",
        "file:///home/bob/node_modules/@types/node/index.d.ts",
        "https://${HOST}:${PORT}/users/@me",
        "https://{host}:{port}/users/@me",
        "https://{{ host }}:{{ port }}/users/@me",
        # Text that is no URL with userinfo.
        "contact bob@example.com about https://example.com:8443/x",
        "git@github.com:org/repo.git",
        "https://x:y",
        "http://svc:abc/path/to/foo@",
    ],
)
def test_url_text_without_userinfo_is_preserved(text):
    assert sanitize_text(text) == text


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # A URL inside another one's match: after a ',' or ';' (connection and
        # broker lists), in a query value, a path or a fragment.
        (
            f"redis://:{SECRET}@cache:6379,redis://:{SECRET}@cache2:6379",
            f"redis://{REDACTED}@cache:6379,redis://{REDACTED}@cache2:6379",
        ),
        (
            f"DATABASE_URLS=postgres://u:{SECRET}@h1/db;postgres://u:{SECRET}@h2/db",
            f"DATABASE_URLS=postgres://{REDACTED}@h1/db;postgres://{REDACTED}@h2/db",
        ),
        (
            f"https://a.example/login?next=https://user:{SECRET}@b.example/x&y=1",
            f"https://a.example/login?next=https://{REDACTED}@b.example/x&y=1",
        ),
        (
            f"https://a.example/r?next=ftp://user:{SECRET}@b.example&x=1",
            f"https://a.example/r?next=ftp://{REDACTED}@b.example&x=1",
        ),
        (
            f"https://a.example,https://user:{SECRET}@b.example",
            f"https://a.example,https://{REDACTED}@b.example",
        ),
        (
            f"https://a.example/proxy/https://user:{SECRET}@b.example/x",
            f"https://a.example/proxy/https://{REDACTED}@b.example/x",
        ),
        (
            f"https://a.example/r#https://user:{SECRET}@b.example",
            f"https://a.example/r#https://{REDACTED}@b.example",
        ),
        (
            f"https://u:{SECRET}@a.example/?u=https://u2:{SECRET}@b.example",
            f"https://{REDACTED}@a.example/?u=https://{REDACTED}@b.example",
        ),
        # A password with a raw '#' in the inner URL, as in the outer one.
        (
            f"https://a.example/?u=postgres://u:Pass#{SECRET}@h/db",
            f"https://a.example/?u=postgres://{REDACTED}@h/db",
        ),
        # The inner URL's credential query fields, as in the outer one.
        (
            f"https://a.example/r?next=https://b.example/?auth={SECRET}&x=1,https://c.example/?pat={SECRET}",
            f"https://a.example/r?next=https://b.example/?auth={REDACTED}&x=1,https://c.example/?pat={REDACTED}",
        ),
        # A name the assignment rules read keeps its value withheld.
        (
            f"https://a.example/?x=https://password=@{SECRET}",
            f"https://a.example/?x=https://password={REDACTED}",
        ),
        # An inner URL without userinfo is kept.
        (
            "https://a.example/login?next=https://b.example/p?x=a@b",
            "https://a.example/login?next=https://b.example/p?x=a@b",
        ),
        (
            "https://web.archive.org/web/2020/https://example.com/@alice",
            "https://web.archive.org/web/2020/https://example.com/@alice",
        ),
    ],
)
def test_a_url_inside_another_is_read_as_a_url(text, expected):
    # The URL match runs to the first blank or quote, and only its first
    # authority was read: the inner URL's password was shown.
    safe = sanitize_text(text)
    assert safe == expected
    assert sanitize_text(safe) == safe


def _bounded_process(script: str, *args: str) -> None:
    # This generous bound distinguishes linear work (well below a second on
    # ordinary hardware) from the former quadratic retry, which takes minutes.
    # No small wall-clock threshold or machine-dependent timing ratio is used.
    result = subprocess.run(
        [sys.executable, "-c", script, *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_unmatched_url_query_prefix_has_bounded_work():
    _bounded_process("""
from shadowscan.utils.redaction import REDACTED, sanitize_text
url = 'https://example.test/' + '?' * 500_000
assert sanitize_text(url) == url
assert sanitize_text(url + '&%74oken=opaque-secret') == url + '&%74oken=' + REDACTED
""")


def test_unmatched_very_long_identifier_has_bounded_work():
    # The identifier cannot be retried at each internal dot or hyphen.
    _bounded_process("""
from shadowscan.utils.redaction import REDACTED, sanitize_text
key = 'segment.' * 40_000 + 'API_KEY'
source = key + ' ' * 50_000
assert sanitize_text(source) == source
secret = 'opaque-synthetic-value'
safe = sanitize_text(key + ' = "' + secret + '"')
assert secret not in safe and REDACTED in safe
""")


def test_full_source_scan_survives_hostile_url_preprocessing(tmp_path):
    (tmp_path / "a.py").write_text(
        "url = 'https://example.test/" + "?" * 500_000 + "'\n",
        encoding="utf-8",
    )
    (tmp_path / "b.py").write_text("from crewai import Agent\n", encoding="utf-8")
    _bounded_process(
        """
import sys
from shadowscan.connectors.base import ConnectorContext
from shadowscan.connectors.code.filesystem import FilesystemConnector
from shadowscan.signatures import get_index
ctx = ConnectorContext(config={
    'path': sys.argv[1], 'use_git': False, 'scan_timeout': 0.05,
}, index=get_index())
findings = FilesystemConnector(ctx).run()
assert ctx.stats.objects_examined == 2, ctx.stats
assert any('framework.crewai' in finding.frameworks for finding in findings), ctx.stats
""",
        str(tmp_path),
    )


def test_token_and_jwt_backstops_read_hostile_runs_in_linear_time():
    # The boundary before a token admits '_' and escapes, so a run of repeated
    # prefixes offers a start at every repeat. Reading the dots of 'eyJ-eyJ-...'
    # once per 'eyJ' took about a minute for this input.
    _bounded_process("""
from shadowscan.utils.redaction import REDACTED, sanitize_text
shapes = [
    'eyJ-' * 100_000, 'eyJ_' * 100_000, 'eyJa.' * 80_000, 'sk-proj-' * 50_000, 'sk-' + '-' * 400_000,
    'AKIA_' * 80_000, '%3D' * 130_000, '\\\\n' * 200_000, 'ghp_' * 100_000,
    'a' * 14 + '.atlasv1' * 50_000, 'eyJ_' * 50_000 + '.' * 50_000,
]
for shape in shapes:
    sanitize_text(shape)
jwt = 'eyJ' + 'a' * 20 + '.' + 'b' * 30 + '.' + 'c' * 20
assert sanitize_text('x ' + 'eyJ_' * 50_000 + jwt) == 'x ' + REDACTED
""")


def test_url_userinfo_scan_is_linear():
    # The last '@' and the end of the host are each found by one scan of the URL.
    _bounded_process("""
from shadowscan.utils.redaction import REDACTED, sanitize_text
url = 'postgres://u:p' + '#@x' * 150_000 + '/db'
safe = sanitize_text(url)
assert safe.startswith('postgres://' + REDACTED + '@'), safe[:40]
text = ' '.join(['https://u:' + 'a/' * 20 + 'b@h/p'] * 20_000)
assert sanitize_text(text).count(REDACTED) == 20_000
""")


def test_operator_patterns_read_hostile_text_in_linear_time():
    # Every operator is read whole by one atomic group, a name is read once, and a long
    # unterminated mapping is withheld in one scan.
    _bounded_process("""
from shadowscan.utils.redaction import SanitizationLimitError, sanitize_text
n = 200_000
shapes = [
    'password' + '=' * n, 'password' + '|' * n + '=', 'password ' + '=> ' * (n // 3), 'a=' * (n // 2),
    'password == ' * (n // 12), 'password ||= ' * (n // 13), 'api_key := ' * (n // 11), 'key ?= ' * (n // 7),
    'password' + '!=' * (n // 2), "'password' => 'x' ," * (n // 19), 'api_key.' * (n // 8) + '= 1',
    'key <' + '-' * n, 'password =~ /' * (n // 13), 'key ==== ' * (n // 9), 'password' + ' ' * n + '= x',
    'db_pass.=' * (n // 9), 'passphrase:' * (n // 11), ';Pwd=' * (n // 5), 'PuTTY-User-Key-File-2:' * (n // 22),
    'token => {' * (n // 10), '(token => ' * (n // 10),
]
for shape in shapes:
    try:
        sanitize_text(shape)
    except SanitizationLimitError:
        pass  # a nesting limit fails closed, quickly
""")


def test_quadratic_tokenizer_versions_pay_for_each_line_copy(monkeypatch):
    """CPython 3.12.0 to 3.12.3 copy the whole line into every token.

    Forced on here so every interpreter runs that path: a hostile long line
    must end in the fail-closed limit quickly, and ordinary text still redacts.
    """
    import time

    from shadowscan.utils import redaction_statements
    from shadowscan.utils.redaction import SanitizationLimitError

    monkeypatch.setattr(redaction_statements, "_TOKEN_COPIES_LINE", True)
    started = time.perf_counter()
    with pytest.raises(SanitizationLimitError):
        sanitize_text("cookie=a, " * 40_000)
    assert time.perf_counter() - started < 30.0
    assert sanitize_text(f'api_key = "{SECRET}"\nmodel = "x"') == f'api_key = "{REDACTED}"\nmodel = "x"'


def test_only_the_quadratic_tokenizer_versions_charge_line_copies():
    from shadowscan.utils.redaction_statements import _TOKEN_COPIES_LINE

    assert _TOKEN_COPIES_LINE is ((3, 12) <= sys.version_info[:3] < (3, 12, 4))
