"""Redaction of CLI flags, shell/JSON text shapes, token formats and linear-time matching."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from shadowscan.models import Kind
from shadowscan.utils.redaction import (
    REDACTED,
    SanitizationLimitError,
    credential_id,
    sanitize,
    sanitize_text,
)

SECRET = "Zx9qOpaqueSecretValue7731"


def _json_in_string(value: str, escapes: int) -> str:
    """JSON text as it appears inside a string literal that escapes its quotes."""
    quote = "\\" * escapes + '"'
    return (
        "{"
        + quote
        + "api_key"
        + quote
        + ": "
        + quote
        + value
        + quote
        + ", "
        + quote
        + "model"
        + quote
        + ": 1}"
    )


def _clean(text: str) -> str:
    result = sanitize_text(text)
    assert SECRET not in result
    assert sanitize_text(result) == result
    return result


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (f"--api-key={SECRET}", f"--api-key={REDACTED}"),
        (f"--token={SECRET} --model gpt-example", f"--token={REDACTED} --model gpt-example"),
        (f"--db-password={SECRET}", f"--db-password={REDACTED}"),
        (f"--pat={SECRET}", f"--pat={REDACTED}"),
        (f"npx -y @acme/mcp-two --token {SECRET}", f"npx -y @acme/mcp-two --token {REDACTED}"),
        (f"tool --pat {SECRET} --verbose", f"tool --pat {REDACTED} --verbose"),
        (f"tool --passphrase {SECRET}", f"tool --passphrase {REDACTED}"),
        (f"tool --key {SECRET}", f"tool --key {REDACTED}"),
        (f"tool --auth {SECRET}", f"tool --auth {REDACTED}"),
        (f"tool --secret {SECRET} run", f"tool --secret {REDACTED} run"),
        (f"tool --password '{SECRET} with spaces' run", f"tool --password '{REDACTED}' run"),
        (f'tool --token="{SECRET} x" run', f'tool --token="{REDACTED}" run'),
        (f"tool --token '{SECRET}", f"tool --token '{REDACTED}"),
        (
            f"curl -u admin:{SECRET} https://api.example.test/x",
            f"curl -u admin:{REDACTED} https://api.example.test/x",
        ),
        (f"curl --user admin:{SECRET}", f"curl --user admin:{REDACTED}"),
        (f"mysql -u root -p{SECRET} -h db.example.test", f"mysql -u root -p{REDACTED} -h db.example.test"),
    ],
)
def test_cli_flag_credentials_are_redacted_in_text(text, expected):
    assert _clean(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "tool --max-tokens 100 --model gpt-example",
        "tool --token --verbose",
        "tool --token",
        "docker run -p 8080:80 -u 1000:1000 image",
        "tool --key-file /etc/ssl/key.pem --password-file /run/pw",
        "mysql -p -h db.example.test",
        "tool --tokenizer gpt2 --keyboard us",
        "pip install --user package",
    ],
)
def test_cli_flag_redaction_leaves_ordinary_arguments(text):
    assert sanitize_text(text) == text


@pytest.mark.parametrize(
    "flag", ["--token", "--pat", "--passphrase", "--secret", "--password", "--key", "--auth"]
)
def test_argv_pairs_and_inline_flags_are_redacted_in_sanitize(flag):
    result = sanitize(
        {"command": "npx", "args": [flag, SECRET, "--model", "gpt-example", f"{flag}={SECRET}"]},
    )
    assert SECRET not in json.dumps(result)
    assert result["args"][2:4] == ["--model", "gpt-example"]
    # Siblings of a flag/value pair are scrubbed even where the pair is a tuple.
    assert SECRET not in json.dumps(sanitize({"args": (flag, SECRET), "copy": f"saw {SECRET}"}))


def test_mcp_server_arguments_do_not_reach_code_scan_findings(tmp_path: Path, run_connector):
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "one": {"command": "npx", "args": ["-y", "@acme/mcp-one", f"--api-key={SECRET}"]},
                    "two": {"command": f"npx -y @acme/mcp-two --token {SECRET}"},
                    "three": {"command": "npx", "args": ["-y", "@acme/mcp-three", "--pat", SECRET]},
                }
            }
        )
    )
    findings, _ = run_connector("code.filesystem", path=str(tmp_path))
    assert any(f.kind == Kind.MCP_SERVER for f in findings)
    assert SECRET not in json.dumps([f.to_dict() for f in findings], default=str)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (f'payload = "{_json_in_string(SECRET, 1)}"', f'payload = "{_json_in_string(REDACTED, 1)}"'),
        (_json_in_string(SECRET, 3), _json_in_string(REDACTED, 3)),
        (f"password:{SECRET}", f'password:"{REDACTED}"'),
        (f"x-api-key:{SECRET}", f'x-api-key:"{REDACTED}"'),
        (f"Cookie: a=1; sessionid={SECRET}", f'Cookie: "{REDACTED}"'),
        (f"Set-Cookie: sid={SECRET}; Path=/; HttpOnly", f'Set-Cookie: "{REDACTED}"'),
        (f"PASSWORD=Ab;tail{SECRET}", f'PASSWORD="{REDACTED}"'),
        (f"DB_PASSWORD=Ab;{SECRET}\nNEXT=1", f'DB_PASSWORD="{REDACTED}"\nNEXT=1'),
        (
            f"-----BEGIN PGP PRIVATE KEY BLOCK-----\n{SECRET}\n-----END PGP PRIVATE KEY BLOCK-----",
            f"{REDACTED}\n\n",
        ),
    ],
)
def test_text_shape_gaps_are_redacted(text, expected):
    assert _clean(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        json.dumps(f'HOST=db;\n:password => "{SECRET}"'),
        json.dumps(f"HOST=db;\r\nAPI_KEY: {SECRET}"),
        json.dumps(f'url=https://h/x;\n:secret => "{SECRET}"'),
    ],
)
def test_a_semicolon_before_an_escaped_line_break_ends_an_unquoted_value(text):
    # '\\n' is the line break of JSON-escaped text. Read as a ';' glued into
    # the value, it ran 'db' into the next line and took the credential's name.
    result = _clean(text)
    assert result.startswith('"HOST=db;') or result.startswith('"url=https://h/x;')


@pytest.mark.parametrize("depth", [1, 2, 3])
@pytest.mark.parametrize("value", [f'ab"cd{SECRET}', f"{SECRET}\\", f'a\\"b{SECRET}', f"x'{SECRET}"])
def test_escaped_json_values_close_at_their_own_delimiter(value, depth):
    # A quote inside the value, escaped one level deeper than its delimiter,
    # ends with a copy of that delimiter. The value closed there and the rest
    # of it was shown.
    text = json.dumps({"password": value, "model": 1})
    for _ in range(depth):
        text = json.dumps(text)
    result = _clean(text)
    assert REDACTED in result and "model" in result


_PGP_KEY = f"-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n{SECRET}\n=AbCd\n-----END PGP PRIVATE KEY BLOCK-----"


@pytest.mark.parametrize(
    ("prefix", "expected"),
    [
        ("private_key: ", f'private_key: "{REDACTED}"'),
        ("secret: ", f'secret: "{REDACTED}"'),
        ("GPG_PRIVATE_KEY: ", f'GPG_PRIVATE_KEY: "{REDACTED}"'),
        ("Authorization: ", f'Authorization: "{REDACTED}"'),
        ("INFO loaded secret: ", f'INFO loaded secret: "{REDACTED}"'),
        ("ENV GPG_KEY ", f"ENV GPG_KEY {REDACTED}"),
        ("api-key:", f'api-key:"{REDACTED}"'),
        ("x-api-key: ", f'x-api-key: "{REDACTED}"'),
        ("Cookie: x ", f'Cookie: "{REDACTED}"'),
        ("note: ", f"note: {REDACTED}"),
    ],
)
def test_pgp_private_key_body_is_withheld_after_a_credential_name(prefix, expected):
    # The name's rule withheld the BEGIN line, and the block rule, which
    # starts there, no longer found the block: its body lines were shown.
    for newline in ("\n", "\r\n"):
        text = prefix + _PGP_KEY.replace("\n", newline)
        assert _clean(text) == expected + "\n" * 4
        assert SECRET not in json.dumps(sanitize({"excerpt": text, "items": [text]}))


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # A cookie argument the statement rules withheld ends at the ',' or ')' after it.
        (
            "resp = session.get(url, cookie=session_cookie, timeout=5)",
            f'resp = session.get(url, cookie="{REDACTED}", timeout=5)',
        ),
        (f"f(cookie={SECRET}, timeout=5)", f'f(cookie="{REDACTED}", timeout=5)'),
        (
            f"HttpRequest(method=GET, cookie=sid={SECRET}, timeout=5)",
            f'HttpRequest(method=GET, cookie="{REDACTED}", timeout=5)',
        ),
        (f'x(cookie={{"a": "{SECRET}"}}, t=1)', f'x(cookie="{REDACTED}", t=1)'),
        # Past a ';' come the other cookies: withheld to the end of the line,
        # quoted where the statement rules read an argument.
        (
            f"Request(url=https://x.test/a, cookie=sid=abc; csrftoken={SECRET})",
            f'Request(url=https://x.test/a, cookie="{REDACTED}"',
        ),
        (f"COOKIE=a=1; sid={SECRET}", f"COOKIE={REDACTED}"),
        (f"cookie = sid=abc; csrftoken={SECRET}", f"cookie = {REDACTED}"),
        (f"get(url, cookie=a; b={SECRET}\n& x", f'get(url, cookie="{REDACTED}"\n'),
        # A withheld 'name:value' before a ';' reads as an annotation, as the statement rules read it.
        (f"api_key:a=1; sid={SECRET}", f'api_key:"{REDACTED}"; sid= "{REDACTED}"'),
        (f"api_key:a={SECRET}; sid=X", f'api_key:"{REDACTED}"; sid= "{REDACTED}"'),
        # Inside a quoted string the compact marker stays bare, so the statement
        # rules then read it as an annotation; the result is stable.
        (
            f'{{"log": "xapikey:a=1; sid={SECRET} end"}}',
            f'{{"log": "xapikey:{REDACTED} "{REDACTED}"; sid= "{REDACTED}"',
        ),
    ],
)
def test_cookie_arguments_and_compact_values_are_stable_under_resanitization(text, expected):
    # The cookie pass read a cookie argument's ', timeout=5)' as more cookies
    # and left a bare marker after '=' that the next sanitization quoted; a
    # withheld 'api_key:a=1' became an annotation whose ';' the next one read past.
    assert _clean(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        f"get(u, cookie=c1, timeout=5) Cookie: a=1; sid={SECRET}",
        f"get(u, cookie=c1) cookie=x; sid={SECRET}",
        f"x; Request(url=u, cookie=sid=abc; sessionid={SECRET})",
    ],
)
def test_cookie_header_after_a_cookie_argument_on_the_same_line_is_withheld(text):
    # Skipping an argument the established passes withheld also skipped the
    # rest of its line, and a Cookie header there kept its other cookies.
    _clean(text)


@pytest.mark.parametrize(
    "text",
    [
        json.dumps({"msg": json.dumps({"body": json.dumps({"password": SECRET})})}),
        json.dumps(json.dumps({"body": json.dumps({"api_key": SECRET, "model": "x"})})),
        json.dumps({"body": json.dumps({"api_key": SECRET, "model": "x"})}),
        # Three escaping levels (seven backslashes), within the eight the rules read.
        json.dumps({"a": json.dumps({"b": json.dumps({"c": json.dumps({"token": SECRET})})})}),
    ],
)
def test_escaped_json_under_another_name_is_read_for_credentials(text):
    # An escaped value closes only at its own delimiter, so a value under a
    # name that is not a credential spans the more deeply escaped JSON in it;
    # that JSON is read on its own.
    _clean(text)


@pytest.mark.parametrize(
    "text",
    [
        json.dumps({"log": f'password: "{SECRET}"'}),
        json.dumps({"msg": f'token: "{SECRET}"'}),
        json.dumps({"msg": f'api_key: "{SECRET}" rejected'}),
        json.dumps({"stdout": f'client_secret: "{SECRET}"\n'}),
        json.dumps({"msg": f'secret: "{SECRET}", user: "bob"'}),
        json.dumps({"data": {"config.yaml": f'password: "{SECRET}"\nhost: db\n'}}),
        # Python's repr escapes a quote of its own kind.
        "{'msg': 'password: \\'" + SECRET + "\\' (\"prod\")'}",
    ],
)
def test_a_string_that_starts_with_an_escaped_credential_value_is_withheld(text):
    # The string after "log": closed at the escaped quote ('"password: \\"'), so
    # only that backslash was withheld from the credential and the value was shown.
    _clean(text)


def test_an_escaped_credential_value_is_withheld_from_a_structured_excerpt():
    # A JSON file's excerpt is sanitized with its parsed structure, which names
    # no credential here: the text passes alone decide what the excerpt shows.
    text = json.dumps(
        {"kind": "ConfigMap", "data": {"config.yaml": f'password: "{SECRET}"\nhost: db\n'}}, indent=2
    )
    excerpt = sanitize((json.loads(text), text))[1]
    assert SECRET not in excerpt and REDACTED in excerpt and '"kind": "ConfigMap"' in excerpt


@pytest.mark.parametrize(
    "text",
    [
        '$path = "C:\\temp\\"; $password = "' + SECRET + '"',
        'path = "C:\\temp\\" ; password = "' + SECRET + '"',
        'dir = "C:\\x\\" token = "' + SECRET + '"',
        '[db]\nroot = "C:\\data\\"  # dir\npassword = "' + SECRET + '"',
    ],
)
def test_a_quoted_path_ending_in_a_backslash_does_not_hide_a_later_credential(text):
    # Windows paths end in a backslash before their closing quote; the
    # credential assigned after one on the same line is still withheld.
    _clean(text)


@pytest.mark.parametrize(
    "text",
    [
        f'tool --password "ab\\"{SECRET}"',
        f'tool --api-key "ab\\"{SECRET}"',
        f'curl -u "user:ab\\"{SECRET}" https://x.test',
        f'mysql -p"ab\\"{SECRET}"',
        f'echo "ab\\"{SECRET}" | docker login -u svc --password-stdin',
        f'dotnet user-secrets set "OpenAI:Key" "ab\\"{SECRET}"',
        f'requests.get(url, auth=("user", "ab\\"{SECRET}"))',
        f"requests.get(url, auth=('user', 'ab\\'{SECRET}'))",
        # A shell's single quotes escape nothing: the value ends at the next quote.
        f"tool --user 'C:\\' --password '{SECRET}'",
    ],
)
def test_a_quoted_argument_closes_at_its_first_unescaped_quote(text):
    # In a shell's double quotes and in a Python string '\\"' is a quote inside
    # the value: closed there, the rest of the credential was shown.
    _clean(text)


@pytest.mark.parametrize(
    ("text", "kept"),
    [
        (f'curl -H "api-key:{SECRET}" https://x.test', 'curl -H "api-key:'),
        (f'curl -H "Cookie: a=1; sessionid={SECRET}" https://x.test', 'curl -H "Cookie: '),
        (f"line one\nCookie: a=1; sessionid={SECRET}\nline three", "line one\nCookie: "),
        (f'{{"headers": "api-key:{SECRET}"}}', '{"headers": "api-key:'),
    ],
)
def test_inline_header_credentials_are_redacted_in_context(text, kept):
    result = _clean(text)
    assert result.startswith(kept) and REDACTED in result


@pytest.mark.parametrize(
    ("text", "kept"),
    [
        (
            json.dumps({"message": f"login failed\npassword:{SECRET}"}),
            '{"message": "login failed\\npassword:',
        ),
        (json.dumps({"request": f"GET /v1 HTTP/1.1\r\nX-Api-Key:{SECRET}\r\n"}), "HTTP/1.1\\r\\nX-Api-Key:"),
        (f'"a\\tpassword:{SECRET}"', '"a\\tpassword:'),
        (f'{{"headers": "Accept:*/*\\nAuthorization:{SECRET}"}}', "Accept:*/*\\nAuthorization:"),
        (
            json.dumps(json.dumps({"message": f"login failed\npassword:{SECRET}"})),
            "login failed\\\\npassword:",
        ),
        (json.dumps({"m": f"x\fpasswd:{SECRET}"}), '{"m": "x\\fpasswd:'),
        (f'{{"m": "x\\u000apassword:{SECRET}"}}', '{"m": "x\\u000apassword:'),
        (
            json.dumps({"request": f"GET / HTTP/1.1\r\nCookie: a=1; sid={SECRET}\r\n"}),
            "HTTP/1.1\\r\\nCookie: ",
        ),
    ],
)
def test_inline_headers_after_an_escaped_line_break_are_redacted(text, kept):
    # The name was read from the escape's letter ('npassword', 'nX-Api-Key'),
    # which named no header: the value was shown.
    result = _clean(text)
    assert kept in result and REDACTED in result


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # A key=value neighbour after ';' ends the value (connection strings, shell lists).
        (f"Server=db;Password={SECRET};Database=app", f"Server=db;Password={REDACTED};Database=app"),
        (f"export PASSWORD=x{SECRET}; echo done", f"export PASSWORD={REDACTED}; echo done"),
        ("mac aa:bb:cc:dd:ee:ff:00:11:22:33", "mac aa:bb:cc:dd:ee:ff:00:11:22:33"),
        ("time 12:34:56 path C:\\Users\\x", "time 12:34:56 path C:\\Users\\x"),
        ("def f(name:str, size:int) -> None: ...", "def f(name:str, size:int) -> None: ..."),
        ("Cookie handling is documented in the guide", "Cookie handling is documented in the guide"),
        # Resource paths that merely contain a bare ``secret:`` or ``token:`` segment.
        (
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf",
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf",
        ),
        # Evidence signals and identifiers that merely contain a credential-like word.
        ("example-credential:provider.anthropic", "example-credential:provider.anthropic"),
        ("secret:provider.openai", "secret:provider.openai"),
        ("jwt:service-account", "jwt:service-account"),
        # Opaque identities written by the shared fingerprint and the gateway.
        ("api-key:" + credential_id("k"), "api-key:" + credential_id("k")),
        ("api-key:credential:hmac-sha256:" + "a" * 64, "api-key:credential:hmac-sha256:" + "a" * 64),
    ],
)
def test_text_shape_fixes_keep_neighbouring_context(text, expected):
    assert sanitize_text(text) == expected
    assert sanitize_text(sanitize_text(text)) == expected


_TOKENS = {
    "stripe-live": "sk_live_" + "a1B2c3D4e5F6g7H8i9J0k1L2",
    "stripe-restricted": "rk_live_" + "a1B2c3D4e5F6g7H8i9J0k1L2",
    "stripe-webhook": "whsec_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4",
    "sendgrid": "SG." + "abcdefghijklmnopqrstuv" + "." + "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
    "npm": "npm_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
    "pypi": "pypi-AgEIcHlwaS5vcmcCJGExMjM0NTY3OC1hYmNkLTQ1NjctYWJjZGVm" + "x" * 40,
    "digitalocean": "dop_v1_" + "0123456789abcdef" * 4,
    "databricks": "dapi" + "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    "slack-app": "xapp-" + "1-A0123456789-1234567890123-abcdef0123456789abcdef",
    "slack-config": "xoxe-" + "1-abcdef0123456789abcdef",
    "fireworks": "fw_" + "a1B2c3D4e5F6g7H8i9J0k1L2",
    "google-oauth": "ya29." + "a0AfH6SMBabcdefghijklmnopqrstuvwxyz0123456789",
    "anthropic-oauth": "sk-ant-oat01-" + "abcdefghijklmnopqrstuvwxyz0123456789",
    "elevenlabs": "sk_" + "0123456789abcdef" * 3,
}


@pytest.mark.parametrize("token", _TOKENS.values(), ids=_TOKENS)
def test_token_backstop_covers_common_formats(token):
    for template in ("{}", "value is {} here", "密钥{}", "{}令牌"):
        text = template.format(token)
        result = sanitize_text(text)
        assert token not in result and REDACTED in result, template
        assert sanitize_text(result) == result


def test_token_backstop_after_cjk_and_ascii_boundaries():
    assert sanitize_text("密钥sk-proj-abcdefghijklmnopqrst1234") == f"密钥{REDACTED}"
    assert sanitize_text("令牌ghp_abcdefghijklmnop1234!") == f"令牌{REDACTED}!"
    # A value too short for its format is not a credential; behind an underscore a
    # token is still one (`cfg_sk-proj-…`), so no such identifier is listed here.
    for text in ("npm_short", "ya29.x"):
        assert sanitize_text(text) == text


@pytest.mark.parametrize("key", ["auth", "pwd", "pat", "X-Amz-Security-Token", "x-amz-security-token"])
def test_url_query_keys_auth_pwd_pat_and_session_token_are_redacted(key):
    url = f"https://example.test/path?model=a&{key}={SECRET}&safe=1#{key}={SECRET}"
    result = _clean(url)
    assert result == f"https://example.test/path?model=a&{key}={REDACTED}&safe=1#{key}={REDACTED}"


def test_set_and_bytes_values_are_sanitized():
    token = "sk-proj-" + "a1B2c3D4e5F6g7H8i9J0"
    original = {
        "plain": {token},
        "frozen": frozenset({f"copy {token}"}),
        "raw": token.encode(),
        "buffer": bytearray(f"note {token}".encode()),
        "nested": {"x": {"y": {token}}},
        "tuple_set": {("a", token)},
        "api_key": {token},
        "ok": {"alpha"},
        "count": b"12",
    }
    result = sanitize(original)
    assert token not in json.dumps(result, default=str)
    assert token not in repr(result)
    # A set is read as a list in a stable order and bytes as text, so a report
    # never prints either raw (see ``_plain``).
    assert result["ok"] == ["alpha"] and result["count"] == "12"
    assert isinstance(result["plain"], list) and isinstance(result["frozen"], list)
    assert isinstance(result["raw"], str) and isinstance(result["buffer"], str)


@pytest.mark.parametrize(
    "value",
    [
        {"args": ["--token", SECRET.encode()]},
        {"args": ["--password", bytearray(SECRET.encode())]},
        {"args": ("--api-key", SECRET.encode())},
        {"args": [b"--token", SECRET.encode()]},
        {"args": [b"--token", SECRET]},
        {"args": [b"--pat", SECRET.encode()]},
        {"env": {"X": SECRET.encode()}},
        {"env": [{"name": "X", "value": SECRET.encode()}]},
        {"environment": {"nested": {"X": SECRET.encode()}}},
    ],
)
def test_bytes_argv_and_environment_values_are_removed_from_sibling_fields(value):
    # The established pass remembers text alone, and the later passes read
    # its copy, where these values were already withheld (or, after a bytes
    # option, never read): a copy in another field was shown.
    for short in (False, True):
        result = sanitize({**value, "note": f"saw {SECRET}"}, redact_short_secrets=short)
        assert SECRET not in repr(result)
    # Ordinary environments keep their values out of the sibling rule, as text values do.
    kept = sanitize({"env": {"X": SECRET.encode()}, "note": SECRET}, env_values_are_secrets=False)
    assert kept["note"] == SECRET
    assert sanitize({"args": ["--model", b"gpt-4o"], "note": "gpt-4o"})["note"] == "gpt-4o"


def test_bytes_with_invalid_utf8_are_sanitized_without_error():
    token = "ghp_" + "a1B2c3D4e5F6g7H8i9J0"
    result = sanitize({"blob": b"\xff\xfe" + token.encode() + b"\x80"})
    assert isinstance(result["blob"], str) and token not in result["blob"]


def test_set_values_count_toward_sanitization_limits():
    from shadowscan.utils.redaction import SanitizationLimitError

    with pytest.raises(SanitizationLimitError):
        sanitize({"big": frozenset(f"v{i}" for i in range(150_000))})


def test_a_container_in_a_set_counts_toward_sanitization_limits():
    # A set's members were counted as leaves, so a set around a deep or wide
    # tuple passed the structure check: the copy then cut the deep one short
    # with a marker instead of failing the nesting limit, and copied the wide
    # one past the size limit.
    deep: object = "leaf"
    for _ in range(100):
        deep = (deep,)
    wide = ("x" * 1024 * 1024,) * 65
    for value in (frozenset({deep}), {"field": {deep}}, {"field": frozenset({wide})}):
        with pytest.raises(SanitizationLimitError):
            sanitize(value)
    assert sanitize({"field": {("a", ("b", "c"))}}) == {"field": [("a", ("b", "c"))]}


@pytest.mark.parametrize(
    "text",
    [
        "Bearer abcDEF123xyz",
        "bearer abcDEF123xyz",
        "Authorization header: Bearer abcDEF123xyz.part-two_three==",
        'curl -H "Authorization: Bearer abcDEF123xyz" https://x.test',
        "token=Bearer   abcDEF123xyz",
        "Basic dXNlcjpwYXNzd29yZA==",
        "SSWS 00abcDEF123xyz",
    ],
)
def test_bare_authorization_scheme_credentials_are_redacted(text):
    result = sanitize_text(text)
    assert "abcDEF123xyz" not in result and "dXNlcjpwYXNzd29yZA" not in result and "00abcDEF" not in result
    assert sanitize_text(result) == result


def test_bare_bearer_keeps_scheme_and_surrounding_words():
    assert sanitize_text("sent Bearer abcDEF123xyz to host") == f"sent Bearer {REDACTED} to host"
    assert sanitize_text("Bearer") == "Bearer"
    assert sanitize({"note": "use Bearer abcDEF123xyz"}) == {"note": f"use Bearer {REDACTED}"}


@pytest.mark.parametrize(
    "unit",
    [
        "eyJ-",
        "eyJ-eyJa-",
        "eyJa.eyJb.",
        "eyJ_",
        "sk-",
        "Bearer ",
        "--token ",
        "--api-key=",
        "Cookie: a=1; ",
        "cookie=a, ",
        "cookie=a, Cookie: b ",
        '\\"k\\": \\"',
        'password:\\"',
        "api-key:",
        "PASSWORD=a;",
        "mysql x -p",
        "curl -u ",
        "SG.",
        "xapp-",
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\n",
    ],
)
def test_hostile_repetitive_input_is_matched_in_linear_time(unit):
    # Linear, not fast: four times the input may take at most ten times as
    # long, where quadratic work takes sixteen. An absolute bound failed on a
    # loaded runner under coverage ('Cookie: a=1; ' tokenizes each of its
    # 30,769 annotated assignments). The floor keeps timer noise on a fast
    # unit from failing it; the ceiling still fails a stall.
    small = min(_sanitize_seconds(unit * (100_000 // len(unit))) for _ in range(2))
    large = _sanitize_seconds(unit * (400_000 // len(unit)))
    assert large < 10 * max(small, 0.05), (small, large)
    assert large < 60.0


def _sanitize_seconds(text: str) -> float:
    started = time.perf_counter()
    try:
        sanitize_text(text)
    except SanitizationLimitError:  # a fail-closed limit is acceptable; a stall is not
        pass
    return time.perf_counter() - started


def test_real_jwts_are_still_redacted_in_every_position():
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    unsigned = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0."
    for template in ("{}", "token {} end", "x-{}", "a.b.{}", "密钥{}", '"{}"', "Bearer-{}"):
        result = sanitize_text(template.format(jwt))
        assert jwt not in result and "eyJ" not in result, template
    assert "eyJ" not in sanitize_text(f"unsigned {unsigned}")
    # A header with '-' characters stays one token.
    hyphenated = "eyJhbGci-OiJI_UzI1.eyJzdWIiOiIxIn0.sig-nature_1"
    assert sanitize_text(hyphenated) == REDACTED
    # Not a token: identifiers that contain eyJ mid-word, and two-segment values.
    for text in ("abceyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0"):
        assert sanitize_text(text) == text
