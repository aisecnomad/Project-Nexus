"""Credentials on command lines, in request headers and in environment commands.

Internal to :mod:`shadowscan.utils.redaction`, which re-exports every name
here. Option values ('--api-key v', '-u user:v', '-H "X-Api-Key:v"', and an
opaque '--key v'), a login's '-p v', a password echoed into
'--password-stdin', the value 'dotnet user-secrets set NAME v' stores, and
the values of 'ENV NAME v', 'setx NAME v' and '#define NAME v'.
"""

from __future__ import annotations

import re

from shadowscan.utils.redaction_rules import (
    _CLI_WORD,
    REDACTED,
    _credential_literal,
    _credential_name,
    _kept_value,
    _sensitive_assignment_key,
    _sensitive_key,
    _setting_level,
    _setting_value_withheld,
    _withhold_spans,
)

# Command-line options that take a credential: '--api-key=v', '--token v', an
# argv list '"--password", "v"' or a YAML list item; user:password options
# (curl -u/--user, httpie -a/--auth); and headers written without a space
# after the colon ('-H "X-Api-Key:v"'), which the assignment rules skip.
# An option whose last word names a credential ('--key', '--openai-key') only
# loses a value that looks like an opaque key, as the same name does in an
# assignment. The leading literal dash lets the regex engine skip ahead quickly.
_CLI_OPTION = re.compile(r"-(?<![\w./\\\]-]-)-?[A-Za-z][A-Za-z0-9]*(?:[-_.][A-Za-z0-9]+)*")
_CLI_BOUNDARY = re.compile(r"[\w./\\\]-]")
_CLI_USER_OPTIONS = frozenset({"a", "u", "U", "auth", "basic-auth", "proxy-user", "user"})
_CLI_HEADER_OPTIONS = frozenset({"H", "header", "headers"})
_CLI_SPACE = re.compile(r"[ \t]*\\\r?\n[ \t]*|[ \t]*\r?\n[ \t]*-[ \t]+|[ \t]+")
_CLI_LIST_GAP = re.compile(r"[ \t]*,[ \t]*|[ \t]*\r?\n[ \t]*-[ \t]+|[ \t]+")
_CLI_VALUE = re.compile(
    r"\"(?P<double>[^\"\r\n]*)\"|'(?P<single>[^'\r\n]*)'|(?P<bare>[^\s\"'`;|&<>(){}\[\],\\]+)"
)
_CLI_METAVAR = re.compile(r"[A-Z]+(?:[_-][A-Z0-9]+)*")
_CLI_VALUE_LIMIT = 4096
_HEADER_VALUE = re.compile(
    r"(?P<name>[A-Za-z][A-Za-z0-9-]*):(?:(?:Bearer|Basic|Token|Bot|Digest|SSWS|ApiKey|Api-Key|token)[ \t]+)?"
    r"(?P<secret>\S[^\r\n]*)"
)
# '-p' is a password only after some commands: a registry or cloud 'login'
# (docker, podman, helm registry, az, az acr, oc, cf...) and 'sshpass', and the
# attached '-pVALUE' of MySQL clients ('mysql -p db' prompts and names a
# database). Elsewhere it is often a port or a path. The command is read from
# at most 256 characters before '-p'.
_CLI_COMMAND_CONTEXT = 256
_CLI_CONTINUATION = re.compile(r"\\\r?\n")
_CLI_REGISTRY_LOGIN = re.compile(
    r"(?:^|[\s(/])(?:docker|podman|nerdctl|buildah|skopeo|oras|crane|helm|az|oc|cf)[ \t]"
    r"(?:.*[ \t])?login(?:[ \t]|$)"
)
_CLI_SSHPASS = re.compile(r"(?:^|[\s(/])sshpass(?:[ \t]+-[A-Za-z]\S*)*[ \t]+$")
_CLI_MYSQL = re.compile(
    r"(?:^|[\s(/])(?:mysql(?:dump|admin|import|show|check|sh)?|mariadb(?:-dump|-admin)?)[ \t]"
)
# A password echoed into a login that reads it from standard input:
# 'echo VALUE | docker login -u svc --password-stdin'.
_CLI_PIPED_PASSWORD = re.compile(
    r"(?:^|[\s;&(])echo[ \t]+(?:-[neE]+[ \t]+)*"
    r"(?:\"(?P<double>[^\"\r\n]*)\"|'(?P<single>[^'\r\n]*)'|(?P<bare>[^\s\"'`;|&<>()]+))"
    r"[ \t]*\|[^|;&\r\n]*?[ \t]--password-stdin(?![\w-])"
)
# 'dotnet user-secrets set NAME VALUE' stores a .NET configuration setting;
# its name decides as a setting's does (see _setting_level).
_USER_SECRETS_SET = re.compile(
    r"(?<![\w.-])dotnet[ \t]+user-secrets[ \t]+set[ \t]+"
    r"(?:\"(?P<dname>[^\"\r\n]*)\"|'(?P<sname>[^'\r\n]*)'|(?P<bname>[^\s\"'`;|&<>]+))[ \t]+"
    r"(?:\"(?P<double>[^\"\r\n]*)\"|'(?P<single>[^'\r\n]*)'|(?P<bare>[^\s\"'`;|&<>]+))"
)


def _cli_option_mode(option: str) -> str:
    name = option.lstrip("-")
    if name in _CLI_USER_OPTIONS:
        return "user"
    if name in _CLI_HEADER_OPTIONS:
        return "header"
    if name.lower().startswith(("no-", "no_")):
        return ""
    if _sensitive_assignment_key(re.sub(r"[-.]", "_", name)):
        return "secret"
    return "opaque" if _credential_name(name) else ""


def _cli_password_mode(text: str, option: re.Match[str], logins: bool, mysql: bool) -> str:
    """'secret' for a login's '-p', 'attached' for a MySQL client's '-pVALUE', else ''.

    ``logins`` and ``mysql`` say whether the text names those commands at all.
    """
    if not option.group().startswith("-p") or option.group().startswith("--"):
        return ""
    following = text[option.end():option.end() + 1]
    rules: tuple[re.Pattern[str], ...]
    if option.group() == "-p" and following in {" ", "\t", "\\"}:
        mode, rules = "secret", ((_CLI_REGISTRY_LOGIN, _CLI_SSHPASS) if logins else ())
    elif option.group() != "-p" or following.strip():
        mode, rules = "attached", ((_CLI_MYSQL,) if mysql else ())
    else:
        return ""
    if not rules:
        return ""
    head = _CLI_CONTINUATION.sub(" ", text[max(0, option.start() - _CLI_COMMAND_CONTEXT):option.start()])
    command = head[max(head.rfind(separator) for separator in ";&|\n\r") + 1:]
    return mode if any(rule.search(command) for rule in rules) else ""


def _cli_secret_span(mode: str, value: str, start: int, strict: bool) -> tuple[int, int] | None:
    """The part of an option value ``value`` (at ``start``) that is a credential."""
    if value.startswith("-"):
        return None  # the next option, not a value
    if mode == "opaque":
        # A value holding an assignment or ending in a mapping key
        # ('--key a.api_key=v', '--key a:Secret:') is left to the rules that
        # read those, and what follows them.
        if "=" in value.rstrip("=") or value.endswith(":"):
            return None
        return (start, start + len(value)) if _credential_literal(value, positional=False) else None
    if mode == "user":
        user, colon, password = value.partition(":")
        if not colon or "=" in user or not password or password.isdigit() or _kept_value(password):
            return None
        if password.startswith("//"):
            return None  # a URL ('cf login -a https://api.example.com'), not user:password
        return start + len(user) + 1, start + len(value)
    if mode == "header":
        header = _HEADER_VALUE.fullmatch(value)
        if header is None or not _sensitive_key(header.group("name")) or _kept_value(header.group("secret")):
            return None
        return start + header.start("secret"), start + len(value)
    if _kept_value(value) or _CLI_METAVAR.fullmatch(value):
        return None
    if not strict and _CLI_WORD.fullmatch(value):
        return None  # prose ('--token to authenticate') or an argparse dest name
    return start, start + len(value)


def _cli_value_span(mode: str, text: str, position: int, strict: bool) -> tuple[int, int] | None:
    if text.startswith("-", position):
        return None  # the next option: checked first so chained options are not rescanned
    value = _CLI_VALUE.match(text, position)
    if value is None:
        return None
    group = next(name for name in ("double", "single", "bare") if value.group(name) is not None)
    return _cli_secret_span(mode, value.group(group), value.start(group), strict)


def _redact_piped_passwords(text: str) -> str:
    """Withhold a literal password echoed into a '--password-stdin' login."""
    spans: list[tuple[int, int]] = []
    for match in _CLI_PIPED_PASSWORD.finditer(text):
        group = next(name for name in ("double", "single", "bare") if match.group(name) is not None)
        if not _kept_value(match.group(group)):
            spans.append(match.span(group))
    return _withhold_spans(text, spans)


def _redact_user_secrets(text: str) -> str:
    """Withhold the value 'dotnet user-secrets set' stores under a credential's name."""
    spans: list[tuple[int, int]] = []
    for match in _USER_SECRETS_SET.finditer(text):
        name = match.group("dname") or match.group("sname") or match.group("bname") or ""
        group = next(group for group in ("double", "single", "bare") if match.group(group) is not None)
        value = match.group(group)
        if not _kept_value(value) and _setting_value_withheld(_setting_level(name), value):
            spans.append(match.span(group))
    return _withhold_spans(text, spans)


def _redact_command_credentials(text: str) -> str:
    """Withhold credentials passed as command-line option values."""
    if "-" not in text:
        return text
    if "--password-stdin" in text:
        text = _redact_piped_passwords(text)
    if "user-secrets" in text:
        text = _redact_user_secrets(text)
    pieces: list[str] = []
    cursor = 0
    logins = "login" in text or "sshpass" in text
    mysql = "mysql" in text or "mariadb" in text
    for match in _CLI_OPTION.finditer(text):
        mode = _cli_option_mode(match.group()) or (
            _cli_password_mode(text, match, logins, mysql) if logins or mysql else ""
        )
        if not mode:
            continue
        start = match.start()
        # An opening quote belongs to the option unless it closes a preceding word.
        quote = text[start - 1] if start and text[start - 1] in "\"'" else ""
        if quote and start > 1 and _CLI_BOUNDARY.match(text, start - 2):
            quote = ""
        if start - len(quote) < cursor:
            continue
        position = match.end()
        strict = text.startswith("=", position)
        span: tuple[int, int] | None = None
        closing = -1
        if mode == "attached":
            closing = position
            span = _cli_value_span("secret", text, start + 2, True)
        elif quote and strict:
            # '"--api-key=value"' as one argv element.
            limit = text.find("\n", position, position + _CLI_VALUE_LIMIT)
            closing = text.find(quote, position + 1, position + _CLI_VALUE_LIMIT if limit < 0 else limit)
            if closing >= 0:
                span = _cli_secret_span(mode, text[position + 1:closing], position + 1, True)
        elif quote and text.startswith(quote, position):
            # An argv list or a quoted shell word names its value in quotes.
            gap = _CLI_LIST_GAP.match(text, position + 1)
            if gap is None or not text.startswith(("\"", "'"), gap.end()):
                continue
            closing = position
            span = _cli_value_span(mode, text, gap.end(), False)
        if closing < 0:
            # Plain text, or a quote that does not delimit this option.
            if strict:
                span = _cli_value_span(mode, text, position + 1, True)
            else:
                gap = _CLI_SPACE.match(text, position)
                span = None if gap is None else _cli_value_span(mode, text, gap.end(), False)
        if span is None:
            continue
        pieces.append(text[cursor:span[0]])
        pieces.append(REDACTED)
        cursor = span[1]
    if not pieces:
        return text
    pieces.append(text[cursor:])
    return "".join(pieces)


# Dockerfile's legacy 'ENV NAME value', csh/Windows 'setenv NAME value' and
# 'setx NAME value', and C's '#define NAME value' set a name without '='.
# 'ENV A=b C=d' is an assignment.
_ENVIRONMENT_COMMAND = re.compile(
    r"(?m)^[ \t]*(?P<command>ENV|[Ee]nv|setenv|setx|#[ \t]*define)[ \t]+(?P<name>[A-Za-z_][A-Za-z0-9_.-]*)"
    r"(?P<gap>[ \t]+(?:\\\r?\n[ \t]*)?)(?P<value>[^\r\n]*)"
)


def _redact_environment_commands(text: str) -> str:
    """Withhold values set by space-separated environment commands."""
    pieces: list[str] = []
    cursor = 0
    for match in _ENVIRONMENT_COMMAND.finditer(text):
        if match.start() < cursor or not _sensitive_assignment_key(match.group("name")):
            continue
        command = match.group("command")
        start = match.start("value")
        raw = match.group("value").rstrip()
        if raw.startswith(("\"", "'")) and raw.find(raw[0], 1) > 0:
            start, raw = start + 1, raw[1:raw.find(raw[0], 1)]
        elif command == "ENV":
            raw = raw.removesuffix("\\").rstrip()  # the legacy form's value is the rest of the line
        else:
            raw = raw.split()[0] if raw.split() else ""
            if command in {"env", "Env"} and _CLI_WORD.fullmatch(raw):
                continue  # prose: 'Env token should be set'
        if _kept_value(raw):
            continue
        pieces.append(text[cursor:start])
        pieces.append(REDACTED)
        cursor = start + len(raw)
    if not pieces:
        return text
    pieces.append(text[cursor:])
    return "".join(pieces)
