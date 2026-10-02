"""Credentials on command lines, in request headers and in environment commands.

Internal to :mod:`shadowscan.utils.redaction`, which re-exports every name
here. Option values ('--api-key v', '-u user:v', '-H "X-Api-Key:v"', and an
opaque '--key v'), a login's '-p v', a password echoed into
'--password-stdin', the value 'dotnet user-secrets set NAME v' stores, and
the values of 'ENV NAME v', 'setx NAME v' and '#define NAME v'.
"""

from __future__ import annotations

import heapq
import re

from shadowscan.utils.redaction_rules import (
    _ALPHANUMERIC,
    _CLI_WORD,
    _FINGERPRINT,
    _REFERENCE,
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
_CLI_GLUED_OPTION = re.compile(r"--[A-Za-z][A-Za-z0-9]*(?:[-_.][A-Za-z0-9]+)*")
_CLI_LLM = re.compile(r"(?:^|[\s(/])llm(?:[ \t]+[^\r\n;&|]*)?[ \t]+$")
_CLI_BOUNDARY = re.compile(r"[\w./\\\]-]")
_CLI_USER_OPTIONS = frozenset({"a", "u", "U", "basic-auth", "proxy-user", "user"})
# Short spellings that name a credential as an option but are too broad as
# record field names; their whole value is withheld.
_CLI_SECRET_OPTIONS = frozenset({"auth", "pass", "passphrase", "pat", "pwd"})
_CLI_HEADER_OPTIONS = frozenset({"H", "header", "headers"})
_CLI_SPACE = re.compile(r"[ \t]*\\\r?\n[ \t]*|[ \t]*\r?\n[ \t]*-[ \t]+|[ \t]+")
_CLI_LIST_GAP = re.compile(r"[ \t]*,[ \t]*|[ \t]*\r?\n[ \t]*-[ \t]+|[ \t]+")
# An unterminated quote (a copied fragment) runs the value to its line end.
_CLI_VALUE = re.compile(
    r"\"(?P<double>[^\"\r\n]*)\"|'(?P<single>[^'\r\n]*)'|(?P<bare>[^\s\"'`;|&<>(){}\[\],\\]+)"
    r"|[\"'](?P<open>[^\r\n]+)"
)
# One character of an unquoted value (the 'bare' group above), and a run of them.
_CLI_BARE_CHARACTER = re.compile(r"[^\s\"'`;|&<>(){}\[\],\\]")
_CLI_BARE_RUN = re.compile(r"[^\s\"'`;|&<>(){}\[\],\\]+")
# An unquoted value that holds a marker an earlier pass left in it.
_CLI_MARKED_VALUE = re.compile(r"(?:\[REDACTED\]|[^\s\"'`;|&<>(){}\[\],\\])+")
_CLI_METAVAR = re.compile(r"[A-Z]+(?:[_-][A-Z0-9]+)*")
_CLI_VALUE_LIMIT = 4096
# An opaque option's value that is kept is read to the end of its unquoted
# word, and every later option in that word reads it again
# ('--key=#--key=#...'). Past this many options in one word the last pass
# withholds the rest of the word instead, which keeps it linear; command
# lines separate their options. (The established options read each run of
# value characters once: see _ValueRuns.)
_CLI_WORD_OPTIONS = 16
_HEADER_VALUE = re.compile(
    r"(?P<name>[A-Za-z][A-Za-z0-9-]*):(?:(?:Bearer|Basic|Token|Bot|Digest|SSWS|ApiKey|Api-Key|token)[ \t]+)?"
    r"(?P<secret>\S[^\r\n]*)"
)
_HEADER_NAME = re.compile(r"[A-Za-z][A-Za-z0-9-]*")
_FINGERPRINT_LENGTH = len("credential:sha256:") + 64
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
    if name.lower() in _CLI_SECRET_OPTIONS:
        return "secret"
    if name in _CLI_USER_OPTIONS:
        return "user"
    if name in _CLI_HEADER_OPTIONS:
        return "header"
    if name.lower().startswith(("no-", "no_")):
        return ""
    if _sensitive_assignment_key(re.sub(r"[-.]", "_", name)):
        return "secret"
    return "opaque" if _credential_name(name, numbered=True) else ""


def _cli_password_mode(text: str, option: re.Match[str], logins: bool, mysql: bool) -> str:
    """'secret' for a login's '-p', 'attached' for a MySQL client's '-pVALUE', else ''.

    ``logins`` and ``mysql`` say whether the text names those commands at all.
    """
    if not option.group().startswith("-p") or option.group().startswith("--"):
        return ""
    following = text[option.end() : option.end() + 1]
    rules: tuple[re.Pattern[str], ...]
    if option.group() == "-p" and following in {" ", "\t", "\\"}:
        mode, rules = "secret", ((_CLI_REGISTRY_LOGIN, _CLI_SSHPASS) if logins else ())
    elif option.group() != "-p" or following.strip():
        mode, rules = "attached", ((_CLI_MYSQL,) if mysql else ())
    else:
        return ""
    if not rules:
        return ""
    head = _CLI_CONTINUATION.sub(" ", text[max(0, option.start() - _CLI_COMMAND_CONTEXT) : option.start()])
    command = head[max(head.rfind(separator) for separator in ";&|\n\r") + 1 :]
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


class _ValueRuns:
    """The unquoted option values of one text, each run of value characters read once.

    An unquoted value runs to the end of its run of value characters, so each
    option inside one run ('-u=#-u=#-u=#...', '-H=a:-H=a:...') read its own
    copy of the rest of the run, which made the pass quadratic. The end of
    the current run and the next ':' and '=' in it are kept, and ``kept`` and
    ``digits`` stop at the first character that decides them: the next
    option in a run has a letter that no reference covers. Each decision is
    the one ``_cli_secret_span`` makes on the copy.
    """

    def __init__(self, text: str) -> None:
        self.text = text
        self.run = (0, 0)
        # A character -> (searched from, run end, where it is or -1).
        self.found: dict[str, tuple[int, int, int]] = {}

    def end(self, position: int) -> int:
        """The end of the unquoted value that starts at ``position``, a value character."""
        start, end = self.run
        if not start <= position < end:
            run = _CLI_BARE_RUN.match(self.text, position)
            end = position if run is None else run.end()
            self.run = (position, end)
        return end

    def find(self, character: str, start: int, end: int) -> int:
        """``text.find(character, start, end)`` for the tail of a run, searched once per run."""
        searched, run_end, found = self.found.get(character, (-1, -1, -1))
        if run_end == end and 0 <= searched <= start and (found < 0 or start <= found):
            return found
        found = self.text.find(character, start, end)
        self.found[character] = (start, end, found)
        return found

    def kept(self, start: int, end: int) -> bool:
        """``_kept_value(text[start:end])``: a run holds no blank, marker, bracket or brace."""
        text = self.text
        if end - start == _FINGERPRINT_LENGTH and _FINGERPRINT.fullmatch(text[start:end]):
            return True
        position = start
        while position < end:
            reference = _REFERENCE.match(text, position, end)
            if reference is not None:
                position = reference.end()
            elif _ALPHANUMERIC.match(text, position):
                return False
            else:
                position += 1
        return True

    def digits(self, start: int, end: int) -> bool:
        """``text[start:end].isdigit()``."""
        text = self.text
        return start < end and all(text[position].isdigit() for position in range(start, end))


def _run_secret_span(
    mode: str,
    runs: _ValueRuns,
    start: int,
    end: int,
    strict: bool,
) -> tuple[int, int] | None:
    """``_cli_secret_span`` of the unquoted value text[start:end] of a 'secret', 'user' or 'header' option."""
    text = runs.text
    if text.startswith("-", start):
        return None  # the next option, not a value
    if mode == "user":
        colon = runs.find(":", start, end)
        if colon < 0 or 0 <= runs.find("=", start, end) < colon or colon + 1 == end:
            return None
        if runs.digits(colon + 1, end) or runs.kept(colon + 1, end) or text.startswith("//", colon + 1, end):
            return None
        return colon + 1, end
    if mode == "header":
        # The pattern's scheme needs a blank, which a run does not hold.
        name = _HEADER_NAME.match(text, start, end)
        if name is None or not text.startswith(":", name.end(), end) or name.end() + 1 == end:
            return None
        if not _sensitive_key(name.group()) or runs.kept(name.end() + 1, end):
            return None
        return name.end() + 1, end
    if runs.kept(start, end) or _CLI_METAVAR.fullmatch(text, start, end):
        return None
    if not strict and _CLI_WORD.fullmatch(text, start, end):
        return None  # prose ('--token to authenticate') or an argparse dest name
    return start, end


def _cli_value_span(
    mode: str,
    text: str,
    position: int,
    strict: bool,
    runs: _ValueRuns | None = None,
) -> tuple[int, int] | None:
    """The credential in the option value at ``position``; ``runs`` reads unquoted ones (see _ValueRuns)."""
    if text.startswith("-", position):
        return None  # the next option: checked first so chained options are not rescanned
    if runs is not None and mode != "opaque" and _CLI_BARE_CHARACTER.match(text, position):
        return _run_secret_span(mode, runs, position, runs.end(position), strict)
    value = _CLI_VALUE.match(text, position)
    if mode == "opaque" and (value is None or value.group("bare") is not None):
        # These options are read last, after an earlier pass may have withheld
        # part of an unquoted value ('--key sk-...:rest'): the rest decides.
        if text.startswith(REDACTED, position if value is None else value.end()):
            marked = _CLI_MARKED_VALUE.match(text, position)
            assert marked is not None
            rest = marked.group().replace(REDACTED, "")
            return marked.span() if rest and _cli_secret_span(mode, rest, position, strict) else None
    if value is None:
        return None
    group = next(name for name in ("double", "single", "bare", "open") if value.group(name) is not None)
    if group == "open" and mode != "secret":
        return None
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
    if "user-secrets" not in text:
        return text
    spans: list[tuple[int, int]] = []
    for match in _USER_SECRETS_SET.finditer(text):
        name = match.group("dname") or match.group("sname") or match.group("bname") or ""
        group = next(group for group in ("double", "single", "bare") if match.group(group) is not None)
        value = match.group(group)
        if not _kept_value(value) and _setting_value_withheld(_setting_level(name), value):
            spans.append(match.span(group))
    return _withhold_spans(text, spans)


def _redact_command_credentials(text: str) -> str:
    """Withhold credentials passed as command-line option values (the established rules).

    Opaque values of options whose last word names a credential are left to
    ``_redact_opaque_options``, which runs after every established pass.
    """
    if "-" not in text:
        return text
    if "--password-stdin" in text:
        text = _redact_piped_passwords(text)
    return _redact_options(text, opaque=False)


def _redact_opaque_options(text: str) -> str:
    """Withhold opaque values of options whose last word names a credential ('--key v').

    This runs after every pass that reads a name: an opaque value glued to a
    following assignment ('--key v#password = "p"') would otherwise hide that
    assignment's name from them. It also withholds the rest of a word crowded
    with options (see _CLI_WORD_OPTIONS), which nothing reads after it.
    """
    return text if "-" not in text else _redact_options(text, opaque=True)


def _redact_extended_options(text: str) -> str:
    """Recognize glued credential options and llm's command-specific '-k'.

    Short '-k' remains ordinary for curl and unrelated commands. This pass
    runs after established context readers, before an opaque '--key' value
    could consume a credential option glued after it.
    """
    if "-" not in text:
        return text
    spans: list[tuple[int, int]] = []
    runs = _ValueRuns(text)
    cursor = 0
    matches = heapq.merge(
        _CLI_OPTION.finditer(text), _CLI_GLUED_OPTION.finditer(text), key=lambda item: item.start()
    )
    seen = -1
    for match in matches:
        if match.start() == seen:
            continue
        seen = match.start()
        if match.start() < cursor:
            continue
        mode = _cli_option_mode(match.group())
        if match.group() == "-k":
            head = _CLI_CONTINUATION.sub(
                " ", text[max(0, match.start() - _CLI_COMMAND_CONTEXT) : match.start()]
            )
            command = head[max(head.rfind(separator) for separator in ";&|\n\r") + 1 :]
            mode = "secret" if _CLI_LLM.search(command) else ""
        elif not match.group().startswith("--") or mode != "secret":
            continue
        if not mode:
            continue
        span = _option_value_span(text, match, mode, "", runs)
        if span is not None:
            spans.append(span)
            cursor = span[1]
    return _withhold_spans(text, spans)


def _redact_options(text: str, *, opaque: bool) -> str:
    """Withhold values of 'opaque' options ('--key v') when ``opaque``, else of all other options.

    A login's '-p' and a MySQL client's '-pValue' are read first, so
    '-pS3cretKey' after 'mysql' is an attached password, not an 'opaque' option.
    """
    spans: list[tuple[int, int]] = []
    cursor = 0
    logins = "login" in text or "sshpass" in text
    mysql = "mysql" in text or "mariadb" in text
    runs = None if opaque else _ValueRuns(text)
    # The unquoted word the current option starts in, and how many options start in it.
    word_end = word_options = 0
    for match in _CLI_OPTION.finditer(text):
        start = match.start()
        if opaque:
            if start < word_end:
                word_options += 1
            else:
                word = _CLI_MARKED_VALUE.match(text, start)
                word_end, word_options = (start + 1 if word is None else word.end()), 1
            if word_options > _CLI_WORD_OPTIONS:
                if start >= cursor:
                    spans.append((start, word_end))
                    cursor = word_end
                continue
        mode = _cli_option_mode(match.group())
        if opaque and mode != "opaque":
            continue
        if mode in {"", "opaque"} and (logins or mysql):
            # A login's '-p' and a MySQL client's '-pValue' ('-pSecret') come first.
            mode = _cli_password_mode(text, match, logins, mysql) or mode
        if not mode or (mode == "opaque") != opaque:
            continue
        # An opening quote belongs to the option unless it closes a preceding word.
        quote = text[start - 1] if start and text[start - 1] in "\"'" else ""
        if quote and start > 1 and _CLI_BOUNDARY.match(text, start - 2):
            quote = ""
        if start - len(quote) < cursor:
            continue
        span = _option_value_span(text, match, mode, quote, runs)
        if span is None:
            continue
        spans.append(span)
        cursor = span[1]
    return _withhold_spans(text, spans)


def _option_value_span(
    text: str,
    match: re.Match[str],
    mode: str,
    quote: str,
    runs: _ValueRuns | None,
) -> tuple[int, int] | None:
    """The credential that the option ``match`` of ``mode`` passes, if any.

    ``quote`` is the quote that opens the option ('"--api-key=v"'), or ''.
    """
    start, position = match.start(), match.end()
    strict = text.startswith("=", position)
    if mode == "attached":
        return _cli_value_span("secret", text, start + 2, True, runs)
    if quote and strict:
        # '"--api-key=value"' as one argv element.
        limit = text.find("\n", position, position + _CLI_VALUE_LIMIT)
        closing = text.find(quote, position + 1, position + _CLI_VALUE_LIMIT if limit < 0 else limit)
        if closing >= 0:
            return _cli_secret_span(mode, text[position + 1 : closing], position + 1, True)
    elif quote and text.startswith(quote, position):
        # An argv list or a quoted shell word names its value in quotes.
        gap = _CLI_LIST_GAP.match(text, position + 1)
        if gap is None or not text.startswith(('"', "'"), gap.end()):
            return None
        return _cli_value_span(mode, text, gap.end(), False, runs)
    # Plain text, or a quote that does not delimit this option.
    if strict:
        return _cli_value_span(mode, text, position + 1, True, runs)
    gap = _CLI_SPACE.match(text, position)
    return None if gap is None else _cli_value_span(mode, text, gap.end(), False, runs)


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
        if raw.startswith(('"', "'")) and raw.find(raw[0], 1) > 0:
            start, raw = start + 1, raw[1 : raw.find(raw[0], 1)]
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
