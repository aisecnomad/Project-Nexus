"""Credentials on command lines, in request headers and in environment commands.

Internal to :mod:`shadowscan.utils.redaction`, which re-exports every name
here. Option values ('--api-key v', '-u user:v', '-H "X-Api-Key:v"', and an
opaque '--key v'), a login's '-p v', a password echoed into
'--password-stdin', the value 'dotnet user-secrets set NAME v' stores, and
the values of 'ENV NAME v', 'setx NAME v' and '#define NAME v'. The last
option pass also reads short credential option names ('--pat v',
'--passphrase v', '--auth v') and a quoted value that never closes on its
line; cookie headers and headers written without a space after the colon
('x-api-key:v') are read after the established passes as well.
"""

from __future__ import annotations

import re

from shadowscan.utils.redaction_rules import (
    _ALPHANUMERIC,
    _CLI_WORD,
    _FINGERPRINT,
    _KEY_NORMALISE,
    _REFERENCE,
    REDACTED,
    _credential_literal,
    _credential_name,
    _kept_value,
    _redact_value,
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
# Short option names that name a credential on a command line ('--pat v',
# '--passphrase v', '-pass v', '--pwd v') but are too broad as record field
# names, and '--auth', which passes user:password (httpie) or a token. Only the
# last option pass reads them (see _redact_options), as an argv list's
# extended pass does: their values are withheld as a '--password' value is.
_CLI_SECRET_NAMES = frozenset({"pat", "pass", "passphrase", "pwd"})
_CLI_AUTH_OPTIONS = frozenset({"auth"})
_CLI_SPACE = re.compile(r"[ \t]*\\\r?\n[ \t]*|[ \t]*\r?\n[ \t]*-[ \t]+|[ \t]+")
_CLI_LIST_GAP = re.compile(r"[ \t]*,[ \t]*|[ \t]*\r?\n[ \t]*-[ \t]+|[ \t]+")
# A quote that never closes on its line ('--token 'v' in a cut excerpt) opens
# the rest of the line; only the last option pass reads it ('unclosed'). It is
# reached only at the last quote of its kind on a line, so the line is read
# to its end at most twice.
_CLI_VALUE = re.compile(
    r"\"(?P<double>[^\"\r\n]*)\"|'(?P<single>[^'\r\n]*)'|(?P<bare>[^\s\"'`;|&<>(){}\[\],\\]+)"
    r"|[\"'](?P<unclosed>[^\r\n]*)"
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
    """How the established option pass reads the value of ``option`` ('' when it does not)."""
    name = option.lstrip("-")
    if name in _CLI_USER_OPTIONS:
        return "user"
    if name in _CLI_HEADER_OPTIONS:
        return "header"
    if name.lower().startswith(("no-", "no_")):
        return ""
    if _sensitive_assignment_key(re.sub(r"[-.]", "_", name)):
        return "secret"
    return "opaque" if _credential_name(name, numbered=True) else ""


def _cli_added_mode(option: str) -> str:
    """How the last option pass reads ``option`` beyond the established rules ('' when it does not).

    'secret' for a short credential name ('--pat', '-pass'), 'auth' for
    '--auth', whose value is user:password or a token.
    """
    name = option.lstrip("-")
    if name in _CLI_AUTH_OPTIONS:
        return "auth"
    return "secret" if _KEY_NORMALISE.sub("", name.lower()) in _CLI_SECRET_NAMES else ""


def _cli_secret_option(option: str) -> bool:
    """Whether an argv option names a credential by one of the names only the last pass reads."""
    return option.startswith("-") and bool(_cli_added_mode(option))


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
    if mode == "auth":
        mode = "user" if ":" in value else "secret"
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
    """``_cli_secret_span`` of the unquoted value text[start:end] of a 'secret', 'user' or 'header' option.

    An 'auth' option's value is read as a 'user' one when it holds a ':',
    else as a 'secret' one.
    """
    text = runs.text
    if text.startswith("-", start):
        return None  # the next option, not a value
    if mode == "auth":
        mode = "user" if runs.find(":", start, end) >= 0 else "secret"
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
    extended: bool = False,
) -> tuple[int, int] | None:
    """The credential in the option value at ``position``; ``runs`` reads unquoted ones (see _ValueRuns).

    The ``extended`` pass, which runs last, also reads a quote that does not
    close on its line as opening the rest of the line, and an unquoted value
    that an earlier pass withheld in part, as the 'opaque' options always do.
    """
    if text.startswith("-", position):
        return None  # the next option: checked first so chained options are not rescanned
    if runs is not None and mode != "opaque" and _CLI_BARE_CHARACTER.match(text, position):
        end = runs.end(position)
        if not (extended and text.startswith(REDACTED, end)):
            return _run_secret_span(mode, runs, position, end, strict)
    value = _CLI_VALUE.match(text, position)
    if (mode == "opaque" or extended) and (value is None or value.group("bare") is not None):
        # These options are read last, after an earlier pass may have withheld
        # part of an unquoted value ('--key sk-...:rest'): the rest decides.
        if text.startswith(REDACTED, position if value is None else value.end()):
            marked = _CLI_MARKED_VALUE.match(text, position)
            assert marked is not None
            rest = marked.group().replace(REDACTED, "")
            return marked.span() if rest and _cli_secret_span(mode, rest, position, strict) else None
    if value is None or (value.group("unclosed") is not None and not extended):
        return None
    group = next(name for name in ("double", "single", "bare", "unclosed") if value.group(name) is not None)
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

    Opaque values of options whose last word names a credential, and the
    options and values only the added rules read, are left to
    ``_redact_extended_options``, which runs after every established pass.
    """
    if "-" not in text:
        return text
    if "--password-stdin" in text:
        text = _redact_piped_passwords(text)
    return _redact_options(text, extended=False)


def _redact_extended_options(text: str) -> str:
    """Withhold option values only the added rules read (see ``_redact_options``).

    Opaque values of options whose last word names a credential ('--key v'),
    values of short credential names ('--pat v', '--auth v') and a quoted
    value that never closes on its line ('--token 'v'). This runs after every
    pass that reads a name: an opaque value glued to a following assignment
    ('--key v#password = "p"') would otherwise hide that assignment's name
    from them. It also withholds the rest of a word crowded with options (see
    _CLI_WORD_OPTIONS), which nothing reads after it.
    """
    return text if "-" not in text else _redact_options(text, extended=True)


def _redact_options(text: str, *, extended: bool) -> str:
    """Withhold credential option values by the established rules, and the added ones if ``extended``.

    The established pass reads every option but the 'opaque' ones ('--key v').
    The ``extended`` pass, which runs last, reads every option again on what
    the other passes left, with the added rules: 'opaque' options, the short
    names of ``_cli_added_mode`` and quoted values that do not close on their
    line. What the established pass withheld is a marker by then, which it
    keeps. A login's '-p' and a MySQL client's '-pValue' are read first, so
    '-pS3cretKey' after 'mysql' is an attached password, not an 'opaque' option.
    """
    spans: list[tuple[int, int]] = []
    cursor = 0
    # Whether an option inside the value that ends at the cursor is skipped.
    skip_inside = True
    logins = "login" in text or "sshpass" in text
    mysql = "mysql" in text or "mariadb" in text
    runs = _ValueRuns(text)
    # The unquoted word the current option starts in, and how many options start in it.
    word_end = word_options = 0
    for match in _CLI_OPTION.finditer(text):
        start = match.start()
        if extended:
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
        if mode in {"", "opaque"} and (logins or mysql):
            # A login's '-p' and a MySQL client's '-pValue' ('-pSecret') come first.
            mode = _cli_password_mode(text, match, logins, mysql) or mode
        if extended and mode in {"", "opaque", "user"}:
            mode = _cli_added_mode(match.group()) or mode
        if not mode or (mode == "opaque" and not extended):
            continue
        # An opening quote belongs to the option unless it closes a preceding word.
        quote = text[start - 1] if start and text[start - 1] in "\"'" else ""
        if quote and start > 1 and _CLI_BOUNDARY.match(text, start - 2):
            quote = ""
        # An option inside a value withheld before it is part of that value,
        # but in the last pass its own value after that one is still read:
        # main read the 'opaque' options in a pass of their own, after every
        # other option's value was withheld, so a value only the last pass
        # withholds ('--auth x=--pwd v', '-H "api-key:x --pass v' with a quote
        # that never closes) must not hide them. Inside an 'opaque' value
        # they are skipped, as main's pass skipped them.
        if start - len(quote) < cursor and skip_inside:
            continue
        span = _option_value_span(text, match, mode, quote, runs, extended)
        if span is None or span[0] < cursor:
            continue
        spans.append(span)
        cursor = span[1]
        skip_inside = not extended or mode == "opaque"
    return _withhold_spans(text, spans)


def _option_value_span(
    text: str,
    match: re.Match[str],
    mode: str,
    quote: str,
    runs: _ValueRuns,
    extended: bool,
) -> tuple[int, int] | None:
    """The credential that the option ``match`` of ``mode`` passes, if any.

    ``quote`` is the quote that opens the option ('"--api-key=v"'), or ''.
    ``extended`` reads values as the last pass does (see ``_cli_value_span``).
    """
    start, position = match.start(), match.end()
    strict = text.startswith("=", position)
    if mode == "attached":
        return _cli_value_span("secret", text, start + 2, True, runs, extended)
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
        return _cli_value_span(mode, text, gap.end(), False, runs, extended)
    # Plain text, or a quote that does not delimit this option.
    if strict:
        return _cli_value_span(mode, text, position + 1, True, runs, extended)
    gap = _CLI_SPACE.match(text, position)
    return None if gap is None else _cli_value_span(mode, text, gap.end(), False, runs, extended)


# Cookie headers hold several 'name=value' pairs separated by ';', any of
# which can be a session credential and may be quoted (sid="v"), so the whole
# header value is withheld, to the end of the line. A header may follow a
# JSON string escape ('\r\nCookie: ...'). The established
# assignment rules withhold only the first pair and quote it ('Cookie:
# "[REDACTED]"; sid=v'), and the mapping rules then read a quoted marker
# together with what follows it to the next ';', so a value cut at a quote
# would grow on every pass. The pattern stops before the value:
# _redact_cookie_headers finds the end of the line only when it withholds the
# value, so a line of many cookie arguments is read once.
_COOKIE_HEADER = re.compile(
    r"(?i)(?:(?<![\w.-])|(?<=\\[nrtbf])|(?<=\\u[0-9a-f]{4}))(?P<key>set-cookie2?|cookie2?)"
    r"(?P<sep>[ \t]*[:=][ \t]*)(?=\S)"
)
_LINE_END = re.compile(r"[\r\n]")
# A cookie assigned with '=' that the established passes withheld whole as a
# quoted marker, which a ',', ')', ']' or '}' then ends: an argument
# ('get(url, cookie=session_cookie, timeout=5)') or a field. What follows it
# is the next argument, not another cookie. (A ';' after it is: 'f(cookie=a;
# sid=v)' leaves 'f(cookie="[REDACTED]"; sid=v)'.)
_COOKIE_ARGUMENT = re.compile(r"(?P<quote>[\"'])\[REDACTED\](?P=quote)[ \t]*[,)\]}]")


def _redact_cookie_headers(text: str) -> str:
    """Withhold the value of a Cookie or Set-Cookie header (see ``_COOKIE_HEADER``).

    Runs after every established pass. The marker is left bare: the mapping
    rules quote it after a colon ('Cookie: "[REDACTED]"'), and after '=' the
    statement rules, which run again once this pass changed the text, quote
    it where it is an argument ('cookie="[REDACTED]"'). After '=', an
    argument the established passes already withheld ends the argument (see
    ``_COOKIE_ARGUMENT``), and the rest of its line is read for another
    header ('get(u, cookie=c, timeout=5) Cookie: ...').
    """
    out: list[str] = []
    pos = 0
    while (match := _COOKIE_HEADER.search(text, pos)) is not None:
        start = match.end()
        if "=" in match.group("sep"):
            argument = _COOKIE_ARGUMENT.match(text, start)
            if argument is not None:
                out.append(text[pos : argument.end()])
                pos = argument.end()
                continue
        line_end = _LINE_END.search(text, start)
        end = len(text) if line_end is None else line_end.start()
        raw = text[start:end]
        bare = raw.rstrip(" \t")
        out.append(text[pos:start])
        if _ALPHANUMERIC.search(bare.replace(REDACTED, "")) is None:
            out.append(raw)  # already withheld: only markers and punctuation are left
        else:
            out.append(_redact_value(bare) + raw[len(bare) :])
        pos = end
    out.append(text[pos:])
    return "".join(out)


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
