"""Shared redaction policy: the marker, sensitive names, limits and value tests.

Internal to :mod:`shadowscan.utils.redaction`, which re-exports every name
here. Replace a rule through that module so every pass that binds it sees
the replacement.
"""

from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED]"
_FINGERPRINT = re.compile(r"^credential:sha256:[a-f0-9]{64}$")
_SENSITIVE_SUFFIXES = (
    "apikey",
    "accesskey",
    "secretkey",
    "keystring",
    "privatekeydata",
    "accesskeyid",
    "secretaccesskey",
    "accesstoken",
    "refreshtoken",
    "idtoken",
    "authtoken",
    "apitoken",
    "foundrytoken",
    "githubtoken",
    "clientsecret",
    "authorization",
    "proxyauthorization",
    "password",
    "passwd",
    "privatekey",
    "credential",
    "credentials",
    "bearertoken",
    "sessiontoken",
    "signingkey",
    "secretstring",
    "secretbinary",
    "connectionstring",
    "connstr",
    # Azure storage / Service Bus connection-string members and SAS tokens.
    "accountkey",
    "sharedaccesskey",
    "sastoken",
    # Capability URLs: whoever holds a webhook URL can post through it.
    "webhookurl",
    "webhookuri",
    "webhookid",
    "hookurl",
    # Azure API Management and AI services (Ocp-Apim-Subscription-Key).
    "subscriptionkey",
)
_SENSITIVE_NAMES = {
    "token",
    "jwt",
    "secret",
    "bearer",
    "passwd",
    "password",
    "authorization",
    "cookie",
    "setcookie",
}
_MAX_SANITIZATION_NODES = 100_000
_MAX_SANITIZATION_CHARS = 64 * 1024 * 1024
_MAX_REDACTION_WORK = 128 * 1024 * 1024
_KEY_NORMALISE = re.compile(r"[^a-z0-9]")
# Environment-style credential names: an underscore-separated identifier ending
# in KEY/TOKEN/SECRET/... names a credential by convention (AZURE_OPENAI_KEY,
# DATABRICKS_TOKEN, MODAL_TOKEN_SECRET, LITELLM_MASTER_KEY) even though the bare
# suffixes are too broad for arbitrary record fields (S3 object keys, pagination
# tokens, tag "Key" members). Applied to assignments in text excerpts only, where
# over-redaction of a sort key or a page token costs nothing.
_ASSIGNMENT_CREDENTIAL_NAME = re.compile(
    r"(?i)[a-z][a-z0-9]*(?:_[a-z0-9]+)*_(?:key|token|secret|password|passwd|credentials?)"
)


class SanitizationLimitError(ValueError):
    """Evidence cannot be safely sanitized within the work/output budget."""


def _sensitive_key(key: str) -> bool:
    normalized = _KEY_NORMALISE.sub("", key.lower())
    # This runs for every key of every sanitized record. ``str.endswith`` with
    # a tuple compares the suffixes in C; a Python loop over length-bucketed
    # sets measured about twice as slow per key, so keep the builtin.
    return normalized in _SENSITIVE_NAMES or normalized.endswith(_SENSITIVE_SUFFIXES)


def _sensitive_assignment_key(key: str) -> bool:
    """Sensitive-key test for assignments and mapping entries inside text."""
    return _sensitive_key(key) or _ASSIGNMENT_CREDENTIAL_NAME.fullmatch(key.strip()) is not None


def _redact_value(value: Any) -> Any:
    if value is None or value == "" or value == b"":
        return value
    if isinstance(value, str) and (value == REDACTED or _FINGERPRINT.fullmatch(value)):
        return value
    return REDACTED


# The words of a name: 'AzureKeyCredential' is Azure, Key, Credential.
_CALLEE_WORD = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")
# Names whose last word names a credential (openaiKey, OPENAI-KEY, dbPass,
# stripe.secretKey, key) also name sort keys, page tokens and cache keys, so
# only a literal that looks like an opaque key is withheld from them.
_OPAQUE_NAME = re.compile(r"[A-Za-z_$][\w$-]*(?:\.[A-Za-z_$][\w$-]*)*")
_OPAQUE_NAME_WORDS = frozenset(
    {
        "apikey",
        "credential",
        "credentials",
        "key",
        "pass",
        "passwd",
        "password",
        "pwd",
        "secret",
        "token",
    }
)
# Values that name, locate or stand in for a credential instead of being one.
_REFERENCE = re.compile(
    r"\$\{\{[^{}\r\n]*\}\}|\{\{[^{}\r\n]*\}\}|\$\{[A-Za-z_][A-Za-z0-9_.]*\}|\$\([^()\r\n]*\)"
    r"|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%|<[A-Za-z][A-Za-z0-9 _.-]*>|#\{[^{}\r\n]*\}"
)
_ALPHANUMERIC = re.compile(r"[A-Za-z0-9]")
_ENVIRONMENT_NAME = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+")
_FILE_PATH = re.compile(r"(?:[\w.~-]*[/\\])+[\w.-]+\.[A-Za-z][A-Za-z0-9]{0,5}")
_PLACEHOLDER_WORDS = frozenset(
    {
        "changeme",
        "dummy",
        "example",
        "fake",
        "insert",
        "placeholder",
        "redacted",
        "replace",
        "replaceme",
        "sample",
        "todo",
        "your",
    }
)
_PLACEHOLDER_FILL = re.compile(r"(?i)x{4,}|\*{4,}|\.{3,}")
# Random keys change character class (digit, lower, upper) often inside one
# long alphanumeric run; names, words and model identifiers rarely do.
_OPAQUE_RUN = re.compile(r"[A-Za-z0-9]{8,}")
# A lowercase word: prose or an argument name rather than a value.
_CLI_WORD = re.compile(r"[a-z][a-z_-]*")
# A ';' ends an unquoted value only before whitespace, the end of the text or
# another 'name=' pair (connection strings, shell lists): a password may hold
# one ('PASSWORD=Ab;cd'). The established passes end the value at any ';';
# the extended ones withhold the rest of the value past a ';' glued to it.
_GLUED_SEMICOLON = r";(?!\s|\Z|[A-Za-z_][A-Za-z0-9_.-]*\s*=)"


def _kept_value(value: str) -> bool:
    """Empty, already withheld, or only variable references and placeholders."""
    value = value.strip()
    return (
        _FINGERPRINT.fullmatch(value) is not None
        or _ALPHANUMERIC.search(_REFERENCE.sub("", value.replace(REDACTED, ""))) is None
    )


def _opaque(value: str) -> bool:
    for run in _OPAQUE_RUN.finditer(value):
        classes = ["d" if char.isdigit() else "u" if char.isupper() else "l" for char in run.group()]
        # An upper-to-lower change starts a capitalized word, not a new class.
        changes = sum(a != b and (a, b) != ("u", "l") for a, b in zip(classes, classes[1:], strict=False))
        if changes >= 3:
            return True
    return False


def _placeholder(value: str) -> bool:
    words = {word.lower() for word in _CALLEE_WORD.findall(value)}
    return not _PLACEHOLDER_WORDS.isdisjoint(words) or _PLACEHOLDER_FILL.search(value) is not None


def _credential_literal(value: str, *, positional: bool) -> bool:
    """Whether a string literal passed to a credential-named callee is a credential."""
    if _kept_value(value) or any(char.isspace() for char in value) or "://" in value:
        return False
    if _ENVIRONMENT_NAME.fullmatch(value) or _FILE_PATH.fullmatch(value) or _placeholder(value):
        return False
    return positional or _opaque(value)


def _interpolated(prefix: str, quote: str, value: str) -> bool:
    """Whether a literal with ``prefix`` and ``quote`` assembles its text from expressions.

    C# '$"..."' always is; a Python f-string or a JavaScript template only
    when it holds a replacement field.
    """
    if "$" in prefix:
        return True
    if "f" in prefix.lower():
        return "{" in value
    return quote == "`" and "${" in value


def _credential_name(name: str, *, numbered: bool = False) -> bool:
    """Whether a name's last word names a credential ('monkey' and 'bypass' do not).

    With ``numbered``, trailing digits number a credential rather than name it
    ('KEY1', 'token2'); the established passes read the last word as it is.
    """
    if not _OPAQUE_NAME.fullmatch(name):
        return False
    words = _CALLEE_WORD.findall(name.rsplit(".", 1)[-1])
    while numbered and words and words[-1].isdigit():
        words.pop()
    return bool(words) and words[-1].lower() in _OPAQUE_NAME_WORDS


# .NET configuration, environment variables and properties name a setting by
# its path ('AzureOpenAI:Key', 'AzureOpenAI__Key', 'openai.token'); the last
# segment names what the setting holds.
_SETTING_SEGMENT = re.compile(r":|__|\.")


def _setting_level(name: str, *, record: bool = False) -> int:
    """How a setting named ``name`` identifies its value as a credential.

    2: the name alone does ('Token', 'OpenAI:Secret', 'OPENAI_API_KEY'), so
    any value is withheld. 1: its last word names a credential ('OpenAIKey',
    'AzureOpenAI:Key', 'CacheKey', 'KEY1'), so only an opaque literal is
    withheld, as for the same names in assignments. 0: an ordinary setting.
    A ``record`` is a field of a structured record, where an
    environment-style name ('PAGE_TOKEN', 'SORT_KEY') is too broad to
    withhold any value (see _ASSIGNMENT_CREDENTIAL_NAME) and counts as 1.
    """
    sensitive = _sensitive_key if record else _sensitive_assignment_key
    last = _SETTING_SEGMENT.split(name)[-1]
    if sensitive(name) or (last != name and sensitive(last)):
        return 2
    named = _credential_name(name, numbered=True) or (last != name and _credential_name(last, numbered=True))
    return 1 if named else 0


def _setting_value_withheld(level: int, value: Any) -> bool:
    """Whether a setting of ``level`` (see ``_setting_level``) withholds ``value``.

    Only a string can be the opaque literal a level-1 name withholds.
    """
    if level == 2:
        return True
    return level == 1 and isinstance(value, str) and _credential_literal(value.strip(), positional=False)


def _name_before(text: str, end: int, characters: str) -> str:
    """The longest run of letters, digits and ``characters`` that ends at ``end``."""
    start = end
    while start > 0 and (text[start - 1].isalnum() or text[start - 1] in characters):
        start -= 1
    return text[start:end]


def _blanks_before(text: str, end: int) -> int:
    """Where the spaces and tabs that end at ``end`` start."""
    while end > 0 and text[end - 1] in " \t":
        end -= 1
    return end


def _withhold_spans(text: str, spans: list[tuple[int, int]]) -> str:
    """Replace each span that does not overlap an earlier one with the marker."""
    if not spans:
        return text
    pieces: list[str] = []
    cursor = 0
    for start, end in sorted(spans):
        if start >= cursor:
            pieces.append(text[cursor:start])
            pieces.append(REDACTED)
            cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)
