"""Credentials recognizable by format: provider tokens, JWTs, keys and URLs.

Internal to :mod:`shadowscan.utils.redaction`, which re-exports every name
here. These rules need no context: a prefixed provider token, a JWT, a PEM
private key or an authorization scheme is withheld wherever it appears, and a
URL loses its userinfo, credential-bearing webhook path and sensitive query
fields (some only in the extended pass, see ``_ADDED_QUERY_NAMES``).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from urllib.parse import unquote

from shadowscan.utils.redaction_rules import REDACTED, _sensitive_assignment_key

# Keep this backstop aligned with detectable credential formats regardless of
# which signature packs the operator enables for discovery.
_TOKEN_FORMATS = (
    r"sk-(?:proj-|ant-|live-|or-v1-|lf-|litellm-|svcacct-|admin-)?[A-Za-z0-9_-]{8,}"
    r"|gh[pousr]_[A-Za-z0-9]{8,}|github_pat_[A-Za-z0-9_]{8,}"
    # GitLab personal/runner/trigger/deploy/feed/SCIM/CI/mail/OAuth/agent tokens.
    r"|gl(?:pat|rt|ptt|dt|ft|soat|cbt|imt|oas|agent|ffct)-[A-Za-z0-9_-]{8,}|GR1348941[A-Za-z0-9_-]{20,}"
    r"|xox[abeprs]-[A-Za-z0-9-]{8,}|xoxe\.xox[bp]-[A-Za-z0-9-]{8,}|xapp-[A-Za-z0-9-]{8,}"
    # Google API keys, OAuth access/refresh tokens and OAuth client secrets.
    r"|AIza[A-Za-z0-9_-]{16,}|ya29\.[A-Za-z0-9_-]{20,}|1//0[A-Za-z0-9_-]{30,}|GOCSPX-[A-Za-z0-9_-]{20,}"
    r"|(?:AKIA|ASIA)[A-Z0-9]{16}|hf_[A-Za-z0-9]{8,}"
    r"|gsk_[A-Za-z0-9]{40,}|pcsk_[A-Za-z0-9_]{20,}|e2b_[a-f0-9]{40}|tgp_v1_[A-Za-z0-9_-]{30,}"
    r"|lsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10}|tvly-(?:dev-|prod-)?[A-Za-z0-9_-]{20,}"
    r"|xai-[A-Za-z0-9]{60,}|pplx-[A-Za-z0-9]{40,}|csk-[A-Za-z0-9]{30,}|nvapi-[A-Za-z0-9_-]{60,}"
    r"|r8_[A-Za-z0-9]{30,}|fc-[a-f0-9]{32}|app-[A-Za-z0-9]{24}|sk_[a-f0-9]{40,}"
    # Package registries, cloud platforms and developer SaaS.
    r"|npm_[A-Za-z0-9]{30,}|pypi-AgE[A-Za-z0-9_-]{40,}|do[opr]_v1_[a-f0-9]{64}"
    r"|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}|whsec_[A-Za-z0-9]{24,}"
    r"|SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}|dapi[a-f0-9]{32}|shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}"
    r"|ATATT3[A-Za-z0-9_=-]{40,}|lin_api_[A-Za-z0-9]{32,}|ntn_[A-Za-z0-9]{40,}"
    r"|PMAK-[a-f0-9]{24}-[a-f0-9]{34}|dp\.(?:pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,}"
    r"|sbp_[a-f0-9]{40}|sb_secret_[A-Za-z0-9_-]{20,}|glsa_[A-Za-z0-9]{32}_[a-f0-9]{8}|glc_[A-Za-z0-9+/]{32,}"
    r"|sntry[su]_[A-Za-z0-9+/=_-]{30,}|hv[sbr]\.[A-Za-z0-9_-]{24,}"
    r"|[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,}"
)
_SECRET_TOKEN = re.compile(r"\b(?:" + _TOKEN_FORMATS + r")\b")
# The extended pass reads the formats again with ASCII-only boundaries:
# ``\b`` reads CJK and other letters as word characters, so a key written
# directly before or after non-Latin text ('密钥sk-...') was kept. It also
# reads Fireworks AI keys: the vendor prefix and a digit somewhere in a long
# key, so an identifier such as 'fw_ConfigurationManagerFactory' is left
# alone. Read in the established pass, a key glued to a following name
# ('fw_...éKey: v', 'fw_...-2PASSWORD=v') hid that name from the rules that
# withhold by it.
_ADDED_SECRET_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_])(?:" + _TOKEN_FORMATS + r"|fw_(?=[A-Za-z]*\d)[A-Za-z0-9]{24,})(?<!-)(?![A-Za-z0-9_])"
)
# Webhook and bot endpoints whose *path* is the credential. The scheme, host
# and a fixed prefix are kept for context; the remainder of the path is
# withheld. Query parameters (e.g. Power Automate's ``sig``) are handled by the
# ordinary query-field rules.
_PATH_SECRET_RULES: tuple[tuple[re.Pattern[str], re.Pattern[str]], ...] = (
    (
        re.compile(r"hooks\.slack(?:-gov)?\.com"),
        re.compile(r"/(?:services|workflows|triggers|actions|commands)/"),
    ),
    (re.compile(r"(?:(?:ptb|canary)\.)?discord(?:app)?\.com"), re.compile(r"/api(?:/v\d+)?/webhooks/")),
    (re.compile(r"(?:[a-z0-9-]+\.)*webhook\.office\.com"), re.compile(r"/webhook(?:b2)?/")),
    (re.compile(r"outlook\.office(?:365)?\.com"), re.compile(r"/webhook(?:b2)?/")),
    (re.compile(r"hooks\.zapier\.com"), re.compile(r"/hooks/")),
    (re.compile(r"hook\.(?:[a-z0-9-]+\.)?(?:make|integromat)\.com"), re.compile(r"/")),
    (re.compile(r"maker\.ifttt\.com"), re.compile(r"/trigger/[^/]+/(?:json/)?with/key/")),
    (re.compile(r"api\.telegram\.org"), re.compile(r"/(?:file/)?bot")),
    # n8n (commonly self-hosted, so any host): /webhook/<id> and /webhook-test/<id>.
    (re.compile(r".+"), re.compile(r"(?:/[^/]+)*?/webhook(?:-test|-waiting)?/")),
)
# A token starts only at the beginning of a run of token characters or after a
# '-' inside one, never mid-word ('abceyJ...'), and every quantifier is
# possessive. The ``prefix`` group walks the run's '-' separated chunks once
# and is kept by the replacement ('x-eyJ...' becomes 'x-[REDACTED]'), so each
# character is read a bounded number of times: a long run of 'eyJ-eyJ-...'
# with no '.' is linear, where '\beyJ[A-Za-z0-9_-]*\.' retried at every
# 'eyJ' and was quadratic. The established ``_JWT`` withholds exactly what
# that pattern did: '\b' before 'eyJ' becomes '(?<!\w)', which a '-' prefix
# meets and a letter does not, so a run right after a non-Latin letter
# ('密eyJa-eyJ...') first skips its first chunk, where no token can start.
# ``_ADDED_JWT`` starts one there too ('密钥eyJ...'), in the extended pass.
_JWT_BODY = r"eyJ[A-Za-z0-9_-]*+\.[A-Za-z0-9_-]++\.[A-Za-z0-9_-]*+"
_JWT = re.compile(
    r"(?<![A-Za-z0-9_-])(?P<prefix>(?:(?<=\w)[A-Za-z0-9_]*+-)?+(?:(?!eyJ)[A-Za-z0-9_]*+-)*+)(?<!\w)"
    + _JWT_BODY
)
_ADDED_JWT = re.compile(r"(?<![A-Za-z0-9_-])(?P<prefix>(?:(?!eyJ)[A-Za-z0-9_]*+-)*+)" + _JWT_BODY)
_PEM = re.compile(
    r"-----BEGIN (?:[A-Z ]{0,30})PRIVATE KEY-----.*?(?:-----END (?:[A-Z ]{0,30})PRIVATE KEY-----|\Z)",
    re.DOTALL,
)
# OpenPGP's armored 'PRIVATE KEY BLOCK', in the extended pass.
_ADDED_PEM = re.compile(
    r"-----BEGIN (?:[A-Z ]{0,30})PRIVATE KEY BLOCK-----.*?"
    r"(?:-----END (?:[A-Z ]{0,30})PRIVATE KEY BLOCK-----|\Z)",
    re.DOTALL,
)
_AUTH = re.compile(r"(?i)\b(Bearer|Basic|SSWS)\s+[A-Za-z0-9+/_.=-]+")
_URL = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]{0,20}://[^\s<>\"']+")
_QUERY_SEPARATOR = re.compile(r"[&#]")


def _url_host(authority: str) -> str:
    host = authority.rsplit("@", 1)[-1]
    if host.startswith("["):
        host = host[1 : host.find("]")] if "]" in host else host[1:]
    else:
        host = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
    return host.rstrip(".").lower()


def _redact_path_secret(host: str, path: str) -> str:
    """Withhold the credential-bearing remainder of a known webhook path.

    Idempotent: an already withheld path is returned unchanged.
    """
    if not host or not path:
        return path
    for host_rx, prefix_rx in _PATH_SECRET_RULES:
        if not host_rx.fullmatch(host):
            continue
        prefix = prefix_rx.match(path)
        if prefix and prefix.end() < len(path):
            return path[: prefix.end()] + REDACTED
    return path


def _sanitize_url(match: re.Match[str]) -> str:
    url = match.group(0)
    scheme, rest = url.split("://", 1)
    # Userinfo ends at the authority boundary, not at the first slash alone.
    # An @ in a query value must not be mistaken for a hostname separator.
    authority_end = min((pos for c in "/?#" if (pos := rest.find(c)) >= 0), default=len(rest))
    authority, tail = rest[:authority_end], rest[authority_end:]
    if "@" in authority:
        authority = REDACTED + "@" + authority.rsplit("@", 1)[1]
    path_end = min((pos for c in "?#" if (pos := tail.find(c)) >= 0), default=len(tail))
    tail = _redact_path_secret(_url_host(authority), tail[:path_end]) + tail[path_end:]
    url = scheme + "://" + authority + tail

    def sensitive(name: str) -> bool:
        return _sensitive_assignment_key(name) or name in {
            "key",
            "sig",
            "signature",
            "code",
            "x-amz-signature",
            "x-goog-signature",
        }

    return _redact_query_fields(url, sensitive)


# Query and fragment fields only the extended pass withholds, in a URL the
# established passes left: an AWS STS session token and short credential
# names. Withheld in the first URL pass, a value glued to a following name
# ('?auth=AzureKeyCredential("v")') hid that name from the call rules.
_ADDED_QUERY_NAMES = frozenset({"x-amz-security-token", "auth", "pwd", "pat"})


def _sanitize_url_fields(match: re.Match[str]) -> str:
    """Withhold the URL fields named in ``_ADDED_QUERY_NAMES`` (the extended pass)."""
    return _redact_query_fields(match.group(0), lambda name: name in _ADDED_QUERY_NAMES)


def _redact_query_fields(url: str, sensitive: Callable[[str], bool]) -> str:
    """Withhold each query or fragment field of ``url`` whose decoded, lowercase name is ``sensitive``."""

    def query_value(field: str) -> str:
        key, equals, value = field.partition("=")
        if not equals:
            return field
        return key + equals + (REDACTED if sensitive(unquote(key).lower()) else value)

    # Consume each field once. A regex that retries an unbounded key after every
    # '?' takes quadratic time on a URL containing many '?' and no '='. Keep '?'
    # within values (it is legal there) so redacting a secret never retains its
    # suffix. Fragment parameters receive the same protection as query fields.
    start = min((pos for c in "?&#" if (pos := url.find(c)) >= 0), default=len(url))
    if start == len(url):
        return url
    parts = [url[: start + 1]]
    cursor = start + 1
    for separator in _QUERY_SEPARATOR.finditer(url, cursor):
        parts.append(query_value(url[cursor : separator.start()]))
        parts.append(separator.group(0))
        cursor = separator.end()
    parts.append(query_value(url[cursor:]))
    return "".join(parts)


def _redact_added_formats(text: str) -> str:
    """Withhold what the extended pass adds to the formats: PGP private keys, tokens next to non-Latin text.

    Runs after every pass that reads a name (see ``_ADDED_SECRET_TOKEN``).
    """
    text = _ADDED_PEM.sub(lambda m: REDACTED + "\n" * m.group(0).count("\n"), text)
    text = _ADDED_JWT.sub(r"\g<prefix>" + REDACTED, text)
    return _ADDED_SECRET_TOKEN.sub(REDACTED, text)
