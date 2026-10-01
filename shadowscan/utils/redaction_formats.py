"""Credentials recognizable by format: provider tokens, JWTs, keys and URLs.

Internal to :mod:`shadowscan.utils.redaction`, which re-exports every name
here. These rules need no context: a prefixed provider token, a JWT, a PEM
private key or an authorization scheme is withheld wherever it appears, and a
URL loses its userinfo, credential-bearing webhook path and sensitive query
fields.
"""

from __future__ import annotations

import re
from urllib.parse import unquote

from shadowscan.utils.redaction_rules import REDACTED, _sensitive_assignment_key

# A token inside a longer identifier ('risk-assessment-2024') is not one, so a
# prefix needs a boundary before it. '\b' is too strict: 'n', 'D' and '_' are word
# characters, so it hid a token behind an escaped line break ('...key:\nsk-proj-...'
# in a trace or fixture), behind a percent escape ('?next=%2Fv1%3Fapi_key%3Dsk-proj-...')
# and behind an underscore ('cfg_sk-proj-...'). Those count as boundaries. A prefix that
# no ordinary word contains ('sk-proj-', 'ghp_', 'AKIA', JWT 'eyJ') also stands after a
# digit; the others keep the usual rule so a word or number that ends in their text
# ('disk-', 'task-', '2app-') is not read as a token.
_ESCAPED_BOUNDARY = r"(?<=\\[nrt])|(?<=\\x[0-9A-Fa-f]{2})|(?<=\\u[0-9A-Fa-f]{4})|(?<=%[0-9A-Fa-f]{2})"
_TOKEN_START = r"(?:(?<![A-Za-z0-9])|" + _ESCAPED_BOUNDARY + ")"
_SPECIFIC_TOKEN_START = r"(?:(?<![A-Za-z])|" + _ESCAPED_BOUNDARY + ")"
# Keep this backstop aligned with detectable credential formats regardless of
# which signature packs the operator enables for discovery.
_SECRET_TOKEN = re.compile(
    r"(?:"
    + _SPECIFIC_TOKEN_START
    + r"(?:sk-(?:proj|ant|live|or-v1|lf|litellm|svcacct|admin)-[A-Za-z0-9_-]{8,}"
    r"|gh[pousr]_[A-Za-z0-9]{8,}|github_pat_[A-Za-z0-9_]{8,}"
    # GitLab personal/runner/trigger/deploy/feed/SCIM/CI/mail/OAuth/agent tokens.
    r"|gl(?:pat|rt|ptt|dt|ft|soat|cbt|imt|oas|agent|ffct)-[A-Za-z0-9_-]{8,}|GR1348941[A-Za-z0-9_-]{20,}"
    r"|xox[abeprs]-[A-Za-z0-9-]{8,}|xoxe\.xox[bp]-[A-Za-z0-9-]{8,}|xapp-[A-Za-z0-9-]{8,}"
    # Google API keys, OAuth access/refresh tokens and OAuth client secrets.
    r"|AIza[A-Za-z0-9_-]{16,}|ya29\.[A-Za-z0-9_-]{20,}|1//0[A-Za-z0-9_-]{30,}|GOCSPX-[A-Za-z0-9_-]{20,}"
    r"|(?:AKIA|ASIA)[A-Z0-9]{16}|hf_[A-Za-z0-9]{8,})"
    r"|" + _TOKEN_START + r"(?:sk-[A-Za-z0-9_-]{8,}"
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
    r"|[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,}))\b"
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
# A JWT starts at an 'eyJ' that follows the boundary rule above and runs to the end of
# its third dotted segment. Each attempt starts at a run of base64url characters and
# reads the characters before the first such 'eyJ' as 'lead', which is kept: an attempt
# from every 'eyJ' would read a run of 'eyJ-eyJ-eyJ-...' without dots once per 'eyJ',
# which takes quadratic time, and every run is read once here. Use ``_redact_jwts``.
_JWT_HEADER = r"(?=eyJ)" + _SPECIFIC_TOKEN_START + "eyJ"
_JWT = re.compile(
    r"(?<![A-Za-z0-9_-])(?P<lead>(?:(?!" + _JWT_HEADER + r")[A-Za-z0-9_-])*+)"
    r"(?P<jwt>" + _JWT_HEADER + r"[A-Za-z0-9_-]*+\.[A-Za-z0-9_-]++\.[A-Za-z0-9_-]*+)"
)
_PEM = re.compile(
    r"-----BEGIN (?:[A-Z ]{0,30})PRIVATE KEY-----.*?(?:-----END (?:[A-Z ]{0,30})PRIVATE KEY-----|\Z)",
    re.DOTALL,
)
# A scheme after an escaped line break or a percent escape ('...header:\nBearer v') is read as well.
_AUTH = re.compile(r"(?i)(?:\b|" + _ESCAPED_BOUNDARY + r")(Bearer|Basic|SSWS)\s+[A-Za-z0-9+/_.=-]+")
_URL = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]{0,20}://[^\s<>\"']+")
_QUERY_SEPARATOR = re.compile(r"[&#]")


def _redact_jwts(text: str) -> str:
    """Withhold every JSON Web Token in ``text``, keeping what precedes its 'eyJ'."""
    if "eyJ" not in text:
        return text
    return _JWT.sub(lambda match: match.group("lead") + REDACTED, text)


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

    def query_value(field: str) -> str:
        key, equals, value = field.partition("=")
        if not equals:
            return field
        decoded = unquote(key).lower()
        sensitive = _sensitive_assignment_key(decoded) or decoded in {
            "key",
            "sig",
            "signature",
            "code",
            "x-amz-signature",
            "x-goog-signature",
        }
        return key + equals + (REDACTED if sensitive else value)

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
