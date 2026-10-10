"""Opt-in A2A Agent Card probe and card signature checks for ``endpoint.mcp``.

The operator lists card URLs or agent origins. A bare origin (no path, or
``/``) is probed at ``/.well-known/agent-card.json`` and, only on HTTP 404,
at the older ``/.well-known/agent.json``. URLs a card declares (interfaces,
provider, documentation, icons, a signature header's ``jku``) are never
fetched. Every fetch uses the shared HTTPS client: same-origin redirects only,
private, loopback and metadata addresses refused unless the scan sets
``options.allow_private_origin``, a 1 MiB body cap and strict JSON
(duplicate keys and non-finite numbers refused).

Signatures are verified only against the operator's ``agent_card_jwks_url``
key set. The payload is the RFC 8785 canonical card without ``signatures``.
Signers disagree on which empty values they drop first, so each signature is
checked against three forms of the card (see ``signed_forms``). The forms
differ only by nulls and empty strings, arrays and objects, so a ``verified``
card differs from what was signed by nothing else; it is then read as the form
its signature covers, so an empty value added to the served card (an empty
``securitySchemes`` entry) decides nothing.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit, urlunsplit

from jwt.exceptions import InvalidSignatureError

from shadowscan.connectors.base import ConnectorError, _positive_limit
from shadowscan.utils.http import HttpClient, HttpError
from shadowscan.utils.jcs import MAX_DEPTH, CanonicalizationError, canonicalize
from shadowscan.utils.jwks import verify_detached_jws
from shadowscan.utils.redaction import REDACTED

RECORD_TYPE = "a2a_card"
WELL_KNOWN_CARD_PATH = "/.well-known/agent-card.json"
LEGACY_CARD_PATH = "/.well-known/agent.json"
MAX_CARD_BYTES = 1024 * 1024
DEFAULT_MAX_AGENT_CARDS = 100


def https_url(value: Any, name: str) -> str:
    """Check an operator-supplied HTTPS URL without resolving it; messages never echo the value.

    The shared client repeats the full check, including the private-address
    policy, when it connects.
    """
    if not isinstance(value, str) or not value or any(c.isspace() or not c.isprintable() for c in value):
        raise ConnectorError(f"endpoint.mcp: {name} must be an HTTPS URL without whitespace")
    try:
        parts = urlsplit(value)
        _ = parts.port
    except ValueError:
        raise ConnectorError(f"endpoint.mcp: {name} is not a valid URL") from None
    if parts.scheme != "https" or not parts.hostname or "@" in parts.netloc:
        raise ConnectorError(f"endpoint.mcp: {name} must use HTTPS without embedded credentials")
    return value


def agent_card_urls(value: Any, limit: Any) -> list[str]:
    """The configured card URLs, in order and without repeats; a list over the limit is refused, never cut."""
    maximum = _positive_limit(DEFAULT_MAX_AGENT_CARDS if limit is None else limit, "max_agent_cards")
    if value is None:
        return []
    if not isinstance(value, list):
        raise ConnectorError("endpoint.mcp: agent_card_urls must be a list of HTTPS URLs")
    if len(value) > maximum:
        raise ConnectorError(
            f"endpoint.mcp: agent_card_urls lists {len(value)} URLs, more than max_agent_cards ({maximum})"
        )
    return list(
        dict.fromkeys(https_url(item, f"agent_card_urls entry {n}") for n, item in enumerate(value, 1))
    )


def card_resource(url: str) -> str:
    """A card URL without userinfo, query or fragment, and without the default port: the finding identity."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    authority = f"[{host}]" if ":" in host else host
    if parts.port not in (None, 443):
        authority += f":{parts.port}"
    return urlunsplit(("https", authority, parts.path or "/", "", ""))


def fetch_card(url: str, *, ca_bundle: str | None = None) -> tuple[str, Any]:
    """Fetch one configured card: ``(card URL without query, decoded JSON)``.

    Raises on every failure: transport, HTTP status (a 404 at the well-known
    path tries the legacy path once), redirect off the origin, size, or JSON.
    """
    parts = urlsplit(url)
    origin = urlunsplit(("https", parts.netloc, "", "", ""))
    client = HttpClient(base_url=origin, ca_bundle=ca_bundle, max_response_bytes=MAX_CARD_BYTES)
    try:
        if parts.path not in ("", "/"):
            target = urlunsplit(("", "", parts.path, parts.query, ""))
            return card_resource(url), client.get_json(target, max_bytes=MAX_CARD_BYTES)
        try:
            data = client.get_json(WELL_KNOWN_CARD_PATH, max_bytes=MAX_CARD_BYTES)
            return card_resource(origin + WELL_KNOWN_CARD_PATH), data
        except HttpError as exc:
            if exc.status != 404:
                raise
        data = client.get_json(LEGACY_CARD_PATH, max_bytes=MAX_CARD_BYTES)
        return card_resource(origin + LEGACY_CARD_PATH), data
    finally:
        client.session.close()


# A2A 1.0 members the specification keeps when empty (REQUIRED or proto
# ``optional``, a2a.proto), and the message a member's value or items hold.
_Fields = tuple[frozenset[str], dict[str, Any]]
_NO_FIELDS: _Fields = (frozenset(), {})
_CARD_FIELDS: _Fields = (
    frozenset(
        {
            "name",
            "description",
            "supportedInterfaces",
            "version",
            "documentationUrl",
            "capabilities",
            "defaultInputModes",
            "defaultOutputModes",
            "skills",
            "iconUrl",
        }
    ),
    {
        "supportedInterfaces": (frozenset({"url", "protocolBinding", "protocolVersion"}), {}),
        "provider": (frozenset({"url", "organization"}), {}),
        "skills": (frozenset({"id", "name", "description", "tags"}), {}),
    },
)


def signed_forms(card: dict[str, Any]) -> list[tuple[dict[str, Any], bytes]]:
    """The forms of a card a signature may cover, each with its canonical bytes, without repeats.

    In order: the card as served; with every null, empty string, array and
    object removed recursively (the A2A Python SDK's signer); and with empty
    members removed except those the A2A 1.0 schema marks REQUIRED or
    ``optional``, list items kept (the specification's section 8.4.1
    example). A signer that also drops ``false`` or ``0`` defaults matches
    none of them. Raises CanonicalizationError.
    """
    unsigned = {key: value for key, value in card.items() if key != "signatures"}
    forms: dict[bytes, dict[str, Any]] = {}
    for form in (unsigned, _without_empty(unsigned, 0), _without_empty_optional(unsigned, _CARD_FIELDS, 0)):
        # A card with nothing but empty values has no SDK form: its payload is null.
        forms.setdefault(canonicalize(form), form if isinstance(form, dict) else {})
    return [(form, payload) for payload, form in forms.items()]


def signed_payloads(card: dict[str, Any]) -> list[bytes]:
    """The canonical bytes a card signature may cover (see :func:`signed_forms`)."""
    return [payload for _, payload in signed_forms(card)]


def _empty(value: Any) -> bool:
    return isinstance(value, (str, list, dict)) and not value


def _without_empty(value: Any, depth: int) -> Any:
    """``value`` without nulls or empty strings, arrays and objects at any depth; None if nothing is left."""
    if depth > MAX_DEPTH:
        raise CanonicalizationError("JSON nesting exceeds the canonicalization depth limit")
    if isinstance(value, dict):
        members = {key: _without_empty(item, depth + 1) for key, item in value.items()}
        return {key: item for key, item in members.items() if item is not None} or None
    if isinstance(value, list):
        items = [_without_empty(item, depth + 1) for item in value]
        return [item for item in items if item is not None] or None
    return None if value == "" else value


def _without_empty_optional(value: Any, fields: _Fields, depth: int) -> Any:
    """``value`` without empty object members, except the members ``fields`` keeps."""
    if depth > MAX_DEPTH:
        raise CanonicalizationError("JSON nesting exceeds the canonicalization depth limit")
    keep, children = fields
    if isinstance(value, list):
        return [_without_empty_optional(item, fields, depth + 1) for item in value]
    if not isinstance(value, dict):
        return value
    members = {
        key: _without_empty_optional(item, children.get(key, _NO_FIELDS), depth + 1)
        for key, item in value.items()
    }
    return {key: item for key, item in members.items() if key in keep or not _empty(item)}


def verify_card(
    card: dict[str, Any], forms: list[tuple[dict[str, Any], bytes]], keys: dict[str, Any]
) -> tuple[str, str | None, dict[str, Any] | None]:
    """``("verified", None, form)`` when one signature verifies one form with an operator-trusted key.

    ``form`` is the card as that signature covers it, without ``signatures``: what a
    verified card is read as. Otherwise ``("invalid", reason, None)``. ``card`` must already
    have a well-formed ``signatures`` array (``a2a_signature_state`` returned
    ``present-unverified``); ``forms`` come from :func:`signed_forms`.
    """
    reasons: list[str] = []
    for entry in card["signatures"]:
        for form, payload in forms:
            try:
                verify_detached_jws(entry["protected"], payload, entry["signature"], keys)
            except Exception as exc:  # noqa: BLE001 - every failure leaves this signature unverified
                reasons.append(_failure_reason(exc))
                if not isinstance(exc, InvalidSignatureError):
                    break  # header, key and algorithm failures do not depend on the payload
            else:
                return "verified", None, form
    return "invalid", "; ".join(dict.fromkeys(reasons)), None


def export_card(card: dict[str, Any]) -> dict[str, Any]:
    """``card`` for ``--dump-records``: userinfo withheld from scheme-less ``host:port`` addresses.

    The shared sanitizer withholds userinfo from URLs with a scheme but does
    not recognize a gRPC ``user:password@host:port`` address. A replayed card
    that lost one reports its signature ``present-unverified``.
    """
    return {key: _withhold_address_userinfo(value, 0) for key, value in card.items()}


def _withhold_address_userinfo(value: Any, depth: int) -> Any:
    if depth > MAX_DEPTH:
        return REDACTED
    if isinstance(value, dict):
        return {key: _withhold_address_userinfo(item, depth + 1) for key, item in value.items()}
    if isinstance(value, list):
        return [_withhold_address_userinfo(item, depth + 1) for item in value]
    if isinstance(value, str) and "@" in value and "://" not in value:
        userinfo, _, address = value.rpartition("@")
        if userinfo and _host_port(address):
            return f"{REDACTED}@{address}"
    return value


def _host_port(value: str) -> bool:
    """Whether ``value`` is exactly a ``host:port`` network address."""
    try:
        parts = urlsplit("//" + value)
        return bool(parts.hostname) and parts.port is not None and parts.netloc == value
    except ValueError:
        return False


def _failure_reason(exc: Exception) -> str:
    """A fixed description: library messages are not copied into findings."""
    if isinstance(exc, InvalidSignatureError):
        return "signature matches none of the card's canonical forms"
    if isinstance(exc, CanonicalizationError) or type(exc) is ValueError:
        # Raised by shadowscan's own checks with fixed messages.
        return str(exc)
    return f"signature not verifiable ({type(exc).__name__})"
