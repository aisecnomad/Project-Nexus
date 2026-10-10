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
key set. The payload is the RFC 8785 canonical card without ``signatures``,
exactly as served: protobuf default values are not removed first, so a card
served with defaults its signer omitted reports ``invalid``.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit, urlunsplit

from jwt.exceptions import InvalidSignatureError

from shadowscan.connectors.base import ConnectorError, _positive_limit
from shadowscan.utils.http import HttpClient, HttpError
from shadowscan.utils.jcs import CanonicalizationError, canonicalize
from shadowscan.utils.jwks import verify_detached_jws

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


def signed_payload(card: dict[str, Any]) -> bytes:
    """The canonical bytes a card signature covers; raises CanonicalizationError."""
    return canonicalize({key: value for key, value in card.items() if key != "signatures"})


def verify_card(card: dict[str, Any], payload: bytes, keys: dict[str, Any]) -> tuple[str, str | None]:
    """``("verified", None)`` when one signature verifies with an operator-trusted key, else ``invalid``.

    ``card`` must already have a well-formed ``signatures`` array
    (``a2a_signature_state`` returned ``present-unverified``).
    """
    reasons: list[str] = []
    for entry in card["signatures"]:
        try:
            verify_detached_jws(entry["protected"], payload, entry["signature"], keys)
        except Exception as exc:  # noqa: BLE001 - every failure leaves this signature unverified
            reasons.append(_failure_reason(exc))
        else:
            return "verified", None
    return "invalid", "; ".join(dict.fromkeys(reasons))


def _failure_reason(exc: Exception) -> str:
    """A fixed description: library messages are not copied into findings."""
    if isinstance(exc, InvalidSignatureError):
        return "signature does not match the canonical card"
    if isinstance(exc, CanonicalizationError) or type(exc) is ValueError:
        # Raised by shadowscan's own checks with fixed messages.
        return str(exc)
    return f"signature not verifiable ({type(exc).__name__})"
