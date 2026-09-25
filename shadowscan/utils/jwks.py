"""Bounded, origin-pinned JWKS fetching and analysis-only JWT verification.

Algorithms and the optional expected issuer come from operator configuration.
A token's own issuer is never used as a trust anchor. Expiry, audience, and
other authorization claims remain unvalidated: this is a scanner, not a token
acceptance service.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

ALLOWED_JWT_ALGS = ("RS256", "ES256", "EdDSA", "PS256")
_ALGORITHM_KEY_TYPES = {"RS256": "RSA", "PS256": "RSA", "ES256": "EC", "EdDSA": "OKP"}
_PRIVATE_JWK_MEMBERS = frozenset({"k", "d", "p", "q", "dp", "dq", "qi", "oth"})
_MAX_JWKS_KEYS = 64
MAX_JWKS_BYTES = 1024 * 1024


def verification_algorithms(configured: Sequence[str] | None = None) -> tuple[str, ...]:
    """Operators can narrow the fixed asymmetric allowlist, never expand it."""
    if configured is None:
        return ALLOWED_JWT_ALGS
    if isinstance(configured, (str, bytes)) or not isinstance(configured, (list, tuple)):
        raise ValueError("JWT allowed_algorithms must be a nonempty list")
    if not configured or any(not isinstance(alg, str) or alg not in ALLOWED_JWT_ALGS for alg in configured):
        raise ValueError("JWT algorithms must be a nonempty subset of the asymmetric allowlist")
    return tuple(dict.fromkeys(configured))


def _signature_candidate(item: Any, *, alg: str, kid: str | None) -> bool:
    if not isinstance(item, dict) or item.get("kty") != _ALGORITHM_KEY_TYPES[alg]:
        return False
    if _PRIVATE_JWK_MEMBERS.intersection(item):
        return False
    if item.get("use") not in (None, "sig"):
        return False
    if "alg" in item and item["alg"] != alg:
        return False
    if kid is not None and item.get("kid") != kid:
        return False
    if "key_ops" in item:
        operations = item["key_ops"]
        if not isinstance(operations, list) or operations != ["verify"]:
            return False
    if alg in {"RS256", "PS256"}:
        # Bound attacker-controlled big integers before the cryptography backend
        # constructs or verifies with them (8192-bit modulus, 48-bit exponent).
        if any(not isinstance(item.get(name), str) or not 0 < len(item[name]) <= limit for name, limit in (("n", 1366), ("e", 8))):
            return False
    if alg == "ES256" and item.get("crv") != "P-256":
        return False
    if alg == "EdDSA" and item.get("crv") not in ("Ed25519", "Ed448"):
        return False
    return True


def fetch_jwks(jwks_url: str) -> dict[str, Any]:
    """Fetch and shape-check a JWKS document over the shared, bounded transport."""
    from shadowscan.utils.http import HttpClient, validate_url

    url = validate_url(jwks_url)
    client = HttpClient()
    try:
        document = client.get_json(url, max_bytes=MAX_JWKS_BYTES)
    finally:
        client.session.close()
    if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
        raise ValueError("JWKS document is not a key set")
    if len(document["keys"]) > _MAX_JWKS_KEYS:
        raise ValueError("JWKS document has too many keys")
    return document


def verify_against_jwks(
    token: str,
    jwks_url: str,
    header: dict[str, Any],
    *,
    expected_issuer: str | None = None,
    allowed_algorithms: Sequence[str] | None = None,
    document_loader: Callable[[str], dict[str, Any]] | None = None,
) -> bool:
    """Verify a signature with exactly one eligible public key.

    ``expected_issuer`` is an explicit operator-supplied claim value. It need
    not share a host with the configured JWKS endpoint (CDN and central IdP key
    endpoints are valid). Without it, success establishes a signature only.
    ``document_loader`` may provide a per-analysis cache. It is invoked only
    after header validation, so rejected algorithms never trigger network IO.
    """
    import jwt as pyjwt
    from jwt import PyJWK

    allowed = verification_algorithms(allowed_algorithms)
    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in allowed:
        raise ValueError("JWT algorithm is not in the configured asymmetric allowlist")
    if header.get("crit"):
        raise ValueError("JWT critical header extensions are unsupported")
    kid = header.get("kid")
    if kid is not None and (not isinstance(kid, str) or not kid):
        raise ValueError("JWT key ID must be a nonempty string")
    if expected_issuer is not None and (not isinstance(expected_issuer, str) or not expected_issuer):
        raise ValueError("JWT expected_issuer must be a nonempty string")
    document = (document_loader or fetch_jwks)(jwks_url)
    if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
        raise ValueError("JWKS document is not a key set")
    keys = document["keys"]
    if len(keys) > _MAX_JWKS_KEYS:
        raise ValueError("JWKS document has too many keys")
    candidates = [item for item in keys if _signature_candidate(item, alg=alg, kid=kid)]
    if not candidates:
        raise ValueError("JWKS does not contain a matching signature key")
    if len(candidates) != 1:
        raise ValueError("JWKS signing key selection is ambiguous")
    key = PyJWK.from_dict(candidates[0], algorithm=alg).key
    if alg in {"RS256", "PS256"} and not 2048 <= key.key_size <= 8192:
        raise ValueError("RSA signing keys must be between 2048 and 8192 bits")
    pyjwt.decode(
        token,
        key,
        algorithms=[alg],  # alg has already passed the operator's fixed allowlist.
        issuer=expected_issuer,
        options={
            "verify_signature": True,
            "verify_exp": False,
            "verify_nbf": False,
            "verify_iat": False,
            "verify_aud": False,
            "verify_iss": expected_issuer is not None,
            "verify_sub": False,
            "verify_jti": False,
        },
    )
    return True
