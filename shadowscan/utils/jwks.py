"""JWKS fetch and JWT signature checks.

Verification is analysis-only: expiry, audience and issuer claims are not
authorization decisions. ``header.alg`` is never used as the algorithm list.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

ALLOWED_JWT_ALGS = ("RS256", "ES256", "EdDSA", "PS256")
_ALLOWED_JWK_KTY = frozenset({"RSA", "EC", "OKP"})
_MAX_JWKS_KEYS = 64


def verify_against_jwks(token: str, jwks_url: str, header: dict[str, Any], issuer: str | None = None) -> bool:
    """Verify ``token`` against JWKS fetched through origin-pinned HttpClient.

    Returns True on success. Raises ValueError/HttpError on refusal so callers
    can record ``metadata.verified = False`` without treating the exception as
    a crash.
    """
    import jwt as pyjwt
    from jwt import PyJWK

    from shadowscan.utils.http import HttpClient, validate_url

    alg = header.get("alg")
    if alg not in ALLOWED_JWT_ALGS:
        raise ValueError(f"JWT alg {alg!r} is not in the asymmetric allowlist")
    url = validate_url(jwks_url)
    if issuer:
        iss_host = urlsplit(str(issuer)).hostname
        jwks_host = urlsplit(url).hostname
        if iss_host and jwks_host and iss_host.rstrip(".").lower() != jwks_host.rstrip(".").lower():
            raise ValueError("JWKS host does not match token issuer host")
    document = HttpClient().get_json(url)
    if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
        raise ValueError("JWKS document is not a key set")
    keys = document["keys"]
    if len(keys) > _MAX_JWKS_KEYS:
        raise ValueError("JWKS document has too many keys")
    kid = header.get("kid")
    selected: dict[str, Any] | None = None
    for item in keys:
        if not isinstance(item, dict):
            continue
        if item.get("kty") not in _ALLOWED_JWK_KTY:
            continue
        if item.get("use") not in {None, "sig"}:
            continue
        if item.get("k") is not None:  # symmetric octet key — never accept
            continue
        if kid is not None and item.get("kid") != kid:
            continue
        selected = item
        if kid is not None:
            break
    if selected is None:
        raise ValueError("JWKS does not contain a matching signature key")
    key = PyJWK.from_dict(selected).key
    pyjwt.decode(
        token,
        key,
        algorithms=list(ALLOWED_JWT_ALGS),
        options={
            "verify_signature": True,
            "verify_exp": False,
            "verify_aud": False,
            "verify_iss": False,
        },
    )
    return True
