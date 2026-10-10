"""RFC 8785 canonicalization and detached JWS verification against an operator key set."""

from __future__ import annotations

import base64
import json
import math
import struct

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from jwt.algorithms import ECAlgorithm, OKPAlgorithm, RSAAlgorithm
from jwt.api_jws import PyJWS
from jwt.exceptions import InvalidSignatureError

from shadowscan.utils.jcs import CanonicalizationError, canonicalize, es_number
from shadowscan.utils.jwks import verify_detached_jws

# ------------------------------------------------------------------ RFC 8785

# RFC 8785 Appendix B: IEEE 754 bit patterns and their ECMAScript serialization.
RFC_8785_NUMBERS = [
    ("0000000000000000", "0"),
    ("8000000000000000", "0"),
    ("0000000000000001", "5e-324"),
    ("8000000000000001", "-5e-324"),
    ("7fefffffffffffff", "1.7976931348623157e+308"),
    ("ffefffffffffffff", "-1.7976931348623157e+308"),
    ("4340000000000000", "9007199254740992"),
    ("c340000000000000", "-9007199254740992"),
    ("4430000000000000", "295147905179352830000"),
    ("44b52d02c7e14af5", "9.999999999999997e+22"),
    ("44b52d02c7e14af6", "1e+23"),
    ("44b52d02c7e14af7", "1.0000000000000001e+23"),
    ("444b1ae4d6e2ef4e", "999999999999999700000"),
    ("444b1ae4d6e2ef4f", "999999999999999900000"),
    ("444b1ae4d6e2ef50", "1e+21"),
    ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
    ("3eb0c6f7a0b5ed8d", "0.000001"),
    ("41b3de4355555553", "333333333.3333332"),
    ("41b3de4355555554", "333333333.33333325"),
    ("41b3de4355555555", "333333333.3333333"),
    ("41b3de4355555556", "333333333.3333334"),
    ("41b3de4355555557", "333333333.33333343"),
    ("becbf647612f3696", "-0.0000033333333333333333"),
    ("43143ff3c1cb0959", "1424953923781206.2"),
]


@pytest.mark.parametrize(("bits", "expected"), RFC_8785_NUMBERS)
def test_numbers_serialize_as_ecmascript_does(bits: str, expected: str) -> None:
    (value,) = struct.unpack(">d", bytes.fromhex(bits))
    assert es_number(value) == expected


def test_objects_sort_by_utf16_code_units_and_strings_escape_minimally() -> None:
    # RFC 8785 section 3.2.3: U+1F600 (surrogates D83D DE00) sorts before U+FB33.
    data = {"\ufb33": 6, "\u20ac": 1, "\r": 2, "\U0001f600": 3, "\u00f6": 4, "1": 5, "b": [True, None, 2.0]}
    text = canonicalize(data).decode("utf-8")
    assert text == '{"\\r":2,"1":5,"b":[true,null,2],"ö":4,"€":1,"\U0001f600":3,"\ufb33":6}'
    assert canonicalize({"s": '\u000f\n"\\/\u007f\u2028'}) == b'{"s":"\\u000f\\n\\"\\\\/\x7f\xe2\x80\xa8"}'
    assert canonicalize({"a": {"c": 1, "b": []}}) == b'{"a":{"b":[],"c":1}}'


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ({"n": 2**53 + 1}, "outside the exactly representable range"),
        ({"n": -(2**60)}, "outside the exactly representable range"),
        ({"n": math.inf}, "not finite"),
        ({"n": math.nan}, "not finite"),
        ({1: "key"}, "keys must be strings"),
        ({"s": "\ud800"}, "unpaired surrogate"),
        ({"t": (1, 2)}, "not a JSON type"),
        ({"d": __import__("decimal").Decimal("1.5")}, "not a JSON type"),
    ],
)
def test_values_without_a_canonical_form_are_refused(value: object, reason: str) -> None:
    with pytest.raises(CanonicalizationError, match=reason):
        canonicalize(value)


def test_integers_within_the_exact_range_keep_their_digits() -> None:
    assert canonicalize([2**53, -(2**53), 0, -1]) == b"[9007199254740992,-9007199254740992,0,-1]"


def test_nesting_is_bounded() -> None:
    deep: list[object] = []
    for _ in range(250):
        deep = [deep]
    with pytest.raises(CanonicalizationError, match="depth"):
        canonicalize(deep)


# ------------------------------------------------------------ detached JWS

PAYLOAD = canonicalize({"name": "Synthetic Agent", "version": "1.0"})


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _sign(key: object, algorithm: str, kid: str = "k1", **header: object) -> tuple[str, str]:
    token = PyJWS().encode(PAYLOAD, key, algorithm=algorithm, headers={"kid": kid, **header})
    protected, _, signature = token.split(".")
    return protected, signature


def _jwks(public_jwk: str, kid: str = "k1", **extra: object) -> dict[str, object]:
    return {"keys": [{**json.loads(public_jwk), "kid": kid, "use": "sig", **extra}]}


@pytest.fixture(scope="module")
def ec_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture(scope="module")
def ec_jwks(ec_key: ec.EllipticCurvePrivateKey) -> dict[str, object]:
    return _jwks(ECAlgorithm.to_jwk(ec_key.public_key()), alg="ES256")


def test_es256_rs256_and_eddsa_signatures_verify() -> None:
    ec_private = ec.generate_private_key(ec.SECP256R1())
    rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ed_private = ed25519.Ed25519PrivateKey.generate()
    for key, algorithm, public in [
        (ec_private, "ES256", ECAlgorithm.to_jwk(ec_private.public_key())),
        (rsa_private, "RS256", RSAAlgorithm.to_jwk(rsa_private.public_key())),
        (rsa_private, "PS256", RSAAlgorithm.to_jwk(rsa_private.public_key())),
        (ed_private, "EdDSA", OKPAlgorithm.to_jwk(ed_private.public_key())),
    ]:
        protected, signature = _sign(key, algorithm)
        verify_detached_jws(protected, PAYLOAD, signature, _jwks(public))


def test_a_changed_payload_does_not_verify(ec_key, ec_jwks) -> None:
    protected, signature = _sign(ec_key, "ES256")
    with pytest.raises(InvalidSignatureError):
        verify_detached_jws(protected, PAYLOAD + b" ", signature, ec_jwks)


def test_header_key_locations_are_ignored_and_never_trusted(ec_key, ec_jwks) -> None:
    attacker = ec.generate_private_key(ec.SECP256R1())
    embedded = json.loads(ECAlgorithm.to_jwk(attacker.public_key()))
    protected, signature = _sign(
        attacker, "ES256", jku="https://attacker.agents.example.net/jwks.json", jwk=embedded
    )
    with pytest.raises(InvalidSignatureError):
        verify_detached_jws(protected, PAYLOAD, signature, ec_jwks)
    # The trusted key still verifies a signature whose header names other key locations.
    protected, signature = _sign(ec_key, "ES256", jku="https://attacker.agents.example.net/jwks.json")
    verify_detached_jws(protected, PAYLOAD, signature, ec_jwks)


@pytest.mark.parametrize(
    ("header", "message"),
    [
        ({"alg": "ES256", "kid": "k1", "b64": False, "crit": ["b64"]}, "unencoded payloads"),
        ({"alg": "ES256", "kid": "k1", "crit": ["exp"]}, "critical header"),
        ({"alg": "HS256", "kid": "k1"}, "allowlist"),
        ({"alg": "none"}, "allowlist"),
        ({"alg": "ES256", "kid": ""}, "key ID"),
        ({"alg": "ES256", "kid": "other"}, "matching signature key"),
    ],
)
def test_unacceptable_headers_are_refused_before_verification(ec_jwks, header, message) -> None:
    protected = _b64(json.dumps(header).encode())
    with pytest.raises(ValueError, match=message):
        verify_detached_jws(protected, PAYLOAD, _b64(b"x" * 64), ec_jwks)


@pytest.mark.parametrize(
    ("protected", "signature", "message"),
    [
        ("not base64url!", "c2ln", "not base64url"),
        (None, "c2ln", "not base64url"),
        (_b64(b"[1, 2]"), "c2ln", "not a JSON object"),
        (_b64(b'{"alg": "ES256", "alg": "RS256"}'), "c2ln", "not a JSON object"),
        (_b64(b"\xff\xfe"), "c2ln", "not a JSON object"),
        (_b64(b'{"alg": "ES256", "kid": "k1"}'), "sig+nature", "signature is not base64url"),
    ],
)
def test_malformed_signature_parts_are_refused(ec_jwks, protected, signature, message) -> None:
    with pytest.raises(ValueError, match=message):
        verify_detached_jws(protected, PAYLOAD, signature, ec_jwks)


def test_operator_algorithm_allowlist_applies(ec_key, ec_jwks) -> None:
    protected, signature = _sign(ec_key, "ES256")
    with pytest.raises(ValueError, match="allowlist"):
        verify_detached_jws(protected, PAYLOAD, signature, ec_jwks, allowed_algorithms=["RS256"])


def test_key_set_shape_is_checked(ec_key) -> None:
    protected, signature = _sign(ec_key, "ES256")
    with pytest.raises(ValueError, match="not a key set"):
        verify_detached_jws(protected, PAYLOAD, signature, {"keys": "none"})
