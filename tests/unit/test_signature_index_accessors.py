"""Public accessors of the signature index."""

from __future__ import annotations

from shadowscan.connectors.code.source_semantics import _collect_import_hints
from shadowscan.signatures.loader import Signal, Signature
from shadowscan.signatures.matcher import SignatureIndex


def _import_signature(sig_id: str, pattern: str, languages: list[str] | None = None) -> Signature:
    signal = Signal(type="import", weight=0.9, languages=languages or ["python"], patterns=[pattern])
    signal.compile()
    return Signature(id=sig_id, name=sig_id, category="framework", signals=[signal])


def test_signals_of_type_keeps_every_signature_that_shares_an_id() -> None:
    first = _import_signature("framework.shared", r"\bfrom\s+alpha_sdk\b")
    second = _import_signature("framework.shared", r"\bfrom\s+beta_sdk\b")
    env = Signature(
        id="provider.env", name="Env", category="provider", signals=[Signal(type="env", names=["ALPHA_KEY"])]
    )
    index = SignatureIndex([first, second, env])

    # The id-keyed view keeps one of the two signatures; the accessor keeps both.
    assert list(index.signatures) == ["framework.shared", "provider.env"]
    pairs = index.signals_of_type("import")
    assert [(sig, signal) for sig, signal in pairs] == [
        (first, first.signals[0]),
        (second, second.signals[0]),
    ]
    assert index.signals_of_type("env") == [(env, env.signals[0])]
    assert index.signals_of_type("no-such-type") == []


def test_signals_of_type_returns_a_copy() -> None:
    signature = _import_signature("framework.alpha", r"\bimport\s+alpha_sdk\b")
    index = SignatureIndex([signature])

    returned = index.signals_of_type("import")
    returned.clear()
    index.signals_of_type("no-such-type").append((signature, signature.signals[0]))

    assert index.signals_of_type("import") == [(signature, signature.signals[0])]
    assert index.signals_of_type("no-such-type") == []
    assert [m.signature_id for m in index.match_imports("import alpha_sdk", "python")] == ["framework.alpha"]


def test_signals_of_type_follows_pack_order_of_the_loaded_index(index: SignatureIndex) -> None:
    expected = [
        (sig, signal)
        for sig in index.signatures.values()
        for signal in sig.signals
        if signal.type == "import"
    ]
    assert index.signals_of_type("import") == expected
    assert expected


def test_python_import_hints_cover_both_signatures_sharing_an_id() -> None:
    first = _import_signature("framework.shared", r"\bfrom\s+alpha_sdk\b")
    second = _import_signature("framework.shared", r"\bfrom\s+beta_sdk\b")
    other_language = _import_signature("framework.js", r"gamma-sdk", languages=["javascript"])

    hints = _collect_import_hints(SignatureIndex([first, second, other_language]))

    assert hints == ((("alpha_sdk",),), (("beta_sdk",),))
