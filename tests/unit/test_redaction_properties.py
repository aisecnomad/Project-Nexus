"""Property-based tests for the redaction module using Hypothesis.

These tests verify invariants that must hold for *any* input, not just
hand-picked examples: idempotency, credential removal, and crash-freedom
on adversarial unicode.
"""

from __future__ import annotations

import re
import string

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from shadowscan.utils.redaction import REDACTED, sanitize, sanitize_text  # noqa: E402
from shadowscan.utils.redaction_rules import _MAX_SANITIZATION_CHARS  # noqa: E402

# Bound generated text to stay within sanitization limits.
_SAFE_MAX = min(_MAX_SANITIZATION_CHARS, 50_000)

# Characters that commonly appear in credentials and source code.
_CREDENTIAL_ALPHABET = string.ascii_letters + string.digits + "/-_=+.@#$%^&*(){}[]|\\:;\"'<>,?! \t\n"

# Well-known credential patterns that sanitize_text must always redact.
_SAMPLE_TOKENS = [
    "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz",
    "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12",
    "AKIA1234567890ABCDEF",
    "glpat-ABCDEFGHIJKLMNOPQRSTUVWXYZab1234",
]


@given(text=st.text(alphabet=_CREDENTIAL_ALPHABET, max_size=2000))
@settings(max_examples=200, deadline=5000)
def test_sanitize_text_never_crashes(text: str) -> None:
    """sanitize_text must not raise on arbitrary text within size limits."""
    result = sanitize_text(text)
    assert isinstance(result, str)


@given(text=st.text(alphabet=_CREDENTIAL_ALPHABET, max_size=2000))
@settings(max_examples=200, deadline=5000)
def test_sanitize_text_idempotent(text: str) -> None:
    """Applying sanitize_text twice must produce the same result as once."""
    once = sanitize_text(text)
    twice = sanitize_text(once)
    assert once == twice


@given(text=st.text(max_size=2000))
@settings(max_examples=100, deadline=5000)
def test_sanitize_text_unicode_safety(text: str) -> None:
    """sanitize_text must handle arbitrary unicode without crashing."""
    result = sanitize_text(text)
    assert isinstance(result, str)


# A token starts and ends at an ASCII word boundary: glued to a letter, digit
# or underscore it is part of an identifier ('task-proj-…') or of a longer
# value that is not this token ('AKIA…F0' is not a 20-character key id).
_NOT_A_WORD_END = re.compile(r"(?<![A-Za-z0-9_])\Z")
_NOT_A_WORD_START = re.compile(r"\A(?![A-Za-z0-9_])")


@given(
    token=st.sampled_from(_SAMPLE_TOKENS),
    prefix=st.text(max_size=50).filter(_NOT_A_WORD_END.search),
    suffix=st.text(max_size=50).filter(_NOT_A_WORD_START.search),
)
@settings(max_examples=100, deadline=5000)
def test_known_tokens_always_redacted(token: str, prefix: str, suffix: str) -> None:
    """Known credential patterns must be redacted whatever precedes or follows them."""
    text = prefix + token + suffix
    result = sanitize_text(text)
    assert token not in result


@given(
    data=st.recursive(
        st.text(alphabet=_CREDENTIAL_ALPHABET, max_size=200) | st.integers() | st.none() | st.booleans(),
        lambda children: (
            st.lists(children, max_size=5)
            | st.dictionaries(
                st.text(alphabet=string.ascii_lowercase, min_size=1, max_size=10),
                children,
                max_size=5,
            )
        ),
        max_leaves=20,
    )
)
@settings(max_examples=100, deadline=10000)
def test_sanitize_structured_data_never_crashes(data: object) -> None:
    """sanitize() on nested dicts/lists/scalars must not crash."""
    result = sanitize(data)
    assert result is not None or data is None


@given(safe=st.text(alphabet=string.ascii_lowercase + string.digits + " .,\n", max_size=500))
@settings(max_examples=200, deadline=5000)
def test_safe_text_passes_through(safe: str) -> None:
    """Text without credential patterns should pass through mostly unchanged."""
    result = sanitize_text(safe)
    assert REDACTED not in result or REDACTED in safe
