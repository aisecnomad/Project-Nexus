"""shadowscan.utils.text: compatibility aliases."""

from __future__ import annotations

from shadowscan.utils import text
from shadowscan.utils.redaction import credential_id, sanitize
from shadowscan.utils.text import redact


def test_redact_shim_remains_a_compatibility_alias():
    token = "sk-proj-exampletokenvalue"
    assert redact(token, keep=8) == credential_id(token)


def test_sanitize_record_alias_is_replaced_by_sanitize():
    token = "sk-proj-exampletokenvalue"
    assert not hasattr(text, "sanitize_record")
    assert sanitize({"token": token})["token"] != token
