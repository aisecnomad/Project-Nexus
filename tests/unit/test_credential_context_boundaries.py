"""Synthetic controls for contextual redaction added after the discovery review."""

from __future__ import annotations

import pytest

from shadowscan.utils.redaction import REDACTED, sanitize_text

SECRET = "Gh4Hj9Kl8Zx2Qw"


@pytest.mark.parametrize(
    "source",
    [
        '{"value": "' + SECRET + '",\n "name": "Password"}',
        '{"value": "p}\\"' + SECRET + '", "name": "Password"}',
        '{"name": "Password", "value": "p}' + SECRET,
        '{"name": "Password", "value": "p}\n' + SECRET,
        "{name: Password, value: 'p}" + SECRET,
        '- value: "' + SECRET + '"\n  name: DB_PASSWORD\n- name: MODEL\n  value: gpt-4o\n',
        '- value: "p}\\"' + SECRET + '"\n  name: DB_PASSWORD\n',
        '{outer: {value: "' + SECRET + '", name: OpenAIKey}, model: "gpt-4o"}',
        "?sv=1&%73ig=" + SECRET + "&se=2030",
        "account.blob.core.windows.net/container?sig=" + SECRET + "&se=2030",
        'llm --model model-name -k "' + SECRET + '" prompt',
        "llm -k=" + SECRET + " prompt",
        'tool --key=users--password "' + SECRET + '" --model model-name',
        "tool --key=" + SECRET + '--password "another-synthetic-password"',
        "KEY1=" + SECRET,
        "openaiKey: " + SECRET,
    ],
)
def test_known_credential_contexts_are_withheld_without_losing_line_counts(source):
    safe = sanitize_text(source)
    assert SECRET not in safe
    assert REDACTED in safe
    assert source.count("\n") == safe.count("\n")
    assert sanitize_text(safe) == safe


@pytest.mark.parametrize(
    "source",
    [
        '{"value": "ordinary", "name": "CacheKey"}',
        '{"value": "$OPENAI_KEY", "name": "Password"}',
        '{"value": "ordinary", "name": "MODEL"}',
        '{"value": "' + SECRET + '"}, {"name": "Password"}',
        '{"value": "' + SECRET + '", "nested": {"name": "Password"}}',
        "- value: " + SECRET + "\n- name: DB_PASSWORD\n",
        "- value: " + SECRET + "\n  name: MODEL\n",
        "curl -k " + SECRET,
        "tool -k " + SECRET,
        "tool --key users --cache-key users-by-id",
        "?key=users&code=42&search=hello",
        "KEY1=Ed25519PrivateKey\nopenaiKey: NextPage2\n",
        "KEY1=ApiVersion2Feature3Enabled4\n",
    ],
)
def test_noncredential_contexts_references_and_ordinary_keys_are_preserved(source):
    assert sanitize_text(source) == source
