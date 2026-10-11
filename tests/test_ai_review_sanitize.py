"""Regression tests for tools.ai_review.sanitize.

The sanitizer is the last line of defense before untrusted pull-request
text reaches a posted review or a workflow log: credential-shaped strings
must never survive it, and no line it emits may be a workflow command.
The families mirror tools/check_secrets.py closely enough for posted text;
check_secrets.py remains the authoritative file gate with exact approvals.
"""

from __future__ import annotations

from tools.ai_review.sanitize import redact
from tools.check_secrets import findings


def test_every_check_secrets_family_is_redacted() -> None:
    samples = {
        "OpenAI API key": "call with sk-" + "aA1" * 7 + "aA",
        "OpenAI project key": "key sk-proj-" + "Ab1-" * 9,
        "Anthropic API key": "sk-ant-api03-" + "Zz9_" * 6,
        "AWS access key ID": "AKIA" + "1A2B" * 4,
        "GitHub token": "ghp_" + "a1" * 20,
        "GitHub fine-grained token": "github_pat_" + "a" * 22 + "_" + "b" * 59,
        "GitLab token": "glpat-" + "x1-" * 8,
        "Slack token": "xoxb-" + "1234-" + "abcDEF0123-xyz",
        "Google API key": "AIza" + "qQ1-" * 8 + "_x1",
        "Hugging Face token": "hf_" + "zZ9" * 12,
        "Stripe live key": "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc",
        "JSON Web Token": "eyJ" + "h" * 12 + ".eyJ" + "p" * 12 + "." + "s" * 12,
        "private key": "-----BEGIN " + "PRIVATE KEY-----",
        "Azure account or shared access key": "AccountKey=" + "QWxhZGRpbjEyMzQ1" * 3 + "==",
        "password in a URL": "https://" + "user:" + "synthetic-password@" + "example.internal/path",
    }
    for family, sample in samples.items():
        detected = {fam for _, fam, _ in findings(sample)}
        assert family in detected, f"test sample for {family!r} is not shaped like one"
        out = redact(f"prefix {sample} suffix")
        assert sample not in out, f"{family} survived redact()"
        assert "[redacted]" in out
        assert out.startswith("prefix ") and out.endswith(" suffix")


def test_workflow_commands_are_neutralized() -> None:
    out = redact("normal line\n::set-output name=x::1\n::warning::hi")
    assert "\n::" not in out
    assert not out.startswith("::")
    assert "set-output" in out  # content stays readable, command is inert


def test_plain_text_passes_through() -> None:
    text = "requests.post(url, timeout=30)  # no retry on 429"
    assert redact(text) == text


def test_redaction_is_idempotent() -> None:
    text = "token ghp_" + "a1" * 20 + " here"
    assert redact(redact(text)) == redact(text)
