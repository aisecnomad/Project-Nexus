"""Credential call syntax uses bounded parsing and retains ordinary expressions."""

from __future__ import annotations

import time

import pytest

from shadowscan.utils import redaction
from shadowscan.utils.redaction import REDACTED, SanitizationLimitError, sanitize_text

SYNTHETIC = "a8f3c91d7e2b4f6a9d0c2b3e4f5a6c7d"


@pytest.mark.parametrize(
    "template",
    [
        'AzureKeyCredential ("{value}")',
        'AzureKeyCredential\t ("{value}")',
        'AzureKeyCredential\n  ("{value}")',
        'AzureKeyCredential/*synthetic comment*/("{value}")',
        'AzureKeyCredential /*synthetic comment*/ ("{value}")',
        'AzureKeyCredential // synthetic comment\n  ("{value}")',
        'AzureKeyCredential # synthetic comment\n  ("{value}")',
        'AzureKeyCredential(("{value}"))',
        'AzureKeyCredential( ( /*synthetic comment*/ ("{value}") ) )',
        'new AzureKeyCredential($"{value}")',
        'new AzureKeyCredential($@"{value}")',
        'new AzureKeyCredential(@$"{value}")',
        'new AzureKeyCredential($@"first\n{value}")',
        'new AzureKeyCredential(@$"first\n{value}")',
        'new AzureKeyCredential(@"first\n{value}")',
        'new AzureKeyCredential(@"first""quoted\n{value}")',
        'new AzureKeyCredential($@"first""quoted\n{value}")',
        'new AzureKeyCredential($"{{{{literal}}}}{value}")',
        "AzureKeyCredential('''\n{value}\n''')",
        'AzureKeyCredential("""\n{value}\n""")',
        'AzureKeyCredential(r"""\n{value}\n""")',
        'AzureKeyCredential("""\n{value}\nsynthetic second line\n""")',
        'AzureKeyCredential credential = new ("{value}");',
        'builder().apiKey /*synthetic comment*/ ("{value}")',
        'builder()\n  .apiKey /*synthetic comment*/ ("{value}")',
        'AzureKeyCredential(key=("{value}"))',
    ],
)
def test_recognizable_credential_call_syntax_withholds_literal(template):
    source = template.format(value=SYNTHETIC) + '\nnext_call("ordinary")'
    safe = sanitize_text(source)
    assert SYNTHETIC not in safe
    assert REDACTED in safe
    assert safe.endswith('\nnext_call("ordinary")')
    assert source.count("\n") == safe.count("\n")
    assert sanitize_text(safe) == safe


@pytest.mark.parametrize(
    "expression",
    [
        'Environment.GetEnvironmentVariable("K") ?? "{value}"',
        'Environment.GetEnvironmentVariable("K") ?? ("{value}")',
        '(Environment.GetEnvironmentVariable("K") ?? ("{value}"))',
        'Environment.GetEnvironmentVariable("K") /*synthetic comment*/ ?? "{value}"',
        'os.getenv("K") or "{value}"',
        'os.environ.get("K") or "{value}"',
        'System.getenv("K") ?: "{value}"',
        'os.Getenv("K") || "{value}"',
    ],
)
@pytest.mark.parametrize("value", [SYNTHETIC, "hunter2hunter"])
def test_constructor_context_withholds_environment_literal_fallback(expression, value):
    source = "new AzureKeyCredential(" + expression.format(value=value) + ")"
    safe = sanitize_text(source)
    assert value not in safe
    assert '"K"' in safe
    assert REDACTED in safe
    assert safe.count("\n") == source.count("\n")
    assert sanitize_text(safe) == safe


@pytest.mark.parametrize(
    "source",
    [
        f'ordinaryCall /*synthetic comment*/ (("{SYNTHETIC}"))',
        f'ordinaryCall (Environment.GetEnvironmentVariable("K") ?? "{SYNTHETIC}")',
        'new AzureKeyCredential($"{prefix}{suffix}")',
        'new AzureKeyCredential($@"first\n{prefix}{suffix}")',
        'new AzureKeyCredential(@$"first\n{prefix}{suffix}")',
        'AzureKeyCredential(f"{prefix}{suffix}")',
        'AzureKeyCredential(("${AZURE_OPENAI_KEY}"))',
        'AzureKeyCredential /*synthetic comment*/ ("YOUR_API_KEY")',
        'AzureKeyCredential("""\n<your-api-key>\n""")',
        'AzureKeyCredential("""\n<your api key>\n""")',
        'new AzureKeyCredential(@"\n<your api key>\n")',
        'new AzureKeyCredential($@"\n<your api key>\n")',
        'AzureKeyCredential(Environment.GetEnvironmentVariable("K") ?? "YOUR_API_KEY")',
        'AzureKeyCredential(Environment.GetEnvironmentVariable("K"))',
        "94 | Cosmetic | Spelling error on Login ('log|n')",
        'get_password ("admin")',
        'requireAuth /*synthetic comment*/ ("admin")',
        'HTTPBasicAuth (("user"), ("${PASSWORD}"))',
        f'AzureKeyCredential(str("{SYNTHETIC}"))',
    ],
)
def test_noncredential_calls_names_references_and_computed_arguments_are_preserved(source):
    assert sanitize_text(source) == source


def test_authentication_pair_keeps_user_and_withholds_wrapped_password():
    source = 'HTTPBasicAuth (("user"), ("hunter2hunter"))'
    safe = sanitize_text(source)
    assert '"user"' in safe
    assert "hunter2hunter" not in safe
    assert sanitize_text(safe) == safe


@pytest.mark.parametrize("prefix", ["@", "$@", "@$"])
def test_unterminated_verbatim_credential_literal_is_withheld_to_eof(prefix):
    source = f'new AzureKeyCredential({prefix}"first\n{SYNTHETIC}'
    safe = sanitize_text(source)
    assert SYNTHETIC not in safe
    assert REDACTED in safe
    assert source.count("\n") == safe.count("\n")
    assert sanitize_text(safe) == safe


def test_excessively_nested_constructor_fails_closed():
    source = "AzureKeyCredential(" + "(" * 40 + f'"{SYNTHETIC}"' + ")" * 41
    with pytest.raises(SanitizationLimitError, match="credential call nesting limit"):
        sanitize_text(source)


def test_call_trivia_obeys_shared_work_budget(monkeypatch):
    monkeypatch.setattr(redaction, "_MAX_REDACTION_WORK", 8)
    with pytest.raises(SanitizationLimitError, match="credential call work limit"):
        redaction._redact_credential_calls("AzureKeyCredential" + " " * 16 + f'# note\n("{SYNTHETIC}")')


def test_dense_comment_callee_candidates_scale_linearly():
    # Each name used to seek the same comment end. Indexed line/block ends
    # make four times the candidates cost approximately four times the work.
    def best_time(repeats):
        source = "ordinary#" * repeats + '\n("ordinary")'
        best = float("inf")
        for _ in range(3):
            started = time.perf_counter()
            redaction._redact_credential_calls(source)
            best = min(best, time.perf_counter() - started)
        return best

    small = best_time(1000)
    assert best_time(4000) < max(small, 0.02) * 10
