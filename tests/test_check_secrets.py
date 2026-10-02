"""The no-hardcoded-secrets hook (`tools/check_secrets.py`).

Every credential below is synthetic: a vendor prefix split across string
literals plus seeded random characters, assembled at run time so that this
file holds no credential-shaped literal for the hook, push protection or the
private-key pre-commit check to find.
"""

from __future__ import annotations

import random
import string
import time
from pathlib import Path

import pytest

from tools.check_secrets import display, findings, main

_ALNUM = string.ascii_letters + string.digits
_UPPER = string.ascii_uppercase + string.digits
_BASE64 = _ALNUM + "+/"
_URLSAFE = _ALNUM + "_-"


def _random(seed: str, length: int, alphabet: str = _ALNUM) -> str:
    rng = random.Random(seed)
    return "".join(rng.choice(alphabet) for _ in range(length))


# (id, family, text before the random part, random part, text after it)
_PLANTED = [
    ("openai-legacy", "OpenAI API key", "OPENAI_API_KEY=" + "sk" + "-", _random("o1", 48), ""),
    ("openai-project", "OpenAI project key", "sk-" + "proj" + "-", _random("o2", 40, _URLSAFE), ""),
    ("anthropic", "Anthropic API key", "sk-" + "ant-" + "api03-", _random("a1", 40, _URLSAFE), ""),
    ("aws-akia", "AWS access key ID", "AK" + "IA", _random("k1", 16, _UPPER), ""),
    ("aws-asia", "AWS access key ID", "AS" + "IA", _random("k2", 16, _UPPER), ""),
    ("aws-secret", "AWS secret access key", "aws_secret_" + "access_key = ", _random("k3", 40, _BASE64), ""),
    ("github-classic", "GitHub token", "gh" + "p_", _random("g1", 36), ""),
    ("github-oauth", "GitHub token", "gh" + "o_", _random("g2", 36), ""),
    ("github-user", "GitHub token", "gh" + "u_", _random("g3", 36), ""),
    ("github-app", "GitHub token", "gh" + "s_", _random("g4", 36), ""),
    ("github-refresh", "GitHub token", "gh" + "r_", _random("g5", 36), ""),
    (
        "github-fine-grained",
        "GitHub fine-grained token",
        "github" + "_pat_",
        _random("g6", 22) + "_" + _random("g7", 59),
        "",
    ),
    ("gitlab", "GitLab token", "gl" + "pat-", _random("l1", 20, _URLSAFE), ""),
    ("slack-bot", "Slack token", "xo" + "xb-" + "123456789012-1234567890123-", _random("s1", 24), ""),
    ("slack-user", "Slack token", "xo" + "xp-" + "123456789012-123456789012-", _random("s2", 32), ""),
    ("slack-app", "Slack token", "xo" + "xa-" + "2-", _random("s3", 30), ""),
    ("slack-refresh", "Slack token", "xo" + "xr-" + "1-", _random("s4", 30), ""),
    ("google", "Google API key", "AI" + "za", _random("y1", 35, _URLSAFE), ""),
    ("huggingface", "Hugging Face token", "hf" + "_", _random("h1", 34), ""),
    ("stripe-secret", "Stripe live key", "sk" + "_live_", _random("p1", 24), ""),
    ("stripe-restricted", "Stripe live key", "rk" + "_live_", _random("p2", 24), ""),
    (
        "jwt",
        "JSON Web Token",
        "ey" + "J" + _random("j1", 20, _URLSAFE) + ".ey" + "J",
        _random("j2", 30, _URLSAFE) + "." + _random("j3", 43, _URLSAFE),
        "",
    ),
    ("pem-rsa", "private key", "-----BEGIN " + "RSA PRIVATE" + " KEY-----\n", _random("m1", 64, _BASE64), ""),
    ("pem-openssh", "private key", "-----BEGIN " + "OPENSSH PRIVATE" + " KEY-----\n", _random("m2", 64), ""),
    ("pem-pkcs8", "private key", "-----BEGIN " + "PRIVATE" + " KEY-----\n", _random("m3", 64, _BASE64), ""),
    (
        "azure-storage",
        "Azure account or shared access key",
        "DefaultEndpointsProtocol=https;AccountName=demo;Account" + "Key=",
        _random("z1", 86, _BASE64) + "==",
        ";EndpointSuffix=core.windows.net",
    ),
    (
        "azure-shared-access",
        "Azure account or shared access key",
        "Endpoint=sb://demo.servicebus.windows.net/;SharedAccessKeyName=Root;SharedAccess" + "Key=",
        _random("z2", 43, _BASE64) + "=",
        "",
    ),
    (
        "url-password",
        "password in a URL",
        "postgres" + "://scanner:",
        _random("u1", 20),
        "@db.internal:5432/app",
    ),
]


@pytest.mark.parametrize(
    "family,before,sample,after",
    [pytest.param(*case[1:], id=case[0]) for case in _PLANTED],
)
def test_planted_credential_is_reported_without_its_value(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    family: str,
    before: str,
    sample: str,
    after: str,
) -> None:
    text = f"# config\nvalue = {before}{sample}{after}\n"
    assert [(line, kind) for line, kind, _ in findings(text)] == [(2, family)]
    monkeypatch.chdir(tmp_path)
    Path("sample.txt").write_text(text, encoding="utf-8")
    assert main(["sample.txt"]) == 1
    output = capsys.readouterr().out
    ((_, _, match),) = findings(text)
    assert output == (
        f"sample.txt:2: possible hardcoded {family}: {match[:4]}... ({len(match)} characters)\n"
    )
    # At most four characters of a match are printed, never a run of the planted value.
    assert not [
        sample[index : index + 5] for index in range(len(sample) - 4) if sample[index : index + 5] in output
    ]


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("OPENAI_API_KEY=" + "sk-" + "x" * 40, id="placeholder-run"),
        pytest.param("ANTHROPIC_API_KEY=" + "sk-" + "ant-api03-REPLACE_ME_WITH_REAL_KEY", id="replace-me"),
        pytest.param("aws_access_key_id = " + "AK" + "IAIOSFODNN7EXAMPLE", id="aws-documentation-example"),
        pytest.param("aws_secret_access_key = <your-secret-access-key>", id="angle-placeholder"),
        pytest.param("SLACK_BOT_TOKEN=" + "xo" + "xb-your-bot-token", id="slack-placeholder"),
        pytest.param("DATABASE_URL=postgres://app:${DB_PASSWORD}@db:5432/app", id="url-env-reference"),
        pytest.param("DATABASE_URL=postgres://app:REPLACE_ME@localhost:5432/app", id="url-replace-me"),
        pytest.param("DATABASE_URL=postgres://postgres:postgres@localhost/app", id="url-user-as-password"),
        pytest.param("DATABASE_URL=postgres://returns:password@localhost/app", id="url-password-word"),
        pytest.param("risk-" + "assessmentframeworkversion2026", id="sk-inside-a-word"),
        pytest.param("task-" + _random("w1", 30), id="sk-inside-task"),
        pytest.param("lookup_" + "gh" + "p_" + _random("w2", 36), id="github-prefix-inside-identifier"),
        pytest.param("hf_hub_download(repo_id='org/model')", id="hf-identifier"),
        pytest.param("git clone git@github.com:org/repo.git https://github.com/org/repo", id="plain-urls"),
        pytest.param("ssh://git@example.net:22/org/repo", id="ssh-user-without-password"),
        pytest.param("-----BEGIN " + "PUBLIC KEY-----\n-----BEGIN CERTIFICATE-----", id="public-material"),
        pytest.param("signature: eyJhbGciOi", id="short-jwt-prefix"),
    ],
)
def test_placeholders_and_lookalikes_are_not_reported(text: str) -> None:
    assert list(findings(text)) == []


def test_exit_codes_and_paths_that_are_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    planted = "gh" + "p_" + _random("e1", 36)
    excluded = [
        "tests/unit/test_example.py",
        "./tests/fixtures/export.json",
        "shadowscan/signatures/data/pack.yaml",
        "tools/evaluation/corpus.json",
        "tools/evaluation/review_corpus.json",
    ]
    reported = [
        "contests/app.py",
        "tools/evaluation/independent_annotations.json",
        "tools/evaluation/x/corpus.json",
    ]
    for name in excluded + reported:
        Path(name).parent.mkdir(parents=True, exist_ok=True)
        Path(name).write_text(planted, encoding="utf-8")
    Path("clean.md").write_text("No credentials here.\n", encoding="utf-8")
    Path("link.txt").symlink_to(tmp_path / reported[0])
    Path("submodule").mkdir()
    assert main(excluded + ["clean.md", "link.txt", "submodule"]) == 0
    assert capsys.readouterr().out == ""
    # No file at all means the listing that feeds the check failed: never a pass.
    assert main([]) == 2
    assert "no files to check" in capsys.readouterr().err
    for name in reported:
        assert main([name]) == 1
        assert capsys.readouterr().out.startswith(f"{name}:1: possible hardcoded GitHub token")
    # A named file that cannot be read fails closed instead of passing unchecked.
    assert main(["missing.txt"]) == 1
    assert "missing.txt: cannot read" in capsys.readouterr().err


def test_patterns_stay_linear_on_hostile_input() -> None:
    hostile = [
        "eyJ" * 70_000,
        "eyJ" + "A" * 200_000,
        "x://" + "a:" * 100_000,
        "a" * 200_000,
        "-----BEGIN " + "A " * 100_000,
        "sk-" * 70_000,
        "aws_secret_access_key" + " " * 200_000,
        "AccountKey" + " " * 200_000 + "=",
    ]
    started = time.perf_counter()
    for text in hostile:
        list(findings(text))
    assert time.perf_counter() - started < 2


def test_reported_file_names_cannot_forge_a_report_line_or_a_workflow_command(tmp_path, capsys):
    # A tracked file name may hold control characters; the report escapes them
    # so a crafted name cannot start a new line or a `::` workflow command.
    path = tmp_path / "config.py\n::error::forged"
    path.write_text("token = 'sk-" + "proj-" + _random("n1", 40, _URLSAFE) + "'\n", encoding="utf-8")
    assert main([str(path)]) == 1
    out = capsys.readouterr().out
    assert out.count("\n") == 1 and "\\x0a::error::forged" in out
    assert display("plain/name.py") == "plain/name.py"
