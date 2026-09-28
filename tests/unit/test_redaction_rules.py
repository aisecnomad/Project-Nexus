"""What the redaction sanitizer withholds and what it keeps, in text and in records.

All credentials below are synthetic.
"""

from __future__ import annotations

import json

import pytest

from shadowscan.connectors import ConnectorContext
from shadowscan.utils import redaction
from shadowscan.utils.redaction import REDACTED, sanitize, sanitize_text

ACCOUNT = "123456789012"
KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN"


def test_sanitize_env_values_policy_distinguishes_configuration_from_secrets():
    record = {
        "arn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:prod-agent",
        "env": {"STAGE": "prod", "N": "4"},
    }
    # Tool/agent configuration keeps the strict default: env values are credentials everywhere.
    assert sanitize(record)["arn"] == REDACTED
    inventory = sanitize(record, env_values_are_secrets=False)
    assert inventory["arn"] == record["arn"]
    assert inventory["env"] == {"STAGE": REDACTED, "N": REDACTED}
    # Values under sensitive names and recognizable formats are still removed from siblings.
    leaky = {"note": f"uses {KEY} and opaque-configured-value", "env": {"API_KEY": "opaque-configured-value"}}
    clean = sanitize(leaky, env_values_are_secrets=False)
    assert KEY not in clean["note"] and "opaque-configured-value" not in clean["note"]


@pytest.mark.parametrize(
    "name", ["AZURE_OPENAI_KEY", "DATABRICKS_TOKEN", "MODAL_TOKEN_SECRET", "LITELLM_MASTER_KEY"]
)
@pytest.mark.parametrize("shape", ["mapping", "variables", "list", "aliased"])
def test_configuration_environment_still_redacts_named_secrets_from_siblings(name, shape):
    secret = "opaque-configured-secret-material"
    env = {name: secret, "STAGE": "prod"}
    if shape == "variables":
        env = {"Variables": env}
    elif shape == "list":
        env = [{"name": name, "value": secret}, {"name": "STAGE", "value": "prod"}]
    record = {"label": "prod-agent", "url": f"https://example.invalid/{secret}"}
    if shape == "aliased":
        record["other"] = env
    record["environment"] = env
    clean = sanitize(record, env_values_are_secrets=False)
    assert secret not in json.dumps(clean)
    assert clean["label"] == "prod-agent"


def test_repeated_sanitization_observes_lowered_resource_budgets(monkeypatch):
    value = "plain text with no credentials"
    assert redaction.sanitize_text(value) == value
    monkeypatch.setattr(redaction, "_MAX_SANITIZATION_CHARS", 1)
    with pytest.raises(redaction.SanitizationLimitError, match="size limit"):
        redaction.sanitize_text(value)


@pytest.mark.parametrize(
    "line, value",
    [
        ('AZURE_OPENAI_KEY = "0123456789abcdef0123456789abcdef"', "0123456789abcdef"),
        ("export DATABRICKS_TOKEN=synthetic-databricks-token-value-0000", "synthetic-databricks"),
        ('modal_token_secret = "as-deadbeefcafe0123456789"', "as-deadbeefcafe"),
        ("LITELLM_MASTER_KEY: sk-1234", "sk-1234"),
        ('"OPENAI_ADMIN_KEY": "fedcba9876543210fedcba9876543210"', "fedcba9876543210"),
        ("CLAUDE_CODE_OAUTH_TOKEN=abcdefabcdefabcdefabcdef", "abcdefabcdef"),
        ("hugging_face_hub_token = 'hf_synthetic_value_without_known_prefix_shape'", "synthetic_value"),
        ("https://example.com/callback?litellm_master_key=sk-1234&model=gpt", "sk-1234"),
        ('os.environ["DATABRICKS_TOKEN"] = "synthetic-databricks-token-value-0000"', "synthetic-databricks"),
        ("process.env['AZURE_OPENAI_KEY'] = '0123456789abcdef0123456789abcdef'", "0123456789abcdef"),
    ],
)
def test_environment_style_credential_names_are_redacted_in_text(line, value):
    clean = sanitize_text(line)
    assert value not in clean and REDACTED in clean


@pytest.mark.parametrize(
    "line",
    [
        "sort_key_fn = compute()",
        "key = 1",
        'nextPageToken = "abc"',
        'partition = "id"',
        'AWS_REGION = "us-east-1"',
        'OPENAI_BASE_URL = "https://api.openai.com/v1"',
        "MAX_TOKENS = 4096",
    ],
)
def test_non_credential_assignments_are_preserved(line):
    assert sanitize_text(line) == line


def test_record_field_names_keep_their_narrow_sensitivity():
    # Provider inventories use bare "Key"/"Value" members and pagination tokens;
    # the environment-style rule applies to text assignments only.
    record = {"Tags": [{"Key": "Name", "Value": "prod-agent"}], "nextToken": "page-2", "PARTITION_KEY": "id"}
    assert sanitize(record) == record


def test_ssws_scheme_and_repr_escaped_values_are_redacted():
    assert "00abcdefghijklmnop" not in redaction.sanitize_text("Authorization: SSWS 00abcdefghijklmnop")
    secret = "00SuperSecretOktaApiToken123456\n"
    ctx = ConnectorContext(config={"token": secret})
    message = ctx.sanitize_message(f"InvalidHeader: Invalid leading whitespace in header value: {secret!r}")
    assert "SuperSecretOktaApiToken" not in message


@pytest.mark.parametrize(
    "secret",
    [
        "pplx-" + "a" * 45,
        "gsk_" + "A" * 45,
        "xai-" + "b" * 64,
        "nvapi-" + "c" * 64,
        "r8_" + "d" * 32,
        "csk-" + "e" * 32,
        "tgp_v1_" + "f" * 32,
        "e2b_" + "0" * 40,
        "lsv2_pt_" + "a" * 32 + "_" + "b" * 10,
        "tvly-dev-" + "g" * 24,
        "pcsk_" + "h" * 24,
        "fc-" + "1" * 32,
        "app-" + "A" * 24,
        "sk-lf-" + "0" * 36,
    ],
)
def test_every_detectable_credential_format_is_redacted_by_the_text_sanitizer(secret):
    assert secret not in redaction.sanitize_text(f"value {secret} trailing")


@pytest.mark.parametrize("key", ["api_token", "foundry_token", "github_token"])
def test_specific_credential_names_redact_record_and_diagnostic(key):
    secret = "synthetic-opaque-credential-value-0123456789"
    record = sanitize({key: secret, "status": f"provider rejected {secret}"})
    assert record[key] == REDACTED
    assert secret not in record["status"]
    ctx = ConnectorContext(config={key: secret})
    assert secret not in ctx.sanitize_message(f"provider rejected {secret}")


def test_short_credential_still_withholds_diagnostic_by_default():
    record, diagnostic = sanitize(({"api_token": "a"}, "provider rejected a"))
    assert diagnostic == REDACTED
    assert REDACTED in record.values()


def test_usage_metric_names_stay_visible():
    metrics = {"token_count": 12, "input_tokens": 3, "output_tokens": 9}
    assert sanitize(metrics) == metrics
