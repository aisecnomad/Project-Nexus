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


# Fields of a generic SaaS export that kept their raw values in the record dump: the
# whole-name rule knew nine names and about forty compound suffixes, and none of these.
WORD_NAMED_SECRETS = [
    "webhook_secret",
    "signing_secret",
    "bot_token",
    "slack_token",
    "npm_token",
    "client_key",
    "consumer_secret",
    "openai_key",
    "authorization_token",
    "verification_token",
    "pwd",
    "passphrase",
    "db_pass",
    "security_token",
    "jwtSecret",
    "access_secret",
]


@pytest.mark.parametrize("name", WORD_NAMED_SECRETS)
def test_fields_whose_last_word_names_a_credential_are_withheld(name):
    secret = "opaque-credential-value-0123456789"
    clean = sanitize({"id": "app-1", name: secret, "note": f"copied {secret} here"})
    assert clean == {"id": "app-1", name: REDACTED, "note": f"copied {REDACTED} here"}
    # Case, separators and trailing digits do not matter.
    variants = [name + "2", name + "_2"]
    if "_" in name:
        variants += [name.upper(), name.replace("_", "-"), name.replace("_", ".")]
        variants.append("".join(word.title() for word in name.split("_")))
    for variant in variants:
        assert sanitize({variant: secret}) == {variant: REDACTED}, variant


@pytest.mark.parametrize(
    "name",
    [
        # Cursors, which connectors page with.
        "next_token",
        "nextToken",
        "NextToken",
        "page_token",
        "nextPageToken",
        "continuation_token",
        "pagination_token",
        "sync_token",
        "delta_token",
        "skipToken",
        # Names that do not end in a credential word.
        "token_type",
        "token_count",
        "max_tokens",
        "prompt_tokens",
        "secret_name",
        "tokenizer",
        "keyword",
        "monkey",
        "bypass",
        # A key that names no credential.
        "key",
        "Key",
        "sort_key",
        "partition_key",
        "cache_key",
        "primary_key",
        "public_key",
        "object_key",
        "kid",
        # A tokenizer's special tokens, a cancellation token and switches.
        "eos_token",
        "pad_token",
        "CancellationToken",
        "requires_auth",
        "has_secret",
        "use_token",
        # A key named only 'pass' is a test result.
        "pass",
        # A name whose last word only names a credential keeps ordinary values.
        "OpenAIKey",
    ],
)
def test_fields_that_connectors_need_stay_visible(name):
    record = {name: "ordinary-value", "n": 3}
    assert sanitize(record) == record


def test_aws_tags_and_object_keys_stay_visible():
    tags = [{"Key": "Environment", "Value": "prod"}, {"Key": "Owner", "Value": "platform"}]
    listing = {"Contents": [{"Key": "photos/2024/img.jpg", "Size": 12}], "NextToken": "page-2", "Tags": tags}
    assert sanitize(listing) == listing
    record = {"name": "OpenAIKey", "value": "photos/2024/img.jpg"}
    assert sanitize(record) == record


def test_existing_suffix_rules_are_kept():
    for name in (
        "access_key_id",
        "accessKeyId",
        "SecretAccessKey",
        "client_secret",
        "Authorization",
        "apiKey",
    ):
        assert sanitize({name: "AKIAIOSFODNN7EXAMPLE"}) == {name: REDACTED}, name


def test_the_words_of_a_setting_name_are_still_read_as_a_setting():
    # The fields of a record are read by their words; the name of a setting is read as
    # before, so an ordinary value under a name such as 'cache_key' stays.
    for record in ({"name": "cache_key", "value": "users"}, {"name": "OpenAIKey", "value": "users"}):
        assert sanitize(record) == record


def test_credential_words_are_read_in_command_line_options_and_headers():
    secret = "opaque-credential-value-0123456789"
    assert sanitize({"args": ["--bot-token", secret, "--next-token", "page-2"]}) == {
        "args": ["--bot-token", REDACTED, "--next-token", "page-2"]
    }


def test_the_word_rule_leaves_ordinary_keys_alone():
    keys = [f"field_{index}" for index in range(2000)] + [f"api_field_{index}_name" for index in range(2000)]
    assert sanitize(dict.fromkeys(keys, "v")) == dict.fromkeys(keys, "v")
