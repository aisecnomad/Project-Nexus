"""Regressions for the 2026-09-24 review of the connector base and sanitizer.

All credentials below are synthetic.
"""

from __future__ import annotations

import json

import pytest

from shadowscan.connectors.base import BaseConnector, ConnectorContext
from shadowscan.models import Finding, Kind, Surface
from shadowscan.utils.redaction import REDACTED, sanitize, sanitize_text

KEY = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN"


def _finding(title: str, **kwargs) -> Finding:
    return Finding(surface=Surface.CODE, connector="test.records", kind=Kind.AGENT, title=title,
                   resource=f"repo:{title}", resource_type="repository", **kwargs)


class _Oversized(BaseConnector):
    """Yields an ordinary finding, one whose aggregate exceeds the sanitizer budget, then a credential finding."""

    name = "test.records"

    def collect(self):
        yield {"id": 1}

    def analyze(self, records):
        yield _finding("first")
        huge = _finding("aggregate")
        # Individually bounded pieces whose expanded serialization exceeds the budget.
        huge.metadata["agent_definitions"] = [{"tools": ["tool"] * 1000}] * 200
        yield huge
        secret = _finding("credential")
        secret.metadata["excerpt"] = f"OPENAI_API_KEY={KEY}"
        yield secret


def test_one_oversized_finding_is_omitted_without_discarding_the_others(index):
    ctx = ConnectorContext(config={}, index=index)
    findings = _Oversized(ctx).run()
    assert [f.title for f in findings] == ["first", "credential"]
    assert ctx.stats is not None and ctx.stats.incomplete
    assert any("finding omitted: sanitization safety limit exceeded" in e for e in ctx.stats.errors)
    assert KEY not in json.dumps([f.to_dict() for f in findings])


@pytest.mark.parametrize("line, value", [
    ('AZURE_OPENAI_KEY = "0123456789abcdef0123456789abcdef"', "0123456789abcdef"),
    ("export DATABRICKS_TOKEN=synthetic-databricks-token-value-0000", "synthetic-databricks"),
    ('modal_token_secret = "as-deadbeefcafe0123456789"', "as-deadbeefcafe"),
    ("LITELLM_MASTER_KEY: sk-1234", "sk-1234"),
    ('"OPENAI_ADMIN_KEY": "fedcba9876543210fedcba9876543210"', "fedcba9876543210"),
    ("CLAUDE_CODE_OAUTH_TOKEN=abcdefabcdefabcdefabcdef", "abcdefabcdef"),
    ("hugging_face_hub_token = 'hf_synthetic_value_without_known_prefix_shape'", "synthetic_value"),
    ("https://example.com/callback?litellm_master_key=sk-1234&model=gpt", "sk-1234"),
])
def test_environment_style_credential_names_are_redacted_in_text(line, value):
    clean = sanitize_text(line)
    assert value not in clean and REDACTED in clean


@pytest.mark.parametrize("line", [
    "sort_key_fn = compute()", "key = 1", 'nextPageToken = "abc"', 'partition = "id"',
    'AWS_REGION = "us-east-1"', 'OPENAI_BASE_URL = "https://api.openai.com/v1"', "MAX_TOKENS = 4096",
])
def test_non_credential_assignments_are_preserved(line):
    assert sanitize_text(line) == line


def test_record_field_names_keep_their_narrow_sensitivity():
    # Provider inventories use bare "Key"/"Value" members and pagination tokens;
    # the environment-style rule applies to text assignments only.
    record = {"Tags": [{"Key": "Name", "Value": "prod-agent"}], "nextToken": "page-2", "PARTITION_KEY": "id"}
    assert sanitize(record) == record
