"""Opaque values in credential containers must be withheld across output paths."""

from __future__ import annotations

import json

import pytest

from shadowscan.connectors.base import BaseConnector, ConnectorContext
from shadowscan.models import Evidence, Finding, Kind, Surface
from shadowscan.signatures import SignatureIndex
from shadowscan.utils.redaction import REDACTED, sanitize

SECRET = "opaque-nested-test-credential-271828"


@pytest.mark.parametrize("secret", [SECRET, "abc"])
def test_direct_nested_credential_redacts_identical_opaque_sibling(secret):
    clean = sanitize({"credentials": {"value": secret}, "description": f"rejected {secret}"})
    assert clean["credentials"] == REDACTED
    assert clean["description"] == (REDACTED if len(secret) < 8 else f"rejected {REDACTED}")


def _record() -> dict:
    return {
        "credentials": {
            "primary": [{"name": "production", "value": SECRET}],
            "provider": "openai",
        },
        "description": f"rejected {SECRET} by provider",
        "provider": "openai",
        "status": "production",
    }


def test_nested_credentials_redact_sibling_copies_without_removing_descriptors():
    original = _record()
    clean = sanitize(original)
    assert clean["credentials"] == REDACTED
    assert clean["description"] == f"rejected {REDACTED} by provider"
    assert clean["provider"] == "openai"
    assert clean["status"] == "production"
    assert sanitize(clean) == clean
    assert original["credentials"]["primary"][0]["value"] == SECRET


def test_opaque_container_id_does_not_taint_an_unrelated_caller_label():
    clean = sanitize({"api_key": {"id": "k"}, "service": "worker", "model": "gpt-4o"})
    assert clean == {"api_key": REDACTED, "service": "worker", "model": "gpt-4o"}


def test_generic_credentials_id_is_opaque_secret_and_redacts_its_sibling_copy():
    clean = sanitize({"credentials": {"id": SECRET}, "title": f"agent {SECRET}"})
    assert clean == {"credentials": REDACTED, "title": f"agent {REDACTED}"}


def test_authorization_principal_object_id_remains_a_descriptive_identity():
    clean = sanitize({"identity": {"authorization": {"objectId": "obj-9"}}, "caller": "azure:obj-9"})
    assert clean == {"identity": {"authorization": REDACTED}, "caller": "azure:obj-9"}


@pytest.mark.parametrize(
    ("descriptor", "nested"),
    [
        ("id", {"value": SECRET}),
        ("name", {"value": SECRET}),
        ("provider", [{"value": SECRET}]),
        ("scope", ("unrelated", {"value": SECRET})),
    ],
)
def test_nested_record_under_descriptor_still_propagates_credentials(descriptor, nested):
    clean = sanitize({"credentials": {descriptor: nested}, "description": f"copy {SECRET}"})
    assert clean == {"credentials": REDACTED, "description": f"copy {REDACTED}"}


def test_nested_credentials_are_discovered_through_an_aliased_cycle():
    credentials = {"value": SECRET}
    credentials["self"] = credentials
    clean = sanitize({"credentials": credentials, "description": f"copy {SECRET}"})
    assert clean == {"credentials": REDACTED, "description": f"copy {REDACTED}"}


def test_shared_object_is_revisited_under_sensitive_parent():
    shared = {"value": SECRET}
    clean = sanitize({"details": shared, "credentials": shared, "error": f"rejected {SECRET}"})
    assert clean["details"]["value"] == REDACTED
    assert clean["credentials"] == REDACTED
    assert clean["error"] == f"rejected {REDACTED}"


def test_finding_serialization_never_emits_nested_opaque_credentials():
    finding = Finding(
        surface=Surface.CODE,
        connector="test.nested-credentials",
        kind=Kind.AGENT,
        title=f"agent: {SECRET}",
        resource="example/repo",
        resource_type="repository",
        metadata=_record(),
        evidence=[Evidence(signal="test", description=f"response contained {SECRET}")],
    )
    serialized = finding.to_dict()
    assert SECRET not in json.dumps(serialized)
    assert serialized["metadata"]["provider"] == "openai"
    assert serialized["metadata"]["description"] == f"rejected {REDACTED} by provider"


class _NestedCredentialConnector(BaseConnector):
    name = "test.nested-credentials"

    def collect(self):
        yield _record()

    def analyze(self, records):
        for record in records:
            self.ctx.examined()
            yield Finding(
                surface=Surface.CODE,
                connector=self.name,
                kind=Kind.AGENT,
                title="agent",
                resource="example/repo",
                resource_type="repository",
                metadata=record,
            )


def test_record_export_and_finding_report_never_emit_nested_credentials(tmp_path):
    target = tmp_path / "records.jsonl"
    context = ConnectorContext(config={"_dump_path": str(target)}, index=SignatureIndex([]))
    findings = _NestedCredentialConnector(context).run()

    assert not context.stats.incomplete
    assert len(findings) == 1
    assert SECRET not in target.read_text()
    assert SECRET not in json.dumps(findings[0].to_dict())
    exported = json.loads(target.read_text())
    assert exported["description"] == f"rejected {REDACTED} by provider"
    assert exported["provider"] == "openai"
