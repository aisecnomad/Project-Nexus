"""Regressions for credential exposure, report injection and scan completeness."""

from __future__ import annotations

import csv
import datetime
import io
import json
import re
import stat

import jwt
import pytest
from rich.console import Console

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors.base import BaseConnector, ConnectorContext
from shadowscan.connectors.code.filesystem import _excerpt
from shadowscan.connectors.identity.jwt import JwtConnector
from shadowscan.connectors.saas.generic import GenericSaaSConnector
from shadowscan.engine import Engine
from shadowscan.models import Evidence, Finding, Kind, ScanResult, ScanStats, Surface
from shadowscan.reporters import render
from shadowscan.reporters.csv_ import render_csv
from shadowscan.reporters.table import print_table
from shadowscan.signatures.loader import Signature
from shadowscan.signatures.matcher import SignatureIndex
from shadowscan.utils import redaction_formats
from shadowscan.utils.redaction import REDACTED, credential_id, sanitize, sanitize_text

SECRET = "opaque-synthetic-credential-value"
PROVIDER_KEY = "sk-proj-syntheticcredentialvaluenotarealkey"


def _index():
    return SignatureIndex([Signature(id="framework.test", name="Test", category="framework")])


def _finding(**kwargs):
    return Finding(
        surface=Surface.CODE,
        connector="test",
        kind=Kind.AGENT,
        title=kwargs.pop("title", "Agent"),
        resource="repo:example",
        resource_type="repository",
        **kwargs,
    )


def test_sanitizes_structured_credentials_urls_argv_and_copies():
    original = {
        "api_key": SECRET,
        "note": f"debug copy {SECRET}",
        "config": {
            "env": {"CUSTOM_CREDENTIAL_NAME": SECRET, "MODE": "debug"},
            "args": ["--token", SECRET, "--model", "gpt-example", "PASSWORD='a value with spaces'"],
            "url": f"https://user:{SECRET}@example.com/path?token={SECRET}&model=gpt-example",
        },
        "environment": "production",
        "repository": "org/repo",
        "deployment_id": "deploy-1",
        "events": 15,
        "capabilities": ["tool-use", "memory"],
    }
    result = sanitize(original)
    assert SECRET not in json.dumps(result)
    assert "a value with spaces" not in json.dumps(result)
    assert result["config"]["env"] == {"CUSTOM_CREDENTIAL_NAME": REDACTED, "MODE": REDACTED}
    assert result["config"]["args"][3] == "gpt-example"
    assert "model=gpt-example" in result["config"]["url"]
    for key in ("environment", "repository", "deployment_id", "events", "capabilities"):
        assert result[key] == original[key]
    assert sanitize(result) == result
    assert original["api_key"] == SECRET  # analysis still receives the original input


@pytest.mark.parametrize(
    "record",
    [
        {"env": [{"name": "PASSWORD", "value": SECRET}]},
        {"environment": [{"name": "CUSTOM_NAME", "value": SECRET}]},
        {"Environment": {"Variables": {"CUSTOM_NAME": SECRET}}},
        {"key": "OPENAI_API_KEY", "value": SECRET},
        {"Name": "CLIENT_SECRET", "Value": SECRET},
        {"SecretString": SECRET},
        {"keyString": SECRET},
        {"privateKeyData": SECRET},
    ],
)
def test_cloud_environment_and_name_value_exports(record):
    assert SECRET not in json.dumps(sanitize(record))


def test_gcp_api_key_string_never_reaches_report_or_record_dump(tmp_path, index):
    secret = "opaque-private-google-api-value-123"
    export = tmp_path / "api-keys.jsonl"
    export.write_text(
        json.dumps(
            {
                "_kind": "api-key",
                "_project": "test-project",
                "name": "projects/test-project/locations/global/keys/example",
                "displayName": "Gemini service",
                "keyString": secret,
            }
        )
        + "\n"
    )
    dumped = tmp_path / "dumped"
    config = ScanConfig(
        connectors=[ConnectorSpec("cloud.gcp", {"input": str(export)})], dump_records=str(dumped)
    )
    result = Engine(config, index).run()
    assert result.complete
    assert any(finding.kind == Kind.SECRET for finding in result.findings)
    dump_files = list(dumped.glob("*.jsonl"))
    assert len(dump_files) == 1
    assert json.loads(dump_files[0].read_text())["keyString"] == REDACTED
    assert secret not in result.to_json() and secret not in dump_files[0].read_text()


def test_generic_saas_record_dump_withholds_fields_named_for_a_credential_by_their_words(tmp_path, index):
    names = [
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
    secrets = {name: f"synthetic-{name}-value-0123456789" for name in names}
    export = tmp_path / "apps.jsonl"
    record = {"id": "app-1", "name": "Slack bot", "users": 4, "next_token": "page-2"}
    export.write_text(json.dumps({**record, **secrets}) + "\n")
    dumped = tmp_path / "dumped"
    config = ScanConfig(
        connectors=[ConnectorSpec("saas.generic", {"input": str(export)})], dump_records=str(dumped)
    )
    result = Engine(config, index).run()
    assert result.complete
    (dump_file,) = dumped.glob("*.jsonl")
    row = json.loads(dump_file.read_text())
    assert {name: row[name] for name in names} == dict.fromkeys(names, REDACTED)
    assert {key: row[key] for key in record} == record
    assert not any(secret in dump_file.read_text() for secret in secrets.values())


@pytest.mark.parametrize(
    "value",
    [
        f'OPENAI_API_KEY = "{PROVIDER_KEY}"',
        f'password="{SECRET}"',
        f'wrapper = "api_key={SECRET}"',
        f"Authorization: Bearer {SECRET}",
        f"https://example.com?api_key={SECRET}&safe=yes",
        f"https://example.com?%61pi_key={SECRET}&safe=yes",
        f"https://user:{SECRET}@example.com/path",
        "-----BEGIN PRIVATE KEY-----\n" + SECRET + "\n-----END PRIVATE KEY-----",
    ],
)
def test_text_redaction_idempotent(value):
    result = sanitize_text(value)
    assert SECRET not in result and PROVIDER_KEY not in result
    assert sanitize_text(result) == result


def test_credential_fingerprint_is_stable_nonsecret_and_survives_sanitization():
    identity = credential_id(SECRET)
    assert identity == credential_id(SECRET) == credential_id(identity)
    assert identity != credential_id(SECRET + "other")
    assert SECRET not in identity
    assert sanitize({"api_key": identity, "caller": identity}) == {"api_key": identity, "caller": identity}


def test_finding_and_serialization_sanitize_sibling_evidence():
    f = _finding(
        title=f"Agent {PROVIDER_KEY}",
        metadata={"api_key": SECRET, "repository": "org/repo"},
        evidence=[
            Evidence(
                signal="import",
                description=f"copy {SECRET}",
                snippet=f"import langchain; KEY='{PROVIDER_KEY}'",
            )
        ],
        capabilities=["tool-use"],
    )
    assert SECRET not in str(f.evidence)
    assert PROVIDER_KEY not in f.title
    f.metadata["password"] = SECRET
    f.title = f"Agent {PROVIDER_KEY}"
    result = f.to_dict()
    assert SECRET not in json.dumps(result) and PROVIDER_KEY not in json.dumps(result)
    assert f.capabilities == ["tool-use"] and f.metadata["repository"] == "org/repo"


class _RecordConnector(BaseConnector):
    name = "test.records"

    def collect(self):
        yield {"api_key": SECRET, "debug": SECRET, "environment": "production"}

    def analyze(self, records):
        for record in records:
            self.ctx.examined()
            finding = _finding()
            finding.metadata = record
            yield finding


def test_export_is_sanitized_atomic_and_owner_only(tmp_path):
    target = tmp_path / "records.jsonl"
    target.write_text("old contents")
    target.chmod(0o644)
    connector = _RecordConnector(ConnectorContext(config={"_dump_path": str(target)}, index=_index()))
    findings = connector.run()
    assert SECRET not in target.read_text()
    assert SECRET not in str(findings)
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert json.loads(target.read_text())["environment"] == "production"
    assert list(tmp_path.iterdir()) == [target]
    assert not connector.ctx.stats.errors


def test_jwt_dump_never_writes_token_records(tmp_path):
    target = tmp_path / "jwt.jsonl"
    token = jwt.encode(
        {"sub": "agent", "agent_id": "agent-1"},
        "synthetic-test-signing-key-only-32-bytes",
        algorithm="HS256",
    )
    connector = JwtConnector(
        ConnectorContext(
            config={"tokens": [token], "_dump_path": str(target)},
            index=_index(),
        )
    )
    findings = connector.run()
    assert len(findings) == 1 and not connector.ctx.stats.errors
    assert not target.exists()
    assert token not in json.dumps(findings[0].to_dict())
    assert findings[0].metadata["agent_claims"]["agent_id"] == "agent-1"


def test_generic_saas_does_not_copy_arbitrary_export_columns():
    connector = GenericSaaSConnector(ConnectorContext(config={"keep_all": True}, index=_index()))
    result = list(
        connector.analyze(
            [
                {"name": "Agent", "id": "app-1", "users": 4, "custom_private_column": SECRET},
            ]
        )
    )
    assert len(result) == 1
    assert SECRET not in json.dumps(result[0].to_dict())
    assert result[0].metadata["users"] == 4
    assert "raw" not in result[0].metadata


@pytest.mark.parametrize(
    "formula,expected",
    [
        ("=1+1", "'=1+1"),
        ("+1+1", "'+1+1"),
        ("-1+1", "'-1+1"),
        ("@SUM(1)", "'@SUM(1)"),
        # A tab or line break also starts a cell when the report is split on it.
        ("\t=1+1", "'\t'=1+1"),
        ("\r=1+1", "'\r'=1+1"),
        ("\n=1+1", "'\n'=1+1"),
        ("  =1+1", "'  =1+1"),
        ("\ufeff=1+1", "'\ufeff=1+1"),
    ],
)
def test_csv_formula_values_are_literal_text(formula, expected):
    f = _finding(title=formula, owner=formula, evidence=[Evidence(signal="test", description=formula)])
    # A complete scan: an incomplete one leads with a status row.
    complete = ScanResult(findings=[f], stats=[ScanStats(connector="test", started_at="now")])
    row = next(csv.DictReader(io.StringIO(render_csv(complete))))
    for column in ("title", "owner", "top_evidence"):
        assert row[column] == expected
    assert row["confidence"] == "0.0"


def test_incomplete_status_and_sanitized_context_diagnostics(caplog):
    context = ConnectorContext(index=_index())
    context.stats = ScanStats(connector="test", started_at="now")
    assert ScanResult(stats=[context.stats]).complete
    context.warn("advisory only", incomplete=False)
    assert ScanResult(stats=[context.stats]).complete
    context.warn(f"could not access url?api_key={SECRET}")
    assert not ScanResult(stats=[context.stats]).complete
    context.error(f"password={SECRET}")
    assert SECRET not in str(context.stats) and SECRET not in caplog.text
    assert not ScanResult().complete
    assert ScanResult(stats=[context.stats]).summary()["status"] == "incomplete"


def test_completed_findings_survive_connector_failure():
    class PartialConnector(_RecordConnector):
        def analyze(self, records):
            yield from super().analyze(records)
            raise ValueError(f"bad token={SECRET}")

    connector = PartialConnector(ConnectorContext(index=_index()))
    findings = connector.run()
    assert len(findings) == 1
    result = ScanResult(findings=findings, stats=[connector.ctx.stats])
    assert not result.complete and result.summary()["errors"] == 1
    assert SECRET not in result.to_json()


def test_cyclic_untrusted_metadata_does_not_recurse_or_leak():
    record = {"token": SECRET}
    record["cycle"] = record
    safe = sanitize(record)
    assert safe == {"token": REDACTED, "cycle": REDACTED}
    assert SECRET not in str(_finding(metadata=record).to_dict())


def test_machine_signal_identifiers_and_jwt_fingerprints_are_preserved():
    for value in ("jwt:hygiene", "jwt:delegated-agent", "jwt:1234567890abcdef", "secret:provider.openai"):
        assert sanitize_text(value) == value


def test_source_secret_copies_are_redacted_using_parsed_environment_and_argv():
    parsed = {"env": {"CUSTOM_NAME": SECRET}, "args": ["--token", "other-opaque-credential"]}
    source = json.dumps(parsed)
    safe = sanitize({"source": source, "parsed": parsed})["source"]
    assert SECRET not in safe and "other-opaque-credential" not in safe


def test_safe_token_statistics_and_secret_reference_lists_are_preserved():
    value = {"tokens": 12, "secrets": ["approved-secret-reference"], "environment": "production"}
    assert sanitize(value) == value


def test_multiline_private_keys_preserve_source_line_numbers():
    source = "-----BEGIN PRIVATE KEY-----\nsecret-material\n-----END PRIVATE KEY-----\nimport langchain"
    safe = sanitize_text(source)
    assert source.count("\n") == safe.count("\n")
    assert safe.splitlines()[3] == "import langchain"
    assert "secret-material" not in safe


@pytest.mark.parametrize("from_environment", [False, True])
def test_diagnostics_redact_opaque_configured_credentials(caplog, monkeypatch, from_environment):
    config = {} if from_environment else {"api_key": SECRET}
    context = ConnectorContext(config=config, index=_index())
    context.stats = ScanStats(connector="test", started_at="now")
    if from_environment:
        monkeypatch.setenv("TEST_PROVIDER_KEY", SECRET)
        assert context.get("api_key", env="TEST_PROVIDER_KEY") == SECRET
    message = f"remote server rejected supplied value {SECRET}"
    context.warn(message)
    context.error(message)
    assert SECRET not in str(context.stats) and SECRET not in caplog.text


@pytest.mark.parametrize(
    "credential",
    [
        "gsk_" + "a" * 40,
        "pcsk_" + "a" * 20,
        "e2b_" + "a" * 40,
        "tgp_v1_" + "a" * 30,
        "lsv2_pt_" + "a" * 32 + "_" + "b" * 10,
        "tvly-prod-" + "a" * 20,
        "xai-" + "a" * 60,
        "pplx-" + "a" * 40,
        "csk-" + "a" * 30,
        "nvapi-" + "a" * 60,
        "r8_" + "a" * 30,
        "fc-" + "a" * 32,
        "app-" + "a" * 24,
    ],
)
def test_additional_provider_tokens_are_redacted(credential):
    assert credential not in sanitize_text(f"credential={credential}")


def test_ssws_authorization_is_redacted():
    credential = "synthetic-okta-token-value"
    assert credential not in sanitize_text(f"Authorization: SSWS {credential}")


def test_repr_escaped_configured_secret_is_redacted():
    credential = "first-line\nsecond-line"
    result = sanitize({"client_secret": credential, "debug": repr(credential)})
    assert credential not in result["debug"]
    assert repr(credential)[1:-1] not in result["debug"]


def test_long_secret_is_redacted_before_excerpt_truncation():
    credential = "opaque-" + "x" * 240
    excerpt = _excerpt([f"token={credential}"], 1, credential)
    assert credential not in excerpt
    assert credential[:120] not in excerpt


LEAF_KEY = "sk" + "-proj-" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6"


class _PluginObject:
    """An arbitrary object a plugin may leave in metadata; only its repr shows the value."""

    def __repr__(self) -> str:
        return f"PluginObject(token={LEAF_KEY})"


def _leaf_finding():
    return _finding(
        metadata={
            "b": LEAF_KEY.encode(),
            "ba": bytearray(LEAF_KEY.encode()),
            "s": {LEAF_KEY},
            "fs": frozenset({LEAF_KEY}),
            "e": ValueError(LEAF_KEY),
            "o": _PluginObject(),
            "nested": [{"deeper": (b"\xff" + LEAF_KEY.encode(),)}],
        }
    )


def test_unknown_leaf_types_are_stringified_and_sanitized():
    clean = sanitize({"b": LEAF_KEY.encode(), "s": {LEAF_KEY, "other"}, "e": ValueError(LEAF_KEY), "n": 3})
    assert LEAF_KEY not in repr(clean)
    assert clean["n"] == 3
    assert clean["b"] == REDACTED
    assert sorted(clean["s"]) == sorted([REDACTED, "other"])
    assert clean["e"] == REDACTED
    # Bytes that are not text are decoded with replacement characters, not an error.
    assert sanitize({"x": b"\xff\xfe ok"}) == {"x": "�� ok"}
    # Plain JSON-like leaves and the standard library's scalars keep their type.
    scalars = {"i": 1, "f": 1.5, "t": True, "none": None, "when": datetime.date(2024, 1, 2)}
    assert sanitize(scalars) == scalars


@pytest.mark.parametrize("fmt", ["json", "html", "markdown", "csv", "sarif"])
def test_unknown_leaf_types_never_reach_a_report(fmt):
    result = ScanResult(findings=[_leaf_finding()])
    assert LEAF_KEY not in render(result, fmt)
    assert LEAF_KEY not in repr(result.findings[0].metadata)


def test_unknown_leaf_types_never_reach_the_terminal_table():
    out = io.StringIO()
    print_table(ScanResult(findings=[_leaf_finding()]), console=Console(file=out, width=200), verbose=True)
    assert LEAF_KEY not in out.getvalue()


def test_unknown_leaf_types_never_reach_a_record_dump(tmp_path):
    target = tmp_path / "records.jsonl"

    class Connector(BaseConnector):
        name = "test.leaf"

        def collect(self):
            yield {
                "id": "1",
                "payload": LEAF_KEY.encode(),
                "labels": {LEAF_KEY},
                "error": RuntimeError(LEAF_KEY),
            }

        def analyze(self, records):
            for _ in records:
                self.ctx.examined()
            yield from ()

    connector = Connector(ConnectorContext(config={"_dump_path": str(target)}, index=_index()))
    connector.run()
    assert target.exists() and LEAF_KEY not in target.read_text()


KEY_BODY = "\n".join("Zm9vYmFyU3ludGhldGljS2V5TWF0ZXJpYWw" + chr(ord("a") + line) * 6 for line in range(6))


@pytest.mark.parametrize(
    "block",
    [
        f"-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n{KEY_BODY}\n=ab12\n-----END PGP PRIVATE KEY BLOCK-----",
        f"-----BEGIN RSA PRIVATE KEY-----\n{KEY_BODY}\n-----END RSA PRIVATE KEY-----",
        f'---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\nComment: "key"\n{KEY_BODY}\n---- END SSH2 ENCRYPTED PRIVATE KEY ----',
        f"PuTTY-User-Key-File-2: ssh-rsa\nEncryption: none\nComment: key\nPublic-Lines: 2\n{KEY_BODY}\n"
        f"Private-Lines: 2\n{KEY_BODY}\nPrivate-MAC: 0123456789abcdef0123456789abcdef01234567",
        f"PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: aes256-cbc\nComment: key\nPublic-Lines: 2\n{KEY_BODY}\n"
        f"Key-Derivation: Argon2id\nPrivate-Lines: 2\n{KEY_BODY}\nPrivate-MAC: 0123456789abcdef0123456789abcdef01234567",
    ],
)
def test_every_private_key_block_is_withheld_with_its_line_count(block):
    source = f"before\n{block}\nafter\n"
    safe = sanitize_text(source)
    assert KEY_BODY.splitlines()[0] not in safe and "0123456789abcdef" not in safe
    assert safe.startswith("before\n" + REDACTED) and safe.endswith("\nafter\n")
    assert safe.count("\n") == source.count("\n")
    assert sanitize_text(safe) == safe


@pytest.mark.parametrize(
    "start",
    [
        "-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----",
        "PuTTY-User-Key-File-2: ssh-rsa",
    ],
)
def test_an_unterminated_key_block_is_withheld_to_the_end_of_the_text(start):
    source = f"note\n{start}\n{KEY_BODY}\nnot a marker line\n"
    safe = sanitize_text(source)
    assert safe.startswith("note\n" + REDACTED) and KEY_BODY.splitlines()[-1] not in safe
    assert "not a marker line" not in safe


@pytest.mark.parametrize(
    "text",
    [
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\nmQENBGZ\n-----END PGP PUBLIC KEY BLOCK-----",
        "---- BEGIN SSH2 PUBLIC KEY ----\nAAAAB3NzaC1yc2E\n---- END SSH2 PUBLIC KEY ----",
        "-----BEGIN CERTIFICATE-----\nMIIBkTCB\n-----END CERTIFICATE-----",
        "see PuTTY-User-Key-File formats in the PuTTY manual",
    ],
)
def test_public_keys_and_prose_about_key_formats_are_kept(text):
    assert sanitize_text(text) == text


# ---------------------------------------------------------------- token formats


def _run(alphabet: str, length: int) -> str:
    # Ends in a word character: the backstop stops at a word boundary, so a token that ended in
    # a hyphen would legitimately leave that one character behind.
    return (alphabet * length)[: length - 1] + "7"


_ALNUM, _HEX, _WORD = "aB3xY7", "0123456789abcdef", "aB3_x-Y7"


def _token_samples() -> list[tuple[str, str]]:
    """One synthetic token per alternative of the backstop, assembled so that no sample is a literal.

    The pairs are (the alternative's own source, a string it matches in full). Splitting a prefix
    keeps a secret scanner from reading a test fixture as a credential.
    """
    return [
        ("sk-(?:proj|ant|live|or-v1|lf|litellm|svcacct|admin)-", "sk" + "-proj-" + _run(_WORD, 20)),
        ("gh[pousr]_", "gh" + "p_" + _run(_ALNUM, 36)),
        ("github_pat_", "github" + "_pat_" + _run(_ALNUM + "_", 40)),
        ("gl(?:pat|rt|ptt|dt|ft|soat|cbt|imt|oas|agent|ffct)-", "gl" + "pat-" + _run(_WORD, 20)),
        ("GR1348941", "GR" + "1348941" + _run(_WORD, 24)),
        ("xox[abeprs]-", "xo" + "xb-" + _run(_ALNUM + "-", 24)),
        ("xoxe\\.xox[bp]-", "xo" + "xe.xoxp-" + _run(_ALNUM + "-", 24)),
        ("xapp-", "xa" + "pp-" + _run(_ALNUM + "-", 24)),
        ("AIza", "AI" + "za" + _run(_WORD, 30)),
        ("ya29\\.", "ya" + "29." + _run(_WORD, 30)),
        ("1//0", "1/" + "/0" + _run(_WORD, 40)),
        ("GOCSPX-", "GOC" + "SPX-" + _run(_WORD, 28)),
        ("(?:AKIA|ASIA)", "AK" + "IA" + _run("ABCDEF0123456789", 16)),
        ("hf_", "hf" + "_" + _run(_ALNUM, 30)),
        ("sk-[A-Za-z0-9_-]{8,}", "sk" + "-" + _run(_WORD, 24)),
        ("gsk_", "gs" + "k_" + _run(_ALNUM, 52)),
        ("pcsk_", "pc" + "sk_" + _run(_ALNUM + "_", 30)),
        ("e2b_", "e2" + "b_" + _run(_HEX, 40)),
        ("tgp_v1_", "tgp" + "_v1_" + _run(_WORD, 40)),
        ("lsv2_(?:pt|sk)_", "ls" + "v2_pt_" + _run(_HEX, 32) + "_" + _run(_HEX, 10)),
        ("tvly-(?:dev-|prod-)?", "tv" + "ly-dev-" + _run(_WORD, 28)),
        ("xai-", "xa" + "i-" + _run(_ALNUM, 70)),
        ("pplx-", "pp" + "lx-" + _run(_ALNUM, 50)),
        ("csk-", "cs" + "k-" + _run(_ALNUM, 40)),
        ("nvapi-", "nv" + "api-" + _run(_WORD, 70)),
        ("r8_", "r" + "8_" + _run(_ALNUM, 40)),
        ("fc-", "f" + "c-" + _run(_HEX, 32)),
        ("app-", "ap" + "p-" + _run(_ALNUM, 24)),
        ("sk_[a-f0-9]{40,}", "sk" + "_" + _run(_HEX, 44)),
        ("npm_", "np" + "m_" + _run(_ALNUM, 40)),
        ("pypi-AgE", "py" + "pi-AgE" + _run(_WORD, 56)),
        ("do[opr]_v1_", "do" + "p_v1_" + _run(_HEX, 64)),
        ("(?:sk|rk)_(?:live|test)_", "rk" + "_live_" + _run(_ALNUM, 24)),
        ("whsec_", "wh" + "sec_" + _run(_ALNUM, 32)),
        ("SG\\.", "S" + "G." + _run(_WORD, 22) + "." + _run(_WORD, 22)),
        ("dapi", "da" + "pi" + _run(_HEX, 32)),
        ("shp(?:at|ca|pa|ss)_", "sh" + "pat_" + _run(_HEX, 32)),
        ("ATATT3", "ATA" + "TT3" + _run(_WORD, 50)),
        ("lin_api_", "lin" + "_api_" + _run(_ALNUM, 40)),
        ("ntn_", "nt" + "n_" + _run(_ALNUM, 46)),
        ("PMAK-", "PM" + "AK-" + _run(_HEX, 24) + "-" + _run(_HEX, 34)),
        ("dp\\.(?:pt|st|sa|ct|scim|audit)\\.", "d" + "p.pt." + _run(_ALNUM, 46)),
        ("sbp_", "sb" + "p_" + _run(_HEX, 40)),
        ("sb_secret_", "sb" + "_secret_" + _run(_WORD, 30)),
        ("glsa_", "gl" + "sa_" + _run(_ALNUM, 32) + "_" + _run(_HEX, 8)),
        ("glc_", "gl" + "c_" + _run(_ALNUM + "+/", 40)),
        ("sntry[su]_", "sn" + "trys_" + _run(_ALNUM + "+=_-", 40)),
        ("hv[sbr]\\.", "h" + "vs." + _run(_WORD, 30)),
        ("fw_", "fw_" + "aB3xY7" * 4),
        ("[A-Za-z0-9]{14}\\.atlasv1\\.", _run(_ALNUM, 14) + "." + "atl" + "asv1." + _run(_WORD, 70)),
    ]


def _backstop_alternatives() -> list[str]:
    alternatives: list[str] = []
    for pattern in (redaction_formats._SPECIFIC_TOKEN, redaction_formats._GENERIC_TOKEN):
        depth, current, in_class, index = 0, "", False, 0
        while index < len(pattern):
            char = pattern[index]
            if char == "\\":
                current += pattern[index : index + 2]
                index += 2
                continue
            if in_class:
                in_class = char != "]"
            elif char == "[":
                in_class = True
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
            elif char == "|" and depth == 0:
                alternatives.append(current)
                current = ""
                index += 1
                continue
            current += char
            index += 1
        alternatives.append(current)
    return alternatives


def test_the_token_table_covers_every_alternative_of_the_backstop():
    alternatives = _backstop_alternatives()
    samples = _token_samples()
    assert len(samples) == len(alternatives), "a token format was added or removed: update the samples"
    for (prefix, sample), alternative in zip(samples, alternatives, strict=True):
        assert alternative.startswith(prefix), (prefix, alternative)
        assert re.fullmatch(alternative, sample), f"the sample for {prefix} does not match its format"


@pytest.mark.parametrize("prefix,sample", _token_samples(), ids=[prefix for prefix, _ in _token_samples()])
def test_every_provider_token_format_is_withheld(prefix, sample):
    for text in (f"key = {sample}", f"see {sample} here", f"Authorization failed for {sample}."):
        redacted = sanitize_text(text)
        assert sample not in redacted, text
        assert REDACTED in redacted, text
    # The token is cut at its own boundary: the surrounding words stay readable.
    assert sanitize_text(f"see {sample} here") == f"see {REDACTED} here"
