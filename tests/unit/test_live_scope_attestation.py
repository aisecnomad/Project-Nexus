"""Live collection scope attestation: when two live scans may resolve findings.

A live connector attests its scope only from what its provider reported in the
run: the principal (account, tenant, projects, subscriptions), the requested
options, the partitions and the outcome of every enumeration. Detail calls,
counts and discovered resources never enter the fingerprint. Transports are
stubbed; nothing leaves the process.
"""

from __future__ import annotations

import json
import sys
import threading
import time
from collections import Counter
from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar

import jwt as pyjwt
import pytest
from click.testing import CliRunner

import shadowscan.engine as engine_module
from shadowscan.cli import main
from shadowscan.comparison import IDENTITY_KEY_ENV, build_collection_scope, compare_reports
from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.connectors import get_connector_class
from shadowscan.connectors.base import (
    LIVE_SCOPE_SCHEMA,
    SCOPE_OUTCOMES,
    BaseConnector,
    ConnectorContext,
)
from shadowscan.connectors.cloud.azure import _arm_operation
from shadowscan.connectors.cloud.gcp import GcpConnector
from shadowscan.connectors.common import failure_outcome
from shadowscan.connectors.identity.entra import _graph_operation
from shadowscan.engine import Engine, _JobState, _ScopeLedger
from shadowscan.models import Finding, ScanResult, ScanStats, Surface
from shadowscan.signatures import SignatureIndex
from shadowscan.utils.http import HttpClient, HttpError
from shadowscan.utils.redaction import _sensitive_key

ACCOUNT = "123456789012"
OTHER_ACCOUNT = "210987654321"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/ShadowScanReader"
TENANT = "11111111-2222-3333-4444-555555555555"
OTHER_TENANT = "99999999-8888-7777-6666-555555555555"
SUBSCRIPTION = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
CLIENT_SECRET = "synthetic-entra-client-secret-value"
GRAPH_TOKEN = "synthetic-graph-access-token-value"
ARM_TOKEN = "synthetic-arm-access-token-value"
GCP_TOKEN = "synthetic-gcp-access-token-value"
SESSION_TOKEN = "synthetic-assumed-role-session-value"
_TEST_HMAC_KEY = "live-scope-test-hmac-key-0123456789abcdef"


def _invoke(tmp_path: Path, baseline: dict, current: dict, *extra: str):
    before, after = tmp_path / "before.json", tmp_path / "after.json"
    before.write_text(json.dumps(baseline))
    after.write_text(json.dumps(current))
    return CliRunner().invoke(main, ["diff", str(before), str(after), *extra])


def _record(**overrides: Any) -> dict[str, Any]:
    """A complete live scope record as ConnectorContext.scope_record returns it."""
    record: dict[str, Any] = {
        "schema": LIVE_SCOPE_SCHEMA,
        "principal": {"provider": "aws", "kind": "account", "id": ACCOUNT, "verified_by": "sts"},
        "requested": {"regions": ["us-east-1"], "services": ["qbusiness"]},
        "partitions": {"regions": ["us-east-1"]},
        "operations": [
            {
                "service": "qbusiness",
                "operation": "list_applications",
                "partition": "us-east-1",
                "outcome": "ok",
            }
        ],
        "details": [],
        "complete": True,
    }
    record.update(overrides)
    return record


def _scope(index, record: Any, name: str = "cloud.aws", **config: Any) -> dict[str, Any]:
    spec = ConnectorSpec(name, config)
    return build_collection_scope(ScanConfig(connectors=[spec]), index, [spec], live_records=[record])


# ------------------------------------------------------------- the recorder
def test_context_keeps_the_most_severe_outcome_and_only_allowlisted_options(index, monkeypatch):
    monkeypatch.setenv("SHADOWSCAN_TEST_TENANT", TENANT)
    ctx = ConnectorContext(config={"client_secret": CLIENT_SECRET, "max": 3}, index=index)
    ctx.stats = ScanStats(connector="test", started_at="2026-10-10")
    assert ctx.get("tenant_id", env="SHADOWSCAN_TEST_TENANT") == TENANT
    ctx.get("client_secret")
    ctx.get("max")
    ctx.get("unset", 7)
    ctx.attest_principal("entra", "tenant", TENANT, "graph")
    ctx.attest_partition("regions", ["b", "a", "b"])
    for outcome in ("ok", "denied", "ok", "truncated"):
        ctx.attest_operation("graph", "/v1.0/applications", None, outcome)
    ctx.attest_operation("graph", "/v1.0/x/{id}", None, "ok", enumeration=False)
    ctx.attest_operation("graph", "/v1.0/x/{id}", None, "not-an-outcome", enumeration=False)
    record = ctx.scope_record({"tenant_id", "max", "unset", "never-read"})
    assert record["requested"] == {"max": 3, "tenant_id": TENANT, "unset": 7}
    assert CLIENT_SECRET not in json.dumps(record)
    assert record["partitions"] == {"regions": ["a", "b"]}
    assert record["operations"] == [
        {"service": "graph", "operation": "/v1.0/applications", "partition": None, "outcome": "denied"}
    ]
    assert record["details"] == [{"service": "graph", "operation": "/v1.0/x/{id}", "outcome": "failed"}]
    assert record["principal"]["id"] == TENANT and record["complete"] is False


def test_scope_record_is_complete_only_for_a_complete_run_with_successful_listings(index):
    ctx = ConnectorContext(index=index)
    ctx.attest_operation("s", "list", "p", "ok")
    assert ctx.scope_record(())["complete"] is False  # no stats: completion unknown
    ctx.stats = ScanStats(connector="test", started_at="2026-10-10")
    assert ctx.scope_record(())["complete"] is True
    ctx.warn("informational", incomplete=False)
    assert ctx.scope_record(())["complete"] is True
    ctx.warn("a coverage gap")
    assert ctx.scope_record(())["complete"] is False


def test_two_principals_in_one_run_attest_none(index):
    ctx = ConnectorContext(index=index)
    ctx.attest_principal("aws", "account", ACCOUNT, "sts")
    ctx.attest_principal("aws", "account", ACCOUNT, "sts")
    assert ctx.scope_record(())["principal"]["id"] == ACCOUNT
    ctx.attest_principal("aws", "account", OTHER_ACCOUNT, "sts")
    assert ctx.scope_record(())["principal"] is None


def test_outcomes_are_ordered_by_severity():
    assert SCOPE_OUTCOMES[0] == "ok" and set(SCOPE_OUTCOMES) == {
        "ok",
        "truncated",
        "unavailable",
        "throttled",
        "failed",
        "denied",
    }


@pytest.mark.parametrize(
    "exc,outcome",
    [
        (HttpError(401, "https://graph.microsoft.com"), "denied"),
        (HttpError(403, "https://graph.microsoft.com"), "denied"),
        (HttpError(429, "https://graph.microsoft.com"), "throttled"),
        (HttpError(404, "https://graph.microsoft.com"), "unavailable"),
        (HttpError(500, "https://graph.microsoft.com"), "failed"),
        (RuntimeError("Pagination limit reached; collection incomplete"), "truncated"),
        (RuntimeError("Repeated pagination link; collection incomplete"), "failed"),
        (ValueError("Invalid JSON response"), "failed"),
    ],
)
def test_http_failures_map_to_scope_outcomes(exc, outcome):
    assert failure_outcome(exc) == outcome


def test_scope_ledger_drops_cancelled_timed_out_and_repeated_reports():
    ledger = _ScopeLedger()
    ledger.record(_JobState(), 1, {"n": 1})
    cancelled = _JobState()
    cancelled.cancelled.set()
    ledger.record(cancelled, 2, {"n": 2})
    ledger.record(_JobState(), 3, {"n": 3})
    ledger.record(_JobState(), 4, {"n": 4})
    ledger.record(_JobState(), 4, {"n": 5})
    assert ledger.records(timed_out={3}) == {1: {"n": 1}}


# ------------------------------------------------------------- comparison
def test_live_scope_without_collection_records_is_not_attested(index):
    scope = _scope(index, None)
    spec = ConnectorSpec("cloud.aws", {"regions": ["us-east-1"]})
    before_collection = build_collection_scope(ScanConfig(connectors=[spec]), index, [spec])
    assert before_collection == {
        "schema": "shadowscan.collection-scope/v1",
        "comparable": False,
        "reason": "live collection scope is not attested",
    }
    # After collection, a missing record of an attesting connector means its job did not report.
    assert scope["reason"] == "live collection was not verified or was incomplete"


def test_complete_record_attests_and_ignores_details_and_verification_notes(index):
    attested = _scope(index, _record())
    assert attested["comparable"] is True and len(attested["fingerprint"]) == 64
    busier = _record(
        details=[{"service": "qbusiness", "operation": "get_application", "outcome": "ok"}],
        principal={"provider": "aws", "kind": "account", "id": ACCOUNT, "verified_by": "another note"},
    )
    assert _scope(index, busier)["fingerprint"] == attested["fingerprint"]
    assert attested["live"] == [
        {"connector": "cloud.aws", "label": None, **{k: v for k, v in _record().items() if k != "schema"}}
    ]


@pytest.mark.parametrize(
    "change",
    [
        {"principal": {"provider": "aws", "kind": "account", "id": OTHER_ACCOUNT, "verified_by": "sts"}},
        {"requested": {"regions": ["us-east-1"], "services": ["qbusiness"], "role_arn": ROLE}},
        {"partitions": {"regions": ["eu-west-1", "us-east-1"]}},
        {
            "operations": [
                {
                    "service": "qbusiness",
                    "operation": "list_applications",
                    "partition": "us-east-1",
                    "outcome": "ok",
                },
                {"service": "lex", "operation": "list_bots", "partition": "us-east-1", "outcome": "ok"},
            ]
        },
    ],
)
def test_principal_options_partitions_and_enumerations_change_the_scope(index, change):
    assert _scope(index, _record(**change))["fingerprint"] != _scope(index, _record())["fingerprint"]


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"complete": False}, "live collection was not verified or was incomplete"),
        (
            {
                "operations": [
                    {
                        "service": "qbusiness",
                        "operation": "list_applications",
                        "partition": "us-east-1",
                        "outcome": "denied",
                    }
                ]
            },
            "live collection was not verified or was incomplete",
        ),
        (
            {"details": [{"service": "qbusiness", "operation": "get_application", "outcome": "throttled"}]},
            "live collection was not verified or was incomplete",
        ),
        ({"operations": []}, "live collection was not verified or was incomplete"),
        ({"operations": [{"service": 1, "operation": "x", "partition": None, "outcome": "ok"}]}, None),
        ({"operations": [{"service": "s", "operation": "x", "partition": 3, "outcome": "ok"}]}, None),
        ({"operations": ["not a record"]}, None),
        ({"schema": "shadowscan.live-scope/v0"}, None),
        ({"requested": []}, None),
        ({"principal": None}, "live principal could not be verified"),
        (
            {"principal": {"provider": "aws", "kind": "account", "id": ""}},
            "live principal could not be verified",
        ),
    ],
)
def test_incomplete_or_malformed_records_are_not_attested(index, change, reason):
    scope = _scope(index, _record(**change))
    assert scope["comparable"] is False and "fingerprint" not in scope
    assert scope["reason"] == (reason or "live collection was not verified or was incomplete")


@pytest.mark.parametrize(
    "change",
    [
        {"requested": {"client_secret": "x"}},
        {"requested": {"regions": ["credential:sha256:" + "a" * 64]}},
        {"partitions": {"regions": ["sk-proj-" + "A1b2C3d4" * 5]}},
    ],
)
def test_private_values_in_a_record_fail_closed(index, change):
    scope = _scope(index, _record(**change))
    assert scope["reason"] == "configuration contains private comparison values"
    assert scope["live"] == [{"connector": "cloud.aws", "label": None, "complete": False}]


def test_records_of_unattesting_and_third_party_connectors_are_not_attested(index):
    # A live built-in connector that does not attest, with or without a (foreign) record.
    assert _scope(index, None, "code.github", org="acme")["reason"] == "live collection scope is not attested"
    plugin = ConnectorSpec("platform.custom")
    scope = build_collection_scope(ScanConfig(connectors=[plugin]), index, [plugin], live_records=[_record()])
    assert scope["reason"] == "third-party connector scope is not attested"


def test_offline_exports_keep_their_scope_when_live_records_are_supplied(index, tmp_path):
    spec = ConnectorSpec("cloud.aws", {"input": str(tmp_path / "aws.jsonl")})
    config = ScanConfig(connectors=[spec])
    plain = build_collection_scope(config, index, [spec])
    assert build_collection_scope(config, index, [spec], live_records=[None]) == plain


# ------------------------------------------------------------- cloud.aws
class _AwsError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(f"An error occurred ({code}) when calling the operation")
        self.response = {"Error": {"Code": code}}


class _Page(dict):
    """An SDK list page: every item key the connector asks for is present (empty unless set)."""

    def __missing__(self, key: str) -> list[Any]:
        return []

    def __contains__(self, key: object) -> bool:
        return key not in ("error", "Error")


class _AwsCloud:
    """A fake AWS account: list pages and errors by operation, detail calls by name."""

    def __init__(
        self,
        pages: dict[str, list[dict[str, Any]]] | None = None,
        details: dict[str, dict[str, Any]] | None = None,
        errors: dict[str, Exception] | None = None,
        account: str = ACCOUNT,
        delay: float = 0.0,
    ) -> None:
        self.pages = pages or {}
        self.details = details or {}
        self.errors = errors or {}
        self.account = account
        self.delay = delay
        self.calls: list[tuple[str, str | None, str]] = []

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cloud = self

        class Sts:
            def get_caller_identity(self) -> dict[str, str]:
                return {"Account": cloud.account}

            def assume_role(self, **kwargs: Any) -> dict[str, Any]:
                return {
                    "Credentials": {
                        "AccessKeyId": "synthetic-access-key-id",
                        "SecretAccessKey": "synthetic-secret",
                        "SessionToken": SESSION_TOKEN,
                    }
                }

        class Client:
            def __init__(self, service: str, region: str | None) -> None:
                self.service, self.region = service, region

            def get_paginator(self, op: str) -> Any:
                client = self

                class Paginator:
                    def paginate(self, **kwargs: Any) -> Any:
                        cloud.calls.append((client.service, client.region, op))
                        if cloud.delay:
                            time.sleep(cloud.delay)
                        if op in cloud.errors:
                            raise cloud.errors[op]
                        for page in cloud.pages.get(op, [{}]):
                            yield _Page(page)

                return Paginator()

            def __getattr__(self, op: str) -> Any:
                def call(**kwargs: Any) -> dict[str, Any]:
                    cloud.calls.append((self.service, self.region, op))
                    if op in cloud.errors:
                        raise cloud.errors[op]
                    detail = cloud.details.get(op, {})
                    return detail(**kwargs) if callable(detail) else detail

                call.__name__ = op
                return call

        class Session:
            def client(self, service: str, region_name: str | None = None, config: Any = None) -> Any:
                return Sts() if service == "sts" else Client(service, region_name)

        session = Session()
        monkeypatch.setitem(sys.modules, "boto3", SimpleNamespace(Session=lambda **kwargs: session))


def _app(name: str) -> dict[str, Any]:
    return {"applicationId": name, "displayName": name, "status": "ACTIVE"}


def _aws_run(index, monkeypatch, cloud: _AwsCloud, **config: Any) -> dict[str, Any]:
    pytest.importorskip("botocore")
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    cloud.install(monkeypatch)
    settings = {"regions": ["us-east-1"], "services": ["qbusiness", "stepfunctions"], **config}
    spec = ConnectorSpec("cloud.aws", settings)
    return Engine(ScanConfig(connectors=[spec]), index=index).run().to_dict()


def _apps(*names: str, pages: int = 1) -> dict[str, list[dict[str, Any]]]:
    items = [_app(name) for name in names]
    split = [items[i::pages] for i in range(pages)]
    return {"list_applications": [{"applications": page} for page in split]}


def test_identical_live_aws_scans_compare_and_extra_pages_or_details_keep_the_scope(
    index, monkeypatch, tmp_path
):
    machine = {"name": "agent-flow", "stateMachineArn": f"arn:aws:states:us-east-1:{ACCOUNT}:stateMachine:a"}
    plain = {"name": "etl", "stateMachineArn": f"arn:aws:states:us-east-1:{ACCOUNT}:stateMachine:etl"}
    agentic = '{"States": {"Ask": {"Resource": "arn:aws:states:::bedrock:invokeModel"}}}'

    def flow(**request: Any) -> dict[str, Any]:
        bedrock = request["stateMachineArn"] == machine["stateMachineArn"]
        return {"definition": agentic if bedrock else '{"States": {}}'}

    first = _AwsCloud(
        pages={**_apps("helper"), "list_state_machines": [{"stateMachines": [machine]}]},
        details={"describe_state_machine": flow},
    )
    baseline = _aws_run(index, monkeypatch, first)
    assert baseline["summary"]["complete"] is True, baseline["stats"]
    scope = baseline["collection_scope"]
    assert scope["comparable"] is True
    (live,) = scope["live"]
    assert live["principal"] == {
        "provider": "aws",
        "kind": "account",
        "id": ACCOUNT,
        "verified_by": "sts:GetCallerIdentity",
    }
    assert live["partitions"] == {"regions": ["us-east-1"]}
    assert {(op["service"], op["operation"], op["partition"]) for op in live["operations"]} == {
        ("qbusiness", "list_applications", "us-east-1"),
        ("stepfunctions", "list_state_machines", "us-east-1"),
    }
    assert live["details"] == [
        {"service": "stepfunctions", "operation": "describe_state_machine", "outcome": "ok"}
    ]
    # More pages and another detail call (a state machine without AI) find the same agents.
    second = _AwsCloud(
        pages={
            **_apps("helper", pages=2),
            "list_state_machines": [{"stateMachines": [machine]}, {"stateMachines": [plain]}],
        },
        details={"describe_state_machine": flow},
    )
    current = _aws_run(index, monkeypatch, second)
    assert current["collection_scope"]["fingerprint"] == scope["fingerprint"]
    result = _invoke(tmp_path, baseline, current, "--json", "--fail-on-new")
    assert result.exit_code == 0, result.output
    comparison = json.loads(result.output)
    assert comparison["comparable"] is True and comparison["new"] == comparison["resolved"] == []


def test_a_new_live_agent_fails_the_gate_and_a_removed_one_resolves(index, monkeypatch, tmp_path):
    baseline = _aws_run(index, monkeypatch, _AwsCloud(pages=_apps("helper", "retired")))
    current = _aws_run(index, monkeypatch, _AwsCloud(pages=_apps("helper", "newcomer")))
    result = _invoke(tmp_path, baseline, current, "--json", "--fail-on-new")
    assert result.exit_code == 2, result.output
    comparison = json.loads(result.output)
    assert comparison["comparable"] is True
    assert [f["title"] for f in comparison["new"]] == ["Amazon Q Business application: newcomer"]
    assert [f["title"] for f in comparison["resolved"]] == ["Amazon Q Business application: retired"]


@pytest.mark.parametrize(
    "config,account",
    [
        ({"regions": ["us-east-1", "eu-west-1"]}, ACCOUNT),
        ({"role_arn": ROLE}, ACCOUNT),
        ({"services": ["qbusiness"]}, ACCOUNT),
        ({}, OTHER_ACCOUNT),
    ],
)
def test_changed_account_regions_role_or_services_make_aws_scans_incomparable(
    index, monkeypatch, tmp_path, config, account
):
    baseline = _aws_run(index, monkeypatch, _AwsCloud(pages=_apps("helper")))
    current = _aws_run(index, monkeypatch, _AwsCloud(pages=_apps("helper"), account=account), **config)
    assert current["summary"]["complete"] is True, current["stats"]
    assert current["collection_scope"]["comparable"] is True
    assert current["collection_scope"]["fingerprint"] != baseline["collection_scope"]["fingerprint"]
    result = _invoke(tmp_path, baseline, current)
    assert result.exit_code == 3 and "scope differs" in result.output


@pytest.mark.parametrize(
    "code,outcome", [("AccessDeniedException", "denied"), ("ThrottlingException", "throttled")]
)
def test_denied_or_throttled_aws_enumeration_is_unattested_and_incomplete(
    index, monkeypatch, tmp_path, code, outcome
):
    baseline = _aws_run(index, monkeypatch, _AwsCloud(pages=_apps("helper")))
    current = _aws_run(index, monkeypatch, _AwsCloud(errors={"list_applications": _AwsError(code)}))
    assert current["summary"]["complete"] is False
    scope = current["collection_scope"]
    assert scope["comparable"] is False
    assert scope["reason"] == "live collection was not verified or was incomplete"
    (live,) = scope["live"]
    assert live["complete"] is False
    assert {
        "service": "qbusiness",
        "operation": "list_applications",
        "partition": "us-east-1",
        "outcome": outcome,
    } in live["operations"]
    result = _invoke(tmp_path, baseline, current, "--json")
    assert result.exit_code == 3
    assert [f["title"] for f in json.loads(result.output)["unknown"]] == [
        "Amazon Q Business application: helper"
    ]


def test_aws_page_limit_truncates_the_attested_scope(index, monkeypatch, tmp_path):
    baseline = _aws_run(index, monkeypatch, _AwsCloud(pages=_apps("helper")))
    monkeypatch.setattr("shadowscan.connectors.cloud.aws.MAX_LIST_PAGES", 1)
    pages = {
        "list_applications": [{"applications": [_app("helper")], "NextToken": "t1"}, {"applications": []}]
    }
    current = _aws_run(index, monkeypatch, _AwsCloud(pages=pages))
    (live,) = current["collection_scope"]["live"]
    assert {
        "service": "qbusiness",
        "operation": "list_applications",
        "partition": "us-east-1",
        "outcome": "truncated",
    } in live["operations"]
    assert _invoke(tmp_path, baseline, current).exit_code == 3


def test_aws_lambda_cap_records_truncation(index, monkeypatch):
    functions = [
        {"FunctionName": f"f{n}", "FunctionArn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:f{n}"}
        for n in range(3)
    ]
    cloud = _AwsCloud(
        pages={"list_functions": [{"Functions": functions}]}, details={"list_tags": {"Tags": {}}}
    )
    report = _aws_run(index, monkeypatch, cloud, services=["lambda"], max_lambda=2)
    (live,) = report["collection_scope"]["live"]
    assert {
        "service": "lambda",
        "operation": "list_functions",
        "partition": "us-east-1",
        "outcome": "truncated",
    } in live["operations"]
    assert {"service": "lambda", "operation": "list_tags", "outcome": "ok"} in live["details"]
    assert report["collection_scope"]["comparable"] is False


def test_aws_registry_listings_record_enumerations_and_configured_registries(index, monkeypatch):
    arn = f"arn:aws:agent-registry:us-east-1:{OTHER_ACCOUNT}:registry/SharedRegistry01"
    cloud = _AwsCloud(pages={"list_discoverable_registry_records": [{"registryRecords": []}]})
    report = _aws_run(index, monkeypatch, cloud, services=["registry"], registry_arns=[arn])
    assert report["summary"]["complete"] is True, report["stats"]
    (live,) = report["collection_scope"]["live"]
    assert {(op["service"], op["operation"], op["partition"]) for op in live["operations"]} == {
        ("registry", "list_registries", "us-east-1"),
        ("registry", "list_discoverable_registry_records", arn),
    }
    assert live["requested"]["registry_arns"] == [arn]
    assert report["collection_scope"]["comparable"] is True


def test_failed_sts_authentication_is_not_attested(index, monkeypatch):
    report = _aws_run(index, monkeypatch, _AwsCloud(account="not-an-account"))
    assert report["collection_scope"]["reason"] == "live collection was not verified or was incomplete"
    (live,) = report["collection_scope"]["live"]
    assert live["principal"] is None and live["complete"] is False


def test_timed_out_live_job_is_never_attested(index, monkeypatch):
    pytest.importorskip("botocore")
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    _AwsCloud(pages=_apps("helper"), delay=1.0).install(monkeypatch)
    spec = ConnectorSpec("cloud.aws", {"regions": ["us-east-1"], "services": ["qbusiness"]})
    engine = Engine(ScanConfig(connectors=[spec], connector_timeout_seconds=0.2), index=index)
    result = engine.run()
    assert not result.complete
    assert result.collection_scope is not None
    assert result.collection_scope["reason"] == "live collection was not verified or was incomplete"
    assert "live" not in result.collection_scope
    deadline = time.monotonic() + 5
    while engine._abandoned_futures and not all(f.done() for f in engine._abandoned_futures):
        if time.monotonic() > deadline:
            break
        time.sleep(0.05)


def test_plugins_never_attest_even_when_they_record_a_scope(index, monkeypatch):
    class Attesting(BaseConnector):
        name: ClassVar[str] = "platform.attesting"
        surface: ClassVar[Surface] = Surface.LOWCODE
        description: ClassVar[str] = "claims an attested scope"
        attests_live_scope: ClassVar[bool] = True
        scope_options: ClassVar[frozenset[str]] = frozenset({"tenant"})

        def collect(self) -> list[dict[str, Any]]:
            self.ctx.attest_principal("x", "tenant", "t", "self")
            self.ctx.attest_operation("x", "list", None, "ok")
            return []

        def analyze(self, records: Any) -> list[Finding]:
            return []

    monkeypatch.setattr(engine_module, "get_connector_class", lambda name, **kwargs: Attesting)
    spec = ConnectorSpec("platform.attesting", {"tenant": "t"})
    result = Engine(ScanConfig(connectors=[spec], plugins=["platform.attesting"]), SignatureIndex([])).run()
    assert result.complete
    assert result.collection_scope is not None
    assert result.collection_scope["reason"] == "third-party connector scope is not attested"
    assert "live" not in result.collection_scope


# ------------------------------------------------------------- identity.entra
def _graph(
    monkeypatch, *, organization: Any, pages: dict[str, list[dict[str, Any]]] | None = None
) -> list[str]:
    calls: list[str] = []
    listings = pages or {}

    def post(self, url, **kwargs):
        calls.append(f"POST {url}")
        return SimpleNamespace()

    def read_json_response(self, response, **kwargs):
        return {"access_token": GRAPH_TOKEN}

    def get_json(self, path, **kwargs):
        calls.append(f"GET {path}")
        value = organization if path == "/organization" else None
        if isinstance(value, Exception):
            raise value
        return value

    def paginate_odata(self, path, params=None, max_pages=1000):
        calls.append(f"LIST {path}")
        yield from listings.get(path, [])

    monkeypatch.setattr(HttpClient, "post", post)
    monkeypatch.setattr(HttpClient, "read_json_response", read_json_response)
    monkeypatch.setattr(HttpClient, "get_json", get_json)
    monkeypatch.setattr(HttpClient, "paginate_odata", paginate_odata)
    return calls


def _organization(tenant: str = TENANT) -> dict[str, Any]:
    return {"value": [{"id": tenant.upper()}]}


def _entra_run(index, **config: Any) -> dict[str, Any]:
    settings = {"tenant_id": TENANT, "client_id": "client", "client_secret": CLIENT_SECRET, **config}
    spec = ConnectorSpec("identity.entra", settings)
    return Engine(ScanConfig(connectors=[spec]), index=index).run().to_dict()


def test_entra_attests_the_tenant_the_graph_reports(index, monkeypatch, tmp_path):
    calls = _graph(monkeypatch, organization=_organization())
    baseline = _entra_run(index)
    assert baseline["summary"]["complete"] is True, baseline["stats"]
    assert "GET /organization" in calls
    scope = baseline["collection_scope"]
    assert scope["comparable"] is True
    (live,) = scope["live"]
    assert live["principal"] == {
        "provider": "entra",
        "kind": "tenant",
        "id": TENANT,
        "verified_by": "graph:GET /organization",
    }
    assert {op["operation"] for op in live["operations"]} == {
        "/v1.0/servicePrincipals",
        "/v1.0/oauth2PermissionGrants",
        "/v1.0/applications",
    }
    assert live["requested"]["tenant_id"] == TENANT and "client_secret" not in live["requested"]
    current = _entra_run(index)
    assert current["collection_scope"]["fingerprint"] == scope["fingerprint"]
    assert _invoke(tmp_path, baseline, current).exit_code == 0


@pytest.mark.parametrize(
    "organization",
    [HttpError(403, "https://graph.microsoft.com"), {"value": []}, {"value": [{"id": "x"}]}, None],
)
def test_unverified_entra_tenant_completes_but_is_not_comparable(index, monkeypatch, organization):
    _graph(monkeypatch, organization=organization)
    report = _entra_run(index)
    # Reading the organization is needed only for drift: the scan itself stays complete.
    assert report["summary"]["complete"] is True, report["stats"]
    assert any(
        "tenant" in warning and "not attested" in warning
        for s in report["stats"]
        for warning in s["warnings"]
    )
    assert report["collection_scope"]["reason"] == "live principal could not be verified"


def test_entra_tenant_other_than_tenant_id_stops_the_scan(index, monkeypatch):
    calls = _graph(monkeypatch, organization=_organization(OTHER_TENANT))
    report = _entra_run(index)
    (stats,) = [s for s in report["stats"] if s["connector"] == "identity.entra"]
    assert stats["skipped"] and "does not match tenant_id" in stats["skip_reason"]
    assert not any(call.startswith("LIST") for call in calls)


def test_entra_domain_tenant_id_attests_the_reported_tenant(index, monkeypatch):
    _graph(monkeypatch, organization=_organization())
    report = _entra_run(index, tenant_id="contoso.onmicrosoft.com")
    (live,) = report["collection_scope"]["live"]
    assert live["principal"]["id"] == TENANT and report["collection_scope"]["comparable"] is True


def _delegated_run(index, monkeypatch, scopes: str = "User.Read Application.Read.All") -> dict[str, Any]:
    token = pyjwt.encode(
        {"tid": TENANT, "scp": scopes, "exp": int(time.time()) + 3600},
        _TEST_HMAC_KEY,
        algorithm="HS256",
    )
    monkeypatch.setenv("GRAPH_DELEGATED_TOKEN", token)
    spec = ConnectorSpec("identity.entra", {"tenant_id": TENANT, "auth_mode": "delegated"})
    report = Engine(ScanConfig(connectors=[spec]), index=index).run().to_dict()
    assert token not in json.dumps(report)
    return report


def test_delegated_entra_scans_are_never_attested(index, monkeypatch):
    """A delegated listing shows what the signed-in user may see: the tenant alone attests nothing."""
    _graph(monkeypatch, organization=_organization())
    app_only = _entra_run(index)
    assert app_only["collection_scope"]["comparable"] is True
    delegated = _delegated_run(index, monkeypatch)
    scope = delegated["collection_scope"]
    assert delegated["summary"]["complete"] is True
    assert scope["comparable"] is False and scope["reason"] == "live principal could not be verified"
    (live,) = scope["live"]
    assert live["principal"] is None and live["requested"]["auth_mode"] == "delegated"
    (stats,) = [s for s in delegated["stats"] if s["connector"] == "identity.entra"]
    assert any("scoped to the signed-in user" in warning for warning in stats["warnings"])


def test_delegated_scan_by_a_user_who_sees_less_never_resolves_findings(index, monkeypatch):
    fixture = Path(__file__).parents[1] / "fixtures" / "identity" / "entra_graph.json"
    names = {"procurement-agent-svc", "aks-agent-runner"}
    principals = [
        {key: value for key, value in record.items() if key != "_kind"}
        for record in json.loads(fixture.read_text(encoding="utf-8"))
        if record.get("_kind") == "servicePrincipal" and record.get("displayName") in names
    ]
    assert len(principals) == 2
    _graph(monkeypatch, organization=_organization(), pages={"/servicePrincipals": principals})
    administrator = _delegated_run(index, monkeypatch)
    _graph(monkeypatch, organization=_organization(), pages={"/servicePrincipals": principals[:1]})
    restricted = _delegated_run(index, monkeypatch)
    assert len(restricted["findings"]) < len(administrator["findings"])
    comparison = compare_reports(administrator, restricted)
    assert comparison["comparable"] is False and comparison["resolved"] == []
    assert comparison["unknown"]


def test_delegated_scan_of_another_tenant_still_stops(index, monkeypatch):
    calls = _graph(monkeypatch, organization=_organization(OTHER_TENANT))
    report = _delegated_run(index, monkeypatch)
    (stats,) = [s for s in report["stats"] if s["connector"] == "identity.entra"]
    assert stats["skipped"] and "does not match tenant_id" in stats["skip_reason"]
    assert not any(call.startswith("LIST") for call in calls)


def test_entra_app_role_lookup_cap_is_a_truncated_detail(index, monkeypatch):
    principals = [{"id": f"sp-{n}", "appId": f"app-{n}", "displayName": f"sp {n}"} for n in range(2)]
    _graph(monkeypatch, organization=_organization(), pages={"/servicePrincipals": principals})
    report = _entra_run(index, max_app_role_lookups=1)
    (live,) = report["collection_scope"]["live"]
    assert {
        "service": "graph",
        "operation": "/v1.0/servicePrincipals/{id}/appRoleAssignments",
        "outcome": "truncated",
    } in live["details"]
    assert report["collection_scope"]["comparable"] is False


def test_graph_operations_drop_the_host_and_keep_the_version():
    assert _graph_operation("/applications") == "/v1.0/applications"
    assert _graph_operation("https://graph.microsoft.com/beta/copilot/x") == "/beta/copilot/x"
    assert _graph_operation("https://graph.microsoft.com/v1.0/copilot/x") == "/v1.0/copilot/x"


# ------------------------------------------------------------- cloud.gcp
class _GoogleApis:
    def __init__(
        self,
        projects: list[str] | None = None,
        accounts: int = 0,
        failures: dict[str, Exception] | None = None,
    ) -> None:
        self.projects = projects or []
        self.accounts = accounts
        self.failures = failures or {}

    def get_json(self, url: str, params: Any = None, **kwargs: Any) -> Any:
        for suffix, failure in self.failures.items():
            if url.endswith(suffix):
                raise failure
        if url.endswith("/v1/projects"):
            return {"projects": [{"projectId": p, "projectNumber": "1234"} for p in self.projects]}
        if url.endswith("/serviceAccounts"):
            project = url.split("/projects/")[1].split("/")[0]
            return {
                "accounts": [
                    {"name": f"projects/{project}/serviceAccounts/sa{n}@{project}.iam.gserviceaccount.com"}
                    for n in range(self.accounts)
                ]
            }
        if url.endswith("/keys"):
            return {"keys": []}
        return {"services": []}

    def post_json(self, url: str, **kwargs: Any) -> Any:
        return {"version": 3, "bindings": []}


class _VertexApis(_GoogleApis):
    """Vertex AI enabled in every project, with one Agent Engine each, so each project has a finding."""

    def get_json(self, url: str, params: Any = None, **kwargs: Any) -> Any:
        if url.endswith("/services"):
            return {"services": [{"config": {"name": "aiplatform.googleapis.com"}}]}
        if url.endswith("/reasoningEngines"):
            project = url.split("/projects/")[1].split("/")[0]
            name = f"projects/{project}/locations/us-central1/reasoningEngines/1"
            return {"reasoningEngines": [{"name": name, "displayName": f"agent-{project}"}]}
        return super().get_json(url, params, **kwargs)


def _gcp_run(index, monkeypatch, apis: _GoogleApis, **config: Any) -> dict[str, Any]:
    monkeypatch.setattr(GcpConnector, "_auth", lambda self: setattr(self, "http", apis))
    spec = ConnectorSpec("cloud.gcp", {"access_token": GCP_TOKEN, **config})
    return Engine(ScanConfig(connectors=[spec]), index=index).run().to_dict()


def test_gcp_configured_projects_are_the_principal_and_details_do_not_change_scope(index, monkeypatch):
    baseline = _gcp_run(index, monkeypatch, _GoogleApis(), projects=["proj-b", "proj-a"])
    assert baseline["summary"]["complete"] is True, baseline["stats"]
    (live,) = baseline["collection_scope"]["live"]
    assert live["principal"]["kind"] == "projects" and live["principal"]["id"] == "proj-a,proj-b"
    assert live["partitions"]["projects"] == ["proj-a", "proj-b"]
    operations = {(op["service"], op["operation"], op["partition"]) for op in live["operations"]}
    assert ("serviceusage", "/v1/projects/{project}/services", "proj-a") in operations
    assert ("cloudresourcemanager", "/v1/projects/{project}:getIamPolicy", "proj-b") in operations
    current = _gcp_run(index, monkeypatch, _GoogleApis(accounts=2), projects=["proj-a", "proj-b"])
    (after,) = current["collection_scope"]["live"]
    assert {
        "service": "iam",
        "operation": "/v1/projects/{project}/serviceAccounts/{account}/keys",
        "outcome": "ok",
    } in after["details"]
    assert current["collection_scope"]["fingerprint"] == baseline["collection_scope"]["fingerprint"]
    assert GCP_TOKEN not in json.dumps(current)


def test_gcp_discovery_mode_attests_the_discovered_project_set(index, monkeypatch):
    baseline = _gcp_run(index, monkeypatch, _GoogleApis(projects=["proj-b", "proj-a"]))
    (live,) = baseline["collection_scope"]["live"]
    assert live["principal"]["kind"] == "visible-projects" and live["principal"]["id"] == "proj-a,proj-b"
    assert "projects" not in live["partitions"]
    assert [op["operation"] for op in live["operations"]] == ["/v1/projects"]
    assert all(detail["operation"] != "/v1/projects" for detail in live["details"])
    assert baseline["collection_scope"]["comparable"] is True
    again = _gcp_run(index, monkeypatch, _GoogleApis(projects=["proj-a", "proj-b"]))
    assert again["collection_scope"]["fingerprint"] == baseline["collection_scope"]["fingerprint"]


@pytest.mark.parametrize(
    ("visible", "lost"),
    [
        (["proj-a"], {"proj-b"}),
        (["other-org"], {"proj-a", "proj-b"}),
        (["proj-a", "proj-b", "proj-c"], set()),
    ],
)
def test_gcp_discovered_project_set_change_is_not_comparable(index, monkeypatch, visible, lost):
    """Credentials that lose (or gain) a project must not resolve findings: the scope differs."""
    baseline = _gcp_run(index, monkeypatch, _VertexApis(projects=["proj-a", "proj-b"]))
    current = _gcp_run(index, monkeypatch, _VertexApis(projects=visible))
    assert baseline["summary"]["complete"] is True and current["collection_scope"]["comparable"] is True
    assert current["collection_scope"]["fingerprint"] != baseline["collection_scope"]["fingerprint"]
    comparison = compare_reports(baseline, current)
    # Findings of a project the credentials no longer see stay unknown, never resolved.
    assert comparison["comparable"] is False and comparison["resolved"] == []
    assert {finding["resource"].split("/")[1] for finding in comparison["unknown"]} == lost


def test_gcp_discovery_stopped_by_max_projects_is_not_attested(index, monkeypatch):
    report = _gcp_run(index, monkeypatch, _GoogleApis(projects=["proj-a", "proj-b"]), max_projects=1)
    (live,) = report["collection_scope"]["live"]
    assert live["principal"] is None and report["collection_scope"]["comparable"] is False


def test_gcp_discovery_with_no_visible_project_is_not_attested(index, monkeypatch):
    report = _gcp_run(index, monkeypatch, _GoogleApis(projects=[]))
    assert report["collection_scope"]["comparable"] is False


def test_gcp_denied_project_is_neither_verified_nor_attested(index, monkeypatch):
    apis = _GoogleApis(failures={"/services": HttpError(403, "https://serviceusage.googleapis.com")})
    report = _gcp_run(index, monkeypatch, apis, projects=["proj-a"])
    assert report["summary"]["complete"] is False
    (live,) = report["collection_scope"]["live"]
    assert live["principal"] is None
    assert {
        "service": "serviceusage",
        "operation": "/v1/projects/{project}/services",
        "partition": "proj-a",
        "outcome": "denied",
    } in live["operations"]
    assert report["collection_scope"]["reason"] == "live collection was not verified or was incomplete"


def test_gcp_request_templates(index):
    configured = GcpConnector(ConnectorContext(config={"projects": ["p"]}, index=index))
    discovered = GcpConnector(ConnectorContext(config={}, index=index))
    url = "https://us-central1-aiplatform.googleapis.com/v1/projects/p/locations/us-central1/reasoningEngines"
    assert configured._scope_operation(url) == (
        "aiplatform",
        "/v1/projects/{project}/locations/{location}/reasoningEngines",
        "p/us-central1",
        True,
    )
    assert discovered._scope_operation(url)[2:] == (None, False)
    engine = "https://discoveryengine.googleapis.com/v1alpha/projects/p/locations/global/collections/c/engines/e/assistants"
    assert configured._scope_operation(engine) == (
        "discoveryengine",
        "/v1alpha/projects/{project}/locations/{location}/collections/c/engines/{engine}/assistants",
        None,
        False,
    )
    assert configured._scope_operation("https://logging.googleapis.com/v2/entries:list", "p") == (
        "logging",
        "/v2/entries:list",
        "p",
        True,
    )


# ------------------------------------------------------------- cloud.azure
def _arm(monkeypatch, *, subscription: Any = None, listing: Any = None) -> list[str]:
    calls: list[str] = []

    def get_json(self, path, **kwargs):
        calls.append(path)
        if path.lower() == f"/subscriptions/{SUBSCRIPTION}":
            value = subscription if subscription is not None else {"subscriptionId": SUBSCRIPTION}
        elif path == "/subscriptions":
            value = listing if listing is not None else {"value": [{"subscriptionId": SUBSCRIPTION}]}
        else:
            value = {"value": []}
        if isinstance(value, Exception):
            raise value
        return value

    def post_json(self, path, **kwargs):
        calls.append(f"POST {path}")
        return {"data": []}

    monkeypatch.setattr(HttpClient, "get_json", get_json)
    monkeypatch.setattr(HttpClient, "post_json", post_json)
    return calls


def _azure_run(index, **config: Any) -> dict[str, Any]:
    spec = ConnectorSpec("cloud.azure", {"access_token": ARM_TOKEN, **config})
    return Engine(ScanConfig(connectors=[spec]), index=index).run().to_dict()


def test_azure_configured_subscriptions_are_verified_and_attested(index, monkeypatch, tmp_path):
    calls = _arm(monkeypatch)
    baseline = _azure_run(index, subscriptions=[SUBSCRIPTION.upper()])
    assert baseline["summary"]["complete"] is True, baseline["stats"]
    assert f"/subscriptions/{SUBSCRIPTION.upper()}" in calls
    (live,) = baseline["collection_scope"]["live"]
    assert live["principal"] == {
        "provider": "azure",
        "kind": "subscriptions",
        "id": SUBSCRIPTION,
        "verified_by": "arm:GET /subscriptions/{subscriptionId}",
    }
    assert live["partitions"] == {"subscriptions": [SUBSCRIPTION]}
    assert {(op["operation"], op["partition"]) for op in live["operations"]} == {
        ("POST /providers/Microsoft.ResourceGraph/resources", None),
        ("GET /subscriptions/{subscription}/providers/Microsoft.Authorization/roleAssignments", SUBSCRIPTION),
    }
    current = _azure_run(index, subscriptions=[SUBSCRIPTION.upper()])
    assert current["collection_scope"]["fingerprint"] == baseline["collection_scope"]["fingerprint"]
    assert _invoke(tmp_path, baseline, current).exit_code == 0
    assert ARM_TOKEN not in json.dumps(current)


def test_azure_listed_subscriptions_are_the_principal(index, monkeypatch):
    _arm(monkeypatch)
    report = _azure_run(index)
    (live,) = report["collection_scope"]["live"]
    assert (
        live["principal"]["id"] == SUBSCRIPTION
        and live["principal"]["verified_by"] == "arm:GET /subscriptions"
    )
    assert ("GET /subscriptions", None) in {(op["operation"], op["partition"]) for op in live["operations"]}
    assert report["collection_scope"]["comparable"] is True


@pytest.mark.parametrize("answer", [HttpError(403, "https://management.azure.com"), {"id": "x"}])
def test_unverified_azure_subscription_completes_but_is_not_comparable(index, monkeypatch, answer):
    _arm(monkeypatch, subscription=answer)
    report = _azure_run(index, subscriptions=[SUBSCRIPTION])
    assert report["summary"]["complete"] is True, report["stats"]
    assert report["collection_scope"]["reason"] == "live principal could not be verified"


def test_azure_subscription_reported_as_another_stops_the_scan(index, monkeypatch):
    _arm(monkeypatch, subscription={"subscriptionId": "ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee"})
    report = _azure_run(index, subscriptions=[SUBSCRIPTION])
    (stats,) = [s for s in report["stats"] if s["connector"] == "cloud.azure"]
    assert stats["skipped"] and "another subscription" in stats["skip_reason"]


def test_azure_request_templates():
    assert _arm_operation("/subscriptions") == ("GET /subscriptions", None, True)
    assert _arm_operation(
        f"https://management.azure.com/subscriptions/{SUBSCRIPTION.upper()}/providers/"
        "Microsoft.Authorization/roleAssignments?api-version=1&$skiptoken=x"
    ) == (
        "GET /subscriptions/{subscription}/providers/Microsoft.Authorization/roleAssignments",
        SUBSCRIPTION,
        True,
    )
    rid = f"/subscriptions/{SUBSCRIPTION}/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/a"
    assert _arm_operation(f"{rid}/deployments") == ("GET {resource}/deployments", None, False)
    assert _arm_operation(rid) == ("GET {resource}", None, False)


# ------------------------------------------------------------- credentials
def test_credentials_and_the_identity_key_never_reach_the_report(index, monkeypatch):
    key = bytes(range(32, 64))
    monkeypatch.setenv(IDENTITY_KEY_ENV, f"hex:{key.hex()}")
    _graph(monkeypatch, organization=_organization())
    entra = _entra_run(index)
    assert entra["collection_scope"]["comparable"] is True
    _arm(monkeypatch)
    azure = _azure_run(index, subscriptions=[SUBSCRIPTION])
    output = json.dumps([entra, azure])
    for secret in (CLIENT_SECRET, GRAPH_TOKEN, ARM_TOKEN, key.hex()):
        assert secret not in output
    pytest.importorskip("botocore")
    aws = _aws_run(index, monkeypatch, _AwsCloud(pages=_apps("helper")), role_arn=ROLE)
    assert aws["collection_scope"]["comparable"] is True
    assert SESSION_TOKEN not in json.dumps(aws) and "synthetic-secret" not in json.dumps(aws)


# ------------------------------------------------------------- hooks
def test_attesting_connectors_list_only_declared_non_secret_options():
    credentials = {
        "access_token",
        "client_id",
        "client_secret",
        "credentials_file",
        "delegated_token_env",
        "foundry_token",
        "profile",
        "allow_instance_credentials",
    }
    for name in ("cloud.aws", "cloud.azure", "cloud.gcp", "identity.entra"):
        cls = get_connector_class(name)
        assert cls.attests_live_scope is True
        assert cls.scope_options and cls.scope_options <= set(cls.config_keys)
        assert not {key for key in cls.scope_options if _sensitive_key(key)}
        assert not cls.scope_options & credentials


def test_report_counts_keep_matching_with_live_scope(index, monkeypatch):
    report = _aws_run(index, monkeypatch, _AwsCloud(pages=_apps("helper")))
    findings = report["findings"]
    assert report["summary"]["by_surface"] == dict(Counter(f["surface"] for f in findings))
    comparison = compare_reports(report, report)
    assert comparison["comparable"] is True


def test_threaded_scope_ledger_is_consistent():
    ledger = _ScopeLedger()

    def report(number: int) -> None:
        ledger.record(_JobState(), number, {"n": number})

    workers = [threading.Thread(target=report, args=(n,)) for n in range(1, 21)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    assert set(ledger.records(set())) == set(range(1, 21))


def test_scan_result_round_trip_keeps_live_summaries(index, monkeypatch):
    report = _aws_run(index, monkeypatch, _AwsCloud(pages=_apps("helper")))
    result = ScanResult(collection_scope=report["collection_scope"])
    assert result.to_dict()["collection_scope"]["live"] == report["collection_scope"]["live"]
