"""Default cloud scope is disclosed, informational notices stay informational, Azure app settings stay bounded."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import Mock

import pytest

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.cloud import aws as aws_module
from shadowscan.connectors.cloud import gcp as gcp_module
from shadowscan.connectors.cloud.aws import AwsConnector
from shadowscan.connectors.cloud.azure import AzureConnector
from shadowscan.connectors.cloud.gcp import GcpConnector
from shadowscan.models import ScanResult, ScanStats
from shadowscan.utils.http import HttpError
from shadowscan.utils.redaction import REDACTED, sanitize

ACCOUNT = "123456789012"
PROJECT = "acme-search"


def context(index: Any, **config: Any) -> ConnectorContext:
    ctx = ConnectorContext(config=config, index=index)
    ctx.stats = ScanStats(connector="test", started_at="2026-01-01")
    return ctx


def _complete(ctx: ConnectorContext) -> bool:
    return ScanResult(stats=[ctx.stats]).complete  # type: ignore[list-item]


# --------------------------------------------------------------------- AWS
def _aws_collect(index: Any, **config: Any) -> tuple[ConnectorContext, list[str]]:
    ctx = context(index, account_id=ACCOUNT, **config)
    connector = AwsConnector(ctx)
    connector._session_ = Mock()
    connector._client = Mock()
    connector._client.return_value.describe_regions.return_value = {
        "Regions": [{"RegionName": "us-east-2"}, {"RegionName": "eu-north-1"}]
    }
    scanned: list[str] = []
    connector._collect_lambda = lambda region: (scanned.append(region), iter(()))[1]  # type: ignore[method-assign]
    list(connector.collect())
    return ctx, scanned


def test_aws_default_regions_are_disclosed_without_marking_the_scan_incomplete(index):
    ctx, scanned = _aws_collect(index, services=["lambda"])
    assert scanned == aws_module.DEFAULT_REGIONS
    (notice,) = [w for w in ctx.stats.warnings if "regions" in w]
    for region in aws_module.DEFAULT_REGIONS:
        assert region in notice
    assert "not scanned" in notice and "regions: all" in notice
    assert not ctx.stats.incomplete and _complete(ctx)


@pytest.mark.parametrize("regions", [["us-east-2"], ["all"], "us-east-2"])
def test_aws_explicit_regions_emit_no_default_scope_notice(index, regions):
    ctx, _ = _aws_collect(index, services=["lambda"], regions=regions)
    assert ctx.stats.warnings == [] and _complete(ctx)


def test_aws_iam_only_scan_is_not_region_scoped_so_it_has_no_region_notice(index):
    ctx = context(index, account_id=ACCOUNT, services=["iam"])
    connector = AwsConnector(ctx)
    connector._session_ = Mock()
    connector._collect_iam = lambda: iter(())  # type: ignore[method-assign]
    list(connector.collect())
    assert ctx.stats.warnings == []


def test_aws_failed_cloudtrail_lookup_still_marks_the_scan_incomplete(index):
    ctx = context(index, account_id=ACCOUNT, regions=["us-east-1"])
    connector = AwsConnector(ctx)
    client = Mock()
    client.get_paginator.return_value.paginate.side_effect = RuntimeError("AccessDenied: lookup_events")
    connector._client = Mock(return_value=client)
    assert list(connector._collect_cloudtrail("us-east-1")) == []
    assert ctx.stats.incomplete and not _complete(ctx)


def test_aws_iam_policy_limitation_names_the_principal_and_stays_incomplete(index):
    ctx = context(index, account_id=ACCOUNT, regions=["us-east-1"])
    connector = AwsConnector(ctx)
    arn = f"arn:aws:iam::{ACCOUNT}:role/PowerRole"
    connector._client = Mock()
    connector._paginate_details = Mock(
        return_value=iter(
            [
                {
                    "_type": "RoleDetailList",
                    "RoleName": "PowerRole",
                    "Arn": arn,
                    "RolePolicyList": [
                        {
                            "PolicyDocument": {
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "bedrock:*",
                                        "Resource": "*",
                                        "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
                                    }
                                ]
                            }
                        }
                    ],
                }
            ]
        )
    )
    (record,) = connector._collect_iam()
    assert record["policy_limitations"] == ["conditions-not-evaluated"]
    (warning,) = ctx.stats.warnings
    assert arn in warning and "conditions-not-evaluated" in warning
    assert "effective authorization is unknown" in warning and "marked incomplete" in warning
    assert ctx.stats.incomplete


# --------------------------------------------------------------------- GCP
class FakeGoogle:
    def __init__(self, routes: dict[str, Any] | None = None) -> None:
        self.routes = routes or {}
        self.gets: list[str] = []

    def get_json(self, url: str, params: dict[str, Any] | None = None) -> Any:
        self.gets.append(url)
        if url.endswith("/services"):
            return {"services": [{"config": {"name": name}} for name in self.enabled]}
        return {}

    def post_json(self, url: str, json: dict[str, Any] | None = None) -> Any:
        return {"bindings": []}

    enabled: tuple[str, ...] = ()


def _gcp(index: Any, enabled: tuple[str, ...], **config: Any) -> tuple[GcpConnector, FakeGoogle]:
    connector = GcpConnector(context(index, **config))
    fake = FakeGoogle()
    fake.enabled = enabled
    connector.http = fake  # type: ignore[assignment]
    connector._auth = Mock()  # type: ignore[method-assign]
    return connector, fake


def test_gcp_default_locations_are_disclosed_once_without_marking_the_scan_incomplete(index):
    connector, _ = _gcp(
        index, ("aiplatform.googleapis.com", "dialogflow.googleapis.com"), projects=["p1", "p2"]
    )
    list(connector.collect())
    ctx = connector.ctx
    (notice,) = [w for w in ctx.stats.warnings if "locations" in w]
    for location in gcp_module.DEFAULT_LOCATIONS:
        assert location in notice
    assert "not scanned" in notice and "locations" in notice
    assert not ctx.stats.incomplete and _complete(ctx)


def test_gcp_explicit_locations_emit_no_default_scope_notice(index):
    connector, _ = _gcp(index, ("aiplatform.googleapis.com",), projects=["p1"], locations=["us-east1"])
    list(connector.collect())
    assert connector.ctx.stats.warnings == [] and _complete(connector.ctx)


def test_gcp_notice_is_skipped_when_no_location_scoped_service_is_enabled(index):
    connector, _ = _gcp(index, ("cloudfunctions.googleapis.com",), projects=["p1"])
    list(connector.collect())
    assert connector.ctx.stats.warnings == []


def test_gcp_dialogflow_and_discovery_engine_use_their_documented_regional_hosts(index):
    connector, fake = _gcp(
        index,
        ("dialogflow.googleapis.com", "discoveryengine.googleapis.com"),
        projects=[PROJECT],
        locations=["us-central1", "global", "europe-west4"],
    )
    list(connector.collect())
    agents = f"/v3/projects/{PROJECT}/locations/%s/agents"
    engines = f"/v1/projects/{PROJECT}/locations/%s/collections/default_collection/engines"
    urls = [url for url in fake.gets if "dialogflow" in url or "discoveryengine" in url]
    assert urls == [
        f"https://dialogflow.googleapis.com{agents % 'global'}",
        f"https://us-central1-dialogflow.googleapis.com{agents % 'us-central1'}",
        f"https://europe-west4-dialogflow.googleapis.com{agents % 'europe-west4'}",
        f"https://discoveryengine.googleapis.com{engines % 'global'}",
        f"https://us-discoveryengine.googleapis.com{engines % 'us'}",
        f"https://eu-discoveryengine.googleapis.com{engines % 'eu'}",
    ]


# ------------------------------------------------------------------- Azure
WEB_APP = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Web/sites"
SECRET = "sk-proj-kLKFlNfzW2mTofMpnx1qOu7fTm9F8IRv6iKzoC2h"
OPAQUE = "opaque-credential-value-9f8e7d6c5b4a"


def _azure(index: Any, post: Any, **config: Any) -> AzureConnector:
    connector = AzureConnector(context(index, subscriptions="s1", **config))
    connector._auth = Mock()  # type: ignore[method-assign]
    connector._list = Mock(return_value=[])  # type: ignore[method-assign]
    connector.http = Mock()
    rows = [
        {"id": f"{WEB_APP}/{n}", "type": "microsoft.web/sites", "name": n, "kind": "app"} for n in ("a", "b")
    ]
    connector.http.post_json.side_effect = [{"data": rows}, *post]
    return connector


@pytest.mark.parametrize("status", [401, 403])
def test_azure_appsettings_permission_denial_is_a_bounded_warning_that_names_the_permission(index, status):
    denied = HttpError(status, "https://management.azure.com/x")
    good = {"properties": {"OPENAI_API_KEY": SECRET}}
    connector = _azure(index, [denied, good])
    records = list(connector.collect())
    assert [r["name"] for r in records if r["_kind"] == "appsettings"] == ["b"]
    (warning,) = connector.ctx.stats.warnings
    assert f"HTTP {status}" in warning and f"{WEB_APP}/a" in warning
    assert "Microsoft.Web/sites/config/list/action" in warning and "include_app_settings" in warning
    assert connector.ctx.stats.incomplete


def test_azure_include_app_settings_false_never_calls_the_appsettings_api(index):
    connector = _azure(index, [], include_app_settings=False)
    records = list(connector.collect())
    assert [r["_kind"] for r in records] == ["resource", "resource"]
    assert connector.http.post_json.call_count == 1  # the Resource Graph query only
    assert connector.ctx.stats.warnings == []


def test_azure_appsettings_values_never_reach_findings_or_dumps(index):
    settings = {"properties": {"OPENAI_API_KEY": SECRET, "CUSTOM_BLOB": OPAQUE}}
    connector = _azure(index, [settings, settings])
    records = list(connector.collect())
    dumped = json.dumps(sanitize(records))
    assert SECRET not in dumped and OPAQUE not in dumped and REDACTED in dumped
    findings = list(connector.analyze(records))
    assert findings
    for finding in findings:
        text = json.dumps(finding.to_dict(), default=str)
        assert SECRET not in text and OPAQUE not in text


def test_azure_app_settings_option_help_names_the_permission_and_the_opt_out():
    help_text = AzureConnector.config_keys["include_app_settings"]
    assert "Microsoft.Web/sites/config/list/action" in help_text
    assert "plaintext" in help_text and "false skips" in help_text
