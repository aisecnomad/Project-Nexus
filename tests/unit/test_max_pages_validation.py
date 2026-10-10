"""Every connector's ``max_pages`` setting is validated and bounded the same way.

Some connectors clamped invalid values to a single page (``max(1, int(value))``)
and accepted any upper bound, while others rejected them and capped at 1000.
The other integer limits and look-back windows follow the same rule.
"""

from __future__ import annotations

from unittest.mock import Mock

import pytest

from shadowscan.connectors import ConnectorContext, get_connector_class
from shadowscan.connectors.base import ConnectorError
from shadowscan.connectors.cloud.aws import AwsConnector
from shadowscan.connectors.cloud.gcp import GcpConnector
from shadowscan.connectors.cloud.oci import OciConnector
from shadowscan.connectors.common import MAX_PAGES, max_pages_limit
from shadowscan.connectors.gateway.logs import GatewayLogConnector
from shadowscan.connectors.saas.teams import TeamsConnector

# A null setting is unset in connector configuration and takes the default.
INVALID = [0, -1, True, False, 1.5, float("nan"), float("inf"), "abc", "1.5"]
ERROR = "max_pages must be a positive integer"


@pytest.mark.parametrize(
    "value, expected", [(1, 1), (10, 10), ("25", 25), (2.0, 2), (1000, 1000), (5000, 1000)]
)
def test_max_pages_accepts_positive_integers_up_to_the_shared_cap(value, expected):
    assert max_pages_limit(value) == expected
    assert MAX_PAGES == 1000


@pytest.mark.parametrize("value", [*INVALID, None])
def test_max_pages_rejects_non_integers_booleans_and_values_below_one(value):
    with pytest.raises(ConnectorError, match=ERROR):
        max_pages_limit(value)


@pytest.mark.parametrize("cls", [GcpConnector, OciConnector])
@pytest.mark.parametrize("value", INVALID)
def test_cloud_connectors_reject_invalid_max_pages_at_construction(index, cls, value):
    with pytest.raises(ConnectorError, match=ERROR):
        cls(ConnectorContext(config={"max_pages": value}, index=index))


@pytest.mark.parametrize("cls", [GcpConnector, OciConnector])
def test_cloud_connectors_cap_max_pages(index, cls):
    assert cls(ConnectorContext(config={"max_pages": 5000}, index=index)).max_pages == 1000
    assert cls(ConnectorContext(config={}, index=index)).max_pages == 1000


LIVE = [
    ("lowcode.n8n", {"api_url": "https://n8n.example.com/api/v1", "api_key": "test"}),
    ("lowcode.make", {"api_url": "https://eu1.make.com/api/v2", "token": "test", "team_id": "team"}),
    ("lowcode.zapier", {"token": "test"}),
    ("lowcode.workato", {"token": "test"}),
    ("saas.notion", {"token": "test"}),
]
_HTTP_CLIENT = {
    "lowcode.n8n": "shadowscan.connectors.lowcode.automation.HttpClient",
    "lowcode.make": "shadowscan.connectors.lowcode.automation.HttpClient",
    "lowcode.zapier": "shadowscan.connectors.lowcode.automation.HttpClient",
    "lowcode.workato": "shadowscan.connectors.lowcode.automation.HttpClient",
    "saas.notion": "shadowscan.connectors.saas.notion.HttpClient",
}


@pytest.mark.parametrize("name, config", LIVE, ids=[name for name, _ in LIVE])
@pytest.mark.parametrize("value", [0, True, 1.5, "abc"])
def test_live_collection_rejects_invalid_max_pages_before_any_request(
    index, monkeypatch, name, config, value
):
    http = Mock()
    monkeypatch.setattr(_HTTP_CLIENT[name], Mock(return_value=http))
    ctx = ConnectorContext(config={**config, "max_pages": value}, index=index)
    assert get_connector_class(name)(ctx).run() == []
    # A configuration error, not a silently truncated one-page scan.
    assert ctx.stats.skipped and ctx.stats.skip_reason == ERROR
    assert ctx.stats.errors == [ERROR]
    assert not (http.get_json.called or http.paginate_token.called)


def test_previously_unbounded_connector_stops_at_the_shared_cap(index, monkeypatch):
    pages = iter(range(10_000))
    http = Mock()
    http.get_json.side_effect = lambda url, **kw: {"data": [], "links": {"next": f"/v2/zaps?c={next(pages)}"}}
    monkeypatch.setattr("shadowscan.connectors.lowcode.automation.HttpClient", Mock(return_value=http))
    ctx = ConnectorContext(config={"token": "test", "max_pages": 5000}, index=index)
    get_connector_class("lowcode.zapier")(ctx).run()
    assert http.get_json.call_count == 1000
    assert ctx.stats.incomplete and "lowcode.zapier: pagination limit reached" in ctx.stats.warnings


# Integer options other than max_pages. ``int()`` used to accept booleans (``true``
# became 1) and truncate fractions: ``cloudtrail_days: 0.5`` became 0 and switched
# the CloudTrail lookup off without a diagnostic.
NOT_INTEGERS = [True, False, 1.5, float("nan"), float("inf"), "abc", "1.5"]
LIMITS = [
    (AwsConnector, "max_lambda"),
    (AwsConnector, "max_ecs_api_calls"),
    (AwsConnector, "max_registry_records"),
    (GcpConnector, "max_projects"),
    (GatewayLogConnector, "min_events"),
    (TeamsConnector, "max_teams"),
]
WINDOWS = [(AwsConnector, "cloudtrail_days"), (GcpConnector, "audit_days")]


@pytest.mark.parametrize("cls, setting", LIMITS)
@pytest.mark.parametrize("value", [0, -1, *NOT_INTEGERS])
def test_integer_limits_reject_values_that_are_not_positive_integers(index, cls, setting, value):
    with pytest.raises(ConnectorError, match=f"{setting} must be a positive integer"):
        cls(ConnectorContext(config={setting: value}, index=index))


@pytest.mark.parametrize("cls, setting", WINDOWS)
@pytest.mark.parametrize("value", [-1, *NOT_INTEGERS])
def test_look_back_windows_reject_values_that_are_not_non_negative_integers(index, cls, setting, value):
    with pytest.raises(ConnectorError, match=f"{setting} must be a non-negative integer"):
        cls(ConnectorContext(config={setting: value}, index=index))


@pytest.mark.parametrize("cls, setting", [*LIMITS, *WINDOWS])
def test_integer_options_accept_integers_in_any_spelling(index, cls, setting):
    for value in (3, "3", 3.0):
        assert getattr(cls(ConnectorContext(config={setting: value}, index=index)), setting) == 3
    if (cls, setting) in WINDOWS:  # zero switches a look-back window off
        assert getattr(cls(ConnectorContext(config={setting: 0}, index=index)), setting) == 0
