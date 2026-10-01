"""Permission classification shared by the connectors keeps a stable order."""

from __future__ import annotations

import pytest

from shadowscan.connectors.common import classify_permissions
from shadowscan.models import Finding, Kind, Surface


@pytest.mark.parametrize("container", [set, frozenset])
def test_unordered_permissions_have_stable_order(index, container):
    finding = Finding(
        surface=Surface.SAAS,
        connector="test",
        kind=Kind.BOT_APP,
        title="Agent",
        resource="test:agent",
        resource_type="app",
    )
    scopes = container(["repo:write", "admin:org", "read:user"])

    classify_permissions(index, finding, scopes)

    assert finding.permissions == ["admin:org", "read:user", "repo:write"]


def test_ordered_permissions_preserve_provider_order(index):
    finding = Finding(
        surface=Surface.SAAS,
        connector="test",
        kind=Kind.BOT_APP,
        title="Agent",
        resource="test:agent",
        resource_type="app",
    )

    classify_permissions(index, finding, ["repo:write", "read:user", "admin:org"])

    assert finding.permissions == ["repo:write", "read:user", "admin:org"]
