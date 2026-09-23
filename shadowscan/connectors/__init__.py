"""Connector registry.

Connectors are looked up by name (``surface.provider``). Built-ins are
registered here; third parties can add more through the
``shadowscan.connectors`` entry-point group.
"""

from __future__ import annotations

import importlib
from importlib.metadata import entry_points

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.models import Surface

_BUILTIN: dict[str, str] = {
    # code
    "code.filesystem": "shadowscan.connectors.code.filesystem:FilesystemConnector",
    "code.github": "shadowscan.connectors.code.github:GitHubConnector",
    "code.gitlab": "shadowscan.connectors.code.gitlab:GitLabConnector",
    # identity
    "identity.okta": "shadowscan.connectors.identity.okta:OktaConnector",
    "identity.entra": "shadowscan.connectors.identity.entra:EntraConnector",
    "identity.google-workspace": "shadowscan.connectors.identity.google_workspace:GoogleWorkspaceConnector",
    "identity.auth0": "shadowscan.connectors.identity.auth0:Auth0Connector",
    "identity.jwt": "shadowscan.connectors.identity.jwt:JwtConnector",
    # gateway
    "gateway.logs": "shadowscan.connectors.gateway.logs:GatewayLogConnector",
    # lowcode
    "lowcode.power-platform": "shadowscan.connectors.lowcode.power_platform:PowerPlatformConnector",
    "lowcode.salesforce": "shadowscan.connectors.lowcode.salesforce:SalesforceConnector",
    "lowcode.servicenow": "shadowscan.connectors.lowcode.servicenow:ServiceNowConnector",
    "lowcode.n8n": "shadowscan.connectors.lowcode.automation:N8nConnector",
    "lowcode.make": "shadowscan.connectors.lowcode.automation:MakeConnector",
    "lowcode.zapier": "shadowscan.connectors.lowcode.automation:ZapierConnector",
    "lowcode.workato": "shadowscan.connectors.lowcode.automation:WorkatoConnector",
    # saas
    "saas.slack": "shadowscan.connectors.saas.slack:SlackConnector",
    "saas.microsoft-teams": "shadowscan.connectors.saas.teams:TeamsConnector",
    "saas.github-apps": "shadowscan.connectors.saas.github_apps:GitHubAppsConnector",
    "saas.atlassian": "shadowscan.connectors.saas.atlassian:AtlassianConnector",
    "saas.notion": "shadowscan.connectors.saas.notion:NotionConnector",
    "saas.zoom": "shadowscan.connectors.saas.zoom:ZoomConnector",
    "saas.generic": "shadowscan.connectors.saas.generic:GenericSaaSConnector",
    # cloud
    "cloud.aws": "shadowscan.connectors.cloud.aws:AwsConnector",
    "cloud.gcp": "shadowscan.connectors.cloud.gcp:GcpConnector",
    "cloud.azure": "shadowscan.connectors.cloud.azure:AzureConnector",
    "cloud.oci": "shadowscan.connectors.cloud.oci:OciConnector",
}

_cache: dict[str, type[BaseConnector]] = {}


def _load(path: str) -> type[BaseConnector]:
    module_name, _, attr = path.partition(":")
    module = importlib.import_module(module_name)
    cls = getattr(module, attr)
    if not (isinstance(cls, type) and issubclass(cls, BaseConnector)):
        raise TypeError(f"{path} is not a BaseConnector subclass")
    return cls


def builtin_connector_names() -> frozenset[str]:
    """Names reserved for first-party connectors. Plugins cannot replace them."""
    return frozenset(_BUILTIN)


def available_connectors() -> dict[str, str]:
    """Return name -> import path for built-in and plugin connectors.

    Third-party ``shadowscan.connectors`` entry points may *add* names. They
    cannot replace a built-in name: a colliding plugin is ignored.
    """
    out = dict(_BUILTIN)
    try:
        for ep in entry_points(group="shadowscan.connectors"):
            if ep.name in _BUILTIN:
                continue
            out[ep.name] = ep.value
    except Exception:  # pragma: no cover - defensive against odd metadata
        pass
    return out


def get_connector_class(name: str) -> type[BaseConnector]:
    if name in _cache:
        return _cache[name]
    registry = available_connectors()
    if name not in registry:
        raise KeyError(f"unknown connector '{name}'. Known: {', '.join(sorted(registry))}")
    cls = _load(registry[name])
    _cache[name] = cls
    return cls


def connectors_for_surface(surface: Surface | str) -> list[str]:
    s = surface.value if isinstance(surface, Surface) else str(surface)
    return sorted(n for n in available_connectors() if n.startswith(s + "."))


__all__ = [
    "BaseConnector",
    "ConnectorContext",
    "ConnectorError",
    "available_connectors",
    "builtin_connector_names",
    "get_connector_class",
    "connectors_for_surface",
]
