"""Connector registry.

Connectors are looked up by name (``surface.provider``). Built-ins are
registered here; third parties can add more through the
``shadowscan.connectors`` entry-point group.

A plugin's identity is its entry-point name: it is what operators approve in
``options.plugins`` and what every finding and scan statistic is attributed
to. The class an entry point names must declare that same ``name``. The
registry verifies this, together with the other class attributes the scanner
relies on, when an approved plugin is loaded, and refuses the plugin
otherwise, so a plugin can never report under a built-in connector's name.
"""

from __future__ import annotations

import importlib
import inspect
from collections.abc import Sequence
from dataclasses import dataclass
from importlib.metadata import entry_points

from shadowscan.connectors.base import BaseConnector, ConnectorContext, ConnectorError
from shadowscan.models import Surface
from shadowscan.utils.redaction import sanitize_text

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

# Bare namespace ids ("cloud", "saas", ...) are reserved alongside built-in names.
_SURFACE_IDS: frozenset[str] = frozenset(surface.value for surface in Surface)

# Longer plugin-supplied strings are never echoed into a diagnostic.
_MAX_DISPLAY_CHARS = 120


@dataclass(frozen=True, slots=True)
class PluginDiagnostic:
    """One printable, credential-free problem with a third-party connector entry.

    ``entry`` is the entry-point name the problem concerns (``None`` when the
    metadata did not yield one). ``rule`` is a stable identifier of the rule
    that failed: ``unreadable-metadata``, ``invalid-name``, ``reserved-name``,
    ``duplicate-name``, ``invalid-import-path``, ``load-failed``,
    ``not-a-connector``, ``abstract-class``, ``missing-attribute``,
    ``invalid-attribute``, ``identity-mismatch`` or ``surface-mismatch``.
    ``message`` is the complete, sanitized line to show an operator;
    ``str(diagnostic)`` returns it.
    """

    entry: str | None
    rule: str
    message: str

    def __str__(self) -> str:
        return self.message


class PluginRegistryError(ConnectorError):
    """An approved third-party connector was refused by the registry's identity rules.

    ``diagnostic`` carries the structured, printable reason; the exception
    message is the same text.
    """

    def __init__(self, diagnostic: PluginDiagnostic) -> None:
        super().__init__(diagnostic.message)
        self.diagnostic = diagnostic


class _NotAConnectorError(TypeError):
    """An import path resolved to something other than a BaseConnector subclass."""


_cache: dict[str, type[BaseConnector]] = {}
# Problems found by the most recent entry-point scan, replaced on every scan.
_listing_errors: list[PluginDiagnostic] = []
# Load-time refusals by entry-point name. A class is deterministic within one
# process, so the latest refusal for a name is the only one worth keeping.
_load_errors: dict[str, PluginDiagnostic] = {}


def _load(path: str) -> type[BaseConnector]:
    module_name, _, attr = path.partition(":")
    module = importlib.import_module(module_name)
    cls = getattr(module, attr)
    if not (isinstance(cls, type) and issubclass(cls, BaseConnector)):
        raise _NotAConnectorError(f"{path} is not a BaseConnector subclass")
    return cls


def _display(text: str) -> str:
    """Quote a plugin-supplied string for a diagnostic without leaking credentials."""
    if len(text) > _MAX_DISPLAY_CHARS:
        return f"<{len(text)}-character value omitted>"
    return repr(sanitize_text(text))


def _malformed_name(name: str) -> bool:
    return name != name.strip() or not name.isprintable() or any(ch.isspace() for ch in name)


def _reserved_name_reason(name: str) -> str | None:
    """Explain why ``name`` may not identify a third-party connector, or return None.

    Built-in names are reserved exactly and in every variant that differs only
    by case, Unicode case folding or surrounding whitespace, because such a
    variant reads as the built-in in a report.
    """
    folded = name.strip().casefold()
    if folded in _SURFACE_IDS:
        return f"is the built-in {folded!r} namespace; a connector name has the form namespace.provider"
    if folded in _BUILTIN:
        if name == folded:
            return "is a built-in connector name; plugins cannot replace it"
        return f"differs from the built-in connector {folded!r} only by case or surrounding whitespace"
    return None


def _declares(cls: type, attribute: str) -> bool:
    """Whether ``attribute`` is set by the plugin or a parent other than BaseConnector."""
    return any(attribute in vars(klass) for klass in cls.__mro__ if klass is not BaseConnector)


def _refuse(name: str, rule: str, message: str) -> PluginRegistryError:
    diagnostic = PluginDiagnostic(entry=name, rule=rule, message=message)
    _load_errors[name] = diagnostic
    return PluginRegistryError(diagnostic)


def _verify_connector_class(name: str, path: str, cls: object) -> type[BaseConnector]:
    """Enforce the connector identity contract on a loaded entry-point target.

    ``name`` is the registered connector name, ``path`` its ``module:attribute``
    value and ``cls`` whatever that path resolved to. Returns ``cls`` when it is
    a concrete ``BaseConnector`` subclass whose declared ``name`` is exactly
    ``name`` and whose ``surface``, ``description`` and ``config_keys`` are
    declared with the types the scanner relies on. A declared name that differs
    from ``name`` is reported as reserved when it is a built-in name or
    namespace, and as an identity mismatch otherwise. Every built-in connector
    satisfies this contract; plugins are held to it at load time. Raises
    :class:`PluginRegistryError` otherwise and records the diagnostic.
    """
    where = f"plugin {_display(name)} ({_display(path)})"
    if not (isinstance(cls, type) and issubclass(cls, BaseConnector)):
        raise _refuse(name, "not-a-connector", f"{where} is not a BaseConnector subclass")
    if inspect.isabstract(cls):
        raise _refuse(name, "abstract-class", f"{where} is abstract; implement collect() and analyze()")
    for attribute in ("name", "surface", "description", "config_keys"):
        if not _declares(cls, attribute):
            raise _refuse(name, "missing-attribute", f"{where} does not declare {attribute}")
    declared = cls.name
    if not isinstance(declared, str):
        raise _refuse(name, "identity-mismatch",
                      f"{where} declares a {type(declared).__name__} name; name must be the string {_display(name)}")
    if declared != name:
        reserved = _reserved_name_reason(declared)
        if reserved is not None:
            raise _refuse(name, "reserved-name", f"{where} declares name {_display(declared)}, which {reserved}")
        raise _refuse(name, "identity-mismatch",
                      f"{where} declares name {_display(declared)}; a plugin class must declare "
                      "name equal to its entry-point name")
    surface = cls.surface
    if not isinstance(surface, Surface):
        raise _refuse(name, "invalid-attribute",
                      f"{where} must declare surface as a shadowscan.models.Surface member, not {type(surface).__name__}")
    namespace = name.partition(".")[0]
    if namespace in _SURFACE_IDS and surface.value != namespace:
        raise _refuse(name, "surface-mismatch",
                      f"{where} declares surface {surface.value!r} but its name is in the built-in {namespace!r} namespace")
    if not isinstance(cls.description, str) or not cls.description.strip():
        raise _refuse(name, "invalid-attribute", f"{where} must declare a nonempty string description")
    keys = cls.config_keys
    if not isinstance(keys, dict) or not all(isinstance(key, str) and isinstance(value, str) for key, value in keys.items()):
        raise _refuse(name, "invalid-attribute",
                      f"{where} must declare config_keys as a dict of option name to description")
    if cls.provider is not None and not isinstance(cls.provider, str):
        raise _refuse(name, "invalid-attribute", f"{where} must declare provider as a string or None")
    if not isinstance(cls.requires, list) or not all(isinstance(module, str) for module in cls.requires):
        raise _refuse(name, "invalid-attribute", f"{where} must declare requires as a list of module names")
    if not isinstance(cls.offline_formats, str):
        raise _refuse(name, "invalid-attribute", f"{where} must declare offline_formats as a string")
    return cls


def _load_plugin(name: str, path: str) -> type[BaseConnector]:
    """Import an approved third-party connector and enforce its identity contract."""
    where = f"plugin {_display(name)} ({_display(path)})"
    try:
        cls = _load(path)
    except _NotAConnectorError:
        raise _refuse(name, "not-a-connector", f"{where} is not a BaseConnector subclass") from None
    except Exception as exc:  # noqa: BLE001 - any import failure refuses the plugin with a bounded diagnostic
        detail = f"{type(exc).__name__}: {_display(str(exc))}"
        raise _refuse(name, "load-failed", f"{where} could not be imported ({detail})") from exc
    return _verify_connector_class(name, path, cls)


def builtin_connector_names() -> frozenset[str]:
    """Names reserved for first-party connectors. Plugins cannot replace them."""
    return frozenset(_BUILTIN)


def plugin_registry_errors() -> tuple[PluginDiagnostic, ...]:
    """Credential-free diagnostics about third-party connector entries.

    Rescans the entry points, so listing problems always reflect the current
    environment; load-time refusals recorded in this process follow them.
    Duplicates are removed and every ``message`` is safe to print. Nothing is
    imported.
    """
    available_connectors()
    return tuple(dict.fromkeys([*_listing_errors, *_load_errors.values()]))


def available_connectors() -> dict[str, str]:
    """Return name -> import path for built-in and plugin connectors.

    Third-party ``shadowscan.connectors`` entry points may *add* names. They
    cannot replace a built-in name, a bare surface namespace or a variant of
    either that differs only by case or surrounding whitespace: such an entry
    is refused. A name registered by more than one entry point with different
    targets is ambiguous, and none of its entries is listed, whatever the
    installation order. Each plugin entry is isolated: a broken entry does not
    hide the others. Nothing is imported.
    """
    out = dict(_BUILTIN)
    errors: list[PluginDiagnostic] = []
    try:
        discovered = list(entry_points(group="shadowscan.connectors"))
    except Exception as exc:  # pragma: no cover - defensive against odd metadata
        errors.append(PluginDiagnostic(None, "unreadable-metadata",
                                       f"plugin metadata listing failed: {type(exc).__name__}"))
        _listing_errors[:] = errors
        return out
    candidates: dict[str, list[object]] = {}
    for ep in discovered:
        try:
            name = ep.name
            value = ep.value
        except Exception as exc:  # pragma: no cover - broken metadata object
            errors.append(PluginDiagnostic(None, "unreadable-metadata",
                                           f"plugin entry is unreadable: {type(exc).__name__}"))
            continue
        if not isinstance(name, str) or not name.strip():
            errors.append(PluginDiagnostic(None, "invalid-name", "plugin entry is missing a nonempty connector name"))
            continue
        candidates.setdefault(name, []).append(value)
    for name, values in candidates.items():
        shown = _display(name)
        if _malformed_name(name):
            errors.append(PluginDiagnostic(name, "invalid-name",
                                           f"plugin {shown} must be a single printable token without whitespace"))
            continue
        reserved = _reserved_name_reason(name)
        if reserved is not None:
            errors.append(PluginDiagnostic(name, "reserved-name", f"plugin {shown} {reserved}"))
            continue
        if any(value != values[0] for value in values[1:]):
            errors.append(PluginDiagnostic(name, "duplicate-name",
                                           f"plugin {shown} is registered by {len(values)} entry points with "
                                           "different targets; none of them is loaded"))
            continue
        target = values[0]
        if not isinstance(target, str) or ":" not in target:
            errors.append(PluginDiagnostic(name, "invalid-import-path",
                                           f"plugin {shown} has an invalid import path; expected module:ClassName"))
            continue
        out[name] = target
    _listing_errors[:] = errors
    return out


def get_connector_class(name: str, *, allowed_plugins: Sequence[str] | None = None) -> type[BaseConnector]:
    """Return the connector class registered under ``name``.

    Built-in names load directly. A third-party name must be listed by an
    entry point and approved through ``allowed_plugins`` on every call; its
    class is then imported and verified against the plugin identity rules
    before it is cached. Raises ``KeyError`` for an unknown name,
    ``ValueError`` for an unapproved plugin and :class:`PluginRegistryError`
    for a plugin that fails verification.
    """
    # Check authorization before looking in the cache. A previous scan's plugin
    # approval must never authorize a later scan in the same process.
    if name in _BUILTIN:
        path = _BUILTIN[name]
    else:
        registry = available_connectors()
        if name not in registry:
            raise KeyError(f"unknown connector '{name}'. Known: {', '.join(sorted(registry))}")
        if isinstance(allowed_plugins, str) or name not in (allowed_plugins or ()):
            raise ValueError(f"third-party connector '{name}' is not approved; add its exact name to options.plugins")
        path = registry[name]
    if name in _cache:
        return _cache[name]
    cls = _load(path) if name in _BUILTIN else _load_plugin(name, path)
    _cache[name] = cls
    return cls


def connectors_for_surface(surface: Surface | str) -> list[str]:
    s = surface.value if isinstance(surface, Surface) else str(surface)
    return sorted(n for n in available_connectors() if n.startswith(s + "."))


__all__ = [
    "BaseConnector",
    "ConnectorContext",
    "ConnectorError",
    "PluginDiagnostic",
    "PluginRegistryError",
    "available_connectors",
    "builtin_connector_names",
    "get_connector_class",
    "connectors_for_surface",
    "plugin_registry_errors",
]
