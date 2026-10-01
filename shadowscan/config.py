"""Scan configuration (YAML file and/or CLI options).

Example ``shadowscan.yaml``::

    inventory:
      - ./inventory/            # Agent Capability Cards / agents.yaml / CSV
    signatures:
      - ./custom-signatures/    # extra or overriding signature packs
    options:
      min_confidence: 0.3
      fail_on: high             # exit non-zero when a finding reaches this level
      dump_records: ./exports   # save sanitized connector records (JSONL) for offline re-analysis
    connectors:
      - name: code.github
        org: acme
        token: ${GITHUB_TOKEN}
      - name: identity.entra
        tenant_id: ${AZURE_TENANT_ID}
        client_id: ${AZURE_CLIENT_ID}
        client_secret: ${AZURE_CLIENT_SECRET}
      - name: gateway.logs
        input: ./exports/litellm-spend.jsonl
      - name: cloud.aws
        regions: [us-east-1, eu-west-1]
        cloudtrail_days: 7

``${VAR}`` requires a nonempty environment value. ``${VAR:-default}`` uses its
explicit fallback when the variable is missing or empty.

``options.connector_timeout`` is a deprecated alias for
``options.connector_timeout_seconds``. Legacy null selects the bounded
120-second default; it never disables the completion deadline. Specify one key.
Using the alias logs a deprecation warning once per process.

Connector entries of built-in connectors accept only the keys the connector
reads (see ``shadowscan connectors``) plus the shared offline input limits.
Unknown keys are rejected so that a typo cannot silently disable an option.
Third-party plugins are not imported while parsing, so their keys are not
checked here. Keys starting with an underscore are reserved for the engine.
"""

from __future__ import annotations

import difflib
import json
import logging
import math
import os
import re
from collections.abc import Mapping
from dataclasses import InitVar, dataclass, field
from pathlib import Path
from typing import Any

import yaml

from shadowscan.errors import SetupError, yaml_error_position
from shadowscan.risk import RiskPolicy
from shadowscan.utils.files import read_policy_text
from shadowscan.utils.redaction import REDACTED, sanitize_text
from shadowscan.utils.safe_json import JSONIntegrityError, strict_json_loads
from shadowscan.utils.safe_yaml import BoundedSafeLoader

log = logging.getLogger("shadowscan.config")

_ENV_RX = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")
PATH_KEYS = (
    "input",
    "path",
    "paths",
    "service_account_file",
    "credentials_file",
    "config_file",
    "token_file",
)
_CONFIG_FIELDS = {"connectors", "inventory", "signatures", "options"}
_OPTION_FIELDS = {
    "min_confidence",
    "fail_on",
    "dump_records",
    "workdir",
    "parallel",
    "incremental",
    "state_dir",
    "plugins",
    "allow_signature_override",
    "allow_private_origin",
    "allow_instance_credentials",
    "allow_credential_mixing",
    "connector_timeout_seconds",
    "connector_timeout",
    "risk_basis",
    "risk_weights",
    "job_deadline_seconds",
}
_RISK_LEVELS = {"critical", "high", "medium", "low", "info"}
# Keys every connector accepts: BaseConnector / ConnectorContext read the input
# and offline limits, and the engine hands every connector its ``label``.
SHARED_CONNECTOR_KEYS = frozenset(
    {"input", "label", "max_input_bytes", "max_input_file_bytes", "max_input_files"}
)
# Built-in connector switches are normalised before connector construction so
# environment expansion cannot turn the string ``"false"`` into a truthy
# value.  Plugin configuration remains opaque: an approved plugin owns its
# schema and receives values unchanged.
_BOOLEAN_CONNECTOR_KEYS: dict[str, frozenset[str]] = {
    "cloud.aws": frozenset({"allow_instance_credentials"}),
    "cloud.azure": frozenset({"allow_instance_credentials", "include_app_settings"}),
    "cloud.gcp": frozenset({"allow_instance_credentials"}),
    "cloud.oci": frozenset({"allow_instance_credentials"}),
    "code.filesystem": frozenset({"include_tests", "scan_secrets", "strict_coverage", "use_git"}),
    "code.github": frozenset(
        {
            "include_archived",
            "include_forks",
            "include_tests",
            "scan_secrets",
            "strict_coverage",
            "use_git",
        }
    ),
    "code.gitlab": frozenset(
        {"include_archived", "include_tests", "scan_secrets", "strict_coverage", "use_git"}
    ),
    "gateway.logs": frozenset({"llm_hosts_only"}),
    "identity.entra": frozenset({"include_first_party"}),
    "identity.okta": frozenset({"fetch_tokens", "include_inactive"}),
    "lowcode.power-platform": frozenset({"include_bots"}),
    "saas.generic": frozenset({"keep_all"}),
    "saas.github-apps": frozenset({"include_unrecognized_apps"}),
    "saas.microsoft-teams": frozenset({"include_store"}),
}
_IDENTIFIER_RX = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_deprecations_warned: set[str] = set()


class ConfigValidationError(SetupError, ValueError):
    """Configuration error whose message never includes user-supplied values."""


class MinConfidenceError(ConfigValidationError):
    """``min_confidence`` is outside the finite unit interval.

    The CLI reports it as a usage error because the same threshold is also a
    command line option.
    """


def _validate_config_graph(value: Any, *, reject_nonfinite: bool = True) -> None:
    """Reject non-finite numbers while bounding work over opaque values.

    Plugin configuration has no first-party key schema, but it still crosses
    the scanner's serialization and hashing boundaries. Traverse mappings and
    ordinary containers without interpreting their keys, applying the same
    node/depth ceilings as bounded YAML construction.
    """
    remaining = BoundedSafeLoader.MAX_EXPANDED_NODES
    active: set[int] = set()

    def validate(item: Any, depth: int = 0) -> None:
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or depth > BoundedSafeLoader.MAX_DEPTH:
            raise ConfigValidationError("scan configuration validation limit exceeded")
        if reject_nonfinite and isinstance(item, float) and not math.isfinite(item):
            raise ConfigValidationError("scan configuration numbers must be finite")
        if isinstance(item, Mapping):
            children: Any = item.items()
        elif isinstance(item, (list, tuple, set, frozenset)):
            children = item
        else:
            return
        identity = id(item)
        if identity in active:
            raise ConfigValidationError("scan configuration cannot contain cycles")
        active.add(identity)
        try:
            if isinstance(item, Mapping):
                for key, child in children:
                    validate(key, depth + 1)
                    validate(child, depth + 1)
            else:
                for child in children:
                    validate(child, depth + 1)
        finally:
            active.remove(identity)

    validate(value)


def _warn_deprecated_once(key: str, message: str) -> None:
    """Log a deprecation once per process so repeated parses do not flood logs."""
    if key in _deprecations_warned:
        return
    _deprecations_warned.add(key)
    log.warning("%s", message)


def _display_identifier(value: Any, fallback: str) -> str:
    """Quote a key or connector name for a diagnostic only when it is plainly an identifier."""
    if isinstance(value, str) and _IDENTIFIER_RX.fullmatch(value):
        shown = sanitize_text(value)
        if shown == value and REDACTED not in shown:
            return f"'{value}'"
    return fallback


def accepted_connector_keys(name: str) -> frozenset[str] | None:
    """Return the configuration keys a built-in connector accepts, or None for plugins.

    A built-in connector accepts exactly its documented ``config_keys`` and
    the shared keys. Built-in connector modules are first-party code, so
    importing one to read its ``config_keys`` is safe at parse time.
    Third-party plugins are not imported before they are approved, so their
    keys cannot be checked and ``None`` is returned.
    """
    from shadowscan.connectors import builtin_connector_names, get_connector_class

    if name not in builtin_connector_names():
        return None
    return frozenset(get_connector_class(name).config_keys) | SHARED_CONNECTOR_KEYS


def validate_connector_config(name: str, config: Mapping[Any, Any]) -> None:
    """Reject connector keys that would otherwise be ignored silently.

    Raises :class:`ConfigValidationError` naming the connector and the key
    (never its value) when a built-in connector does not read the key, or
    when any connector receives a reserved underscore-prefixed key.
    """
    shown_name = _display_identifier(name, "connector")
    accepted = accepted_connector_keys(name)
    for key in config:
        if not isinstance(key, str) or not key:
            raise ConfigValidationError(
                f"connector {shown_name}: configuration keys must be nonempty strings"
            )
        if key.startswith("_"):
            raise ConfigValidationError(
                f"connector {shown_name}: keys starting with an underscore are reserved for internal use"
            )
        if accepted is None or key in accepted:
            continue
        shown_key = _display_identifier(key, "an unsupported key")
        message = f"connector {shown_name} does not accept {shown_key}"
        close = difflib.get_close_matches(key, sorted(accepted), n=1, cutoff=0.75)
        if close:
            message += f" (did you mean '{close[0]}'?)"
        raise ConfigValidationError(message + "; run `shadowscan connectors` to list its options")


def connector_boolean(value: Any, name: str) -> bool:
    """Return a strict built-in connector boolean without Python truthiness.

    Native booleans and case-insensitive ``true`` / ``false`` strings are
    accepted.  Strings are necessary because environment interpolation occurs
    after YAML parsing.  Other spellings and scalar types are rejected rather
    than guessing at a security-sensitive switch.
    """
    return _strict_boolean(value, f"connector option {name}")


def normalize_connector_config(name: str, config: Mapping[Any, Any]) -> dict[str, Any]:
    """Validate and copy one connector configuration for programmatic callers."""
    _validate_config_graph(config)
    validate_connector_config(name, config)
    normalized = dict(config)
    if name == "code.filesystem" and "path" in normalized and "paths" in normalized:
        raise ConfigValidationError("connector 'code.filesystem': specify path or paths, not both")
    for key in _BOOLEAN_CONNECTOR_KEYS.get(name, frozenset()):
        if key in normalized:
            normalized[key] = connector_boolean(normalized[key], key)
    return normalized


def expand_env(value: Any) -> Any:
    if isinstance(value, str):

        def repl(m: re.Match[str]) -> str:
            name, fallback = m.group(1), m.group(2)
            resolved = os.environ.get(name)
            if resolved:
                return resolved
            if fallback is not None:
                return fallback
            raise ConfigValidationError(
                f"environment variable {sanitize_text(name)} is missing or empty; "
                "set it or use an explicit ${VAR:-default} fallback"
            )

        return _ENV_RX.sub(repl, value)
    if isinstance(value, list):
        return [expand_env(v) for v in value]
    if isinstance(value, dict):
        return {k: expand_env(v) for k, v in value.items()}
    return value


@dataclass(slots=True)
class ConnectorSpec:
    name: str
    config: dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    label: str | None = None  # optional distinct id when the same connector runs twice

    def __post_init__(self) -> None:
        self.name = _nonempty_string(self.name, "connector name")
        if not isinstance(self.config, dict):
            raise ConfigValidationError("connector config must be a mapping")
        self.enabled = _connector_enabled(self.enabled)
        if self.label is not None:
            self.label = _nonempty_string(self.label, "connector label")

    @property
    def id(self) -> str:
        return self.label or self.name


@dataclass(slots=True)
class ScanConfig:
    connectors: list[ConnectorSpec] = field(default_factory=list)
    inventory: list[str] = field(default_factory=list)
    signature_dirs: list[str] = field(default_factory=list)
    min_confidence: float = 0.0
    fail_on: str | None = None
    dump_records: str | None = None
    workdir: str | None = None
    parallel: int = 4
    incremental: bool = False
    state_dir: str | None = None
    plugins: list[str] = field(default_factory=list)
    allow_signature_override: bool = False
    allow_private_origin: bool = False
    allow_instance_credentials: bool = False
    allow_credential_mixing: bool = False
    connector_timeout_seconds: float = 120.0
    job_deadline_seconds: float | None = None  # CLI process deadline; embedding callers own supervision
    risk_basis: str = "combined"
    risk_weights: dict[str, Any] | None = field(default_factory=dict)
    source: str | None = None
    # Constructor-only compatibility: never retain stale alias state that could
    # overwrite a later CLI or library update to the canonical setting.
    connector_timeout: InitVar[float | None] = field(default=None, kw_only=True)

    def __post_init__(self, connector_timeout: float | None) -> None:
        if connector_timeout is not None:
            if self.connector_timeout_seconds != 120.0:
                raise ConfigValidationError(
                    "specify connector_timeout_seconds or connector_timeout, not both"
                )
            _warn_deprecated_once(
                "connector_timeout",
                "ScanConfig(connector_timeout=...) is deprecated; use connector_timeout_seconds",
            )
            self.connector_timeout_seconds = connector_timeout
        self.validate_security_options()
        self.validate_connector_specs()

    def validate_security_options(self) -> None:
        self.plugins = validate_plugins(self.plugins)
        self.allow_signature_override = _boolean_option(
            self.allow_signature_override, "allow_signature_override"
        )
        self.allow_private_origin = _boolean_option(self.allow_private_origin, "allow_private_origin")
        self.allow_instance_credentials = _boolean_option(
            self.allow_instance_credentials, "allow_instance_credentials"
        )
        self.allow_credential_mixing = _boolean_option(
            self.allow_credential_mixing, "allow_credential_mixing"
        )
        self.connector_timeout_seconds = validate_connector_timeout_seconds(self.connector_timeout_seconds)
        self.job_deadline_seconds = validate_job_deadline_seconds(self.job_deadline_seconds)
        self.incremental = _boolean_option(self.incremental, "incremental")
        if self.fail_on is not None and (
            not isinstance(self.fail_on, str) or self.fail_on not in _RISK_LEVELS
        ):
            raise ConfigValidationError("options.fail_on must be critical, high, medium, low, info, or null")
        self.parallel = _positive_integer(self.parallel, "options.parallel")
        if self.risk_weights is None:
            self.risk_weights = {}
        try:
            RiskPolicy.from_options(self.risk_weights, self.risk_basis)
        except ValueError as exc:
            raise ConfigValidationError(f"options.{exc}") from None

    def validate_connector_specs(self) -> None:
        """Validate programmatically constructed built-in connector specs.

        File-based configuration takes this path too, keeping one schema
        boundary for YAML, embedding callers, and configurations mutated
        between reusable engine runs. Third-party plugin options deliberately
        remain opaque.
        """
        if not isinstance(self.connectors, list):
            raise ConfigValidationError("connectors must be a list")
        for spec in self.connectors:
            if not isinstance(spec, ConnectorSpec):
                raise ConfigValidationError("each connector entry must be a ConnectorSpec")
            # ConnectorSpec validates its structural fields at construction,
            # but embedding callers may mutate them afterwards.
            spec.name = _nonempty_string(spec.name, "connector name")
            if not isinstance(spec.config, dict):
                raise ConfigValidationError("connector config must be a mapping")
            spec.enabled = _connector_enabled(spec.enabled)
            if spec.label is not None:
                spec.label = _nonempty_string(spec.label, "connector label")
            spec.config = normalize_connector_config(spec.name, spec.config)

    def validate_connector_isolation(self, specs: list[ConnectorSpec]) -> None:
        """Do not expose live connector credentials to an unrelated source parser."""
        if self.allow_credential_mixing:
            return
        code = [spec for spec in specs if spec.name.startswith("code.")]
        live = [
            spec
            for spec in specs
            if not spec.config.get("input")
            and (
                spec.name in {"code.github", "code.gitlab"}
                or (
                    spec.name.startswith(("cloud.", "identity.", "saas.", "lowcode."))
                    and spec.name != "identity.jwt"
                )
                or spec.name in self.plugins
            )
        ]
        if any(source is not credentialed for source in code for credentialed in live):
            raise ConfigValidationError(
                "code scanning and live credentialed connectors require separate scans; "
                "set options.allow_credential_mixing to true (or pass --allow-credential-mixing) "
                "only for reviewed inputs"
            )

    @classmethod
    def from_dict(cls, data: dict[str, Any], source: str | None = None) -> ScanConfig:
        if not isinstance(data, dict):
            raise ConfigValidationError("scan configuration must be a mapping")
        # Bound/cycle-check before environment expansion, whose recursive copy
        # assumes a finite acyclic graph. Known fields retain their more useful
        # field-specific numeric diagnostics; opaque connector values receive
        # finite-number validation in ``normalize_connector_config``.
        _validate_config_graph(data, reject_nonfinite=False)
        _check_fields(data, _CONFIG_FIELDS, "scan configuration")
        data = expand_env(data)
        opts = data.get("options", {})
        if not isinstance(opts, dict):
            raise ConfigValidationError("options must be a mapping")
        _check_fields(opts, _OPTION_FIELDS, "options")
        if "connector_timeout_seconds" in opts and "connector_timeout" in opts:
            raise ConfigValidationError(
                "specify options.connector_timeout_seconds or options.connector_timeout, not both"
            )
        timeout = opts.get("connector_timeout_seconds", 120.0)
        if "connector_timeout" in opts:
            # Older configurations used null for no deadline. Keep them usable
            # while enforcing the safe default instead of permitting infinity.
            _warn_deprecated_once(
                "connector_timeout",
                "options.connector_timeout is deprecated; use options.connector_timeout_seconds",
            )
            timeout = 120.0 if opts["connector_timeout"] is None else opts["connector_timeout"]
        connectors = data.get("connectors", [])
        if not isinstance(connectors, list):
            raise ConfigValidationError("connectors must be a list")
        specs: list[ConnectorSpec] = []
        for item in connectors:
            if isinstance(item, str):
                specs.append(ConnectorSpec(name=_nonempty_string(item, "connector name")))
                continue
            if not isinstance(item, dict):
                raise ConfigValidationError("each connector entry must be a name or mapping")
            item = dict(item)
            name = _nonempty_string(item.pop("name", None), "connector name")
            enabled = _connector_enabled(item.pop("enabled", True))
            label = item.pop("label", None)
            if label is not None:
                label = _nonempty_string(label, "connector label")
            if "config" in item and not isinstance(item["config"], dict):
                raise ConfigValidationError("connector config must be a mapping")
            cfg = item.pop("config", None)
            if isinstance(cfg, dict):
                overlap = next((key for key in item if key in cfg), None)
                if overlap is not None:
                    shown_key = _display_identifier(overlap, "a key")
                    shown_name = _display_identifier(name, "connector")
                    raise ConfigValidationError(
                        f"connector {shown_name}: inline options and nested config both define {shown_key}"
                    )
                item.update(cfg)
            validate_connector_config(name, item)
            specs.append(ConnectorSpec(name=name, config=item, enabled=enabled, label=label))
        base = Path(source).parent if source else Path()
        for spec in specs:
            for key in PATH_KEYS:
                val = spec.config.get(key)
                if isinstance(val, str) and val:
                    spec.config[key] = _resolve(base, val)
                elif isinstance(val, list):
                    spec.config[key] = [_resolve(base, v) if isinstance(v, str) else v for v in val]
        return cls(
            connectors=specs,
            inventory=[_resolve(base, p) for p in _path_list(data.get("inventory", []), "inventory")],
            signature_dirs=[_resolve(base, p) for p in _path_list(data.get("signatures", []), "signatures")],
            min_confidence=validate_min_confidence(opts.get("min_confidence", 0.0)),
            fail_on=opts.get("fail_on"),
            dump_records=_optional_path(base, opts.get("dump_records"), "options.dump_records"),
            workdir=_optional_path(base, opts.get("workdir"), "options.workdir"),
            parallel=_positive_integer(opts.get("parallel", 4), "options.parallel"),
            incremental=_boolean_option(opts.get("incremental", False), "incremental"),
            state_dir=_optional_path(base, opts.get("state_dir"), "options.state_dir"),
            plugins=validate_plugins(opts.get("plugins", [])),
            allow_signature_override=_boolean_option(
                opts.get("allow_signature_override", False), "allow_signature_override"
            ),
            allow_private_origin=_boolean_option(
                opts.get("allow_private_origin", False), "allow_private_origin"
            ),
            allow_instance_credentials=_boolean_option(
                opts.get("allow_instance_credentials", False), "allow_instance_credentials"
            ),
            allow_credential_mixing=_boolean_option(
                opts.get("allow_credential_mixing", False), "allow_credential_mixing"
            ),
            connector_timeout_seconds=validate_connector_timeout(timeout),
            job_deadline_seconds=validate_job_deadline_seconds(opts.get("job_deadline_seconds")),
            risk_basis=opts.get("risk_basis", "combined"),
            risk_weights=opts.get("risk_weights", {}),
            source=source,
        )

    @classmethod
    def from_yaml(cls, path: str | Path) -> ScanConfig:
        p = Path(path)
        text = read_policy_text(p)
        try:
            data = yaml.load(text, Loader=_ConfigLoader)
        except ConfigValidationError:
            raise
        except (ValueError, yaml.YAMLError) as exc:
            # SafeLoader raises a plain ValueError for an impossible date or an
            # integer beyond Python's digit limit; that is malformed YAML too.
            # PyYAML diagnostics may echo source snippets containing credentials.
            # Only the position (numbers) is kept so the mistake can be located.
            raise ConfigValidationError(
                "invalid YAML syntax or structural limits exceeded" + yaml_error_position(exc)
            ) from None
        if data is None:
            data = {}
        return cls.from_dict(data, source=str(p))

    def enabled_connectors(self) -> list[ConnectorSpec]:
        return [s for s in self.connectors if s.enabled]


def _resolve(base: Path, p: str) -> str:
    path = Path(p).expanduser()
    if path.is_absolute():
        return str(path)
    return str(base / path)


def _strict_boolean(value: Any, location: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized == "true":
            return True
        if normalized == "false":
            return False
    raise ConfigValidationError(f"{location} must be a boolean (true or false)")


def _boolean_option(value: Any, name: str) -> bool:
    # Options are parsed by YAML before environment expansion. Preserve the
    # existing native-boolean contract; only connector values document and
    # support string interpolation for booleans.
    if not isinstance(value, bool):
        raise ConfigValidationError(f"options.{name} must be a YAML boolean")
    return value


def validate_plugins(value: Any) -> list[str]:
    """Loading a connector imports arbitrary code, so approvals must be explicit names."""
    if not isinstance(value, list) or any(not isinstance(name, str) or not name.strip() for name in value):
        raise ConfigValidationError("options.plugins must be a list of nonempty connector names")
    return list(dict.fromkeys(name.strip() for name in value))


def _check_fields(value: dict[Any, Any], allowed: set[str], location: str) -> None:
    if any(not isinstance(key, str) or key not in allowed for key in value):
        raise ConfigValidationError(
            f"{location} contains an unsupported field; allowed fields: " + ", ".join(sorted(allowed))
        )


def _nonempty_string(value: Any, location: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigValidationError(f"{location} must be a nonempty string")
    return value


def _path_list(value: Any, location: str) -> list[str]:
    if not isinstance(value, list):
        raise ConfigValidationError(f"{location} must be a list of nonempty paths")
    return [_nonempty_string(path, location) for path in value]


def _optional_path(base: Path, value: Any, location: str) -> str | None:
    return None if value is None else _resolve(base, _nonempty_string(value, location))


def _positive_integer(value: Any, location: str) -> int:
    if isinstance(value, str) and re.fullmatch(r"[0-9]+", value):
        try:
            value = int(value)
        except ValueError:
            raise ConfigValidationError(f"{location} must be a positive integer") from None
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ConfigValidationError(f"{location} must be a positive integer")
    return value


class _ConfigLoader(BoundedSafeLoader):
    def flatten_mapping(self, node: yaml.MappingNode) -> None:
        # Check authored keys before flattening: YAML merge overrides are valid,
        # while a repeated key in one authored mapping silently changes policy.
        if node in self._flattened:
            return
        seen: set[str] = set()
        for key_node, _ in node.value:
            position = _node_position(key_node)
            if key_node.tag == "tag:yaml.org,2002:merge":
                key = "<<"
            elif key_node.tag == "tag:yaml.org,2002:str":
                key = key_node.value
            else:
                raise ConfigValidationError("configuration mapping keys must be strings" + position)
            if key in seen:
                raise ConfigValidationError("duplicate configuration mapping key" + position)
            seen.add(key)
        super().flatten_mapping(node)


def _node_position(node: yaml.Node) -> str:
    """Line and column of a YAML node for diagnostics; never its text."""
    mark = getattr(node, "start_mark", None)
    if (
        mark is None
        or not isinstance(getattr(mark, "line", None), int)
        or not isinstance(getattr(mark, "column", None), int)
    ):
        return ""
    return f" (line {mark.line + 1}, column {mark.column + 1})"


def _connector_enabled(value: Any) -> bool:
    """Expand environment-backed connector flags without relying on string truthiness."""
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"yes", "on", "1"}:
            return True
        if normalized in {"no", "off", "0"}:
            return False
    return _strict_boolean(value, "connector enabled")


def validate_connector_timeout_seconds(value: Any) -> float:
    message = "connector_timeout_seconds must be a positive finite number"
    if isinstance(value, bool):
        raise ConfigValidationError(message)
    try:
        timeout = float(value)
    except (TypeError, ValueError, OverflowError):
        raise ConfigValidationError(message) from None
    if not math.isfinite(timeout) or timeout <= 0:
        raise ConfigValidationError(message)
    return timeout


def validate_connector_timeout(value: Any) -> float:
    """Validate the deprecated spelling with the canonical finite deadline."""
    return validate_connector_timeout_seconds(value)


def validate_job_deadline_seconds(value: Any) -> float | None:
    """Optional CLI process deadline; null leaves supervision to the caller."""
    if value is None:
        return None
    try:
        return validate_connector_timeout_seconds(value)
    except ConfigValidationError:
        raise ConfigValidationError("job_deadline_seconds must be a positive finite number or null") from None


def validate_min_confidence(value: Any) -> float:
    """Keep invalid thresholds from silently filtering out all gated findings.

    Raises :class:`MinConfidenceError` (a ``ValueError``) whose message never
    echoes the rejected value.
    """
    message = "min_confidence must be a finite number between 0 and 1"
    if isinstance(value, bool):
        raise MinConfidenceError(message)
    try:
        confidence = float(value)
    except (TypeError, ValueError, OverflowError):
        raise MinConfidenceError(message) from None
    if not math.isfinite(confidence) or not 0 <= confidence <= 1:
        raise MinConfidenceError(message)
    return confidence


def parse_set_options(items: list[str]) -> dict[str, Any]:
    """Parse ``--set key=value`` pairs; JSON-ish values are decoded (lists, numbers, booleans)."""
    out: dict[str, Any] = {}
    for item in items:
        if "=" not in item:
            raise ValueError(f"--set expects key=value, got {item!r}")
        key, value = item.split("=", 1)
        key, value = key.strip(), value.strip()
        # Account IDs are identifiers: integer coercion loses leading zeros
        # and changes exact comparisons with provider-issued string IDs.
        out[key] = value if key == "account_id" and re.fullmatch(r"[0-9]+", value) else _coerce(value)
    return out


def _coerce(value: str) -> Any:
    low = value.lower()
    if low in {"true", "yes", "on"}:
        return True
    if low in {"false", "no", "off"}:
        return False
    if low in {"null", "none", ""}:
        return None
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    if re.fullmatch(r"-?\d+\.\d+", value):
        return float(value)
    if value.startswith(("[", "{")):
        try:
            return strict_json_loads(value)
        except JSONIntegrityError:
            raise ValueError("structured --set values require unique fields and finite numbers") from None
        except json.JSONDecodeError:
            pass
    if "," in value and not value.startswith(("http", "/")):
        return [v.strip() for v in value.split(",") if v.strip()]
    return value
