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

``${VAR}`` / ``${VAR:-default}`` references are expanded from the environment.
"""

from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from shadowscan.utils.files import read_policy_text
from shadowscan.utils.safe_yaml import bounded_safe_load

_ENV_RX = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")
PATH_KEYS = ("input", "path", "paths", "service_account_file", "config_file", "token_file")
_SECRET_KEY_NAMES = frozenset({
    "token", "secret", "password", "passwd", "jwt", "bearer", "authorization",
    "cookie", "credential", "credentials", "apikey", "api_key",
})
_SECRET_KEY_SUFFIXES = (
    "token", "secret", "password", "passwd", "private_key", "privatekey",
    "access_key", "accesskey", "secret_key", "secretkey", "api_key", "apikey",
    "client_secret", "refresh_token", "session_token", "signing_key",
    "connection_string", "connstr",
)
DEFAULT_CONNECTOR_TIMEOUT = 300
MAX_CONNECTOR_TIMEOUT = 3600


def _is_secret_key(key: str | None) -> bool:
    if not key:
        return False
    name = key.strip().lower().replace("-", "_")
    compact = name.replace("_", "")
    if name in _SECRET_KEY_NAMES or compact in _SECRET_KEY_NAMES:
        return True
    return any(name.endswith(suffix) or compact.endswith(suffix.replace("_", "")) for suffix in _SECRET_KEY_SUFFIXES)


def expand_env(value: Any, *, key: str | None = None) -> Any:
    if isinstance(value, str):
        secret = _is_secret_key(key)

        def repl(m: re.Match[str]) -> str:
            name = m.group(1)
            default = m.group(2)
            if name in os.environ:
                raw = os.environ[name]
            elif default is not None:
                raw = default
            else:
                raw = None
            if secret and (raw is None or raw == ""):
                raise ValueError(f"missing required environment variable {name}")
            return "" if raw is None else raw

        expanded = _ENV_RX.sub(repl, value)
        if secret and not str(expanded).strip():
            raise ValueError(f"missing required secret '{key}'")
        return expanded
    if isinstance(value, list):
        return [expand_env(v, key=key) for v in value]
    if isinstance(value, dict):
        return {k: expand_env(v, key=k) for k, v in value.items()}
    return value


@dataclass(slots=True)
class ConnectorSpec:
    name: str
    config: dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    label: str | None = None  # optional distinct id when the same connector runs twice

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
    connector_timeout: int = DEFAULT_CONNECTOR_TIMEOUT
    source: str | None = None

    def __post_init__(self) -> None:
        self.validate_security_options()

    def validate_security_options(self) -> None:
        self.plugins = validate_plugins(self.plugins)
        self.allow_signature_override = _boolean_option(self.allow_signature_override, "allow_signature_override")
        self.allow_private_origin = _boolean_option(self.allow_private_origin, "allow_private_origin")
        self.connector_timeout = validate_connector_timeout(self.connector_timeout)

    @classmethod
    def from_dict(cls, data: dict[str, Any], source: str | None = None) -> ScanConfig:
        if not isinstance(data, dict):
            raise ValueError("scan configuration must be a mapping")
        data = expand_env(data or {})
        opts = data.get("options") or {}
        if not isinstance(opts, dict):
            raise ValueError("options must be a mapping")
        specs: list[ConnectorSpec] = []
        for item in data.get("connectors") or []:
            if isinstance(item, str):
                specs.append(ConnectorSpec(name=item))
                continue
            if not isinstance(item, dict) or not item.get("name"):
                raise ValueError("each connector entry needs a 'name'")
            item = dict(item)
            name = str(item.pop("name"))
            enabled = _connector_enabled(item.pop("enabled", True))
            label = item.pop("label", None)
            cfg = item.pop("config", None)
            if isinstance(cfg, dict):
                item.update(cfg)
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
            inventory=[_resolve(base, p) for p in (data.get("inventory") or [])],
            signature_dirs=[_resolve(base, p) for p in (data.get("signatures") or [])],
            min_confidence=validate_min_confidence(opts.get("min_confidence", 0.0)),
            fail_on=opts.get("fail_on"),
            dump_records=_resolve(base, opts["dump_records"]) if opts.get("dump_records") else None,
            workdir=opts.get("workdir"),
            parallel=int(opts.get("parallel", 4)),
            incremental=_boolean_option(opts.get("incremental", False), "incremental"),
            state_dir=_resolve(base, opts["state_dir"]) if opts.get("state_dir") else None,
            plugins=validate_plugins(opts.get("plugins", [])),
            allow_signature_override=_boolean_option(opts.get("allow_signature_override", False), "allow_signature_override"),
            allow_private_origin=_boolean_option(opts.get("allow_private_origin", False), "allow_private_origin"),
            connector_timeout=validate_connector_timeout(opts.get("connector_timeout", DEFAULT_CONNECTOR_TIMEOUT)),
            source=source,
        )

    @classmethod
    def from_yaml(cls, path: str | Path) -> ScanConfig:
        p = Path(path)
        data = bounded_safe_load(read_policy_text(p))
        if data is None:
            data = {}
        return cls.from_dict(data, source=str(p))

    def enabled_connectors(self) -> list[ConnectorSpec]:
        return [s for s in self.connectors if s.enabled]


def _resolve(base: Path, p: str) -> str:
    path = Path(p).expanduser()
    if path.is_absolute() or any(ch in p for ch in "*?["):
        return str(path)
    return str(base / path)


def _boolean_option(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"options.{name} must be a YAML boolean")
    return value


def validate_plugins(value: Any) -> list[str]:
    """Loading a connector imports arbitrary code, so approvals must be explicit names."""
    if not isinstance(value, list) or any(not isinstance(name, str) or not name.strip() for name in value):
        raise ValueError("options.plugins must be a list of nonempty connector names")
    return list(dict.fromkeys(name.strip() for name in value))


def _connector_enabled(value: Any) -> bool:
    """Expand environment-backed connector flags without relying on string truthiness."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "on", "1"}:
            return True
        if normalized in {"false", "no", "off", "0"}:
            return False
    raise ValueError("connector enabled must be a boolean (true or false)")


def validate_connector_timeout(value: Any) -> int:
    message = f"connector_timeout must be an integer between 1 and {MAX_CONNECTOR_TIMEOUT}"
    if isinstance(value, bool) or not isinstance(value, int):
        try:
            if isinstance(value, bool) or isinstance(value, float):
                raise ValueError(message)
            value = int(value)
        except (TypeError, ValueError):
            raise ValueError(message) from None
    if value < 1 or value > MAX_CONNECTOR_TIMEOUT:
        raise ValueError(message)
    return value


def validate_min_confidence(value: Any) -> float:
    """Keep invalid thresholds from silently filtering out all gated findings."""
    message = "min_confidence must be a finite number between 0 and 1"
    if isinstance(value, bool):
        raise ValueError(message)
    try:
        confidence = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(message) from exc
    if not math.isfinite(confidence) or not 0 <= confidence <= 1:
        raise ValueError(message)
    return confidence


def parse_set_options(items: list[str]) -> dict[str, Any]:
    """Parse ``--set key=value`` pairs; JSON-ish values are decoded (lists, numbers, booleans)."""
    out: dict[str, Any] = {}
    for item in items:
        if "=" not in item:
            raise ValueError(f"--set expects key=value, got {item!r}")
        key, value = item.split("=", 1)
        out[key.strip()] = _coerce(value.strip())
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
            import json

            return json.loads(value)
        except ValueError:
            pass
    if "," in value and not value.startswith(("http", "/")):
        return [v.strip() for v in value.split(",") if v.strip()]
    return value
