"""Scan configuration (YAML file and/or CLI options).

Example ``shadowscan.yaml``::

    inventory:
      - ./inventory/            # Agent Capability Cards / agents.yaml / CSV
    signatures:
      - ./custom-signatures/    # extra or overriding signature packs
    options:
      min_confidence: 0.3
      fail_on: high             # exit non-zero when a finding reaches this level
      dump_records: ./exports   # save raw connector records (JSONL) for offline re-analysis
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

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_ENV_RX = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")
PATH_KEYS = ("input", "path", "paths", "service_account_file", "config_file", "token_file")


def expand_env(value: Any) -> Any:
    if isinstance(value, str):
        def repl(m: re.Match[str]) -> str:
            return os.environ.get(m.group(1), m.group(2) if m.group(2) is not None else "")

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
    source: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any], source: str | None = None) -> ScanConfig:
        data = expand_env(data or {})
        opts = data.get("options") or {}
        specs: list[ConnectorSpec] = []
        for item in data.get("connectors") or []:
            if isinstance(item, str):
                specs.append(ConnectorSpec(name=item))
                continue
            if not isinstance(item, dict) or not item.get("name"):
                raise ValueError("each connector entry needs a 'name'")
            item = dict(item)
            name = str(item.pop("name"))
            enabled = bool(item.pop("enabled", True))
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
            min_confidence=float(opts.get("min_confidence", 0.0)),
            fail_on=opts.get("fail_on"),
            dump_records=_resolve(base, opts["dump_records"]) if opts.get("dump_records") else None,
            workdir=opts.get("workdir"),
            parallel=int(opts.get("parallel", 4)),
            source=source,
        )

    @classmethod
    def from_yaml(cls, path: str | Path) -> ScanConfig:
        p = Path(path)
        with p.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        return cls.from_dict(data, source=str(p))

    def enabled_connectors(self) -> list[ConnectorSpec]:
        return [s for s in self.connectors if s.enabled]


def _resolve(base: Path, p: str) -> str:
    path = Path(p).expanduser()
    if path.is_absolute() or any(ch in p for ch in "*?["):
        return str(path)
    return str(base / path)


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
