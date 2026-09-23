"""Connector base classes.

A connector scans one *surface* (code, identity, gateway, lowcode, saas, cloud)
for one provider / data source and yields :class:`Finding` objects.

Every connector supports two execution modes:

* **live** – talk to the provider's API with credentials from the config or
  environment (``collect()`` returns raw records);
* **offline** – read an export of the same records from a file (``input:``),
  which makes connectors usable without credentials, reproducible and testable.

``analyze()`` turns raw records into findings and is shared by both modes.
"""

from __future__ import annotations

import csv
import importlib
import json
import logging
import os
from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any, ClassVar

import yaml

from shadowscan.models import Finding, ScanStats, Surface, now_iso
from shadowscan.signatures import SignatureIndex, get_index


class ConnectorError(RuntimeError):
    """Raised when a connector cannot run at all (bad config, missing creds)."""


class ConnectorContext:
    """Runtime context handed to a connector."""

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        index: SignatureIndex | None = None,
        logger: logging.Logger | None = None,
        input_path: str | None = None,
        workdir: str | None = None,
    ):
        self.config: dict[str, Any] = dict(config or {})
        self.index: SignatureIndex = index or get_index()
        self.log = logger or logging.getLogger("shadowscan")
        self.input_path = input_path or self.config.get("input")
        self.workdir = workdir
        self.stats: ScanStats | None = None

    # ---------------------------------------------------------------- config
    def get(self, key: str, default: Any = None, env: str | None = None) -> Any:
        """Read a config key, falling back to an environment variable."""
        val = self.config.get(key)
        if val is None and env:
            val = os.environ.get(env)
        return default if val is None else val

    def require(self, key: str, env: str | None = None) -> Any:
        val = self.get(key, env=env)
        if val in (None, ""):
            hint = f" (or env {env})" if env else ""
            raise ConnectorError(f"missing required config '{key}'{hint}")
        return val

    def warn(self, msg: str) -> None:
        self.log.warning(msg)
        if self.stats is not None:
            self.stats.warnings.append(msg)

    def error(self, msg: str) -> None:
        self.log.error(msg)
        if self.stats is not None:
            self.stats.errors.append(msg)

    def examined(self, n: int = 1) -> None:
        if self.stats is not None:
            self.stats.objects_examined += n


class BaseConnector(ABC):
    """Base class for all connectors."""

    name: ClassVar[str] = "base"
    surface: ClassVar[Surface] = Surface.CODE
    description: ClassVar[str] = ""
    provider: ClassVar[str | None] = None
    requires: ClassVar[list[str]] = []  # optional python packages for live mode
    config_keys: ClassVar[dict[str, str]] = {}  # documentation: key -> description
    offline_formats: ClassVar[str] = "JSON / JSONL / YAML / CSV export"

    def __init__(self, ctx: ConnectorContext):
        self.ctx = ctx
        self.index = ctx.index
        self.log = ctx.log

    # ----------------------------------------------------------------- modes
    @property
    def offline(self) -> bool:
        return bool(self.ctx.input_path)

    def check_requirements(self) -> None:
        missing = []
        for mod in self.requires:
            try:
                importlib.import_module(mod)
            except ImportError:
                missing.append(mod)
        if missing:
            raise ConnectorError(
                f"{self.name}: live mode needs python packages {missing}; install the matching extra "
                f"(e.g. pip install 'shadowscan[cloud]') or use offline input"
            )

    @abstractmethod
    def collect(self) -> Iterable[dict[str, Any]]:
        """Fetch raw records from the live source."""

    @abstractmethod
    def analyze(self, records: Iterable[dict[str, Any]]) -> Iterable[Finding]:
        """Turn raw records into findings."""

    def load_offline(self, path: str) -> Iterator[dict[str, Any]]:
        """Load exported records from a file or directory of files."""
        p = Path(path)
        if p.is_dir():
            for f in sorted(p.rglob("*")):
                if f.is_file() and f.suffix.lower() in {".json", ".jsonl", ".ndjson", ".yaml", ".yml", ".csv"}:
                    yield from self.load_offline(str(f))
            return
        if not p.exists():
            raise ConnectorError(f"{self.name}: input file not found: {path}")
        suffix = p.suffix.lower()
        text = p.read_text(encoding="utf-8", errors="replace")
        if suffix in {".jsonl", ".ndjson"}:
            for line in text.splitlines():
                line = line.strip()
                if line:
                    yield json.loads(line)
        elif suffix == ".csv":
            yield from csv.DictReader(text.splitlines())
        elif suffix in {".yaml", ".yml"}:
            data = yaml.safe_load(text)
            yield from self._unwrap(data)
        else:
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                # tolerate JSON lines in a .json file
                for line in text.splitlines():
                    line = line.strip()
                    if line:
                        yield json.loads(line)
                return
            yield from self._unwrap(data)

    @staticmethod
    def _unwrap(data: Any) -> Iterator[dict[str, Any]]:
        """Accept a list of records or a dict wrapping a list under common keys."""
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    yield item
        elif isinstance(data, dict):
            for key in ("records", "items", "value", "data", "results", "resources", "logs", "entries", "plugins", "installations", "apps", "users", "members", "workflows", "scenarios", "aiAgents", "teamsApps", "servicePrincipals", "clients", "tokens", "agents", "bots", "flows", "Records", "logEvents", "hits"):
                if isinstance(data.get(key), list):
                    for item in data[key]:
                        if isinstance(item, dict):
                            yield item
                    return
            yield data

    # ------------------------------------------------------------------- run
    def _tee(self, records: Iterable[dict[str, Any]], path: str) -> Iterator[dict[str, Any]]:
        """Write every raw record to a JSONL file (for offline re-analysis / evidence retention)."""
        with open(path, "w", encoding="utf-8") as fh:
            for rec in records:
                try:
                    fh.write(json.dumps(rec, default=str) + "\n")
                except (TypeError, ValueError):
                    pass
                yield rec

    def run(self) -> list[Finding]:
        stats = ScanStats(connector=self.name, started_at=now_iso())
        self.ctx.stats = stats
        findings: list[Finding] = []
        try:
            if self.offline:
                records: Iterable[dict[str, Any]] = self.load_offline(str(self.ctx.input_path))
            else:
                self.check_requirements()
                records = self.collect()
            dump = self.ctx.config.get("_dump_path")
            if dump and not isinstance(self, _NoDump):
                records = self._tee(records, str(dump))
            for f in self.analyze(records):
                f.connector = self.name
                if f.provider is None:
                    f.provider = self.provider
                findings.append(f)
        except ConnectorError as exc:
            stats.skipped = True
            stats.skip_reason = str(exc)
            self.ctx.error(str(exc))
        except Exception as exc:  # noqa: BLE001 - connectors must never abort the whole scan
            self.ctx.error(f"{self.name}: {type(exc).__name__}: {exc}")
            self.log.debug("connector failure", exc_info=True)
        stats.finished_at = now_iso()
        stats.findings = len(findings)
        return findings


class _NoDump:
    """Mixin marker for connectors whose records are not worth dumping (e.g. filesystem walks)."""
