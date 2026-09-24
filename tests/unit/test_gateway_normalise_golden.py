"""Golden replay of gateway log normalisation and caller findings.

Every file under ``tests/fixtures/gateway_golden/`` pins, for one input, the
observable behaviour of the gateway connector: the schema detected for each
expanded record, the ``Event`` that ``_normalise`` builds from it, the findings
the connector emits (``Finding.to_dict``) and the diagnostics it records. The
goldens were generated from the normaliser before it was decomposed into
per-schema functions, so any later refactor is held to identical output.

A golden's input is either a fixture file under ``tests/fixtures/gateway/``
(``"input"``) or inline content the test writes to a temporary file:
``"records"`` (JSON objects written as JSONL) or ``"lines"`` (text written
verbatim, with the file extension in ``"suffix"``). ``"config"`` carries any
additional connector configuration.

The comparison ignores only ``VOLATILE_FINDING_FIELDS``. Everything else,
including opaque HMAC caller and scope identities, is deterministic because
the test pins the gateway identity key.

Regenerate the output sections after an intentional behaviour change with::

    SHADOWSCAN_UPDATE_GATEWAY_GOLDENS=1 pytest tests/unit/test_gateway_normalise_golden.py

and review the resulting diff before committing it.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from shadowscan.connectors import ConnectorContext
from shadowscan.connectors.base import ConnectorError
from shadowscan.connectors.gateway.logs import NORMALISERS, GatewayLogConnector, _normalise, detect_schema
from shadowscan.signatures.matcher import MatchTimeoutError

GATEWAY_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "gateway"
GOLDEN_DIR = GATEWAY_FIXTURES.parent / "gateway_golden"  # outside gateway/ so a directory scan of the samples never ingests goldens

# A fixed key makes every HMAC-derived opaque identity reproducible. It is a
# test constant, never a secret.
IDENTITY_KEY = b"shadowscan-gateway-golden-identity-key"

# Volatile finding fields, as dotted paths into ``Finding.to_dict()``:
#
# * ``id`` is hashed together with the source id.
# * ``metadata.runtime_source.id`` is an HMAC over the connector configuration,
#   which includes the absolute, resolved input path of the checkout.
# * ``metadata.runtime_source.input`` is that absolute path itself.
#
# Each finding entry instead carries ``identity`` (``Finding.compute_id``),
# which depends only on the finding's own fields.
VOLATILE_FINDING_FIELDS = ("id", "metadata.runtime_source.id", "metadata.runtime_source.input")

SUPPORTED_SCHEMAS = frozenset({
    "litellm", "portkey", "kong", "cloudflare", "helicone", "langfuse", "bedrock",
    "azure-openai", "vertex", "openai-usage", "anthropic-usage", "access-log", "generic",
})

_RECORD_ERRORS = (
    ValueError, TypeError, AttributeError, KeyError, OverflowError,
    RecursionError, ConnectorError, MatchTimeoutError,
)


def _update_requested() -> bool:
    return os.environ.get("SHADOWSCAN_UPDATE_GATEWAY_GOLDENS") == "1"


def _golden_paths() -> list[Path]:
    return sorted(GOLDEN_DIR.glob("*.json"))


def _load(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _materialise_input(golden: dict[str, Any], tmp_path: Path) -> Path:
    """Return the input path for a golden, writing inline content to ``tmp_path``."""
    if "input" in golden:
        return GATEWAY_FIXTURES / golden["input"]
    if "records" in golden:
        path = tmp_path / ("input" + golden.get("suffix", ".jsonl"))
        path.write_text("".join(json.dumps(record) + "\n" for record in golden["records"]), encoding="utf-8")
        return path
    path = tmp_path / ("input" + golden.get("suffix", ".log"))
    path.write_text("\n".join(golden["lines"]) + "\n", encoding="utf-8")
    return path


def _connector(index, path: Path, config: dict[str, Any]) -> GatewayLogConnector:
    ctx = ConnectorContext(config={"input": str(path), **config}, index=index, gateway_identity_key=IDENTITY_KEY)
    return GatewayLogConnector(ctx)


def _jsonable(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _normalised_events(connector: GatewayLogConnector, path: Path) -> list[dict[str, Any]]:
    """Detect the schema of every expanded record and normalise it, as analyze() does."""
    events = []
    for record in connector.load_offline(str(path)):
        schema = connector.format or detect_schema(record)
        try:
            event = _normalise(record, schema)
        except _RECORD_ERRORS as exc:
            events.append({"schema": schema, "error": f"{type(exc).__name__}: {exc}"})
            continue
        events.append({"schema": schema, "event": None if event is None else _jsonable(asdict(event))})
    return events


def _without_volatile(finding: dict[str, Any]) -> dict[str, Any]:
    for dotted in VOLATILE_FINDING_FIELDS:
        *parents, leaf = dotted.split(".")
        node: Any = finding
        for part in parents:
            node = node.get(part) if isinstance(node, dict) else None
        if isinstance(node, dict):
            node.pop(leaf, None)
    return finding


def observe(index, golden: dict[str, Any], tmp_path: Path) -> dict[str, Any]:
    """Run the connector on a golden's input and collect its observable output."""
    path = _materialise_input(golden, tmp_path)
    config = golden.get("config", {})
    events = _normalised_events(_connector(index, path, config), path)
    connector = _connector(index, path, config)
    findings = connector.run()
    stats = connector.ctx.stats
    assert stats is not None
    return {
        "events": events,
        "findings": [
            {"identity": finding.compute_id(), **_without_volatile(finding.to_dict())}
            for finding in findings
        ],
        "diagnostics": {
            "warnings": list(stats.warnings),
            "errors": list(stats.errors),
            "objects_examined": stats.objects_examined,
            "incomplete": stats.incomplete,
            "skipped": stats.skipped,
        },
    }


def _write(path: Path, golden: dict[str, Any], observed: dict[str, Any]) -> None:
    updated = {key: value for key, value in golden.items() if key not in ("events", "findings", "diagnostics")}
    updated["volatile_fields"] = list(VOLATILE_FINDING_FIELDS)
    updated.update(observed)
    path.write_text(json.dumps(updated, indent=1, allow_nan=False) + "\n", encoding="utf-8")


@pytest.mark.parametrize("golden_path", _golden_paths(), ids=lambda path: path.stem)
def test_golden_replay(index, tmp_path, golden_path):
    golden = _load(golden_path)
    observed = json.loads(json.dumps(observe(index, golden, tmp_path), allow_nan=False))
    if _update_requested():
        # Regenerate, then still verify the rewritten file so update mode can never pass silently.
        _write(golden_path, golden, observed)
        golden = _load(golden_path)
    assert golden["volatile_fields"] == list(VOLATILE_FINDING_FIELDS)
    expected = {key: golden[key] for key in ("events", "findings", "diagnostics")}
    assert observed == expected
    # Dict equality ignores key order; the report layout must not drift either.
    assert json.dumps(observed) == json.dumps(expected), "field order changed"


def test_goldens_cover_every_supported_schema():
    if _update_requested():
        pytest.skip("golden files are being regenerated")
    seen = {entry["schema"] for path in _golden_paths() for entry in _load(path)["events"]}
    assert seen == SUPPORTED_SCHEMAS


def test_registry_matches_supported_schemas_and_falls_back_to_generic():
    assert set(NORMALISERS) == SUPPORTED_SCHEMAS
    for schema, normaliser in NORMALISERS.items():
        assert normaliser.__name__ == "_normalise_" + schema.replace("-", "_")
    record = {"api_key": "k", "model": "gpt-4o", "provider": "openai"}
    event = _normalise(record, "not-a-schema")
    assert event is not None and event.schema == "generic" and event.caller == "api-key:k"
    assert _normalise({"model": "gpt-4o"}, "generic") is None
