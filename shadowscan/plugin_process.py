"""Killable plugin workers; lifecycle isolation, never a security sandbox.

Only trusted first-party configuration and signature objects travel through
``spawn``. Plugin results use a size-bounded JSON socket stream, never pickle.
Dedicated processes allow individual timeouts on Python 3.11, where cancelling
a ProcessPoolExecutor future cannot stop a running worker.
"""

from __future__ import annotations

import json
import multiprocessing
import os
import re
import socket
import time
from dataclasses import asdict, replace
from multiprocessing.process import BaseProcess
from pathlib import Path
from typing import TYPE_CHECKING, Any

from shadowscan.config import ConnectorSpec, ScanConfig
from shadowscan.models import Finding, ScanStats, now_iso
from shadowscan.signatures import Signature, SignatureIndex
from shadowscan.utils.redaction import sanitize
from shadowscan.utils.safe_json import strict_json_loads

if TYPE_CHECKING:
    from shadowscan.engine import _ConnectorRunner, _JobResult, _JobState

MAX_RESULT_BYTES = 16 * 1024 * 1024
_CLEANUP_SECONDS = 0.5


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    return remaining


def _encode_result(value: dict[str, Any]) -> bytes:
    output = bytearray()
    for chunk in json.JSONEncoder(allow_nan=False, separators=(",", ":")).iterencode(value):
        output.extend(chunk.encode("utf-8"))
        if len(output) > MAX_RESULT_BYTES:
            raise ValueError("plugin result exceeds transport limit")
    return bytes(output)


def _worker(
    channel: socket.socket,
    config: ScanConfig,
    signatures: list[Signature],
    number: int,
    deadline: float,
    identity_key: bytes,
) -> None:
    """Import and execute the approved plugin only inside its spawned process."""
    # A plugin's print/log calls may contain credentials. Diagnostics must come
    # through the scanner's sanitized result, not inherited stdout or stderr.
    with open(os.devnull, "w") as sink:
        os.dup2(sink.fileno(), 1)
        os.dup2(sink.fileno(), 2)
    try:
        from shadowscan.engine import Engine, _ConnectorRunner, _ExportLedger, _JobState
        from shadowscan.incremental import IncrementalCache

        index = SignatureIndex(signatures)
        engine = Engine(config, index)
        exports = _ExportLedger()
        runner = _ConnectorRunner(
            engine,
            IncrementalCache(config, index),
            Path(config.dump_records) if config.dump_records else None,
            exports,
        )
        runner._run_identity_key = identity_key
        state = _JobState(started_at=now_iso(), deadline=deadline)
        spec = config.connectors[0]
        _, findings, stats = runner._run_job(number, spec, state)
        payload = _encode_result(
            {
                "findings": [finding.to_dict() for finding in findings],
                "stats": asdict(stats),
                "exports": exports.entries([(number, spec)], set()),
            }
        )
    except BaseException:  # noqa: BLE001 - a plugin may raise SystemExit; never echo its exception
        payload = b'{"error":"plugin worker failed or its result exceeded the transport limit"}'
    try:
        channel.settimeout(_remaining(deadline))
        channel.sendall(payload)
    except (OSError, TimeoutError):
        pass
    finally:
        channel.close()


def _receive(channel: socket.socket, deadline: float) -> bytes:
    """Bound both frame size and partial writes by the original job deadline."""
    result = bytearray()
    while True:
        channel.settimeout(_remaining(deadline))
        chunk = channel.recv(min(65536, MAX_RESULT_BYTES + 1 - len(result)))
        if not chunk:
            return bytes(result)
        result.extend(chunk)
        if len(result) > MAX_RESULT_BYTES:
            raise ValueError("plugin result exceeds transport limit")


def _stop(process: BaseProcess) -> None:
    if process.pid is None:
        return
    if process.is_alive():
        process.terminate()
        process.join(_CLEANUP_SECONDS)
    if process.is_alive():
        process.kill()
        process.join(_CLEANUP_SECONDS)
    if process.is_alive():
        # An OS task in uninterruptible kernel sleep cannot be forcibly reaped
        # even by SIGKILL. Do not hide that exceptional cleanup failure.
        raise RuntimeError("plugin worker could not be reaped; external process supervision required")
    process.close()


def _decode_result(
    payload: bytes, number: int, spec: ConnectorSpec
) -> tuple[list[Finding], ScanStats, list[dict[str, Any]]]:
    data = strict_json_loads(payload)
    if not isinstance(data, dict) or set(data) != {"findings", "stats", "exports"}:
        raise ValueError("invalid plugin result envelope")
    if not isinstance(data["findings"], list) or not isinstance(data["exports"], list):
        raise ValueError("invalid plugin result arrays")
    raw = data["stats"]
    if not isinstance(raw, dict) or set(raw) != set(asdict(ScanStats("", ""))):
        raise ValueError("invalid plugin statistics")
    for key in ("connector", "started_at"):
        if not isinstance(raw[key], str):
            raise ValueError("invalid plugin statistics string")
    for key in ("finished_at", "skip_reason"):
        if raw[key] is not None and not isinstance(raw[key], str):
            raise ValueError("invalid plugin statistics optional string")
    for key in ("findings", "objects_examined"):
        if type(raw[key]) is not int or raw[key] < 0:
            raise ValueError("invalid plugin statistics count")
    for key in ("incomplete", "skipped", "cached"):
        if type(raw[key]) is not bool:
            raise ValueError("invalid plugin statistics flag")
    for key in ("errors", "warnings"):
        if not isinstance(raw[key], list) or any(not isinstance(item, str) for item in raw[key]):
            raise ValueError("invalid plugin diagnostics")
    stats = ScanStats(**sanitize(raw))
    stats.connector = spec.id
    stats.incomplete = stats.incomplete or stats.skipped or bool(stats.errors)
    findings = [Finding.from_dict(item) for item in data["findings"]]
    if any(finding.connector != spec.name for finding in findings) or stats.findings != len(findings):
        raise ValueError("invalid plugin finding attribution or count")
    exports = data["exports"]
    for entry in exports:
        if not isinstance(entry, dict) or set(entry) != {
            "config_ordinal",
            "part",
            "connector",
            "label",
            "filename",
            "complete",
            "exported",
        }:
            raise ValueError("invalid plugin export")
        if entry["config_ordinal"] != number or entry["connector"] != spec.name:
            raise ValueError("invalid plugin export attribution")
        part = entry["part"]
        if not isinstance(part, str) or not re.fullmatch(rf"{number:04d}(?:-[0-9]+)?", part):
            raise ValueError("invalid plugin export part")
        filename = entry["filename"]
        if filename is not None and (
            not isinstance(filename, str) or Path(filename).name != filename or filename in {".", ".."}
        ):
            raise ValueError("invalid plugin export filename")
        if type(entry["complete"]) is not bool or type(entry["exported"]) is not bool:
            raise ValueError("invalid plugin export flags")
        entry["label"] = spec.label
    return findings, stats, exports


def _run_plugin_process(
    runner: _ConnectorRunner, number: int, spec: ConnectorSpec, state: _JobState
) -> _JobResult:
    """Supervise one child and reject timeout, crash, or malformed/oversized output."""
    assert state.deadline is not None
    deadline = state.deadline
    # Do not transmit sibling configurations or load inventory in this child.
    config = replace(runner._config, connectors=[spec], inventory=[], plugin_execution="thread")
    parent, child = socket.socketpair()
    try:
        process = multiprocessing.get_context("spawn").Process(
            target=_worker,
            args=(
                child,
                config,
                list(runner._index.signatures.values()),
                number,
                deadline,
                runner._run_identity_key,
            ),
            daemon=True,
            name="shadowscan-plugin",
        )
    except Exception:
        parent.close()
        child.close()
        raise

    def kill_process() -> None:
        try:
            if process.pid is not None and process.is_alive():
                process.kill()
        except (OSError, ValueError):
            pass  # The worker may already have exited or closed its process handle.

    state.kill_process = kill_process
    runner._engine._report_progress(spec.id, "starting (process)")
    result: _JobResult | None = None
    message = "plugin process failed, crashed, or returned invalid/oversized output; results discarded"
    warnings: list[str] = []
    try:
        _remaining(deadline)
        process.start()
        if state.cancelled.is_set():
            raise TimeoutError
        child.close()
        payload = _receive(parent, deadline)
        process.join(_remaining(deadline))
        _remaining(deadline)
        if process.exitcode != 0:
            raise ValueError("plugin worker did not exit successfully")
        findings, stats, entries = _decode_result(payload, number, spec)
        _remaining(deadline)
        if state.cancelled.is_set():
            raise TimeoutError
        result = spec, findings, stats
    except TimeoutError:
        message = "connector_timeout completion deadline exceeded; plugin process results discarded"
        warnings = [
            "Plugin worker terminated; its descendants and external side effects are not rolled back."
        ]
    except Exception:  # noqa: BLE001 - no fallback or unsafe exception/configuration diagnostics
        pass
    finally:
        parent.close()
        child.close()
        try:
            _stop(process)
        except RuntimeError as exc:
            result = None
            message = str(exc)
    if result is not None:
        runner._engine._report_progress(spec.id, f"{len(result[1])} findings (process)")
        if not state.cancelled.is_set() and time.monotonic() < deadline:
            for entry in entries:
                runner._exports.record(state, entry)
            return result
        message = "connector_timeout completion deadline exceeded; plugin process results discarded"
    runner._exports.record(
        state,
        {
            "config_ordinal": number,
            "part": f"{number:04d}",
            "connector": spec.name,
            "label": spec.label,
            "filename": None,
            "complete": False,
            "exported": False,
        },
    )
    state.cancelled.set()
    return (
        spec,
        [],
        ScanStats(
            connector=spec.id,
            started_at=state.started_at or now_iso(),
            finished_at=now_iso(),
            incomplete=True,
            skipped=True,
            skip_reason=message,
            errors=[message],
            warnings=warnings,
        ),
    )


def run_plugin_process(
    runner: _ConnectorRunner, number: int, spec: ConnectorSpec, state: _JobState
) -> _JobResult:
    """Keep process setup/resource failures fail-closed just like worker failures."""
    try:
        return _run_plugin_process(runner, number, spec, state)
    except Exception:  # noqa: BLE001 - report a fixed diagnostic, never configuration or exception text
        runner._exports.record(
            state,
            {
                "config_ordinal": number,
                "part": f"{number:04d}",
                "connector": spec.name,
                "label": spec.label,
                "filename": None,
                "complete": False,
                "exported": False,
            },
        )
        state.cancelled.set()
        message = "plugin process setup or supervision failed; results discarded"
        return (
            spec,
            [],
            ScanStats(
                connector=spec.id,
                started_at=state.started_at or now_iso(),
                finished_at=now_iso(),
                incomplete=True,
                skipped=True,
                skip_reason=message,
                errors=[message],
            ),
        )
