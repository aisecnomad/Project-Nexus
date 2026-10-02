"""Killable plugin workers; lifecycle isolation, never a security sandbox.

Only trusted first-party configuration and signature objects travel through
``spawn``. Plugin results use one length-prefixed, size-bounded JSON message
on a socket, never pickle.
Dedicated processes allow individual timeouts on Python 3.11, where cancelling
a ProcessPoolExecutor future cannot stop a running worker.
"""

from __future__ import annotations

import json
import multiprocessing
import multiprocessing.connection
import os
import re
import socket
import sys
import threading
import time
from collections.abc import Iterable
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
_LENGTH_BYTES = 8
_CLEANUP_SECONDS = 0.5
# Socket and multiprocessing waits overflow beyond about 24.8 days. Waits use
# slices of at most a day, so a very large connector timeout still works.
_MAX_WAIT_SECONDS = 86_400.0
# A worker stops itself this long after its deadline, matching the parent's
# supervision guard, in case nothing in the scanner is left to terminate it.
_WORKER_GRACE_SECONDS = 2.0


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    return remaining


def _wait_slice(deadline: float) -> float:
    """The time left before *deadline*, at most one wait slice; TimeoutError once it has passed."""
    return min(_remaining(deadline), _MAX_WAIT_SECONDS)


def _encode_result(value: dict[str, Any]) -> bytes:
    # Match ScanResult.to_json: values JSON cannot represent (datetime, set,
    # bytes) become str() as in a thread-mode report, then the parent's
    # Finding.from_dict sanitizes them. NaN and infinity still fail closed.
    output = bytearray()
    encoder = json.JSONEncoder(allow_nan=False, separators=(",", ":"), default=str)
    for chunk in encoder.iterencode(value):
        output.extend(chunk.encode("utf-8"))
        if len(output) > MAX_RESULT_BYTES:
            raise ValueError("plugin result exceeds transport limit")
    return bytes(output)


def _exit_with_scanner(deadline: float) -> None:
    """Stop this worker when the scanner process exits or the deadline grace ends.

    The scanner can exit without running its cleanup (the job-deadline
    watchdog's ``os._exit``, SIGTERM or SIGKILL). A plugin that ignores its
    deadline would then keep running, with its credentials, as an orphan.
    The parent sentinel becomes readable as soon as the scanner process is gone.
    """
    parent = multiprocessing.parent_process()
    sentinels = [parent.sentinel] if parent is not None else []

    def watch() -> None:
        try:
            end = deadline + _WORKER_GRACE_SECONDS
            while (remaining := end - time.monotonic()) > 0:
                wait = min(remaining, _MAX_WAIT_SECONDS)
                if sentinels:
                    if multiprocessing.connection.wait(sentinels, wait):
                        break
                else:
                    time.sleep(wait)
        finally:
            os._exit(1)

    threading.Thread(target=watch, name="shadowscan-plugin-watchdog", daemon=True).start()


def _keep_descriptors_from_programs() -> None:
    """Programs a plugin starts must not inherit this worker's descriptors.

    Spawn passes the result socket and multiprocessing's liveness pipe as
    inheritable descriptors. A program still holding the liveness pipe keeps
    the parent from seeing this worker exit, so a result that already arrived
    would be discarded at the deadline.
    """
    for listing in ("/proc/self/fd", "/dev/fd"):
        try:
            descriptors: Iterable[int] = [int(name) for name in os.listdir(listing)]
            break
        except (OSError, ValueError):
            continue
    else:
        descriptors = range(3, 4096)
    for descriptor in descriptors:
        if descriptor > 2:
            try:
                os.set_inheritable(descriptor, False)
            except OSError:
                pass  # Closed meanwhile, such as the directory listing's own descriptor.


def _worker(
    channel: socket.socket,
    config: ScanConfig,
    signatures: list[Signature],
    number: int,
    deadline: float,
    identity_key: bytes,
    dump_directory: Path | None,
) -> None:
    """Import and execute the approved plugin only inside its spawned process."""
    _keep_descriptors_from_programs()
    _exit_with_scanner(deadline)
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
            # The parent's prepare_private_directory result: expanded, symlink
            # free, owned and 0700. Never re-derive it from the raw option.
            dump_directory,
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
        status = 0
    except BaseException:  # noqa: BLE001 - a plugin may raise SystemExit; never echo its exception
        payload = b'{"error":"plugin worker failed or its result exceeded the transport limit"}'
        status = 1
    try:
        try:
            channel.settimeout(_wait_slice(deadline))
            channel.sendall(len(payload).to_bytes(_LENGTH_BYTES, "big") + payload)
        finally:
            channel.close()
    except BaseException:  # noqa: BLE001 - an unsent result is a failed worker
        status = 1
    finally:
        # Exit now: a plugin's lingering non-daemon threads or atexit handlers
        # must not delay, and so discard, a result that was already sent.
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.flush()
            except Exception:  # noqa: BLE001 - output goes to /dev/null
                pass
        os._exit(status)


def _read_exactly(channel: socket.socket, size: int, deadline: float) -> bytes:
    result = bytearray()
    while len(result) < size:
        channel.settimeout(_wait_slice(deadline))
        try:
            chunk = channel.recv(min(65536, size - len(result)))
        except TimeoutError:
            continue  # A wait slice ended; _wait_slice raises once the deadline has passed.
        if not chunk:
            raise ValueError("plugin result ended before its declared length")
        result.extend(chunk)
    return bytes(result)


def _receive(channel: socket.socket, deadline: float) -> bytes:
    """Read one length-prefixed result, bounded in size and by the original job deadline.

    The declared length ends the result, so a program the plugin started that
    still holds the worker's end of the socket cannot delay it.
    """
    size = int.from_bytes(_read_exactly(channel, _LENGTH_BYTES, deadline), "big")
    if size > MAX_RESULT_BYTES:
        raise ValueError("plugin result exceeds transport limit")
    return _read_exactly(channel, size, deadline)


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


class _WorkerHandle:
    """Serialize the watchdog's kill with the supervisor's cleanup of one worker.

    ``Process.close()`` clears its handle before it marks the object closed;
    a kill from another thread in between would fail with AttributeError and
    end the scan without a report.
    """

    def __init__(self, process: BaseProcess) -> None:
        self._process = process
        self._lock = threading.Lock()

    def kill(self) -> None:
        with self._lock:
            try:
                if self._process.pid is not None and self._process.is_alive():
                    self._process.kill()
            except (OSError, ValueError):
                pass  # The worker already exited, or its process handle is closed.

    def stop(self) -> None:
        with self._lock:
            _stop(self._process)


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
    dump_directory = runner._dump_directory
    config = replace(
        runner._config,
        connectors=[spec],
        inventory=[],
        plugin_execution="thread",
        dump_records=str(dump_directory) if dump_directory else None,
    )
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
                dump_directory,
            ),
            daemon=True,
            name="shadowscan-plugin",
        )
    except Exception:
        parent.close()
        child.close()
        raise

    handle = _WorkerHandle(process)
    state.kill_process = handle.kill
    runner._engine._report_progress(spec.id, "starting (process)")
    result: _JobResult | None = None
    message = "plugin process failed, crashed, or returned invalid/oversized output; results discarded"
    warnings: list[str] = []
    try:
        _remaining(deadline)
        if state.cancelled.is_set():
            raise TimeoutError
        process.start()
        if state.cancelled.is_set():
            raise TimeoutError
        child.close()
        payload = _receive(parent, deadline)
        process.join(_wait_slice(deadline))
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
            handle.stop()
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
