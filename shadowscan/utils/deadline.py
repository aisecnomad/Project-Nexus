"""Cancellable CLI process deadline for blocked SDK, plugin or output work.

This is deliberately separate from Engine's cooperative connector deadlines:
embedding applications must never have their process terminated implicitly.
An external job supervisor is still needed to reap subprocesses and constrain
native code that never releases the Python interpreter lock.
"""

from __future__ import annotations

import math
import os
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

JOB_DEADLINE_EXIT_CODE = 3
JOB_DEADLINE_MESSAGE = (
    "job deadline exceeded; exiting without waiting for blocked workers "
    "(scan coverage is incomplete)"
)


@dataclass(frozen=True)
class JobDeadline:
    thread: threading.Thread
    _cancelled: threading.Event

    def cancel(self) -> None:
        """Disarm the watchdog when a CLI invocation has finished."""
        self._cancelled.set()


def arm_job_deadline(
    seconds: float,
    *,
    exit_code: int = JOB_DEADLINE_EXIT_CODE,
    message: str = JOB_DEADLINE_MESSAGE,
    _exit: Callable[[int], None] | None = None,
) -> JobDeadline:
    """Arm a process-exit watchdog and return its cancellation handle.

    Call ``cancel`` in a ``finally`` block. A diagnostic is best effort: a
    locked or blocked stderr cannot hold up the independent exit callback.
    """
    if isinstance(seconds, bool) or not math.isfinite(seconds) or seconds <= 0:
        raise ValueError("job deadline must be a positive finite number of seconds")
    stopper = _exit or os._exit
    fire_at = time.monotonic() + seconds
    cancelled = threading.Event()

    def _announce() -> None:
        try:
            sys.stderr.write(message + "\n")
            sys.stderr.flush()
        except Exception:  # noqa: BLE001 - output must not prevent termination
            pass

    def _watch() -> None:
        while True:
            remaining = fire_at - time.monotonic()
            if remaining <= 0:
                break
            # Chunk waits to avoid overflow for very large finite deadlines.
            if cancelled.wait(min(remaining, 60.0)):
                return
        if cancelled.is_set():
            return
        try:
            threading.Thread(target=_announce, name="shadowscan-deadline-message", daemon=True).start()
        finally:
            stopper(exit_code)

    thread = threading.Thread(target=_watch, name="shadowscan-job-deadline", daemon=True)
    thread.start()
    return JobDeadline(thread, cancelled)
