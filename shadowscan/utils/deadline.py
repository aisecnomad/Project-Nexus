"""Process-wide job deadline that can terminate blocked SDK or plugin work."""

from __future__ import annotations

import os
import sys
import threading
import time
from collections.abc import Callable


JOB_DEADLINE_EXIT_CODE = 3
JOB_DEADLINE_MESSAGE = (
    "job deadline exceeded; exiting without waiting for blocked workers "
    "(scan coverage is incomplete)"
)


def arm_job_deadline(
    seconds: float,
    *,
    exit_code: int = JOB_DEADLINE_EXIT_CODE,
    message: str = JOB_DEADLINE_MESSAGE,
    _exit: Callable[[int], None] | None = None,
    _sleep: Callable[[float], None] = time.sleep,
    _monotonic: Callable[[], float] = time.monotonic,
) -> threading.Thread:
    """Start a daemon watchdog that process-exits when the wall clock expires.

    Connector timeouts remain cooperative. This watchdog is the in-process
    equivalent of a host/job deadline: blocked SDK, plugin, or filesystem
    calls are abandoned by killing the process. It cannot reclaim threads.
    ``seconds`` must already be a positive finite number.
    """
    if isinstance(seconds, bool) or seconds != seconds or seconds <= 0 or seconds == float("inf"):
        raise ValueError("job deadline must be a positive finite number of seconds")
    stopper = _exit or os._exit
    fire_at = _monotonic() + float(seconds)

    def _watch() -> None:
        remaining = fire_at - _monotonic()
        while remaining > 0:
            _sleep(min(remaining, 0.05))
            remaining = fire_at - _monotonic()
        try:
            sys.stderr.write(message + "\n")
            sys.stderr.flush()
        except Exception:
            pass
        stopper(exit_code)

    thread = threading.Thread(target=_watch, name="shadowscan-job-deadline", daemon=True)
    thread.start()
    return thread
