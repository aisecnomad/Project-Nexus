"""Supported runtime platforms for path-confinement primitives."""

from __future__ import annotations

import os
import sys

UNSUPPORTED_WINDOWS_MESSAGE = (
    "ShadowScan is validated on Linux x86_64 with Python 3.11–3.13. "
    "Windows is unsupported: file confinement uses O_NOFOLLOW and dir_fd."
)
MISSING_NOFOLLOW_MESSAGE = (
    "ShadowScan requires os.O_NOFOLLOW to refuse symbolic links while opening files."
)


class UnsupportedPlatformError(RuntimeError):
    """Raised when the host cannot enforce the scanner's path policy."""


def require_supported_platform() -> None:
    """Fail closed on hosts that cannot implement the documented trust boundary."""
    if sys.platform.startswith("win"):
        raise UnsupportedPlatformError(UNSUPPORTED_WINDOWS_MESSAGE)
    if not hasattr(os, "O_NOFOLLOW"):
        raise UnsupportedPlatformError(MISSING_NOFOLLOW_MESSAGE)
