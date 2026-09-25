from __future__ import annotations

import sys

from shadowscan.cli import main as cli_main
from shadowscan.utils.platform import UnsupportedPlatformError, require_supported_platform

_HELP_OR_VERSION = {"-h", "--help", "--version"}


def main() -> None:
    args = sys.argv[1:]
    if args and not (set(args) & _HELP_OR_VERSION):
        try:
            require_supported_platform()
        except UnsupportedPlatformError as exc:
            raise SystemExit(f"Error: {exc}") from None
    cli_main()


if __name__ == "__main__":  # pragma: no cover
    main()
