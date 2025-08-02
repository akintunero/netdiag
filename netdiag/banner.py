from __future__ import annotations

import os
import sys
from typing import TextIO

# Block wordmark (UTF-8); disable with NETDIAG_NO_BANNER=1 on narrow terminals
BANNER_LINES: tuple[str, ...] = (
    " ▄▄        ▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄ ",
    "▐░░▌      ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌",
    "▐░▌░▌     ▐░▌▐░█▀▀▀▀▀▀▀▀▀  ▀▀▀▀█░█▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌▀▀▀▀█░█▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀▀▀ ",
    "▐░▌▐░▌    ▐░▌▐░▌               ▐░▌     ▐░▌       ▐░▌    ▐░▌     ▐░▌       ▐░▌▐░▌          ",
    "▐░▌ ▐░▌   ▐░▌▐░█▄▄▄▄▄▄▄▄▄      ▐░▌     ▐░▌       ▐░▌    ▐░▌     ▐░█▄▄▄▄▄▄▄█░▌▐░▌ ▄▄▄▄▄▄▄▄ ",
    "▐░▌  ▐░▌  ▐░▌▐░░░░░░░░░░░▌     ▐░▌     ▐░▌       ▐░▌    ▐░▌     ▐░░░░░░░░░░░▌▐░▌▐░░░░░░░░▌",
    "▐░▌   ▐░▌ ▐░▌▐░█▀▀▀▀▀▀▀▀▀      ▐░▌     ▐░▌       ▐░▌    ▐░▌     ▐░█▀▀▀▀▀▀▀█░▌▐░▌ ▀▀▀▀▀▀█░▌",
    "▐░▌    ▐░▌▐░▌▐░▌               ▐░▌     ▐░▌       ▐░▌    ▐░▌     ▐░▌       ▐░▌▐░▌       ▐░▌",
    "▐░▌     ▐░▐░▌▐░█▄▄▄▄▄▄▄▄▄      ▐░▌     ▐░█▄▄▄▄▄▄▄█░▌▄▄▄▄█░█▄▄▄▄ ▐░▌       ▐░▌▐░█▄▄▄▄▄▄▄█░▌",
    "▐░▌      ▐░░▌▐░░░░░░░░░░░▌     ▐░▌     ▐░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌▐░░░░░░░░░░░▌",
    " ▀        ▀▀  ▀▀▀▀▀▀▀▀▀▀▀       ▀       ▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀  ▀         ▀  ▀▀▀▀▀▀▀▀▀▀▀ ",
)


def banner_enabled() -> bool:
    value = os.environ.get("NETDIAG_NO_BANNER", "").strip().lower()
    return value not in ("1", "true", "yes", "on")


def banner_text() -> str:
    return "\n".join(BANNER_LINES)


def print_banner(*, stream: TextIO | None = None) -> None:
    if not banner_enabled():
        return
    out = stream or sys.stdout
    out.write(banner_text())
    out.write("\n\n")
