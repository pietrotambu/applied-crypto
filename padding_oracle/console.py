"""Shared terminal output helpers with optional ANSI colors."""

from __future__ import annotations

import os
import sys
from typing import TextIO


class Console:
    """Small helper for consistent CLI output formatting."""

    def __init__(self, stream: TextIO | None = None):
        self._stream = stream if stream is not None else sys.stdout
        self._use_color = (
            self._stream.isatty()
            and os.getenv("NO_COLOR") is None
            and os.getenv("TERM") != "dumb"
        )
        self._reset = "\033[0m"

    def style(self, text: str, code: str) -> str:
        if not self._use_color:
            return text
        return f"\033[{code}m{text}{self._reset}"

    def bold(self, text: str) -> str:
        return self.style(text, "1")

    def section(self, title: str) -> None:
        print(self.style(title, "1;36"), file=self._stream)

    def kv(self, key: str, value: str | int | float) -> None:
        print(f"{self.bold(key + ':')} {value}", file=self._stream)

    def tag(self, label: str, code: str) -> str:
        return self.style(f"[{label}]", code)

    def warn(self, message: str) -> None:
        print(f"{self.tag('WARN', '33')} {message}", file=self._stream)

    def ok_label(self, ok: bool) -> str:
        return self.style("YES", "32") if ok else self.style("NO", "31")

    def row_status(self, success_rate: float, error_trials: int) -> str:
        if error_trials > 0:
            return self.style("ERROR", "31")
        if success_rate >= 0.9:
            return self.style("GOOD", "32")
        if success_rate > 0.0:
            return self.style("PARTIAL", "33")
        return self.style("FAIL", "31")

    def delta_label(self, delta_ms: float) -> str:
        if delta_ms > 0:
            return self.style("LONG>SHORT", "32")
        if delta_ms < 0:
            return self.style("LONG<SHORT", "31")
        return self.style("EQUAL", "33")


CONSOLE = Console()
