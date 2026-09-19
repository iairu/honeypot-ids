"""Reassembles complete lines from arbitrary-sized text chunks.

QProcess (and any pipe) delivers output in whatever chunk boundaries the
OS gives it, which don't line up with log-line boundaries -- every
consumer that parses lines out of a live stream (threat-log parsing, error
counting, LogPanel's line filter) needs this exact buffering, so it lives
here once.
"""
from __future__ import annotations


class LineBuffer:
    def __init__(self) -> None:
        self._pending = ""

    def feed(self, chunk: str) -> list[str]:
        """Returns every COMPLETE line in pending+chunk (without their
        newline); a trailing incomplete line is held for the next call."""
        text = self._pending + chunk
        lines = text.split("\n")
        self._pending = lines.pop()  # "" if chunk ended on a newline, else the partial line
        return lines

    def reset(self) -> None:
        self._pending = ""
