"""Minimal ANSI SGR (Select Graphic Rendition -- color/bold/underline)
escape-code parser, for rendering `docker compose --ansi always logs`
output as real color in a Qt text widget instead of either raw escape-code
garbage or flat, colorless text.

Split into a PURE parsing layer (this module -- no Qt import, testable
under a plain `python3 -m py_compile`/pytest-free unittest run) and a
Qt-dependent rendering layer (ui/process_runner.py's LogPanel, which turns
each (text, AnsiStyle) segment into a QTextCharFormat).

Deliberately scoped to SGR codes only (`ESC [ <params> m`) -- the only CSI
sequence class that shows up in docker/nginx/suricata log output in
practice. Cursor-movement/clear-screen CSI sequences etc. are not
something a log stream legitimately emits, so they're not handled (a
stray one is just dropped, not crashed on).
"""
from __future__ import annotations

from dataclasses import dataclass, replace

ESC = "\x1b"

# Standard 16-color ANSI palette (foreground codes 30-37/90-97, background
# 40-47/100-107 reuse the same base colors). Matches VS Code's default
# terminal scheme -- a reasonably familiar, neutral choice, not tied to any
# one dark/light theme.
_BASE_COLORS = {
    0: "#000000", 1: "#cd3131", 2: "#0dbc79", 3: "#e5e510",
    4: "#2472c8", 5: "#bc3fbc", 6: "#11a8cd", 7: "#e5e5e5",
}
_BRIGHT_COLORS = {
    0: "#666666", 1: "#f14c4c", 2: "#23d18b", 3: "#f5f543",
    4: "#3b8eea", 5: "#d670d6", 6: "#29b8db", 7: "#e5e5e5",
}


@dataclass(frozen=True)
class AnsiStyle:
    fg: str | None = None
    bg: str | None = None
    bold: bool = False
    italic: bool = False
    underline: bool = False


_DEFAULT_STYLE = AnsiStyle()


def _apply_sgr(style: AnsiStyle, params: list[int]) -> AnsiStyle:
    """One SGR escape's parameter list (already split on ';') applied on
    top of the current style. Unrecognized codes are ignored, not fatal --
    a genuinely unknown/malformed code shouldn't take down log rendering."""
    if not params:
        params = [0]

    i = 0
    while i < len(params):
        code = params[i]
        if code == 0:
            style = _DEFAULT_STYLE
        elif code == 1:
            style = replace(style, bold=True)
        elif code == 3:
            style = replace(style, italic=True)
        elif code == 4:
            style = replace(style, underline=True)
        elif code == 22:
            style = replace(style, bold=False)
        elif code == 23:
            style = replace(style, italic=False)
        elif code == 24:
            style = replace(style, underline=False)
        elif 30 <= code <= 37:
            style = replace(style, fg=_BASE_COLORS[code - 30])
        elif code == 39:
            style = replace(style, fg=None)
        elif 40 <= code <= 47:
            style = replace(style, bg=_BASE_COLORS[code - 40])
        elif code == 49:
            style = replace(style, bg=None)
        elif 90 <= code <= 97:
            style = replace(style, fg=_BRIGHT_COLORS[code - 90])
        elif 100 <= code <= 107:
            style = replace(style, bg=_BRIGHT_COLORS[code - 100])
        elif code == 38 and i + 1 < len(params) and params[i + 1] == 5 and i + 2 < len(params):
            # 256-color foreground (ESC[38;5;<n>m) -- only handle it enough
            # not to misparse the parameter list; map the 16 "standard"
            # slots of the 256-color cube back to the same base palette
            # rather than implementing the full cube for a log viewer.
            n = params[i + 2]
            if 0 <= n <= 7:
                style = replace(style, fg=_BASE_COLORS[n])
            elif 8 <= n <= 15:
                style = replace(style, fg=_BRIGHT_COLORS[n - 8])
            i += 2
        elif code == 48 and i + 1 < len(params) and params[i + 1] == 5 and i + 2 < len(params):
            n = params[i + 2]
            if 0 <= n <= 7:
                style = replace(style, bg=_BASE_COLORS[n])
            elif 8 <= n <= 15:
                style = replace(style, bg=_BRIGHT_COLORS[n - 8])
            i += 2
        i += 1

    return style


class AnsiTextParser:
    """Stateful: carries the current SGR style AND any incomplete escape
    sequence across feed() calls, since QProcess delivers output in
    arbitrary-sized chunks that can split `ESC [ 3 2 m` at any byte."""

    def __init__(self) -> None:
        self._style = _DEFAULT_STYLE
        self._pending = ""  # an incomplete "ESC[...." not yet terminated by 'm'

    def feed(self, chunk: str) -> list[tuple[str, AnsiStyle]]:
        """Returns a list of (plain_text, style) segments ready to render,
        in order. May return an empty list if the whole chunk was (part
        of) an escape sequence with no visible text yet."""
        text = self._pending + chunk
        self._pending = ""

        segments: list[tuple[str, AnsiStyle]] = []
        i = 0
        buf_start = 0
        n = len(text)

        while i < n:
            if text[i] != ESC:
                i += 1
                continue

            # Flush any plain text seen before this escape.
            if i > buf_start:
                segments.append((text[buf_start:i], self._style))

            # Need at least ESC + '[' to know it's a CSI sequence at all.
            if i + 1 >= n:
                self._pending = text[i:]
                buf_start = n
                i = n
                break
            if text[i + 1] != "[":
                # Not a CSI sequence (or truncated) -- drop just the ESC
                # byte and keep going rather than getting stuck on it.
                i += 1
                buf_start = i
                continue

            end = i + 2
            while end < n and not text[end].isalpha():
                end += 1
            if end >= n:
                # Sequence not terminated yet -- wait for more input.
                self._pending = text[i:]
                buf_start = n
                i = n
                break

            final_byte = text[end]
            params_str = text[i + 2:end]
            if final_byte == "m":
                params = [int(p) if p else 0 for p in params_str.split(";")] if params_str else [0]
                self._style = _apply_sgr(self._style, params)
            # Any other final byte (cursor movement etc.) is silently
            # consumed and ignored -- see module docstring.

            i = end + 1
            buf_start = i

        if buf_start < n and not self._pending:
            segments.append((text[buf_start:n], self._style))

        return segments
