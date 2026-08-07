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
# 40-47/100-107 reuse the same base colors) -- Ethan Schoonover's published
# Solarized terminal color values (https://ethanschoonover.com/solarized/),
# matching ui/theme.py's SOLARIZED dict so the log panel's colors agree with
# the rest of the app's theme instead of being a separate, arbitrary
# palette. Deliberately duplicated here as literal hex rather than
# importing ui.theme -- this module has no Qt/theme dependency by design
# (see module docstring), and Solarized's whole celebrated design point is
# that these SAME 16 ANSI values are legible on both a dark and a light
# background (unlike a conventional terminal palette, which needs two
# genuinely different sets) -- confirmed against the published spec, so
# DARK_*/LIGHT_* intentionally hold identical values here, kept as
# separate names for API stability (callers already select between them
# by theme; a future divergence would be a one-line change here, not a
# call-site change).
DARK_BASE_COLORS = {
    0: "#073642", 1: "#dc322f", 2: "#859900", 3: "#b58900",
    4: "#268bd2", 5: "#d33682", 6: "#2aa198", 7: "#eee8d5",
}
DARK_BRIGHT_COLORS = {
    0: "#002b36", 1: "#cb4b16", 2: "#586e75", 3: "#657b83",
    4: "#839496", 5: "#6c71c4", 6: "#93a1a1", 7: "#fdf6e3",
}
LIGHT_BASE_COLORS = dict(DARK_BASE_COLORS)
LIGHT_BRIGHT_COLORS = dict(DARK_BRIGHT_COLORS)

# High Contrast palettes -- near-maximally saturated primaries rather than
# Solarized's more moderate tones, for anyone who specifically wants that
# over Solarized's ~4.7:1 body-text contrast. Genuinely different between
# dark/light here (unlike the Solarized sets above): a color bright enough
# to read on black (e.g. pure green #00ff00) is often too washed-out or
# low-contrast on white and vice versa, so max-contrast necessarily means
# two real palettes, not one shared one.
HC_DARK_BASE_COLORS = {
    0: "#000000", 1: "#ff0000", 2: "#00ff00", 3: "#ffff00",
    4: "#5599ff", 5: "#ff00ff", 6: "#00ffff", 7: "#ffffff",
}
HC_DARK_BRIGHT_COLORS = {
    0: "#808080", 1: "#ff5555", 2: "#55ff55", 3: "#ffff55",
    4: "#77aaff", 5: "#ff55ff", 6: "#55ffff", 7: "#ffffff",
}
HC_LIGHT_BASE_COLORS = {
    0: "#000000", 1: "#cc0000", 2: "#007700", 3: "#806600",
    4: "#0000ee", 5: "#aa00aa", 6: "#007777", 7: "#444444",
}
HC_LIGHT_BRIGHT_COLORS = {
    0: "#222222", 1: "#ff0000", 2: "#00aa00", 3: "#aa8800",
    4: "#3333ff", 5: "#cc00cc", 6: "#00aaaa", 7: "#000000",
}


@dataclass(frozen=True)
class AnsiStyle:
    fg: str | None = None
    bg: str | None = None
    bold: bool = False
    italic: bool = False
    underline: bool = False


_DEFAULT_STYLE = AnsiStyle()


def _apply_sgr(
    style: AnsiStyle, params: list[int],
    base_colors: dict[int, str], bright_colors: dict[int, str],
) -> AnsiStyle:
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
            style = replace(style, fg=base_colors[code - 30])
        elif code == 39:
            style = replace(style, fg=None)
        elif 40 <= code <= 47:
            style = replace(style, bg=base_colors[code - 40])
        elif code == 49:
            style = replace(style, bg=None)
        elif 90 <= code <= 97:
            style = replace(style, fg=bright_colors[code - 90])
        elif 100 <= code <= 107:
            style = replace(style, bg=bright_colors[code - 100])
        elif code == 38 and i + 1 < len(params) and params[i + 1] == 5 and i + 2 < len(params):
            # 256-color foreground (ESC[38;5;<n>m) -- only handle it enough
            # not to misparse the parameter list; map the 16 "standard"
            # slots of the 256-color cube back to the same base palette
            # rather than implementing the full cube for a log viewer.
            n = params[i + 2]
            if 0 <= n <= 7:
                style = replace(style, fg=base_colors[n])
            elif 8 <= n <= 15:
                style = replace(style, fg=bright_colors[n - 8])
            i += 2
        elif code == 48 and i + 1 < len(params) and params[i + 1] == 5 and i + 2 < len(params):
            n = params[i + 2]
            if 0 <= n <= 7:
                style = replace(style, bg=base_colors[n])
            elif 8 <= n <= 15:
                style = replace(style, bg=bright_colors[n - 8])
            i += 2
        i += 1

    return style


class AnsiTextParser:
    """Stateful: carries the current SGR style AND any incomplete escape
    sequence across feed() calls, since QProcess delivers output in
    arbitrary-sized chunks that can split `ESC [ 3 2 m` at any byte.

    base_colors/bright_colors default to the dark-background palette
    (unchanged behavior for any existing caller) -- pass LIGHT_BASE_COLORS/
    LIGHT_BRIGHT_COLORS for a parser feeding a light-background widget. See
    ui/theme.py; the Qt-aware caller (ui/process_runner.LogPanel) is the
    one that actually decides which to use, not this module -- this file
    stays free of any Qt/theme-detection import by design (see module
    docstring)."""

    def __init__(
        self, base_colors: dict[int, str] = DARK_BASE_COLORS,
        bright_colors: dict[int, str] = DARK_BRIGHT_COLORS,
    ) -> None:
        self._style = _DEFAULT_STYLE
        self._pending = ""  # an incomplete "ESC[...." not yet terminated by 'm'
        self._base_colors = base_colors
        self._bright_colors = bright_colors

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
                self._style = _apply_sgr(self._style, params, self._base_colors, self._bright_colors)
            # Any other final byte (cursor movement etc.) is silently
            # consumed and ignored -- see module docstring.

            i = end + 1
            buf_start = i

        if buf_start < n and not self._pending:
            segments.append((text[buf_start:n], self._style))

        return segments
