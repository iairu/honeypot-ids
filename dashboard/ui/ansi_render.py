"""Shared ANSI-to-QTextCharFormat rendering, theme-aware.

Factored out of ui/process_runner.LogPanel so any read-only text view that
wants to show real terminal colors from `docker compose logs --ansi
always` output (currently: LogPanel itself, and ui/page_log_search.py's
results view) can do it the same way, without duplicating the palette-
selection/format-building logic.
"""
from __future__ import annotations

from PyQt6.QtGui import QColor, QFont, QTextCharFormat, QTextCursor
from PyQt6.QtWidgets import QPlainTextEdit

from ui import theme
from ui.ansi import (
    AnsiStyle, AnsiTextParser, DARK_BASE_COLORS, DARK_BRIGHT_COLORS,
    LIGHT_BASE_COLORS, LIGHT_BRIGHT_COLORS,
)

# (background, default-text) for a terminal-style panel -- this is what the
# user called "the shell": a fixed dark background regardless of the app's
# own theme looked broken once light theme support existed (bright ANSI
# colors meant for a dark background go low-contrast-to-invisible on it
# too -- see ui/ansi.py's LIGHT_* palettes).
DARK_PANEL_COLORS = ("#1e1e1e", "#d4d4d4")
LIGHT_PANEL_COLORS = ("#fafafa", "#1e1e1e")


def panel_colors() -> tuple[str, str]:
    return DARK_PANEL_COLORS if theme.is_dark() else LIGHT_PANEL_COLORS


def panel_stylesheet(widget_selector: str = "QPlainTextEdit") -> str:
    bg, fg = panel_colors()
    return (
        f"{widget_selector} {{ background-color: {bg}; color: {fg}; "
        "font-family: monospace; font-size: 11px; }"
    )


def make_parser() -> AnsiTextParser:
    if theme.is_dark():
        return AnsiTextParser(DARK_BASE_COLORS, DARK_BRIGHT_COLORS)
    return AnsiTextParser(LIGHT_BASE_COLORS, LIGHT_BRIGHT_COLORS)


def format_for(style: AnsiStyle, default_color: str) -> QTextCharFormat:
    fmt = QTextCharFormat()
    fmt.setForeground(QColor(style.fg or default_color))
    if style.bg:
        fmt.setBackground(QColor(style.bg))
    if style.bold:
        fmt.setFontWeight(QFont.Weight.Bold)
    if style.italic:
        fmt.setFontItalic(True)
    if style.underline:
        fmt.setFontUnderline(True)
    return fmt


def append(text_edit: QPlainTextEdit, parser: AnsiTextParser, chunk: str, default_color: str) -> None:
    """Feeds `chunk` (which may contain raw ANSI SGR escape codes) through
    `parser` and inserts the resulting styled segments at the end of
    `text_edit`. `parser` is caller-owned (not reset here) so state -- the
    currently-active SGR style, any incomplete escape sequence -- carries
    correctly across multiple calls, same as ui/process_runner.LogPanel's
    own use of an AnsiTextParser."""
    cursor = text_edit.textCursor()
    cursor.movePosition(QTextCursor.MoveOperation.End)
    for segment, style in parser.feed(chunk):
        if segment:
            cursor.insertText(segment, format_for(style, default_color))
    text_edit.setTextCursor(cursor)
    text_edit.moveCursor(QTextCursor.MoveOperation.End)
