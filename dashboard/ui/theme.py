"""App-wide light/dark theme switching.

Uses Qt's native QStyleHints.setColorScheme() (Qt 6.5+, confirmed present
on this app's PyQt6 6.11) so every standard widget (buttons, checkboxes,
tables, scrollbars, menus, ...) picks up the correct palette automatically
-- no hand-rolled QPalette/global stylesheet needed for the vast majority
of the app.

The handful of widgets that hardcode their OWN colors via setStyleSheet()
(the log panel's terminal-style background, its ANSI palette, the health
diagram's canvas, the threat-diagram cards) are theme-blind by
construction -- a raw hex string doesn't know what theme it's in. Those
call is_dark() to pick their own light/dark color pair, and connect to
on_change() to re-derive it if the theme changes while they're alive
(either from this app's own selector, or -- when "system" is selected --
the OS's own light/dark switch firing while the app is running).
"""
from __future__ import annotations

from typing import Callable

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication

THEME_SYSTEM = "system"
THEME_LIGHT = "light"
THEME_DARK = "dark"
THEMES = [THEME_SYSTEM, THEME_LIGHT, THEME_DARK]

THEME_LABELS = {
    THEME_SYSTEM: "Follow system",
    THEME_LIGHT: "Light",
    THEME_DARK: "Dark",
}

_QT_SCHEME = {
    THEME_SYSTEM: Qt.ColorScheme.Unknown,  # Unknown == "defer to the OS"
    THEME_LIGHT: Qt.ColorScheme.Light,
    THEME_DARK: Qt.ColorScheme.Dark,
}

_current_theme = THEME_SYSTEM


def apply_theme(theme: str) -> None:
    """Call once at startup with the persisted state.theme, and again
    whenever the user changes it in Settings."""
    global _current_theme
    _current_theme = theme if theme in THEMES else THEME_SYSTEM
    app = QApplication.instance()
    if app is not None:
        app.styleHints().setColorScheme(_QT_SCHEME[_current_theme])


def current_theme() -> str:
    return _current_theme


def is_dark() -> bool:
    """Whether the EFFECTIVE current scheme is dark -- what theme-blind
    custom-stylesheet widgets should actually paint with. Resolves
    "system" via Qt's own reported scheme; if that itself comes back
    Unknown (some platform plugins -- e.g. this app's own offscreen test
    environment -- have no theme integration at all and never resolve it),
    falls back to dark, matching this app's original, only-ever-dark
    color choices."""
    if _current_theme == THEME_LIGHT:
        return False
    if _current_theme == THEME_DARK:
        return True
    app = QApplication.instance()
    if app is None:
        return True
    return app.styleHints().colorScheme() == Qt.ColorScheme.Dark or (
        app.styleHints().colorScheme() == Qt.ColorScheme.Unknown
    )


def on_change(callback: Callable[[], None]) -> None:
    """Registers callback() to run whenever the EFFECTIVE color scheme
    changes -- whether from apply_theme() or (while "system" is selected)
    the OS's own switch firing live. Not disconnected automatically; safe
    to call from any long-lived widget's __init__ (the same lifetime as
    the QApplication itself, in practice, for every caller in this app)."""
    app = QApplication.instance()
    if app is not None:
        app.styleHints().colorSchemeChanged.connect(lambda _scheme: callback())
