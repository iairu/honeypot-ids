"""App-wide theme: Solarized Light, Solarized Dark, High Contrast Light,
High Contrast Dark -- applied as an actual forced QPalette, not just Qt's
native color-scheme hint.

QStyleHints.setColorScheme() alone (the original implementation) does NOT
reliably force a real dark look on a real desktop: it only influences how
SOME native Qt styles generate their own palette, and does nothing at all
under styles that ignore Qt's color-scheme hint entirely -- confirmed live
this was the case here ("dark" wasn't really forced dark). Explicitly
building a QPalette and switching QApplication's style to "Fusion" (the one
built-in Qt style guaranteed to actually paint every widget FROM a custom
QPalette, rather than drawing many elements from the OS's own native theme
APIs regardless of what QPalette says) is what actually forces it -- see
apply_theme(). This does mean the whole app's widget rendering switches to
Fusion's flat, cross-platform look, not just its colors -- an unavoidable
side effect of the fix, not a separate stylistic choice.

Solarized colors are Ethan Schoonover's published palette
(https://ethanschoonover.com/solarized/) -- the same 16 base/accent colors
in both variants; only which base tones serve as background vs. foreground
swaps between light and dark. High Contrast uses near-maximum-contrast
black/white pairs (21:1, well past WCAG AAA's 7:1) instead, for anyone who
needs that over Solarized's more moderate (~4.7:1) body-text contrast.
"""
from __future__ import annotations

from typing import Callable

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QPalette
from PyQt6.QtWidgets import QApplication

THEME_SYSTEM = "system"
THEME_LIGHT = "light"
THEME_DARK = "dark"
THEME_HC_LIGHT = "hc_light"
THEME_HC_DARK = "hc_dark"
THEMES = [THEME_SYSTEM, THEME_LIGHT, THEME_DARK, THEME_HC_LIGHT, THEME_HC_DARK]

# THEME_SYSTEM only ever resolves into THEME_LIGHT/THEME_DARK (see
# _resolve_effective()) -- Qt's own OS-preference signal (Qt.ColorScheme)
# is exactly light/dark, with no "prefers high contrast" concept to
# auto-select the HC variants from. HC is always an explicit choice, never
# something "system" falls into.

THEME_LABELS = {
    THEME_SYSTEM: "Follow system",
    THEME_LIGHT: "Solarized Light",
    THEME_DARK: "Solarized Dark",
    THEME_HC_LIGHT: "High Contrast Light",
    THEME_HC_DARK: "High Contrast Dark",
}

# Ethan Schoonover's Solarized palette -- same 16 colors regardless of
# variant; only their ROLE (background vs. foreground) swaps between light
# and dark. https://ethanschoonover.com/solarized/
SOLARIZED = {
    "base03": "#002b36", "base02": "#073642", "base01": "#586e75", "base00": "#657b83",
    "base0": "#839496", "base1": "#93a1a1", "base2": "#eee8d5", "base3": "#fdf6e3",
    "yellow": "#b58900", "orange": "#cb4b16", "red": "#dc322f", "magenta": "#d33682",
    "violet": "#6c71c4", "blue": "#268bd2", "cyan": "#2aa198", "green": "#859900",
}

# Named hex colors per theme, for custom-stylesheet widgets that need a
# specific value directly rather than going through QPalette (ui/
# ansi_render.py's terminal-style panel, ui/health_diagram.py's canvas, ui/
# page_exploits.py's threat-event cards, ...). Every theme defines the same
# role names so callers never need their own per-theme branching:
#   bg        - main background
#   fg        - main text, full contrast against bg
#   bg_alt    - secondary/panel fill (cards, canvas borders, table stripes)
#   fg_muted  - secondary/detail text, still legible but visually quieter
#   border    - subtle dividers/outlines
_SCHEME_COLORS = {
    THEME_DARK: {
        "bg": SOLARIZED["base03"], "fg": SOLARIZED["base0"],
        "bg_alt": SOLARIZED["base02"], "fg_muted": SOLARIZED["base01"],
        "border": SOLARIZED["base02"],
    },
    THEME_LIGHT: {
        "bg": SOLARIZED["base3"], "fg": SOLARIZED["base00"],
        "bg_alt": SOLARIZED["base2"], "fg_muted": SOLARIZED["base1"],
        "border": SOLARIZED["base2"],
    },
    THEME_HC_DARK: {
        "bg": "#000000", "fg": "#ffffff",
        "bg_alt": "#1a1a1a", "fg_muted": "#e6e6e6",
        "border": "#ffffff",
    },
    THEME_HC_LIGHT: {
        "bg": "#ffffff", "fg": "#000000",
        "bg_alt": "#e6e6e6", "fg_muted": "#333333",
        "border": "#000000",
    },
}

_current_theme = THEME_SYSTEM
_change_callbacks: list[Callable[[], None]] = []
_os_listener_installed = False


def _resolve_effective(theme: str) -> str:
    """"system" resolves to Solarized Light/Dark via Qt's best-effort
    OS-preference signal, defaulting to dark if the platform can't report
    one (e.g. this app's own offscreen test environment, or a minimal
    window manager with no theme integration at all). Every other theme
    (including both High Contrast variants) is already concrete and is
    returned as-is -- see _SYSTEM_RESOLVES_TO's comment for why HC is
    never auto-selected this way."""
    if theme != THEME_SYSTEM:
        return theme
    app = QApplication.instance()
    if app is not None and app.styleHints().colorScheme() == Qt.ColorScheme.Light:
        return THEME_LIGHT
    return THEME_DARK


def _build_palette(effective: str) -> QPalette:
    s = SOLARIZED
    palette = QPalette()

    if effective == THEME_HC_DARK:
        window, window_text = "#000000", "#ffffff"
        base, alt_base = "#000000", "#1a1a1a"
        button = "#1a1a1a"
        placeholder = "#a0a0a0"
        disabled_text = "#808080"
        highlight, highlighted_text = "#ffff00", "#000000"  # bright yellow -- classic max-visibility selection
        bright_text = "#ff5555"
        link, link_visited = "#66ccff", "#ff66ff"
    elif effective == THEME_HC_LIGHT:
        window, window_text = "#ffffff", "#000000"
        base, alt_base = "#ffffff", "#e6e6e6"
        button = "#e6e6e6"
        placeholder = "#444444"
        disabled_text = "#555555"
        highlight, highlighted_text = "#000000", "#ffffff"  # black selection -- max contrast against white chrome
        bright_text = "#cc0000"
        link, link_visited = "#0000ee", "#7f00ff"
    elif effective == THEME_DARK:
        window, window_text = s["base03"], s["base0"]
        base, alt_base = s["base03"], s["base02"]
        button = s["base02"]
        placeholder = s["base01"]
        disabled_text = s["base01"]
        highlight, highlighted_text = s["blue"], s["base03"]
        bright_text = s["red"]
        link, link_visited = s["blue"], s["violet"]
    else:  # THEME_LIGHT
        window, window_text = s["base3"], s["base00"]
        base, alt_base = s["base3"], s["base2"]
        button = s["base2"]
        placeholder = s["base1"]
        disabled_text = s["base1"]
        highlight, highlighted_text = s["blue"], s["base3"]
        bright_text = s["red"]
        link, link_visited = s["blue"], s["violet"]

    palette.setColor(QPalette.ColorRole.Window, QColor(window))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(window_text))
    palette.setColor(QPalette.ColorRole.Base, QColor(base))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(alt_base))
    palette.setColor(QPalette.ColorRole.Text, QColor(window_text))
    palette.setColor(QPalette.ColorRole.Button, QColor(button))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(window_text))
    palette.setColor(QPalette.ColorRole.BrightText, QColor(bright_text))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(button))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor(window_text))
    palette.setColor(QPalette.ColorRole.PlaceholderText, QColor(placeholder))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(highlight))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(highlighted_text))
    palette.setColor(QPalette.ColorRole.Link, QColor(link))
    palette.setColor(QPalette.ColorRole.LinkVisited, QColor(link_visited))

    palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.WindowText, QColor(disabled_text))
    palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, QColor(disabled_text))
    palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, QColor(disabled_text))

    return palette


def apply_theme(theme: str) -> None:
    """Call once at startup with the persisted state.theme, and again
    whenever the user changes it in Settings."""
    global _current_theme, _os_listener_installed
    _current_theme = theme if theme in THEMES else THEME_SYSTEM

    app = QApplication.instance()
    if app is None:
        return

    if not _os_listener_installed:
        # Only matters while "system" is selected -- re-applies (and
        # re-resolves) on a live OS light/dark switch. Connected once,
        # here, rather than requiring main.py to remember to wire it up.
        app.styleHints().colorSchemeChanged.connect(_on_os_scheme_changed)
        _os_listener_installed = True

    effective = _resolve_effective(_current_theme)

    if app.style().objectName().lower() != "fusion":
        app.setStyle("Fusion")
    app.setPalette(_build_palette(effective))

    # Secondary signal for anything that DOES respect Qt's own hint
    # (mainly QWebEngineView's internal chrome -- scrollbars, form control
    # rendering -- which this app has no other way to theme). Only a
    # light/dark bit, so the HC variants report as their nearest of the
    # two rather than nothing.
    is_light = effective in (THEME_LIGHT, THEME_HC_LIGHT)
    app.styleHints().setColorScheme(Qt.ColorScheme.Light if is_light else Qt.ColorScheme.Dark)

    for callback in _change_callbacks:
        callback()


def _on_os_scheme_changed(_scheme) -> None:
    if _current_theme == THEME_SYSTEM:
        apply_theme(THEME_SYSTEM)


def current_theme() -> str:
    return _current_theme


def effective_theme() -> str:
    """The current theme, with "system" already resolved to a concrete
    THEME_LIGHT/THEME_DARK -- what every theme-blind custom-stylesheet
    widget should key its own colors off, via scheme_colors()."""
    return _resolve_effective(_current_theme)


def is_dark() -> bool:
    """Whether the EFFECTIVE current theme has a dark background (either
    Solarized Dark or High Contrast Dark)."""
    return effective_theme() in (THEME_DARK, THEME_HC_DARK)


def scheme_colors() -> dict[str, str]:
    """Named hex colors (bg/fg/bg_alt/fg_muted/border) for the CURRENT
    effective theme -- see _SCHEME_COLORS' comment for what each role
    means. The one lookup every theme-blind custom-stylesheet widget in
    this app should use, so a new theme only ever needs a new entry here,
    not a new branch in every widget that paints its own colors."""
    return _SCHEME_COLORS[effective_theme()]


def solarized_color(name: str) -> str:
    """One of the 16 Solarized base/accent color names (see SOLARIZED) --
    for anything that specifically wants a Solarized tone regardless of
    which theme is actually active (e.g. semantic status colors that don't
    change with theme)."""
    return SOLARIZED[name]


def on_change(callback: Callable[[], None]) -> None:
    """Registers callback() to run whenever apply_theme() runs -- either
    from this app's own Settings selector, or (while "system" is selected)
    re-applied in response to the OS's own live light/dark switch. Not
    disconnected automatically; safe to call from any long-lived widget's
    __init__ (the same lifetime as the QApplication itself, in practice,
    for every caller in this app)."""
    _change_callbacks.append(callback)
