"""App-wide theme: Console Dark/Light (the default security-operations
look), Solarized Light/Dark, High Contrast Light/Dark -- applied as an actual forced QPalette, not just Qt's
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

import tempfile
from pathlib import Path
from typing import Callable

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QPalette
from PyQt6.QtWidgets import QApplication

THEME_SYSTEM = "system"
THEME_LIGHT = "light"
THEME_DARK = "dark"
THEME_HC_LIGHT = "hc_light"
THEME_HC_DARK = "hc_dark"
THEME_CONSOLE_DARK = "console_dark"
THEME_CONSOLE_LIGHT = "console_light"
THEMES = [THEME_SYSTEM, THEME_CONSOLE_DARK, THEME_CONSOLE_LIGHT, THEME_LIGHT, THEME_DARK,
          THEME_HC_LIGHT, THEME_HC_DARK]

# THEME_SYSTEM only ever resolves into the Console Light/Dark pair (see
# _resolve_effective()) -- Qt's own OS-preference signal (Qt.ColorScheme)
# is exactly light/dark, with no "prefers high contrast" concept to
# auto-select the HC variants from. HC is always an explicit choice, never
# something "system" falls into.

THEME_LABELS = {
    THEME_SYSTEM: "Follow system (Console)",
    THEME_CONSOLE_DARK: "Console Dark",
    THEME_CONSOLE_LIGHT: "Console Light",
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

# Security-operations console palettes: slate/navy surfaces with a cyan
# accent (dark), cool grey surfaces with a sky-blue accent (light).
CONSOLE = {
    THEME_CONSOLE_DARK: {
        "window": "#0b1120", "surface": "#111a2e", "surface_alt": "#16213a",
        "nav": "#080d1a", "border": "#1f2c47", "text": "#e2e8f0", "muted": "#8b9bb4",
        "accent": "#22d3ee", "accent_text": "#04131a", "danger": "#ef4444",
        "success": "#22c55e", "warning": "#f59e0b",
    },
    THEME_CONSOLE_LIGHT: {
        "window": "#f4f6fa", "surface": "#ffffff", "surface_alt": "#eef2f7",
        "nav": "#0f172a", "border": "#d8dee9", "text": "#0f172a", "muted": "#5b6b84",
        "accent": "#0284c7", "accent_text": "#ffffff", "danger": "#dc2626",
        "success": "#16a34a", "warning": "#d97706",
    },
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
#   accent    - brand/selection color (focus rings, active nav item)
#   surface   - raised panel fill (cards, inputs, tables)
#   nav_bg / nav_fg / nav_muted - the navigation rail (dark in every theme
#               except High Contrast Light)
#   danger / success / warning - semantic status colors
_SCHEME_COLORS = {
    THEME_CONSOLE_DARK: {
        "bg": CONSOLE[THEME_CONSOLE_DARK]["window"], "fg": CONSOLE[THEME_CONSOLE_DARK]["text"],
        "bg_alt": CONSOLE[THEME_CONSOLE_DARK]["surface_alt"],
        "fg_muted": CONSOLE[THEME_CONSOLE_DARK]["muted"],
        "border": CONSOLE[THEME_CONSOLE_DARK]["border"],
    },
    THEME_CONSOLE_LIGHT: {
        "bg": CONSOLE[THEME_CONSOLE_LIGHT]["window"], "fg": CONSOLE[THEME_CONSOLE_LIGHT]["text"],
        "bg_alt": CONSOLE[THEME_CONSOLE_LIGHT]["surface_alt"],
        "fg_muted": CONSOLE[THEME_CONSOLE_LIGHT]["muted"],
        "border": CONSOLE[THEME_CONSOLE_LIGHT]["border"],
    },
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

_EXTRA_ROLES = {
    THEME_CONSOLE_DARK: {
        "accent": "#22d3ee", "accent_text": "#04131a", "surface": "#111a2e",
        "nav_bg": "#080d1a", "nav_fg": "#e2e8f0", "nav_muted": "#64748b",
        "danger": "#ef4444", "success": "#22c55e", "warning": "#f59e0b",
    },
    THEME_CONSOLE_LIGHT: {
        "accent": "#0284c7", "accent_text": "#ffffff", "surface": "#ffffff",
        "nav_bg": "#0f172a", "nav_fg": "#e2e8f0", "nav_muted": "#94a3b8",
        "danger": "#dc2626", "success": "#16a34a", "warning": "#d97706",
    },
    THEME_DARK: {
        "accent": SOLARIZED["cyan"], "accent_text": SOLARIZED["base03"],
        "surface": SOLARIZED["base02"], "nav_bg": "#00212b", "nav_fg": SOLARIZED["base1"],
        "nav_muted": SOLARIZED["base01"], "danger": SOLARIZED["red"],
        "success": SOLARIZED["green"], "warning": SOLARIZED["yellow"],
    },
    THEME_LIGHT: {
        "accent": SOLARIZED["blue"], "accent_text": SOLARIZED["base3"],
        "surface": SOLARIZED["base3"], "nav_bg": SOLARIZED["base02"], "nav_fg": SOLARIZED["base2"],
        "nav_muted": SOLARIZED["base1"], "danger": SOLARIZED["red"],
        "success": SOLARIZED["green"], "warning": SOLARIZED["yellow"],
    },
    THEME_HC_DARK: {
        "accent": "#ffff00", "accent_text": "#000000", "surface": "#000000",
        "nav_bg": "#000000", "nav_fg": "#ffffff", "nav_muted": "#e6e6e6",
        "danger": "#ff5555", "success": "#55ff55", "warning": "#ffcc00",
    },
    THEME_HC_LIGHT: {
        "accent": "#000000", "accent_text": "#ffffff", "surface": "#ffffff",
        "nav_bg": "#ffffff", "nav_fg": "#000000", "nav_muted": "#333333",
        "danger": "#cc0000", "success": "#006600", "warning": "#8a5a00",
    },
}
for _name, _roles in _EXTRA_ROLES.items():
    _SCHEME_COLORS[_name].update(_roles)

_current_theme = THEME_SYSTEM
_change_callbacks: list[Callable[[], None]] = []
_os_listener_installed = False


def _resolve_effective(theme: str) -> str:
    """"system" resolves to Console Light/Dark via Qt's best-effort
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
        return THEME_CONSOLE_LIGHT
    return THEME_CONSOLE_DARK


def _build_palette(effective: str) -> QPalette:
    s = SOLARIZED
    palette = QPalette()

    if effective in CONSOLE:
        c = CONSOLE[effective]
        window, window_text = c["window"], c["text"]
        base, alt_base = c["surface"], c["surface_alt"]
        button = c["surface_alt"]
        placeholder = c["muted"]
        disabled_text = c["muted"]
        highlight, highlighted_text = c["accent"], c["accent_text"]
        bright_text = c["danger"]
        link, link_visited = c["accent"], c["accent"]
    elif effective == THEME_HC_DARK:
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


_LIGHT_THEMES = (THEME_LIGHT, THEME_HC_LIGHT, THEME_CONSOLE_LIGHT)

FONT_STACK = '"Inter", "Segoe UI", "Roboto", "Noto Sans", "Helvetica Neue", "DejaVu Sans", sans-serif'
MONO_STACK = '"JetBrains Mono", "Cascadia Mono", "Fira Code", "DejaVu Sans Mono", monospace'


def _arrow_icons(color: str) -> tuple[str, str]:
    """Paths of small down/up chevron SVGs in `color`. Styling a combo or
    spin box's frame makes Qt drop its native arrows, and QSS takes images
    only by file path, so they are written once per color to a temp dir."""
    folder = Path(tempfile.gettempdir()) / "honeypot-dashboard-icons"
    folder.mkdir(exist_ok=True)
    paths = []
    for name, points in (("down", "2,4 6,8 10,4"), ("up", "2,8 6,4 10,8")):
        path = folder / f"{name}_{color.lstrip('#')}.svg"
        if not path.exists():
            path.write_text(
                '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12">'
                f'<polyline points="{points}" fill="none" stroke="{color}" '
                'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>')
        paths.append(path.as_posix())
    return paths[0], paths[1]


def _build_stylesheet(effective: str) -> str:
    """The app-wide QSS layered on top of the palette: rounded controls,
    focus rings in the accent color, flat tabs/tables/scrollbars, and the
    navigation rail / page header object names main_window.py uses. Every
    color comes from scheme_colors() roles, so each theme gets the same
    shapes in its own colors."""
    c = _SCHEME_COLORS[effective]
    radius = "2px" if effective in (THEME_HC_DARK, THEME_HC_LIGHT) else "6px"
    down, up = _arrow_icons(c["fg_muted"])
    return f"""
    QWidget {{ font-family: {FONT_STACK}; font-size: 10pt; }}
    QMainWindow, QDialog {{ background: {c["bg"]}; }}
    QToolTip {{ background: {c["surface"]}; color: {c["fg"]}; border: 1px solid {c["border"]};
               padding: 6px 8px; border-radius: 4px; }}

    QPushButton, QToolButton {{
        background: {c["bg_alt"]}; color: {c["fg"]}; border: 1px solid {c["border"]};
        border-radius: {radius}; padding: 5px 14px; min-height: 18px;
    }}
    QToolButton {{ padding: 4px 8px; }}
    QPushButton[compact="true"] {{ padding: 4px 0; }}
    QPushButton:hover, QToolButton:hover {{ border-color: {c["accent"]}; }}
    QPushButton:pressed, QToolButton:pressed, QToolButton:checked {{
        background: {c["accent"]}; color: {c["accent_text"]}; border-color: {c["accent"]};
    }}
    QPushButton:default {{ border-color: {c["accent"]}; }}
    QPushButton:disabled, QToolButton:disabled {{ color: {c["fg_muted"]}; background: {c["bg"]}; }}

    QLineEdit, QPlainTextEdit, QTextEdit, QTextBrowser, QSpinBox, QDoubleSpinBox,
    QComboBox, QDateTimeEdit {{
        background: {c["surface"]}; color: {c["fg"]}; border: 1px solid {c["border"]};
        border-radius: {radius}; padding: 4px 6px;
        selection-background-color: {c["accent"]}; selection-color: {c["accent_text"]};
    }}
    QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus, QSpinBox:focus,
    QDoubleSpinBox:focus, QComboBox:focus, QDateTimeEdit:focus {{ border-color: {c["accent"]}; }}
    QComboBox::drop-down {{ border: none; width: 22px; }}
    QComboBox::down-arrow, QSpinBox::down-arrow, QDoubleSpinBox::down-arrow,
    QDateTimeEdit::down-arrow {{ image: url("{down}"); width: 10px; height: 10px; }}
    QSpinBox::up-arrow, QDoubleSpinBox::up-arrow,
    QDateTimeEdit::up-arrow {{ image: url("{up}"); width: 10px; height: 10px; }}
    QSpinBox::up-button, QSpinBox::down-button, QDoubleSpinBox::up-button,
    QDoubleSpinBox::down-button, QDateTimeEdit::up-button, QDateTimeEdit::down-button {{
        subcontrol-origin: border; width: 18px; border: none; background: transparent;
    }}
    QSpinBox::up-button, QDoubleSpinBox::up-button, QDateTimeEdit::up-button {{ subcontrol-position: top right; }}
    QSpinBox::down-button, QDoubleSpinBox::down-button, QDateTimeEdit::down-button {{ subcontrol-position: bottom right; }}
    QComboBox QAbstractItemView {{
        background: {c["surface"]}; color: {c["fg"]}; border: 1px solid {c["border"]};
        selection-background-color: {c["accent"]}; selection-color: {c["accent_text"]};
    }}

    QGroupBox {{
        background: {c["surface"]}; border: 1px solid {c["border"]}; border-radius: 8px;
        margin-top: 14px; padding: 12px 10px 10px 10px;
    }}
    QGroupBox::title {{
        subcontrol-origin: margin; left: 12px; padding: 0 4px; color: {c["fg_muted"]};
        font-weight: 600; letter-spacing: 0.5px;
    }}

    QTabWidget::pane {{ border: 1px solid {c["border"]}; border-radius: {radius}; top: -1px;
                        background: {c["bg"]}; }}
    QTabBar::tab {{
        background: transparent; color: {c["fg_muted"]}; padding: 7px 14px;
        border: none; border-bottom: 2px solid transparent; margin-right: 2px;
    }}
    QTabBar::tab:hover {{ color: {c["fg"]}; }}
    QTabBar::tab:selected {{ color: {c["fg"]}; border-bottom: 2px solid {c["accent"]}; font-weight: 600; }}

    QTableView, QTreeView, QListView, QTableWidget, QTreeWidget, QListWidget {{
        background: {c["surface"]}; alternate-background-color: {c["bg_alt"]};
        border: 1px solid {c["border"]}; border-radius: {radius}; gridline-color: {c["border"]};
        selection-background-color: {c["accent"]}; selection-color: {c["accent_text"]};
    }}
    QHeaderView::section {{
        background: {c["bg_alt"]}; color: {c["fg_muted"]}; border: none;
        border-bottom: 1px solid {c["border"]}; border-right: 1px solid {c["border"]};
        padding: 5px 8px; font-weight: 600;
    }}
    QTableCornerButton::section {{ background: {c["bg_alt"]}; border: none; }}

    QScrollBar:vertical {{ background: transparent; width: 10px; margin: 0; }}
    QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 0; }}
    QScrollBar::handle:vertical, QScrollBar::handle:horizontal {{
        background: {c["border"]}; border-radius: 4px; min-height: 24px; min-width: 24px;
    }}
    QScrollBar::handle:hover {{ background: {c["fg_muted"]}; }}
    QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
    QScrollBar::add-page, QScrollBar::sub-page {{ background: none; }}

    QProgressBar {{ background: {c["bg_alt"]}; border: 1px solid {c["border"]};
                    border-radius: {radius}; text-align: center; color: {c["fg"]}; }}
    QProgressBar::chunk {{ background: {c["accent"]}; border-radius: {radius}; }}

    QMenuBar {{ background: {c["bg"]}; border-bottom: 1px solid {c["border"]}; }}
    QMenuBar::item {{ padding: 4px 10px; background: transparent; }}
    QMenuBar::item:selected {{ background: {c["bg_alt"]}; border-radius: 4px; }}
    QMenu {{ background: {c["surface"]}; border: 1px solid {c["border"]}; padding: 4px; }}
    QMenu::item {{ padding: 5px 22px 5px 14px; border-radius: 4px; }}
    QMenu::item:selected {{ background: {c["accent"]}; color: {c["accent_text"]}; }}
    QMenu::separator {{ height: 1px; background: {c["border"]}; margin: 4px 6px; }}
    QStatusBar {{ background: {c["nav_bg"]}; color: {c["nav_muted"]}; border-top: 1px solid {c["border"]}; }}
    QStatusBar QLabel {{ color: {c["nav_muted"]}; }}
    QSplitter::handle {{ background: {c["border"]}; }}

    #NavRail {{ background: {c["nav_bg"]}; border-right: 1px solid {c["border"]}; }}
    #NavRail QLabel {{ color: {c["nav_fg"]}; background: transparent; }}
    #BrandTitle {{ font-size: 12pt; font-weight: 700; letter-spacing: 2px; }}
    #NavRail QLabel#BrandSubtitle {{ color: {c["nav_muted"]}; font-size: 8pt; letter-spacing: 0.5px; }}
    #NavRail QLabel#BrandMark {{ background: {c["accent"]}; border-radius: 3px; }}
    #NavList {{ background: transparent; border: none; color: {c["nav_fg"]}; outline: 0; }}
    #NavList::item {{ padding: 7px 12px; margin: 1px 8px; border-radius: 6px;
                      border-left: 3px solid transparent; }}
    #NavList::item:hover {{ background: rgba(148, 163, 184, 0.14); }}
    #NavList::item:selected {{ background: rgba(148, 163, 184, 0.20); color: {c["nav_fg"]};
                               border-left: 3px solid {c["accent"]}; font-weight: 600; }}
    #NavRail QLabel#NavFooter {{ color: {c["nav_muted"]}; font-size: 8pt; }}

    #HeaderBar {{ background: {c["bg"]}; border-bottom: 1px solid {c["border"]}; }}
    #PageCrumb {{ color: {c["accent"]}; font-size: 8pt; font-weight: 700; letter-spacing: 1.5px; }}
    #PageTitle {{ color: {c["fg"]}; font-size: 16pt; font-weight: 700; }}
    #PageSubtitle {{ color: {c["fg_muted"]}; }}
    """


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
    app.setStyleSheet(_build_stylesheet(effective))

    # Secondary signal for anything that DOES respect Qt's own hint
    # (mainly QWebEngineView's internal chrome -- scrollbars, form control
    # rendering -- which this app has no other way to theme). Only a
    # light/dark bit, so the HC variants report as their nearest of the
    # two rather than nothing.
    is_light = effective in _LIGHT_THEMES
    app.styleHints().setColorScheme(Qt.ColorScheme.Light if is_light else Qt.ColorScheme.Dark)

    for callback in list(_change_callbacks):
        try:
            callback()
        except RuntimeError:
            # The widget behind a bound-method callback was deleted (e.g. a
            # closed setup wizard's banner): drop it instead of failing.
            _change_callbacks.remove(callback)


def _on_os_scheme_changed(_scheme) -> None:
    if _current_theme == THEME_SYSTEM:
        apply_theme(THEME_SYSTEM)


def current_theme() -> str:
    return _current_theme


def effective_theme() -> str:
    """The current theme, with "system" already resolved to a concrete
    theme -- what every theme-blind custom-stylesheet
    widget should key its own colors off, via scheme_colors()."""
    return _resolve_effective(_current_theme)


def is_dark() -> bool:
    """Whether the EFFECTIVE current theme has a dark background (either
    Console Dark, Solarized Dark or High Contrast Dark)."""
    return effective_theme() not in _LIGHT_THEMES


def scheme_colors() -> dict[str, str]:
    """Named hex colors (bg/fg/bg_alt/fg_muted/border/accent/...) for the CURRENT
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


def style_chart(chart) -> None:
    """Paints a QChart (and its axes and legend) in the current theme's
    surface/text/border colors. Call after the axes are attached, and again
    from on_change()."""
    from PyQt6.QtGui import QBrush, QPen

    c = scheme_colors()
    fg, muted, border = QColor(c["fg"]), QColor(c["fg_muted"]), QColor(c["border"])
    chart.setBackgroundBrush(QBrush(QColor(c["surface"])))
    chart.setBackgroundRoundness(6)
    chart.setTitleBrush(QBrush(fg))
    chart.legend().setLabelColor(fg)
    for axis in chart.axes():
        axis.setLabelsColor(muted)
        axis.setTitleBrush(QBrush(muted))
        axis.setLinePen(QPen(border))
        axis.setGridLineColor(border)


def on_change(callback: Callable[[], None]) -> None:
    """Registers callback() to run whenever apply_theme() runs -- either
    from this app's own Settings selector, or (while "system" is selected)
    re-applied in response to the OS's own live light/dark switch. Not
    disconnected automatically; safe to call from any long-lived widget's
    __init__ (the same lifetime as the QApplication itself, in practice,
    for every caller in this app)."""
    _change_callbacks.append(callback)
