"""Small shared UI pieces every page used to hand-roll: a destructive-action
confirm dialog, colored status text, the red error banner, the local/remote
target dropdown, and layout clearing.
"""
from __future__ import annotations

from typing import Callable

from PyQt6.QtWidgets import QComboBox, QLabel, QLayout, QMessageBox, QPushButton, QWidget

from core.colors import RED
from core.docker_ctl import Target


def confirm(parent: QWidget | None, title: str, text: str) -> bool:
    """Yes/Cancel warning dialog defaulting to Cancel -- the shape every
    destructive action in this app asks with. True iff the user hit Yes."""
    reply = QMessageBox.warning(
        parent, title, text,
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
        QMessageBox.StandardButton.Cancel,
    )
    return reply == QMessageBox.StandardButton.Yes


def set_status(label: QLabel, text: str, color: str | None = None, bold: bool = False) -> None:
    """Sets a label's text and (only) its text color in one go."""
    label.setText(text)
    style = f"color: {color};" if color else ""
    if bold:
        style += " font-weight: bold;"
    label.setStyleSheet(style)


def badge_css(bg: str, fg: str = "#1e1e1e") -> str:
    """Pill-style QLabel stylesheet (score/route badges on the Exploits page)."""
    return f"QLabel {{ background-color: {bg}; color: {fg}; padding: 4px 10px; border-radius: 4px; font-weight: bold; }}"


def danger_button(text: str, on_click: Callable[[], None] | None = None) -> QPushButton:
    """A QPushButton whose text is red -- the convention for anything that
    deletes/overwrites/wipes."""
    btn = QPushButton(text)
    btn.setStyleSheet(f"QPushButton {{ color: {RED}; }}")
    if on_click is not None:
        btn.clicked.connect(on_click)
    return btn


def muted_label(text: str) -> QLabel:
    label = QLabel(text)
    label.setStyleSheet("color: #888888;")
    label.setWordWrap(True)
    return label


def clear_layout(layout: QLayout) -> None:
    """Removes and deletes every widget (and nested layout item) in `layout`."""
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.deleteLater()
        elif item.layout() is not None:
            clear_layout(item.layout())


class ErrorBanner(QLabel):
    """Red, word-wrapped, hidden until show_message() -- the "this target is
    unreachable / this service is down" strip at the top of a page."""

    def __init__(self, parent=None):
        super().__init__("", parent)
        self.setWordWrap(True)
        self.setStyleSheet(f"background-color: {RED}; color: white; padding: 6px; border-radius: 4px;")
        self.setVisible(False)

    def show_message(self, text: str) -> None:
        self.setText(text)
        self.setVisible(True)

    def set_error(self, error: str | None, prefix: str = "") -> None:
        """Shows `prefix + error` when error is truthy, hides otherwise."""
        if error:
            self.show_message(f"{prefix}{error}")
        else:
            self.setVisible(False)


class TargetSelector(QComboBox):
    """Dropdown over a project's targets (local, plus remote when
    configured). `get_targets` is a callable so rebuild() always reflects
    the current remote settings -- pages call it from their own
    rebuild_targets() hook."""

    def __init__(self, get_targets: Callable[[], list[Target]], parent=None):
        super().__init__(parent)
        self._get_targets = get_targets
        self._targets: list[Target] = []
        self.rebuild()

    def rebuild(self) -> None:
        """Repopulates without emitting currentIndexChanged, keeping the
        same index selected where it still exists."""
        previous = self.currentIndex()
        self.blockSignals(True)
        self.clear()
        self._targets = self._get_targets()
        for t in self._targets:
            self.addItem(t.label)
        if 0 <= previous < len(self._targets):
            self.setCurrentIndex(previous)
        self.blockSignals(False)

    def current_target(self) -> Target | None:
        idx = self.currentIndex()
        return self._targets[idx] if 0 <= idx < len(self._targets) else None

    def current_remote(self):
        target = self.current_target()
        return target.remote if target else None
