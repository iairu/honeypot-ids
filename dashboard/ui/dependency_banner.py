"""Shared "missing dependency" warning banner -- used on the setup
wizard's first page and persistently in MainWindow (visible above the page
stack regardless of which page is selected), so a missing docker/docker
compose/ssh/rsync is surfaced up front instead of failing one feature at a
time with a raw "command not found" the first time it's actually used.
"""
from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from core.dependency_check import check_dependencies, install_command
from ui import theme


class DependencyBanner(QWidget):
    # Emitted only on a transition INTO a required tool being missing (not
    # re-emitted on every refresh() while it stays missing, and not for
    # optional-only gaps) -- ui/security_feed.py's recent-events list is
    # meant to surface "something changed", not repeat the same standing
    # warning this banner already shows persistently on its own.
    required_missing_detected = pyqtSignal(str)  # human-readable detail text

    def __init__(self, parent=None):
        super().__init__(parent)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(14, 10, 14, 10)
        self._layout.setSpacing(4)
        # A plain QWidget subclass ignores its own stylesheet background
        # without this.
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setVisible(False)
        self._last_required_missing: frozenset[str] = frozenset()
        self._severity: str | None = None  # "danger" | "warning" while shown
        theme.on_change(self._apply_style)
        self.refresh()

    def _apply_style(self) -> None:
        """Alert card: tinted fill with a solid left edge in the severity
        color, in the current theme's own text color."""
        if self._severity is None:
            self.setStyleSheet("")
            return
        c = theme.scheme_colors()
        edge = c[self._severity]
        self.setStyleSheet(
            f"DependencyBanner {{ background-color: {c['bg_alt']}; border: 1px solid {c['border']}; "
            f"border-left: 4px solid {edge}; }} "
            f"QLabel {{ color: {c['fg']}; background: transparent; }} "
            f"QLabel#BannerHeader {{ color: {edge}; font-weight: 700; }} "
            f"QLabel#BannerCommand {{ font-family: {theme.MONO_STACK}; background-color: {c['bg']}; "
            f"border: 1px solid {c['border']}; border-radius: 4px; padding: 6px; }}"
        )

    def refresh(self) -> None:
        while self._layout.count():
            item = self._layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        statuses = check_dependencies()
        missing = [s for s in statuses if not s.ok]

        if not missing:
            self._last_required_missing = frozenset()
            self.setVisible(False)
            self._severity = None
            self._apply_style()
            return

        required_missing = [s for s in missing if s.required]
        current_required = frozenset(s.name for s in required_missing)
        if current_required and current_required != self._last_required_missing:
            self.required_missing_detected.emit(
                "Required tool(s) not found: " + ", ".join(sorted(current_required))
            )
        self._last_required_missing = current_required
        # Red if core tools are missing, amber if only optional ones.
        self._severity = "danger" if required_missing else "warning"
        self._apply_style()
        self.setVisible(True)

        if required_missing:
            header_text = (
                "⚠ Host prerequisite check failed -- most console functions are unavailable until "
                "these are installed: " + ", ".join(s.name for s in required_missing)
            )
        else:
            header_text = (
                "⚠ Optional tooling missing -- remote targets (SSH control, project sync) are "
                "unavailable: " + ", ".join(s.name for s in missing)
            )
        header = QLabel(header_text)
        header.setObjectName("BannerHeader")
        header.setWordWrap(True)
        self._layout.addWidget(header)

        for s in missing:
            line = QLabel(f"  •  {s.name}: {s.detail}")
            line.setWordWrap(True)
            self._layout.addWidget(line)

        cmd_label = QLabel(f"Recommended install command:\n{install_command()}")
        cmd_label.setWordWrap(True)
        cmd_label.setObjectName("BannerCommand")
        cmd_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self._layout.addWidget(cmd_label)

        btn_row = QHBoxLayout()
        recheck_btn = QPushButton("Recheck")
        recheck_btn.clicked.connect(self.refresh)
        btn_row.addWidget(recheck_btn)
        btn_row.addStretch()
        self._layout.addLayout(btn_row)
