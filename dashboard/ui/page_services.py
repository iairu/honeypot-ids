"""Services page: start/restart/stop/purge for each project, local and
(if configured) remote, with live status shown next to the buttons and
live command output below."""
from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QGroupBox, QHBoxLayout, QLabel, QMessageBox, QPushButton, QScrollArea,
    QVBoxLayout, QWidget,
)

from core.docker_ctl import PROJECT_LABELS, Target
from ui.process_runner import LogPanel


def summarize_status(containers: list[dict]) -> tuple[str, str]:
    """Returns (summary_text, color) for a target's container list."""
    if not containers:
        return "not running / unreachable", "#888888"

    running = sum(1 for c in containers if c.get("State") == "running")
    healthy = sum(1 for c in containers if c.get("Health") == "healthy")
    unhealthy = sum(1 for c in containers if c.get("Health") == "unhealthy")
    exited_bad = sum(
        1 for c in containers
        if c.get("State") == "exited" and str(c.get("ExitCode", "0")) not in ("0", "")
    )
    total = len(containers)

    if unhealthy or exited_bad:
        return f"{running}/{total} up ({unhealthy} unhealthy, {exited_bad} exited with error)", "#d9534f"
    if running == total:
        detail = f" ({healthy} healthy)" if healthy else ""
        return f"all {total} up{detail}", "#5cb85c"
    if running > 0:
        return f"{running}/{total} up", "#f0ad4e"
    return f"0/{total} up", "#888888"


class TargetPanel(QGroupBox):
    def __init__(self, target: Target, parent=None):
        super().__init__(target.label, parent)
        self.target = target

        layout = QVBoxLayout(self)

        status_row = QHBoxLayout()
        self.status_label = QLabel("checking…")
        status_row.addWidget(QLabel("Status:"))
        status_row.addWidget(self.status_label)
        status_row.addStretch()
        layout.addLayout(status_row)

        button_row = QHBoxLayout()
        self.start_btn = QPushButton("Start")
        self.restart_btn = QPushButton("Restart")
        self.stop_btn = QPushButton("Stop")
        self.purge_btn = QPushButton("Purge (⚠ deletes volumes)")
        self.purge_btn.setStyleSheet("QPushButton { color: #d9534f; }")
        for b in (self.start_btn, self.restart_btn, self.stop_btn, self.purge_btn):
            button_row.addWidget(b)
        layout.addLayout(button_row)

        self.start_btn.clicked.connect(self._start)
        self.restart_btn.clicked.connect(self._restart)
        self.stop_btn.clicked.connect(self._stop)
        self.purge_btn.clicked.connect(self._purge)

        self.log_panel = LogPanel()
        self.log_panel.setMinimumHeight(160)
        layout.addWidget(self.log_panel)

    def update_status(self, containers: list[dict]) -> None:
        text, color = summarize_status(containers)
        self.status_label.setText(text)
        self.status_label.setStyleSheet(f"color: {color}; font-weight: bold;")

    def _run(self, *compose_args: str) -> None:
        argv, cwd = self.target.build(*compose_args)
        self.log_panel.run(argv, cwd)

    def _start(self) -> None:
        self._run("up", "-d")

    def _restart(self) -> None:
        self._run("restart")

    def _stop(self) -> None:
        self._run("down")

    def _purge(self) -> None:
        reply = QMessageBox.warning(
            self, "Confirm purge",
            f"This will run 'docker compose down -v' for {self.target.label}, "
            "permanently deleting all named volumes (databases, Redis data, "
            "Elasticsearch indices, everything) for this stack.\n\n"
            "This cannot be undone. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self._run("down", "-v")


class ServicesPage(QWidget):
    def __init__(self, get_targets, parent=None):
        super().__init__(parent)
        self._get_targets = get_targets
        self.panels: dict[str, TargetPanel] = {}

        outer = QVBoxLayout(self)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        outer.addWidget(scroll)

        inner = QWidget()
        self.inner_layout = QVBoxLayout(inner)
        self.inner_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        scroll.setWidget(inner)

        self.rebuild_panels()

    def rebuild_panels(self) -> None:
        """Call after remote settings change, so newly-configured remote
        targets get their own panel without restarting the app."""
        while self.inner_layout.count():
            item = self.inner_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self.panels.clear()

        for target in self._get_targets():
            panel = TargetPanel(target)
            self.panels[target.key] = panel
            self.inner_layout.addWidget(panel)

    def apply_status(self, results: dict[str, list[dict]]) -> None:
        for key, containers in results.items():
            if key in self.panels:
                self.panels[key].update_status(containers)
