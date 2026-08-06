"""Health page: the cross-referenced service diagram, plus a details
panel for whatever node is selected (status detail, Restart, View Logs,
Open Web UI, Open Shell)."""
from __future__ import annotations

from PyQt6.QtCore import QProcess, QUrl, Qt
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QGroupBox, QHBoxLayout, QLabel, QMessageBox, QPushButton, QSplitter,
    QVBoxLayout, QWidget,
)

from core.shell_ctl import build_shell_command
from core.web_links import build_url, web_ui_for
from ui.health_diagram import HealthDiagram, STATUS_COLORS, classify, status_detail
from ui.process_runner import LogPanel


class LegendWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        labels = {
            "healthy": "Up, healthy",
            "running": "Up (no healthcheck)",
            "unhealthy": "Up, unhealthy",
            "exited_ok": "Exited OK (code 0)",
            "exited_bad": "Exited with error",
            "down": "Down / not created",
        }
        for key, text in labels.items():
            color = STATUS_COLORS[key]
            swatch = QLabel("  ")
            swatch.setStyleSheet(f"background-color: {color.name()}; border-radius: 3px;")
            swatch.setFixedSize(16, 16)
            layout.addWidget(swatch)
            lbl = QLabel(text)
            layout.addWidget(lbl)
            layout.addSpacing(12)
        layout.addStretch()


class HealthPage(QWidget):
    def __init__(self, get_targets, parent=None):
        super().__init__(parent)
        self._get_targets = get_targets
        self._last_results: dict[str, list[dict]] = {}
        self._targets_by_key: dict[str, object] = {}

        layout = QVBoxLayout(self)

        layout.addWidget(LegendWidget())

        splitter = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(splitter, stretch=1)

        self.diagram = HealthDiagram()
        self.diagram.node_selected.connect(self._on_node_selected)
        splitter.addWidget(self.diagram)

        detail_panel = QGroupBox("Selected service")
        detail_layout = QVBoxLayout(detail_panel)
        self.detail_label = QLabel("Click a node to see details.")
        self.detail_label.setWordWrap(True)
        detail_layout.addWidget(self.detail_label)

        btn_row = QHBoxLayout()
        self.restart_btn = QPushButton("Restart")
        self.restart_btn.setEnabled(False)
        self.restart_btn.clicked.connect(self._restart_selected)
        self.logs_btn = QPushButton("View logs")
        self.logs_btn.setEnabled(False)
        self.logs_btn.clicked.connect(self._view_logs_selected)
        btn_row.addWidget(self.restart_btn)
        btn_row.addWidget(self.logs_btn)
        detail_layout.addLayout(btn_row)

        btn_row2 = QHBoxLayout()
        self.web_ui_btn = QPushButton("Open web UI")
        self.web_ui_btn.setEnabled(False)
        self.web_ui_btn.clicked.connect(self._open_web_ui_selected)
        self.shell_btn = QPushButton("Open shell")
        self.shell_btn.setEnabled(False)
        self.shell_btn.clicked.connect(self._open_shell_selected)
        btn_row2.addWidget(self.web_ui_btn)
        btn_row2.addWidget(self.shell_btn)
        detail_layout.addLayout(btn_row2)

        self.log_panel = LogPanel()
        detail_layout.addWidget(self.log_panel, stretch=1)

        detail_panel.setMinimumWidth(320)
        splitter.addWidget(detail_panel)
        splitter.setSizes([700, 320])

        self._selected: tuple[str, str] | None = None

    def apply_status(self, results: dict[str, list[dict]]) -> None:
        self._last_results = results
        targets = self._get_targets()
        self._targets_by_key = {t.key: t for t in targets}
        self.diagram.rebuild(targets, results)
        if self._selected:
            self._refresh_detail_label()

    def _selected_container(self) -> dict | None:
        if not self._selected:
            return None
        target_key, service = self._selected
        containers = self._last_results.get(target_key, [])
        return next((c for c in containers if c.get("Service") == service), None)

    def _on_node_selected(self, target_key: str, service: str) -> None:
        self._selected = (target_key, service)
        self.restart_btn.setEnabled(True)
        self.logs_btn.setEnabled(True)
        self._refresh_detail_label()

    def _refresh_detail_label(self) -> None:
        target_key, service = self._selected
        container = self._selected_container()
        status = classify(container)
        detail = status_detail(container)
        target = self._targets_by_key.get(target_key)
        target_label = target.label if target else target_key
        self.detail_label.setText(
            f"<b>{service}</b><br>Target: {target_label}<br>Status: {status}<br>{detail}"
        )

        is_running = container is not None and container.get("State") == "running"
        project = target.project if target else None

        has_web_ui = project is not None and web_ui_for(project, service) is not None
        self.web_ui_btn.setEnabled(has_web_ui and is_running)

        self.shell_btn.setEnabled(is_running)

    def _restart_selected(self) -> None:
        if not self._selected:
            return
        target_key, service = self._selected
        target = self._targets_by_key.get(target_key)
        if target is None:
            return
        argv, cwd = target.build("restart", service)
        self.log_panel.run(argv, cwd)

    def _view_logs_selected(self) -> None:
        if not self._selected:
            return
        target_key, service = self._selected
        target = self._targets_by_key.get(target_key)
        if target is None:
            return
        argv, cwd = target.build("logs", "--tail=300", "-f", service)
        self.log_panel.run(argv, cwd)

    def _open_web_ui_selected(self) -> None:
        if not self._selected:
            return
        target_key, service = self._selected
        target = self._targets_by_key.get(target_key)
        if target is None:
            return
        host = target.remote.host if target.is_remote else "127.0.0.1"
        url = build_url(target.project, service, host)
        if url:
            QDesktopServices.openUrl(QUrl(url))

    def _open_shell_selected(self) -> None:
        if not self._selected:
            return
        target_key, service = self._selected
        target = self._targets_by_key.get(target_key)
        container = self._selected_container()
        if target is None or container is None:
            return

        container_name = container.get("Name") or container.get("Names") or service
        shell_cmd = build_shell_command(target, container_name)

        if shell_cmd.terminal_argv is None:
            QMessageBox.information(
                self, "No terminal emulator found",
                "Couldn't find a terminal emulator on this system to launch. "
                "Run this command yourself:\n\n" + " ".join(shell_cmd.argv),
            )
            return

        QProcess.startDetached(shell_cmd.terminal_argv[0], shell_cmd.terminal_argv[1:])
