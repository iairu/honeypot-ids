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
from ui.log_export import LogExporter
from ui.process_runner import LogPanel


def summarize_status(containers: list[dict]) -> tuple[str, str]:
    """Returns (summary_text, color) for a target's container list."""
    if not containers:
        return "not running / unreachable", "#888888"

    total = len(containers)
    running = sum(1 for c in containers if c.get("State") == "running")
    healthy = sum(1 for c in containers if c.get("Health") == "healthy")
    unhealthy = sum(1 for c in containers if c.get("Health") == "unhealthy")
    exited_bad = sum(
        1 for c in containers
        if c.get("State") == "exited" and str(c.get("ExitCode", "0")) not in ("0", "")
    )
    # Run-once-and-exit services (init_setup, honeypot_db_migration,
    # init-password, ...) are expected to end in State=exited/ExitCode=0 --
    # that's their successful terminal state, not a sign anything is down.
    # Count them toward "up" alongside actually-running containers so a
    # fully healthy stack doesn't sit permanently at "N/total up" (orange)
    # just because some of its services are one-shot jobs by design.
    exited_ok = sum(
        1 for c in containers
        if c.get("State") == "exited" and str(c.get("ExitCode", "0")) in ("0", "")
    )
    up = running + exited_ok

    if unhealthy or exited_bad:
        return f"{up}/{total} up ({unhealthy} unhealthy, {exited_bad} exited with error)", "#d9534f"
    if up == total:
        details = []
        if healthy:
            details.append(f"{healthy} healthy")
        if exited_ok:
            details.append(f"{exited_ok} completed")
        detail = f" ({', '.join(details)})" if details else ""
        return f"all {total} up{detail}", "#5cb85c"
    if up > 0:
        return f"{up}/{total} up", "#f0ad4e"
    return f"0/{total} up", "#888888"


class TargetPanel(QGroupBox):
    def __init__(self, target: Target, parent=None):
        super().__init__(target.label, parent)
        self.target = target
        # Whether the LogPanel's current process is a mutating compose
        # command (up/down/restart) vs. the harmless auto-tail (logs -f) --
        # used to warn before quitting mid-operation without nagging the
        # user every time (the auto-tail is running almost constantly), and
        # to know whether to auto-resume the tail once it finishes (see
        # _on_log_finished).
        self._mutating_action = False
        self._log_exporter = LogExporter(self)

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
        self.download_btn = QPushButton("Download logs…")
        for b in (self.start_btn, self.restart_btn, self.stop_btn, self.purge_btn, self.download_btn):
            button_row.addWidget(b)
        layout.addLayout(button_row)

        self.start_btn.clicked.connect(self._start)
        self.restart_btn.clicked.connect(self._restart)
        self.stop_btn.clicked.connect(self._stop)
        self.purge_btn.clicked.connect(self._purge)
        self.download_btn.clicked.connect(self._download_logs)

        log_label = QLabel(
            "Logs (auto-tailing -- Start/Restart/Stop/Purge takes over this "
            "panel, then returns to auto-tailing once the command finishes):"
        )
        log_label.setStyleSheet("color: #888888;")
        layout.addWidget(log_label)

        # No Stop button on this LogPanel -- Start/Restart/Stop/Purge above
        # already cover stopping/controlling this target, a second "Stop"
        # here would just be redundant (and ambiguous about what it stops).
        self.log_panel = LogPanel(show_stop_button=False)
        self.log_panel.setMinimumHeight(160)
        self.log_panel.finished.connect(self._on_log_finished)
        layout.addWidget(self.log_panel)

        # Auto-show logs immediately rather than waiting for a button click
        # -- for a remote target with bad SSH config this also surfaces the
        # connectivity problem right away instead of only on the next
        # manual action.
        self._run("logs", "--tail=50", "-f", mutating=False)

    def update_status(self, containers: list[dict]) -> None:
        text, color = summarize_status(containers)
        self.status_label.setText(text)
        self.status_label.setStyleSheet(f"color: {color}; font-weight: bold;")

    def is_mutating_action_running(self) -> bool:
        return self._mutating_action and self.log_panel.is_running()

    def _run(self, *compose_args: str, mutating: bool = True) -> None:
        self._mutating_action = mutating
        argv, cwd = self.target.build(*compose_args)
        self.log_panel.run(argv, cwd)

    def _on_log_finished(self, _exit_code: int) -> None:
        # `docker compose up -d` (and restart/down/down -v) exit as soon as
        # the command completes -- with -d, that's almost immediately, so
        # the panel would otherwise just sit there showing "process exited
        # with code 0" instead of going back to showing what the containers
        # are actually doing. Resume the live tail once a mutating action
        # finishes; don't do this for the tail itself finishing (would only
        # happen on a genuine failure/all-containers-gone, and retrying
        # immediately in a loop isn't useful there).
        if self._mutating_action:
            self._mutating_action = False
            self._run("logs", "--tail=50", "-f", mutating=False)

    def _download_logs(self) -> None:
        self._log_exporter.export(self.target, self.target.key, None, self.target.label)

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

    def any_mutating_action_running(self) -> bool:
        """True if any panel has an in-flight up/down/restart/purge --
        used to warn before quitting mid-operation. Deliberately excludes
        the auto-tail log stream, which is always running and harmless to
        interrupt."""
        return any(p.is_mutating_action_running() for p in self.panels.values())

    def apply_status(self, results: dict[str, list[dict]]) -> None:
        for key, containers in results.items():
            if key in self.panels:
                self.panels[key].update_status(containers)
