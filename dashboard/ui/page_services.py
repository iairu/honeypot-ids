"""Services page: start/restart/stop/purge for each project, local and
(if configured) remote, with live status shown next to the buttons and
live command output below."""
from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QGroupBox, QHBoxLayout, QLabel, QPushButton, QScrollArea, QTabWidget,
    QVBoxLayout, QWidget,
)

from core.container_status import summarize
from core.docker_ctl import Target
from ui.common import confirm, danger_button, muted_label, set_status
from ui.error_monitor import ErrorLogMonitor
from ui.log_export import LogExporter
from ui.process_runner import LogPanel


class TargetPanel(QGroupBox):
    def __init__(self, target: Target, error_monitor: ErrorLogMonitor | None = None, parent=None):
        super().__init__(target.label, parent)
        self.target = target
        self._error_monitor = error_monitor
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
        self.purge_btn = danger_button("Purge (⚠ deletes volumes)")
        self.download_btn = QPushButton("Download logs…")
        for b in (self.start_btn, self.restart_btn, self.stop_btn, self.purge_btn, self.download_btn):
            button_row.addWidget(b)
        layout.addLayout(button_row)

        self.start_btn.clicked.connect(self._start)
        self.restart_btn.clicked.connect(self._restart)
        self.stop_btn.clicked.connect(self._stop)
        self.purge_btn.clicked.connect(self._purge)
        self.download_btn.clicked.connect(self._download_logs)

        layout.addWidget(muted_label(
            "Logs (auto-tailing -- Start/Restart/Stop/Purge takes over this "
            "panel, then returns to auto-tailing once the command finishes):"
        ))

        # No Stop button on this LogPanel -- Start/Restart/Stop/Purge above
        # already cover stopping/controlling this target, a second "Stop"
        # here would just be redundant (and ambiguous about what it stops).
        # reload_action overrides Reload to always switch to tailing logs
        # rather than replaying whatever command last ran here -- that's
        # frequently a mutating one (up -d/restart/down), and naively
        # replaying it would re-trigger it instead of showing logs;
        # confirmed live this could loop indefinitely if Reload was
        # clicked again before the mutating command finished (each click
        # kills the in-flight one and restarts it, so it never reaches
        # the point where _on_log_finished would auto-resume the tail).
        self.log_panel = LogPanel(show_stop_button=False, reload_action=self._reload_logs)
        self.log_panel.setMinimumHeight(160)
        self.log_panel.finished.connect(self._on_log_finished)
        if self._error_monitor is not None:
            self.log_panel.line_received.connect(self._on_log_line)
        layout.addWidget(self.log_panel)

        # Auto-show logs immediately rather than waiting for a button click
        # -- for a remote target with bad SSH config this also surfaces the
        # connectivity problem right away instead of only on the next
        # manual action.
        self._run("logs", "--tail=50", "-f", mutating=False)

    def update_status(self, containers: list[dict]) -> None:
        text, color = summarize(containers)
        set_status(self.status_label, text, color, bold=True)

    def is_mutating_action_running(self) -> bool:
        return self._mutating_action and self.log_panel.is_running()

    def _run(self, *compose_args: str, mutating: bool = True) -> None:
        self._mutating_action = mutating
        # A fresh `logs -f` tail replays its own `--tail=50` scrollback --
        # reset this target's error counts so that scrollback isn't
        # double-counted on top of whatever it already contributed the
        # last time this same tail started (see ErrorLogMonitor.reset()).
        if compose_args and compose_args[0] == "logs" and self._error_monitor is not None:
            self._error_monitor.reset(self.target.key)
        argv, cwd = self.target.build(*compose_args)
        self.log_panel.run(argv, cwd)

    def _on_log_line(self, text: str) -> None:
        self._error_monitor.process_chunk(self.target.key, text)

    def _on_log_finished(self, _exit_code: int) -> None:
        # `docker compose up -d` (and restart/down/down -v) exit as soon as
        # the command completes -- with -d, that's almost immediately, so
        # the panel would otherwise just sit there showing "process exited
        # with code 0" instead of going back to showing what the containers
        # are actually doing. Resume the live tail once a mutating action
        # finishes; don't do this for the tail itself finishing (would only
        # happen on a genuine failure/all-containers-gone, and retrying
        # immediately in a loop isn't useful there). The log panel's own
        # "[process exited with code N]" banner (ui/process_runner.py)
        # already surfaces success/failure -- no separate indicator needed
        # here.
        if self._mutating_action:
            self._mutating_action = False
            self._run("logs", "--tail=50", "-f", mutating=False)

    def _reload_logs(self) -> None:
        self._run("logs", "--tail=50", "-f", mutating=False)

    def _download_logs(self) -> None:
        self._log_exporter.export(self.target, self.target.key, None, self.target.label)

    def _start(self) -> None:
        self._run("up", "-d")

    def _restart(self) -> None:
        # `docker compose restart` only acts on containers that already
        # exist and are running -- after a Purge (down -v), a Stop, or a
        # partially-created state it silently does nothing, so "Restart"
        # appeared broken (nothing came up). `up -d --force-recreate`
        # (with --remove-orphans appended by Target._augment_args) cycles
        # every service from ANY prior state -- down, created, or running
        # -- so Restart reliably lands the stack in a fresh running state.
        self._run("up", "-d", "--force-recreate")

    def _stop(self) -> None:
        self._run("down")

    def _purge(self) -> None:
        if confirm(
            self, "Confirm purge",
            f"This will run 'docker compose down -v' for {self.target.label}, "
            "permanently deleting all named volumes (databases, Redis data, "
            "Elasticsearch indices, everything) for this stack.\n\n"
            "This cannot be undone. Continue?",
        ):
            self._run("down", "-v")


class ServicesPage(QWidget):
    def __init__(self, get_targets, error_monitor: ErrorLogMonitor | None = None, parent=None):
        super().__init__(parent)
        self._get_targets = get_targets
        self._error_monitor = error_monitor
        self.panels: dict[str, TargetPanel] = {}
        self._tab_view = True

        outer = QVBoxLayout(self)

        toggle_row = QHBoxLayout()
        toggle_row.addStretch()
        self.view_toggle_btn = QPushButton("Switch to stack view")
        self.view_toggle_btn.clicked.connect(self._toggle_view)
        toggle_row.addWidget(self.view_toggle_btn)
        outer.addLayout(toggle_row)

        # Stack view (toggle): every target's panel one below another in a
        # scroll area -- see everything at once, scroll to find one.
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        outer.addWidget(self.scroll)

        inner = QWidget()
        self.inner_layout = QVBoxLayout(inner)
        self.inner_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.scroll.setWidget(inner)

        # Tab view (default): one tab per target -- only one panel's log
        # tail/controls visible at a time, useful once there are enough
        # targets (local + remote x2 projects) that the stack view means
        # a lot of scrolling to reach the one you want.
        self.tab_widget = QTabWidget()
        self.tab_widget.setVisible(True)
        outer.addWidget(self.tab_widget)

        self.rebuild_panels()

    def _toggle_view(self) -> None:
        self._tab_view = not self._tab_view
        self.view_toggle_btn.setText("Switch to stack view" if self._tab_view else "Switch to tab view")
        self._populate_current_view()

    def rebuild_panels(self) -> None:
        """Call after remote settings change, so newly-configured remote
        targets get their own panel without restarting the app."""
        for panel in self.panels.values():
            panel.deleteLater()
        self.panels.clear()

        for target in self._get_targets():
            self.panels[target.key] = TargetPanel(target, self._error_monitor)

        self._populate_current_view()

    def _populate_current_view(self) -> None:
        # Detach every panel from whichever container currently holds it
        # -- removeTab()/takeAt() detach the widget without deleting it,
        # and addTab()/addWidget() below reparents it into the other
        # container. Panels themselves are constructed once (rebuild_
        # panels()) and just move between the two views on toggle, so
        # each one's auto-tailing log process keeps running uninterrupted
        # regardless of which view is currently shown.
        while self.inner_layout.count():
            self.inner_layout.takeAt(0)
        while self.tab_widget.count():
            self.tab_widget.removeTab(0)

        for target in self._get_targets():
            panel = self.panels.get(target.key)
            if panel is None:
                continue
            if self._tab_view:
                self.tab_widget.addTab(panel, target.label)
            else:
                self.inner_layout.addWidget(panel)
                # QTabWidget hides every tab page except the currently
                # selected one, and removeTab() doesn't restore visibility
                # on the way out -- confirmed live: switching back to
                # stack view left every panel that wasn't the active tab
                # invisible (a blank-looking page), since addWidget()
                # alone doesn't undo that hidden state.
                panel.setVisible(True)

        self.scroll.setVisible(not self._tab_view)
        self.tab_widget.setVisible(self._tab_view)

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
