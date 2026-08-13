"""Services page: start/restart/stop/purge for each project, local and
(if configured) remote, with live status shown next to the buttons and
live command output below."""
from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QGroupBox, QHBoxLayout, QLabel, QMessageBox, QProgressBar, QPushButton,
    QScrollArea, QTabWidget, QVBoxLayout, QWidget,
)

from core.docker_ctl import PROJECT_LABELS, Target
from ui.error_monitor import ErrorLogMonitor
from ui.health_diagram import is_problem, is_ready
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

    # A container `docker compose up` created but never got around to
    # starting -- happens if that `up` itself got interrupted partway
    # through (closed terminal/app, killed mid-command). Doesn't self-heal
    # and looks identical to a healthy "just hasn't been started yet"
    # state without calling it out specifically -- confirmed live this is
    # otherwise easy to mistake for "0/N up" (not started ON PURPOSE)
    # rather than "up got interrupted, re-run it."
    created = sum(1 for c in containers if c.get("State") == "created")
    if created:
        return f"{up}/{total} up ({created} created but never started -- re-run Start)", "#d9534f"

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


def _progress_counts(containers: list[dict]) -> tuple[int, int, bool]:
    """(ready, total, problem) for the start/restart progress bar, built on
    the same is_ready()/is_problem() the Health page uses so the notion of
    "up" agrees everywhere in the app."""
    total = len(containers)
    ready = sum(1 for c in containers if is_ready(c))
    problem = any(is_problem(c) for c in containers)
    return ready, total, problem


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
        # Whether we're currently tracking containers coming up after a
        # Start/Restart click, independent of _mutating_action -- `docker
        # compose up -d`/`restart` themselves return almost immediately,
        # long before the containers they started are actually healthy, so
        # this stays true (and the progress bar visible) across that whole
        # gap, driven by the same status-poll data that feeds status_label.
        self._starting = False
        self._start_verb = ""

        layout = QVBoxLayout(self)

        status_row = QHBoxLayout()
        self.status_label = QLabel("checking…")
        status_row.addWidget(QLabel("Status:"))
        status_row.addWidget(self.status_label)
        status_row.addStretch()
        layout.addLayout(status_row)

        self.progress = QProgressBar()
        self.progress.setVisible(False)
        self.progress.setTextVisible(True)
        layout.addWidget(self.progress)

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
        text, color = summarize_status(containers)
        self.status_label.setText(text)
        self.status_label.setStyleSheet(f"color: {color}; font-weight: bold;")
        self._update_progress(containers)

    def _begin_progress(self, verb: str) -> None:
        self._starting = True
        self._start_verb = verb
        # Indeterminate ("busy") until the next status poll actually reports
        # container counts -- otherwise the bar would have to sit at a
        # meaningless 0/0 for up to one poll interval right after the click.
        self.progress.setRange(0, 0)
        self.progress.setFormat(f"{verb}…")
        self.progress.setStyleSheet("")
        self.progress.setVisible(True)

    def _cancel_progress(self) -> None:
        self._starting = False
        self.progress.setVisible(False)

    def _update_progress(self, containers: list[dict]) -> None:
        if not self._starting:
            return
        if not containers:
            return  # stay indeterminate -- nothing reported yet
        ready, total, problem = _progress_counts(containers)
        self.progress.setRange(0, max(total, 1))
        self.progress.setValue(ready)
        self.progress.setFormat(f"{self._start_verb}… {ready}/{total} ready (%p%)")
        self.progress.setStyleSheet(
            "QProgressBar::chunk { background-color: #d9534f; }" if problem
            else "QProgressBar::chunk { background-color: #5cb85c; }"
        )
        if ready >= total:
            self._starting = False
            self.progress.setVisible(False)

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
        # immediately in a loop isn't useful there).
        if self._mutating_action:
            self._mutating_action = False
            # A nonzero exit here means `up -d`/`restart` itself failed
            # (bad compose file, image pull failure, etc.) -- no containers
            # will ever come up to drive _update_progress() to 100%, so the
            # bar would otherwise sit there indeterminate forever.
            if self._starting and _exit_code != 0:
                self._starting = False
                self.progress.setFormat(f"{self._start_verb} failed (exit {_exit_code})")
                self.progress.setRange(0, 1)
                self.progress.setValue(1)
                self.progress.setStyleSheet("QProgressBar::chunk { background-color: #d9534f; }")
            self._run("logs", "--tail=50", "-f", mutating=False)

    def _reload_logs(self) -> None:
        self._run("logs", "--tail=50", "-f", mutating=False)

    def _download_logs(self) -> None:
        self._log_exporter.export(self.target, self.target.key, None, self.target.label)

    def _start(self) -> None:
        self._begin_progress("Starting")
        self._run("up", "-d")

    def _restart(self) -> None:
        self._begin_progress("Restarting")
        self._run("restart")

    def _stop(self) -> None:
        self._cancel_progress()
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
            self._cancel_progress()
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
