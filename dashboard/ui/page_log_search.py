"""Global log search: grep-style search across every configured target's
containers at once (both projects, local + remote), instead of only ever
being able to tail one service's log at a time on the Services page.

Runs `docker compose logs --tail=<N>` (no -f, no specific service -- every
container in that target's project, with --ansi always) per selected
target, filters the captured output by the search string, and shows
matching lines prefixed with which target they came from -- in real color,
via the same ANSI rendering ui/process_runner.LogPanel uses (ui/
ansi_render.py): docker compose colors each service's own prefix
differently when tailing multiple services combined, which is genuinely
useful for telling matches from different containers apart at a glance,
on top of whatever coloring the underlying app's own log lines carry.
Matching itself still runs against the ANSI-stripped text (so escape codes
can't hide/split a search term), only DISPLAY keeps the original codes.

Runs in a background QThread (mirroring ui/status_poller.StatusPoller's own
reasoning) so a slow/unreachable remote target never freezes the UI.
"""
from __future__ import annotations

import re
import subprocess

from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox, QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit, QPushButton,
    QSpinBox, QVBoxLayout, QWidget,
)

from core.docker_ctl import Target, all_targets
from core.state import AppState
from ui import ansi_render, theme

MAX_DISPLAYED_MATCHES = 500

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


class LogSearchWorker(QThread):
    results_ready = pyqtSignal(list, list)  # matching lines, errors

    def __init__(
        self, targets: list[Target], query: str, tail: int, case_sensitive: bool,
        parent=None,
    ):
        super().__init__(parent)
        self._targets = targets
        self._query = query
        self._tail = tail
        self._case_sensitive = case_sensitive

    def run(self) -> None:
        matches: list[str] = []
        errors: list[str] = []
        needle = self._query if self._case_sensitive else self._query.lower()

        for target in self._targets:
            argv, cwd = target.build("logs", f"--tail={self._tail}")
            try:
                result = subprocess.run(
                    argv, cwd=cwd, capture_output=True, text=True, timeout=30,
                )
            except (subprocess.TimeoutExpired, OSError) as e:
                errors.append(f"{target.label}: {e}")
                continue
            if result.returncode != 0 and not result.stdout:
                errors.append(f"{target.label}: {result.stderr.strip()[:200] or 'command failed'}")
                continue

            for line in result.stdout.splitlines():
                clean = _ANSI_RE.sub("", line)
                haystack = clean if self._case_sensitive else clean.lower()
                if needle in haystack:
                    # Keep the ORIGINAL line (with its ANSI codes intact)
                    # for display -- only the target-label prefix is plain
                    # text. Matching above ran against `clean` so escape
                    # codes can't hide/split the search term.
                    matches.append(f"[{target.label}] {line}")
                    if len(matches) >= MAX_DISPLAYED_MATCHES:
                        self.results_ready.emit(matches, errors)
                        return

        self.results_ready.emit(matches, errors)


class LogSearchPage(QWidget):
    def __init__(self, state: AppState, parent=None):
        super().__init__(parent)
        self.state = state
        self._worker: LogSearchWorker | None = None
        self._target_checks: dict[str, QCheckBox] = {}

        layout = QVBoxLayout(self)

        search_row = QHBoxLayout()
        search_row.addWidget(QLabel("Search:"))
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Text to search for across every selected target's containers...")
        self.search_box.returnPressed.connect(self.run_search)
        search_row.addWidget(self.search_box, stretch=1)

        self.case_check = QCheckBox("Case sensitive")
        search_row.addWidget(self.case_check)

        search_row.addWidget(QLabel("Lines/container:"))
        self.tail_spin = QSpinBox()
        self.tail_spin.setRange(100, 20000)
        self.tail_spin.setSingleStep(500)
        self.tail_spin.setValue(2000)
        search_row.addWidget(self.tail_spin)

        self.search_btn = QPushButton("Search")
        self.search_btn.clicked.connect(self.run_search)
        search_row.addWidget(self.search_btn)
        layout.addLayout(search_row)

        targets_row = QHBoxLayout()
        targets_row.addWidget(QLabel("Targets:"))
        self._targets_container = targets_row
        layout.addLayout(targets_row)
        self.rebuild_targets()

        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: #888888;")
        layout.addWidget(self.status_label)

        self.results = QPlainTextEdit(readOnly=True)
        self.results.setPlaceholderText("Results will appear here.")
        layout.addWidget(self.results, stretch=1)
        self._apply_theme_colors()
        theme.on_change(self._apply_theme_colors)

    def rebuild_targets(self) -> None:
        """Call when remote settings change -- rebuilds the target
        checkbox list without losing which ones were already checked, for
        any target key that still exists after the change."""
        previously_checked = {key for key, cb in self._target_checks.items() if cb.isChecked()}

        while self._targets_container.count() > 1:  # keep the "Targets:" label
            item = self._targets_container.takeAt(1)
            if item.widget():
                item.widget().deleteLater()
        self._target_checks.clear()

        for target in all_targets(self.state.remote_edge, self.state.remote_siem):
            cb = QCheckBox(target.label)
            cb.setChecked(target.key in previously_checked or not previously_checked)
            self._targets_container.addWidget(cb)
            self._target_checks[target.key] = cb
        self._targets_container.addStretch()

    def _apply_theme_colors(self) -> None:
        self.results.setStyleSheet(ansi_render.panel_stylesheet())

    def focus_search_box(self) -> None:
        self.search_box.setFocus()
        self.search_box.selectAll()

    def _selected_targets(self) -> list[Target]:
        all_t = all_targets(self.state.remote_edge, self.state.remote_siem)
        return [t for t in all_t if self._target_checks.get(t.key) and self._target_checks[t.key].isChecked()]

    def run_search(self) -> None:
        query = self.search_box.text().strip()
        if not query:
            return
        targets = self._selected_targets()
        if not targets:
            self.status_label.setText("No targets selected.")
            return

        if self._worker is not None and self._worker.isRunning():
            return  # a search is already in flight

        self.search_btn.setEnabled(False)
        self.status_label.setText(f"Searching {len(targets)} target(s)...")
        self.results.clear()

        self._worker = LogSearchWorker(targets, query, self.tail_spin.value(), self.case_check.isChecked())
        self._worker.results_ready.connect(self._on_results)
        self._worker.start()

    def _on_results(self, matches: list[str], errors: list[str]) -> None:
        self.search_btn.setEnabled(True)
        self.results.clear()

        if not matches:
            self.results.setPlainText("(no matches)")
        else:
            default_color = ansi_render.panel_colors()[1]
            for line in matches:
                # Fresh parser per line, not one shared across the whole
                # result set -- each match is an independent line from
                # (possibly) a different container/point in time, so SGR
                # state from one match's colors must not bleed into the
                # next the way it correctly would within one continuous
                # live tail (ui/process_runner.LogPanel's own use case).
                ansi_render.append(self.results, ansi_render.make_parser(), line + "\n", default_color)

        status = f"{len(matches)} match(es)"
        if len(matches) >= MAX_DISPLAYED_MATCHES:
            status += f" (capped at {MAX_DISPLAYED_MATCHES}, refine your search)"
        if errors:
            status += " -- " + "; ".join(errors)
        self.status_label.setText(status)
