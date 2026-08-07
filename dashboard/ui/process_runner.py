"""Runs a command via QProcess and streams its output into a QPlainTextEdit
-- shared by the Services page (start/stop/restart/purge), the Health page
(per-service restart/logs), and the Certificates page (regenerate).

One LogPanel = one QProcess at a time. Starting a new command while one is
already running kills the previous one first (there's no legitimate reason
to have two `docker compose` invocations racing against the same project
from this app).
"""
from __future__ import annotations

from PyQt6.QtCore import QProcess, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QTextCharFormat, QTextCursor
from PyQt6.QtWidgets import (
    QHBoxLayout, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget,
)

from ui.ansi import AnsiStyle, AnsiTextParser

_DEFAULT_TEXT_COLOR = "#d4d4d4"  # matches this panel's own stylesheet below


class LogPanel(QWidget):
    finished = pyqtSignal(int)  # exit code
    # Raw stdout chunks, emitted independent of pause state -- unlike
    # append()/_emit(), this never buffers or holds anything back, so a
    # consumer that wants to react to output as it happens (e.g.
    # page_exploits.py's threat-event parser) isn't at the mercy of the
    # log tail's own Pause button.
    line_received = pyqtSignal(str)

    def __init__(self, parent=None, show_stop_button: bool = True, reload_action=None):
        super().__init__(parent)
        self.process: QProcess | None = None
        self._paused = False
        self._pending: list[str] = []
        self._ansi = AnsiTextParser()
        self._last_argv: list[str] | None = None
        self._last_cwd: str | None = None
        # Overrides what the Reload button does, instead of blindly
        # replaying the last command run() was given. Needed by the
        # Services page: its LogPanel's "last command" is often a
        # mutating one (up -d/restart/down) that the panel only runs
        # once before auto-resuming a `logs -f` tail (see
        # page_services.py's TargetPanel) -- naively replaying THAT would
        # re-trigger the mutating command instead of showing logs, and
        # confirmed live this can loop indefinitely if Reload gets clicked
        # again before the mutating command finishes (each click kills
        # the in-flight one and starts a fresh one, so it can never reach
        # the point where it would auto-resume tailing on its own).
        self._reload_action = reload_action

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.text = QPlainTextEdit(readOnly=True)
        self.text.setMaximumBlockCount(5000)
        self.text.setStyleSheet(
            "QPlainTextEdit { background-color: #1e1e1e; color: #d4d4d4; "
            "font-family: monospace; font-size: 11px; }"
        )
        layout.addWidget(self.text)

        button_row = QHBoxLayout()

        self.pause_button = QPushButton("Pause")
        self.pause_button.clicked.connect(self._toggle_pause)
        button_row.addWidget(self.pause_button)

        self.catchup_button = QPushButton("Catch up (0)")
        self.catchup_button.clicked.connect(self._catch_up)
        self.catchup_button.setEnabled(False)
        button_row.addWidget(self.catchup_button)

        # Re-runs the last run() command from scratch (fresh process, fresh
        # output) -- only ever enabled once run() has actually been called,
        # since pages that only ever push lines in via append() (e.g. the
        # Certificates page's worker-thread output) have no command to
        # replay.
        self.reload_button = QPushButton("Reload")
        self.reload_button.clicked.connect(self._reload)
        self.reload_button.setEnabled(False)
        button_row.addWidget(self.reload_button)

        # The Services page already has its own Start/Restart/Stop/Purge
        # buttons directly above this panel -- a second "Stop" button here
        # would be redundant (and ambiguous: stopping WHAT, the compose
        # command or the containers?). Health/Certificates pages have no
        # such buttons of their own, so they keep it.
        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop)
        self.stop_button.setEnabled(False)
        self.stop_button.setVisible(show_stop_button)
        button_row.addWidget(self.stop_button)

        layout.addLayout(button_row)

    @staticmethod
    def _format_for(style: AnsiStyle) -> QTextCharFormat:
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(style.fg or _DEFAULT_TEXT_COLOR))
        if style.bg:
            fmt.setBackground(QColor(style.bg))
        if style.bold:
            fmt.setFontWeight(QFont.Weight.Bold)
        if style.italic:
            fmt.setFontItalic(True)
        if style.underline:
            fmt.setFontUnderline(True)
        return fmt

    def append(self, text: str) -> None:
        """text may contain raw ANSI SGR escape codes (e.g. from `docker
        compose --ansi always logs`) -- self._ansi turns those into styled
        segments instead of literal escape-code garbage. Plain text with no
        codes in it (worker-thread lines, the "$ ..." command echo below,
        "[process exited...]" banners) just comes back as one segment in
        the default color, unchanged from before."""
        cursor = self.text.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        for segment, style in self._ansi.feed(text):
            if segment:
                cursor.insertText(segment, self._format_for(style))
        self.text.setTextCursor(cursor)
        self.text.moveCursor(QTextCursor.MoveOperation.End)

    def clear(self) -> None:
        self.text.clear()
        self._ansi = AnsiTextParser()

    def run(self, argv: list[str], cwd: str | None = None) -> None:
        self.stop()
        self.clear()
        self._paused = False
        self.pause_button.setText("Pause")
        self._pending.clear()
        self.catchup_button.setEnabled(False)
        self.catchup_button.setText("Catch up (0)")
        self._last_argv = argv
        self._last_cwd = cwd
        self.reload_button.setEnabled(True)
        self.append(f"$ {' '.join(argv)}\n\n")

        self.process = QProcess(self)
        if cwd:
            self.process.setWorkingDirectory(cwd)
        self.process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self.process.readyReadStandardOutput.connect(self._on_output)
        self.process.finished.connect(self._on_finished)
        self.process.errorOccurred.connect(self._on_error)

        program, args = argv[0], argv[1:]
        self.process.start(program, args)
        self.stop_button.setEnabled(True)

    def _reload(self) -> None:
        if self._reload_action is not None:
            self._reload_action()
        elif self._last_argv is not None:
            self.run(self._last_argv, self._last_cwd)

    def is_running(self) -> bool:
        return self.process is not None and self.process.state() != QProcess.ProcessState.NotRunning

    def stop(self) -> None:
        if self.process is not None and self.process.state() != QProcess.ProcessState.NotRunning:
            self.process.kill()
            self.process.waitForFinished(2000)
        self.process = None
        self.stop_button.setEnabled(False)

    # ---- pause / catch-up ----
    #
    # Pausing does NOT stop the underlying process -- it keeps running and
    # producing output, which is buffered here instead of being appended to
    # the visible text, so a fast-scrolling live tail can be held still to
    # read without losing anything. "Catch up" flushes that buffer without
    # necessarily leaving pause mode, so you can jump to the latest output
    # and then keep reading from there without it immediately scrolling
    # away again.

    def _toggle_pause(self) -> None:
        self._paused = not self._paused
        self.pause_button.setText("Resume" if self._paused else "Pause")
        if not self._paused:
            self._flush_pending()

    def _catch_up(self) -> None:
        self._flush_pending()

    def _flush_pending(self) -> None:
        if self._pending:
            self.append("".join(self._pending))
            self._pending.clear()
        self.catchup_button.setEnabled(False)
        self.catchup_button.setText("Catch up (0)")

    def _emit(self, text: str) -> None:
        """Routes all output -- live stdout AND the finished/error banners
        below -- through the same pause-aware path, so pausing genuinely
        holds the view still with nothing slipping through, and catch-up
        reveals everything (including "process exited") in order."""
        if self._paused:
            self._pending.append(text)
            self.catchup_button.setEnabled(True)
            buffered_lines = sum(chunk.count("\n") for chunk in self._pending)
            self.catchup_button.setText(f"Catch up ({buffered_lines})")
        else:
            self.append(text)

    def _on_output(self) -> None:
        if self.process is None:
            return
        data = self.process.readAllStandardOutput().data().decode(errors="replace")
        self.line_received.emit(data)
        self._emit(data)

    def _on_finished(self, exit_code: int, _exit_status) -> None:
        self._emit(f"\n\n[process exited with code {exit_code}]\n")
        self.stop_button.setEnabled(False)
        self.finished.emit(exit_code)

    def _on_error(self, error) -> None:
        self._emit(f"\n[process error: {error}]\n")
        self.stop_button.setEnabled(False)
