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
from PyQt6.QtGui import QTextCursor
from PyQt6.QtWidgets import QPlainTextEdit, QPushButton, QVBoxLayout, QWidget


class LogPanel(QWidget):
    finished = pyqtSignal(int)  # exit code

    def __init__(self, parent=None):
        super().__init__(parent)
        self.process: QProcess | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.text = QPlainTextEdit(readOnly=True)
        self.text.setMaximumBlockCount(5000)
        self.text.setStyleSheet(
            "QPlainTextEdit { background-color: #1e1e1e; color: #d4d4d4; "
            "font-family: monospace; font-size: 11px; }"
        )
        layout.addWidget(self.text)

        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop)
        self.stop_button.setEnabled(False)
        layout.addWidget(self.stop_button)

    def append(self, text: str) -> None:
        self.text.moveCursor(QTextCursor.MoveOperation.End)
        self.text.insertPlainText(text)
        self.text.moveCursor(QTextCursor.MoveOperation.End)

    def clear(self) -> None:
        self.text.clear()

    def run(self, argv: list[str], cwd: str | None = None) -> None:
        self.stop()
        self.clear()
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

    def is_running(self) -> bool:
        return self.process is not None and self.process.state() != QProcess.ProcessState.NotRunning

    def stop(self) -> None:
        if self.process is not None and self.process.state() != QProcess.ProcessState.NotRunning:
            self.process.kill()
            self.process.waitForFinished(2000)
        self.process = None
        self.stop_button.setEnabled(False)

    def _on_output(self) -> None:
        if self.process is None:
            return
        data = self.process.readAllStandardOutput().data().decode(errors="replace")
        self.append(data)

    def _on_finished(self, exit_code: int, _exit_status) -> None:
        self.append(f"\n\n[process exited with code {exit_code}]\n")
        self.stop_button.setEnabled(False)
        self.finished.emit(exit_code)

    def _on_error(self, error) -> None:
        self.append(f"\n[process error: {error}]\n")
        self.stop_button.setEnabled(False)
