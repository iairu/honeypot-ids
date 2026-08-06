"""Certificates page: regenerate per service/group, or all, via cert_ctl.
Runs regeneration in a background thread (openssl calls are fast but
several run in sequence for "all", and blocking the UI thread even
briefly for a click is bad practice)."""
from __future__ import annotations

from PyQt6.QtCore import QThread, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QGroupBox, QHBoxLayout, QLabel, QMessageBox, QPushButton, QScrollArea,
    QSplitter, QVBoxLayout, QWidget,
)

from core.cert_ctl import CERT_GROUPS, CertError, regenerate
from ui.process_runner import LogPanel


class CertWorker(QThread):
    line = pyqtSignal(str)
    done = pyqtSignal(bool, str)  # success, message

    def __init__(self, group_id: str, parent=None):
        super().__init__(parent)
        self.group_id = group_id

    def run(self) -> None:
        try:
            regenerate(self.group_id, log=lambda msg: self.line.emit(msg + "\n"))
            self.done.emit(True, "Done.")
        except CertError as e:
            self.done.emit(False, str(e))


class CertsPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._worker: CertWorker | None = None

        outer = QVBoxLayout(self)

        warn = QLabel(
            "Regenerating a service's certificate reuses the existing SIEM CA "
            "(unless you pick \"full CA + all service certs\", which rotates "
            "the CA itself and invalidates every previously-issued cert). "
            "Affected containers need a restart afterward to pick up new files."
        )
        warn.setWordWrap(True)
        outer.addWidget(warn)

        # Horizontal split (buttons left, console right) rather than
        # stacking the console below the button list -- with 6+ cert
        # groups, a fixed-height console below ate enough vertical space
        # that the button list needed scrolling to see every group. The
        # console now gets its own full-height column instead.
        splitter = QSplitter(Qt.Orientation.Horizontal)
        outer.addWidget(splitter, stretch=1)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        splitter.addWidget(scroll)

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        scroll.setWidget(inner)

        for group in CERT_GROUPS:
            box = QGroupBox(group.label)
            box_layout = QVBoxLayout(box)
            desc = QLabel(group.description)
            desc.setWordWrap(True)
            desc.setStyleSheet("color: #888888;")
            box_layout.addWidget(desc)

            btn = QPushButton("Regenerate")
            btn.clicked.connect(lambda _checked, gid=group.id, glabel=group.label: self._regenerate(gid, glabel))
            box_layout.addWidget(btn)

            inner_layout.addWidget(box)

        all_box = QGroupBox("Regenerate everything")
        all_layout = QHBoxLayout(all_box)
        all_btn = QPushButton("Regenerate ALL cert groups above, in order")
        all_btn.clicked.connect(self._regenerate_all)
        all_layout.addWidget(all_btn)
        inner_layout.addWidget(all_box)

        console_panel = QWidget()
        console_layout = QVBoxLayout(console_panel)
        console_layout.setContentsMargins(0, 0, 0, 0)
        console_layout.addWidget(QLabel("<b>Output</b>"))

        self.log_panel = LogPanel()
        self.log_panel.stop_button.setVisible(False)  # cert generation isn't interruptible mid-openssl-call
        console_layout.addWidget(self.log_panel, stretch=1)

        console_panel.setMinimumWidth(320)
        splitter.addWidget(console_panel)
        splitter.setSizes([420, 480])

        self._queue: list[str] = []

    def _regenerate(self, group_id: str, label: str) -> None:
        if group_id == "siem-all":
            reply = QMessageBox.warning(
                self, "Confirm CA rotation",
                "This rotates the SIEM's root CA and re-issues every SIEM "
                "service's certificate. Any previously-distributed "
                "vector-agent client cert on the edge host becomes invalid "
                "until it's re-copied (this tool does that automatically), "
                "and es01/kibana/vector all need a restart afterward.\n\nContinue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return

        self.log_panel.clear()
        self.log_panel.append(f"=== {label} ===\n")
        self._worker = CertWorker(group_id)
        self._worker.line.connect(self.log_panel.append)
        self._worker.done.connect(self._on_group_done)
        self._worker.start()

    def _regenerate_all(self) -> None:
        reply = QMessageBox.warning(
            self, "Confirm full regeneration",
            "This regenerates every certificate group, including a full "
            "SIEM CA rotation. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        self.log_panel.clear()
        # "siem-all" already covers every siem-* group; only append edge-nginx.
        self._queue = ["siem-all", "edge-nginx"]
        self._run_next_in_queue()

    def _run_next_in_queue(self) -> None:
        if not self._queue:
            return
        group_id = self._queue.pop(0)
        label = next((g.label for g in CERT_GROUPS if g.id == group_id), group_id)
        self.log_panel.append(f"\n=== {label} ===\n")
        self._worker = CertWorker(group_id)
        self._worker.line.connect(self.log_panel.append)
        self._worker.done.connect(self._on_queue_step_done)
        self._worker.start()

    def _on_queue_step_done(self, success: bool, message: str) -> None:
        if not success:
            self.log_panel.append(f"\n[FAILED] {message}\n")
            self._queue.clear()
            return
        self._run_next_in_queue()

    def _on_group_done(self, success: bool, message: str) -> None:
        if not success:
            self.log_panel.append(f"\n[FAILED] {message}\n")
