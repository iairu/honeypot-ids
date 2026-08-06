"""Shared "export logs to a file" helper -- used by the Health page (one
container at a time, via a node's corner icon) and the Services page (a
whole target/project's combined logs, via a button on each panel).
Factored out from what was originally page_health.py-only logic so both
pages share one implementation instead of drifting apart."""
from __future__ import annotations

from datetime import datetime

from PyQt6.QtCore import QProcess
from PyQt6.QtWidgets import QInputDialog, QMessageBox, QWidget

from core.docker_ctl import Target
from core.paths import LOG_DIR


class LogExporter:
    """Owns the list of in-flight export QProcess objects so they aren't
    garbage-collected mid-run. One instance per page that offers exports."""

    def __init__(self, parent: QWidget):
        self._parent = parent
        self._export_processes: list[QProcess] = []

    def export(self, target: Target, target_key: str, service: str | None, label: str) -> None:
        """service=None exports the whole target/project's combined logs
        (`docker compose logs`, no service arg); otherwise just that one
        container's logs."""
        lines, ok = QInputDialog.getInt(
            self._parent, f"Export logs — {label}",
            "How many lines (most recent)? 0 = entire log:",
            200, 0, 1_000_000,
        )
        if not ok:
            return

        log_args = ["logs", "--no-color"]
        if lines > 0:
            log_args.append(f"--tail={lines}")
        if service:
            log_args.append(service)
        argv, cwd = target.build(*log_args)

        LOG_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_label = label.replace("/", "_").replace(" ", "_")
        out_path = LOG_DIR / f"{target_key}_{safe_label}_{timestamp}.log"

        process = QProcess(self._parent)
        process.setProgram(argv[0])
        process.setArguments(argv[1:])
        if cwd:
            process.setWorkingDirectory(cwd)
        process.setStandardOutputFile(str(out_path))
        process.setProcessChannelMode(QProcess.ProcessChannelMode.SeparateChannels)

        def _on_finished(exit_code: int, _status, path=out_path, proc=process) -> None:
            self._export_processes.remove(proc)
            if exit_code == 0 and path.exists() and path.stat().st_size > 0:
                QMessageBox.information(
                    self._parent, "Logs exported",
                    f"{label} logs ({'all' if lines == 0 else lines} lines) "
                    f"written to:\n\n{path}",
                )
            else:
                stderr = bytes(proc.readAllStandardError()).decode(errors="replace").strip()
                QMessageBox.warning(
                    self._parent, "Log export produced no output",
                    f"'docker compose logs' for {label} exited with code "
                    f"{exit_code} and produced no log content.\n\n"
                    + (stderr or "(no error output -- the container may have no logs yet)"),
                )

        process.finished.connect(_on_finished)
        self._export_processes.append(process)
        process.start()
