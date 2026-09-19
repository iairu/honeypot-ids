"""Backups page: lists the DB dumps + WordPress file archives backup_service
(ids / edge project) has written under /backups, plus a tail of
its structured backup.log, and lets you restore either kind of backup back
onto the live production stack -- see core/backup_ctl.py for exactly how
each restore path works and why they differ.

Also covers the full lifecycle around those backups -- label/rename,
delete, export to a local file, import from one (ids/backups/
manage_backups.sh is the non-dashboard equivalent, sharing the exact same
labels.json manifest) -- and a "Reset demo store" action that re-runs the
WP-CLI seed script (scripts/seed_production_db.sh) to rebuild a clean
WooCommerce/Elementor storefront, e.g. after exploits have been run
against it."""
from __future__ import annotations

import html

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QFileDialog, QGroupBox, QHBoxLayout, QHeaderView, QInputDialog,
    QLabel, QMessageBox, QPlainTextEdit, QPushButton, QSplitter, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from core.backup_ctl import (
    BackupCtlError, BackupFile, delete_backup, export_backup, import_backup,
    list_backups, read_backup_log, reseed_command, restore_db_command,
    restore_wp_command, set_label,
)
from core.colors import GREEN, RED
from core.docker_ctl import targets_for
from core.state import AppState
from ui.common import ErrorBanner, TargetSelector, confirm, danger_button
from ui.process_runner import LogPanel


def _human_size(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


class _BackupTable(QTableWidget):
    def __init__(self, parent=None):
        super().__init__(0, 3, parent)
        self.setHorizontalHeaderLabels(["Filename (date)", "Size", "Label"])
        self.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._files: list[BackupFile] = []

    def set_files(self, files: list[BackupFile]) -> None:
        self._files = files
        self.setRowCount(len(files))
        for row, f in enumerate(files):
            when = f.mtime.strftime("%Y-%m-%d %H:%M:%S UTC")
            self.setItem(row, 0, QTableWidgetItem(f"{f.filename}\n{when}"))
            self.setItem(row, 1, QTableWidgetItem(_human_size(f.size_bytes)))
            self.setItem(row, 2, QTableWidgetItem(f.label or ""))

    def selected_file(self) -> BackupFile | None:
        rows = self.selectionModel().selectedRows()
        if not rows:
            return None
        row = rows[0].row()
        if row >= len(self._files):
            return None
        return self._files[row]


class BackupsPage(QWidget):
    def __init__(self, state: AppState, parent=None):
        super().__init__(parent)
        self.state = state

        layout = QVBoxLayout(self)

        toolbar = QHBoxLayout()
        toolbar.addWidget(QLabel("Target:"))
        self.target_combo = TargetSelector(lambda: targets_for("edge", self.state))
        toolbar.addWidget(self.target_combo)
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh)
        toolbar.addWidget(self.refresh_btn)
        toolbar.addStretch()
        # Page-level, not tied to either table -- rebuilds the live demo
        # storefront from scratch via production_db_seed (see
        # core/backup_ctl.reseed_command). Not a "backup" action itself,
        # but lives here since it's the same "reset the eshop's data to a
        # known state" family of operation as restore.
        self.reseed_btn = danger_button("Reset demo store…", self._reseed)
        toolbar.addWidget(self.reseed_btn)
        layout.addLayout(toolbar)

        self.error_banner = ErrorBanner()
        layout.addWidget(self.error_banner)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(splitter, stretch=2)

        self.db_table = _BackupTable()
        splitter.addWidget(self._build_backup_group(
            "Database dumps", self.db_table, "db", "Restore selected dump…", self._restore_db,
        ))
        self.wp_table = _BackupTable()
        splitter.addWidget(self._build_backup_group(
            "WordPress file archives", self.wp_table, "wp", "Restore selected archive…", self._restore_wp,
        ))

        activity_box = QGroupBox("Recent backup activity (backup.log)")
        activity_layout = QVBoxLayout(activity_box)
        self.activity_view = QPlainTextEdit(readOnly=True)
        self.activity_view.setMaximumBlockCount(500)
        self.activity_view.setStyleSheet("QPlainTextEdit { font-family: monospace; font-size: 11px; }")
        self.activity_view.setMaximumHeight(140)
        activity_layout.addWidget(self.activity_view)
        layout.addWidget(activity_box)

        layout.addWidget(QLabel("Restore / reset output:"))
        self.log_panel = LogPanel(show_stop_button=False)
        self.log_panel.setMinimumHeight(140)
        self.log_panel.finished.connect(self._on_action_finished)
        layout.addWidget(self.log_panel, stretch=1)

        self.target_combo.currentIndexChanged.connect(self.refresh)
        self.refresh()

    def _build_backup_group(
        self, title: str, table: _BackupTable, kind: str, restore_text: str, restore_fn,
    ) -> QGroupBox:
        """One of the two backup-kind panels: its table, the shared
        Label/Export/Import/Delete row, and the kind's restore button."""
        box = QGroupBox(title)
        box_layout = QVBoxLayout(box)
        box_layout.addWidget(table)

        btn_row = QHBoxLayout()
        for text, handler in (
            ("Label…", lambda: self._label(table)),
            ("Export…", lambda: self._export(table)),
            ("Import…", lambda: self._import(kind)),
        ):
            btn = QPushButton(text)
            btn.clicked.connect(handler)
            btn_row.addWidget(btn)
        btn_row.addWidget(danger_button("Delete", lambda: self._delete(table)))
        box_layout.addLayout(btn_row)

        box_layout.addWidget(danger_button(restore_text, restore_fn))
        return box

    def showEvent(self, event) -> None:
        """Refreshes the backup listing + activity log the moment this
        page becomes visible -- backup_service runs on its own 24h loop
        independently of whether this page is open, so without this,
        switching away and back could show a listing that's hours stale
        (or still showing an unreachable-target error banner from before
        the target came back up). refresh() only re-populates the tables/
        log view and error banner -- the target dropdown selection is
        untouched."""
        super().showEvent(event)
        self.refresh()

    def rebuild_targets(self) -> None:
        """Call when remote settings change (Settings page / setup wizard)."""
        self.target_combo.rebuild()

    def refresh(self) -> None:
        remote = self.target_combo.current_remote()
        try:
            db_files, wp_files = list_backups(remote)
            log_entries = read_backup_log(remote, tail=50)
            error = None
        except BackupCtlError as e:
            db_files, wp_files, log_entries = [], [], []
            error = str(e)

        self.db_table.set_files(db_files)
        self.wp_table.set_files(wp_files)

        self.activity_view.clear()
        for entry in log_entries:
            color = RED if entry.status == "failure" else GREEN
            line = f"{entry.timestamp}  {entry.status:8s} {entry.step:12s} {entry.detail}"
            line_html = html.escape(line).replace(" ", "&nbsp;")
            self.activity_view.appendHtml(f'<span style="color:{color};">{line_html}</span>')

        self.error_banner.set_error(error, prefix="⚠ backup_service unreachable: ")

    def _restore_db(self) -> None:
        target = self.target_combo.current_target()
        selected = self.db_table.selected_file()
        if target is None or selected is None:
            return
        if not confirm(
            self, "Confirm database restore",
            f"This will overwrite the LIVE production database on {target.label} "
            f"with the contents of:\n\n{selected.filename}\n"
            f"({selected.mtime.strftime('%Y-%m-%d %H:%M:%S UTC')})\n\n"
            "Any data written since that backup was taken (including anything "
            "an attacker may have added since) will be lost. This cannot be undone. "
            "Continue?",
        ):
            return
        try:
            argv, cwd = restore_db_command(target.remote, selected.filename)
        except BackupCtlError as e:
            QMessageBox.warning(self, "Restore failed", str(e))
            return
        self.log_panel.run(argv, cwd)

    def _restore_wp(self) -> None:
        target = self.target_combo.current_target()
        selected = self.wp_table.selected_file()
        if target is None or selected is None:
            return
        if not confirm(
            self, "Confirm WordPress file restore",
            f"This will overwrite the LIVE production WordPress files on {target.label} "
            f"with the contents of:\n\n{selected.filename}\n"
            f"({selected.mtime.strftime('%Y-%m-%d %H:%M:%S UTC')})\n\n"
            "Any file changes since that backup was taken (including anything "
            "an attacker may have uploaded since) will be overwritten where the "
            "archive has a matching file, though nothing added since is deleted. "
            "This cannot be undone. Continue?",
        ):
            return
        try:
            argv, cwd = restore_wp_command(target.remote, selected.filename)
        except BackupCtlError as e:
            QMessageBox.warning(self, "Restore failed", str(e))
            return
        self.log_panel.run(argv, cwd)

    def _label(self, table: _BackupTable) -> None:
        remote = self.target_combo.current_remote()
        selected = table.selected_file()
        if selected is None:
            return
        text, ok = QInputDialog.getText(
            self, "Label backup", f"Label for {selected.filename}\n(leave blank to clear):",
            text=selected.label or "",
        )
        if not ok:
            return
        try:
            set_label(remote, selected.filename, text)
        except BackupCtlError as e:
            QMessageBox.warning(self, "Label failed", str(e))
            return
        self.refresh()

    def _delete(self, table: _BackupTable) -> None:
        remote = self.target_combo.current_remote()
        selected = table.selected_file()
        if selected is None:
            return
        if not confirm(
            self, "Confirm delete",
            f"This permanently deletes the backup file:\n\n{selected.filename}\n\n"
            "This does not affect the live production database/files -- only the "
            "backup copy itself. This cannot be undone. Continue?",
        ):
            return
        try:
            delete_backup(remote, selected.filename)
        except BackupCtlError as e:
            QMessageBox.warning(self, "Delete failed", str(e))
            return
        self.refresh()

    def _export(self, table: _BackupTable) -> None:
        remote = self.target_combo.current_remote()
        selected = table.selected_file()
        if selected is None:
            return
        dest, _ = QFileDialog.getSaveFileName(self, "Export backup to…", selected.filename)
        if not dest:
            return
        try:
            export_backup(remote, selected.filename, dest)
        except BackupCtlError as e:
            QMessageBox.warning(self, "Export failed", str(e))
            return
        QMessageBox.information(self, "Exported", f"Saved {selected.filename} to:\n{dest}")

    def _import(self, kind: str) -> None:
        remote = self.target_combo.current_remote()
        name_filter = "DB dumps (*.sql.gz)" if kind == "db" else "WP archives (*.tar.gz)"
        src, _ = QFileDialog.getOpenFileName(self, "Import backup…", "", name_filter)
        if not src:
            return
        try:
            imported_name = import_backup(remote, src)
        except BackupCtlError as e:
            QMessageBox.warning(self, "Import failed", str(e))
            return
        self.refresh()
        QMessageBox.information(self, "Imported", f"Imported as {imported_name}")

    def _reseed(self) -> None:
        target = self.target_combo.current_target()
        if target is None:
            return
        if not confirm(
            self, "Confirm demo store reset",
            f"This wipes and rebuilds the ENTIRE live production database on {target.label} "
            "(WordPress, WooCommerce, Elementor, every product/page/order) from a clean "
            "seed -- everything currently there, including anything an attacker has done, "
            "will be lost. This cannot be undone. Continue?",
        ):
            return
        try:
            argv, cwd = reseed_command(target.remote, force=True)
        except BackupCtlError as e:
            QMessageBox.warning(self, "Reset failed", str(e))
            return
        self.log_panel.run(argv, cwd)

    def _on_action_finished(self, _exit_code: int) -> None:
        # Picks up restore_db.sh's db_restore log entry / the reseed's
        # effect on the DB (and re-checks backup_service is still
        # reachable) without a separate manual Refresh click.
        self.refresh()
