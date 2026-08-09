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
    QComboBox, QFileDialog, QGroupBox, QHBoxLayout, QHeaderView, QInputDialog,
    QLabel, QMessageBox, QPlainTextEdit, QPushButton, QSplitter, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from core.backup_ctl import (
    BackupCtlError, BackupFile, delete_backup, export_backup, import_backup,
    list_backups, read_backup_log, reseed_command, restore_db_command,
    restore_wp_command, set_label,
)
from core.docker_ctl import Target, targets_for
from core.state import AppState, RemoteConfig
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
        self._targets: list[Target] = []

        layout = QVBoxLayout(self)

        toolbar = QHBoxLayout()
        toolbar.addWidget(QLabel("Target:"))
        self.target_combo = QComboBox()
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
        self.reseed_btn = QPushButton("Reset demo store…")
        self.reseed_btn.setStyleSheet("QPushButton { color: #d9534f; }")
        self.reseed_btn.clicked.connect(self._reseed)
        toolbar.addWidget(self.reseed_btn)
        layout.addLayout(toolbar)

        self.error_banner = QLabel("")
        self.error_banner.setWordWrap(True)
        self.error_banner.setStyleSheet(
            "background-color: #d9534f; color: white; padding: 6px; border-radius: 4px;"
        )
        self.error_banner.setVisible(False)
        layout.addWidget(self.error_banner)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(splitter, stretch=2)

        db_box = QGroupBox("Database dumps")
        db_layout = QVBoxLayout(db_box)
        self.db_table = _BackupTable()
        db_layout.addWidget(self.db_table)
        db_btn_row = QHBoxLayout()
        self.label_db_btn = QPushButton("Label…")
        self.label_db_btn.clicked.connect(lambda: self._label(self.db_table))
        db_btn_row.addWidget(self.label_db_btn)
        self.export_db_btn = QPushButton("Export…")
        self.export_db_btn.clicked.connect(lambda: self._export(self.db_table))
        db_btn_row.addWidget(self.export_db_btn)
        self.import_db_btn = QPushButton("Import…")
        self.import_db_btn.clicked.connect(lambda: self._import("db"))
        db_btn_row.addWidget(self.import_db_btn)
        self.delete_db_btn = QPushButton("Delete")
        self.delete_db_btn.setStyleSheet("QPushButton { color: #d9534f; }")
        self.delete_db_btn.clicked.connect(lambda: self._delete(self.db_table))
        db_btn_row.addWidget(self.delete_db_btn)
        db_layout.addLayout(db_btn_row)
        self.restore_db_btn = QPushButton("Restore selected dump…")
        self.restore_db_btn.setStyleSheet("QPushButton { color: #d9534f; }")
        self.restore_db_btn.clicked.connect(self._restore_db)
        db_layout.addWidget(self.restore_db_btn)
        splitter.addWidget(db_box)

        wp_box = QGroupBox("WordPress file archives")
        wp_layout = QVBoxLayout(wp_box)
        self.wp_table = _BackupTable()
        wp_layout.addWidget(self.wp_table)
        wp_btn_row = QHBoxLayout()
        self.label_wp_btn = QPushButton("Label…")
        self.label_wp_btn.clicked.connect(lambda: self._label(self.wp_table))
        wp_btn_row.addWidget(self.label_wp_btn)
        self.export_wp_btn = QPushButton("Export…")
        self.export_wp_btn.clicked.connect(lambda: self._export(self.wp_table))
        wp_btn_row.addWidget(self.export_wp_btn)
        self.import_wp_btn = QPushButton("Import…")
        self.import_wp_btn.clicked.connect(lambda: self._import("wp"))
        wp_btn_row.addWidget(self.import_wp_btn)
        self.delete_wp_btn = QPushButton("Delete")
        self.delete_wp_btn.setStyleSheet("QPushButton { color: #d9534f; }")
        self.delete_wp_btn.clicked.connect(lambda: self._delete(self.wp_table))
        wp_btn_row.addWidget(self.delete_wp_btn)
        wp_layout.addLayout(wp_btn_row)
        self.restore_wp_btn = QPushButton("Restore selected archive…")
        self.restore_wp_btn.setStyleSheet("QPushButton { color: #d9534f; }")
        self.restore_wp_btn.clicked.connect(self._restore_wp)
        wp_layout.addWidget(self.restore_wp_btn)
        splitter.addWidget(wp_box)

        activity_box = QGroupBox("Recent backup activity (backup.log)")
        activity_layout = QVBoxLayout(activity_box)
        self.activity_view = QPlainTextEdit(readOnly=True)
        self.activity_view.setMaximumBlockCount(500)
        self.activity_view.setStyleSheet("QPlainTextEdit { font-family: monospace; font-size: 11px; }")
        self.activity_view.setMaximumHeight(140)
        activity_layout.addWidget(self.activity_view)
        layout.addWidget(activity_box)

        log_label = QLabel("Restore / reset output:")
        layout.addWidget(log_label)
        self.log_panel = LogPanel(show_stop_button=False)
        self.log_panel.setMinimumHeight(140)
        self.log_panel.finished.connect(self._on_action_finished)
        layout.addWidget(self.log_panel, stretch=1)

        self.rebuild_targets()
        self.target_combo.currentIndexChanged.connect(self.refresh)
        self.refresh()

    def rebuild_targets(self) -> None:
        """Call when remote settings change (Settings page / setup wizard)
        -- rebuilds the target dropdown, mirroring RedisPage's own
        rebuild_targets()."""
        self.target_combo.blockSignals(True)
        self.target_combo.clear()
        self._targets = targets_for("edge", self.state.remote_edge, self.state.remote_siem)
        for t in self._targets:
            self.target_combo.addItem(t.label)
        self.target_combo.blockSignals(False)

    def _current_target(self) -> Target | None:
        idx = self.target_combo.currentIndex()
        if 0 <= idx < len(self._targets):
            return self._targets[idx]
        return None

    def _current_remote(self) -> RemoteConfig | None:
        target = self._current_target()
        return target.remote if target else None

    def refresh(self) -> None:
        remote = self._current_remote()
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
            color = "#d9534f" if entry.status == "failure" else "#5cb85c"
            line = f"{entry.timestamp}  {entry.status:8s} {entry.step:12s} {entry.detail}"
            line_html = html.escape(line).replace(" ", "&nbsp;")
            self.activity_view.appendHtml(f'<span style="color:{color};">{line_html}</span>')

        if error:
            self.error_banner.setText(f"⚠ backup_service unreachable: {error}")
            self.error_banner.setVisible(True)
        else:
            self.error_banner.setVisible(False)

    def _restore_db(self) -> None:
        target = self._current_target()
        selected = self.db_table.selected_file()
        if target is None or selected is None:
            return
        reply = QMessageBox.warning(
            self, "Confirm database restore",
            f"This will overwrite the LIVE production database on {target.label} "
            f"with the contents of:\n\n{selected.filename}\n"
            f"({selected.mtime.strftime('%Y-%m-%d %H:%M:%S UTC')})\n\n"
            "Any data written since that backup was taken (including anything "
            "an attacker may have added since) will be lost. This cannot be undone. "
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            argv, cwd = restore_db_command(target.remote, selected.filename)
        except BackupCtlError as e:
            QMessageBox.warning(self, "Restore failed", str(e))
            return
        self.log_panel.run(argv, cwd)

    def _restore_wp(self) -> None:
        target = self._current_target()
        selected = self.wp_table.selected_file()
        if target is None or selected is None:
            return
        reply = QMessageBox.warning(
            self, "Confirm WordPress file restore",
            f"This will overwrite the LIVE production WordPress files on {target.label} "
            f"with the contents of:\n\n{selected.filename}\n"
            f"({selected.mtime.strftime('%Y-%m-%d %H:%M:%S UTC')})\n\n"
            "Any file changes since that backup was taken (including anything "
            "an attacker may have uploaded since) will be overwritten where the "
            "archive has a matching file, though nothing added since is deleted. "
            "This cannot be undone. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            argv, cwd = restore_wp_command(target.remote, selected.filename)
        except BackupCtlError as e:
            QMessageBox.warning(self, "Restore failed", str(e))
            return
        self.log_panel.run(argv, cwd)

    def _label(self, table: _BackupTable) -> None:
        remote = self._current_remote()
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
        remote = self._current_remote()
        selected = table.selected_file()
        if selected is None:
            return
        reply = QMessageBox.warning(
            self, "Confirm delete",
            f"This permanently deletes the backup file:\n\n{selected.filename}\n\n"
            "This does not affect the live production database/files -- only the "
            "backup copy itself. This cannot be undone. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        try:
            delete_backup(remote, selected.filename)
        except BackupCtlError as e:
            QMessageBox.warning(self, "Delete failed", str(e))
            return
        self.refresh()

    def _export(self, table: _BackupTable) -> None:
        remote = self._current_remote()
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
        remote = self._current_remote()
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
        target = self._current_target()
        if target is None:
            return
        reply = QMessageBox.warning(
            self, "Confirm demo store reset",
            f"This wipes and rebuilds the ENTIRE live production database on {target.label} "
            "(WordPress, WooCommerce, Elementor, every product/page/order) from a clean "
            "seed -- everything currently there, including anything an attacker has done, "
            "will be lost. This cannot be undone. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if reply != QMessageBox.StandardButton.Yes:
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
