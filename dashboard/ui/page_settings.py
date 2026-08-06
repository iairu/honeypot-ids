"""Settings page: edit either project's real .env file, and configure
remote (SSH) control for either project. This is the "adjust existing
.env" surface -- the wizard covers first-run creation; this covers
anytime changes."""
from __future__ import annotations

from PyQt6.QtWidgets import QMessageBox, QPushButton, QTabWidget, QVBoxLayout, QWidget

from core.env_file import EnvFile
from core.paths import EDGE_ENV_FILE, SIEM_ENV_FILE
from core.state import AppState
from ui.env_editor import EnvEditorWidget
from ui.remote_config_widget import RemoteConfigWidget


class SettingsPage(QWidget):
    def __init__(self, state: AppState, on_state_changed, parent=None):
        super().__init__(parent)
        self.state = state
        self._on_state_changed = on_state_changed

        layout = QVBoxLayout(self)
        tabs = QTabWidget()
        layout.addWidget(tabs)

        self.edge_env_file = EnvFile.load(EDGE_ENV_FILE)
        self.edge_env_editor = EnvEditorWidget(self.edge_env_file)
        edge_env_tab = self._wrap_with_save(self.edge_env_editor, self._save_edge_env)
        tabs.addTab(edge_env_tab, "openstack-work .env")

        self.siem_env_file = EnvFile.load(SIEM_ENV_FILE)
        self.siem_env_editor = EnvEditorWidget(self.siem_env_file)
        siem_env_tab = self._wrap_with_save(self.siem_env_editor, self._save_siem_env)
        tabs.addTab(siem_env_tab, "openstack-siem-work .env")

        self.edge_remote_widget = RemoteConfigWidget("edge", state.remote_edge)
        edge_remote_tab = self._wrap_with_save(self.edge_remote_widget, self._save_edge_remote)
        tabs.addTab(edge_remote_tab, "openstack-work remote (SSH)")

        self.siem_remote_widget = RemoteConfigWidget("siem", state.remote_siem)
        siem_remote_tab = self._wrap_with_save(self.siem_remote_widget, self._save_siem_remote)
        tabs.addTab(siem_remote_tab, "openstack-siem-work remote (SSH)")

    def _wrap_with_save(self, widget: QWidget, save_fn) -> QWidget:
        container = QWidget()
        v = QVBoxLayout(container)
        v.addWidget(widget, stretch=1)
        save_btn = QPushButton("Save")
        save_btn.clicked.connect(save_fn)
        v.addWidget(save_btn)
        return container

    def _save_edge_env(self) -> None:
        self.edge_env_editor.save()
        QMessageBox.information(self, "Saved", f"Saved {EDGE_ENV_FILE}")

    def _save_siem_env(self) -> None:
        self.siem_env_editor.save()
        QMessageBox.information(self, "Saved", f"Saved {SIEM_ENV_FILE}")

    def _save_edge_remote(self) -> None:
        self.state.remote_edge = self.edge_remote_widget.to_config()
        self.state.save()
        self._on_state_changed()
        QMessageBox.information(self, "Saved", "Remote settings saved for openstack-work.")

    def _save_siem_remote(self) -> None:
        self.state.remote_siem = self.siem_remote_widget.to_config()
        self.state.save()
        self._on_state_changed()
        QMessageBox.information(self, "Saved", "Remote settings saved for openstack-siem-work.")
