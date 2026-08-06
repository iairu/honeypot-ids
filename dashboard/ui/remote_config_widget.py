"""Form for a single project's remote (SSH) connection settings, plus a
Test Connection button. Shared by the wizard and the Settings page."""
from __future__ import annotations

from PyQt6.QtWidgets import (
    QCheckBox, QFileDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit,
    QMessageBox, QPushButton, QSpinBox, QVBoxLayout, QWidget,
)

from core.docker_ctl import Target
from core.state import RemoteConfig


class RemoteConfigWidget(QWidget):
    def __init__(self, project: str, config: RemoteConfig, parent=None):
        super().__init__(parent)
        self.project = project

        layout = QVBoxLayout(self)

        self.enabled_check = QCheckBox("Enable remote control for this project")
        self.enabled_check.setChecked(config.enabled)
        layout.addWidget(self.enabled_check)

        form = QFormLayout()
        self.host_edit = QLineEdit(config.host)
        form.addRow("Host / IP:", self.host_edit)

        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(config.port or 22)
        form.addRow("SSH port:", self.port_spin)

        self.user_edit = QLineEdit(config.user)
        form.addRow("SSH user:", self.user_edit)

        key_row = QHBoxLayout()
        self.key_edit = QLineEdit(config.key_path)
        key_browse = QPushButton("Browse…")
        key_browse.clicked.connect(self._browse_key)
        key_row.addWidget(self.key_edit)
        key_row.addWidget(key_browse)
        form.addRow("SSH private key:", key_row)

        self.remote_path_edit = QLineEdit(config.remote_path)
        self.remote_path_edit.setPlaceholderText(
            "e.g. /home/user/DP_Repository/openstack-work "
            "(or .../openstack-siem-work/elk_dockerized/docker)"
        )
        form.addRow("Remote project path:", self.remote_path_edit)

        layout.addLayout(form)

        test_row = QHBoxLayout()
        self.test_btn = QPushButton("Test connection")
        self.test_btn.clicked.connect(self._test_connection)
        self.test_result = QLabel("")
        test_row.addWidget(self.test_btn)
        test_row.addWidget(self.test_result)
        test_row.addStretch()
        layout.addLayout(test_row)

    def _browse_key(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select SSH private key")
        if path:
            self.key_edit.setText(path)

    def to_config(self) -> RemoteConfig:
        return RemoteConfig(
            enabled=self.enabled_check.isChecked(),
            host=self.host_edit.text().strip(),
            port=self.port_spin.value(),
            user=self.user_edit.text().strip(),
            key_path=self.key_edit.text().strip(),
            remote_path=self.remote_path_edit.text().strip(),
        )

    def _test_connection(self) -> None:
        config = self.to_config()
        if not config.is_configured():
            self.test_result.setText("Fill in host, user, and key path first.")
            self.test_result.setStyleSheet("color: #f0ad4e;")
            return
        target = Target(project=self.project, remote=config)
        self.test_result.setText("Testing…")
        self.test_result.setStyleSheet("color: #888888;")
        self.repaint()
        ok = target.is_reachable()
        if ok:
            self.test_result.setText("✓ Reachable")
            self.test_result.setStyleSheet("color: #5cb85c;")
        else:
            self.test_result.setText("✗ Could not connect")
            self.test_result.setStyleSheet("color: #d9534f;")
