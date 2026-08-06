"""Form for a single project's remote (SSH) connection settings, plus a
Test Connection button. Shared by the wizard and the Settings page."""
from __future__ import annotations

from PyQt6.QtWidgets import (
    QCheckBox, QFileDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit,
    QMessageBox, QPushButton, QSpinBox, QVBoxLayout, QWidget,
)

from core.docker_ctl import Target
from core.env_upload import EnvUploadError, upload_env
from core.paths import EDGE_ENV_FILE, SIEM_ENV_FILE
from core.state import RemoteConfig

_LOCAL_ENV_FILES = {"edge": EDGE_ENV_FILE, "siem": SIEM_ENV_FILE}
_PROJECT_ENV_LABELS = {"edge": "openstack-work/.env", "siem": "openstack-siem-work/.env"}


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

        # Only enabled after a successful Test connection -- clearly names
        # which project's .env it would send (openstack-work vs.
        # openstack-siem-work), since a remote target's own .env otherwise
        # has to be placed there by hand.
        upload_row = QHBoxLayout()
        self.upload_btn = QPushButton(f"Upload {_PROJECT_ENV_LABELS[project]} to remote…")
        self.upload_btn.setEnabled(False)
        self.upload_btn.clicked.connect(self._upload_env)
        self.upload_result = QLabel("")
        upload_row.addWidget(self.upload_btn)
        upload_row.addWidget(self.upload_result)
        upload_row.addStretch()
        layout.addLayout(upload_row)

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
            self.upload_btn.setEnabled(False)
            return
        target = Target(project=self.project, remote=config)
        self.test_result.setText("Testing…")
        self.test_result.setStyleSheet("color: #888888;")
        self.upload_btn.setEnabled(False)
        self.repaint()
        ok = target.is_reachable()
        if ok:
            self.test_result.setText("✓ Reachable")
            self.test_result.setStyleSheet("color: #5cb85c;")
            self.upload_result.setText("")
            self.upload_btn.setEnabled(True)
        else:
            self.test_result.setText("✗ Could not connect")
            self.test_result.setStyleSheet("color: #d9534f;")

    def _upload_env(self) -> None:
        config = self.to_config()
        local_path = _LOCAL_ENV_FILES[self.project]
        env_label = _PROJECT_ENV_LABELS[self.project]

        reply = QMessageBox.warning(
            self, "Confirm upload",
            f"This will overwrite {config.remote_path}/.env on "
            f"{config.user}@{config.host} with the LOCAL {env_label} file "
            "(sent as-is, including secrets, over the SSH connection just "
            "tested).\n\nContinue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        self.upload_result.setText("Uploading…")
        self.upload_result.setStyleSheet("color: #888888;")
        self.repaint()

        try:
            upload_env(local_path, config)
        except EnvUploadError as e:
            self.upload_result.setText("✗ Upload failed")
            self.upload_result.setStyleSheet("color: #d9534f;")
            QMessageBox.warning(self, "Upload failed", str(e))
            return

        self.upload_result.setText("✓ Uploaded")
        self.upload_result.setStyleSheet("color: #5cb85c;")
        QMessageBox.information(
            self, "Uploaded",
            f"{env_label} uploaded to {config.host}:{config.remote_path}/.env",
        )
