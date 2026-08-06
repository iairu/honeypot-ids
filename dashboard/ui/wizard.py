"""First-run setup wizard: creates and populates both projects' .env
files, optionally configures remote SSH control, and optionally generates
initial certificates. Re-runnable anytime from the menu; it loads existing
.env values rather than blanking them, so re-running it to fix one field
doesn't discard everything else.
"""
from __future__ import annotations

from PyQt6.QtWidgets import (
    QLabel, QMessageBox, QPushButton, QVBoxLayout, QWizard, QWizardPage,
)

from core.cert_ctl import CertError, regenerate
from core.env_file import seed_from_example
from core.paths import (
    EDGE_ENV_EXAMPLE, EDGE_ENV_FILE, SIEM_ENV_EXAMPLE, SIEM_ENV_FILE,
)
from core.state import AppState
from ui.env_editor import EnvEditorWidget
from ui.remote_config_widget import RemoteConfigWidget

EDGE_ENV_DEFAULT_KEYS = [
    "MYSQL_ROOT_PASSWORD", "MYSQL_PASSWORD", "REDIS_PASSWORD",
    "SESSION_MANAGER_SECRET", "INTERNAL_TEST_SECRET",
    "ELK_ENABLED", "VECTOR_HOST", "VECTOR_PORT",
    "ABUSEIPDB_API_KEY", "ABUSEIPDB_CONFIDENCE_MINIMUM", "ABUSEIPDB_DAILY_CHECK_LIMIT",
    "COMPOSE_PROJECT_NAME", "ENVIRONMENT",
]


class WelcomePage(QWizardPage):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTitle("Welcome")
        layout = QVBoxLayout(self)
        label = QLabel(
            "This wizard creates/populates the .env files both compose "
            "projects need (openstack-work and openstack-siem-work), and "
            "optionally sets up remote SSH control and initial certificates.\n\n"
            "Re-running this wizard later loads your existing .env values "
            "instead of blanking them -- it's also reachable anytime from "
            "the menu."
        )
        label.setWordWrap(True)
        layout.addWidget(label)


class EdgeEnvPage(QWizardPage):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTitle("openstack-work (edge honeypot) — .env")
        layout = QVBoxLayout(self)
        info = QLabel(
            f"Writes to {EDGE_ENV_FILE}. Password/secret fields have a "
            "Generate button for a random value -- recommended over the "
            "placeholder defaults."
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        self.env_file = seed_from_example(EDGE_ENV_FILE, EDGE_ENV_EXAMPLE)
        self.editor = EnvEditorWidget(self.env_file, keys=EDGE_ENV_DEFAULT_KEYS)
        layout.addWidget(self.editor, stretch=1)

    def validatePage(self) -> bool:
        self.editor.save()
        return True


class SiemEnvPage(QWizardPage):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTitle("openstack-siem-work (SIEM) — .env")
        layout = QVBoxLayout(self)
        info = QLabel(
            f"Writes to {SIEM_ENV_FILE}. Password/secret fields have a "
            "Generate button for a random value -- recommended over the "
            "placeholder defaults."
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        self.env_file = seed_from_example(SIEM_ENV_FILE, SIEM_ENV_EXAMPLE)
        self.editor = EnvEditorWidget(self.env_file)
        layout.addWidget(self.editor, stretch=1)

    def validatePage(self) -> bool:
        self.editor.save()
        return True


class RemotePage(QWizardPage):
    def __init__(self, state: AppState, parent=None):
        super().__init__(parent)
        self.state = state
        self.setTitle("Remote hosts (optional)")
        layout = QVBoxLayout(self)
        info = QLabel(
            "If either project runs on a separate host (the real two-host "
            "deployment this project is designed for -- see ARCHITECTURE.md), "
            "configure SSH access here. Leave disabled to control only the "
            "local stacks."
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        self.edge_widget = RemoteConfigWidget("edge", state.remote_edge)
        layout.addWidget(QLabel("<b>openstack-work</b>"))
        layout.addWidget(self.edge_widget)

        self.siem_widget = RemoteConfigWidget("siem", state.remote_siem)
        layout.addWidget(QLabel("<b>openstack-siem-work</b>"))
        layout.addWidget(self.siem_widget)

    def validatePage(self) -> bool:
        self.state.remote_edge = self.edge_widget.to_config()
        self.state.remote_siem = self.siem_widget.to_config()
        self.state.save()
        return True


class CertsPage(QWizardPage):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTitle("Certificates (optional)")
        layout = QVBoxLayout(self)
        info = QLabel(
            "Generate the SIEM CA + service certs, and the edge nginx "
            "SSL cert, now. You can also do this later from the "
            "Certificates page (which offers per-service regeneration "
            "too)."
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        btn = QPushButton("Generate all certificates now")
        btn.clicked.connect(self._generate_all)
        layout.addWidget(btn)

    def _generate_all(self) -> None:
        lines = []
        try:
            for group_id in ["siem-all", "edge-nginx"]:
                regenerate(group_id, log=lambda msg: lines.append(msg))
            self.status_label.setText("\n".join(lines) + "\n\nDone.")
        except CertError as e:
            self.status_label.setText(f"Failed: {e}")
            QMessageBox.warning(self, "Certificate generation failed", str(e))


class FinishPage(QWizardPage):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTitle("Done")
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(
            "Setup complete. Use the Services page to start the stacks, "
            "Health to watch container status, and Settings to change any "
            "of this later."
        ))


class SetupWizard(QWizard):
    def __init__(self, state: AppState, parent=None):
        super().__init__(parent)
        self.state = state
        self.setWindowTitle("Honeypot Dashboard — Setup")
        self.setMinimumSize(700, 560)

        self.addPage(WelcomePage())
        self.addPage(EdgeEnvPage())
        self.addPage(SiemEnvPage())
        self.addPage(RemotePage(state))
        self.addPage(CertsPage())
        self.addPage(FinishPage())

    def accept(self) -> None:
        self.state.first_run_complete = True
        self.state.save()
        super().accept()
