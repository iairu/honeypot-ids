"""First-run setup wizard: creates and populates both projects' .env
files, optionally configures remote SSH control, and optionally generates
initial certificates. Re-runnable anytime from the menu; it loads existing
.env values rather than blanking them, so re-running it to fix one field
doesn't discard everything else.
"""
from __future__ import annotations

from PyQt6.QtGui import QPalette
from PyQt6.QtWidgets import (
    QHBoxLayout, QLabel, QMessageBox, QPushButton, QVBoxLayout, QWidget,
    QWizard, QWizardPage,
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

# Page IDs, module-level (not SetupWizard class attributes) so both the
# wizard itself and WizardTimeline's step list can reference them without
# an import-order/forward-reference problem.
PAGE_WELCOME, PAGE_REMOTE, PAGE_EDGE_ENV, PAGE_SIEM_ENV, PAGE_CERTS, PAGE_FINISH = range(6)

# Fixed step labels, in wizard order. Which of these a run actually visits
# depends on the remote/local choice (see visible_steps()) -- Edge/SIEM
# .env are skipped entirely for a project marked remote.
_STEP_LABELS = {
    PAGE_WELCOME: "Welcome",
    PAGE_REMOTE: "Remote/Local",
    PAGE_EDGE_ENV: "Edge .env",
    PAGE_SIEM_ENV: "SIEM .env",
    PAGE_CERTS: "Certificates",
    PAGE_FINISH: "Done",
}


def visible_steps(state: AppState) -> list[tuple[int, str]]:
    """The ordered list of (page_id, label) this wizard run will actually
    visit, given the current remote/local choice. Recomputed on every page
    show (not just once) since Back navigation can change remote/local
    mid-run -- see WizardTimeline.refresh()."""
    steps = [(PAGE_WELCOME, _STEP_LABELS[PAGE_WELCOME]), (PAGE_REMOTE, _STEP_LABELS[PAGE_REMOTE])]
    if not state.remote_edge.enabled:
        steps.append((PAGE_EDGE_ENV, _STEP_LABELS[PAGE_EDGE_ENV]))
    if not state.remote_siem.enabled:
        steps.append((PAGE_SIEM_ENV, _STEP_LABELS[PAGE_SIEM_ENV]))
    steps.append((PAGE_CERTS, _STEP_LABELS[PAGE_CERTS]))
    steps.append((PAGE_FINISH, _STEP_LABELS[PAGE_FINISH]))
    return steps


class WizardTimeline(QWidget):
    """Step-indicator row shown at the top of every wizard page: all steps
    that will actually be visited (see visible_steps()), with completed
    steps checked off, the current one highlighted, and remaining ones
    dimmed. Rebuilt via refresh() on every page show (TimelineMixin calls
    this from initializePage(), which Qt calls on every visit including
    Back navigation) since the skip-aware step list can change mid-run.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._row = QHBoxLayout(self)
        self._row.setContentsMargins(0, 0, 0, 10)

    def refresh(self, state: AppState, current_id: int) -> None:
        while self._row.count():
            item = self._row.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        steps = visible_steps(state)
        current_index = next((i for i, (pid, _label) in enumerate(steps) if pid == current_id), None)

        for i, (pid, label) in enumerate(steps):
            if current_index is not None and i < current_index:
                text, style = f"✓ {label}", "color: #5cb85c;"
            elif pid == current_id:
                text, style = f"● {label}", f"color: {self._current_step_text_color()}; font-weight: bold;"
            else:
                text, style = label, "color: #888888;"

            lbl = QLabel(text)
            lbl.setStyleSheet(style)
            self._row.addWidget(lbl)

            if i < len(steps) - 1:
                arrow = QLabel("→")
                arrow.setStyleSheet("color: #555555;")
                self._row.addWidget(arrow)

        self._row.addStretch()

    def _current_step_text_color(self) -> str:
        """Black on a light background, white on a dark one. Was hardcoded
        white -- unreadable (white-on-light) on a light system/Qt theme,
        confirmed live. Reads the widget's own actual effective palette
        rather than assuming either theme, so it's correct regardless of
        OS light/dark mode or a custom app stylesheet."""
        bg = self.palette().color(QPalette.ColorRole.Window)
        # Perceived-brightness formula (ITU-R BT.601), 0-255 scale.
        brightness = (bg.red() * 299 + bg.green() * 587 + bg.blue() * 114) / 1000
        return "#000000" if brightness > 128 else "#ffffff"


class TimelineMixin:
    """Mixed into every QWizardPage below. _init_timeline() inserts a
    WizardTimeline as the first item in the page's own layout; Qt calls
    initializePage() every time a page is shown (including via Back
    navigation), which is what keeps the highlighted step correct if the
    user goes back and changes the remote/local choice."""

    def _init_timeline(self, layout: QVBoxLayout) -> None:
        self._timeline = WizardTimeline()
        layout.addWidget(self._timeline)

    def initializePage(self) -> None:
        wiz = self.wizard()
        timeline = getattr(self, "_timeline", None)
        if wiz is not None and timeline is not None:
            timeline.refresh(wiz.state, wiz.currentId())
        super().initializePage()


class WelcomePage(TimelineMixin, QWizardPage):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTitle("Welcome")
        layout = QVBoxLayout(self)
        self._init_timeline(layout)
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


class RemotePage(TimelineMixin, QWizardPage):
    def __init__(self, state: AppState, parent=None):
        super().__init__(parent)
        self.state = state
        self.setTitle("Remote hosts (optional)")
        layout = QVBoxLayout(self)
        self._init_timeline(layout)
        info = QLabel(
            "If either project runs on a separate host (the real two-host "
            "deployment this project is designed for -- see ARCHITECTURE.md), "
            "configure SSH access here. Leave disabled to control only the "
            "local stack.\n\n"
            "A project marked remote here has its .env living on that "
            "remote host, not on this machine -- so the next step skips "
            "local .env editing for it entirely."
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

    def nextId(self) -> int:
        if self.state.remote_edge.enabled:
            if self.state.remote_siem.enabled:
                return PAGE_CERTS
            return PAGE_SIEM_ENV
        return PAGE_EDGE_ENV


class EdgeEnvPage(TimelineMixin, QWizardPage):
    def __init__(self, state: AppState, parent=None):
        super().__init__(parent)
        self.state = state
        self.setTitle("openstack-work (edge honeypot) — .env")
        layout = QVBoxLayout(self)
        self._init_timeline(layout)
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

    def nextId(self) -> int:
        if self.state.remote_siem.enabled:
            return PAGE_CERTS
        return PAGE_SIEM_ENV


class SiemEnvPage(TimelineMixin, QWizardPage):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTitle("openstack-siem-work (SIEM) — .env")
        layout = QVBoxLayout(self)
        self._init_timeline(layout)
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


class CertsPage(TimelineMixin, QWizardPage):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTitle("Certificates (optional)")
        layout = QVBoxLayout(self)
        self._init_timeline(layout)
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


class FinishPage(TimelineMixin, QWizardPage):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTitle("Done")
        layout = QVBoxLayout(self)
        self._init_timeline(layout)
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
        self.setMinimumSize(700, 620)

        # Remote/local choice comes first so the .env pages that follow
        # know which projects to skip.
        self.setPage(PAGE_WELCOME, WelcomePage())
        self.setPage(PAGE_REMOTE, RemotePage(state))
        self.setPage(PAGE_EDGE_ENV, EdgeEnvPage(state))
        self.setPage(PAGE_SIEM_ENV, SiemEnvPage())
        self.setPage(PAGE_CERTS, CertsPage())
        self.setPage(PAGE_FINISH, FinishPage())

    def accept(self) -> None:
        self.state.first_run_complete = True
        self.state.save()
        super().accept()
