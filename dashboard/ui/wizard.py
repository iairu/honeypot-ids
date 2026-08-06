"""First-run setup wizard: creates and populates both projects' .env
files, optionally configures remote SSH control, and optionally generates
initial certificates. Re-runnable anytime from the menu; it loads existing
.env values rather than blanking them, so re-running it to fix one field
doesn't discard everything else.
"""
from __future__ import annotations

from pathlib import Path

from PyQt6.QtGui import QPalette
from PyQt6.QtWidgets import (
    QHBoxLayout, QLabel, QMessageBox, QPushButton, QVBoxLayout, QWidget,
    QWizard, QWizardPage,
)

from core.cert_ctl import CertError, regenerate
from core.env_file import EnvFile, seed_from_example
from core.env_upload import EnvUploadError, download_env_text, upload_env_text
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

# Fixed step labels, in wizard order. Every run visits every page, in this
# order -- a project marked remote no longer skips its .env page; that
# page instead fetches and edits the .env directly on the remote host
# (see RemoteAwareEnvPage). WizardTimeline appends "(remote)" to the
# Edge/SIEM .env labels when that project is remote-enabled.
_STEP_LABELS = {
    PAGE_WELCOME: "Welcome",
    PAGE_REMOTE: "Remote/Local",
    PAGE_EDGE_ENV: "Edge .env",
    PAGE_SIEM_ENV: "SIEM .env",
    PAGE_CERTS: "Certificates",
    PAGE_FINISH: "Done",
}
_STEP_ORDER = (PAGE_WELCOME, PAGE_REMOTE, PAGE_EDGE_ENV, PAGE_SIEM_ENV, PAGE_CERTS, PAGE_FINISH)


def visible_steps() -> list[tuple[int, str]]:
    """The full, fixed step list -- every wizard run visits every page."""
    return [(pid, _STEP_LABELS[pid]) for pid in _STEP_ORDER]


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

        steps = visible_steps()
        current_index = next((i for i, (pid, _label) in enumerate(steps) if pid == current_id), None)

        for i, (pid, label) in enumerate(steps):
            if pid == PAGE_EDGE_ENV and state.remote_edge.enabled:
                label = f"{label} (remote)"
            elif pid == PAGE_SIEM_ENV and state.remote_siem.enabled:
                label = f"{label} (remote)"

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
            "A project marked remote here has its .env fetched live from "
            "that remote host on the next step (prefilling the same form "
            "you'd see for a local .env) instead of a local file -- Next "
            "there saves it straight back to the remote host, not here."
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


class RemoteAwareEnvPage(TimelineMixin, QWizardPage):
    """Base for EdgeEnvPage/SiemEnvPage. Shows and edits a project's .env
    in the same EnvEditorWidget either way, but the SOURCE depends on the
    live remote/local choice from RemotePage, re-checked every time this
    page is shown (initializePage(), same mechanism the timeline already
    uses -- so going Back and toggling remote then Next again picks it up
    correctly):
      - local (default): seeded from .env.example if the real file doesn't
        exist yet, same as before.
      - remote (that project marked remote AND configured): fetched live
        over SSH via download_env_text() and prefilled -- an empty/missing
        remote .env prefills an empty form rather than failing, matching
        how a missing local file behaves. A fetch failure (bad connection)
        falls back to showing the local file instead, with an explanation.

    validatePage() saves back to whichever source was actually shown --
    upload_env_text() for remote, EnvFile.save() for local.
    """

    def __init__(
        self, state: AppState, project: str, title: str,
        local_path: Path, local_example: Path,
        default_keys: list[str] | None, parent=None,
    ):
        super().__init__(parent)
        self.state = state
        self.project = project
        self.local_path = local_path
        self.local_example = local_example
        self.default_keys = default_keys
        self.setTitle(title)

        layout = QVBoxLayout(self)
        self._init_timeline(layout)

        self.info = QLabel("")
        self.info.setWordWrap(True)
        layout.addWidget(self.info)

        self._editor_slot = QVBoxLayout()
        layout.addLayout(self._editor_slot, stretch=1)

        self.env_file: EnvFile | None = None
        self.editor: EnvEditorWidget | None = None
        self._source_is_remote = False

    def _remote_config(self):
        return self.state.remote_edge if self.project == "edge" else self.state.remote_siem

    def initializePage(self) -> None:
        super().initializePage()  # TimelineMixin's refresh, then QWizardPage's
        self._load_source()

    def _clear_editor(self) -> None:
        while self._editor_slot.count():
            item = self._editor_slot.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def _load_source(self) -> None:
        self._clear_editor()
        remote = self._remote_config()

        if remote.enabled and remote.is_configured():
            self.info.setText(f"Fetching {remote.remote_path}/.env from {remote.user}@{remote.host}…")
            self.repaint()
            try:
                text = download_env_text(remote)
            except EnvUploadError as e:
                self._source_is_remote = False
                self.env_file = seed_from_example(self.local_path, self.local_example)
                self.info.setText(
                    f"Could not fetch the remote .env ({e}) -- showing the "
                    f"LOCAL file instead ({self.local_path}). Fix the "
                    "connection on the previous page and come back, or "
                    "Next will just save locally."
                )
            else:
                self._source_is_remote = True
                display_path = Path(f"{remote.user}@{remote.host}:{remote.remote_path}/.env")
                self.env_file = EnvFile.from_text(text, display_path)
                if text:
                    self.info.setText(
                        f"Writes to REMOTE {remote.user}@{remote.host}:"
                        f"{remote.remote_path}/.env (fetched live just now, "
                        "shown below). Password/secret fields have a "
                        "Generate button for a random value."
                    )
                else:
                    self.info.setText(
                        f"No .env found yet at {remote.user}@{remote.host}:"
                        f"{remote.remote_path}/.env -- starting from an "
                        "empty form; Next creates it there."
                    )
        else:
            self._source_is_remote = False
            self.env_file = seed_from_example(self.local_path, self.local_example)
            self.info.setText(
                f"Writes to {self.local_path}. Password/secret fields have "
                "a Generate button for a random value -- recommended over "
                "the placeholder defaults."
            )

        # The curated key subset (EDGE_ENV_DEFAULT_KEYS) only makes sense
        # for the known local template -- a remote-fetched file might be
        # structured differently, so show everything actually found there.
        keys = self.default_keys if not self._source_is_remote else None
        self.editor = EnvEditorWidget(self.env_file, keys=keys)
        self._editor_slot.addWidget(self.editor)

    def validatePage(self) -> bool:
        self.editor.apply_to_env_file()
        if self._source_is_remote:
            remote = self._remote_config()
            try:
                upload_env_text(self.env_file.render(), remote)
            except EnvUploadError as e:
                QMessageBox.warning(
                    self, "Save to remote failed",
                    f"Could not write to {remote.user}@{remote.host}:"
                    f"{remote.remote_path}/.env:\n\n{e}\n\n"
                    "Go back and fix the connection, or disable remote for "
                    "this project to save locally instead.",
                )
                return False
        else:
            self.env_file.save()
        return True


class EdgeEnvPage(RemoteAwareEnvPage):
    def __init__(self, state: AppState, parent=None):
        super().__init__(
            state, "edge", "openstack-work (edge honeypot) — .env",
            EDGE_ENV_FILE, EDGE_ENV_EXAMPLE, EDGE_ENV_DEFAULT_KEYS, parent,
        )


class SiemEnvPage(RemoteAwareEnvPage):
    def __init__(self, state: AppState, parent=None):
        super().__init__(
            state, "siem", "openstack-siem-work (SIEM) — .env",
            SIEM_ENV_FILE, SIEM_ENV_EXAMPLE, None, parent,
        )


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
        # know whether to fetch from the remote host instead of a local file.
        self.setPage(PAGE_WELCOME, WelcomePage())
        self.setPage(PAGE_REMOTE, RemotePage(state))
        self.setPage(PAGE_EDGE_ENV, EdgeEnvPage(state))
        self.setPage(PAGE_SIEM_ENV, SiemEnvPage(state))
        self.setPage(PAGE_CERTS, CertsPage())
        self.setPage(PAGE_FINISH, FinishPage())

    def accept(self) -> None:
        self.state.first_run_complete = True
        self.state.save()
        super().accept()
