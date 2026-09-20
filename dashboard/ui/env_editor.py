"""Reusable .env editing widget -- one row per key found in the file,
password-masked for anything that looks like a secret, with a per-field
show/hide toggle and a "generate random value" button for secrets.
Shared by the setup wizard (first-run) and the Settings page (anytime).
"""
from __future__ import annotations

import secrets

from PyQt6.QtWidgets import (
    QFormLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QScrollArea,
    QVBoxLayout, QWidget,
)

from core.env_file import EnvFile

SECRET_HINTS = ("PASSWORD", "SECRET", "_KEY")


def looks_like_secret(key: str) -> bool:
    return any(hint in key for hint in SECRET_HINTS)


def generate_secret(length: int = 32) -> str:
    return secrets.token_urlsafe(length)[:length]


class EnvFieldRow(QWidget):
    def __init__(self, key: str, value: str, parent=None):
        super().__init__(parent)
        self.key = key
        is_secret = looks_like_secret(key)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.edit = QLineEdit(value)
        if is_secret:
            self.edit.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.edit, stretch=1)

        if is_secret:
            self.toggle_btn = QPushButton("👁")
            self.toggle_btn.setFixedWidth(28)
            self.toggle_btn.setCheckable(True)
            self.toggle_btn.toggled.connect(self._toggle_visibility)
            layout.addWidget(self.toggle_btn)

            gen_btn = QPushButton("Generate")
            gen_btn.setFixedWidth(80)
            gen_btn.clicked.connect(self._generate)
            layout.addWidget(gen_btn)

    def _toggle_visibility(self, checked: bool) -> None:
        self.edit.setEchoMode(
            QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password
        )

    def _generate(self) -> None:
        self.edit.setText(generate_secret())

    def value(self) -> str:
        return self.edit.text()


class EnvEditorWidget(QWidget):
    def __init__(self, env_file: EnvFile, keys: list[str] | None = None, parent=None):
        """keys: explicit key order/subset to show; None shows every key
        found in the file, in file order."""
        super().__init__(parent)
        self.env_file = env_file
        self.rows: dict[str, EnvFieldRow] = {}

        outer = QVBoxLayout(self)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        outer.addWidget(scroll)

        inner = QWidget()
        form = QFormLayout(inner)
        scroll.setWidget(inner)

        shown_keys = keys if keys is not None else env_file.keys()
        added = set(env_file.added_keys)
        for key in shown_keys:
            row = EnvFieldRow(key, env_file.get(key))
            self.rows[key] = row
            label = QLabel(key)
            if key in added:
                # Pulled in from .env.example because the file lacks it --
                # not on disk until saved (see EnvFile.added_keys).
                label.setText(f"{key}  <span style='color:#e0a800;'>(new, from .env.example)</span>")
                label.setToolTip(
                    "This key exists in .env.example but not in this .env yet. "
                    "It is shown with the template's placeholder value and will "
                    "be written when you Save."
                )
            form.addRow(label, row)

        if not shown_keys:
            form.addRow(QLabel(f"No .env found yet at {env_file.path}"))

    def apply_to_env_file(self) -> None:
        for key, row in self.rows.items():
            self.env_file.set(key, row.value())

    def save(self) -> None:
        self.apply_to_env_file()
        self.env_file.save()
