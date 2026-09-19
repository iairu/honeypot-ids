"""The two compose projects this dashboard controls, as one descriptor each.

Everything project-specific that used to live in parallel
``{"edge": ..., "siem": ...}`` dicts scattered across core/ and ui/ (compose
directory, .env path, display label, where docker-compose.yml sits relative
to the project root on a remote host) is defined exactly once here, so
adding a field or a third project is a one-place change.

``edge`` is the honeypot stack in ``ids/``; ``siem`` is the ELK stack in
``siem/`` -- see ARCHITECTURE.md for why they're separate compose projects.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from core.paths import (
    EDGE_DIR, EDGE_ENV_EXAMPLE, EDGE_ENV_FILE, SIEM_COMPOSE_DIR, SIEM_DIR,
    SIEM_ENV_EXAMPLE, SIEM_ENV_FILE,
)


@dataclass(frozen=True)
class Project:
    id: str  # "edge" | "siem" -- the key used throughout the code/state
    label: str  # user-facing short name (matches the directory name)
    root_dir: Path  # project root -- what "Upload entire project" syncs
    compose_dir: Path  # where docker-compose.yml (and .env) actually live
    env_example: Path

    @property
    def env_file(self) -> Path:
        return self.compose_dir / ".env"

    @property
    def env_label(self) -> str:
        """Repo-relative .env path for UI text, e.g. "siem/docker/.env"."""
        return f"{self.compose_dir.relative_to(self.root_dir.parent)}/.env"

    @property
    def compose_subdir(self) -> str:
        """compose_dir relative to root_dir ("" when they're the same
        directory). On a remote host, RemoteConfig.remote_path is the
        PROJECT ROOT, so this is what gets appended to reach the compose
        file there -- same relationship as locally."""
        rel = self.compose_dir.relative_to(self.root_dir)
        return "" if rel == Path(".") else rel.as_posix()

    def remote_compose_dir(self, remote_path: str) -> str:
        remote_dir = remote_path.rstrip("/")
        return f"{remote_dir}/{self.compose_subdir}" if self.compose_subdir else remote_dir


EDGE = Project(
    id="edge", label="ids", root_dir=EDGE_DIR, compose_dir=EDGE_DIR, env_example=EDGE_ENV_EXAMPLE,
)
SIEM = Project(
    id="siem", label="siem", root_dir=SIEM_DIR, compose_dir=SIEM_COMPOSE_DIR, env_example=SIEM_ENV_EXAMPLE,
)

PROJECTS: dict[str, Project] = {EDGE.id: EDGE, SIEM.id: SIEM}
PROJECT_IDS = tuple(PROJECTS)

# Sanity: the descriptors above must agree with core.paths' own constants,
# which older code (and the README) still reference directly.
assert EDGE.env_file == EDGE_ENV_FILE and SIEM.env_file == SIEM_ENV_FILE


def project(project_id: str) -> Project:
    return PROJECTS[project_id]
