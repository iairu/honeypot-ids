"""Dashboard app state persistence -- window geometry, remote-connection
settings, wizard-completion flag. Plain JSON file next to the app rather
than QSettings' platform-specific registry/plist/ini backends, so the
whole app's state is one inspectable, greppable file (state.json,
gitignored)."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field

from core.paths import STATE_FILE


@dataclass
class RemoteConfig:
    enabled: bool = False
    host: str = ""
    port: int = 22
    user: str = ""
    key_path: str = ""
    # Path to the project directory (containing docker-compose.yml, or for
    # siem the elk_dockerized/docker subdir) on the REMOTE host.
    remote_path: str = ""

    def is_configured(self) -> bool:
        return bool(self.enabled and self.host and self.user and self.key_path)


@dataclass
class AppState:
    first_run_complete: bool = False
    window_geometry_b64: str = ""
    last_page: str = "services"
    remote_edge: RemoteConfig = field(default_factory=RemoteConfig)
    remote_siem: RemoteConfig = field(default_factory=RemoteConfig)
    # How often (ms) StatusPoller re-runs `docker compose ps` for every
    # configured target. Adjustable from Settings -- lower for snappier
    # health-diagram updates, higher to reduce SSH round-trips against a
    # remote target on a slow/metered link.
    poll_interval_ms: int = 5000
    # Notify (system tray balloon) when a container transitions into
    # unhealthy/exited-with-error. Off by default so a first-run headless
    # environment without a tray isn't surprised by anything; the tray
    # icon itself only appears when the platform actually supports one.
    tray_notifications_enabled: bool = True

    @classmethod
    def load(cls) -> "AppState":
        if not STATE_FILE.exists():
            return cls()
        try:
            raw = json.loads(STATE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            return cls()
        state = cls()
        state.first_run_complete = raw.get("first_run_complete", False)
        state.window_geometry_b64 = raw.get("window_geometry_b64", "")
        state.last_page = raw.get("last_page", "services")
        if "remote_edge" in raw:
            state.remote_edge = RemoteConfig(**raw["remote_edge"])
        if "remote_siem" in raw:
            state.remote_siem = RemoteConfig(**raw["remote_siem"])
        state.poll_interval_ms = raw.get("poll_interval_ms", 5000)
        state.tray_notifications_enabled = raw.get("tray_notifications_enabled", True)
        return state

    def save(self) -> None:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "first_run_complete": self.first_run_complete,
            "window_geometry_b64": self.window_geometry_b64,
            "last_page": self.last_page,
            "remote_edge": asdict(self.remote_edge),
            "remote_siem": asdict(self.remote_siem),
            "poll_interval_ms": self.poll_interval_ms,
            "tray_notifications_enabled": self.tray_notifications_enabled,
        }
        STATE_FILE.write_text(json.dumps(data, indent=2))
