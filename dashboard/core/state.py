"""Dashboard app state persistence -- window geometry, remote-connection
settings, wizard-completion flag. Plain JSON file next to the app rather
than QSettings' platform-specific registry/plist/ini backends, so the
whole app's state is one inspectable, greppable file (state.json,
gitignored)."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, fields

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

    @property
    def address(self) -> str:
        """``user@host`` -- the ssh/scp/rsync destination spelling."""
        return f"{self.user}@{self.host}"

    @classmethod
    def from_dict(cls, data: dict) -> "RemoteConfig":
        """Tolerates unknown keys (a state.json/export bundle written by a
        newer or older dashboard) instead of crashing the whole load over
        one unrecognized field; missing keys take the field defaults."""
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})


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
    # Whether the Kibana page's embedded browser uses a persistent (named)
    # QWebEngineProfile -- cookies survive app restarts, so logging into
    # Kibana once doesn't mean doing it again on every dashboard launch --
    # vs. the off-the-record default every other embedded browser in this
    # app uses (see browser_widget.py). On by default: Kibana is the one
    # place in this app where staying logged in is the obviously-wanted
    # behavior, unlike the Exploits page's eshop browser, where an
    # ephemeral session is the whole point.
    kibana_remember_credentials: bool = True
    # "system" (follow the OS), "light", or "dark" -- see ui/theme.py.
    theme: str = "system"
    # Cross-session history of notable security events (honeypot
    # diversions, CVE/high-severity signals, missing required
    # dependencies), capped at security_feed.MAX_EVENTS -- see
    # ui/security_feed.py. Each entry: {timestamp, kind, label, detail,
    # color, score}.
    security_events: list = field(default_factory=list)

    @classmethod
    def load(cls) -> "AppState":
        """Reads STATE_FILE; any missing/unparseable file or field falls
        back to the dataclass defaults, so a state.json from an older
        version always loads."""
        if not STATE_FILE.exists():
            return cls()
        try:
            raw = json.loads(STATE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            return cls()
        if not isinstance(raw, dict):
            return cls()

        state = cls()
        for f in fields(cls):
            if f.name not in raw:
                continue
            value = raw[f.name]
            if f.default_factory is RemoteConfig:
                if isinstance(value, dict):
                    setattr(state, f.name, RemoteConfig.from_dict(value))
            else:
                setattr(state, f.name, value)
        return state

    def save(self) -> None:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(asdict(self), indent=2))
