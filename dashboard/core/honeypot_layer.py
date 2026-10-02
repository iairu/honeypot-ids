"""Which honeypot layer the edge (ids/) stack runs: the default WordPress proxy
level, or the alternative database proxy level.

Both layers are the same compose project in ids/. They differ only in which
compose file is used (see ids/db_proxy/README.md):

* ``reverse_proxy`` -- ids/docker-compose.yml. Suspicious sessions are routed to
  separate honeypot WordPress containers (pools).
* ``database`` -- ids/docker-compose.db-proxy.yml. One eshop serves everything
  and wp-content/db.php switches between the production and honeypot database
  per request. Isolates database-layer attacks only.

The choice is persisted in AppState.honeypot_layer and mirrored here as the
process-wide active layer. core.docker_ctl.Target reads it to pick the
compose file, so every `docker compose` call the dashboard makes follows it
without every call site having to pass it along.
"""
from __future__ import annotations

from dataclasses import dataclass

from core.paths import EDGE_DIR


@dataclass(frozen=True)
class HoneypotLayer:
    id: str
    label: str  # dropdown text
    short_label: str  # for target labels and report headers
    compose_file: str  # relative to ids/

    @property
    def compose_path(self):
        return EDGE_DIR / self.compose_file


REVERSE_PROXY = HoneypotLayer(
    id="reverse_proxy",
    label="WordPress proxy level (Default, Recommended)",
    short_label="WordPress proxy level",
    compose_file="docker-compose.yml",
)
DATABASE = HoneypotLayer(
    id="database",
    label="Database proxy level",
    short_label="database proxy level",
    compose_file="docker-compose.db-proxy.yml",
)

LAYERS: dict[str, HoneypotLayer] = {REVERSE_PROXY.id: REVERSE_PROXY, DATABASE.id: DATABASE}
DEFAULT_LAYER = REVERSE_PROXY.id

_active = DEFAULT_LAYER


def layer(layer_id: str) -> HoneypotLayer:
    """The layer for an id; unknown ids (an old or hand-edited state.json)
    fall back to the default."""
    return LAYERS.get(layer_id, REVERSE_PROXY)


def active() -> HoneypotLayer:
    return layer(_active)


def set_active(layer_id: str) -> HoneypotLayer:
    global _active
    _active = layer(layer_id).id
    return active()


def is_database() -> bool:
    return _active == DATABASE.id
