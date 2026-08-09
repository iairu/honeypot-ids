"""Repository path resolution.

The dashboard lives at <repo_root>/dashboard/ -- everything here is derived
from that, so the app works regardless of where the repo is checked out.
"""
from pathlib import Path

DASHBOARD_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = DASHBOARD_DIR.parent

EDGE_DIR = REPO_ROOT / "ids"
EDGE_COMPOSE_FILE = EDGE_DIR / "docker-compose.yml"
EDGE_ENV_FILE = EDGE_DIR / ".env"
EDGE_ENV_EXAMPLE = EDGE_DIR / ".env.example"

SIEM_DIR = REPO_ROOT / "siem"
SIEM_COMPOSE_DIR = SIEM_DIR / "docker"
SIEM_COMPOSE_FILE = SIEM_COMPOSE_DIR / "docker-compose.yml"
SIEM_ENV_FILE = SIEM_COMPOSE_DIR / ".env"
SIEM_ENV_EXAMPLE = SIEM_COMPOSE_DIR / ".env.example"
SIEM_CERT_SCRIPT = SIEM_DIR / "certs" / "root-ca" / "gen_elk_certs.sh"
SIEM_VECTOR_AGENT_CERT_DIR = SIEM_DIR / "vector" / "certs" / "vector-agent"

EDGE_VECTOR_CERT_DIR = EDGE_DIR / "vector" / "certs"
EDGE_SSL_CERT_DIR = EDGE_DIR / "ssl_certificates"

STATE_FILE = DASHBOARD_DIR / "state.json"
LOG_DIR = DASHBOARD_DIR / "logs"
