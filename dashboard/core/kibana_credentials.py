"""Reads the SIEM stack's ELASTIC_USERNAME/ELASTIC_PASSWORD -- the same
credentials the elk_dockerized .env already documents as "also used for
dashboard login" -- for page_kibana.py's autologin.

Local or remote, matching however state.remote_siem is configured: a local
SIEM reads SIEM_ENV_FILE directly (core/env_file.py), a remote one fetches
the .env over SSH (core/env_upload.py), same as the Settings page's
Local/Remote .env toggle already does for editing it.
"""
from __future__ import annotations

from core.docker_ctl import remote_for
from core.env_upload import EnvUploadError, load_project_env
from core.state import AppState


def get_elastic_credentials(state: AppState) -> tuple[str, str] | None:
    """Returns (username, password), or None if either is missing/blank or
    the remote .env couldn't be fetched -- callers should treat None as
    "skip autologin, let the user log in manually" rather than an error."""
    try:
        env = load_project_env("siem", remote_for("siem", state))
    except EnvUploadError:
        return None

    username = env.get("ELASTIC_USERNAME")
    password = env.get("ELASTIC_PASSWORD")
    if not username or not password:
        return None
    return username, password
