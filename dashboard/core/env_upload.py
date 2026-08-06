"""Uploads a project's local .env file to its configured remote host via
scp, using the same SSH options convention as docker_ctl.py's remote
command construction (system scp binary, not paramiko, so it picks up the
same ssh_config/known_hosts behavior as every other SSH action this app
takes)."""
from __future__ import annotations

import subprocess
from pathlib import Path

from core.state import RemoteConfig


class EnvUploadError(Exception):
    pass


def build_scp_argv(local_path: Path, remote: RemoteConfig, timeout: float = 8.0) -> list[str]:
    remote_target = f"{remote.user}@{remote.host}:{remote.remote_path.rstrip('/')}/.env"
    return [
        "scp",
        "-i", remote.key_path,
        # scp's port flag is capital -P (lowercase -p means "preserve
        # file attributes"), unlike ssh's lowercase -p -- easy to get
        # backwards, called out here deliberately.
        "-P", str(remote.port),
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={int(timeout)}",
        str(local_path),
        remote_target,
    ]


def upload_env(local_path: Path, remote: RemoteConfig, timeout: float = 15.0) -> None:
    """Raises EnvUploadError with a human-readable message on any failure
    (not configured, local file missing, scp itself failing/timing out)."""
    if not remote.is_configured():
        raise EnvUploadError("Remote connection is not fully configured.")
    if not local_path.exists():
        raise EnvUploadError(f"Local file not found: {local_path}")

    argv = build_scp_argv(local_path, remote, timeout=timeout)
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout + 5)
    except subprocess.TimeoutExpired:
        raise EnvUploadError("scp timed out.")
    except OSError as e:
        raise EnvUploadError(f"Could not run scp: {e}")

    if result.returncode != 0:
        raise EnvUploadError(result.stderr.strip() or f"scp exited with code {result.returncode}")
