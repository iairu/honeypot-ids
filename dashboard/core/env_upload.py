"""Transfers a project's .env content to/from its configured remote host
over SSH, using the same options convention as docker_ctl.py's remote
command construction (system ssh/scp binaries, not paramiko, so this picks
up the same ssh_config/known_hosts behavior as every other SSH action this
app takes).

Two shapes, for two different UI flows:
  - upload_env(local_path, remote):    send an existing LOCAL FILE (scp) --
    used by the "Upload local .env to remote" button, which starts from a
    file already on disk.
  - download_env_text(remote) / upload_env_text(text, remote): fetch/send
    TEXT directly over an ssh pipe, no local file involved at any point --
    used by the wizard's remote-prefill env pages and the Settings page's
    Local/Remote toggle, where the content is fetched, edited in memory in
    the same EnvEditorWidget used for local files, and saved straight back
    to the remote host without ever touching local disk.
"""
from __future__ import annotations

import shlex
import subprocess
from pathlib import Path

from core.docker_ctl import Target
from core.state import RemoteConfig


class EnvUploadError(Exception):
    pass


def _base_ssh_argv(remote: RemoteConfig, timeout: float) -> list[str]:
    return [
        "ssh",
        "-i", remote.key_path,
        "-p", str(remote.port),
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={int(timeout)}",
        f"{remote.user}@{remote.host}",
    ]


def _remote_env_path(project: str, remote: RemoteConfig) -> str:
    """.env lives right alongside docker-compose.yml -- reuses
    Target.remote_compose_dir() (docker_ctl.py) rather than duplicating
    its "siem's compose dir is remote_path + /docker, edge's is just
    remote_path" logic a second time here. That asymmetry was previously
    hardcoded as an unconditional "/docker" in this exact function,
    silently breaking edge's remote .env upload/fetch -- confirmed live."""
    remote_dir = Target(project=project, remote=remote).remote_compose_dir()
    return f"{remote_dir}/.env"


def build_scp_argv(local_path: Path, project: str, remote: RemoteConfig, timeout: float = 8.0) -> list[str]:
    remote_target = f"{remote.user}@{remote.host}:{_remote_env_path(project, remote)}"
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


def upload_env(local_path: Path, project: str, remote: RemoteConfig, timeout: float = 15.0) -> None:
    """Sends an existing LOCAL FILE to the remote host via scp. Raises
    EnvUploadError with a human-readable message on any failure (not
    configured, local file missing, scp itself failing/timing out)."""
    if not remote.is_configured():
        raise EnvUploadError("Remote connection is not fully configured.")
    if not local_path.exists():
        raise EnvUploadError(f"Local file not found: {local_path}")

    argv = build_scp_argv(local_path, project, remote, timeout=timeout)
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout + 5)
    except subprocess.TimeoutExpired:
        raise EnvUploadError("scp timed out.")
    except OSError as e:
        raise EnvUploadError(f"Could not run scp: {e}")

    if result.returncode != 0:
        raise EnvUploadError(result.stderr.strip() or f"scp exited with code {result.returncode}")


def download_env_text(project: str, remote: RemoteConfig, timeout: float = 15.0) -> str:
    """Fetches the remote .env's content via `ssh ... cat <remote_path>/.env`
    directly to stdout -- no local temp file. Returns the empty string if
    the remote file doesn't exist yet (a fresh remote host with no .env
    deployed), which the caller can treat the same as EnvFile.load()'s
    handling of a missing local file (an empty EnvFile ready to be filled
    in and saved back). Raises EnvUploadError only for actual connection
    failures, not a missing file."""
    if not remote.is_configured():
        raise EnvUploadError("Remote connection is not fully configured.")

    remote_file = _remote_env_path(project, remote)
    # `|| true` (and discarding cat's stderr) means the ssh command itself
    # always exits 0 for "connected fine, file just isn't there yet" --
    # only a real connection failure (bad host/key/auth) should raise.
    argv = _base_ssh_argv(remote, timeout) + [f"cat {shlex.quote(remote_file)} 2>/dev/null || true"]
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout + 5)
    except subprocess.TimeoutExpired:
        raise EnvUploadError("ssh timed out while fetching the remote .env.")
    except OSError as e:
        raise EnvUploadError(f"Could not run ssh: {e}")

    if result.returncode != 0:
        raise EnvUploadError(result.stderr.strip() or f"ssh exited with code {result.returncode}")

    return result.stdout


def upload_env_text(text: str, project: str, remote: RemoteConfig, timeout: float = 15.0) -> None:
    """Writes `text` directly to <remote_path>/.env over SSH stdin -- no
    local file involved. Used when the content being saved was itself
    fetched from remote and edited in memory (wizard remote-prefill,
    Settings page's Remote toggle), as opposed to upload_env() which sends
    an existing local FILE."""
    if not remote.is_configured():
        raise EnvUploadError("Remote connection is not fully configured.")

    remote_file = _remote_env_path(project, remote)
    argv = _base_ssh_argv(remote, timeout) + [f"cat > {shlex.quote(remote_file)}"]
    try:
        result = subprocess.run(argv, input=text, capture_output=True, text=True, timeout=timeout + 5)
    except subprocess.TimeoutExpired:
        raise EnvUploadError("ssh timed out while writing the remote .env.")
    except OSError as e:
        raise EnvUploadError(f"Could not run ssh: {e}")

    if result.returncode != 0:
        raise EnvUploadError(result.stderr.strip() or f"ssh exited with code {result.returncode}")
