"""Syncs an entire project directory (not just .env) to its configured
remote host via rsync over SSH, so a fresh remote host actually has
everything needed to run `docker compose up` there -- core/env_upload.py's
upload_env() only sends the .env for a quick config-only push.

rsync (not scp -r) is deliberate: delta-transfer (a first sync moves
everything, a re-sync only moves what changed), native machine-readable
progress reporting (--info=progress2), and --exclude support so runtime/
log/backup data isn't blindly copied alongside actual project code -- see
EXCLUDE_PATTERNS, sized against this repo's real directory footprint
(confirmed live: openstack-work/backups/ alone is 1.2GB, suricata_logs/
378MB -- neither belongs in a "deploy the project" sync).
"""
from __future__ import annotations

import re
import shlex
import subprocess
from pathlib import Path

from core.state import RemoteConfig


class ProjectUploadError(Exception):
    pass


# Runtime-generated data (backups, logs, DB/Redis volumes), a pure
# reference snapshot kept only for local diffing, and local dev/VCS cruft
# -- none of it is "the project," all of it can be large, and none of it
# is needed for a remote host to actually run the stack. .env is handled
# separately by core/env_upload.py's own dedicated action, not swept up
# here, so the two features stay independently controllable.
EXCLUDE_PATTERNS = [
    ".git/", "__pycache__/", "*.pyc", "venv/", "node_modules/",
    "backups/",
    "suricata_logs/", "nginx_logs/",
    "production_database_sql_dumps/",
    "production_eshop_files_fresh_for_diff/",
    "redis_data/",
    "honeypot_database_data/", "honeypot_database_data_2/", "honeypot_database_data_3/",
    "production_database_data/", "production_mysql_data/",
    "vector/data/", "vector/logs/",
    ".env",
]


def _base_ssh_command(remote: RemoteConfig, timeout: float) -> str:
    return (
        f"ssh -i {shlex.quote(remote.key_path)} -p {remote.port} "
        "-o StrictHostKeyChecking=accept-new -o BatchMode=yes "
        f"-o ConnectTimeout={int(timeout)}"
    )


def build_rsync_argv(local_dir: Path, remote: RemoteConfig, timeout: float = 10.0) -> list[str]:
    argv = ["rsync", "-az", "--info=progress2", "-e", _base_ssh_command(remote, timeout)]
    for pattern in EXCLUDE_PATTERNS:
        argv += ["--exclude", pattern]
    # Trailing slash on the source: copies the DIRECTORY'S CONTENTS into
    # remote_path, not the directory itself nested one level deeper --
    # remote_path is already meant to BE the project root on the remote
    # host (matches how docker_ctl.py's Target.build() treats it: `cd
    # remote_path && docker compose ...`).
    local_src = str(local_dir).rstrip("/") + "/"
    remote_dst = f"{remote.user}@{remote.host}:{remote.remote_path.rstrip('/')}/"
    argv += [local_src, remote_dst]
    return argv


def remote_dir_has_content(remote: RemoteConfig, timeout: float = 8.0) -> bool:
    """True if remote_path already exists and is non-empty -- used to ask
    "overwrite?" before syncing into it, rather than silently merging into
    whatever's already there."""
    if not remote.is_configured():
        raise ProjectUploadError("Remote connection is not fully configured.")

    remote_dir = remote.remote_path.rstrip("/")
    check_cmd = (
        f"[ -d {shlex.quote(remote_dir)} ] && "
        f"[ -n \"$(ls -A {shlex.quote(remote_dir)} 2>/dev/null)\" ] && echo YES || echo NO"
    )
    argv = [
        "ssh", "-i", remote.key_path, "-p", str(remote.port),
        "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={int(timeout)}",
        f"{remote.user}@{remote.host}", check_cmd,
    ]
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout + 5)
    except subprocess.TimeoutExpired:
        raise ProjectUploadError("ssh timed out while checking the remote directory.")
    except OSError as e:
        raise ProjectUploadError(f"Could not run ssh: {e}")

    if result.returncode != 0:
        raise ProjectUploadError(result.stderr.strip() or f"ssh exited with code {result.returncode}")

    return result.stdout.strip() == "YES"


_PROGRESS_RE = re.compile(r"(\d{1,3})%")


def parse_progress_percent(rsync_output_chunk: str) -> int | None:
    """Pulls the most recent percentage out of a chunk of rsync
    --info=progress2 output (e.g. "  1,234,567  43%   12.3MB/s..."). Pure
    function so it's testable without actually running rsync -- returns
    None if the chunk has no percentage in it (most lines, between
    periodic progress updates)."""
    matches = _PROGRESS_RE.findall(rsync_output_chunk)
    if not matches:
        return None
    return min(int(matches[-1]), 100)
