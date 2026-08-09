"""Backup listing + restore for the "backup_service" container (openstack-work
/ edge project) -- backs ui/page_backups.py.

backup_service (see openstack-work/backups/backup.sh) writes nightly DB
dumps + WordPress file archives under /backups (a host bind mount at
openstack-work/backups/), plus one JSON line per step to
/backups/backup.log. All of that is read back the same way every other
docker-facing feature in this app reaches a service -- `docker compose
exec`, via Target.build() (see core/redis_inspect.py for the identical
pattern applied to session_store) -- rather than assuming a local
host-filesystem path, so it works the same for a remote edge target too.

Restoring is split by which container can actually reach the target:
  - DB restore runs INSIDE backup_service (it already has mysql-client
    installed and is the only container both holding the dump AND
    sitting on production_network next to production_database) via a
    small companion script, backups/restore_db.sh, mirroring backup.sh's
    own --defaults-extra-file password handling so the password is never
    on a command line/argv/ps output.
  - WP file restore can't run inside backup_service the same way:
    backup_service's ./production_eshop_files mount is read-only (it's
    the backup SOURCE, at /source_wp), and that's deliberately the only
    write access this least-privileged container has (cap_drop: ALL,
    no-new-privileges -- see docker-compose.yml). So the WP archive is
    instead streamed straight from backup_service to production_eshop
    (which already owns a read-write mount of the same files at
    /var/www/html) with one shell pipeline: `docker compose exec
    backup_service cat ... | docker compose exec production_eshop tar
    -x ...` -- no new mounts, no capabilities added to either container.
"""
from __future__ import annotations

import json
import re
import shlex
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone

from core.docker_ctl import Target
from core.state import RemoteConfig

BACKUP_SERVICE = "backup_service"
WP_RESTORE_TARGET_SERVICE = "production_eshop"

# Matches backup.sh's own filename shape exactly. Enforced here (before a
# filename ever reaches a command line) AND again inside restore_db.sh
# itself -- belt and suspenders, since this module's whole point is to
# turn a UI selection into a shell command.
_DB_FILENAME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}_production_database\.sql\.gz$")
_WP_FILENAME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}_production_eshop\.tar\.gz$")


class BackupCtlError(Exception):
    pass


@dataclass(frozen=True)
class BackupFile:
    filename: str
    size_bytes: int
    mtime: datetime  # UTC


@dataclass(frozen=True)
class BackupLogEntry:
    timestamp: str
    status: str  # "success" | "failure"
    step: str  # "db_dump" | "wp_archive" | "pruning" | "run_complete" | "db_restore"
    detail: str


def _run(target: Target, *compose_args: str, timeout: float = 15.0) -> str:
    argv, cwd = target.build(*compose_args)
    try:
        result = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise BackupCtlError("Command timed out.")
    except OSError as e:
        raise BackupCtlError(f"Could not run command: {e}")
    if result.returncode != 0:
        raise BackupCtlError(result.stderr.strip() or f"Command exited with code {result.returncode}")
    return result.stdout


def list_backups(
    remote: RemoteConfig | None, timeout: float = 15.0,
) -> tuple[list[BackupFile], list[BackupFile]]:
    """(db_dumps, wp_archives), newest first."""
    target = Target(project="edge", remote=remote)
    # busybox `stat -c` (alpine's own, not GNU coreutils) supports the
    # %n/%s/%Y directives used here -- confirmed against alpine:latest's
    # base image, the same one backup_service itself runs.
    script = (
        "for f in /backups/db/*.sql.gz; do [ -e \"$f\" ] && stat -c 'DB|%n|%s|%Y' \"$f\"; done; "
        "for f in /backups/wp/*.tar.gz; do [ -e \"$f\" ] && stat -c 'WP|%n|%s|%Y' \"$f\"; done"
    )
    out = _run(target, "exec", "-T", BACKUP_SERVICE, "sh", "-c", script, timeout=timeout)

    db_files: list[BackupFile] = []
    wp_files: list[BackupFile] = []
    for line in out.splitlines():
        parts = line.split("|")
        if len(parts) != 4:
            continue
        kind, path, size_str, mtime_str = parts
        try:
            size = int(size_str)
            mtime = datetime.fromtimestamp(int(mtime_str), tz=timezone.utc)
        except ValueError:
            continue
        entry = BackupFile(filename=path.rsplit("/", 1)[-1], size_bytes=size, mtime=mtime)
        (db_files if kind == "DB" else wp_files).append(entry)

    db_files.sort(key=lambda f: f.mtime, reverse=True)
    wp_files.sort(key=lambda f: f.mtime, reverse=True)
    return db_files, wp_files


def read_backup_log(
    remote: RemoteConfig | None, tail: int = 50, timeout: float = 15.0,
) -> list[BackupLogEntry]:
    """Most recent `tail` lines of backup.log, oldest first (same order
    the file itself is written in) -- includes backup.sh's own
    db_dump/wp_archive/pruning/run_complete entries AND restore_db.sh's
    db_restore entries, since both append to the same file. Empty list
    (not an error) if the log doesn't exist yet -- a freshly-started
    stack legitimately has no backups yet."""
    target = Target(project="edge", remote=remote)
    try:
        out = _run(
            target, "exec", "-T", BACKUP_SERVICE, "tail", "-n", str(tail), "/backups/backup.log",
            timeout=timeout,
        )
    except BackupCtlError:
        return []

    entries = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        entries.append(BackupLogEntry(
            timestamp=data.get("timestamp", ""),
            status=data.get("status", ""),
            step=data.get("step", ""),
            detail=data.get("detail", ""),
        ))
    return entries


def restore_db_command(remote: RemoteConfig | None, filename: str) -> tuple[list[str], str | None]:
    """(argv, cwd) that restores `filename` (must be a name as returned
    by list_backups()) into the live production database via
    restore_db.sh. Run this through LogPanel.run(), never subprocess.run()
    directly -- it's slow and mutating, and should stream its own
    progress rather than block the UI thread."""
    if not _DB_FILENAME_RE.match(filename):
        raise BackupCtlError(f"Not a valid DB dump filename: {filename!r}")
    target = Target(project="edge", remote=remote)
    return target.build("exec", "-T", BACKUP_SERVICE, "/restore_db.sh", filename)


def restore_wp_command(remote: RemoteConfig | None, filename: str) -> tuple[list[str], str | None]:
    """(argv, cwd) that restores `filename` (must be a name as returned
    by list_backups()) into the live production_eshop webroot -- see the
    module docstring for why this pipes through production_eshop instead
    of running inside backup_service. Also meant for LogPanel.run(), same
    reasoning as restore_db_command()."""
    if not _WP_FILENAME_RE.match(filename):
        raise BackupCtlError(f"Not a valid WP archive filename: {filename!r}")
    target = Target(project="edge", remote=remote)
    quoted_path = shlex.quote(f"/backups/wp/{filename}")
    command = (
        f"docker compose --profile '*' exec -T {BACKUP_SERVICE} cat {quoted_path} | "
        f"docker compose --profile '*' exec -T {WP_RESTORE_TARGET_SERVICE} "
        "tar --extract --gzip --file=- --directory=/var/www/html"
    )
    return target.build_shell(command)
