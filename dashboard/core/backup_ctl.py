"""Backup listing + restore for the "backup_service" container (ids
/ edge project) -- backs ui/page_backups.py.

backup_service (see ids/backups/backup.sh) writes nightly DB
dumps + WordPress file archives under /backups (a host bind mount at
ids/backups/), plus one JSON line per step to
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
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from core.docker_ctl import Target
from core.proc import run_checked
from core.state import RemoteConfig

BACKUP_SERVICE = "backup_service"
WP_RESTORE_TARGET_SERVICE = "production_eshop"
CONTENT_SYNC_SERVICE = "honeypot_content_sync"

# Appended (via `&&`) after any command that changes production_database's
# *content* (a DB restore, a reseed) so the honeypot pools don't sit on
# stale/no content for up to REPLICATION_INTERVAL_SECONDS (default 300s)
# waiting for honeypot_content_sync's own periodic timer -- `docker compose
# restart` makes its script re-exec from the top (see
# scripts/replicate_content_to_honeypot.sh), which runs one sync_cycle
# immediately rather than waiting out whatever's left of the current
# interval. Status is visible two ways after this runs: this command's own
# echoed messages (streamed live into whichever LogPanel ran it), and the
# Health page's "Content sync activity" panel (ui/page_health.py), which
# parses honeypot_content_sync's own per-pool starting/complete/failed log
# lines out of the same restart's live log tail.
_RESYNC_SUFFIX = (
    " && echo '[dashboard] Production content changed -- restarting "
    f"{CONTENT_SYNC_SERVICE} to replicate it into the honeypot pools now "
    "(see the Health page for per-pool progress) instead of waiting up to "
    "REPLICATION_INTERVAL_SECONDS for the next scheduled cycle...' "
    f"&& docker compose --profile '*' restart {CONTENT_SYNC_SERVICE} "
    "&& echo '[dashboard] Replication triggered.'"
)

# A flat {filename: {"label": ..., "updated": ...}} JSON manifest living at
# /backups/labels.json (i.e. ids/backups/labels.json on the
# local host bind mount) -- read/written by BOTH this module and
# ids/backups/manage_backups.sh via the exact same `docker
# compose exec` path, so a label set from one is immediately visible from
# the other; there is no separate/divergent state to keep in sync.
_LABELS_PATH = "/backups/labels.json"

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
    label: str | None = None


@dataclass(frozen=True)
class BackupLogEntry:
    timestamp: str
    status: str  # "success" | "failure"
    step: str  # "db_dump" | "wp_archive" | "pruning" | "run_complete" | "db_restore"
    detail: str


def _run(target: Target, *compose_args: str, timeout: float = 15.0) -> str:
    argv, cwd = target.build(*compose_args)
    return run_checked(argv, error=BackupCtlError, cwd=cwd, timeout=timeout).stdout


def _run_binary(
    target: Target, *compose_args: str, input_bytes: bytes | None = None, timeout: float = 60.0,
) -> bytes:
    """Like _run(), but for reading/writing raw file bytes (export/import,
    a large mysqldump or tar archive) rather than short text output --
    binary mode throughout, no text decoding that could corrupt a gzip/tar
    stream, and an optional input_bytes piped to stdin (import's `cat >
    file` on the remote end)."""
    argv, cwd = target.build(*compose_args)
    return run_checked(
        argv, error=BackupCtlError, cwd=cwd, timeout=timeout, input=input_bytes, text=False,
    ).stdout


def _backup_subdir(filename: str) -> str:
    """"db" or "wp", purely from filename shape -- raises BackupCtlError
    for anything that doesn't match either (same validation
    restore_db_command()/restore_wp_command() already apply)."""
    if _DB_FILENAME_RE.match(filename):
        return "db"
    if _WP_FILENAME_RE.match(filename):
        return "wp"
    raise BackupCtlError(
        f"Not a valid backup filename: {filename!r} "
        "(expected *_production_database.sql.gz or *_production_eshop.tar.gz)"
    )


def _read_labels(target: Target, timeout: float = 15.0) -> dict:
    """{} if labels.json doesn't exist yet (no labels set) or fails to
    parse -- both non-fatal, same "freshly-started stack" reasoning as
    read_backup_log()."""
    try:
        out = _run(
            target, "exec", "-T", BACKUP_SERVICE, "sh", "-c",
            f"cat {_LABELS_PATH} 2>/dev/null || echo '{{}}'", timeout=timeout,
        )
    except BackupCtlError:
        return {}
    try:
        data = json.loads(out) if out.strip() else {}
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _write_labels(target: Target, labels: dict, timeout: float = 15.0) -> None:
    _run_binary(
        target, "exec", "-T", BACKUP_SERVICE, "sh", "-c", f"cat > {_LABELS_PATH}",
        input_bytes=json.dumps(labels, indent=2, sort_keys=True).encode(), timeout=timeout,
    )


def list_backups(
    remote: RemoteConfig | None, timeout: float = 15.0,
) -> tuple[list[BackupFile], list[BackupFile]]:
    """(db_dumps, wp_archives), newest first."""
    target = Target(project="edge", remote=remote)
    # busybox `stat -c` (alpine's own, not GNU coreutils) supports the
    # %n/%s/%Y directives used here -- confirmed against alpine:latest's
    # base image, the same one backup_service itself runs.
    #
    # Trailing `; true` matters: when a glob matches nothing, the shell
    # leaves it unexpanded (literal "*.tar.gz"), so `[ -e "$f" ]` is
    # false and -- since `&&` short-circuits, skipping `stat` -- that
    # failed test becomes the exit status of the whole `for` iteration.
    # With zero files of one kind (e.g. every WP archive deleted via the
    # dashboard/manage_backups.sh), that failed test is also the LAST
    # command the script runs, so `sh -c` itself would exit 1 -- which
    # _run() treats as a real failure ("backup_service unreachable")
    # despite the command having succeeded perfectly (there just aren't
    # any files of that kind, which is a normal state, not an error).
    # `; true` pins the script's own exit status to 0 whenever it ran at
    # all, regardless of how many files either loop actually found.
    script = (
        "for f in /backups/db/*.sql.gz; do [ -e \"$f\" ] && stat -c 'DB|%n|%s|%Y' \"$f\"; done; "
        "for f in /backups/wp/*.tar.gz; do [ -e \"$f\" ] && stat -c 'WP|%n|%s|%Y' \"$f\"; done; "
        "true"
    )
    out = _run(target, "exec", "-T", BACKUP_SERVICE, "sh", "-c", script, timeout=timeout)
    labels = _read_labels(target, timeout=timeout)

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
        filename = path.rsplit("/", 1)[-1]
        label_entry = labels.get(filename)
        label = label_entry.get("label") if isinstance(label_entry, dict) else None
        entry = BackupFile(filename=filename, size_bytes=size, mtime=mtime, label=label)
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
    restore_db.sh, then restarts honeypot_content_sync so the honeypot
    pools pick up the restored content promptly (see _RESYNC_SUFFIX).
    Run this through LogPanel.run(), never subprocess.run() directly --
    it's slow and mutating, and should stream its own progress rather
    than block the UI thread."""
    if not _DB_FILENAME_RE.match(filename):
        raise BackupCtlError(f"Not a valid DB dump filename: {filename!r}")
    target = Target(project="edge", remote=remote)
    command = (
        f"docker compose --profile '*' exec -T {BACKUP_SERVICE} /restore_db.sh {shlex.quote(filename)}"
        + _RESYNC_SUFFIX
    )
    return target.build_shell(command)


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


def set_label(remote: RemoteConfig | None, filename: str, label: str, timeout: float = 15.0) -> None:
    """Sets (or clears, if label is empty) the human-readable label shown
    next to `filename` in list_backups() -- also visible to/settable from
    ids/backups/manage_backups.sh, same manifest either way."""
    target = Target(project="edge", remote=remote)
    _backup_subdir(filename)  # validates filename shape; raises if not a real backup name
    labels = _read_labels(target, timeout=timeout)
    if label.strip():
        labels[filename] = {
            "label": label.strip(),
            "updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    else:
        labels.pop(filename, None)
    _write_labels(target, labels, timeout=timeout)


def delete_backup(remote: RemoteConfig | None, filename: str, timeout: float = 15.0) -> None:
    """Permanently deletes `filename` from backup_service's /backups and
    drops its label entry, if any. No confirmation here -- callers (the
    dashboard's page_backups.py, manage_backups.sh) are expected to have
    already confirmed with the user; this module's job is just to do
    exactly what's asked."""
    target = Target(project="edge", remote=remote)
    subdir = _backup_subdir(filename)
    _run(target, "exec", "-T", BACKUP_SERVICE, "rm", "-f", f"/backups/{subdir}/{filename}", timeout=timeout)
    labels = _read_labels(target, timeout=timeout)
    if filename in labels:
        del labels[filename]
        _write_labels(target, labels, timeout=timeout)


def export_backup(
    remote: RemoteConfig | None, filename: str, dest_path: str, timeout: float = 120.0,
) -> None:
    """Copies `filename` out of backup_service to a local file at
    dest_path -- a WP file archive can be well over 100MB, hence the
    longer default timeout than this module's other operations."""
    target = Target(project="edge", remote=remote)
    subdir = _backup_subdir(filename)
    data = _run_binary(target, "exec", "-T", BACKUP_SERVICE, "cat", f"/backups/{subdir}/{filename}", timeout=timeout)
    try:
        Path(dest_path).write_bytes(data)
    except OSError as e:
        raise BackupCtlError(f"Could not write {dest_path}: {e}")


def import_backup(remote: RemoteConfig | None, src_path: str, timeout: float = 120.0) -> str:
    """Copies a local file at src_path into backup_service's /backups/db
    or /backups/wp (chosen from its own filename, same as export_backup's
    counterpart) -- e.g. re-importing an exported backup on another
    machine, or a backup a teammate sent you. Returns the filename it was
    imported as (== Path(src_path).name) so a caller can immediately
    refresh/select it. Overwrites an existing file of the same name."""
    filename = Path(src_path).name
    subdir = _backup_subdir(filename)
    try:
        data = Path(src_path).read_bytes()
    except OSError as e:
        raise BackupCtlError(f"Could not read {src_path}: {e}")
    target = Target(project="edge", remote=remote)
    _run_binary(
        target, "exec", "-T", BACKUP_SERVICE, "sh", "-c", f"cat > /backups/{subdir}/{filename}",
        input_bytes=data, timeout=timeout,
    )
    return filename


def reseed_command(
    remote: RemoteConfig | None, force: bool = True,
) -> tuple[list[str], str | None]:
    """(argv, cwd) that (re)runs production_db_seed -- see
    scripts/seed_production_db.sh -- then restarts honeypot_content_sync
    so the honeypot pools promptly mirror whatever the seed just built
    (see _RESYNC_SUFFIX) rather than only catching up on the pools'
    normal fresh-boot dependency ordering (docker-compose.yml's
    production_db_seed -> honeypot_content_sync depends_on chain, which
    only ever applies to a service's FIRST start, not a later `up` of an
    already-running one -- this is what covers that case). force=True
    passes FORCE_RESEED=1 so an already-installed WordPress gets wiped
    and rebuilt from scratch (used by the dashboard's "Reset demo store"
    action, e.g. to restore a clean storefront after running exploits
    against it); force=False just replays the normal idempotent
    no-op-if-already-installed behavior every `docker compose up`
    already gets for free, useful only to watch it happen / confirm it's
    a no-op. Meant for LogPanel.run(), same reasoning as the
    restore_*_command() functions above."""
    target = Target(project="edge", remote=remote)
    env_prefix = "FORCE_RESEED=1 " if force else ""
    command = f"{env_prefix}docker compose --profile '*' up production_db_seed" + _RESYNC_SUFFIX
    return target.build_shell(command)
