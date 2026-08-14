"""Command construction (and simple synchronous helpers) for controlling
the two projects' docker-compose stacks, locally or over SSH on a remote
host.

Command *construction* is kept separate from *execution* on purpose: the
UI layer runs long commands (up/restart/purge) through QProcess for live,
non-blocking output streaming, but status polling (`ps`) is short-lived
enough to run synchronously from a background QThread. Both paths need
the same argv/cwd, hence this module returns argv+cwd rather than running
anything itself except the small `ps`/`logs` synchronous helpers.
"""
from __future__ import annotations

import json
import shlex
import subprocess
from dataclasses import dataclass

from core.paths import EDGE_DIR, SIEM_COMPOSE_DIR
from core.state import RemoteConfig

PROJECT_DIRS = {
    "edge": EDGE_DIR,
    "siem": SIEM_COMPOSE_DIR,
}

PROJECT_LABELS = {
    "edge": "ids",
    "siem": "siem",
}


@dataclass
class Target:
    project: str  # "edge" | "siem"
    remote: RemoteConfig | None = None  # None == local

    @property
    def is_remote(self) -> bool:
        return self.remote is not None

    @property
    def label(self) -> str:
        base = PROJECT_LABELS[self.project]
        return f"{base} (remote: {self.remote.host})" if self.is_remote else f"{base} (local)"

    @property
    def key(self) -> str:
        return f"{self.project}-{'remote' if self.is_remote else 'local'}"

    def _local_dir(self) -> str:
        return str(PROJECT_DIRS[self.project])

    def remote_compose_dir(self) -> str:
        """The directory docker-compose.yml actually lives in on the
        remote host, given self.remote.remote_path -- which is meant to be
        the PROJECT ROOT (matching what "project directory" means
        everywhere else in this app: EDGE_DIR/SIEM_DIR, the same thing the
        user points "Upload entire project to remote" at), not wherever
        docker-compose.yml itself happens to live.

        For "edge" those are the SAME directory (EDGE_DIR IS where
        docker-compose.yml lives, matching PROJECT_DIRS["edge"]). For
        "siem" they are NOT the same: docker-compose.yml lives in a
        "docker" subdirectory one level inside the project root
        (PROJECT_DIRS["siem"] == SIEM_COMPOSE_DIR == SIEM_DIR / "docker"
        locally) -- so remote_path needs that same "/docker" appended here
        to reach it, same as SIEM_COMPOSE_DIR does locally. The user never
        has to know this locally (PROJECT_DIRS already encodes it); this
        is what makes remote match that instead of requiring them to type
        the "docker" subdirectory into remote_path themselves.

        Only remote_path itself gets this treatment -- an EMPTY remote_path
        (falls back to _local_dir(), i.e. mirrors this exact machine's
        checkout) already has the right structure baked in, so appending
        "/docker" again there would double it.
        """
        if not self.remote.remote_path:
            return self._local_dir()
        remote_dir = self.remote.remote_path.rstrip("/")
        if self.project == "siem":
            remote_dir = f"{remote_dir}/docker"
        return remote_dir

    @staticmethod
    def _global_flags(compose_args: tuple[str, ...]) -> list[str]:
        """Flags inserted between `docker compose` and the subcommand.

        --profile '*' (always): activates every profile, e.g. the edge
        project's `vector_outbound` service, which is `profiles: [elk]` --
        confirmed live that without it, `docker compose down`/`up`/
        `restart` silently exclude profiled services from their scope
        entirely (docker compose ps does NOT have this filtering, which is
        why the dashboard's status display looked fine while Stop/Purge
        quietly left `vector_outbound` running). `ps`/`logs` don't need it for
        already-running containers but it's harmless there too, so it's
        applied unconditionally for every command rather than only the
        mutating ones.

        --ansi always (logs only): docker compose's default --ansi auto
        disables ANSI color whenever stdout isn't a TTY, which QProcess's
        pipes never are -- confirmed live that `logs` output was
        colorless through this app without it. Scoped to `logs`
        specifically (not applied to every command) so it can never affect
        machine-parsed output like `ps --format json`. See ui/ansi.py for
        the LogPanel-side rendering of the resulting escape codes.
        """
        flags = ["--profile", "*"]
        if compose_args and compose_args[0] == "logs":
            flags += ["--ansi", "always"]
        return flags

    def build(self, *compose_args: str) -> tuple[list[str], str | None]:
        """Returns (argv, cwd). cwd is None for remote (the ssh command
        does its own `cd`). See _global_flags() for what's inserted
        between `docker compose` and the subcommand."""
        global_flags = self._global_flags(compose_args)

        if not self.is_remote:
            return ["docker", "compose", *global_flags, *compose_args], self._local_dir()

        remote_dir = self.remote_compose_dir()
        remote_cmd = (
            f"cd {shlex.quote(remote_dir)} && docker compose "
            f"{' '.join(shlex.quote(a) for a in global_flags)} "
            f"{' '.join(shlex.quote(a) for a in compose_args)}"
        )
        return self._ssh_argv(remote_cmd), None

    def build_shell(self, command: str) -> tuple[list[str], str | None]:
        """Like build(), but for callers that need more than one `docker
        compose` invocation chained together in one shell line (e.g.
        piping one container's stdout into another's stdin -- see
        core/backup_ctl.py's WP-file restore, which streams an archive
        straight from backup_service into production_eshop rather than
        via any new mount). `command` is a raw POSIX shell one-liner the
        caller has already assembled (its own `docker compose --profile
        '*' ...` invocations, arguments already shlex.quote'd), run as-is
        rather than built up from compose_args."""
        if not self.is_remote:
            return ["sh", "-c", command], self._local_dir()

        remote_dir = self.remote_compose_dir()
        remote_cmd = f"cd {shlex.quote(remote_dir)} && {command}"
        return self._ssh_argv(remote_cmd), None

    def _ssh_argv(self, remote_cmd: str) -> list[str]:
        return [
            "ssh",
            "-i", self.remote.key_path,
            "-p", str(self.remote.port),
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=8",
            f"{self.remote.user}@{self.remote.host}",
            remote_cmd,
        ]

    # ---- one-shot synchronous helpers (call from a background thread) ----

    def ps(self, timeout: float = 15.0) -> list[dict]:
        """Live container status. Returns [] on any failure (host
        unreachable, docker not running, etc.) -- callers treat that the
        same as "nothing running", which is the honest state to show."""
        argv, cwd = self.build("ps", "-a", "--format", "json")
        try:
            result = subprocess.run(
                argv, cwd=cwd, capture_output=True, text=True, timeout=timeout,
            )
        except (subprocess.TimeoutExpired, OSError):
            return []
        if result.returncode != 0:
            return []
        containers = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                containers.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return containers

    def remote_compose_file_exists(self, timeout: float = 8.0) -> bool:
        """For remote targets only: does the resolved remote_compose_dir()
        actually contain a docker-compose.yml/compose.yaml/compose.yml?
        Purely informational (see RemoteConfigWidget._test_connection())
        -- a brand new remote host legitimately has no compose file yet
        until "Upload entire project to remote" puts one there, so this
        never blocks anything, it just tells you plainly whether it's
        there BEFORE that upload."""
        if not self.is_remote:
            return True
        remote_dir = self.remote_compose_dir()
        check_cmd = (
            f"[ -f {shlex.quote(remote_dir)}/docker-compose.yml ] || "
            f"[ -f {shlex.quote(remote_dir)}/compose.yaml ] || "
            f"[ -f {shlex.quote(remote_dir)}/compose.yml ]"
        )
        argv = [
            "ssh", "-i", self.remote.key_path, "-p", str(self.remote.port),
            "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes",
            "-o", f"ConnectTimeout={int(timeout)}",
            f"{self.remote.user}@{self.remote.host}", check_cmd,
        ]
        try:
            result = subprocess.run(argv, capture_output=True, timeout=timeout + 2)
        except (subprocess.TimeoutExpired, OSError):
            return False
        return result.returncode == 0

    def is_reachable(self, timeout: float = 8.0) -> bool:
        """For remote targets: can we even SSH in? Local is always
        reachable (if `docker` itself is missing that surfaces via ps()
        returning [], same as "nothing running")."""
        if not self.is_remote:
            return True
        argv = [
            "ssh", "-i", self.remote.key_path, "-p", str(self.remote.port),
            "-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes",
            "-o", f"ConnectTimeout={int(timeout)}",
            f"{self.remote.user}@{self.remote.host}", "true",
        ]
        try:
            result = subprocess.run(argv, capture_output=True, timeout=timeout + 2)
        except (subprocess.TimeoutExpired, OSError):
            return False
        return result.returncode == 0


def targets_for(project: str, remote_edge: RemoteConfig, remote_siem: RemoteConfig) -> list[Target]:
    """All targets to show for a project: always local, plus remote if
    configured."""
    result = [Target(project=project, remote=None)]
    remote = remote_edge if project == "edge" else remote_siem
    if remote.is_configured():
        result.append(Target(project=project, remote=remote))
    return result


def all_targets(remote_edge: RemoteConfig, remote_siem: RemoteConfig) -> list[Target]:
    return targets_for("edge", remote_edge, remote_siem) + targets_for("siem", remote_edge, remote_siem)
