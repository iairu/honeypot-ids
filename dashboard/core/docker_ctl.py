"""Command construction (and simple synchronous helpers) for controlling
the two projects' docker-compose stacks, locally or over SSH on a remote
host.

Command *construction* is kept separate from *execution* on purpose: the
UI layer runs long commands (up/restart/purge) through QProcess for live,
non-blocking output streaming, but status polling (`ps`) is short-lived
enough to run synchronously from a background QThread. Both paths need
the same argv/cwd, hence this module returns argv+cwd rather than running
anything itself except the small `ps`/reachability synchronous helpers.
"""
from __future__ import annotations

import json
import shlex
import subprocess
from dataclasses import dataclass

from core import ssh
from core.proc import succeeds
from core.projects import PROJECT_IDS, Project, project as project_for
from core.state import AppState, RemoteConfig

# Kept for callers that only need the label of a project id; the full
# descriptor is core.projects.PROJECTS.
PROJECT_LABELS = {pid: project_for(pid).label for pid in PROJECT_IDS}


@dataclass
class Target:
    project: str  # "edge" | "siem"
    remote: RemoteConfig | None = None  # None == local

    @property
    def spec(self) -> Project:
        return project_for(self.project)

    @property
    def is_remote(self) -> bool:
        return self.remote is not None

    @property
    def label(self) -> str:
        base = self.spec.label
        return f"{base} (remote: {self.remote.host})" if self.is_remote else f"{base} (local)"

    @property
    def key(self) -> str:
        return f"{self.project}-{'remote' if self.is_remote else 'local'}"

    @property
    def host(self) -> str:
        """Where this target's published ports are reachable FROM THIS
        MACHINE -- the remote host's address, or loopback for local."""
        return self.remote.host if self.is_remote else "127.0.0.1"

    def _local_dir(self) -> str:
        return str(self.spec.compose_dir)

    def remote_compose_dir(self) -> str:
        """The directory docker-compose.yml lives in on the remote host.
        RemoteConfig.remote_path is the PROJECT ROOT (the same thing
        "Upload entire project to remote" syncs), so SIEM's "docker/"
        subdirectory gets appended here exactly as Project.compose_dir
        already does locally -- the user never types it. An EMPTY
        remote_path mirrors this machine's own checkout layout, which
        already has the subdirectory baked in."""
        if not self.remote.remote_path:
            return self._local_dir()
        return self.spec.remote_compose_dir(self.remote.remote_path)

    def remote_env_path(self) -> str:
        """`.env` sits right next to docker-compose.yml on the remote host."""
        return f"{self.remote_compose_dir()}/.env"

    @staticmethod
    def _global_flags(compose_args: tuple[str, ...]) -> list[str]:
        """Flags inserted between `docker compose` and the subcommand.

        --profile '*' (always): activates every profile, e.g. the edge
        project's `vector_outbound` service, which is `profiles: [elk]` --
        confirmed live that without it, `docker compose down`/`up`/
        `restart` silently exclude profiled services from their scope
        entirely (docker compose ps does NOT have this filtering, which is
        why the dashboard's status display looked fine while Stop/Purge
        quietly left `vector_outbound` running). Harmless for ps/logs, so
        applied unconditionally.

        --ansi always (logs only): docker compose's default --ansi auto
        disables ANSI color whenever stdout isn't a TTY, which QProcess's
        pipes never are. Scoped to `logs` so it can never affect
        machine-parsed output like `ps --format json`. See ui/ansi.py for
        the LogPanel-side rendering of the resulting escape codes.
        """
        flags = ["--profile", "*"]
        if compose_args and compose_args[0] == "logs":
            flags += ["--ansi", "always"]
        return flags

    @staticmethod
    def _augment_args(compose_args: tuple[str, ...]) -> tuple[str, ...]:
        """--remove-orphans, appended for `up`/`down` only (a subcommand
        option, so it goes after the subcommand, unlike _global_flags()).

        Confirmed live this is a real gap: renaming a service in
        docker-compose.yml leaves its OLD container running forever
        afterward -- compose only manages containers for services
        CURRENTLY defined in the file, so a plain `down`/`up` doesn't know
        the old one exists. That orphan then held a network and a named
        volume across a subsequent Purge (`down -v` logged "Resource is
        still in use" and silently left them behind). --remove-orphans
        makes both directions self-healing."""
        if compose_args and compose_args[0] in ("up", "down"):
            return (*compose_args, "--remove-orphans")
        return compose_args

    def build(self, *compose_args: str) -> tuple[list[str], str | None]:
        """Returns (argv, cwd). cwd is None for remote (the ssh command
        does its own `cd`)."""
        global_flags = self._global_flags(compose_args)
        compose_args = self._augment_args(compose_args)

        if not self.is_remote:
            return ["docker", "compose", *global_flags, *compose_args], self._local_dir()

        remote_cmd = "docker compose " + " ".join(shlex.quote(a) for a in (*global_flags, *compose_args))
        return self.build_shell(remote_cmd)

    def build_shell(self, command: str) -> tuple[list[str], str | None]:
        """Like build(), but for callers that need more than one `docker
        compose` invocation chained in one shell line (e.g. piping one
        container's stdout into another's stdin -- see core/backup_ctl.py's
        WP-file restore). `command` is a raw POSIX shell one-liner the
        caller has already assembled (arguments already shlex.quote'd),
        run in the compose directory as-is."""
        if not self.is_remote:
            return ["sh", "-c", command], self._local_dir()

        remote_cmd = f"cd {shlex.quote(self.remote_compose_dir())} && {command}"
        return ssh.ssh_argv(self.remote, remote_cmd), None

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
        """For remote targets only: does remote_compose_dir() actually
        contain a compose file? Purely informational (see
        RemoteConfigWidget._test_connection()) -- a brand new remote host
        legitimately has none until "Upload entire project" puts one
        there, so this never blocks anything."""
        if not self.is_remote:
            return True
        d = shlex.quote(self.remote_compose_dir())
        check_cmd = f"[ -f {d}/docker-compose.yml ] || [ -f {d}/compose.yaml ] || [ -f {d}/compose.yml ]"
        return self._ssh_succeeds(check_cmd, timeout)

    def is_reachable(self, timeout: float = 8.0) -> bool:
        """For remote targets: can we even SSH in? Local is always
        reachable (a missing `docker` surfaces via ps() returning [])."""
        if not self.is_remote:
            return True
        return self._ssh_succeeds("true", timeout)

    def _ssh_succeeds(self, remote_cmd: str, timeout: float) -> bool:
        return succeeds(ssh.ssh_argv(self.remote, remote_cmd, timeout=timeout), timeout=timeout + 2)


def remote_for(project: str, state: AppState) -> RemoteConfig | None:
    """The project's RemoteConfig if it's enabled AND fully filled in,
    else None -- i.e. exactly what Target(remote=...) wants."""
    remote = state.remote_edge if project == "edge" else state.remote_siem
    return remote if remote.is_configured() else None


def target_for(project: str, state: AppState) -> Target:
    """The ONE target a single-target feature should talk to for `project`:
    its remote host when one is configured, otherwise local. Used by pages
    that don't offer a local/remote choice (Exploits, Kibana, the
    security feed)."""
    return Target(project=project, remote=remote_for(project, state))


def targets_for(project: str, state: AppState) -> list[Target]:
    """All targets to show for a project: always local, plus remote if
    configured."""
    result = [Target(project=project, remote=None)]
    remote = remote_for(project, state)
    if remote is not None:
        result.append(Target(project=project, remote=remote))
    return result


def all_targets(state: AppState) -> list[Target]:
    return [t for pid in PROJECT_IDS for t in targets_for(pid, state)]
