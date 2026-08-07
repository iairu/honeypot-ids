"""Checks whether the external command-line tools this app shells out to
(docker, the docker compose plugin, ssh, rsync) are actually present and
runnable -- surfaced as a setup-wizard warning and a persistent dashboard
banner (ui/dependency_banner.py) rather than letting every feature fail
one-by-one with a raw "command not found" the first time it's used.

docker/docker compose are REQUIRED (nothing in this app works without
them). ssh/rsync are only needed for remote-target features (SSH control,
whole-project upload) -- still worth flagging, but distinctly, since a
purely-local user genuinely doesn't need them.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass

# (package manager id, install command) -- checked against /etc/os-release's
# ID/ID_LIKE fields, in order, first match wins. Package names are the
# common/default ones for each distro's repos; Docker's own apt/dnf repos
# (docs.docker.com) give newer versions than some distros' stock packages,
# but the stock package is the simpler one-liner to recommend first.
_INSTALL_COMMANDS = [
    (("arch", "manjaro"), "sudo pacman -S --needed docker docker-compose openssh rsync"),
    (("ubuntu", "debian", "linuxmint", "pop"), "sudo apt install docker.io docker-compose-v2 openssh-client rsync"),
    (("fedora", "rhel", "centos", "rocky", "almalinux"), "sudo dnf install docker docker-compose-plugin openssh-clients rsync"),
    (("opensuse", "opensuse-leap", "opensuse-tumbleweed", "suse"), "sudo zypper install docker docker-compose openssh rsync"),
]
_FALLBACK_INSTALL_COMMAND = (
    "See https://docs.docker.com/engine/install/ for Docker, and install "
    "openssh/rsync via your distro's package manager."
)


def _detect_install_command() -> str:
    try:
        text = open("/etc/os-release").read()
    except OSError:
        return _FALLBACK_INSTALL_COMMAND

    ids = set()
    for line in text.splitlines():
        if line.startswith("ID=") or line.startswith("ID_LIKE="):
            value = line.split("=", 1)[1].strip().strip('"')
            ids.update(value.split())

    for distro_ids, command in _INSTALL_COMMANDS:
        if ids & set(distro_ids):
            return command
    return _FALLBACK_INSTALL_COMMAND


@dataclass(frozen=True)
class DependencyStatus:
    name: str
    required: bool  # False = only needed for remote-target features
    ok: bool
    detail: str  # version string (ok) or what went wrong (not ok)


def _run_version(argv: list[str], timeout: float = 5.0) -> tuple[bool, str]:
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return False, "not found"
    except (subprocess.TimeoutExpired, OSError) as e:
        return False, f"failed to run: {e}"
    if result.returncode != 0:
        return False, (result.stderr or result.stdout or "exited with an error").strip().splitlines()[0]
    return True, (result.stdout or result.stderr or "").strip().splitlines()[0]


def check_dependencies() -> list[DependencyStatus]:
    statuses = []

    if shutil.which("docker") is None:
        statuses.append(DependencyStatus("docker", True, False, "not found"))
    else:
        ok, detail = _run_version(["docker", "--version"])
        statuses.append(DependencyStatus("docker", True, ok, detail))

    if shutil.which("docker") is None:
        statuses.append(DependencyStatus("docker compose", True, False, "not found (needs docker itself first)"))
    else:
        ok, detail = _run_version(["docker", "compose", "version"])
        statuses.append(DependencyStatus("docker compose", True, ok, detail))

    if shutil.which("ssh") is None:
        statuses.append(DependencyStatus("ssh", False, False, "not found -- needed for remote-target features"))
    else:
        ok, detail = _run_version(["ssh", "-V"])
        # OpenSSH prints its version to stderr with no real "success" exit
        # semantics for -V alone in some builds -- shutil.which() finding it
        # is good enough evidence it's actually usable.
        statuses.append(DependencyStatus("ssh", False, True, detail or "found"))

    if shutil.which("rsync") is None:
        statuses.append(DependencyStatus("rsync", False, False, "not found -- needed for whole-project upload"))
    else:
        ok, detail = _run_version(["rsync", "--version"])
        statuses.append(DependencyStatus("rsync", False, ok, detail))

    return statuses


def install_command() -> str:
    return _detect_install_command()


def all_required_ok(statuses: list[DependencyStatus]) -> bool:
    return all(s.ok for s in statuses if s.required)
