"""Launches an interactive shell inside a container, in the user's own
terminal emulator (not embedded in the app -- a real PTY in a real
terminal is simpler and more capable than reimplementing one in Qt).

Tries bash first, falls back to sh, in one command (`exec bash || exec
sh`), since honeypot/production images generally have bash but a minimal
service image might not.
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass

from core import ssh
from core.docker_ctl import Target

# Tried in order; the first one found on PATH is used. Covers the common
# desktop environments this app is likely to run under.
TERMINAL_CANDIDATES = [
    ("x-terminal-emulator", ["-e"]),
    ("gnome-terminal", ["--"]),
    ("konsole", ["-e"]),
    ("xfce4-terminal", ["-x"]),
    ("alacritty", ["-e"]),
    ("kitty", []),
    ("foot", []),
    ("xterm", ["-e"]),
]


class ShellError(RuntimeError):
    pass


@dataclass
class ShellCommand:
    argv: list[str]  # the raw docker-exec/ssh command, for display/copy
    terminal_argv: list[str] | None  # full argv to launch a terminal running it, or None if no terminal found


def find_terminal() -> tuple[str, list[str]] | None:
    for name, args in TERMINAL_CANDIDATES:
        path = shutil.which(name)
        if path:
            return path, args
    return None


def build_shell_command(target: Target, container_id_or_service: str) -> ShellCommand:
    inner_cmd = f"docker exec -it {container_id_or_service} sh -c 'exec bash || exec sh'"

    if not target.is_remote:
        argv = ["sh", "-c", inner_cmd]
    else:
        argv = ssh.ssh_argv(target.remote, inner_cmd, tty=True)

    terminal = find_terminal()
    if terminal is None:
        return ShellCommand(argv=argv, terminal_argv=None)

    term_path, term_args = terminal
    terminal_argv = [term_path, *term_args, *argv]
    return ShellCommand(argv=argv, terminal_argv=terminal_argv)
