"""One place that knows how this app invokes the system ssh/scp binaries.

Every remote action in the app (compose commands, .env fetch/push, rsync's
transport, "open a shell") used to assemble its own ssh argv with the same
options -- this module is that argv, built once. System binaries rather
than paramiko on purpose: the user's own ssh_config/known_hosts/agent
apply exactly as they would from a terminal.

Options and why:
  StrictHostKeyChecking=accept-new  first connection to a new host is
                                    accepted (and pinned); a CHANGED key
                                    still fails loudly.
  BatchMode=yes                     never prompt for a password -- these
                                    run from a GUI/QProcess with no TTY,
                                    so a prompt would just hang. Omitted
                                    for the interactive shell (tty=True).
  ConnectTimeout=N                  bounded wait on an unreachable host.
"""
from __future__ import annotations

import shlex

from core.state import RemoteConfig

DEFAULT_TIMEOUT = 8.0


def _common_options(timeout: float, batch: bool) -> list[str]:
    opts = ["-o", "StrictHostKeyChecking=accept-new"]
    if batch:
        opts += ["-o", "BatchMode=yes"]
    opts += ["-o", f"ConnectTimeout={int(timeout)}"]
    return opts


def ssh_argv(remote: RemoteConfig, *remote_command: str, timeout: float = DEFAULT_TIMEOUT, tty: bool = False) -> list[str]:
    """argv for ``ssh user@host <remote_command>``. `remote_command` is
    passed through as-is (one shell string the remote side interprets --
    callers shlex.quote() anything user-controlled). tty=True requests a
    PTY (``-t``) and drops BatchMode, for an interactive shell."""
    argv = ["ssh"]
    if tty:
        argv.append("-t")
    argv += ["-i", remote.key_path, "-p", str(remote.port)]
    argv += _common_options(timeout, batch=not tty)
    argv.append(remote.address)
    argv += remote_command
    return argv


def ssh_command_string(remote: RemoteConfig, timeout: float = DEFAULT_TIMEOUT) -> str:
    """The same connection options as ssh_argv(), as ONE shell string --
    for rsync's ``-e`` transport option, which takes a command line rather
    than an argv."""
    parts = ["ssh", "-i", shlex.quote(remote.key_path), "-p", str(remote.port)]
    parts += _common_options(timeout, batch=True)
    return " ".join(parts)


def scp_argv(remote: RemoteConfig, local_path: str, remote_path: str, timeout: float = DEFAULT_TIMEOUT) -> list[str]:
    """argv to copy a local file to ``user@host:remote_path``. scp's port
    flag is capital -P (lowercase -p means "preserve attributes"), unlike
    ssh's -- easy to get backwards, hence living here once."""
    return [
        "scp", "-i", remote.key_path, "-P", str(remote.port),
        *_common_options(timeout, batch=True),
        local_path, f"{remote.address}:{remote_path}",
    ]
