"""Synchronous subprocess helpers with uniform failure handling.

core/ modules that shell out (docker compose exec, ssh, scp, redis-cli via
compose, openssl) all want the same thing: run it, bound it with a
timeout, and turn "couldn't start", "timed out" and "exited non-zero" into
ONE module-specific exception carrying a human-readable message. This is
that pattern, written once. Callers stay on the UI thread only for very
short commands; anything slow goes through a QThread or QProcess instead
(see ui/process_runner.py).
"""
from __future__ import annotations

import subprocess
from typing import Sequence


def run_checked(
    argv: Sequence[str],
    *,
    error: type[Exception],
    cwd: str | None = None,
    timeout: float = 15.0,
    input: str | bytes | None = None,
    text: bool = True,
    what: str = "Command",
) -> subprocess.CompletedProcess:
    """Runs argv and returns the CompletedProcess on success (exit 0).

    Raises `error(message)` for: the binary not being runnable (OSError),
    the timeout expiring, or a non-zero exit -- in the last case the
    message is the command's stderr (stripped) when it said anything,
    otherwise a generic "exited with code N". `what` names the command in
    those messages ("scp", "redis-cli", ...). text=False keeps
    stdout/stderr as bytes for binary payloads (archives, dumps).
    """
    try:
        result = subprocess.run(
            list(argv), cwd=cwd, input=input, capture_output=True, text=text, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise error(f"{what} timed out.")
    except OSError as e:
        raise error(f"Could not run {what}: {e}")

    if result.returncode != 0:
        stderr = result.stderr
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        raise error(stderr.strip() or f"{what} exited with code {result.returncode}")
    return result


def succeeds(argv: Sequence[str], *, cwd: str | None = None, timeout: float = 10.0) -> bool:
    """True iff argv runs and exits 0 within `timeout`; every failure mode
    is just False -- for reachability-style probes where the caller only
    wants a yes/no."""
    try:
        return subprocess.run(list(argv), cwd=cwd, capture_output=True, timeout=timeout).returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False
