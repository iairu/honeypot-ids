#!/bin/sh
# Creates the venv (first run only) and launches the dashboard.
set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR"

if [ ! -d venv ]; then
    # Fires before ANYTHING else (venv creation, pip) -- a desktop
    # notification is the one thing that can appear genuinely instantly,
    # since it needs no Python/Qt/venv to exist at all yet (just talks to
    # the system notification daemon over D-Bus and returns immediately,
    # it doesn't wait for the user to dismiss it). This is what actually
    # closes the "not immediate" gap: the graphical progress window further
    # down still can't appear until PyQt6 itself finishes installing (no
    # GUI toolkit exists before that -- unavoidable), but this notification
    # covers the moment in between, which matters most when launched from
    # Dashboard.desktop (Terminal=false), where the echo lines below are
    # never seen at all. Silently skipped if notify-send isn't installed --
    # optional, not a hard dependency.
    if command -v notify-send >/dev/null 2>&1; then
        notify-send -a "Honeypot Dashboard" "Setting up Honeypot Dashboard…" \
            "First run -- installing dependencies, this can take a minute or two." 2>/dev/null || true
    fi

    echo "First run: creating venv and installing dependencies..."
    python3 -m venv venv
    ./venv/bin/pip install --upgrade pip -q

    # PyQt6 alone, first, quietly -- as soon as it's installed we can use
    # PyQt6 ITSELF to show a real graphical progress window for the rest
    # of requirements.txt (setup_progress.py), instead of nothing being
    # visible at all until every package finishes -- especially bad when
    # launched from Dashboard.desktop (Terminal=false), where this echo
    # output is never seen either. Nothing before this point can show a
    # GUI: no toolkit exists yet in the fresh venv.
    pyqt6_line=$(grep -m1 '^PyQt6==' requirements.txt)
    echo "Installing PyQt6 (needed before setup progress can be shown graphically)..."
    ./venv/bin/pip install -q "$pyqt6_line"

    ./venv/bin/python3 setup_progress.py
fi

exec ./venv/bin/python3 main.py "$@"
