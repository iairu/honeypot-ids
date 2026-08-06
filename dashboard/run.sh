#!/bin/sh
# Creates the venv (first run only) and launches the dashboard.
set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR"

if [ ! -d venv ]; then
    echo "First run: creating venv and installing dependencies..."
    python3 -m venv venv
    ./venv/bin/pip install --upgrade pip -q
    ./venv/bin/pip install -r requirements.txt -q
fi

exec ./venv/bin/python3 main.py "$@"
