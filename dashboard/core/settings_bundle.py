"""Export/import bundle for the dashboard's own configuration -- both
projects' real .env values, and remote (SSH) target settings. A single
JSON file an operator can back up or move to a fresh checkout of this
repo, instead of re-typing everything by hand.

SECURITY NOTE: the bundle contains real secrets in plaintext (DB/Redis
passwords, API keys, ABUSEIPDB_API_KEY, the remote SSH key PATH -- not the
key file's contents, just its path). Same trust model as the .env files
themselves (already plaintext on disk); callers (ui/page_settings.py) are
responsible for warning the user before writing one out and for not
committing it to version control.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.env_file import EnvFile
from core.projects import PROJECTS
from core.state import AppState, RemoteConfig

BUNDLE_VERSION = 1


class BundleError(Exception):
    pass


def export_bundle(state: AppState) -> dict[str, Any]:
    """Build the exportable bundle from the current live .env files and
    the app's remote-target settings. Reads .env files fresh from disk
    (not from any UI-held EnvFile instance) so the export always reflects
    what docker compose itself would actually use."""
    bundle: dict[str, Any] = {
        "dashboard_export_version": BUNDLE_VERSION,
        "exported_at": datetime.now(timezone.utc).isoformat(),
    }
    for pid, spec in PROJECTS.items():
        bundle[f"{pid}_env"] = EnvFile.load(spec.env_file).as_dict()
        bundle[f"remote_{pid}"] = asdict(getattr(state, f"remote_{pid}"))
    return bundle


def write_bundle(path: Path, bundle: dict[str, Any]) -> None:
    path.write_text(json.dumps(bundle, indent=2))


def read_bundle(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        raise BundleError(f"Could not read {path}: {e}") from e


def apply_bundle(bundle: dict[str, Any], state: AppState) -> list[str]:
    """Apply an imported bundle: writes edge/siem .env values (preserving
    each file's existing comments/structure -- only the VALUES of keys
    present in the bundle are changed, same comment-preserving approach as
    everywhere else in this app), and replaces the app's remote-target
    settings. Returns a list of human-readable notes for the caller to
    show the user (e.g. keys the bundle added that weren't in the live
    .env yet). Raises BundleError for a file that isn't a recognizable
    export at all; individual missing sections are noted, not fatal.
    """
    if "dashboard_export_version" not in bundle:
        raise BundleError("Not a dashboard export file (missing dashboard_export_version).")
    if bundle["dashboard_export_version"] > BUNDLE_VERSION:
        raise BundleError(
            f"This export is from a newer dashboard version "
            f"({bundle['dashboard_export_version']}) than this app supports "
            f"({BUNDLE_VERSION}). Update the dashboard before importing it."
        )

    notes: list[str] = []

    for pid, spec in PROJECTS.items():
        label, env_path, bundle_key = spec.label, spec.env_file, f"{pid}_env"
        values = bundle.get(bundle_key)
        if not values:
            notes.append(f"{label}: no {bundle_key} data in bundle, skipped.")
            continue
        env_file = EnvFile.load(env_path)
        existing_keys = set(env_file.keys())
        new_keys = [k for k in values if k not in existing_keys]
        for key, value in values.items():
            env_file.set(key, value)
        env_file.save()
        note = f"{label}: applied {len(values)} value(s) to {env_path}."
        if new_keys:
            note += f" New key(s) added: {', '.join(sorted(new_keys))}."
        notes.append(note)

    for pid, spec in PROJECTS.items():
        label = spec.label
        bundle_key = attr = f"remote_{pid}"
        if isinstance(bundle.get(bundle_key), dict):
            # from_dict drops unknown keys (a bundle from another dashboard
            # version) rather than crashing the whole import over one field.
            setattr(state, attr, RemoteConfig.from_dict(bundle[bundle_key]))
            notes.append(f"{label}: remote (SSH) settings replaced.")
        else:
            notes.append(f"{label}: no {bundle_key} data in bundle, left unchanged.")
    state.save()

    return notes
