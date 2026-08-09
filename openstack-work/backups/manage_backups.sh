#!/bin/sh
# manage_backups.sh - Label, rename, delete, export, and import
# backup_service's backups (openstack-work/backups/{db,wp}/*.gz) from the
# command line -- the non-dashboard equivalent of the Backups page's
# label/delete/export/import buttons (dashboard/ui/page_backups.py). Both
# read and write the exact same labels.json manifest inside backup_service,
# via `docker compose exec`, so a label set from one shows up in the other
# immediately -- there's no separate/divergent state.
#
# Usage (run from openstack-work/, or from anywhere -- it cd's to its own
# directory first):
#   ./backups/manage_backups.sh list
#   ./backups/manage_backups.sh label <filename> <label text>
#   ./backups/manage_backups.sh delete <filename> --yes
#   ./backups/manage_backups.sh export <filename> <local-dest-path>
#   ./backups/manage_backups.sh import <local-src-path> [db|wp]
#
# <filename> is always just the basename as shown by `list` (e.g.
# "2026-08-09_02-00-03_production_database.sql.gz") -- never a path; both
# db and wp backups share one flat namespace here since their filename
# suffixes (_production_database.sql.gz vs _production_eshop.tar.gz)
# already disambiguate which directory (db/ or wp/) a given name lives in.
#
# Requires: docker, docker compose, jq (for labels.json -- deliberately NOT
# required inside backup_service itself, which stays the minimal
# alpine+mysql-client image backup.sh already needs; jq only runs here, on
# the host, same as this script itself).
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR/.."

BACKUP_SERVICE=backup_service
LABELS_PATH=/backups/labels.json

if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq is required (used to read/update labels.json) -- install it and retry." >&2
    exit 1
fi

usage() {
    sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
}

compose_exec() {
    docker compose exec -T "$BACKUP_SERVICE" "$@"
}

# Prints labels.json's current content, or "{}" if it doesn't exist yet
# (a freshly-started stack legitimately has no labels yet -- not an error).
read_labels() {
    compose_exec sh -c "cat ${LABELS_PATH} 2>/dev/null || echo '{}'"
}

# Writes new_content (stdin) back into labels.json inside the container.
write_labels() {
    compose_exec sh -c "cat > ${LABELS_PATH}"
}

# Basic filename validation shared by every subcommand that takes one --
# same shape backup.sh/restore_db.sh's own filenames always have, and
# rejects path traversal before it ever reaches a shell command built
# around this value.
require_valid_filename() {
    case "$1" in
        *_production_database.sql.gz|*_production_eshop.tar.gz) ;;
        *)
            echo "ERROR: not a recognized backup filename: $1" >&2
            echo "  (expected *_production_database.sql.gz or *_production_eshop.tar.gz)" >&2
            exit 1
            ;;
    esac
    case "$1" in
        */*|*..*)
            echo "ERROR: invalid filename: $1" >&2
            exit 1
            ;;
    esac
}

# Which of db/ or wp/ a filename belongs to, purely from its own suffix --
# same convention backup.sh's own output already establishes.
backup_dir_for() {
    case "$1" in
        *_production_database.sql.gz) echo db ;;
        *_production_eshop.tar.gz) echo wp ;;
        *) echo "ERROR: cannot determine db/ or wp/ for: $1" >&2; exit 1 ;;
    esac
}

cmd_list() {
    labels=$(read_labels)
    echo "DB dumps (openstack-work/backups/db/):"
    compose_exec sh -c "ls -1 /backups/db 2>/dev/null || true" | while read -r f; do
        [ -n "$f" ] || continue
        label=$(echo "$labels" | jq -r --arg f "$f" '.[$f].label // ""')
        if [ -n "$label" ]; then
            printf '  %-55s [%s]\n' "$f" "$label"
        else
            printf '  %-55s\n' "$f"
        fi
    done
    echo "WP file archives (openstack-work/backups/wp/):"
    compose_exec sh -c "ls -1 /backups/wp 2>/dev/null || true" | while read -r f; do
        [ -n "$f" ] || continue
        label=$(echo "$labels" | jq -r --arg f "$f" '.[$f].label // ""')
        if [ -n "$label" ]; then
            printf '  %-55s [%s]\n' "$f" "$label"
        else
            printf '  %-55s\n' "$f"
        fi
    done
}

cmd_label() {
    filename="${1:?usage: manage_backups.sh label <filename> <label text>}"
    shift
    label_text="${*:?usage: manage_backups.sh label <filename> <label text>}"
    require_valid_filename "$filename"

    now=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    read_labels | jq --arg f "$filename" --arg l "$label_text" --arg t "$now" \
        '.[$f] = {label: $l, updated: $t}' | write_labels
    echo "Labeled $filename: $label_text"
}

cmd_delete() {
    filename="${1:?usage: manage_backups.sh delete <filename> --yes}"
    confirm="${2:-}"
    require_valid_filename "$filename"
    dir=$(backup_dir_for "$filename")

    if [ "$confirm" != "--yes" ]; then
        echo "This permanently deletes /backups/${dir}/${filename} -- pass --yes to confirm:" >&2
        echo "  $0 delete $filename --yes" >&2
        exit 1
    fi

    compose_exec rm -f "/backups/${dir}/${filename}"
    read_labels | jq --arg f "$filename" 'del(.[$f])' | write_labels
    echo "Deleted $filename"
}

cmd_export() {
    filename="${1:?usage: manage_backups.sh export <filename> <local-dest-path>}"
    dest="${2:?usage: manage_backups.sh export <filename> <local-dest-path>}"
    require_valid_filename "$filename"
    dir=$(backup_dir_for "$filename")

    compose_exec cat "/backups/${dir}/${filename}" > "$dest"
    echo "Exported $filename -> $dest ($(du -h "$dest" | cut -f1))"
}

cmd_import() {
    src="${1:?usage: manage_backups.sh import <local-src-path> [db|wp]}"
    kind="${2:-}"
    [ -f "$src" ] || { echo "ERROR: no such file: $src" >&2; exit 1; }

    filename=$(basename "$src")
    require_valid_filename "$filename"
    if [ -z "$kind" ]; then
        kind=$(backup_dir_for "$filename")
    fi

    compose_exec sh -c "cat > /backups/${kind}/${filename}" < "$src"
    echo "Imported $src -> /backups/${kind}/${filename}"
}

[ $# -ge 1 ] || usage

subcommand="$1"
shift

case "$subcommand" in
    list) cmd_list "$@" ;;
    label) cmd_label "$@" ;;
    delete) cmd_delete "$@" ;;
    export) cmd_export "$@" ;;
    import) cmd_import "$@" ;;
    *) usage ;;
esac
