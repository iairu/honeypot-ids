#!/bin/sh
# restore_db.sh - Restores the production MySQL database from a dump
# previously written by backup.sh.
#
# PURPOSE:
#   Runs inside the backup_service Docker container (alpine:latest +
#   mysql-client, same as backup.sh -- both share that container's
#   dependencies). Given the filename of a *.sql.gz dump under
#   /backups/db (as produced by backup.sh, e.g.
#   "2026-08-09_02-00-03_production_database.sql.gz"), it:
#     1. Validates the filename (no path traversal, must exist under
#        /backups/db).
#     2. Restores it into the live production database with
#        `mysql ... < gunzip'd dump`.
#     3. Writes a structured JSON log entry to backup.log, same format
#        and file backup.sh itself appends to, so a restore shows up in
#        the same audit trail as every backup run.
#
# INVOCATION (normally triggered from the dashboard's Backups page --
# see dashboard/core/backup_ctl.py):
#     docker compose exec backup_service /restore_db.sh <dump-filename>
#
# THIS OVERWRITES THE LIVE PRODUCTION DATABASE. There is no undo short of
# restoring a different (e.g. newer) backup afterwards -- the caller is
# expected to have already confirmed this with the user.
#
# SECURITY NOTES (mirrors backup.sh):
#   - The MySQL password is read from the environment variable
#     MYSQL_PASSWORD; it is never passed on the command line.
#   - $1 is validated against a strict allow-list shape before being used
#     to build a filesystem path, so this can't be used to read/execute
#     anything outside /backups/db regardless of what the caller passes.
set -eu

MYSQL_HOST="${MYSQL_HOST:-production_database}"
MYSQL_DATABASE="${MYSQL_DATABASE:-production_database}"
MYSQL_USER="${MYSQL_USER:-production_user}"
: "${MYSQL_PASSWORD:?MYSQL_PASSWORD environment variable is required}"

BACKUP_ROOT="/backups"
DB_BACKUP_DIR="${BACKUP_ROOT}/db"
LOG_FILE="${BACKUP_ROOT}/backup.log"

now_iso() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }

log_entry() {
    # Arguments: $1=status ("success"|"failure"), $2=step, $3=detail
    printf '{"timestamp":"%s","status":"%s","step":"%s","detail":"%s"}\n' \
        "$(now_iso)" "$1" "$2" "$3" >> "${LOG_FILE}"
}

FILENAME="${1:-}"
if [ -z "${FILENAME}" ]; then
    echo "usage: restore_db.sh <dump-filename>" >&2
    exit 1
fi

# Only a bare filename shaped like backup.sh's own output is accepted --
# no "/", no "..", nothing that could walk outside DB_BACKUP_DIR once
# concatenated onto it below.
case "${FILENAME}" in
    *_production_database.sql.gz)
        case "${FILENAME}" in
            */*|*..*)
                echo "invalid filename: ${FILENAME}" >&2
                exit 1
                ;;
        esac
        ;;
    *)
        echo "invalid filename (expected *_production_database.sql.gz): ${FILENAME}" >&2
        exit 1
        ;;
esac

DUMP_FILE="${DB_BACKUP_DIR}/${FILENAME}"
if [ ! -f "${DUMP_FILE}" ]; then
    echo "not found: ${DUMP_FILE}" >&2
    exit 1
fi

# Same --defaults-extra-file trick backup.sh uses to keep the password out
# of argv/history/proc.
MYSQL_OPT_FILE="$(mktemp /tmp/mysql-restore-XXXXXX)"
trap 'rm -f "${MYSQL_OPT_FILE}"' EXIT

cat > "${MYSQL_OPT_FILE}" << MYSQLCONF
[client]
password=${MYSQL_PASSWORD}
MYSQLCONF
chmod 600 "${MYSQL_OPT_FILE}"

echo "[RESTORE] $(now_iso) Restoring ${DUMP_FILE} into ${MYSQL_DATABASE}@${MYSQL_HOST}..."

# --skip-ssl: same TLS-certificate-verification issue backup.sh's own
# comment documents for mysqldump also applies to the mysql client here --
# this is still a private container-to-container connection on
# production_network only.
if gunzip -c "${DUMP_FILE}" | mysql \
        --defaults-extra-file="${MYSQL_OPT_FILE}" \
        --host="${MYSQL_HOST}" \
        --user="${MYSQL_USER}" \
        --skip-ssl \
        "${MYSQL_DATABASE}"; then
    log_entry "success" "db_restore" "${FILENAME}"
    echo "[RESTORE] $(now_iso) OK restored ${FILENAME}"
else
    log_entry "failure" "db_restore" "${FILENAME}"
    echo "[RESTORE] $(now_iso) ERROR failed to restore ${FILENAME}" >&2
    exit 1
fi
