#!/bin/sh
# backup.sh - Automated production backup script for the honeynet system.
#
# PURPOSE:
#   Runs inside the backup_service Docker container (alpine:latest + mysql-client).
#   On each invocation it:
#     1. Dumps the production MySQL database to a compressed SQL file.
#     2. Creates a tar archive of the production WordPress files.
#     3. Writes a structured JSON log entry for ELK / manual auditing.
#     4. Prunes archives older than BACKUP_RETENTION_DAYS (default: 7).
#
# INVOCATION:
#   Called automatically by the backup_service Docker service every 24 hours.
#   Can also be triggered manually:
#     docker compose exec backup_service /backup.sh
#
# OUTPUTS (written to /backups/ which is bind-mounted to ./backups/ on the host):
#   db/YYYY-MM-DD_HH-MM-SS_production_database.sql.gz  – compressed SQL dump
#   wp/YYYY-MM-DD_HH-MM-SS_production_eshop.tar.gz     – WordPress file archive
#   backup.log                                           – append-only JSON log
#
# SECURITY NOTES:
#   - The MySQL password is read from the environment variable MYSQL_PASSWORD;
#     it is never passed on the command line (which would expose it via /proc).
#   - The backup container has no capabilities (cap_drop: ALL) and no access to
#     honeypot networks, so a compromise of this container cannot reach attacker
#     data or escalate privileges.
#   - Backup files are owned by the container's UID (root inside, but the host
#     bind-mount directory should have appropriate host-side permissions).

# pipefail is required so that `mysqldump ... | gzip -9 > file` reports
# mysqldump's exit status, not gzip's. Without it, a failed/empty mysqldump
# still produces a "successful" empty gzip file, and the
# `if mysqldump | gzip; then success; else failure; fi` check below
# silently logs a fake success -- confirmed live: mysqldump was failing on
# a TLS certificate error on every single run (see --skip-ssl below), and
# the resulting empty 4KB .sql.gz (zero actual SQL content) was logged as
# "OK db_dump" regardless, because gzip itself never fails on empty input.
set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration – overridable via environment variables injected by Docker Compose.
# ---------------------------------------------------------------------------
MYSQL_HOST="${MYSQL_HOST:-production_database}"
MYSQL_DATABASE="${MYSQL_DATABASE:-production_database}"
MYSQL_USER="${MYSQL_USER:-production_user}"
# MYSQL_PASSWORD must be set in the environment; fail loudly if it is absent.
: "${MYSQL_PASSWORD:?MYSQL_PASSWORD environment variable is required}"

BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-7}"

# Backup root directory (bind-mounted to ./backups/ on the host).
BACKUP_ROOT="/backups"
DB_BACKUP_DIR="${BACKUP_ROOT}/db"
WP_BACKUP_DIR="${BACKUP_ROOT}/wp"
LOG_FILE="${BACKUP_ROOT}/backup.log"

# Source WordPress files directory (bind-mounted read-only from ./production_eshop_files/).
WP_SOURCE_DIR="/source_wp"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Timestamp in ISO-8601 / filename-safe format.
now_iso()  { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
now_file() { date -u '+%Y-%m-%d_%H-%M-%S'; }

# Append a JSON log entry to the structured log file.
# Arguments: $1=status ("success"|"failure"), $2=step, $3=detail
log_entry() {
    STATUS="$1"
    STEP="$2"
    DETAIL="$3"
    # Minimal JSON – no jq dependency required.
    printf '{"timestamp":"%s","status":"%s","step":"%s","detail":"%s"}\n' \
        "$(now_iso)" "$STATUS" "$STEP" "$DETAIL" >> "${LOG_FILE}"
}

# Print to stdout and also write a log entry.
info()    { echo "[BACKUP] $(now_iso) INFO  $*"; }
success() { echo "[BACKUP] $(now_iso) OK    $*"; log_entry "success" "$1" "${2:-}"; }
failure() { echo "[BACKUP] $(now_iso) ERROR $*"; log_entry "failure" "$1" "${2:-}"; }

# ---------------------------------------------------------------------------
# Initialise backup directories
# ---------------------------------------------------------------------------
mkdir -p "${DB_BACKUP_DIR}" "${WP_BACKUP_DIR}"

TIMESTAMP="$(now_file)"

info "=== Backup run starting at $(now_iso) ==="
info "Retention: ${BACKUP_RETENTION_DAYS} days"

# ---------------------------------------------------------------------------
# Step 1: MySQL database dump
# ---------------------------------------------------------------------------
DB_DUMP_FILE="${DB_BACKUP_DIR}/${TIMESTAMP}_${MYSQL_DATABASE}.sql.gz"

info "Step 1/3: Dumping MySQL database '${MYSQL_DATABASE}' from host '${MYSQL_HOST}'..."

# Write password to a temporary option file to avoid shell history / /proc
# exposure.  The file is removed in the EXIT trap below.
# BusyBox's mktemp (this runs on alpine) requires the template to end in
# XXXXXX with no suffix after it -- unlike GNU mktemp, ".cnf" after the X's
# fails with "Invalid argument". No functional need for the extension:
# mysqldump's --defaults-extra-file doesn't care what the path looks like.
MYSQL_OPT_FILE="$(mktemp /tmp/mysql-backup-XXXXXX)"
trap 'rm -f "${MYSQL_OPT_FILE}"' EXIT

cat > "${MYSQL_OPT_FILE}" << MYSQLCONF
[client]
password=${MYSQL_PASSWORD}
MYSQLCONF
chmod 600 "${MYSQL_OPT_FILE}"

# --skip-ssl: MySQL 8+ enables TLS by default and auto-generates a
# self-signed server cert; mysqldump then refuses it as untrusted ("TLS/SSL
# error: Certificate verification failure"), which -- combined with the
# missing pipefail above -- silently produced an empty 4KB .sql.gz on every
# run instead of a real dump. This is a private container-to-container
# connection on production_network, not a path exposed to the internet, so
# skipping TLS here is a deliberate, scoped tradeoff, not "disable all
# security".
if mysqldump \
        --defaults-extra-file="${MYSQL_OPT_FILE}" \
        --host="${MYSQL_HOST}" \
        --user="${MYSQL_USER}" \
        --skip-ssl \
        --single-transaction \
        --routines \
        --triggers \
        --add-drop-table \
        --comments \
        "${MYSQL_DATABASE}" \
    | gzip -9 > "${DB_DUMP_FILE}"; then

    DB_SIZE="$(du -sh "${DB_DUMP_FILE}" 2>/dev/null | cut -f1)"
    success "db_dump" "${DB_DUMP_FILE} (${DB_SIZE})"
    info "Database dump saved: ${DB_DUMP_FILE} (${DB_SIZE})"
else
    failure "db_dump" "mysqldump exited with error for database ${MYSQL_DATABASE}"
    # Remove the partial (likely corrupt) dump file.
    rm -f "${DB_DUMP_FILE}"
    info "Partial dump removed. Continuing to file backup..."
fi

# ---------------------------------------------------------------------------
# Step 2: WordPress file archive
# ---------------------------------------------------------------------------
WP_ARCHIVE_FILE="${WP_BACKUP_DIR}/${TIMESTAMP}_production_eshop.tar.gz"

info "Step 2/3: Archiving WordPress files from ${WP_SOURCE_DIR}..."

if [ -d "${WP_SOURCE_DIR}" ] && [ -n "$(find "${WP_SOURCE_DIR}" -mindepth 1 -maxdepth 1 2>/dev/null)" ]; then
    if tar \
            --create \
            --gzip \
            --file="${WP_ARCHIVE_FILE}" \
            --directory="${WP_SOURCE_DIR}" \
            --exclude="./wp-content/cache" \
            --exclude="./wp-content/upgrade" \
            --exclude="./.git" \
            .; then

        WP_SIZE="$(du -sh "${WP_ARCHIVE_FILE}" 2>/dev/null | cut -f1)"
        success "wp_archive" "${WP_ARCHIVE_FILE} (${WP_SIZE})"
        info "WordPress archive saved: ${WP_ARCHIVE_FILE} (${WP_SIZE})"
    else
        failure "wp_archive" "tar failed for ${WP_SOURCE_DIR}"
        rm -f "${WP_ARCHIVE_FILE}"
    fi
else
    failure "wp_archive" "Source directory ${WP_SOURCE_DIR} is empty or does not exist"
    info "Skipping WordPress file backup – source not populated yet."
fi

# ---------------------------------------------------------------------------
# Step 3: Retention pruning
# ---------------------------------------------------------------------------
info "Step 3/3: Pruning archives older than ${BACKUP_RETENTION_DAYS} days..."

PRUNED_COUNT=0

# Prune old database dumps.
if find "${DB_BACKUP_DIR}" -maxdepth 1 -name "*.sql.gz" \
        -mtime "+${BACKUP_RETENTION_DAYS}" -print | grep -q .; then
    find "${DB_BACKUP_DIR}" -maxdepth 1 -name "*.sql.gz" \
        -mtime "+${BACKUP_RETENTION_DAYS}" -print | while read -r OLD_FILE; do
        info "  Removing old DB dump: ${OLD_FILE}"
        rm -f "${OLD_FILE}"
        PRUNED_COUNT=$((PRUNED_COUNT + 1))
    done
fi

# Prune old WordPress archives.
if find "${WP_BACKUP_DIR}" -maxdepth 1 -name "*.tar.gz" \
        -mtime "+${BACKUP_RETENTION_DAYS}" -print | grep -q .; then
    find "${WP_BACKUP_DIR}" -maxdepth 1 -name "*.tar.gz" \
        -mtime "+${BACKUP_RETENTION_DAYS}" -print | while read -r OLD_FILE; do
        info "  Removing old WP archive: ${OLD_FILE}"
        rm -f "${OLD_FILE}"
        PRUNED_COUNT=$((PRUNED_COUNT + 1))
    done
fi

success "pruning" "Retention pruning complete (threshold: ${BACKUP_RETENTION_DAYS} days)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
TOTAL_DB="$(find "${DB_BACKUP_DIR}" -maxdepth 1 -name '*.sql.gz' 2>/dev/null | wc -l | tr -d ' ')"
TOTAL_WP="$(find "${WP_BACKUP_DIR}" -maxdepth 1 -name '*.tar.gz' 2>/dev/null | wc -l | tr -d ' ')"

info "=== Backup run complete at $(now_iso) ==="
info "    DB archives retained : ${TOTAL_DB}"
info "    WP archives retained : ${TOTAL_WP}"
info "    Log file             : ${LOG_FILE}"

log_entry "success" "run_complete" "db_archives=${TOTAL_DB},wp_archives=${TOTAL_WP}"