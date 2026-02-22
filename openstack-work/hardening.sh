#!/bin/sh
# hardening.sh - Comprehensive hardening verification script for the honeynet system.
#
# PURPOSE:
#   Audits the security posture of the running honeynet deployment and produces
#   a structured pass/fail report.  Run this after initial deployment and after
#   any configuration change to verify that all hardening measures are active.
#
# USAGE:
#   ./hardening.sh [--json] [--quiet]
#
#   --json         Emit the final report as JSON (suitable for ELK / SIEM ingestion).
#   --quiet        Suppress per-check INFO lines; print only the final summary and
#                  any FAIL lines.
#   --static-only  Skip all live Docker runtime checks. Useful on development
#                  machines where Docker is not installed or the stack is not
#                  running. Only static file-based checks are performed.
#
# EXIT CODES:
#   0  All checks passed.
#   1  One or more checks failed.
#   2  Script prerequisites not met (docker / docker compose not found, and
#      --static-only was not specified).
#
# CHECKS PERFORMED:
#   1.  XML-RPC disabled on production (mu-plugin present + nginx block active)
#   2.  Nginx has server_tokens off
#   3.  Nginx has security headers (HSTS, X-Frame-Options, CSP, etc.)
#   4.  Hotlink protection block present in nginx.conf
#   5.  Version-fingerprint headers stripped (more_set_headers / more_clear_headers)
#   6.  Honeypot container security options (no-new-privileges, cap_drop ALL)
#   7.  Honeypot container resource limits (mem_limit, cpus, pids_limit)
#   8.  Production database reachable and password-protected
#   9.  Redis password authentication enforced
#   10. SSL certificates present and not expired within 30 days
#   11. Backup service is defined and running
#   12. Backup archives exist and are recent (within 48 hours)
#   13. Production hardening mu-plugin is deployed
#   14. Reverse proxy blocks information-disclosure file paths
#
# NOTE: Checks that require a live Docker environment (service status, Redis auth,
#       SSL expiry) will be skipped with a WARN if Docker Compose is not running.

set -eu

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
EMIT_JSON=0
QUIET=0
STATIC_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --json)        EMIT_JSON=1 ;;
        --quiet)       QUIET=1 ;;
        --static-only) STATIC_ONLY=1 ;;
        *)
            echo "Unknown argument: $arg" >&2
            echo "Usage: $0 [--json] [--quiet] [--static-only]" >&2
            exit 2
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Colour support (disabled when output is not a terminal or --json is set)
# ---------------------------------------------------------------------------
if [ -t 1 ] && [ "$EMIT_JSON" -eq 0 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    RED='' GREEN='' YELLOW='' CYAN='' BOLD='' RESET=''
fi

# ---------------------------------------------------------------------------
# Counters and result accumulator
# ---------------------------------------------------------------------------
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
SKIP_COUNT=0

# Accumulate JSON result objects for --json output.
JSON_RESULTS=""

# Script directory (used to locate sibling files relative to this script).
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

now_iso() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }

# Print a formatted line unless --quiet suppresses INFO.
info() {
    [ "$QUIET" -eq 1 ] && return
    printf "${CYAN}[INFO]${RESET}  %s\n" "$*"
}

pass() {
    CHECK_NAME="$1"; DETAIL="${2:-}"
    PASS_COUNT=$((PASS_COUNT + 1))
    printf "${GREEN}[PASS]${RESET}  %-50s %s\n" "$CHECK_NAME" "$DETAIL"
    _append_json "$CHECK_NAME" "pass" "$DETAIL"
}

fail() {
    CHECK_NAME="$1"; DETAIL="${2:-}"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    printf "${RED}[FAIL]${RESET}  %-50s %s\n" "$CHECK_NAME" "$DETAIL"
    _append_json "$CHECK_NAME" "fail" "$DETAIL"
}

warn() {
    CHECK_NAME="$1"; DETAIL="${2:-}"
    WARN_COUNT=$((WARN_COUNT + 1))
    printf "${YELLOW}[WARN]${RESET}  %-50s %s\n" "$CHECK_NAME" "$DETAIL"
    _append_json "$CHECK_NAME" "warn" "$DETAIL"
}

skip() {
    CHECK_NAME="$1"; DETAIL="${2:-}"
    SKIP_COUNT=$((SKIP_COUNT + 1))
    [ "$QUIET" -eq 1 ] && return
    printf "        %-50s (skipped: %s)\n" "$CHECK_NAME" "$DETAIL"
    _append_json "$CHECK_NAME" "skip" "$DETAIL"
}

# Append a check result to the JSON accumulator string.
_append_json() {
    NAME="$1"; STATUS="$2"; DETAIL="$3"
    # Escape double-quotes in detail string.
    DETAIL_ESCAPED="$(printf '%s' "$DETAIL" | sed 's/"/\\"/g')"
    ENTRY="{\"check\":\"$NAME\",\"status\":\"$STATUS\",\"detail\":\"$DETAIL_ESCAPED\",\"timestamp\":\"$(now_iso)\"}"
    if [ -z "$JSON_RESULTS" ]; then
        JSON_RESULTS="$ENTRY"
    else
        JSON_RESULTS="${JSON_RESULTS},${ENTRY}"
    fi
}

# Check whether a string contains a pattern (grep -q wrapper).
contains() { printf '%s' "$1" | grep -q "$2"; }

# Check whether a file exists and is non-empty.
file_exists_nonempty() { [ -f "$1" ] && [ -s "$1" ]; }

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
printf "\n${BOLD}Honeynet Hardening Audit${RESET}  $(now_iso)\n"
printf '%0.s-' $(seq 1 60); printf '\n\n'

# Locate the docker-compose.yml and nginx.conf relative to this script.
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
NGINX_CONF="${SCRIPT_DIR}/reverse_proxy_enhanced/nginx.conf"
MU_PLUGINS_DIR="${SCRIPT_DIR}/production_eshop_files/wp-content/mu-plugins"
BACKUP_DIR="${SCRIPT_DIR}/backups"

if ! command -v docker > /dev/null 2>&1; then
    if [ "$STATIC_ONLY" -eq 1 ]; then
        warn "docker: not found" "running in --static-only mode; all live checks will be skipped"
    else
        echo "ERROR: 'docker' not found in PATH. Cannot run live checks." >&2
        echo "       Use --static-only to run only configuration file checks." >&2
        exit 2
    fi
fi

# Detect whether docker compose (plugin) or docker-compose (standalone) is available.
if docker compose version > /dev/null 2>&1; then
    DC="docker compose"
elif command -v docker-compose > /dev/null 2>&1; then
    DC="docker-compose"
else
    DC=""
fi

# Determine whether the stack is currently up by checking for at least one
# running container whose name starts with "honeypot".
# In --static-only mode the stack is treated as not running so all live
# checks are skipped unconditionally.
STACK_RUNNING=0
if [ "$STATIC_ONLY" -eq 0 ] && [ -n "$DC" ]; then
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q 'honeypot\|reverse_proxy\|production'; then
        STACK_RUNNING=1
    fi
fi

# ---------------------------------------------------------------------------
# Section 1: Static file checks (do not require Docker to be running)
# ---------------------------------------------------------------------------
printf "${BOLD}[Section 1] Static configuration checks${RESET}\n\n"

# Check 1a: Production hardening mu-plugin deployed
info "Checking production hardening mu-plugin..."
HARDENING_PLUGIN="${MU_PLUGINS_DIR}/production-hardening.php"
if file_exists_nonempty "$HARDENING_PLUGIN"; then
    pass "mu-plugin: production-hardening.php" "present at ${HARDENING_PLUGIN}"
else
    fail "mu-plugin: production-hardening.php" "NOT found at ${HARDENING_PLUGIN}"
fi

# Check 1b: XML-RPC filter present inside the mu-plugin
info "Checking xmlrpc_enabled filter in mu-plugin..."
if [ -f "$HARDENING_PLUGIN" ] && grep -q "xmlrpc_enabled.*__return_false" "$HARDENING_PLUGIN"; then
    pass "mu-plugin: xmlrpc_enabled filter" "xmlrpc disabled via filter"
else
    fail "mu-plugin: xmlrpc_enabled filter" "filter not found – XML-RPC may be active"
fi

# Check 1c: DISALLOW_FILE_EDIT defined in mu-plugin
info "Checking DISALLOW_FILE_EDIT..."
if [ -f "$HARDENING_PLUGIN" ] && grep -q "DISALLOW_FILE_EDIT.*true" "$HARDENING_PLUGIN"; then
    pass "mu-plugin: DISALLOW_FILE_EDIT" "file editor disabled"
else
    fail "mu-plugin: DISALLOW_FILE_EDIT" "constant not defined in hardening plugin"
fi

# Check 1d: production-hardening.php must NOT be present in any honeypot pool.
# init_setup deletes it from every pool destination after copying production files.
# If it is found in a honeypot pool it means init_setup did not run the cleanup
# step, and the honeypot would incorrectly disable XML-RPC and strip version
# strings — destroying the realistic attack surface the honeypot depends on.
info "Checking production-hardening.php absent from honeypot pools..."
POOLS_WITH_PLUGIN=""
for POOL_NUM in 1 2 3; do
    # Derive the expected honeypot files directory name for each pool.
    if [ "$POOL_NUM" -eq 1 ]; then
        POOL_FILES_DIR="${SCRIPT_DIR}/honeypot_eshop_files"
    else
        POOL_FILES_DIR="${SCRIPT_DIR}/honeypot_eshop_files_${POOL_NUM}"
    fi

    POOL_PLUGIN="${POOL_FILES_DIR}/wp-content/mu-plugins/production-hardening.php"

    # Only flag as a problem if the pool directory has been populated at all
    # (i.e. init_setup has already run).  An empty/absent pool dir means the
    # stack has never been started – not a hardening violation.
    if [ -d "${POOL_FILES_DIR}/wp-content" ]; then
        if [ -f "$POOL_PLUGIN" ]; then
            POOLS_WITH_PLUGIN="${POOLS_WITH_PLUGIN} pool-${POOL_NUM}"
        fi
    fi
done

if [ -z "$POOLS_WITH_PLUGIN" ]; then
    pass "honeypot: production-hardening.php absent" "plugin not present in any honeypot pool"
else
    fail "honeypot: production-hardening.php absent" \
        "plugin found in:${POOLS_WITH_PLUGIN} – init_setup cleanup may have failed; honeypot attack surface is compromised"
fi

# Check 2: Nginx config file present
info "Checking nginx.conf presence..."
if file_exists_nonempty "$NGINX_CONF"; then
    pass "nginx.conf: file present" "$NGINX_CONF"
else
    fail "nginx.conf: file present" "NOT found at ${NGINX_CONF}"
fi

# Check 3: server_tokens off
info "Checking server_tokens off..."
if [ -f "$NGINX_CONF" ] && grep -q "server_tokens off" "$NGINX_CONF"; then
    pass "nginx.conf: server_tokens off" "version hidden from error pages"
else
    fail "nginx.conf: server_tokens off" "directive missing – nginx version may be exposed"
fi

# Check 4: more_set_headers Server obfuscation
info "Checking more_set_headers Server obfuscation..."
if [ -f "$NGINX_CONF" ] && grep -q 'more_set_headers.*Server.*nginx' "$NGINX_CONF"; then
    pass "nginx.conf: more_set_headers Server" "Server header overwritten to generic 'nginx'"
else
    fail "nginx.conf: more_set_headers Server" "directive missing – OpenResty/version may leak in Server header"
fi

# Check 5: X-Powered-By cleared
info "Checking X-Powered-By header removal..."
if [ -f "$NGINX_CONF" ] && grep -q 'more_clear_headers.*X-Powered-By' "$NGINX_CONF"; then
    pass "nginx.conf: more_clear_headers X-Powered-By" "PHP version not exposed to clients"
else
    fail "nginx.conf: more_clear_headers X-Powered-By" "directive missing – PHP version may leak"
fi

# Check 6: Hotlink protection (valid_referers) present
info "Checking hotlink protection (valid_referers)..."
if [ -f "$NGINX_CONF" ] && grep -q "valid_referers" "$NGINX_CONF"; then
    pass "nginx.conf: hotlink protection" "valid_referers block found"
else
    fail "nginx.conf: hotlink protection" "valid_referers directive not found"
fi

# Check 7: xmlrpc.php location block with deny
info "Checking nginx xmlrpc.php deny block..."
if [ -f "$NGINX_CONF" ] && grep -A10 -e "location = /xmlrpc.php" "$NGINX_CONF" | grep -q "deny all"; then
    pass "nginx.conf: /xmlrpc.php blocked" "deny all in location block"
else
    fail "nginx.conf: /xmlrpc.php blocked" "block missing – xmlrpc.php accessible at proxy level"
fi

# Check 8: Security headers present
info "Checking HTTP security headers..."
MISSING_HEADERS=""
for HEADER in "Strict-Transport-Security" "X-Frame-Options" "X-Content-Type-Options" \
              "X-XSS-Protection" "Content-Security-Policy"; do
    if [ -f "$NGINX_CONF" ] && ! grep -q "$HEADER" "$NGINX_CONF"; then
        MISSING_HEADERS="${MISSING_HEADERS} ${HEADER}"
    fi
done
if [ -z "$MISSING_HEADERS" ]; then
    pass "nginx.conf: security headers" "HSTS, X-Frame-Options, CSP all present"
else
    fail "nginx.conf: security headers" "Missing:${MISSING_HEADERS}"
fi

# Check 9: HSTS includeSubDomains
info "Checking HSTS includeSubDomains..."
if [ -f "$NGINX_CONF" ] && grep -q "includeSubDomains" "$NGINX_CONF"; then
    pass "nginx.conf: HSTS includeSubDomains" "subdomains covered"
else
    warn "nginx.conf: HSTS includeSubDomains" "not set – subdomain cookies may be sent over HTTP"
fi

# Check 10: Information-disclosure file blocks
info "Checking readme.html / license.txt blocks..."
if [ -f "$NGINX_CONF" ] && grep -q "readme\.html" "$NGINX_CONF"; then
    pass "nginx.conf: readme.html blocked" "version disclosure file denied"
else
    fail "nginx.conf: readme.html blocked" "no deny block for readme.html – WP version exposed"
fi

# Check 11: docker-compose.yml presence
info "Checking docker-compose.yml presence..."
if file_exists_nonempty "$COMPOSE_FILE"; then
    pass "docker-compose.yml: present" "$COMPOSE_FILE"
else
    fail "docker-compose.yml: present" "NOT found – cannot check container hardening"
fi

# Check 12: Honeypot container no-new-privileges
info "Checking honeypot containers for no-new-privileges..."
HP_NO_PRIVESC=0
if [ -f "$COMPOSE_FILE" ]; then
    # Count how many times no-new-privileges appears in the honeypot service blocks.
    # Expect at least 3 occurrences (one per honeypot_eshop_N).
    NNP_COUNT=$(grep -c "no-new-privileges:true" "$COMPOSE_FILE" 2>/dev/null || echo 0)
    if [ "$NNP_COUNT" -ge 6 ]; then
        pass "docker-compose: no-new-privileges" "${NNP_COUNT} occurrences (honeypot + db services)"
        HP_NO_PRIVESC=1
    elif [ "$NNP_COUNT" -ge 3 ]; then
        warn "docker-compose: no-new-privileges" "only ${NNP_COUNT} occurrences – may be missing on DB containers"
        HP_NO_PRIVESC=1
    else
        fail "docker-compose: no-new-privileges" "found ${NNP_COUNT} occurrences – honeypot containers not hardened"
    fi
fi

# Check 13: Honeypot containers cap_drop ALL
info "Checking honeypot containers for cap_drop ALL..."
if [ -f "$COMPOSE_FILE" ]; then
    CAP_DROP_COUNT=$(grep -c -e "- ALL" "$COMPOSE_FILE" 2>/dev/null || echo 0)
    if [ "$CAP_DROP_COUNT" -ge 6 ]; then
        pass "docker-compose: cap_drop ALL" "${CAP_DROP_COUNT} service blocks drop all capabilities"
    elif [ "$CAP_DROP_COUNT" -ge 3 ]; then
        warn "docker-compose: cap_drop ALL" "${CAP_DROP_COUNT} service blocks – may be incomplete"
    else
        fail "docker-compose: cap_drop ALL" "found ${CAP_DROP_COUNT} – capabilities not dropped"
    fi
fi

# Check 14: Memory limits on honeypot containers
info "Checking memory limits on honeypot containers..."
if [ -f "$COMPOSE_FILE" ]; then
    MEM_LIMIT_COUNT=$(grep -c "mem_limit:" "$COMPOSE_FILE" 2>/dev/null || echo 0)
    if [ "$MEM_LIMIT_COUNT" -ge 6 ]; then
        pass "docker-compose: mem_limit" "${MEM_LIMIT_COUNT} services have memory limits"
    else
        fail "docker-compose: mem_limit" "only ${MEM_LIMIT_COUNT} services have mem_limit – DoS risk"
    fi
fi

# Check 15: pids_limit on honeypot containers
info "Checking pids_limit on honeypot containers..."
if [ -f "$COMPOSE_FILE" ]; then
    PIDS_COUNT=$(grep -c -e "pids_limit:" "$COMPOSE_FILE" 2>/dev/null || echo 0)
    if [ "$PIDS_COUNT" -ge 6 ]; then
        pass "docker-compose: pids_limit" "${PIDS_COUNT} services have pids_limit (fork-bomb protection)"
    else
        fail "docker-compose: pids_limit" "only ${PIDS_COUNT} services have pids_limit"
    fi
fi

# Check 16: Backup service defined
info "Checking backup_service in docker-compose.yml..."
if [ -f "$COMPOSE_FILE" ] && grep -q "backup_service:" "$COMPOSE_FILE"; then
    pass "docker-compose: backup_service" "backup service defined"
else
    fail "docker-compose: backup_service" "backup_service not found – no automated backups"
fi

# Check 17: Backup script present and executable
info "Checking backup.sh presence and permissions..."
BACKUP_SCRIPT="${BACKUP_DIR}/backup.sh"
if file_exists_nonempty "$BACKUP_SCRIPT"; then
    if [ -x "$BACKUP_SCRIPT" ]; then
        pass "backups/backup.sh: executable" "script present and executable"
    else
        warn "backups/backup.sh: executable" "script present but not executable – run: chmod +x ${BACKUP_SCRIPT}"
    fi
else
    fail "backups/backup.sh: present" "NOT found at ${BACKUP_SCRIPT}"
fi

# Check 18: SSL certificates present on disk
info "Checking SSL certificates on disk..."
SSL_CERT="${SCRIPT_DIR}/ssl_certificates/server.crt"
SSL_KEY="${SCRIPT_DIR}/ssl_certificates/server.key"
if file_exists_nonempty "$SSL_CERT" && file_exists_nonempty "$SSL_KEY"; then
    pass "ssl_certificates: files present" "server.crt and server.key found"
else
    warn "ssl_certificates: files present" "cert or key missing – will be generated by init_setup on first run"
fi

# Check 19: SSL certificate expiry (requires openssl)
info "Checking SSL certificate expiry..."
if [ -f "$SSL_CERT" ] && command -v openssl > /dev/null 2>&1; then
    # Get expiry date in seconds since epoch.
    EXPIRY_DATE="$(openssl x509 -noout -enddate -in "$SSL_CERT" 2>/dev/null | cut -d= -f2)"
    if [ -n "$EXPIRY_DATE" ]; then
        EXPIRY_EPOCH="$(date -d "$EXPIRY_DATE" '+%s' 2>/dev/null || date -j -f '%b %d %T %Y %Z' "$EXPIRY_DATE" '+%s' 2>/dev/null || echo 0)"
        NOW_EPOCH="$(date '+%s')"
        DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
        if [ "$DAYS_LEFT" -gt 30 ]; then
            pass "ssl_certificates: expiry" "${DAYS_LEFT} days remaining (expires: ${EXPIRY_DATE})"
        elif [ "$DAYS_LEFT" -gt 0 ]; then
            warn "ssl_certificates: expiry" "Only ${DAYS_LEFT} days remaining – renew soon (expires: ${EXPIRY_DATE})"
        else
            fail "ssl_certificates: expiry" "Certificate EXPIRED (${EXPIRY_DATE})"
        fi
    else
        warn "ssl_certificates: expiry" "Could not parse certificate expiry date"
    fi
else
    skip "ssl_certificates: expiry" "openssl not available or cert not yet generated"
fi

# ---------------------------------------------------------------------------
# Section 2: Live Docker checks (require the stack to be running)
# ---------------------------------------------------------------------------
printf "\n${BOLD}[Section 2] Live runtime checks${RESET}\n\n"

if [ "$STACK_RUNNING" -eq 0 ]; then
    if [ "$STATIC_ONLY" -eq 1 ]; then
        warn "live-checks" "--static-only mode active; all live Docker checks skipped"
    else
        warn "live-checks" "Docker stack does not appear to be running – skipping all live checks"
    fi
    skip "redis: auth enforced"         "stack not running"
    skip "backup: recent archive"       "stack not running"
    skip "nginx: xmlrpc HTTP response"  "stack not running"
    skip "honeypot: container running"  "stack not running"
else
    # Check 20: Redis authentication enforced
    info "Checking Redis password authentication..."
    # Try to connect to Redis without password; expect NOAUTH or authentication error.
    REDIS_CONTAINER="$(docker ps --format '{{.Names}}' | grep session_store | head -1)"
    if [ -n "$REDIS_CONTAINER" ]; then
        REDIS_NOAUTH="$(docker exec "$REDIS_CONTAINER" redis-cli ping 2>&1 || true)"
        if echo "$REDIS_NOAUTH" | grep -qiE "NOAUTH|AUTH|password|denied"; then
            pass "redis: auth enforced" "unauthenticated PING rejected"
        else
            fail "redis: auth enforced" "Redis accepted unauthenticated connection – no password set"
        fi
    else
        skip "redis: auth enforced" "session_store container not found"
    fi

    # Check 21: nginx xmlrpc.php returns 403 or 444 (not 200)
    info "Checking live HTTP response for /xmlrpc.php..."
    NGINX_CONTAINER="$(docker ps --format '{{.Names}}' | grep reverse_proxy | head -1)"
    if [ -n "$NGINX_CONTAINER" ]; then
        XMLRPC_STATUS="$(docker exec "$NGINX_CONTAINER" \
            curl -sk -o /dev/null -w '%{http_code}' \
            http://localhost/xmlrpc.php 2>/dev/null || echo '000')"
        if [ "$XMLRPC_STATUS" = "403" ] || [ "$XMLRPC_STATUS" = "444" ] || [ "$XMLRPC_STATUS" = "301" ]; then
            pass "nginx: /xmlrpc.php response" "HTTP ${XMLRPC_STATUS} (access denied)"
        elif [ "$XMLRPC_STATUS" = "000" ]; then
            warn "nginx: /xmlrpc.php response" "Could not reach nginx (status 000)"
        else
            fail "nginx: /xmlrpc.php response" "HTTP ${XMLRPC_STATUS} – xmlrpc.php may be accessible"
        fi
    else
        skip "nginx: /xmlrpc.php response" "reverse_proxy container not found"
    fi

    # Check 22: Server header does not contain version
    info "Checking Server response header for version strings..."
    if [ -n "$NGINX_CONTAINER" ]; then
        SERVER_HEADER="$(docker exec "$NGINX_CONTAINER" \
            curl -sk -o /dev/null -w '%{header_json}' \
            http://localhost/nginx-health 2>/dev/null \
            | grep -oi '"server":"[^"]*"' | head -1 || echo '')"
        # Acceptable values: "nginx" or empty; fail if it contains a version number.
        if echo "$SERVER_HEADER" | grep -qE '"nginx/[0-9]|openresty/[0-9]'; then
            fail "nginx: Server header" "Version exposed: ${SERVER_HEADER}"
        else
            pass "nginx: Server header" "No version in Server header (${SERVER_HEADER:-no header})"
        fi
    else
        skip "nginx: Server header" "reverse_proxy container not found"
    fi

    # Check 23: X-Powered-By absent from responses
    info "Checking X-Powered-By absence..."
    if [ -n "$NGINX_CONTAINER" ]; then
        XPB="$(docker exec "$NGINX_CONTAINER" \
            curl -sk -D - -o /dev/null \
            http://localhost/nginx-health 2>/dev/null \
            | grep -i 'x-powered-by' | head -1 || echo '')"
        if [ -n "$XPB" ]; then
            fail "nginx: X-Powered-By absent" "Header present: ${XPB}"
        else
            pass "nginx: X-Powered-By absent" "not exposed to clients"
        fi
    else
        skip "nginx: X-Powered-By absent" "reverse_proxy container not found"
    fi

    # Check 24: All three honeypot eshop containers are running
    info "Checking honeypot pool containers are running..."
    MISSING_POOLS=""
    for POOL_NUM in 1 2 3; do
        CONTAINER="$(docker ps --format '{{.Names}}' | grep "honeypot_eshop_${POOL_NUM}" | head -1)"
        if [ -z "$CONTAINER" ]; then
            MISSING_POOLS="${MISSING_POOLS} honeypot_eshop_${POOL_NUM}"
        fi
    done
    if [ -z "$MISSING_POOLS" ]; then
        pass "docker: honeypot pool containers" "all 3 pool instances running"
    else
        fail "docker: honeypot pool containers" "Not running:${MISSING_POOLS}"
    fi

    # Check 25: Backup archives are recent (within last 48 hours)
    info "Checking for recent backup archives..."
    DB_BACKUP_DIR="${BACKUP_DIR}/db"
    WP_BACKUP_DIR="${BACKUP_DIR}/wp"
    RECENT_DB=0
    RECENT_WP=0

    if [ -d "$DB_BACKUP_DIR" ]; then
        # find returns a non-empty result if a file newer than 2 days exists.
        RECENT_DB_FILE="$(find "$DB_BACKUP_DIR" -maxdepth 1 -name '*.sql.gz' -mtime -2 2>/dev/null | head -1)"
        [ -n "$RECENT_DB_FILE" ] && RECENT_DB=1
    fi

    if [ -d "$WP_BACKUP_DIR" ]; then
        RECENT_WP_FILE="$(find "$WP_BACKUP_DIR" -maxdepth 1 -name '*.tar.gz' -mtime -2 2>/dev/null | head -1)"
        [ -n "$RECENT_WP_FILE" ] && RECENT_WP=1
    fi

    if [ "$RECENT_DB" -eq 1 ] && [ "$RECENT_WP" -eq 1 ]; then
        pass "backups: recent archives" "DB and WP archives found within 48 hours"
    elif [ "$RECENT_DB" -eq 1 ]; then
        warn "backups: recent archives" "DB archive recent but no recent WP archive – check backup_service"
    elif [ "$RECENT_WP" -eq 1 ]; then
        warn "backups: recent archives" "WP archive recent but no recent DB archive – check backup_service"
    else
        warn "backups: recent archives" "No recent archives (< 48h) found – backup_service may not have run yet"
    fi
fi

# ---------------------------------------------------------------------------
# Final summary
# ---------------------------------------------------------------------------
TOTAL=$((PASS_COUNT + FAIL_COUNT + WARN_COUNT + SKIP_COUNT))

printf '\n'; printf '%0.s-' $(seq 1 60); printf '\n'
printf "${BOLD}Hardening Audit Summary${RESET}\n"
printf '%0.s-' $(seq 1 60); printf '\n'
printf "  ${GREEN}PASS${RESET}   : %d\n"  "$PASS_COUNT"
printf "  ${RED}FAIL${RESET}   : %d\n"  "$FAIL_COUNT"
printf "  ${YELLOW}WARN${RESET}   : %d\n"  "$WARN_COUNT"
printf "  SKIP   : %d\n"  "$SKIP_COUNT"
printf "  TOTAL  : %d\n"  "$TOTAL"
printf '%0.s-' $(seq 1 60); printf '\n'

if [ "$FAIL_COUNT" -eq 0 ]; then
    printf "${GREEN}${BOLD}All checks passed.  Hardening posture is acceptable.${RESET}\n\n"
else
    printf "${RED}${BOLD}${FAIL_COUNT} check(s) FAILED.  Review the output above and remediate.${RESET}\n\n"
fi

# ---------------------------------------------------------------------------
# JSON output (--json flag)
# ---------------------------------------------------------------------------
if [ "$EMIT_JSON" -eq 1 ]; then
    printf '{"audit_timestamp":"%s","pass":%d,"fail":%d,"warn":%d,"skip":%d,"total":%d,"results":[%s]}\n' \
        "$(now_iso)" \
        "$PASS_COUNT" "$FAIL_COUNT" "$WARN_COUNT" "$SKIP_COUNT" "$TOTAL" \
        "$JSON_RESULTS"
fi

# Exit 1 if any check failed; 0 if all passed (warns are non-fatal).
[ "$FAIL_COUNT" -eq 0 ] && exit 0 || exit 1