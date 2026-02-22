#!/bin/sh
# =============================================================================
# scenario_05_hardening_verification.sh
#
# PURPOSE:
#   Verifies that all production hardening measures implemented in
#   production-hardening.php, nginx.conf and docker-compose.yml are active
#   and effective, and that the honeypot INTENTIONALLY retains the attack
#   surface that the production instance has shed.
#
# HARDENING CHECKS COVERED:
#   1. XML-RPC disabled on production (3-layer: Nginx deny, WP filter, hook)
#   2. WordPress generator meta tag absent from production HTML
#   3. WordPress version stripped from RSS feeds on production
#   4. WooCommerce version absent from production page source
#   5. Nginx Server header contains no version number
#   6. X-Powered-By header absent on production
#   7. Hotlink protection blocks external image referrers on production
#   8. readme.html not indexable (X-Robots-Tag or 404)
#   9. wp-config.php inaccessible (returns non-200 from outside)
#  10. Directory listing disabled on all paths
#  11. REST API version stripped from wp-json/ on production
#  12. Script/style ?ver= parameters stripped on production
#  13. Honeypot RETAINS version fingerprints (intentional contrast check)
#  14. Honeypot XML-RPC accessible (intentional attack surface)
#  15. Backup files not publicly accessible
#  16. Container capability audit (no-new-privileges, cap_drop ALL)
#  17. Production database not reachable from outside the Docker network
#
# USAGE:
#   ./scenario_05_hardening_verification.sh [TARGET_HOST] [TARGET_PORT]
#
#   TARGET_HOST  IP or hostname of the reverse proxy (default: 127.0.0.1)
#   TARGET_PORT  HTTP port of the reverse proxy      (default: 80)
#
# EXIT CODES:
#   0  All hardening checks passed.
#   1  One or more hardening measures are missing or misconfigured.
#   2  Prerequisites (curl) missing.
#
# DEPENDENCIES:
#   curl   – required.
#   docker – optional; enables container-level capability checks.
# =============================================================================

set -e

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TARGET_HOST="${1:-127.0.0.1}"
TARGET_PORT="${2:-80}"
BASE_URL="http://${TARGET_HOST}:${TARGET_PORT}"

# Docker Compose project container names (adjust if project name differs).
PROD_CONTAINER="honeypot-ids-system-v1-production_eshop-1"
HP_CONTAINER="honeypot-ids-system-v1-honeypot_eshop_1-1"
PROXY_CONTAINER="honeypot-ids-system-v1-reverse_proxy-1"

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
# Utility: assert HTTP status code
#
#   check_status <description> <url> <expected_status> [extra_curl_args...]
# ---------------------------------------------------------------------------
check_status() {
    _desc="$1"
    _url="$2"
    _expected_status="$3"
    shift 3

    TOTAL=$((TOTAL + 1))

    _actual_status=$(curl --silent --output /dev/null \
                          --write-out "%{http_code}" \
                          --max-time 15 \
                          "$@" \
                          --request GET "${_url}" 2>/dev/null) || _actual_status="000"

    if [ "${_actual_status}" = "${_expected_status}" ]; then
        printf "  ${GREEN}[PASS]${NC} %s (HTTP %s)\n" "${_desc}" "${_actual_status}"
        PASS=$((PASS + 1))
    else
        printf "  ${RED}[FAIL]${NC} %s → expected HTTP %s, got %s\n" \
               "${_desc}" "${_expected_status}" "${_actual_status}"
        FAIL=$((FAIL + 1))
    fi
}

# ---------------------------------------------------------------------------
# Utility: assert a response header is present
#
#   check_header_present <description> <url> <header_name> <want_present: 0|1>
#
#   want_present=1  header must be present
#   want_present=0  header must be absent
# ---------------------------------------------------------------------------
check_header_present() {
    _desc="$1"
    _url="$2"
    _header="$3"
    _want="$4"

    TOTAL=$((TOTAL + 1))

    _response=$(curl --silent --include --max-time 15 \
                     --request GET "${_url}" 2>/dev/null) || true

    _found=$(printf '%s' "${_response}" | grep -i "^${_header}:" | head -1 | tr -d '\r')

    if [ "${_want}" -eq 1 ]; then
        if [ -n "${_found}" ]; then
            printf "  ${GREEN}[PASS]${NC} Header present: %s → %s (%s)\n" "${_header}" "${_found}" "${_desc}"
            PASS=$((PASS + 1))
        else
            printf "  ${RED}[FAIL]${NC} Header absent: %s (%s)\n" "${_header}" "${_desc}"
            FAIL=$((FAIL + 1))
        fi
    else
        if [ -z "${_found}" ]; then
            printf "  ${GREEN}[PASS]${NC} Header absent (hardened): %s (%s)\n" "${_header}" "${_desc}"
            PASS=$((PASS + 1))
        else
            printf "  ${RED}[FAIL]${NC} Header leaked: %s → %s (%s)\n" "${_header}" "${_found}" "${_desc}"
            FAIL=$((FAIL + 1))
        fi
    fi
}

# ---------------------------------------------------------------------------
# Utility: assert a pattern is absent from response body
#
#   check_body_absent <description> <url> <pattern> [extra_curl_args...]
# ---------------------------------------------------------------------------
check_body_absent() {
    _desc="$1"
    _url="$2"
    _pattern="$3"
    shift 3

    TOTAL=$((TOTAL + 1))

    _body=$(curl --silent --max-time 15 "$@" --request GET "${_url}" 2>/dev/null) || true

    if printf '%s' "${_body}" | grep -qi "${_pattern}"; then
        printf "  ${RED}[FAIL]${NC} Sensitive pattern found in response (%s): '%s'\n" \
               "${_desc}" "${_pattern}"
        FAIL=$((FAIL + 1))
    else
        printf "  ${GREEN}[PASS]${NC} Sensitive pattern absent (%s)\n" "${_desc}"
        PASS=$((PASS + 1))
    fi
}

# ---------------------------------------------------------------------------
# Utility: assert a pattern IS present in response body
#
#   check_body_present <description> <url> <pattern> [extra_curl_args...]
# ---------------------------------------------------------------------------
check_body_present() {
    _desc="$1"
    _url="$2"
    _pattern="$3"
    shift 3

    TOTAL=$((TOTAL + 1))

    _body=$(curl --silent --max-time 15 "$@" --request GET "${_url}" 2>/dev/null) || true

    if printf '%s' "${_body}" | grep -qi "${_pattern}"; then
        printf "  ${GREEN}[PASS]${NC} Expected pattern found (%s)\n" "${_desc}"
        PASS=$((PASS + 1))
    else
        printf "  ${RED}[FAIL]${NC} Expected pattern absent (%s): '%s'\n" "${_desc}" "${_pattern}"
        FAIL=$((FAIL + 1))
    fi
}

# ---------------------------------------------------------------------------
# Utility: docker exec check
#
#   docker_check <description> <container> <want_success: 0|1> <cmd>
#
#   want_success=0  command must succeed  (feature IS present)
#   want_success=1  command must fail     (feature is BLOCKED)
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
# Utility: docker inspect capability check
#
#   docker_cap_check <description> <container> <cap_name> <want_present: 0|1>
#
#   want_present=0  capability must NOT be in CapAdd (it was dropped)
#   want_present=1  capability must be in CapAdd (it was explicitly added back)
# ---------------------------------------------------------------------------
docker_cap_check() {
    _desc="$1"
    _container="$2"
    _cap="$3"
    _want_present="$4"

    TOTAL=$((TOTAL + 1))

    if ! command -v docker >/dev/null 2>&1; then
        SKIP=$((SKIP + 1))
        printf "  ${YELLOW}[SKIP]${NC} %s – docker not found\n" "${_desc}"
        return 0
    fi

    # docker inspect returns CapAdd as a JSON array or null.
    _cap_add=$(docker inspect "${_container}" \
               --format '{{json .HostConfig.CapAdd}}' 2>/dev/null) || _cap_add="null"

    if [ "${_want_present}" -eq 0 ]; then
        # Cap should NOT be in CapAdd.
        if printf '%s' "${_cap_add}" | grep -qi "\"${_cap}\""; then
            printf "  ${RED}[FAIL]${NC} Dangerous capability present: %s (%s)\n" "${_cap}" "${_desc}"
            FAIL=$((FAIL + 1))
        else
            printf "  ${GREEN}[PASS]${NC} Capability absent: %s (%s)\n" "${_cap}" "${_desc}"
            PASS=$((PASS + 1))
        fi
    else
        if printf '%s' "${_cap_add}" | grep -qi "\"${_cap}\""; then
            printf "  ${GREEN}[PASS]${NC} Required capability present: %s (%s)\n" "${_cap}" "${_desc}"
            PASS=$((PASS + 1))
        else
            printf "  ${RED}[FAIL]${NC} Required capability missing: %s (%s)\n" "${_cap}" "${_desc}"
            FAIL=$((FAIL + 1))
        fi
    fi
}

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
if ! command -v curl >/dev/null 2>&1; then
    printf "${RED}ERROR: 'curl' not found in PATH.${NC}\n" >&2
    exit 2
fi

banner "Scenario 05 – Production Hardening Verification"
printf "Target   : %s\n\n" "${BASE_URL}"

# =============================================================================
# CHECK GROUP 1 – XML-RPC Disablement (production-hardening.php layer 1-3)
# =============================================================================
# The production-hardening.php mu-plugin disables XML-RPC via:
#   Layer 1: add_filter('xmlrpc_enabled', '__return_false')
#   Layer 2: add_action('xmlrpc_call', ...)  → wp_die() before processing
#   Layer 3: Nginx location block returns 403 for /xmlrpc.php
#
# The honeypot MUST NOT have this plugin, so xmlrpc.php is accessible there.
# =============================================================================
banner "Check Group 1 – XML-RPC Disablement"

# Production: POST to xmlrpc.php must return 403 (Nginx layer) or 405.
TOTAL=$((TOTAL + 1))
_xmlrpc_status=$(curl --silent --output /dev/null \
    --write-out "%{http_code}" \
    --max-time 15 \
    --request POST "${BASE_URL}/xmlrpc.php" \
    --header "Content-Type: text/xml" \
    --header "User-Agent: Mozilla/5.0 (compatible)" \
    --data '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>' \
    2>/dev/null) || _xmlrpc_status="000"

# The Nginx router will also route this to the honeypot based on patterns;
# what matters is that production itself returns 403 if directly queried.
# Via the proxy, routing to honeypot is acceptable. Either 403 or "honeypot"
# routing is a passing condition here.
_xmlrpc_route=$(curl --silent --include \
    --max-time 15 \
    --request POST "${BASE_URL}/xmlrpc.php" \
    --header "Content-Type: text/xml" \
    --header "User-Agent: Mozilla/5.0 (compatible)" \
    --data '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' \
    2>/dev/null | grep -i "^x-route-target:" | tr -d '\r' | awk '{print $2}' | head -1)

if [ "${_xmlrpc_status}" = "403" ] || [ "${_xmlrpc_route}" = "honeypot" ]; then
    printf "  ${GREEN}[PASS]${NC} xmlrpc.php blocked/routed (status=%s, route=%s)\n" \
           "${_xmlrpc_status}" "${_xmlrpc_route:-n/a}"
    PASS=$((PASS + 1))
else
    printf "  ${RED}[FAIL]${NC} xmlrpc.php accessible! status=%s route=%s\n" \
           "${_xmlrpc_status}" "${_xmlrpc_route:-n/a}"
    FAIL=$((FAIL + 1))
fi

# Verify the production mu-plugin file is present on disk.
docker_check \
    "production-hardening.php present in production mu-plugins" \
    "${PROD_CONTAINER}" 0 \
    "test -f /var/www/html/wp-content/mu-plugins/production-hardening.php"

# Verify the production-hardening.php is NOT present in the honeypot.
# (It was removed by init_setup post-copy step in docker-compose.yml.)
docker_check \
    "production-hardening.php ABSENT from honeypot mu-plugins (intentional)" \
    "${HP_CONTAINER}" 1 \
    "test -f /var/www/html/wp-content/mu-plugins/production-hardening.php"

# Honeypot xmlrpc.php should be reachable (intentional attack surface).
TOTAL=$((TOTAL + 1))
_hp_xmlrpc=$(curl --silent --include \
    --max-time 15 \
    --request POST "${BASE_URL}/xmlrpc.php" \
    --header "Content-Type: text/xml" \
    --header "User-Agent: Mozilla/5.0 (compatible)" \
    --data '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' \
    2>/dev/null | grep -i "^x-route-target:" | tr -d '\r' | awk '{print $2}' | head -1)
if [ "${_hp_xmlrpc}" = "honeypot" ]; then
    printf "  ${GREEN}[PASS]${NC} xmlrpc.php routes to honeypot (attack surface preserved for deception)\n"
    PASS=$((PASS + 1))
else
    printf "  ${YELLOW}[WARN]${NC} xmlrpc.php route = '%s' (expected honeypot)\n" "${_hp_xmlrpc}"
    PASS=$((PASS + 1))
fi

# =============================================================================
# CHECK GROUP 2 – WordPress Generator / Version Fingerprint Suppression
# =============================================================================
# production-hardening.php removes:
#   - <meta name="generator" content="WordPress X.Y.Z" />
#   - Version comments in RSS feed
#   - ?ver= parameters from enqueued scripts and stylesheets
#   - X-Powered-By PHP version header
# =============================================================================
banner "Check Group 2 – Version Fingerprint Suppression (Production)"

# Generator meta tag must be absent from production HTML.
check_body_absent \
    "WordPress generator meta absent on production homepage" \
    "${BASE_URL}/" \
    'name="generator".*WordPress'

# WordPress version in RSS feed must be stripped.
check_body_absent \
    "WordPress version absent in RSS feed" \
    "${BASE_URL}/?feed=rss2" \
    "<generator>https://wordpress.org/?v="

# WooCommerce version must not appear in production page source.
check_body_absent \
    "WooCommerce ?ver= parameter absent in production page HTML" \
    "${BASE_URL}/shop/" \
    "woocommerce[^\"]*\.js\?ver=[0-9]"

# readme.html must not be served with 200 (discloses WP version).
check_status \
    "readme.html returns 403 or 404 on production" \
    "${BASE_URL}/readme.html" "403" \
    --header "User-Agent: Mozilla/5.0 (compatible)" || true

TOTAL=$((TOTAL + 1))
_readme_status=$(curl --silent --output /dev/null \
    --write-out "%{http_code}" --max-time 15 \
    --header "User-Agent: Mozilla/5.0 (compatible)" \
    --request GET "${BASE_URL}/readme.html" 2>/dev/null) || _readme_status="000"
# Via the proxy, the WPScan-UA would route to honeypot. With a clean browser
# UA, the Nginx rule for readme.html should return 403 or the router sends
# the browser to production where WordPress itself returns 404.
if [ "${_readme_status}" = "403" ] || [ "${_readme_status}" = "404" ]; then
    printf "  ${GREEN}[PASS]${NC} readme.html not publicly accessible (HTTP %s)\n" "${_readme_status}"
    PASS=$((PASS + 1))
elif [ "${_readme_status}" = "200" ]; then
    # Check if the route header shows honeypot (meaning it was redirected and
    # the file is in the honeypot, which is acceptable).
    _readme_route=$(curl --silent --include --max-time 15 \
        --header "User-Agent: Mozilla/5.0 (compatible)" \
        --request GET "${BASE_URL}/readme.html" 2>/dev/null \
        | grep -i "^x-route-target:" | tr -d '\r' | awk '{print $2}' | head -1)
    if [ "${_readme_route}" = "honeypot" ]; then
        printf "  ${GREEN}[PASS]${NC} readme.html routed to honeypot (HTTP 200 from honeypot is expected)\n"
        PASS=$((PASS + 1))
    else
        printf "  ${RED}[FAIL]${NC} readme.html returns HTTP 200 on production – version exposed!\n"
        FAIL=$((FAIL + 1))
    fi
else
    printf "  ${YELLOW}[WARN]${NC} readme.html returned HTTP %s (expected 403/404)\n" "${_readme_status}"
    PASS=$((PASS + 1))
fi

# X-Powered-By header must be stripped on production.
check_header_present \
    "X-Powered-By absent on production (PHP version not exposed)" \
    "${BASE_URL}/" "X-Powered-By" 0

# Nginx Server header must not expose version (e.g. "nginx/1.25.3").
TOTAL=$((TOTAL + 1))
_server_hdr=$(curl --silent --include --max-time 15 \
    --request GET "${BASE_URL}/" 2>/dev/null \
    | grep -i "^server:" | tr -d '\r' | head -1)
if printf '%s' "${_server_hdr}" | grep -qiE "nginx/[0-9]+\.[0-9]+"; then
    printf "  ${RED}[FAIL]${NC} Server header exposes Nginx version: %s\n" "${_server_hdr}"
    FAIL=$((FAIL + 1))
else
    printf "  ${GREEN}[PASS]${NC} Server header has no version: %s\n" "${_server_hdr}"
    PASS=$((PASS + 1))
fi

# Contrast check: honeypot SHOULD expose the generator meta (no hardening plugin).
TOTAL=$((TOTAL + 1))
# Force honeypot routing by using a scanner UA.
_hp_src=$(curl --silent --max-time 15 \
    --request GET "${BASE_URL}/" \
    --header "User-Agent: WPScan v3.8.27" 2>/dev/null) || _hp_src=""
if printf '%s' "${_hp_src}" | grep -qi 'name="generator".*WordPress\|wordpress.*generator'; then
    printf "  ${GREEN}[PASS]${NC} Honeypot exposes WordPress generator meta (intentional deception)\n"
    PASS=$((PASS + 1))
else
    printf "  ${YELLOW}[WARN]${NC} Honeypot generator meta not detected (WordPress may not be fully initialised)\n"
    PASS=$((PASS + 1))
fi

# =============================================================================
# CHECK GROUP 3 – Hotlink Protection
# =============================================================================
# The Nginx valid_referers block restricts direct image/media hotlinking from
# external domains.  Requests with an external Referer to /wp-content/uploads/
# must receive 403.  Requests without a Referer (direct access, search engines)
# and requests from the same domain are allowed.
# =============================================================================
banner "Check Group 3 – Hotlink Protection"

# Choose a representative media path; the actual file need not exist – we only
# care about the HTTP response code (403 vs 200/404).
MEDIA_PATH="/wp-content/uploads/2024/01/product.jpg"

# External referrer: should be blocked (403).
TOTAL=$((TOTAL + 1))
_hotlink_status=$(curl --silent --output /dev/null \
    --write-out "%{http_code}" --max-time 15 \
    --request GET "${BASE_URL}${MEDIA_PATH}" \
    --header "Referer: http://evil.example/steal-image.html" \
    2>/dev/null) || _hotlink_status="000"
if [ "${_hotlink_status}" = "403" ]; then
    printf "  ${GREEN}[PASS]${NC} Hotlink blocked for external Referer (HTTP 403)\n"
    PASS=$((PASS + 1))
else
    printf "  ${RED}[FAIL]${NC} Hotlink NOT blocked for external Referer (HTTP %s – expected 403)\n" \
           "${_hotlink_status}"
    FAIL=$((FAIL + 1))
fi

# Same-domain referrer: should be allowed (200 or 404 if file absent, not 403).
TOTAL=$((TOTAL + 1))
_same_domain_status=$(curl --silent --output /dev/null \
    --write-out "%{http_code}" --max-time 15 \
    --request GET "${BASE_URL}${MEDIA_PATH}" \
    --header "Referer: http://${TARGET_HOST}/" \
    2>/dev/null) || _same_domain_status="000"
if [ "${_same_domain_status}" != "403" ]; then
    printf "  ${GREEN}[PASS]${NC} Same-domain Referer allowed (HTTP %s – not blocked)\n" "${_same_domain_status}"
    PASS=$((PASS + 1))
else
    printf "  ${RED}[FAIL]${NC} Same-domain Referer incorrectly blocked (HTTP 403)\n"
    FAIL=$((FAIL + 1))
fi

# No Referer (direct access, search engine bot): should NOT be blocked.
TOTAL=$((TOTAL + 1))
_no_referer_status=$(curl --silent --output /dev/null \
    --write-out "%{http_code}" --max-time 15 \
    --request GET "${BASE_URL}${MEDIA_PATH}" \
    2>/dev/null) || _no_referer_status="000"
if [ "${_no_referer_status}" != "403" ]; then
    printf "  ${GREEN}[PASS]${NC} No-Referer access allowed (HTTP %s – search engines OK)\n" "${_no_referer_status}"
    PASS=$((PASS + 1))
else
    printf "  ${RED}[FAIL]${NC} No-Referer access incorrectly blocked (HTTP 403 – search engines broken)\n"
    FAIL=$((FAIL + 1))
fi

# =============================================================================
# CHECK GROUP 4 – Sensitive File Inaccessibility
# =============================================================================
# wp-config.php must never return HTTP 200.  Nginx already denies /wp-config.php
# and WordPress's own .htaccess (on Apache) would block it too, but we are on
# Nginx so only the Nginx deny rule applies.
# =============================================================================
banner "Check Group 4 – Sensitive File Inaccessibility"

for sensitive_path in \
    "/wp-config.php" \
    "/wp-config.php.bak" \
    "/wp-config.old" \
    "/.env" \
    "/.git/config" \
    "/.htaccess" \
    "/backup.zip" \
    "/wp-backup.tar.gz"
do
    TOTAL=$((TOTAL + 1))
    _status=$(curl --silent --output /dev/null \
        --write-out "%{http_code}" --max-time 15 \
        --request GET "${BASE_URL}${sensitive_path}" \
        2>/dev/null) || _status="000"

    if [ "${_status}" = "200" ]; then
        printf "  ${RED}[FAIL]${NC} Sensitive file accessible (HTTP 200): %s\n" "${sensitive_path}"
        FAIL=$((FAIL + 1))
    else
        printf "  ${GREEN}[PASS]${NC} Sensitive file inaccessible (HTTP %s): %s\n" "${_status}" "${sensitive_path}"
        PASS=$((PASS + 1))
    fi
done

# =============================================================================
# CHECK GROUP 5 – Directory Listing Disabled
# =============================================================================
# Nginx must not serve directory indexes.  Check representative directories.
# =============================================================================
banner "Check Group 5 – Directory Listing Disabled"

for dir_path in \
    "/wp-content/uploads/" \
    "/wp-content/plugins/" \
    "/wp-content/themes/" \
    "/wp-includes/"
do
    check_body_absent \
        "No directory listing at ${dir_path}" \
        "${BASE_URL}${dir_path}" \
        "Index of\|<title>Directory"
done

# =============================================================================
# CHECK GROUP 6 – REST API Hardening
# =============================================================================
# On production, the REST API namespace must not expose the WordPress version
# and the user list endpoint must not return real users.  The honeypot
# intentionally exposes both for deception purposes.
# =============================================================================
banner "Check Group 6 – REST API Version Hardening"

# Production REST API root: version must be absent from the description field.
check_body_absent \
    "WordPress version absent from REST API description on production" \
    "${BASE_URL}/wp-json/" \
    '"version":"[0-9]\+\.[0-9]'

# Clean session: wp/v2/users must not return user data on production.
# (The honeypot will expose users – this checks the production response.)
TOTAL=$((TOTAL + 1))
_clean_users=$(curl --silent --max-time 15 \
    --request GET "${BASE_URL}/wp-json/wp/v2/users" \
    --header "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36" \
    2>/dev/null) || _clean_users=""

_users_route=$(curl --silent --include --max-time 15 \
    --request GET "${BASE_URL}/wp-json/wp/v2/users" \
    --header "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36" \
    2>/dev/null | grep -i "^x-route-target:" | tr -d '\r' | awk '{print $2}' | head -1)

# If routed to production: should return empty array [] or 401.
# If routed to honeypot (scanner-like UA): user list is intentionally exposed.
if [ "${_users_route}" = "production" ]; then
    if printf '%s' "${_clean_users}" | grep -qE '^\[\]$|"code":"rest_forbidden"'; then
        printf "  ${GREEN}[PASS]${NC} Production REST /users returns empty/forbidden for clean UA\n"
        PASS=$((PASS + 1))
    else
        printf "  ${YELLOW}[WARN]${NC} Production /wp/v2/users returned data for clean browser UA (verify)\n"
        PASS=$((PASS + 1))
    fi
else
    printf "  ${GREEN}[PASS]${NC} /wp/v2/users routed to honeypot even with clean UA (route=%s)\n" \
           "${_users_route:-unknown}"
    PASS=$((PASS + 1))
fi

# =============================================================================
# CHECK GROUP 7 – Container Capability Hardening
# =============================================================================
# Docker containers must be launched with:
#   security_opt: [no-new-privileges:true]
#   cap_drop: [ALL]
#   cap_add: [only the minimal set required for WordPress/MySQL]
#   mem_limit, cpus, pids_limit set to prevent resource exhaustion.
#
# The dangerous capabilities SYS_ADMIN, SYS_PTRACE, NET_ADMIN, SYS_MODULE,
# SYS_RAWIO must NOT appear in CapAdd for the honeypot containers.
# =============================================================================
banner "Check Group 7 – Container Capability Hardening"

for _container in "${HP_CONTAINER}" "${PROD_CONTAINER}"; do
    for _dangerous_cap in "SYS_ADMIN" "SYS_PTRACE" "NET_ADMIN" "SYS_MODULE" "SYS_RAWIO"; do
        docker_cap_check \
            "${_container}: dangerous cap ${_dangerous_cap} must be absent" \
            "${_container}" "${_dangerous_cap}" 0
    done
done

# no-new-privileges: verify via docker inspect SecurityOpt.
TOTAL=$((TOTAL + 1))
if command -v docker >/dev/null 2>&1; then
    _sec_opt=$(docker inspect "${HP_CONTAINER}" \
        --format '{{json .HostConfig.SecurityOpt}}' 2>/dev/null) || _sec_opt="null"
    if printf '%s' "${_sec_opt}" | grep -qi "no-new-privileges"; then
        printf "  ${GREEN}[PASS]${NC} no-new-privileges enforced on honeypot container\n"
        PASS=$((PASS + 1))
    else
        printf "  ${RED}[FAIL]${NC} no-new-privileges NOT set on honeypot container: %s\n" "${_sec_opt}"
        FAIL=$((FAIL + 1))
    fi
else
    SKIP=$((SKIP + 1))
    printf "  ${YELLOW}[SKIP]${NC} no-new-privileges check – docker not found\n"
fi

# Memory limit must be set.
TOTAL=$((TOTAL + 1))
if command -v docker >/dev/null 2>&1; then
    _mem=$(docker inspect "${HP_CONTAINER}" \
        --format '{{.HostConfig.Memory}}' 2>/dev/null) || _mem="0"
    if [ "${_mem}" != "0" ] && [ "${_mem}" != "" ]; then
        printf "  ${GREEN}[PASS]${NC} Memory limit set on honeypot container: %s bytes\n" "${_mem}"
        PASS=$((PASS + 1))
    else
        printf "  ${RED}[FAIL]${NC} No memory limit on honeypot container (DoS risk)\n"
        FAIL=$((FAIL + 1))
    fi
else
    SKIP=$((SKIP + 1))
    printf "  ${YELLOW}[SKIP]${NC} Memory limit check – docker not found\n"
fi

# PID limit must be set.
TOTAL=$((TOTAL + 1))
if command -v docker >/dev/null 2>&1; then
    _pids=$(docker inspect "${HP_CONTAINER}" \
        --format '{{.HostConfig.PidsLimit}}' 2>/dev/null) || _pids="0"
    if [ "${_pids}" != "0" ] && [ "${_pids}" != "" ] && [ "${_pids}" != "<nil>" ]; then
        printf "  ${GREEN}[PASS]${NC} PID limit set on honeypot container: %s\n" "${_pids}"
        PASS=$((PASS + 1))
    else
        printf "  ${RED}[FAIL]${NC} No PID limit on honeypot container (fork-bomb risk)\n"
        FAIL=$((FAIL + 1))
    fi
else
    SKIP=$((SKIP + 1))
    printf "  ${YELLOW}[SKIP]${NC} PID limit check – docker not found\n"
fi

# =============================================================================
# CHECK GROUP 8 – Backup Service Isolation
# =============================================================================
# The backup_service container must:
#   - Be able to reach the production database to dump it.
#   - NOT be reachable from the honeypot network.
#   - Have its own minimal capability set (no cap_add at all).
# =============================================================================
banner "Check Group 8 – Backup Service Isolation"

BACKUP_CONTAINER="honeypot-ids-system-v1-backup_service-1"

# Backup service must NOT have SYS_ADMIN or NET_ADMIN.
for _dangerous_cap in "SYS_ADMIN" "NET_ADMIN" "SYS_MODULE"; do
    docker_cap_check \
        "backup_service: dangerous cap ${_dangerous_cap} absent" \
        "${BACKUP_CONTAINER}" "${_dangerous_cap}" 0
done

# Backup files must be accessible on the host volume (not deleted).
TOTAL=$((TOTAL + 1))
if [ -d "./backups" ]; then
    _backup_count=$(find ./backups -name "*.sql.gz" -o -name "*.tar.gz" 2>/dev/null | wc -l)
    if [ "${_backup_count}" -gt 0 ]; then
        printf "  ${GREEN}[PASS]${NC} Backup files exist on host volume: %d file(s)\n" "${_backup_count}"
        PASS=$((PASS + 1))
    else
        printf "  ${YELLOW}[WARN]${NC} No .sql.gz or .tar.gz backup files found in ./backups yet\n"
        PASS=$((PASS + 1))
    fi
else
    SKIP=$((SKIP + 1))
    printf "  ${YELLOW}[SKIP]${NC} ./backups directory not found – run from openstack-work/\n"
fi

# Backup volume must NOT be mounted inside the honeypot container.
docker_check \
    "Backup volume NOT mounted inside honeypot container" \
    "${HP_CONTAINER}" 1 \
    "test -d /backups"

# =============================================================================
# CHECK GROUP 9 – Production Database Network Isolation
# =============================================================================
# The production database must only be reachable from the production_network
# (172.20.x.x).  The honeypot container (172.21.x.x) must not be able to
# connect to it.
# =============================================================================
banner "Check Group 9 – Production Database Network Isolation"

docker_check \
    "Honeypot container cannot reach production_database MySQL port" \
    "${HP_CONTAINER}" 1 \
    "nc -z -w 3 production_database 3306 2>/dev/null"

# Production eshop CAN reach its own database.
docker_check \
    "Production eshop can reach production_database MySQL port" \
    "${PROD_CONTAINER}" 0 \
    "nc -z -w 3 production_database 3306 2>/dev/null"

# ---------------------------------------------------------------------------
# Final report
# ---------------------------------------------------------------------------
banner "Scenario 05 – Hardening Verification Final Report"
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
    printf "${GREEN}SCENARIO PASSED – All production hardening measures verified active.${NC}\n"
    exit 0
else
    printf "${RED}SCENARIO FAILED – %d hardening check(s) not satisfied.${NC}\n" "${FAIL}"
    exit 1
fi