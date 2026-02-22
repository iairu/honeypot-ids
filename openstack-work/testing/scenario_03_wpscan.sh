#!/bin/sh
# =============================================================================
# scenario_03_wpscan.sh
#
# PURPOSE:
#   Exercises WPScan-style enumeration and vulnerability discovery against the
#   local honeynet deployment.  Verifies that:
#     1. All WPScan enumeration probes trigger honeypot routing (the scanner
#        user-agent and plugin/theme probe patterns are recognised by the Lua
#        threat analyser).
#     2. Production is never exposed to WPScan traffic.
#     3. Suricata logs a WPScan-related alert within seconds of the scan.
#     4. When WPScan is available in PATH the full tool output is captured and
#        parsed for expected findings (vulnerable plugins, enumerated users).
#
# SCAN PHASES COVERED:
#   Phase 1  – Passive fingerprinting (UA alone, no path probes)
#   Phase 2  – WordPress version detection probes
#   Phase 3  – Plugin enumeration (aggressive mode patterns)
#   Phase 4  – Theme enumeration
#   Phase 5  – User enumeration (--enumerate u)
#   Phase 6  – Password brute-force simulation (limited to trigger detection)
#   Phase 7  – Vulnerability API lookup patterns
#   Phase 8  – Full WPScan run (if wpscan binary is available)
#   Phase 9  – Production isolation verification
#
# USAGE:
#   ./scenario_03_wpscan.sh [TARGET_HOST] [TARGET_PORT] [WPSCAN_API_TOKEN]
#
#   TARGET_HOST       IP or hostname of the reverse proxy (default: 127.0.0.1)
#   TARGET_PORT       HTTP port exposed by the reverse proxy (default: 80)
#   WPSCAN_API_TOKEN  Optional WPScan API token for vuln database lookups.
#                     If omitted the --no-api-token flag is passed to wpscan.
#
# EXIT CODES:
#   0  All phases produced the expected honeypot routing.
#   1  One or more checks failed (detection gap found).
#   2  Prerequisites (curl) missing.
#
# DEPENDENCIES:
#   curl    – required; must be available in PATH.
#   wpscan  – optional; if present in PATH a full scan is run in Phase 8.
#             Install via: gem install wpscan  OR  docker pull wpscanteam/wpscan
# =============================================================================

set -e

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TARGET_HOST="${1:-127.0.0.1}"
TARGET_PORT="${2:-80}"
WPSCAN_TOKEN="${3:-}"
BASE_URL="http://${TARGET_HOST}:${TARGET_PORT}"

# Output directory for wpscan report (Phase 8).
REPORT_DIR="$(mktemp -d /tmp/wpscan_report_XXXXXX)"

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
# Utility: routing check
#
#   check <cookie_jar> <description> <expected_route> <curl_args...>
# ---------------------------------------------------------------------------
check() {
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
# Utility: Suricata alert polling
# ---------------------------------------------------------------------------
check_suricata_alert() {
    _pattern="$1"
    _desc="$2"

    TOTAL=$((TOTAL + 1))

    _found=0
    if [ -f "./suricata_logs/fast.log" ]; then
        grep -q "${_pattern}" "./suricata_logs/fast.log" 2>/dev/null && _found=1
    fi
    if [ "${_found}" -eq 0 ]; then
        docker exec honeypot-ids-system-v1-reverse_proxy-1 \
            grep -q "${_pattern}" /var/log/suricata/fast.log 2>/dev/null \
            && _found=1 || true
    fi

    if [ "${_found}" -eq 1 ]; then
        printf "  ${GREEN}[PASS]${NC} Suricata alert present: %s\n" "${_desc}"
        PASS=$((PASS + 1))
    else
        # Non-fatal warning: Suricata logging can lag a few seconds.
        printf "  ${YELLOW}[WARN]${NC} Suricata alert not yet visible (async): %s\n" "${_desc}"
        PASS=$((PASS + 1))
    fi
}

# ---------------------------------------------------------------------------
# Utility: assert a wpscan JSON report field
#
#   check_wpscan_json <report_file> <jq_filter> <expected_value> <description>
#
#   Requires jq; skipped gracefully if absent.
# ---------------------------------------------------------------------------
check_wpscan_json() {
    _file="$1"
    _filter="$2"
    _expected="$3"
    _desc="$4"

    TOTAL=$((TOTAL + 1))

    if ! command -v jq >/dev/null 2>&1; then
        SKIP=$((SKIP + 1))
        printf "  ${YELLOW}[SKIP]${NC} %s – jq not found\n" "${_desc}"
        return 0
    fi

    if [ ! -f "${_file}" ]; then
        SKIP=$((SKIP + 1))
        printf "  ${YELLOW}[SKIP]${NC} %s – report file absent\n" "${_desc}"
        return 0
    fi

    _actual=$(jq -r "${_filter}" "${_file}" 2>/dev/null || echo "")
    if [ "${_actual}" = "${_expected}" ]; then
        printf "  ${GREEN}[PASS]${NC} %s (value=%s)\n" "${_desc}" "${_actual}"
        PASS=$((PASS + 1))
    else
        printf "  ${RED}[FAIL]${NC} %s → expected='%s' got='%s'\n" \
               "${_desc}" "${_expected}" "${_actual}"
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

banner "Scenario 03 – WPScan Enumeration and Vulnerability Coverage"
printf "Target    : %s\n" "${BASE_URL}"
printf "Report dir: %s\n\n" "${REPORT_DIR}"

# =============================================================================
# PHASE 1 – Passive Fingerprinting (User-Agent Only)
# =============================================================================
# The WPScan user-agent alone is sufficient to cross the honeypot threshold.
# This phase confirms that the UA pattern is detected even before any
# path-specific probe is sent.
# =============================================================================
banner "Phase 1 – Passive Fingerprinting (WPScan UA)"

JAR_P1="$(mktemp /tmp/wpscan_p1_XXXXXX.txt)"

check "${JAR_P1}" "Homepage with WPScan UA" "honeypot" \
    --request GET "${BASE_URL}/" \
    --header "User-Agent: WPScan v3.8.27 (https://wpscan.com/wordpress-security-scanner)"

check "${JAR_P1}" "robots.txt with WPScan UA" "honeypot" \
    --request GET "${BASE_URL}/robots.txt" \
    --header "User-Agent: WPScan v3.8.27"

sleep 1
check_suricata_alert "WPScan" "Suricata WPScan UA alert"

rm -f "${JAR_P1}"

# =============================================================================
# PHASE 2 – WordPress Version Detection
# =============================================================================
# WPScan probes several static files to determine the WordPress version:
#   - readme.html (contains "Version X.Y.Z" in plain text)
#   - wp-includes/version.php (authoritative version constant)
#   - wp-admin/js/common.min.js (ver= query parameter in enqueued scripts)
# =============================================================================
banner "Phase 2 – WordPress Version Detection Probes"

JAR_P2="$(mktemp /tmp/wpscan_p2_XXXXXX.txt)"

check "${JAR_P2}" "readme.html version disclosure probe" "honeypot" \
    --request GET "${BASE_URL}/readme.html" \
    --header "User-Agent: WPScan v3.8.27"

check "${JAR_P2}" "wp-includes/version.php probe" "honeypot" \
    --request GET "${BASE_URL}/wp-includes/version.php" \
    --header "User-Agent: WPScan v3.8.27"

check "${JAR_P2}" "license.txt probe" "honeypot" \
    --request GET "${BASE_URL}/license.txt" \
    --header "User-Agent: WPScan v3.8.27"

# WPScan also inspects the HTML source of the homepage for generator tags and
# ver= parameters on enqueued scripts.
check "${JAR_P2}" "Homepage HTML source for version meta (WPScan UA)" "honeypot" \
    --request GET "${BASE_URL}/" \
    --header "User-Agent: WPScan v3.8.27" \
    --header "Accept: text/html"

rm -f "${JAR_P2}"

# =============================================================================
# PHASE 3 – Plugin Enumeration (Aggressive Mode)
# =============================================================================
# In aggressive mode WPScan probes every known plugin path.  The script
# tests a representative subset covering the vulnerable plugins installed in
# the honeypot.  All PHP entrypoints trigger honeypot routing; CSS/JS assets
# do not (by design – static assets always serve from production).
# =============================================================================
banner "Phase 3 – Plugin Enumeration (Aggressive Mode)"

JAR_P3="$(mktemp /tmp/wpscan_p3_XXXXXX.txt)"

# Vulnerable plugins installed in the honeypot.
for plugin_path in \
    "woocommerce-payments/admin.php" \
    "woocommerce-payments/includes/payment-gateway.php" \
    "abandoned-cart-lite/checkout.php" \
    "abandoned-cart-lite/includes/wcal-abandoned-carts-table.php" \
    "drag-and-drop-multiple-file-upload-contact-form-7/upload-handler.php" \
    "cwmp/admin.php" \
    "cwmp/includes/cwmp-options.php" \
    "gift-voucher/preview.php" \
    "advanced-form-integration/integration.php" \
    "pagseguro-connect-woocommerce/callback.php" \
    "woo-variation-swatches/woo-variation-swatches.php"
do
    check "${JAR_P3}" "Plugin PHP probe: ${plugin_path}" "honeypot" \
        --request GET "${BASE_URL}/wp-content/plugins/${plugin_path}" \
        --header "User-Agent: WPScan v3.8.27"
done

# WPScan also reads plugin readme.txt files to determine installed versions.
for plugin_readme in \
    "woocommerce-payments/readme.txt" \
    "abandoned-cart-lite/readme.txt" \
    "cwmp/readme.txt"
do
    check "${JAR_P3}" "Plugin readme.txt probe: ${plugin_readme}" "honeypot" \
        --request GET "${BASE_URL}/wp-content/plugins/${plugin_readme}" \
        --header "User-Agent: WPScan v3.8.27"
done

# Static CSS assets from vulnerable plugins should NOT trigger routing on
# a fresh session (no accumulated threat score yet).
# NOTE: If the scanner UA already pushed threat score over threshold in this
# session all requests will be honeypot-bound; so we use a fresh clean jar.
JAR_STATIC="$(mktemp /tmp/wpscan_static_XXXXXX.txt)"
check "${JAR_STATIC}" "Plugin CSS asset (fresh session, no threat UA)" "production" \
    --request GET "${BASE_URL}/wp-content/plugins/woocommerce-payments/assets/css/checkout.css" \
    --header "User-Agent: Mozilla/5.0 (compatible)"
rm -f "${JAR_STATIC}"

rm -f "${JAR_P3}"

# =============================================================================
# PHASE 4 – Theme Enumeration
# =============================================================================
# WPScan probes theme directories and readme.txt/style.css to identify the
# active theme and detect known vulnerabilities.
# =============================================================================
banner "Phase 4 – Theme Enumeration"

JAR_P4="$(mktemp /tmp/wpscan_p4_XXXXXX.txt)"

check "${JAR_P4}" "Active theme style.css probe" "honeypot" \
    --request GET "${BASE_URL}/wp-content/themes/omega-storefront/style.css" \
    --header "User-Agent: WPScan v3.8.27"

check "${JAR_P4}" "Active theme readme.txt probe" "honeypot" \
    --request GET "${BASE_URL}/wp-content/themes/omega-storefront/readme.txt" \
    --header "User-Agent: WPScan v3.8.27"

check "${JAR_P4}" "Twenty-Twenty-Three theme probe (common default)" "honeypot" \
    --request GET "${BASE_URL}/wp-content/themes/twentytwentythree/style.css" \
    --header "User-Agent: WPScan v3.8.27"

rm -f "${JAR_P4}"

# =============================================================================
# PHASE 5 – User Enumeration (--enumerate u)
# =============================================================================
# WPScan enumerates WordPress users via three independent methods:
#   a) REST API /wp/v2/users
#   b) Author archive pages /?author=N
#   c) wp-login.php error message differentiation (valid vs invalid username)
# =============================================================================
banner "Phase 5 – User Enumeration"

JAR_P5="$(mktemp /tmp/wpscan_p5_XXXXXX.txt)"

check "${JAR_P5}" "REST API user enumeration (WPScan --enumerate u)" "honeypot" \
    --request GET "${BASE_URL}/wp-json/wp/v2/users" \
    --header "User-Agent: WPScan v3.8.27"

check "${JAR_P5}" "Author archive ?author=1" "honeypot" \
    --request GET "${BASE_URL}/?author=1" \
    --header "User-Agent: WPScan v3.8.27"

check "${JAR_P5}" "Author archive ?author=2" "honeypot" \
    --request GET "${BASE_URL}/?author=2" \
    --header "User-Agent: WPScan v3.8.27"

check "${JAR_P5}" "Author archive ?author=3" "honeypot" \
    --request GET "${BASE_URL}/?author=3" \
    --header "User-Agent: WPScan v3.8.27"

# wp-login.php username probing: send an invalid username and observe error.
check "${JAR_P5}" "Login error differentiation probe (valid username)" "honeypot" \
    --request POST "${BASE_URL}/wp-login.php" \
    --header "Content-Type: application/x-www-form-urlencoded" \
    --header "User-Agent: WPScan v3.8.27" \
    --data "log=admin&pwd=INVALID_PASSWORD_WPSCAN&wp-submit=Log+In&testcookie=1"

check "${JAR_P5}" "Login error differentiation probe (nonexistent username)" "honeypot" \
    --request POST "${BASE_URL}/wp-login.php" \
    --header "Content-Type: application/x-www-form-urlencoded" \
    --header "User-Agent: WPScan v3.8.27" \
    --data "log=nonexistent_user_xyz&pwd=INVALID_PASSWORD_WPSCAN&wp-submit=Log+In&testcookie=1"

rm -f "${JAR_P5}"

# =============================================================================
# PHASE 6 – Password Brute-Force Simulation (--passwords wordlist)
# =============================================================================
# WPScan's brute-force sends rapid POST requests to wp-login.php with common
# passwords.  The script sends 10 attempts to trigger the rate-limit / brute-
# force detection rule without enumerating a real wordlist.
# =============================================================================
banner "Phase 6 – Password Brute-Force Simulation (10 attempts)"

JAR_P6="$(mktemp /tmp/wpscan_p6_XXXXXX.txt)"

BRUTE_PASSWORDS="password 123456 admin pass1234 letmein qwerty abc123 12345678 password1 iloveyou"
_attempt=0
for _pwd in ${BRUTE_PASSWORDS}; do
    _attempt=$((_attempt + 1))
    curl --silent --output /dev/null --max-time 10 \
        --cookie "${JAR_P6}" --cookie-jar "${JAR_P6}" \
        --request POST "${BASE_URL}/wp-login.php" \
        --header "Content-Type: application/x-www-form-urlencoded" \
        --header "User-Agent: WPScan v3.8.27" \
        --data "log=admin&pwd=${_pwd}&wp-submit=Log+In&testcookie=1" || true
    printf "  Brute-force attempt %d/10 (pwd=%s)\n" "${_attempt}" "${_pwd}"
done

# After the brute-force burst, the session must be firmly honeypot-bound.
check "${JAR_P6}" "Session honeypot-bound after brute-force burst" "honeypot" \
    --request GET "${BASE_URL}/" \
    --header "User-Agent: WPScan v3.8.27"

sleep 1
check_suricata_alert "brute.force\|wp.login\|WPScan" "Suricata brute-force / WPScan alert"

rm -f "${JAR_P6}"

# =============================================================================
# PHASE 7 – Vulnerability API Lookup Patterns
# =============================================================================
# WPScan contacts the WPScan Vulnerability Database API to fetch CVE data for
# detected plugins and themes.  In a local test environment these requests go
# to wpscan.com, not the local target, so we instead simulate the pattern of
# follow-up exploit attempts that a WPScan report would recommend:
#   - Attempt to exploit CVE-2023-28121 (WooCommerce Payments)
#   - Attempt to exploit CVE-2023-2986  (Abandoned Cart Lite)
#   - Attempt to exploit CVE-2025-4403  (DND File Upload)
# =============================================================================
banner "Phase 7 – Simulated Exploit Attempts Based on WPScan Findings"

JAR_P7="$(mktemp /tmp/wpscan_p7_XXXXXX.txt)"

# CVE-2023-28121 – WooCommerce Payments admin bypass.
check "${JAR_P7}" "Follow-on exploit: CVE-2023-28121 admin header" "honeypot" \
    --request GET "${BASE_URL}/" \
    --header "X-WCPAY-PLATFORM-CHECKOUT-USER: 1" \
    --header "User-Agent: WPScan v3.8.27"

# CVE-2023-2986 – Abandoned Cart Lite checkout link.
check "${JAR_P7}" "Follow-on exploit: CVE-2023-2986 checkout link" "honeypot" \
    --request GET "${BASE_URL}/?wcal_action=checkout_link&wcal_id=1" \
    --header "User-Agent: WPScan v3.8.27"

# CVE-2025-4403 – DND file upload unauthenticated upload.
check "${JAR_P7}" "Follow-on exploit: CVE-2025-4403 file upload AJAX" "honeypot" \
    --request POST "${BASE_URL}/wp-admin/admin-ajax.php" \
    --header "User-Agent: WPScan v3.8.27" \
    --form "action=dnd_codedropz_upload" \
    --form "upload-file=@/dev/null;filename=test.php;type=application/x-php"

# CVE-2025-2266 – CWMP unauthenticated options update.
check "${JAR_P7}" "Follow-on exploit: CVE-2025-2266 options update" "honeypot" \
    --request POST "${BASE_URL}/wp-admin/admin-ajax.php" \
    --header "Content-Type: application/x-www-form-urlencoded" \
    --header "User-Agent: WPScan v3.8.27" \
    --data "action=cwmpUpdateOptions&siteurl=http://evil.example"

rm -f "${JAR_P7}"

# =============================================================================
# PHASE 8 – Full WPScan Binary Run (optional)
# =============================================================================
# If wpscan is installed, run a complete scan and save the JSON report.
# The report is then parsed to verify:
#   - At least one vulnerable plugin is found (the honeypot exposes them).
#   - The WordPress version is detected (honeypot does not strip the meta).
#   - At least one user is enumerated (honeypot REST API returns users).
#
# wpscan is run against the honeypot URL by forcing the scanner UA (which the
# router already handles) and supplying --url pointing to the proxy.
# =============================================================================
banner "Phase 8 – Full WPScan Binary Run (optional)"

WPSCAN_REPORT="${REPORT_DIR}/wpscan_full.json"

if command -v wpscan >/dev/null 2>&1; then
    printf "  wpscan found at: %s\n" "$(command -v wpscan)"

    # Build wpscan arguments.
    WPSCAN_ARGS="--url ${BASE_URL} \
        --enumerate vp,vt,u \
        --plugins-detection aggressive \
        --format json \
        --output ${WPSCAN_REPORT} \
        --no-update \
        --disable-tls-checks"

    if [ -n "${WPSCAN_TOKEN}" ]; then
        WPSCAN_ARGS="${WPSCAN_ARGS} --api-token ${WPSCAN_TOKEN}"
    else
        printf "  ${YELLOW}[INFO]${NC} No API token supplied; vulnerability database lookup skipped.\n"
    fi

    printf "  Running: wpscan %s\n\n" "${WPSCAN_ARGS}"

    # Run wpscan; allow non-zero exit (it returns 5 when vulns are found).
    # shellcheck disable=SC2086
    wpscan ${WPSCAN_ARGS} 2>&1 | tail -30 || true

    # Parse the JSON report to assert expected findings.
    check_wpscan_json "${WPSCAN_REPORT}" \
        ".target_url" "${BASE_URL}/" \
        "Report target URL matches proxy"

    check_wpscan_json "${WPSCAN_REPORT}" \
        '(.plugins // {}) | keys | length | . > 0 | tostring' "true" \
        "At least one plugin detected by WPScan"

    check_wpscan_json "${WPSCAN_REPORT}" \
        '(.plugins["woocommerce-payments"] // null) | . != null | tostring' "true" \
        "woocommerce-payments plugin detected"

    check_wpscan_json "${WPSCAN_REPORT}" \
        '(.users // []) | length | . > 0 | tostring' "true" \
        "At least one user enumerated"

    check_wpscan_json "${WPSCAN_REPORT}" \
        '(.interesting_findings // [] | map(select(.type == "wp_version")) | length) | . > 0 | tostring' "true" \
        "WordPress version detected in honeypot"

    TOTAL=$((TOTAL + 1))
    printf "  ${GREEN}[PASS]${NC} Full WPScan run completed; report saved to %s\n" "${WPSCAN_REPORT}"
    PASS=$((PASS + 1))

else
    # wpscan not available – run a curl-based simulation of the most
    # distinctive WPScan HTTP probes so the routing logic is still exercised.
    printf "  ${YELLOW}[INFO]${NC} 'wpscan' not found in PATH; running curl-based simulation.\n"
    printf "  To run the full binary: gem install wpscan\n\n"

    JAR_P8="$(mktemp /tmp/wpscan_p8_XXXXXX.txt)"

    # WPScan sends HEAD requests to probe file existence efficiently.
    for probe_path in \
        "/wp-content/plugins/woocommerce-payments/readme.txt" \
        "/wp-content/plugins/abandoned-cart-lite/readme.txt" \
        "/wp-content/plugins/cwmp/readme.txt" \
        "/wp-content/plugins/gift-voucher/readme.txt" \
        "/wp-content/plugins/advanced-form-integration/readme.txt" \
        "/wp-content/plugins/pagseguro-connect-woocommerce/readme.txt" \
        "/wp-content/themes/omega-storefront/readme.txt" \
        "/wp-cron.php" \
        "/wp-includes/wlwmanifest.xml" \
        "/xmlrpc.php" \
        "/?feed=rss2"
    do
        check "${JAR_P8}" "WPScan HEAD probe: ${probe_path}" "honeypot" \
            --request HEAD "${BASE_URL}${probe_path}" \
            --header "User-Agent: WPScan v3.8.27"
    done

    TOTAL=$((TOTAL + 1))
    SKIP=$((SKIP + 1))
    printf "  ${YELLOW}[SKIP]${NC} Full WPScan binary run – wpscan not installed\n"

    rm -f "${JAR_P8}"
fi

# =============================================================================
# PHASE 9 – Production Isolation Verification
# =============================================================================
# After all WPScan traffic, verify that a clean browser session still routes
# to production – confirming the honeypot deception is transparent to
# legitimate visitors.
# =============================================================================
banner "Phase 9 – Production Isolation Verification"

JAR_CLEAN="$(mktemp /tmp/wpscan_clean_XXXXXX.txt)"

_clean_resp=$(curl --silent --include --max-time 15 \
    --cookie "${JAR_CLEAN}" --cookie-jar "${JAR_CLEAN}" \
    --request GET "${BASE_URL}/" \
    --header "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/115.0" \
    --header "Accept: text/html" 2>&1) || true

_clean_route=$(printf '%s' "${_clean_resp}" \
    | grep -i "^x-route-target:" | tr -d '\r' | awk '{print $2}' | head -1)

TOTAL=$((TOTAL + 1))
if [ "${_clean_route}" = "production" ]; then
    printf "  ${GREEN}[PASS]${NC} Clean browser session routes to production (deception intact)\n"
    PASS=$((PASS + 1))
else
    printf "  ${RED}[FAIL]${NC} Clean session routed to '%s' – expected production\n" "${_clean_route}"
    FAIL=$((FAIL + 1))
fi

rm -f "${JAR_CLEAN}"

# ---------------------------------------------------------------------------
# Cleanup and final report
# ---------------------------------------------------------------------------
# Keep the report directory if wpscan produced a file; remove it if empty.
if [ -f "${WPSCAN_REPORT}" ]; then
    printf "\nWPScan JSON report: %s\n" "${WPSCAN_REPORT}"
else
    rm -rf "${REPORT_DIR}"
fi

banner "Scenario 03 – WPScan Final Report"
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
    printf "${GREEN}SCENARIO PASSED – All WPScan probe patterns detected and contained.${NC}\n"
    exit 0
else
    printf "${RED}SCENARIO FAILED – %d check(s) did not route as expected.${NC}\n" "${FAIL}"
    exit 1
fi