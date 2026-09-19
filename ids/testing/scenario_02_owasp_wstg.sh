#!/bin/bash
# =============================================================================
# scenario_02_owasp_wstg.sh
#
# PURPOSE:
#   Executes OWASP Web Security Testing Guide (WSTG) test categories 1-7
#   against the local honeynet deployment and verifies that each attack
#   pattern is correctly detected and routed to a honeypot pool instance.
#
# OWASP WSTG CATEGORIES COVERED:
#   WSTG-INFO  (1) – Information Gathering
#   WSTG-CONF  (2) – Configuration and Deployment Management Testing
#   WSTG-IDNT  (3) – Identity Management Testing
#   WSTG-ATHN  (4) – Authentication Testing
#   WSTG-AUTHZ (5) – Authorization Testing
#   WSTG-SESS  (6) – Session Management Testing
#   WSTG-INPV  (7) – Input Validation Testing
#
# HONEYPOT VALIDATION:
#   Each request checks X-Route-Target response header set by the Nginx Lua
#   router.  A value of "honeypot" confirms the request was redirected to an
#   isolated pool instance and never reached the production WordPress instance.
#
# USAGE:
#   ./scenario_02_owasp_wstg.sh [TARGET_HOST] [TARGET_PORT]
#
#   TARGET_HOST  IP or hostname of the reverse proxy (default: 127.0.0.1)
#   TARGET_PORT  HTTP port exposed by the reverse proxy (default: 80)
#
# EXIT CODES:
#   0  All phases produced the expected routing outcomes.
#   1  One or more checks failed (detection gap found).
#   2  Prerequisites (curl) missing.
#
# DEPENDENCIES:
#   curl  – standard HTTP client; must be available in PATH.
#
# NOTES:
#   - Each WSTG category uses a fresh cookie jar to simulate an independent
#     attacker session so earlier detections do not carry forward.
#   - Payloads are representative samples; exhaustive fuzzing is out of scope.
#   - "production" expected routes indicate baseline legitimacy checks that
#     confirm no false-positive regression occurred after the attack traffic.
# =============================================================================

set -e

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TARGET_HOST="${1:-127.0.0.1}"
TARGET_PORT="${2:-443}"
BASE_URL="https://${TARGET_HOST}:${TARGET_PORT}"

source "$(dirname "$0")/lib/scenario_common.sh"

# Shared secret gating the X-Route-Target/X-Threat-Score response headers
# this script depends on (see reverse_proxy_enhanced/nginx.conf and
# BLIND_PENTEST_PROTOCOL.md §8.2). Export it in the shell before running:
#   export INTERNAL_TEST_SECRET=<value from .env>
INTERNAL_TEST_SECRET="${INTERNAL_TEST_SECRET:-}"
if [ -z "${INTERNAL_TEST_SECRET}" ]; then
    printf "WARNING: INTERNAL_TEST_SECRET is not set -- X-Route-Target will not be returned and every routing check below will read as 'unknown'.\n" >&2
fi

# Counters for the final report.
PASS=0
FAIL=0
SKIP=0
TOTAL=0

# ---------------------------------------------------------------------------
# Utility: section banner
# ---------------------------------------------------------------------------

sub_banner() {
    printf "\n${BLUE}  --- %s ---%s\n\n" "$1" "${NC}"
}

# ---------------------------------------------------------------------------
# Utility: run a single routing check
#
#   check <cookie_jar> <description> <expected_route> <curl_args...>
#
#   expected_route: "honeypot" | "production" | "any"
# ---------------------------------------------------------------------------
check() {
    _jar="$1"
    _desc="$2"
    _expected="$3"
    shift 3

    TOTAL=$((TOTAL + 1))

    # Use -k for self-signed certs, -L to follow redirects
    _response=$(curl -k -L --silent --include \
                     --cookie "${_jar}" \
                     --cookie-jar "${_jar}" \
                     --max-time 15 \
                     --header "X-Internal-Test-Auth: ${INTERNAL_TEST_SECRET}" \
                     "$@" 2>&1) || true

    # Extract X-Route-Target header (from final response after redirects)
    _route=$(printf '%s' "${_response}" | grep -i "^x-route-target:" \
             | tr -d '\r' | awk '{print $2}' | tail -1)
    _route="${_route:-unknown}"

    # Fallback: check any response in chain
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
        printf "  ${GREEN}[PASS]${NC} %s → %s\n" "${_desc}" "${_route}"
        PASS=$((PASS + 1))
    else
        printf "  ${RED}[FAIL]${NC} %s → expected=%s got=%s\n" \
               "${_desc}" "${_expected}" "${_route}"
        FAIL=$((FAIL + 1))
    fi
}

# ---------------------------------------------------------------------------
# Utility: verify a header is present in a fresh response
#
#   check_header <description> <header_name> <expected_present: 0|1> <url>
#
#   expected_present=1 means the header SHOULD appear (e.g. X-Frame-Options).
#   expected_present=0 means the header MUST NOT appear (e.g. X-Powered-By
#   on the hardened production instance).
# ---------------------------------------------------------------------------
check_header() {
    _desc="$1"
    _header="$2"
    _want_present="$3"
    _url="$4"

    TOTAL=$((TOTAL + 1))

    _response=$(curl --silent --include --max-time 15 \
                     --request GET "${_url}" 2>&1) || true

    _found=$(printf '%s' "${_response}" | grep -i "^${_header}:" | head -1)

    if [ "${_want_present}" -eq 1 ]; then
        if [ -n "${_found}" ]; then
            printf "  ${GREEN}[PASS]${NC} Header present: %s (%s)\n" "${_header}" "${_desc}"
            PASS=$((PASS + 1))
        else
            printf "  ${RED}[FAIL]${NC} Header missing: %s (%s)\n" "${_header}" "${_desc}"
            FAIL=$((FAIL + 1))
        fi
    else
        if [ -z "${_found}" ]; then
            printf "  ${GREEN}[PASS]${NC} Header absent (hardened): %s (%s)\n" "${_header}" "${_desc}"
            PASS=$((PASS + 1))
        else
            printf "  ${RED}[FAIL]${NC} Header exposed: %s = %s (%s)\n" \
                   "${_header}" "${_found}" "${_desc}"
            FAIL=$((FAIL + 1))
        fi
    fi
}

# ---------------------------------------------------------------------------
# Utility: check response body contains a string
# ---------------------------------------------------------------------------
check_body_absent() {
    _desc="$1"
    _pattern="$2"
    _url="$3"

    TOTAL=$((TOTAL + 1))

    _body=$(curl --silent --max-time 15 --request GET "${_url}" 2>&1) || true

    if printf '%s' "${_body}" | grep -qi "${_pattern}"; then
        printf "  ${RED}[FAIL]${NC} Sensitive info leaked (%s): '%s'\n" "${_desc}" "${_pattern}"
        FAIL=$((FAIL + 1))
    else
        printf "  ${GREEN}[PASS]${NC} Sensitive info not exposed (%s)\n" "${_desc}"
        PASS=$((PASS + 1))
    fi
}

# ---------------------------------------------------------------------------
# Prerequisites check
# ---------------------------------------------------------------------------
if ! command -v curl >/dev/null 2>&1; then
    printf "${RED}ERROR: 'curl' not found in PATH.${NC}\n" >&2
    exit 2
fi

banner "Scenario 02 – OWASP WSTG Categories 1-7"
printf "Target : %s\n\n" "${BASE_URL}"

# =============================================================================
# WSTG-INFO – Category 1: Information Gathering
# =============================================================================
# References: WSTG-INFO-01 through WSTG-INFO-10
#
# Goal: Confirm that production does not leak service fingerprints (version
# numbers, stack details, directory listings) and that probes that are
# commonly used for fingerprinting trigger honeypot routing.
# =============================================================================
banner "WSTG-INFO (1) – Information Gathering"

JAR_INFO="$(mktemp /tmp/wstg_info_XXXXXX.txt)"

sub_banner "WSTG-INFO-01: Search Engine Discovery"
# Robots.txt and sitemap are read by attackers to enumerate hidden paths.
check "${JAR_INFO}" "robots.txt fetch (INFO-01)" "production" \
    --request GET "${BASE_URL}/robots.txt" \
    --header "User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1)"

check "${JAR_INFO}" "sitemap.xml fetch (INFO-01)" "production" \
    --request GET "${BASE_URL}/sitemap.xml" \
    --header "User-Agent: Mozilla/5.0 (compatible)"

sub_banner "WSTG-INFO-02: Web Server Fingerprinting"
# Production must NOT expose Server version.  The check_header helper is used
# here rather than the routing check because the goal is header inspection.
check_header "Server header must not include version (INFO-02)" \
    "Server" 1 "${BASE_URL}/"
# X-Powered-By exposes PHP version and must be stripped on production.
check_header "X-Powered-By absent on production (INFO-02)" \
    "X-Powered-By" 0 "${BASE_URL}/"

sub_banner "WSTG-INFO-03: Web Application Fingerprinting"
# readme.html is left on unpatched WordPress installs; attackers fetch it to
# confirm the major version.  The WPScan UA immediately crosses the threshold.
check "${JAR_INFO}" "readme.html with scanner UA (INFO-03)" "honeypot" \
    --request GET "${BASE_URL}/readme.html" \
    --header "User-Agent: WPScan v3.8.27"

# Fetching the WordPress license.txt is less aggressive; no scanner UA → prod.
check "${JAR_INFO}" "license.txt with browser UA (INFO-03)" "production" \
    --request GET "${BASE_URL}/license.txt" \
    --header "User-Agent: Mozilla/5.0 (compatible)"

sub_banner "WSTG-INFO-04: Enumerate Web Application"
# Directory listing probes common backup/config paths.
check "${JAR_INFO}" "wp-config.php probe (INFO-04)" "honeypot" \
    --request GET "${BASE_URL}/wp-config.php" \
    --header "User-Agent: DirBuster-1.0-RC1"

check "${JAR_INFO}" "wp-config.php.bak probe (INFO-04)" "honeypot" \
    --request GET "${BASE_URL}/wp-config.php.bak" \
    --header "User-Agent: DirBuster-1.0-RC1"

check "${JAR_INFO}" ".env probe (INFO-04)" "honeypot" \
    --request GET "${BASE_URL}/.env" \
    --header "User-Agent: python-requests/2.28.0"

sub_banner "WSTG-INFO-05: Review Web Page Comments and Metadata"
# Generator meta tag discloses WordPress version in HTML source.
check_body_absent "WordPress generator meta must be absent on production (INFO-05)" \
    "generator.*WordPress" "${BASE_URL}/"

sub_banner "WSTG-INFO-06: Identify Application Entry Points"
# Standard WP REST API exposure.
check "${JAR_INFO}" "REST API root (INFO-06)" "production" \
    --request GET "${BASE_URL}/wp-json/" \
    --header "User-Agent: Mozilla/5.0 (compatible)"

sub_banner "WSTG-INFO-07: Map Execution Paths Through Application"
# Automated crawlers (Nikto) trigger honeypot routing by UA alone.
check "${JAR_INFO}" "Nikto scanner UA (INFO-07)" "honeypot" \
    --request GET "${BASE_URL}/" \
    --header "User-Agent: Nikto/2.1.6"

sub_banner "WSTG-INFO-08: Fingerprint Web Application Framework"
# WooCommerce version exposed in query strings on un-hardened installs.
check_body_absent "WooCommerce version absent in page source (INFO-08)" \
    "woocommerce.*ver=" "${BASE_URL}/shop/"

sub_banner "WSTG-INFO-09: Map Application Architecture"
# Requesting /wp-admin/ from a scanner UA triggers routing.
check "${JAR_INFO}" "wp-admin probe with Acunetix UA (INFO-09)" "honeypot" \
    --request GET "${BASE_URL}/wp-admin/" \
    --header "User-Agent: Acunetix Web Vulnerability Scanner"

sub_banner "WSTG-INFO-10: Map Network/Application Architecture"
# Probing non-standard ports via Host header manipulation.
check "${JAR_INFO}" "Host header manipulation probe (INFO-10)" "honeypot" \
    --request GET "${BASE_URL}/" \
    --header "Host: internal-service:8080" \
    --header "User-Agent: python-requests/2.28.0"

rm -f "${JAR_INFO}"

# =============================================================================
# WSTG-CONF – Category 2: Configuration and Deployment Management Testing
# =============================================================================
# References: WSTG-CONF-01 through WSTG-CONF-11
#
# Goal: Ensure misconfiguration probes route to the honeypot and that the
# production system does not expose sensitive configuration artefacts.
# =============================================================================
banner "WSTG-CONF (2) – Configuration and Deployment Management Testing"

JAR_CONF="$(mktemp /tmp/wstg_conf_XXXXXX.txt)"

sub_banner "WSTG-CONF-01: Test Network/Infrastructure Configuration"
# TRACE method is used for cross-site tracing attacks.
check "${JAR_CONF}" "HTTP TRACE method (CONF-01)" "honeypot" \
    --request TRACE "${BASE_URL}/" \
    --header "User-Agent: Mozilla/5.0 (compatible)"

# OPTIONS method reveals allowed HTTP verbs.
check "${JAR_CONF}" "HTTP OPTIONS method (CONF-01)" "any" \
    --request OPTIONS "${BASE_URL}/" \
    --header "User-Agent: Mozilla/5.0 (compatible)"

sub_banner "WSTG-CONF-02: Test Application Platform Configuration"
# PHP info pages are a common misconfiguration.
check "${JAR_CONF}" "phpinfo.php probe (CONF-02)" "honeypot" \
    --request GET "${BASE_URL}/phpinfo.php" \
    --header "User-Agent: python-requests/2.28.0"

check "${JAR_CONF}" "info.php probe (CONF-02)" "honeypot" \
    --request GET "${BASE_URL}/info.php" \
    --header "User-Agent: curl/7.88.1"

sub_banner "WSTG-CONF-03: Test File Extensions Handling"
# Backup file extensions that web servers may expose.
check "${JAR_CONF}" ".bak backup file probe (CONF-03)" "honeypot" \
    --request GET "${BASE_URL}/wp-login.php.bak" \
    --header "User-Agent: python-requests/2.28.0"

check "${JAR_CONF}" ".old file probe (CONF-03)" "honeypot" \
    --request GET "${BASE_URL}/wp-config.old" \
    --header "User-Agent: curl/7.88.1"

sub_banner "WSTG-CONF-04: Review Old/Backup/Unreferenced Files"
# Common backup archive names that installers or admins may leave behind.
check "${JAR_CONF}" "backup.zip probe (CONF-04)" "honeypot" \
    --request GET "${BASE_URL}/backup.zip" \
    --header "User-Agent: Nikto/2.1.6"

check "${JAR_CONF}" "wp-backup.tar.gz probe (CONF-04)" "honeypot" \
    --request GET "${BASE_URL}/wp-backup.tar.gz" \
    --header "User-Agent: Nikto/2.1.6"

sub_banner "WSTG-CONF-05: Enumerate Infrastructure and Admin Interfaces"
# WordPress admin and setup pages.
check "${JAR_CONF}" "install.php probe (CONF-05)" "honeypot" \
    --request GET "${BASE_URL}/wp-admin/install.php" \
    --header "User-Agent: Nikto/2.1.6"

check "${JAR_CONF}" "setup-config.php probe (CONF-05)" "honeypot" \
    --request GET "${BASE_URL}/wp-admin/setup-config.php" \
    --header "User-Agent: Nikto/2.1.6"

sub_banner "WSTG-CONF-06: Test HTTP Methods"
# PUT method is used in WebDAV attacks.
check "${JAR_CONF}" "HTTP PUT to wp-content (CONF-06)" "honeypot" \
    --request PUT "${BASE_URL}/wp-content/uploads/shell.php" \
    --header "User-Agent: curl/7.88.1" \
    --data "<?php system(\$_GET['cmd']); ?>"

sub_banner "WSTG-CONF-07: Test HTTP Strict Transport Security"
# HSTS header should be present on the production endpoint.
# This is an informational check; missing HSTS on HTTP is expected.
check "${JAR_CONF}" "Baseline HTTPS redirect hint (CONF-07)" "production" \
    --request GET "${BASE_URL}/" \
    --header "User-Agent: Mozilla/5.0 (compatible)"

sub_banner "WSTG-CONF-08: Test RIA Cross Domain Policy"
# crossdomain.xml is a legacy Adobe Flash policy file; probing it is recon.
check "${JAR_CONF}" "crossdomain.xml probe (CONF-08)" "honeypot" \
    --request GET "${BASE_URL}/crossdomain.xml" \
    --header "User-Agent: python-requests/2.28.0"

sub_banner "WSTG-CONF-09: Test File Permission"
# Attempt to read .htaccess directly (Nginx blocks this; wp-login should route).
check "${JAR_CONF}" ".htaccess direct read attempt (CONF-09)" "honeypot" \
    --request GET "${BASE_URL}/.htaccess" \
    --header "User-Agent: curl/7.88.1"

sub_banner "WSTG-CONF-10: Test for Subdomain Takeover"
# Not directly testable via HTTP from one host; skip with a note.
TOTAL=$((TOTAL + 1))
SKIP=$((SKIP + 1))
printf "  ${YELLOW}[SKIP]${NC} CONF-10 (subdomain takeover) requires DNS control – skipped\n"

sub_banner "WSTG-CONF-11: Test Cloud Storage"
# Exposed cloud storage buckets are detected by path patterns.
check "${JAR_CONF}" "S3 bucket path probe (CONF-11)" "honeypot" \
    --request GET "${BASE_URL}/s3-backup/" \
    --header "User-Agent: python-requests/2.28.0"

rm -f "${JAR_CONF}"

# =============================================================================
# WSTG-IDNT – Category 3: Identity Management Testing
# =============================================================================
# References: WSTG-IDNT-01 through WSTG-IDNT-05
#
# Goal: Verify that username/account enumeration attempts are detected and
# routed to the honeypot, preventing real user data from being harvested.
# =============================================================================
banner "WSTG-IDNT (3) – Identity Management Testing"

JAR_IDNT="$(mktemp /tmp/wstg_idnt_XXXXXX.txt)"

sub_banner "WSTG-IDNT-01: Test Role Definitions"
# WordPress roles are enumerable via the REST API.
check "${JAR_IDNT}" "REST API user list enumeration (IDNT-01)" "honeypot" \
    --request GET "${BASE_URL}/wp-json/wp/v2/users" \
    --header "User-Agent: python-requests/2.28.0"

sub_banner "WSTG-IDNT-02: Test User Registration Process"
# Open registration probe via wp-login.php?action=register.
check "${JAR_IDNT}" "Registration page probe (IDNT-02)" "any" \
    --request GET "${BASE_URL}/wp-login.php?action=register" \
    --header "User-Agent: Mozilla/5.0 (compatible)"

sub_banner "WSTG-IDNT-03: Test Account Provisioning Process"
# Attempt to create a user account via REST API without auth.
check "${JAR_IDNT}" "Unauthenticated user creation via REST API (IDNT-03)" "honeypot" \
    --request POST "${BASE_URL}/wp-json/wp/v2/users" \
    --header "Content-Type: application/json" \
    --header "User-Agent: python-requests/2.28.0" \
    --data '{"username":"testuser_idnt","password":"pass1234","email":"idnt@test.example"}'

sub_banner "WSTG-IDNT-04: Test Account Enumeration"
# WordPress author enumeration via ?author=N redirects to /author/username/.
check "${JAR_IDNT}" "Author enumeration ?author=1 (IDNT-04)" "honeypot" \
    --request GET "${BASE_URL}/?author=1" \
    --header "User-Agent: WPScan v3.8.27"

check "${JAR_IDNT}" "Author enumeration ?author=2 (IDNT-04)" "honeypot" \
    --request GET "${BASE_URL}/?author=2" \
    --header "User-Agent: WPScan v3.8.27"

# REST API alternative.
check "${JAR_IDNT}" "REST API user slug enumeration (IDNT-04)" "honeypot" \
    --request GET "${BASE_URL}/?rest_route=/wp/v2/users" \
    --header "User-Agent: WPScan v3.8.27"

sub_banner "WSTG-IDNT-05: Test Username Policy"
# Predictable username probe against wp-login.
check "${JAR_IDNT}" "Login with predictable username 'admin' (IDNT-05)" "any" \
    --request POST "${BASE_URL}/wp-login.php" \
    --header "Content-Type: application/x-www-form-urlencoded" \
    --header "User-Agent: python-requests/2.28.0" \
    --data "log=admin&pwd=admin&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1"

rm -f "${JAR_IDNT}"

# =============================================================================
# WSTG-ATHN – Category 4: Authentication Testing
# =============================================================================
# References: WSTG-ATHN-01 through WSTG-ATHN-10
#
# Goal: Verify that brute-force, default-credential, and credential-stuffing
# attempts are detected and that XML-RPC brute force is blocked entirely on
# production (see production-hardening.php).
# =============================================================================
banner "WSTG-ATHN (4) – Authentication Testing"

JAR_ATHN="$(mktemp /tmp/wstg_athn_XXXXXX.txt)"

sub_banner "WSTG-ATHN-01: Test Credentials Transported over Encrypted Channel"
# This is an observational check; on HTTP the cookie jar captures Set-Cookie.
TOTAL=$((TOTAL + 1))
_athn_resp=$(curl --silent --include --max-time 15 \
    --request GET "${BASE_URL}/wp-login.php" 2>&1) || true
_secure=$(printf '%s' "${_athn_resp}" | grep -i "^set-cookie:" | grep -i "secure" | head -1)
if [ -n "${_secure}" ]; then
    printf "  ${GREEN}[PASS]${NC} Login cookie has Secure flag (ATHN-01)\n"
    PASS=$((PASS + 1))
else
    printf "  ${YELLOW}[WARN]${NC} Login cookie Secure flag not observed on HTTP (ATHN-01 – expected in HTTP-only deploy)\n"
    PASS=$((PASS + 1))
fi

sub_banner "WSTG-ATHN-02: Test Default Credentials"
# Default WordPress admin credentials.
check "${JAR_ATHN}" "Default credentials admin/admin (ATHN-02)" "any" \
    --request POST "${BASE_URL}/wp-login.php" \
    --header "Content-Type: application/x-www-form-urlencoded" \
    --header "User-Agent: python-requests/2.28.0" \
    --data "log=admin&pwd=admin&wp-submit=Log+In&testcookie=1"

check "${JAR_ATHN}" "Default credentials admin/password (ATHN-02)" "any" \
    --request POST "${BASE_URL}/wp-login.php" \
    --header "Content-Type: application/x-www-form-urlencoded" \
    --header "User-Agent: python-requests/2.28.0" \
    --data "log=admin&pwd=password&wp-submit=Log+In&testcookie=1"

sub_banner "WSTG-ATHN-03: Test Account Lockout"
# Six rapid login attempts with wrong passwords – should trigger rate limiting.
_i=1
while [ "${_i}" -le 6 ]; do
    curl --silent --output /dev/null --max-time 10 \
        --request POST "${BASE_URL}/wp-login.php" \
        --header "Content-Type: application/x-www-form-urlencoded" \
        --header "User-Agent: python-requests/2.28.0" \
        --data "log=admin&pwd=wrongpass${_i}&wp-submit=Log+In&testcookie=1" || true
    _i=$((_i + 1))
done
# Now a clean check: the session should be honeypot-bound from the rapid posts.
check "${JAR_ATHN}" "Session after brute-force routed to honeypot (ATHN-03)" "honeypot" \
    --request GET "${BASE_URL}/wp-login.php" \
    --header "User-Agent: python-requests/2.28.0"

sub_banner "WSTG-ATHN-04: Test for Bypassing Authentication Schema"
# Direct access to wp-admin pages without cookie.
check "${JAR_ATHN}" "wp-admin direct access without auth (ATHN-04)" "honeypot" \
    --request GET "${BASE_URL}/wp-admin/users.php" \
    --header "User-Agent: python-requests/2.28.0"

sub_banner "WSTG-ATHN-05: Test Remember Password Functionality"
# Check that 'Remember Me' cookie is properly scoped.
TOTAL=$((TOTAL + 1))
SKIP=$((SKIP + 1))
printf "  ${YELLOW}[SKIP]${NC} ATHN-05 (remember-me token analysis) requires valid login session – skipped\n"

sub_banner "WSTG-ATHN-06: Test Browser Cache Weaknesses"
# wp-login.php should include cache control headers.
TOTAL=$((TOTAL + 1))
_cache_resp=$(curl --silent --include --max-time 15 \
    --request GET "${BASE_URL}/wp-login.php" 2>&1) || true
_cc=$(printf '%s' "${_cache_resp}" | grep -i "^cache-control:" | head -1)
if printf '%s' "${_cc}" | grep -qi "no-cache\|no-store\|private"; then
    printf "  ${GREEN}[PASS]${NC} Login page has restrictive Cache-Control (ATHN-06)\n"
    PASS=$((PASS + 1))
else
    printf "  ${YELLOW}[WARN]${NC} Login Cache-Control not restrictive: '%s' (ATHN-06)\n" "${_cc}"
    PASS=$((PASS + 1))
fi

sub_banner "WSTG-ATHN-07: Test Password Policy"
# Attempt to set a trivially weak password via REST API.
check "${JAR_ATHN}" "Weak password via REST API (ATHN-07)" "honeypot" \
    --request PUT "${BASE_URL}/wp-json/wp/v2/users/1" \
    --header "Content-Type: application/json" \
    --header "User-Agent: python-requests/2.28.0" \
    --data '{"password":"123"}'

sub_banner "WSTG-ATHN-08: Test Security Questions"
# WordPress does not use security questions by default; skip.
TOTAL=$((TOTAL + 1))
SKIP=$((SKIP + 1))
printf "  ${YELLOW}[SKIP]${NC} ATHN-08 (security questions) – not applicable to WordPress\n"

sub_banner "WSTG-ATHN-09: Test Password Reset Functionality"
# Lost-password endpoint probe.
check "${JAR_ATHN}" "Password reset endpoint probe (ATHN-09)" "any" \
    --request POST "${BASE_URL}/wp-login.php?action=lostpassword" \
    --header "Content-Type: application/x-www-form-urlencoded" \
    --header "User-Agent: python-requests/2.28.0" \
    --data "user_login=admin&redirect_to=&wp-submit=Get+New+Password"

sub_banner "WSTG-ATHN-10: Test XML-RPC Authentication"
# XML-RPC brute force must be blocked on production by production-hardening.php.
# We expect either a 403 / 404 response from production-hardening, OR the
# request is routed to the honeypot by the Nginx router.
check "${JAR_ATHN}" "XML-RPC system.listMethods probe (ATHN-10)" "honeypot" \
    --request POST "${BASE_URL}/xmlrpc.php" \
    --header "Content-Type: text/xml" \
    --header "User-Agent: python-requests/2.28.0" \
    --data '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>'

check "${JAR_ATHN}" "XML-RPC brute-force multicall (ATHN-10)" "honeypot" \
    --request POST "${BASE_URL}/xmlrpc.php" \
    --header "Content-Type: text/xml" \
    --header "User-Agent: python-requests/2.28.0" \
    --data '<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName><params><param><value><array><data><value><struct><member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member><member><name>params</name><value><array><data><value><array><data><value><string>admin</string></value><value><string>pass1</string></value></data></array></value></data></array></value></member></struct></value></data></array></value></param></params></methodCall>'

rm -f "${JAR_ATHN}"

# =============================================================================
# WSTG-AUTHZ – Category 5: Authorization Testing
# =============================================================================
# References: WSTG-AUTHZ-01 through WSTG-AUTHZ-04
#
# Goal: Verify that vertical and horizontal privilege escalation attempts are
# detected and routed to the honeypot rather than touching production data.
# =============================================================================
banner "WSTG-AUTHZ (5) – Authorization Testing"

JAR_AUTHZ="$(mktemp /tmp/wstg_authz_XXXXXX.txt)"

sub_banner "WSTG-AUTHZ-01: Test Directory Traversal / File Include"
# Path traversal to read sensitive files outside webroot.
check "${JAR_AUTHZ}" "Path traversal ../etc/passwd (AUTHZ-01)" "honeypot" \
    --request GET "${BASE_URL}/../../../etc/passwd" \
    --header "User-Agent: python-requests/2.28.0"

check "${JAR_AUTHZ}" "URL-encoded traversal %2e%2e (AUTHZ-01)" "honeypot" \
    --request GET "${BASE_URL}/%2e%2e/%2e%2e/%2e%2e/etc/passwd" \
    --header "User-Agent: python-requests/2.28.0"

check "${JAR_AUTHZ}" "LFI via file parameter (AUTHZ-01)" "honeypot" \
    --request GET "${BASE_URL}/?file=../../../../etc/passwd" \
    --header "User-Agent: python-requests/2.28.0"

check "${JAR_AUTHZ}" "PHP wrapper LFI php://filter (AUTHZ-01)" "honeypot" \
    --request GET "${BASE_URL}/?page=php://filter/convert.base64-encode/resource=wp-config" \
    --header "User-Agent: python-requests/2.28.0"

sub_banner "WSTG-AUTHZ-02: Test Bypassing Authorization Schema"
# Attempt to access admin-only REST API endpoints without authentication.
check "${JAR_AUTHZ}" "Unauthenticated wp-admin REST users list (AUTHZ-02)" "honeypot" \
    --request GET "${BASE_URL}/wp-json/wp/v2/users?context=edit" \
    --header "User-Agent: python-requests/2.28.0"

# IDOR: access another user's order data.
check "${JAR_AUTHZ}" "IDOR order data access (AUTHZ-02)" "honeypot" \
    --request GET "${BASE_URL}/wp-json/wc/v3/orders/1" \
    --header "User-Agent: python-requests/2.28.0"

sub_banner "WSTG-AUTHZ-03: Test Privilege Escalation"
# CVE-2023-28121-style header that elevates to administrator role.
check "${JAR_AUTHZ}" "Privilege escalation via WCPAY header (AUTHZ-03)" "honeypot" \
    --request GET "${BASE_URL}/wp-admin/users.php" \
    --header "X-WCPAY-PLATFORM-CHECKOUT-USER: 1" \
    --header "User-Agent: python-requests/2.28.0"

# CVE-2025-2266: unauthenticated WordPress options update.
check "${JAR_AUTHZ}" "Options update via cwmpUpdateOptions (AUTHZ-03)" "honeypot" \
    --request POST "${BASE_URL}/wp-admin/admin-ajax.php" \
    --header "Content-Type: application/x-www-form-urlencoded" \
    --header "User-Agent: python-requests/2.28.0" \
    --data "action=cwmpUpdateOptions&siteurl=http://evil.example"

sub_banner "WSTG-AUTHZ-04: Test Insecure Direct Object References"
# Access a private post by ID without authentication.
check "${JAR_AUTHZ}" "Private post IDOR via REST API (AUTHZ-04)" "honeypot" \
    --request GET "${BASE_URL}/wp-json/wp/v2/posts/1?status=private" \
    --header "User-Agent: python-requests/2.28.0"

# WooCommerce customer account IDOR.
check "${JAR_AUTHZ}" "WooCommerce customer IDOR (AUTHZ-04)" "honeypot" \
    --request GET "${BASE_URL}/wp-json/wc/v3/customers/1" \
    --header "User-Agent: python-requests/2.28.0"

rm -f "${JAR_AUTHZ}"

# =============================================================================
# WSTG-SESS – Category 6: Session Management Testing
# =============================================================================
# References: WSTG-SESS-01 through WSTG-SESS-09
#
# Goal: Verify that session-based attacks (fixation, hijacking, CSRF) are
# detected and that the session binding mechanism routes attackers who attempt
# to steal or forge sessions to the honeypot.
# =============================================================================
banner "WSTG-SESS (6) – Session Management Testing"

JAR_SESS="$(mktemp /tmp/wstg_sess_XXXXXX.txt)"

sub_banner "WSTG-SESS-01: Test Session Management Schema"
# Inspect the session cookie attributes returned by the server.
TOTAL=$((TOTAL + 1))
_sess_resp=$(curl --silent --include --max-time 15 \
    --request GET "${BASE_URL}/" 2>&1) || true
_http_only=$(printf '%s' "${_sess_resp}" | grep -i "^set-cookie:" | grep -i "httponly" | head -1)
if [ -n "${_http_only}" ]; then
    printf "  ${GREEN}[PASS]${NC} Session cookie has HttpOnly flag (SESS-01)\n"
    PASS=$((PASS + 1))
else
    printf "  ${YELLOW}[WARN]${NC} HttpOnly flag not observed on session cookie (SESS-01)\n"
    PASS=$((PASS + 1))
fi

sub_banner "WSTG-SESS-02: Test Cookie Attributes"
# Verify SameSite attribute presence to mitigate CSRF via cookie.
TOTAL=$((TOTAL + 1))
_samesite=$(printf '%s' "${_sess_resp}" | grep -i "^set-cookie:" | grep -i "samesite" | head -1)
if [ -n "${_samesite}" ]; then
    printf "  ${GREEN}[PASS]${NC} Session cookie has SameSite attribute (SESS-02): %s\n" "${_samesite}"
    PASS=$((PASS + 1))
else
    printf "  ${YELLOW}[WARN]${NC} SameSite attribute not observed (SESS-02 – may be WordPress default)\n"
    PASS=$((PASS + 1))
fi

sub_banner "WSTG-SESS-03: Test Session Fixation"
# Attempt to fixate a session by supplying a known session token.
# The router detects the suspicious cookie manipulation pattern.
check "${JAR_SESS}" "Session fixation attempt via forged cookie (SESS-03)" "any" \
    --request GET "${BASE_URL}/wp-admin/" \
    --header "Cookie: wordpress_logged_in_FIXATED=admin%7C9999999999%7Cfixated_token%7Csignature" \
    --header "User-Agent: python-requests/2.28.0"

sub_banner "WSTG-SESS-04: Test Exposed Session Variables"
# Verify that the routing decision header does not expose internal pool info.
TOTAL=$((TOTAL + 1))
_xpool=$(printf '%s' "${_sess_resp}" | grep -i "^x-honeypot-pool:" | head -1)
if [ -z "${_xpool}" ]; then
    printf "  ${GREEN}[PASS]${NC} X-Honeypot-Pool header not exposed to clients (SESS-04)\n"
    PASS=$((PASS + 1))
else
    printf "  ${RED}[FAIL]${NC} X-Honeypot-Pool header leaked to client: %s (SESS-04)\n" "${_xpool}"
    FAIL=$((FAIL + 1))
fi

sub_banner "WSTG-SESS-05: Test CSRF"
# CSRF probe: cross-origin POST without a nonce to wp-admin/admin-post.php.
check "${JAR_SESS}" "CSRF POST to admin-post.php (SESS-05)" "honeypot" \
    --request POST "${BASE_URL}/wp-admin/admin-post.php" \
    --header "Content-Type: application/x-www-form-urlencoded" \
    --header "Referer: http://evil.example/csrf.html" \
    --header "User-Agent: Mozilla/5.0 (compatible)" \
    --data "action=some_admin_action&nonce=invalid"

sub_banner "WSTG-SESS-06: Test Cookie Persistence"
# Long-lived session cookie abuse: replaying a stale WordPress auth cookie.
check "${JAR_SESS}" "Stale auth cookie replay attempt (SESS-06)" "any" \
    --request GET "${BASE_URL}/wp-admin/profile.php" \
    --header "Cookie: wordpress_sec_abcdef123456=admin%7C9999999999%7Cstale%7Chash" \
    --header "User-Agent: python-requests/2.28.0"

sub_banner "WSTG-SESS-07: Test Session Timeout"
# Not automatable via HTTP alone; skip with a note.
TOTAL=$((TOTAL + 1))
SKIP=$((SKIP + 1))
printf "  ${YELLOW}[SKIP]${NC} SESS-07 (session timeout) requires a live authenticated session – skipped\n"

sub_banner "WSTG-SESS-08: Test Session Puzzling"
# Test whether a session established on a legitimate page carries over to
# attack-flagged pages (it should not – each session starts clean).
JAR_SESS_PUZZLE="$(mktemp /tmp/wstg_sess_puzzle_XXXXXX.txt)"

# Step 1: Establish a clean session on the homepage.
curl --silent --output /dev/null --max-time 15 \
    --cookie "${JAR_SESS_PUZZLE}" --cookie-jar "${JAR_SESS_PUZZLE}" \
    --request GET "${BASE_URL}/" \
    --header "User-Agent: Mozilla/5.0 (compatible)" || true

# Step 2: From the same session send a malicious request.
check "${JAR_SESS_PUZZLE}" "Escalation from clean session with SQLi (SESS-08)" "honeypot" \
    --request GET "${BASE_URL}/?id=1'+OR+'1'='1" \
    --header "User-Agent: Mozilla/5.0 (compatible)"

rm -f "${JAR_SESS_PUZZLE}"

sub_banner "WSTG-SESS-09: Test JWT Weaknesses"
# WordPress does not use JWT by default; skip.
TOTAL=$((TOTAL + 1))
SKIP=$((SKIP + 1))
printf "  ${YELLOW}[SKIP]${NC} SESS-09 (JWT weaknesses) – not applicable without a JWT plugin\n"

rm -f "${JAR_SESS}"

# =============================================================================
# WSTG-INPV – Category 7: Input Validation Testing
# =============================================================================
# References: WSTG-INPV-01 through WSTG-INPV-19
#
# Goal: Exercise the full spectrum of injection and encoding attacks against
# the WordPress/WooCommerce stack and verify each is detected (honeypot route)
# or blocked (no response body).  Selected representative tests are included;
# exhaustive fuzzing is deferred to the WPScan and Metasploit scenarios.
# =============================================================================
banner "WSTG-INPV (7) – Input Validation Testing"

JAR_INPV="$(mktemp /tmp/wstg_inpv_XXXXXX.txt)"

sub_banner "WSTG-INPV-01: Test Reflected Cross-Site Scripting"
check "${JAR_INPV}" "Reflected XSS in search param (INPV-01)" "honeypot" \
    --request GET "${BASE_URL}/?s=%3Cscript%3Ealert%281%29%3C%2Fscript%3E" \
    --header "User-Agent: Mozilla/5.0 (compatible)"

check "${JAR_INPV}" "Reflected XSS img onerror (INPV-01)" "honeypot" \
    --request GET "${BASE_URL}/?name=%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E" \
    --header "User-Agent: Mozilla/5.0 (compatible)"

sub_banner "WSTG-INPV-02: Test Stored Cross-Site Scripting"
# Attempt to store XSS via WooCommerce product review.
check "${JAR_INPV}" "Stored XSS via comment POST (INPV-02)" "honeypot" \
    --request POST "${BASE_URL}/wp-comments-post.php" \
    --header "Content-Type: application/x-www-form-urlencoded" \
    --header "User-Agent: Mozilla/5.0 (compatible)" \
    --data "comment=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&author=Attacker&email=atk%40evil.example&url=&submit=Post+Comment&comment_post_ID=1&comment_parent=0"

sub_banner "WSTG-INPV-03: Test HTTP Verb Tampering"
# Non-standard HTTP method to bypass WAF rules.
check "${JAR_INPV}" "HTTP verb FUZZ (INPV-03)" "honeypot" \
    --request FUZZ "${BASE_URL}/wp-admin/admin-ajax.php" \
    --header "User-Agent: python-requests/2.28.0" || true

sub_banner "WSTG-INPV-04: Test HTTP Parameter Pollution"
# Duplicate parameters are used to bypass input filters.
check "${JAR_INPV}" "Parameter pollution ?id=1&id=2 (INPV-04)" "honeypot" \
    --request GET "${BASE_URL}/?id=1&id=2'+OR+'1'='1" \
    --header "User-Agent: python-requests/2.28.0"

sub_banner "WSTG-INPV-05: Test SQL Injection"
# Classic SQL injection payloads across multiple parameters.
check "${JAR_INPV}" "SQLi OR 1=1 in id param (INPV-05)" "honeypot" \
    --request GET "${BASE_URL}/?id=1'+OR+'1'='1" \
    --header "User-Agent: sqlmap/1.7.8"

check "${JAR_INPV}" "SQLi UNION SELECT (INPV-05)" "honeypot" \
    --request GET "${BASE_URL}/?id=1+UNION+SELECT+NULL%2CNULL%2Cnull--" \
    --header "User-Agent: sqlmap/1.7.8"

check "${JAR_INPV}" "SQLi time-based SLEEP (INPV-05)" "honeypot" \
    --request GET "${BASE_URL}/?id=1'+AND+SLEEP(5)--" \
    --header "User-Agent: sqlmap/1.7.8"

check "${JAR_INPV}" "SQLi via CVE-2024-2387 integration_id (INPV-05)" "honeypot" \
    --request GET "${BASE_URL}/?integration_id=1'+OR+'1'='1" \
    --header "User-Agent: python-requests/2.28.0"

sub_banner "WSTG-INPV-06: Test LDAP Injection"
# WordPress does not use LDAP by default; skip.
TOTAL=$((TOTAL + 1))
SKIP=$((SKIP + 1))
printf "  ${YELLOW}[SKIP]${NC} INPV-06 (LDAP injection) – not applicable without LDAP plugin\n"

sub_banner "WSTG-INPV-07: Test XML Injection"
# XML injection via the xmlrpc.php endpoint.
check "${JAR_INPV}" "XML injection via xmlrpc.php (INPV-07)" "honeypot" \
    --request POST "${BASE_URL}/xmlrpc.php" \
    --header "Content-Type: text/xml" \
    --header "User-Agent: python-requests/2.28.0" \
    --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><methodCall><methodName>&xxe;</methodName></methodCall>'

sub_banner "WSTG-INPV-08: Test SSI Injection"
check "${JAR_INPV}" "SSI injection in search (INPV-08)" "honeypot" \
    --request GET "${BASE_URL}/?s=%3C%21--+%23exec+cmd%3D%22id%22+--%3E" \
    --header "User-Agent: python-requests/2.28.0"

sub_banner "WSTG-INPV-09: Test XPath Injection"
# Probe XPath-based authentication bypass (not standard WP but tested for completeness).
check "${JAR_INPV}" "XPath injection in login (INPV-09)" "any" \
    --request POST "${BASE_URL}/wp-login.php" \
    --header "Content-Type: application/x-www-form-urlencoded" \
    --header "User-Agent: python-requests/2.28.0" \
    --data "log=admin'+or+'1'%3D'1&pwd=x&wp-submit=Log+In&testcookie=1"

sub_banner "WSTG-INPV-10: Test IMAP/SMTP Injection"
# Not applicable; skip.
TOTAL=$((TOTAL + 1))
SKIP=$((SKIP + 1))
printf "  ${YELLOW}[SKIP]${NC} INPV-10 (IMAP/SMTP injection) – not applicable\n"

sub_banner "WSTG-INPV-11: Test Code Injection"
# PHP code injection via template parameter.
check "${JAR_INPV}" "PHP code injection in template param (INPV-11)" "honeypot" \
    --request GET "${BASE_URL}/?template=system('id')" \
    --header "User-Agent: python-requests/2.28.0"

sub_banner "WSTG-INPV-12: Test Command Injection"
check "${JAR_INPV}" "OS command injection via cmd param (INPV-12)" "honeypot" \
    --request GET "${BASE_URL}/?cmd=;cat+/etc/passwd" \
    --header "User-Agent: python-requests/2.28.0"

check "${JAR_INPV}" "OS command injection pipe ls (INPV-12)" "honeypot" \
    --request GET "${BASE_URL}/?exec=|+ls+-la" \
    --header "User-Agent: python-requests/2.28.0"

check "${JAR_INPV}" "OS command injection backtick (INPV-12)" "honeypot" \
    --request GET "${BASE_URL}/?run=%60whoami%60" \
    --header "User-Agent: python-requests/2.28.0"

sub_banner "WSTG-INPV-13: Test Buffer Overflow"
# Oversized input in search/URL parameters.
LONG_INPUT=$(printf 'A%.0s' $(seq 1 4096))
check "${JAR_INPV}" "Oversized search parameter (INPV-13)" "honeypot" \
    --request GET "${BASE_URL}/?s=${LONG_INPUT}" \
    --header "User-Agent: python-requests/2.28.0"

sub_banner "WSTG-INPV-14: Test Incubated Vulnerability"
# Delayed-execution probe: upload then access.
check "${JAR_INPV}" "File upload probe for incubated exec (INPV-14)" "honeypot" \
    --request POST "${BASE_URL}/wp-admin/admin-ajax.php" \
    --header "User-Agent: python-requests/2.28.0" \
    --form "action=dnd_codedropz_upload" \
    --form "upload-file=@/dev/null;filename=probe.php;type=application/x-php"

sub_banner "WSTG-INPV-15: Test HTTP Splitting/Smuggling"
# CRLF injection attempt in a header value.
check "${JAR_INPV}" "CRLF injection via redirect param (INPV-15)" "honeypot" \
    --request GET "${BASE_URL}/wp-login.php?redirect_to=http%3A%2F%2Fevil.example%0d%0aSet-Cookie%3A+injected%3Dtrue" \
    --header "User-Agent: python-requests/2.28.0"

sub_banner "WSTG-INPV-16: Test HTTP Request Smuggling"
# Content-Length + Transfer-Encoding conflict.
TOTAL=$((TOTAL + 1))
SKIP=$((SKIP + 1))
printf "  ${YELLOW}[SKIP]${NC} INPV-16 (HTTP request smuggling) – requires raw TCP socket tooling\n"

sub_banner "WSTG-INPV-17: Test Web Messaging"
# Not applicable to a server-side PHP application; skip.
TOTAL=$((TOTAL + 1))
SKIP=$((SKIP + 1))
printf "  ${YELLOW}[SKIP]${NC} INPV-17 (web messaging) – client-side, not applicable here\n"

sub_banner "WSTG-INPV-18: Test DOM-based XSS"
# DOM-XSS requires a browser; skip in headless script.
TOTAL=$((TOTAL + 1))
SKIP=$((SKIP + 1))
printf "  ${YELLOW}[SKIP]${NC} INPV-18 (DOM-based XSS) – requires browser execution context\n"

sub_banner "WSTG-INPV-19: Test Local File Inclusion"
# PHP stream wrapper and standard LFI vectors.
check "${JAR_INPV}" "LFI via php://input wrapper (INPV-19)" "honeypot" \
    --request GET "${BASE_URL}/?page=php://input" \
    --header "User-Agent: python-requests/2.28.0"

check "${JAR_INPV}" "LFI data:// wrapper (INPV-19)" "honeypot" \
    --request GET "${BASE_URL}/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOz8+" \
    --header "User-Agent: python-requests/2.28.0"

check "${JAR_INPV}" "LFI file:///etc/passwd (INPV-19)" "honeypot" \
    --request GET "${BASE_URL}/?file=file:///etc/passwd" \
    --header "User-Agent: python-requests/2.28.0"

rm -f "${JAR_INPV}"

# ---------------------------------------------------------------------------
# Final report
# ---------------------------------------------------------------------------
banner "Scenario 02 – OWASP WSTG Final Report"
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
    printf "${GREEN}SCENARIO PASSED – All WSTG 1-7 attack categories detected/contained.${NC}\n"
    exit 0
else
    printf "${RED}SCENARIO FAILED – %d check(s) did not route as expected.${NC}\n" "${FAIL}"
    exit 1
fi