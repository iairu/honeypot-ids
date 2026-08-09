#!/bin/bash
# =============================================================================
# run_all_scenarios.sh
#
# PURPOSE:
#   Master test runner for all honeynet testing scenarios.  Executes each
#   scenario script in sequence, captures pass/fail/skip counts, and produces
#   a consolidated final report.
#
# SCENARIOS:
#   01  TryHackMe WooCommerce / CVE-2023-28121 attack chain
#   02  OWASP WSTG categories 1-7
#   03  WPScan enumeration and vulnerability coverage
#   04  Metasploit: honeypot shell + SQLi + Docker takeover
#   05  Production hardening verification
#   06  WordPress DB hashed password replacement
#   07  Stripe and payment gateway coverage
#   08  Backup deletion attempt from overtaken container
#   09  PentAGI AI-driven penetration testing
#
# USAGE:
#   ./run_all_scenarios.sh [TARGET_HOST] [TARGET_PORT] [OPTIONS]
#
#   TARGET_HOST  IP or hostname of the reverse proxy (default: 127.0.0.1)
#   TARGET_PORT  HTTP port exposed by the reverse proxy (default: 80)
#
#   OPTIONS (environment variables):
#     SCENARIOS          Comma-separated list of scenario numbers to run.
#                        Default: "1,2,3,4,5,6,7,8,9" (all)
#                        Example: SCENARIOS=1,2,5 ./run_all_scenarios.sh
#     SKIP_SCENARIOS     Comma-separated list of scenario numbers to skip.
#                        Example: SKIP_SCENARIOS=4,9 ./run_all_scenarios.sh
#     WPSCAN_API_TOKEN   WPScan API token for scenario 03 (optional).
#     LHOST              Metasploit listener IP for scenario 04 (optional).
#     LPORT              Metasploit listener port for scenario 04 (optional).
#     PENTAGI_API_KEY    LLM API key for scenario 09 (optional).
#     CONTINUE_ON_FAIL   Set to "1" to run all scenarios even if one fails.
#                        Default: "1" (continue on failure).
#     REPORT_DIR         Directory to write the consolidated report.
#                        Default: ./test_reports/
#
# EXIT CODES:
#   0  All executed scenarios passed.
#   1  One or more scenarios failed.
#   2  Prerequisites missing (curl).
#
# DEPENDENCIES:
#   curl   – required for all HTTP checks.
#   docker – optional; enables container-level checks in scenarios 04-08.
#   jq     – optional; enables JSON report parsing in scenario 09.
# =============================================================================

set -e
set -o pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TARGET_HOST="${1:-127.0.0.1}"
TARGET_PORT="${2:-443}"
BASE_URL="https://${TARGET_HOST}:${TARGET_PORT}"

# Scenario selection (default: all).
SCENARIOS="${SCENARIOS:-1,2,3,4,5,6,7,8,9}"
SKIP_SCENARIOS="${SKIP_SCENARIOS:-}"
CONTINUE_ON_FAIL="${CONTINUE_ON_FAIL:-1}"

# Report directory.
REPORT_DIR="${REPORT_DIR:-./test_reports}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
REPORT_FILE="${REPORT_DIR}/report_${TIMESTAMP}.txt"
SUMMARY_FILE="${REPORT_DIR}/summary_${TIMESTAMP}.json"

# Locate the directory where scenario scripts live.
SCENARIO_DIR="$(dirname "$0")"

# Optional tool-specific parameters.
WPSCAN_API_TOKEN="${WPSCAN_API_TOKEN:-}"
LHOST="${LHOST:-127.0.0.1}"
LPORT="${LPORT:-4444}"
PENTAGI_API_KEY="${PENTAGI_API_KEY:-}"

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# ---------------------------------------------------------------------------
# Global counters (across all scenarios)
# ---------------------------------------------------------------------------
TOTAL_SCENARIOS=0
PASS_SCENARIOS=0
FAIL_SCENARIOS=0
SKIP_SCENARIOS_COUNT=0

# Aggregate check counts from individual scenarios.
GRAND_TOTAL=0
GRAND_PASS=0
GRAND_FAIL=0
GRAND_SKIP=0

# Scenario result arrays (stored as newline-separated strings for sh compat).
SCENARIO_RESULTS=""

# ---------------------------------------------------------------------------
# Utility: print a top-level banner
# ---------------------------------------------------------------------------
banner() {
    printf "\n${BOLD}${CYAN}##############################################################${NC}\n"
    printf "${BOLD}${CYAN}  %s${NC}\n" "$1"
    printf "${BOLD}${CYAN}##############################################################${NC}\n\n"
}

# ---------------------------------------------------------------------------
# Utility: check if a scenario number is in a comma-separated list
#
#   in_list <number> <comma_separated_list>
#   Returns 0 (true) if found, 1 (false) if not.
# ---------------------------------------------------------------------------
in_list() {
    _num="$1"
    _list="$2"
    # Convert list to newline-separated and grep for exact match.
    printf '%s' "${_list}" | tr ',' '\n' | grep -qx "${_num}"
}

# ---------------------------------------------------------------------------
# Utility: run a single scenario
#
#   run_scenario <number> <name> <script> [extra_args...]
# ---------------------------------------------------------------------------
run_scenario() {
    _num="$1"
    _name="$2"
    _script="$3"
    shift 3

    TOTAL_SCENARIOS=$((TOTAL_SCENARIOS + 1))

    # Check skip list.
    if [ -n "${SKIP_SCENARIOS}" ] && in_list "${_num}" "${SKIP_SCENARIOS}"; then
        SKIP_SCENARIOS_COUNT=$((SKIP_SCENARIOS_COUNT + 1))
        printf "\n${YELLOW}[SKIP] Scenario %02d: %s (in SKIP_SCENARIOS)${NC}\n" "${_num}" "${_name}"
        SCENARIO_RESULTS="${SCENARIO_RESULTS}${_num}|${_name}|SKIP|0|0|0|0\n"
        return 0
    fi

    # Check include list.
    if ! in_list "${_num}" "${SCENARIOS}"; then
        SKIP_SCENARIOS_COUNT=$((SKIP_SCENARIOS_COUNT + 1))
        printf "\n${YELLOW}[SKIP] Scenario %02d: %s (not in SCENARIOS list)${NC}\n" "${_num}" "${_name}"
        SCENARIO_RESULTS="${SCENARIO_RESULTS}${_num}|${_name}|SKIP|0|0|0|0\n"
        return 0
    fi

    # Verify the script exists and is executable.
    _full_script="${SCENARIO_DIR}/${_script}"
    if [ ! -f "${_full_script}" ]; then
        printf "\n${RED}[ERROR] Script not found: %s${NC}\n" "${_full_script}"
        FAIL_SCENARIOS=$((FAIL_SCENARIOS + 1))
        SCENARIO_RESULTS="${SCENARIO_RESULTS}${_num}|${_name}|ERROR|0|0|0|0\n"
        return 1
    fi
    chmod +x "${_full_script}" 2>/dev/null || true

    printf "\n"
    printf "${BOLD}${BLUE}┌─────────────────────────────────────────────────────────────┐${NC}\n"
    printf "${BOLD}${BLUE}│  Running Scenario %02d: %-42s│${NC}\n" "${_num}" "${_name}"
    printf "${BOLD}${BLUE}└─────────────────────────────────────────────────────────────┘${NC}\n"
    printf "  Script  : %s\n" "${_full_script}"
    printf "  Started : %s\n\n" "$(date '+%Y-%m-%d %H:%M:%S')"

    _start_time=$(date +%s)
    _exit_code=0

    # Run the scenario; capture output and exit code.
    "${_full_script}" "${TARGET_HOST}" "${TARGET_PORT}" "$@" 2>&1 | tee -a "${REPORT_FILE}" || _exit_code=$?

    _end_time=$(date +%s)
    _duration=$((_end_time - _start_time))

    # Classify result.
    if [ "${_exit_code}" -eq 0 ]; then
        _result="PASS"
        PASS_SCENARIOS=$((PASS_SCENARIOS + 1))
        printf "\n  ${GREEN}${BOLD}✓ Scenario %02d PASSED in %ds${NC}\n" "${_num}" "${_duration}"
    else
        _result="FAIL"
        FAIL_SCENARIOS=$((FAIL_SCENARIOS + 1))
        printf "\n  ${RED}${BOLD}✗ Scenario %02d FAILED (exit=%d) in %ds${NC}\n" \
               "${_num}" "${_exit_code}" "${_duration}"
        if [ "${CONTINUE_ON_FAIL}" != "1" ]; then
            printf "${RED}CONTINUE_ON_FAIL=0; aborting test run.${NC}\n"
            _write_summary
            exit 1
        fi
    fi

    SCENARIO_RESULTS="${SCENARIO_RESULTS}${_num}|${_name}|${_result}|${_duration}\n"
}

# ---------------------------------------------------------------------------
# Utility: write the consolidated JSON summary
# ---------------------------------------------------------------------------
_write_summary() {
    mkdir -p "${REPORT_DIR}"

    _end_ts=$(date +%s)
    _total_duration=$((_end_ts - RUN_START_TIME))

    # Build JSON scenario array.
    _json_scenarios=""
    printf '%b' "${SCENARIO_RESULTS}" | while IFS='|' read -r _n _nm _res _dur _rest; do
        [ -z "${_n}" ] && continue
        _json_scenarios="${_json_scenarios}    {\"scenario\": ${_n}, \"name\": \"${_nm}\", \"result\": \"${_res}\", \"duration_s\": ${_dur:-0}},"
    done
    # Remove trailing comma.
    _json_scenarios=$(printf '%s' "${_json_scenarios}" | sed 's/,$//')

    cat > "${SUMMARY_FILE}" <<JSON
{
  "run_timestamp": "${TIMESTAMP}",
  "target": "${BASE_URL}",
  "total_duration_s": ${_total_duration},
  "scenarios": {
    "total": ${TOTAL_SCENARIOS},
    "passed": ${PASS_SCENARIOS},
    "failed": ${FAIL_SCENARIOS},
    "skipped": ${SKIP_SCENARIOS_COUNT}
  },
  "results": [
${_json_scenarios}
  ]
}
JSON
    printf "\nJSON summary written to: %s\n" "${SUMMARY_FILE}"
}

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
if ! command -v curl >/dev/null 2>&1; then
    printf "${RED}ERROR: 'curl' not found in PATH.  Install curl and retry.${NC}\n" >&2
    exit 2
fi

# Create report directory.
mkdir -p "${REPORT_DIR}"

# ---------------------------------------------------------------------------
# Pre-flight: verify target is reachable before starting any scenario
# ---------------------------------------------------------------------------
banner "Honeynet Test Suite – Pre-flight Check"
printf "Target      : %s\n" "${BASE_URL}"
printf "Scenarios   : %s\n" "${SCENARIOS}"
if [ -n "${SKIP_SCENARIOS}" ]; then
    printf "Skipping    : %s\n" "${SKIP_SCENARIOS}"
fi
printf "Report      : %s\n" "${REPORT_FILE}"
printf "Summary     : %s\n\n" "${SUMMARY_FILE}"

_preflight_status=$(curl -k --silent --output /dev/null \
    --write-out "%{http_code}" \
    --max-time 15 \
    --request GET "${BASE_URL}/" \
    --header "User-Agent: Mozilla/5.0 (compatible; HoneynetTestSuite/1.0)" \
    2>/dev/null) || _preflight_status="000"

if [ "${_preflight_status}" = "200" ] || \
   [ "${_preflight_status}" = "301" ] || \
   [ "${_preflight_status}" = "302" ]; then
    printf "${GREEN}[OK]${NC} Target is reachable (HTTP %s)\n\n" "${_preflight_status}"
else
    printf "${RED}[FAIL]${NC} Target is NOT reachable: HTTP %s\n" "${_preflight_status}"
    printf "Ensure the honeynet stack is running:\n"
    printf "  cd ids && docker compose up -d\n\n"
    exit 1
fi

# Record suite start time.
RUN_START_TIME=$(date +%s)

# Write header to report file.
{
    printf "Honeynet Test Suite Run\n"
    printf "Target    : %s\n" "${BASE_URL}"
    printf "Started   : %s\n" "$(date '+%Y-%m-%d %H:%M:%S')"
    printf "Scenarios : %s\n" "${SCENARIOS}"
    printf "=%.0s" $(seq 1 70); printf "\n"
} > "${REPORT_FILE}"

# =============================================================================
# Run all scenarios
# =============================================================================
banner "Executing Scenarios"

# Scenario 01: TryHackMe WooCommerce CVE-2023-28121
run_scenario 1 \
    "TryHackMe WooCommerce CVE-2023-28121" \
    "scenario_01_thm_woocommerce.sh"

# Scenario 02: OWASP WSTG categories 1-7
run_scenario 2 \
    "OWASP WSTG Attack Scenarios 1-7" \
    "scenario_02_owasp_wstg.sh"

# Scenario 03: WPScan enumeration and vulnerability coverage
# Pass the optional WPScan API token as the third argument.
run_scenario 3 \
    "WPScan Enumeration and Vulnerability Coverage" \
    "scenario_03_wpscan.sh" \
    "${WPSCAN_API_TOKEN}"

# Scenario 04: Metasploit shell + SQLi + Docker takeover
# Pass LHOST and LPORT for the reverse-shell listener.
run_scenario 4 \
    "Metasploit Shell + SQLi + Docker Takeover" \
    "scenario_04_metasploit.sh" \
    "${LHOST}" "${LPORT}"

# Scenario 05: Production hardening verification
run_scenario 5 \
    "Production Hardening Verification" \
    "scenario_05_hardening_verification.sh"

# Scenario 06: WordPress DB hashed password replacement
run_scenario 6 \
    "WordPress DB Password Hash Replacement" \
    "scenario_06_db_password_replacement.sh"

# Scenario 07: Stripe and payment gateway coverage
run_scenario 7 \
    "Stripe and Payment Gateway Coverage" \
    "scenario_07_payment_gateway.sh"

# Scenario 08: Backup deletion attempt from overtaken container
run_scenario 8 \
    "Backup Deletion Attempt from Container" \
    "scenario_08_backup_deletion_attempt.sh"

# Scenario 09: PentAGI AI-driven penetration testing
run_scenario 9 \
    "PentAGI AI-Driven Penetration Testing" \
    "scenario_09_pentagi.sh" \
    "${PENTAGI_API_KEY}"

# =============================================================================
# Consolidated Final Report
# =============================================================================
banner "Test Suite – Final Report"

RUN_END_TIME=$(date +%s)
TOTAL_DURATION=$((RUN_END_TIME - RUN_START_TIME))

printf "%-50s  %s\n" "Scenario" "Result"
printf "%s\n" "$(printf '─%.0s' $(seq 1 60))"

printf '%b' "${SCENARIO_RESULTS}" | while IFS='|' read -r _n _nm _res _dur _rest; do
    [ -z "${_n}" ] && continue
    case "${_res}" in
        PASS) _colour="${GREEN}" ;;
        FAIL) _colour="${RED}" ;;
        SKIP) _colour="${YELLOW}" ;;
        *)    _colour="${YELLOW}" ;;
    esac
    printf "  %02d. %-45s  ${_colour}%-6s${NC}  (%ss)\n" \
           "${_n}" "${_nm}" "${_res}" "${_dur:-0}"
done

printf "\n"
printf "Total scenarios : %d\n" "${TOTAL_SCENARIOS}"
printf "${GREEN}Passed          : %d${NC}\n" "${PASS_SCENARIOS}"
if [ "${FAIL_SCENARIOS}" -gt 0 ]; then
    printf "${RED}Failed          : %d${NC}\n" "${FAIL_SCENARIOS}"
else
    printf "Failed          : 0\n"
fi
if [ "${SKIP_SCENARIOS_COUNT}" -gt 0 ]; then
    printf "${YELLOW}Skipped         : %d${NC}\n" "${SKIP_SCENARIOS_COUNT}"
fi
printf "Total duration  : %ds\n" "${TOTAL_DURATION}"
printf "\nFull log        : %s\n" "${REPORT_FILE}"

# Write final summary to report file.
{
    printf "\n=%.0s" $(seq 1 70); printf "\n"
    printf "FINAL SUMMARY\n"
    printf "Finished  : %s\n" "$(date '+%Y-%m-%d %H:%M:%S')"
    printf "Duration  : %ds\n" "${TOTAL_DURATION}"
    printf "Passed    : %d / %d\n" "${PASS_SCENARIOS}" "${TOTAL_SCENARIOS}"
    printf "Failed    : %d\n" "${FAIL_SCENARIOS}"
    printf "Skipped   : %d\n" "${SKIP_SCENARIOS_COUNT}"
} >> "${REPORT_FILE}"

# Write JSON summary.
_end_ts=$(date +%s)
_total_dur=$((_end_ts - RUN_START_TIME))
cat > "${SUMMARY_FILE}" <<JSON
{
  "run_timestamp": "${TIMESTAMP}",
  "target": "${BASE_URL}",
  "total_duration_s": ${_total_dur},
  "scenarios": {
    "total": ${TOTAL_SCENARIOS},
    "passed": ${PASS_SCENARIOS},
    "failed": ${FAIL_SCENARIOS},
    "skipped": ${SKIP_SCENARIOS_COUNT}
  }
}
JSON
printf "JSON summary    : %s\n\n" "${SUMMARY_FILE}"

# Final exit code.
if [ "${FAIL_SCENARIOS}" -eq 0 ]; then
    printf "${GREEN}${BOLD}ALL SCENARIOS PASSED.${NC}\n"
    exit 0
else
    printf "${RED}${BOLD}%d SCENARIO(S) FAILED – review the report for details.${NC}\n" \
           "${FAIL_SCENARIOS}"
    exit 1
fi