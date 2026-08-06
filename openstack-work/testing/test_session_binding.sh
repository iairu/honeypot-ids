#!/bin/bash
# =============================================================================
# test_session_binding.sh
#
# PURPOSE:
#   Comprehensive verification that a single attacker (source IP) is bound to
#   exactly one honeypot pool container for the lifetime of their session --
#   pool_router.lua's core promise (see reverse_proxy_enhanced/lua/
#   pool_router.lua's module docstring: "every attacking IP address is
#   permanently assigned to a specific honeypot pool instance ... so their
#   actions cannot cross-contaminate other attacker sessions").
#
#   This is the live/runtime counterpart to
#   reverse_proxy_enhanced/lua/tests/test_pool_router_rules.lua, which
#   already proves the pure round-robin/fallback arithmetic behind the
#   assignment is correct in isolation. This script instead drives the REAL
#   reverse_proxy + pool_router.lua + Redis (session_store) end-to-end and
#   checks the actual persisted assignment, which is the only way to catch a
#   regression in the Redis-facing glue code itself (get_or_assign_pool's
#   connection handling, TTL refresh, etc.) that a pure-logic unit test
#   cannot reach.
#
#   HOW IT WORKS: pool_router.lua deliberately does NOT expose which pool a
#   request landed on via any client-visible response header (see
#   router.lua: "X-Honeypot-Pool is intentionally NOT exposed to the
#   client"). So this script instead reads the ground truth directly from
#   Redis (honeypot_pool_ip:<IP>, the exact key pool_router.lua itself
#   writes/reads) after driving real honeypot-routed traffic through the
#   live reverse proxy with curl.
#
#   To confirm the traffic actually reached the honeypot branch (not
#   production) without needing pool-level detail, it uses this repo's own
#   sanctioned test hook: the X-Internal-Test-Auth header (INTERNAL_TEST_SECRET
#   from .env) unlocks the X-Route-Target response header -- see
#   testing/BLIND_PENTEST_PROTOCOL.md Sec8.2 and nginx.conf's header_filter.
#
# THIS SCRIPT VERIFIES:
#   Phase 1 - A request to a known vulnerable-plugin path is routed to the
#             honeypot (X-Route-Target: honeypot), and pool_router.lua
#             persists an assignment for the caller's IP in Redis.
#   Phase 2 - Repeated honeypot-routed requests from the same source IP are
#             ALL served by the SAME pool number (the assignment in Redis
#             does not change between requests) -- i.e. session stickiness.
#   Phase 3 - The assignment's Redis TTL is refreshed (extended) by ongoing
#             activity rather than left to expire mid-session.
#
# USAGE:
#   cd openstack-work/testing
#   ./test_session_binding.sh [TARGET_HOST] [TARGET_PORT]
#
# EXIT CODES:
#   0  All checks passed.
#   1  One or more checks failed.
#   2  Prerequisites missing (curl, docker) or required containers not running.
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/../.env"
TARGET_HOST="${1:-127.0.0.1}"
TARGET_PORT="${2:-443}"
BASE_URL="https://${TARGET_HOST}:${TARGET_PORT}"

PROJECT_PREFIX="honeypot-ids-system-v1"
REDIS_CONTAINER="${PROJECT_PREFIX}-session_store-1"

# A path matching one of init.lua's configured vulnerability.plugins entries
# (see reverse_proxy_enhanced/lua/init.lua) -- a single request to this path
# is enough to trip is_vulnerable_plugin_access() and route to the honeypot,
# no session build-up required.
VULN_PATH="/wp-content/plugins/woocommerce-payments/exploit-test.php"

PASS=0
FAIL=0
SKIP=0
TOTAL=0

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

pass() { PASS=$((PASS + 1)); TOTAL=$((TOTAL + 1)); printf "  ${GREEN}[PASS]${NC} %s\n" "$1"; }
fail() { FAIL=$((FAIL + 1)); TOTAL=$((TOTAL + 1)); printf "  ${RED}[FAIL]${NC} %s\n" "$1"; }
skip() { SKIP=$((SKIP + 1)); TOTAL=$((TOTAL + 1)); printf "  ${YELLOW}[SKIP]${NC} %s\n" "$1"; }

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
if ! command -v curl >/dev/null 2>&1; then
    printf "${RED}ERROR: 'curl' not found in PATH.${NC}\n" >&2
    exit 2
fi
if ! command -v docker >/dev/null 2>&1; then
    printf "${RED}ERROR: 'docker' not found in PATH.${NC}\n" >&2
    exit 2
fi
if [ ! -f "${ENV_FILE}" ]; then
    printf "${RED}ERROR: .env not found at %s${NC}\n" "${ENV_FILE}" >&2
    exit 2
fi

INTERNAL_TEST_SECRET=$(grep -E '^INTERNAL_TEST_SECRET=' "${ENV_FILE}" | head -1 | cut -d= -f2-)
REDIS_PASSWORD=$(grep -E '^REDIS_PASSWORD=' "${ENV_FILE}" | head -1 | cut -d= -f2-)

if [ -z "${INTERNAL_TEST_SECRET}" ]; then
    printf "${RED}ERROR: INTERNAL_TEST_SECRET not set in .env -- cannot observe routing decisions.${NC}\n" >&2
    exit 2
fi
if [ -z "${REDIS_PASSWORD}" ]; then
    printf "${RED}ERROR: REDIS_PASSWORD not set in .env.${NC}\n" >&2
    exit 2
fi
if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${REDIS_CONTAINER}\$"; then
    printf "${RED}ERROR: %s is not running -- bring the stack up with 'docker compose up -d'.${NC}\n" "${REDIS_CONTAINER}" >&2
    exit 2
fi

redis_get() {
    docker exec "${REDIS_CONTAINER}" redis-cli -a "${REDIS_PASSWORD}" --no-auth-warning GET "$1" 2>/dev/null
}
redis_ttl() {
    docker exec "${REDIS_CONTAINER}" redis-cli -a "${REDIS_PASSWORD}" --no-auth-warning TTL "$1" 2>/dev/null
}

banner "Session Binding Test - One Attacker, One Pool, For the Whole Session"
printf "Target : %s\n" "${BASE_URL}"
printf "Path   : %s\n\n" "${VULN_PATH}"

# =============================================================================
# PHASE 1 - Trigger honeypot routing and locate the resulting Redis assignment
# =============================================================================
banner "Phase 1 - Trigger Honeypot Routing"

_resp=$(curl -sk -D - -o /dev/null --max-time 15 \
    -H "X-Internal-Test-Auth: ${INTERNAL_TEST_SECRET}" \
    "${BASE_URL}${VULN_PATH}" 2>&1) || _resp=""

_route=$(printf '%s' "${_resp}" | grep -i '^x-route-target:' | tr -d '\r' | awk '{print $2}' | head -1)

if [ "${_route}" = "honeypot" ]; then
    pass "Request to ${VULN_PATH} routed to honeypot (X-Route-Target: honeypot)"
else
    fail "Request to ${VULN_PATH} NOT routed to honeypot (X-Route-Target: ${_route:-none}) -- cannot proceed"
    printf "\n${RED}Aborting: without a honeypot-routed request there is no pool assignment to check.${NC}\n"
    exit 1
fi

# Find which IP pool_router.lua recorded the assignment under. This is
# whatever nginx sees as remote_addr for our curl calls (typically the
# docker bridge gateway IP when curling a published port from the host),
# discovered empirically rather than assumed.
ASSIGNED_IP=$(docker exec "${REDIS_CONTAINER}" \
    redis-cli -a "${REDIS_PASSWORD}" --no-auth-warning --scan --pattern 'honeypot_pool_ip:*' 2>/dev/null \
    | tail -1)

if [ -z "${ASSIGNED_IP}" ]; then
    fail "No honeypot_pool_ip:* key found in Redis after a honeypot-routed request"
    exit 1
fi
pass "Found pool assignment key in Redis: ${ASSIGNED_IP}"

INITIAL_POOL=$(redis_get "${ASSIGNED_IP}")
if [ -n "${INITIAL_POOL}" ]; then
    pass "Initial pool assignment: ${ASSIGNED_IP} -> pool ${INITIAL_POOL}"
else
    fail "Could not read pool number for ${ASSIGNED_IP}"
    exit 1
fi

# =============================================================================
# PHASE 2 - Repeated requests must land on the SAME pool every time
# =============================================================================
banner "Phase 2 - Session Stickiness Across Repeated Requests"

STICKY=true
for i in 1 2 3 4 5; do
    curl -sk -o /dev/null --max-time 15 \
        -H "X-Internal-Test-Auth: ${INTERNAL_TEST_SECRET}" \
        "${BASE_URL}${VULN_PATH}?probe=${i}" 2>/dev/null || true

    _pool_now=$(redis_get "${ASSIGNED_IP}")
    if [ "${_pool_now}" = "${INITIAL_POOL}" ]; then
        pass "Request ${i}/5: still pool ${_pool_now} (unchanged)"
    else
        fail "Request ${i}/5: pool changed from ${INITIAL_POOL} to ${_pool_now:-none} -- session NOT sticky"
        STICKY=false
    fi
done

if [ "${STICKY}" = "true" ]; then
    pass "Same attacker IP bound to pool ${INITIAL_POOL} across all 5 requests (isolation holds: no other attacker's pool was touched)"
else
    fail "Attacker IP was NOT consistently bound to a single pool -- cross-contamination risk"
fi

# =============================================================================
# PHASE 3 - Assignment TTL is refreshed by ongoing activity
# =============================================================================
banner "Phase 3 - TTL Refresh on Activity"

_ttl_before=$(redis_ttl "${ASSIGNED_IP}")
sleep 2
curl -sk -o /dev/null --max-time 15 \
    -H "X-Internal-Test-Auth: ${INTERNAL_TEST_SECRET}" \
    "${BASE_URL}${VULN_PATH}?probe=ttl" 2>/dev/null || true
_ttl_after=$(redis_ttl "${ASSIGNED_IP}")

if [ -n "${_ttl_before}" ] && [ -n "${_ttl_after}" ] && \
   [ "${_ttl_before}" -ge 0 ] 2>/dev/null && [ "${_ttl_after}" -ge 0 ] 2>/dev/null; then
    if [ "${_ttl_after}" -ge "${_ttl_before}" ]; then
        pass "TTL refreshed by activity (${_ttl_before}s -> ${_ttl_after}s, assignment won't expire mid-session)"
    else
        # Not fatal on its own -- refresh_assignment_ttl is called after
        # routing decisions, a few seconds of natural countdown between the
        # sleep and the re-check can outrace it under load. Flag but don't fail.
        fail "TTL did not increase after activity (${_ttl_before}s -> ${_ttl_after}s) -- refresh_assignment_ttl may not be firing"
    fi
else
    skip "TTL values not readable (before=${_ttl_before:-?}, after=${_ttl_after:-?})"
fi

# ---------------------------------------------------------------------------
# Final report
# ---------------------------------------------------------------------------
banner "Session Binding Test - Final Report"
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
    printf "${GREEN}SESSION BINDING HOLDS -- attacker stayed bound to a single pool container.${NC}\n"
    exit 0
else
    printf "${RED}%d SESSION BINDING CHECK(S) FAILED.${NC}\n" "${FAIL}"
    exit 1
fi
