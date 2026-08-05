#!/bin/sh
# Live audit of production-hardening measures: checks that what's documented
# in README.md is actually in effect right now, the same way
# redis_key_audit.sh does for the Redis schema. Run this after any nginx.conf
# / production-hardening.php / docker-compose.yml change that touches
# hardening, and periodically in general -- this whole script exists because
# several of these measures were silently non-functional for a while this
# session (a stale image, a wrong mysqldump flag, an unimplemented block
# that only existed as a comment) with nothing surfacing it short of manual
# curl testing.
#
# Usage: ./scripts/hardening_audit.sh   (run from openstack-work/, or
#        anywhere -- it cd's to its own directory first)
#
# Exit code: 0 if every check passes, 1 if any check fails.
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR/.."

FAILURES=0
pass() { printf '  [PASS] %s\n' "$1"; }
fail() { printf '  [FAIL] %s\n' "$1"; FAILURES=$((FAILURES + 1)); }

echo "=== Production hardening audit ==="
echo

# ---------------------------------------------------------------------------
# 1. XML-RPC: production must 403 with the nginx-layer message; a request
#    scored as suspicious enough to be honeypot-bound must still reach it.
# ---------------------------------------------------------------------------
echo "-- XML-RPC --"
# NOTE on the nginx-layer check specifically: it's intentionally tested via
# production_eshop directly (WP-layer defense), not through reverse_proxy's
# full routing pipeline. Repeatedly running this script from one IP is
# itself exactly the kind of rapid, repeated, scripted traffic
# threat_analyzer.lua's automation detection is designed to flag -- after
# enough runs the test IP legitimately accumulates enough score to get
# pool-routed to honeypot even with a "clean" User-Agent, which would make
# this check fail without the production-layer defense actually being
# broken. That's the routing system working correctly, not a bug -- but it
# makes the full pipeline a flaky thing to assert "always 403" against in
# a repeatable script. The WP-layer check below is deterministic regardless
# of this script's own call history; the nginx-layer nginx.conf block is
# covered separately by the "production-bound" curl test in README.md §9.3,
# run once by hand rather than in a loop.
XMLRPC_PROD=$(docker compose exec -T production_eshop sh -c "curl -sk -o /dev/null -w '%{http_code}' -X POST -d '<?xml version=\"1.0\"?><methodCall><methodName>system.listMethods</methodName></methodCall>' http://localhost/xmlrpc.php" 2>/dev/null)
if [ "$XMLRPC_PROD" = "403" ]; then
    pass "production xmlrpc.php returns 403 even for system.* introspection methods (WP-layer defense)"
else
    fail "production xmlrpc.php returned $XMLRPC_PROD for system.listMethods, expected 403"
fi

XMLRPC_HONEYPOT=$(docker exec honeypot-ids-system-v1-honeypot_eshop_1-1 sh -c "curl -s -o /dev/null -w '%{http_code}' -X POST -d '<?xml version=\"1.0\"?><methodCall><methodName>system.listMethods</methodName></methodCall>' http://localhost/xmlrpc.php" 2>/dev/null)
if [ "$XMLRPC_HONEYPOT" = "200" ]; then
    pass "honeypot pool xmlrpc.php still fully functional (200) -- attack surface preserved"
else
    fail "honeypot pool xmlrpc.php returned $XMLRPC_HONEYPOT, expected 200 (should NOT be blocked)"
fi
echo

# ---------------------------------------------------------------------------
# 2. Hotlink protection: an image request with a third-party Referer must
#    403; the same request with no Referer must succeed.
# ---------------------------------------------------------------------------
echo "-- Hotlink protection --"
IMG=$(curl -sk "https://127.0.0.1/" | grep -oE 'src="[^"]+\.(png|jpg|jpeg|webp)"' | head -1 | sed 's/src="//;s/"$//')
if [ -n "$IMG" ]; then
    HOTLINK_BLOCKED=$(curl -sk -o /dev/null -w '%{http_code}' "$IMG" -H "Referer: https://evil-hotlinker.example.com/")
    HOTLINK_ALLOWED=$(curl -sk -o /dev/null -w '%{http_code}' "$IMG")
    if [ "$HOTLINK_BLOCKED" = "403" ]; then
        pass "cross-site Referer to an image is blocked (403)"
    else
        fail "cross-site Referer to an image returned $HOTLINK_BLOCKED, expected 403"
    fi
    if [ "$HOTLINK_ALLOWED" = "200" ]; then
        pass "no-Referer image request still succeeds (200)"
    else
        fail "no-Referer image request returned $HOTLINK_ALLOWED, expected 200"
    fi
else
    fail "could not find an image on the homepage to test hotlink protection against"
fi
echo

# ---------------------------------------------------------------------------
# 3. Version fingerprint obfuscation: nginx Server header, WP/WC/Elementor
#    generator meta tags, all on production. Honeypot is deliberately left
#    unchecked here -- it's SUPPOSED to still leak these.
# ---------------------------------------------------------------------------
echo "-- Version fingerprint obfuscation (production) --"
SERVER_HEADER=$(curl -skI "https://127.0.0.1/" | grep -i '^server:' | tr -d '\r')
if echo "$SERVER_HEADER" | grep -qiE "nginx/[0-9]"; then
    fail "Server header discloses a version: $SERVER_HEADER"
else
    pass "Server header has no version ($SERVER_HEADER)"
fi

GEN_TAGS=$(docker compose exec -T production_eshop sh -c "curl -sk http://localhost/ -H 'Host: localhost'" 2>/dev/null | grep -ic "generator")
if [ "$GEN_TAGS" = "0" ]; then
    pass "no <meta name=\"generator\"> tags on production (WordPress/WooCommerce/Elementor all suppressed)"
else
    fail "$GEN_TAGS generator meta tag(s) still present on production"
fi
echo

# ---------------------------------------------------------------------------
# 4. Backup automation: the most recent log entry for each step must be a
#    success, and the newest archives must be non-trivially sized (catches
#    the exact "succeeded but wrote an empty file" failure mode found this
#    session).
# ---------------------------------------------------------------------------
echo "-- Backup automation --"
if [ -f backups/backup.log ]; then
    LAST_DB=$(grep '"step":"db_dump"' backups/backup.log | tail -1)
    if echo "$LAST_DB" | grep -q '"status":"success"'; then
        pass "most recent DB dump step logged success"
    else
        fail "most recent DB dump step did not log success: $LAST_DB"
    fi
else
    fail "backups/backup.log does not exist -- backup_service may never have run"
fi

NEWEST_DB=$(find backups/db -maxdepth 1 -name '*.sql.gz' 2>/dev/null | sort | tail -1)
if [ -n "$NEWEST_DB" ]; then
    DB_SIZE=$(stat -c%s "$NEWEST_DB" 2>/dev/null || stat -f%z "$NEWEST_DB" 2>/dev/null || echo 0)
    if [ "$DB_SIZE" -gt 10240 ]; then
        pass "newest DB dump ($NEWEST_DB) is ${DB_SIZE} bytes -- looks like real data"
    else
        fail "newest DB dump ($NEWEST_DB) is only ${DB_SIZE} bytes -- likely empty/broken (this exact failure mode silently produced 4KB gzip files earlier this session)"
    fi
else
    fail "no DB dump found under backups/db/"
fi
echo

# ---------------------------------------------------------------------------
# 5. Docker container hardening: every WordPress-serving container
#    (production + all 3 honeypot pools) should have capabilities dropped
#    and no-new-privileges set, so a compromise of any one of them can't
#    escalate or pivot.
# ---------------------------------------------------------------------------
echo "-- Docker container containment --"
for c in production_eshop honeypot_eshop_1 honeypot_eshop_2 honeypot_eshop_3; do
    CID="honeypot-ids-system-v1-${c}-1"
    CAPS=$(docker inspect "$CID" --format '{{.HostConfig.CapDrop}}' 2>/dev/null)
    NNP=$(docker inspect "$CID" --format '{{.HostConfig.SecurityOpt}}' 2>/dev/null)
    if echo "$CAPS" | grep -qi "ALL"; then
        pass "$c: capabilities dropped (cap_drop: ALL)"
    else
        fail "$c: cap_drop ALL not set (got: $CAPS) -- container has default Docker capabilities"
    fi
    if echo "$NNP" | grep -qi "no-new-privileges"; then
        pass "$c: no-new-privileges set"
    else
        fail "$c: no-new-privileges not set"
    fi
done
echo

echo "=== Summary: ${FAILURES} failure(s) ==="
exit $([ "$FAILURES" -eq 0 ] && echo 0 || echo 1)
