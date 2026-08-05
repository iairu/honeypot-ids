#!/bin/sh
# Live audit of the session_store Redis keyspace, grouped by the prefixes
# documented in README.md §3.5 ("Session, Redis & IP-based state"). Run this
# after an attack test (or periodically in production) to check the live
# keyspace still matches what's documented -- catches the exact kind of
# drift that made the schema only discoverable by grepping ~10 Lua files
# in the first place.
#
# Usage: ./scripts/redis_key_audit.sh   (run from openstack-work/, or from
#        anywhere -- it cd's to its own directory first)
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR/.."

if [ -f .env ]; then
  REDIS_PASSWORD=$(grep -E '^REDIS_PASSWORD=' .env | tail -n1 | cut -d= -f2-)
fi
: "${REDIS_PASSWORD:?REDIS_PASSWORD not set -- check .env}"

redis() {
  docker compose exec -T session_store redis-cli -a "$REDIS_PASSWORD" --no-auth-warning "$@"
}

if ! redis ping >/dev/null 2>&1; then
  echo "ERROR: cannot reach session_store's Redis (is the stack up? 'docker compose up -d session_store')" >&2
  exit 1
fi

# Documented prefixes from README.md §3.5. Exact keys (no trailing '*') are
# matched literally; everything else is a SCAN MATCH pattern.
DOCUMENTED_PATTERNS="
session:*
active_sessions
compromised_sessions
threat_ips
honeytoken:*
honeypot_pool_ip:*
honeypot_pool:counter
admin_access_logs
vulnerability_events
vulnerability_scans
cve:*
vuln_by_ip:*
vuln_stats
suspicious_uploads
suricata_alerts
suricata_log_position
"

total_keys=$(redis dbsize | tr -d '\r')
echo "=== Redis key audit (session_store) === (total keys: $total_keys)"
echo

accounted_for=0
for pattern in $DOCUMENTED_PATTERNS; do
  keys=$(redis --scan --pattern "$pattern" 2>/dev/null | tr -d '\r')
  count=$(printf '%s\n' "$keys" | grep -c . || true)
  accounted_for=$((accounted_for + count))

  printf '%-28s count=%-6s' "$pattern" "$count"
  if [ "$count" -gt 0 ]; then
    sample=$(printf '%s\n' "$keys" | head -n1)
    type=$(redis type "$sample" | tr -d '\r')
    ttl=$(redis ttl "$sample" | tr -d '\r')
    case "$ttl" in
      -1) ttl_desc="no expiry" ;;
      -2) ttl_desc="gone" ;;
      *) ttl_desc="${ttl}s left" ;;
    esac
    printf ' type=%-8s sample-ttl=%s  e.g. %s\n' "$type" "$ttl_desc" "$sample"
  else
    printf '\n'
  fi
done

echo
all_keys=$(redis --scan 2>/dev/null | tr -d '\r')
undocumented=""
for k in $all_keys; do
  matched=0
  for pattern in $DOCUMENTED_PATTERNS; do
    case "$pattern" in
      *'*') prefix=${pattern%\*}; case "$k" in "$prefix"*) matched=1 ;; esac ;;
      *) [ "$k" = "$pattern" ] && matched=1 ;;
    esac
    [ "$matched" -eq 1 ] && break
  done
  [ "$matched" -eq 0 ] && undocumented="$undocumented$k
"
done

if [ -n "$undocumented" ]; then
  echo "=== Keys present but NOT in README.md §3.5's documented schema ==="
  printf '%s' "$undocumented"
  echo
  echo "(This means either the schema doc is now stale, or something new got added -- update README.md §3.5 to match.)"
else
  echo "No undocumented keys found -- live keyspace matches README.md §3.5."
fi
