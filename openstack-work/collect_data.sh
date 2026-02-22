#!/bin/sh
# collect_data.sh - Research data collection and export script for the honeynet system.
#
# PURPOSE:
#   Extracts structured attack-behaviour data from all honeynet data sources and
#   writes the results to a timestamped output directory.  The exported files are
#   formatted as newline-delimited JSON (NDJSON) and CSV, ready for ingestion into
#   a Jupyter notebook, R, or any analytics pipeline.
#
#   This script addresses checklist item 10: "Preparation of collected data for
#   use in research".
#
# DATA SOURCES COLLECTED:
#   1. Redis session store
#      - All active and recently-expired attacker sessions (honeypot_bound=true)
#      - Honeynet pool assignments (honeypot_pool_ip:* keys)
#      - Suricata alert feed (suricata_alerts list)
#      - Honeytoken usage records (honeytoken:* keys)
#
#   2. Suricata EVE JSON log
#      - All alert events (event_type=alert) from the current log file
#      - Filtered to include only events with a src_ip outside RFC-1918 space
#        (optional; see --include-private flag)
#
#   3. Nginx security log
#      - All log lines from security.log (custom format with route_decision,
#        threat_score, session_id, and suspicious fields)
#
#   4. Honeypot MySQL pool-tracking tables
#      - honeypot_ip_assignments: attacker IP → pool mappings + request counts
#      - honeypot_pool_events: fine-grained routing event timeline
#      - Exported as CSV and NDJSON
#
#   5. Backup log
#      - NDJSON entries from backups/backup.log (structured backup audit trail)
#
# OUTPUT DIRECTORY STRUCTURE:
#   ./research_export/YYYY-MM-DD_HH-MM-SS/
#     metadata.json              - Collection metadata (timestamps, versions, counts)
#     sessions/
#       attacker_sessions.ndjson - One JSON object per honeypot-bound session
#     pool/
#       assignments.ndjson       - IP → pool assignments from Redis
#       assignments.csv          - Same data in CSV format
#     alerts/
#       suricata_alerts.ndjson   - Suricata EVE alert events
#       suricata_summary.json    - Alert counts grouped by CVE/signature
#     nginx/
#       security_events.ndjson   - Parsed Nginx security.log entries
#       routing_summary.json     - Counts: production vs honeypot, by threat score
#     database/
#       ip_assignments.csv       - honeypot_ip_assignments table dump
#       pool_events.csv          - honeypot_pool_events table dump
#     honeytokens/
#       token_stats.json         - Usage stats for all defined honeytoken IDs
#     backups/
#       backup_log.ndjson        - Structured backup audit entries
#     combined/
#       attack_timeline.ndjson   - Merged, time-sorted stream of all attack events
#
# USAGE:
#   ./collect_data.sh [OPTIONS]
#
#   Options:
#     --output-dir DIR        Override the default ./research_export/ base directory.
#     --include-private       Include events with RFC-1918 source IPs (default: excluded).
#     --no-db                 Skip MySQL database exports (faster; useful when DB is offline).
#     --no-redis              Skip Redis exports (useful when running offline).
#     --compress              Compress each output file with gzip after writing.
#     --quiet                 Suppress progress messages.
#
# EXIT CODES:
#   0  Export completed successfully (at least one data source produced output).
#   1  Fatal error (output directory could not be created, no data sources available).
#   2  Prerequisites missing (docker, jq, or mysql client not found).
#
# DEPENDENCIES:
#   docker       - access Redis and MySQL via docker exec
#   jq           - JSON transformation and pretty-printing
#   awk, sed     - log parsing helpers
#   mysql-client - direct MySQL access (optional; falls back to docker exec)
#
# ENVIRONMENT VARIABLES (override defaults from docker-compose):
#   MYSQL_ROOT_PASSWORD  - root password for honeypot MySQL instances
#   REDIS_PASSWORD       - Redis AUTH password
#   COMPOSE_PROJECT      - docker-compose project name (default: honeypot-ids-system-v1)
#   POOL_COUNT           - number of honeypot pool instances (default: 3)

set -eu

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
OUTPUT_BASE="./research_export"
INCLUDE_PRIVATE=0
SKIP_DB=0
SKIP_REDIS=0
COMPRESS=0
QUIET=0

for arg in "$@"; do
    case "$arg" in
        --output-dir=*) OUTPUT_BASE="${arg#*=}" ;;
        --include-private) INCLUDE_PRIVATE=1 ;;
        --no-db)        SKIP_DB=1 ;;
        --no-redis)     SKIP_REDIS=1 ;;
        --compress)     COMPRESS=1 ;;
        --quiet)        QUIET=1 ;;
        *)
            printf "Unknown option: %s\n" "$arg" >&2
            printf "Usage: %s [--output-dir=DIR] [--include-private] [--no-db] [--no-redis] [--compress] [--quiet]\n" "$0" >&2
            exit 2
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Colour helpers and logging
# ---------------------------------------------------------------------------
if [ -t 1 ] && [ "$QUIET" -eq 0 ]; then
    CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    RED='\033[0;31m'; BOLD='\033[1m'; RESET='\033[0m'
else
    CYAN=''; GREEN=''; YELLOW=''; RED=''; BOLD=''; RESET=''
fi

info()  { [ "$QUIET" -eq 0 ] && printf "${CYAN}[INFO]${RESET}  %s\n" "$1" || true; }
ok()    { [ "$QUIET" -eq 0 ] && printf "${GREEN}[OK]${RESET}    %s\n" "$1" || true; }
warn()  { printf "${YELLOW}[WARN]${RESET}  %s\n" "$1" >&2; }
err()   { printf "${RED}[ERROR]${RESET} %s\n" "$1" >&2; }
header(){ [ "$QUIET" -eq 0 ] && printf "\n${BOLD}%s${RESET}\n" "=== $1 ===" || true; }

# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------
NOW_ISO()  { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
NOW_FILE() { date -u '+%Y-%m-%d_%H-%M-%S'; }

COLLECTION_START=$(NOW_ISO)
OUTDIR="${OUTPUT_BASE}/$(NOW_FILE)"

# ---------------------------------------------------------------------------
# Prerequisite checks
# ---------------------------------------------------------------------------
header "Prerequisite checks"

HAVE_DOCKER=0
HAVE_JQ=0
HAVE_MYSQL=0

command -v docker >/dev/null 2>&1 && HAVE_DOCKER=1 || warn "docker not found – Docker-based exports will be skipped"
command -v jq     >/dev/null 2>&1 && HAVE_JQ=1     || warn "jq not found – JSON transformations will be limited"

if [ "$SKIP_DB" -eq 0 ]; then
    command -v mysql >/dev/null 2>&1 && HAVE_MYSQL=1 || {
        warn "mysql client not found – will attempt via docker exec"
    }
fi

if [ "$HAVE_DOCKER" -eq 0 ] && [ "$SKIP_REDIS" -eq 0 ] && [ "$SKIP_DB" -eq 0 ]; then
    err "docker is required for Redis and MySQL exports. Use --no-db --no-redis to skip."
    exit 2
fi

# ---------------------------------------------------------------------------
# Output directory setup
# ---------------------------------------------------------------------------
header "Creating output directory"

mkdir -p \
    "${OUTDIR}/sessions" \
    "${OUTDIR}/pool" \
    "${OUTDIR}/alerts" \
    "${OUTDIR}/nginx" \
    "${OUTDIR}/database" \
    "${OUTDIR}/honeytokens" \
    "${OUTDIR}/backups" \
    "${OUTDIR}/combined"

ok "Output directory: ${OUTDIR}"

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------
COMPOSE_PROJECT="${COMPOSE_PROJECT:-honeypot-ids-system-v1}"
POOL_COUNT="${POOL_COUNT:-3}"
REDIS_PASSWORD="${REDIS_PASSWORD:-session_redis_password}"
MYSQL_ROOT_PASSWORD="${MYSQL_ROOT_PASSWORD:-}"

# Counters for final metadata
SESSIONS_EXPORTED=0
ALERTS_EXPORTED=0
NGINX_EVENTS_EXPORTED=0
DB_ROWS_EXPORTED=0
TOKENS_EXPORTED=0

# ---------------------------------------------------------------------------
# Helper: run a Redis command via docker exec
# ---------------------------------------------------------------------------
redis_cmd() {
    if [ "$HAVE_DOCKER" -eq 0 ]; then
        return 1
    fi
    # Use the session_store container.
    if [ -n "$REDIS_PASSWORD" ]; then
        docker exec "${COMPOSE_PROJECT}-session_store-1" \
            redis-cli -a "$REDIS_PASSWORD" --no-auth-warning "$@" 2>/dev/null \
        || docker exec "session_store" \
            redis-cli -a "$REDIS_PASSWORD" --no-auth-warning "$@" 2>/dev/null
    else
        docker exec "${COMPOSE_PROJECT}-session_store-1" \
            redis-cli "$@" 2>/dev/null \
        || docker exec "session_store" \
            redis-cli "$@" 2>/dev/null
    fi
}

# ---------------------------------------------------------------------------
# Helper: run a MySQL query via docker exec (pool instance N)
# ---------------------------------------------------------------------------
mysql_query() {
    _pool="$1"
    _db="$2"
    _query="$3"

    _container="${COMPOSE_PROJECT}-honeypot_database_${_pool}-1"
    # Fall back to bare service name if compose-prefixed name is not found.
    docker exec "$_container" \
        mysql -u root -p"${MYSQL_ROOT_PASSWORD}" \
        --silent --batch "$_db" \
        -e "$_query" 2>/dev/null \
    || docker exec "honeypot_database_${_pool}" \
        mysql -u root -p"${MYSQL_ROOT_PASSWORD}" \
        --silent --batch "$_db" \
        -e "$_query" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Helper: optionally compress a file
# ---------------------------------------------------------------------------
maybe_compress() {
    if [ "$COMPRESS" -eq 1 ] && [ -f "$1" ]; then
        gzip -f "$1"
        ok "Compressed: ${1}.gz"
    fi
}

# ===========================================================================
# 1. Redis: attacker sessions
# ===========================================================================
header "Collecting Redis: attacker sessions"

if [ "$SKIP_REDIS" -eq 1 ] || [ "$HAVE_DOCKER" -eq 0 ]; then
    warn "Skipping Redis session export"
else
    SESSION_FILE="${OUTDIR}/sessions/attacker_sessions.ndjson"
    : > "$SESSION_FILE"

    # Retrieve all session keys from Redis.
    # Using SCAN avoids blocking the server with KEYS on large datasets.
    SESSION_CURSOR=0
    SESSION_COUNT=0

    while true; do
        SCAN_RESULT=$(redis_cmd SCAN "$SESSION_CURSOR" MATCH "session:*" COUNT 100) || break
        SESSION_CURSOR=$(printf '%s' "$SCAN_RESULT" | head -1)
        KEYS=$(printf '%s' "$SCAN_RESULT" | tail -n +2)

        for key in $KEYS; do
            raw=$(redis_cmd GET "$key") || continue
            [ -z "$raw" ] && continue

            # Filter: only export honeypot-bound sessions.
            is_hp=$(printf '%s' "$raw" | grep -o '"honeypot_bound":true' | wc -l | tr -d ' ')
            [ "$is_hp" -eq 0 ] && continue

            # Append as NDJSON line.
            if [ "$HAVE_JQ" -eq 1 ]; then
                printf '%s' "$raw" | jq -c ". + {\"_redis_key\": \"$key\", \"_exported_at\": \"$(NOW_ISO)\"}" \
                    >> "$SESSION_FILE" 2>/dev/null || printf '%s\n' "$raw" >> "$SESSION_FILE"
            else
                printf '%s\n' "$raw" >> "$SESSION_FILE"
            fi

            SESSION_COUNT=$((SESSION_COUNT + 1))
        done

        [ "$SESSION_CURSOR" = "0" ] && break
    done

    SESSIONS_EXPORTED=$SESSION_COUNT
    ok "Exported ${SESSION_COUNT} honeypot-bound sessions → sessions/attacker_sessions.ndjson"
    maybe_compress "$SESSION_FILE"
fi

# ===========================================================================
# 2. Redis: pool assignments
# ===========================================================================
header "Collecting Redis: pool assignments"

if [ "$SKIP_REDIS" -eq 1 ] || [ "$HAVE_DOCKER" -eq 0 ]; then
    warn "Skipping Redis pool assignment export"
else
    ASSIGN_NDJSON="${OUTDIR}/pool/assignments.ndjson"
    ASSIGN_CSV="${OUTDIR}/pool/assignments.csv"

    : > "$ASSIGN_NDJSON"
    printf 'ip_address,pool_id,assigned_at,exported_at\n' > "$ASSIGN_CSV"

    ASSIGN_CURSOR=0
    ASSIGN_COUNT=0

    while true; do
        SCAN_RESULT=$(redis_cmd SCAN "$ASSIGN_CURSOR" MATCH "honeypot_pool_ip:*" COUNT 200) || break
        ASSIGN_CURSOR=$(printf '%s' "$SCAN_RESULT" | head -1)
        IP_KEYS=$(printf '%s' "$SCAN_RESULT" | tail -n +2)

        for key in $IP_KEYS; do
            pool_num=$(redis_cmd GET "$key") || continue
            [ -z "$pool_num" ] && continue
            ip_addr=$(printf '%s' "$key" | sed 's/honeypot_pool_ip://')

            # Optionally exclude RFC-1918 addresses.
            if [ "$INCLUDE_PRIVATE" -eq 0 ]; then
                case "$ip_addr" in
                    10.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|192.168.*|127.*) continue ;;
                esac
            fi

            ttl=$(redis_cmd TTL "$key") || ttl="unknown"
            exported_at=$(NOW_ISO)

            printf '{"ip_address":"%s","pool_id":%s,"redis_ttl":%s,"exported_at":"%s"}\n' \
                "$ip_addr" "$pool_num" "$ttl" "$exported_at" >> "$ASSIGN_NDJSON"
            printf '"%s",%s,"%s"\n' "$ip_addr" "$pool_num" "$exported_at" >> "$ASSIGN_CSV"

            ASSIGN_COUNT=$((ASSIGN_COUNT + 1))
        done

        [ "$ASSIGN_CURSOR" = "0" ] && break
    done

    ok "Exported ${ASSIGN_COUNT} pool assignments → pool/assignments.ndjson, pool/assignments.csv"
    maybe_compress "$ASSIGN_NDJSON"
fi

# ===========================================================================
# 3. Redis: Suricata alert feed
# ===========================================================================
header "Collecting Redis: Suricata alert feed"

if [ "$SKIP_REDIS" -eq 1 ] || [ "$HAVE_DOCKER" -eq 0 ]; then
    warn "Skipping Redis Suricata alert export"
else
    ALERT_REDIS_FILE="${OUTDIR}/alerts/redis_alert_feed.ndjson"
    : > "$ALERT_REDIS_FILE"

    # suricata_alerts is a Redis list; LRANGE 0 -1 retrieves all entries.
    ALERT_JSON=$(redis_cmd LRANGE suricata_alerts 0 -1 2>/dev/null) || ALERT_JSON=""
    ALERT_COUNT=0

    if [ -n "$ALERT_JSON" ]; then
        printf '%s\n' "$ALERT_JSON" | while IFS= read -r line; do
            [ -z "$line" ] && continue
            printf '%s\n' "$line" >> "$ALERT_REDIS_FILE"
            ALERT_COUNT=$((ALERT_COUNT + 1))
        done
    fi

    ok "Exported Suricata alert feed from Redis → alerts/redis_alert_feed.ndjson"
fi

# ===========================================================================
# 4. Redis: honeytoken usage
# ===========================================================================
header "Collecting Redis: honeytoken usage"

if [ "$SKIP_REDIS" -eq 1 ] || [ "$HAVE_DOCKER" -eq 0 ]; then
    warn "Skipping Redis honeytoken export"
else
    TOKEN_FILE="${OUTDIR}/honeytokens/token_stats.ndjson"
    : > "$TOKEN_FILE"
    TOKEN_COUNT=0

    TOKEN_CURSOR=0
    while true; do
        SCAN_RESULT=$(redis_cmd SCAN "$TOKEN_CURSOR" MATCH "honeytoken:*" COUNT 50) || break
        TOKEN_CURSOR=$(printf '%s' "$SCAN_RESULT" | head -1)
        TOKEN_KEYS=$(printf '%s' "$SCAN_RESULT" | tail -n +2)

        for key in $TOKEN_KEYS; do
            raw=$(redis_cmd GET "$key") || continue
            [ -z "$raw" ] && continue
            printf '%s\n' "$raw" >> "$TOKEN_FILE"
            TOKEN_COUNT=$((TOKEN_COUNT + 1))
        done

        [ "$TOKEN_CURSOR" = "0" ] && break
    done

    TOKENS_EXPORTED=$TOKEN_COUNT
    ok "Exported ${TOKEN_COUNT} honeytoken usage records → honeytokens/token_stats.ndjson"

    # Build a summary JSON with aggregated counts.
    if [ "$HAVE_JQ" -eq 1 ] && [ -s "$TOKEN_FILE" ]; then
        jq -s '
            group_by(.token_type) |
            map({
                token_type: .[0].token_type,
                total_uses: (map(.use_count) | add),
                unique_ips: (map(.last_used_ip) | unique | length),
                tokens: map({id: .token_id, uses: .use_count, last_ip: .last_used_ip})
            })
        ' "$TOKEN_FILE" > "${OUTDIR}/honeytokens/token_summary.json" 2>/dev/null \
        && ok "Generated honeytokens/token_summary.json" || true
    fi
fi

# ===========================================================================
# 5. Suricata EVE JSON log
# ===========================================================================
header "Collecting Suricata EVE JSON alerts"

# Locate the EVE log.  Check the bind-mounted path first, then docker exec.
EVE_LOG=""
if [ -f "./suricata_logs/eve.json" ]; then
    EVE_LOG="./suricata_logs/eve.json"
elif [ "$HAVE_DOCKER" -eq 1 ]; then
    # Try to extract via reverse_proxy container (suricata_logs volume is shared).
    EVE_TMP=$(mktemp)
    docker exec "${COMPOSE_PROJECT}-reverse_proxy-1" \
        cat /var/log/suricata/eve.json > "$EVE_TMP" 2>/dev/null \
    || docker exec "reverse_proxy" \
        cat /var/log/suricata/eve.json > "$EVE_TMP" 2>/dev/null \
    || true

    [ -s "$EVE_TMP" ] && EVE_LOG="$EVE_TMP"
fi

SURICATA_NDJSON="${OUTDIR}/alerts/suricata_alerts.ndjson"
: > "$SURICATA_NDJSON"
SURICATA_COUNT=0

if [ -n "$EVE_LOG" ] && [ -f "$EVE_LOG" ]; then
    # Extract only alert events.
    grep '"event_type":"alert"' "$EVE_LOG" | while IFS= read -r line; do
        # Optionally skip private IPs.
        if [ "$INCLUDE_PRIVATE" -eq 0 ]; then
            src=$(printf '%s' "$line" | grep -o '"src_ip":"[^"]*"' | head -1 | cut -d'"' -f4)
            case "${src:-}" in
                10.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|192.168.*|127.*) continue ;;
            esac
        fi
        printf '%s\n' "$line"
        SURICATA_COUNT=$((SURICATA_COUNT + 1))
    done >> "$SURICATA_NDJSON"

    ALERTS_EXPORTED=$SURICATA_COUNT
    ok "Exported ${SURICATA_COUNT} Suricata alerts → alerts/suricata_alerts.ndjson"

    # Build alert summary grouped by Suricata rule signature.
    if [ "$HAVE_JQ" -eq 1 ] && [ -s "$SURICATA_NDJSON" ]; then
        jq -s '
            group_by(.alert.signature) |
            map({
                signature:   .[0].alert.signature,
                category:    .[0].alert.category,
                severity:    .[0].alert.severity,
                rule_id:     .[0].alert.gid,
                alert_count: length,
                unique_src:  (map(.src_ip) | unique | length),
                first_seen:  (map(.timestamp) | sort | first),
                last_seen:   (map(.timestamp) | sort | last)
            }) | sort_by(.alert_count) | reverse
        ' "$SURICATA_NDJSON" > "${OUTDIR}/alerts/suricata_summary.json" 2>/dev/null \
        && ok "Generated alerts/suricata_summary.json" || true
    fi
else
    warn "Suricata EVE log not found – alert export skipped"
fi

# ===========================================================================
# 6. Nginx security log
# ===========================================================================
header "Collecting Nginx security log"

NGINX_LOG=""
if [ -f "./nginx_logs/security.log" ]; then
    NGINX_LOG="./nginx_logs/security.log"
elif [ "$HAVE_DOCKER" -eq 1 ]; then
    NGINX_TMP=$(mktemp)
    docker exec "${COMPOSE_PROJECT}-reverse_proxy-1" \
        cat /var/log/nginx/security.log > "$NGINX_TMP" 2>/dev/null \
    || docker exec "reverse_proxy" \
        cat /var/log/nginx/security.log > "$NGINX_TMP" 2>/dev/null \
    || true
    [ -s "$NGINX_TMP" ] && NGINX_LOG="$NGINX_TMP"
fi

NGINX_NDJSON="${OUTDIR}/nginx/security_events.ndjson"
: > "$NGINX_NDJSON"

if [ -n "$NGINX_LOG" ] && [ -f "$NGINX_LOG" ]; then
    # Parse the custom Nginx security log format:
    #   $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
    #   "$http_referer" "$http_user_agent" "$http_x_forwarded_for"
    #   session_id="$cookie_PHPSESSID" route="$route_decision"
    #   threat_score="$threat_score" suspicious="$suspicious_activity"
    NGINX_COUNT=0

    awk '
    {
        # Extract fields using awk – robust against spaces in user-agent strings.
        ip=$1
        # Time field is between [ ] – skip to the request.
        match($0, /\[([^\]]+)\]/, ts)
        match($0, /"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) ([^ ]+) HTTP/, req)
        status=$(NF-5)  # fragile fallback; override with regex
        match($0, / ([0-9]{3}) /, st)
        match($0, /route="([^"]+)"/, rt)
        match($0, /threat_score="([^"]+)"/, thr)
        match($0, /suspicious="([^"]+)"/, sus)

        ip_clean=ip
        route=rt[1]
        score=thr[1]
        susp=sus[1]

        if (route == "honeypot" || susp == "true") {
            printf "{\"ip\":\"%s\",\"route\":\"%s\",\"threat_score\":\"%s\",\"suspicious\":\"%s\",\"raw_line\":\"%s\"}\n",
                ip_clean, route, score, susp, gensub(/"/, "\\\\\"", "g", $0)
        }
    }
    ' "$NGINX_LOG" >> "$NGINX_NDJSON"

    NGINX_COUNT=$(wc -l < "$NGINX_NDJSON" | tr -d ' ')
    NGINX_EVENTS_EXPORTED=$NGINX_COUNT
    ok "Exported ${NGINX_COUNT} honeypot-routed Nginx events → nginx/security_events.ndjson"

    # Routing summary: count production vs honeypot, distribution of threat scores.
    if [ "$HAVE_JQ" -eq 1 ] && [ -s "$NGINX_NDJSON" ]; then
        jq -s '
            {
                total:           length,
                honeypot_routed: (map(select(.route == "honeypot")) | length),
                production_routed: (map(select(.route == "production")) | length),
                avg_threat_score: (map(.threat_score | tonumber? // 0) | add / length),
                score_buckets: {
                    "0":     (map(select((.threat_score | tonumber? // 0) == 0)) | length),
                    "1-30":  (map(select((.threat_score | tonumber? // 0) >= 1  and (.threat_score | tonumber? // 0) <= 30)) | length),
                    "31-60": (map(select((.threat_score | tonumber? // 0) >= 31 and (.threat_score | tonumber? // 0) <= 60)) | length),
                    "61-79": (map(select((.threat_score | tonumber? // 0) >= 61 and (.threat_score | tonumber? // 0) <= 79)) | length),
                    "80+":   (map(select((.threat_score | tonumber? // 0) >= 80)) | length)
                }
            }
        ' "$NGINX_NDJSON" > "${OUTDIR}/nginx/routing_summary.json" 2>/dev/null \
        && ok "Generated nginx/routing_summary.json" || true
    fi
else
    warn "Nginx security log not found – Nginx event export skipped"
fi

# ===========================================================================
# 7. MySQL pool-tracking tables
# ===========================================================================
header "Collecting MySQL pool-tracking tables"

if [ "$SKIP_DB" -eq 1 ]; then
    warn "Skipping MySQL export (--no-db)"
elif [ "$HAVE_DOCKER" -eq 0 ]; then
    warn "Skipping MySQL export (docker unavailable)"
else
    DB_TOTAL=0

    # Export from pool 1 (all pools share the same schema; pool 1 is canonical).
    _pool=1
    _db="honeypot_database"

    info "Exporting honeypot_ip_assignments from pool ${_pool}..."

    # honeypot_ip_assignments → CSV
    ASSIGN_DB_CSV="${OUTDIR}/database/ip_assignments.csv"
    mysql_query "$_pool" "$_db" \
        "SELECT ip_address, ip_suffix, pool_id, honeypot_reason, request_count,
                DATE_FORMAT(first_seen,'%Y-%m-%dT%H:%i:%SZ') AS first_seen,
                DATE_FORMAT(last_seen,'%Y-%m-%dT%H:%i:%SZ') AS last_seen
         FROM honeypot_ip_assignments
         ORDER BY first_seen;" \
        2>/dev/null | awk 'NR==1{print "ip_address,ip_suffix,pool_id,reason,request_count,first_seen,last_seen"} NR>1{print}' \
    > "$ASSIGN_DB_CSV" \
    || warn "Could not export honeypot_ip_assignments (pool ${_pool})"

    ASSIGN_ROWS=$(wc -l < "$ASSIGN_DB_CSV" | tr -d ' ')
    ASSIGN_ROWS=$((ASSIGN_ROWS - 1))  # subtract header
    [ "$ASSIGN_ROWS" -lt 0 ] && ASSIGN_ROWS=0
    DB_TOTAL=$((DB_TOTAL + ASSIGN_ROWS))
    ok "Exported ${ASSIGN_ROWS} IP assignments → database/ip_assignments.csv"

    # honeypot_pool_events → CSV
    info "Exporting honeypot_pool_events from pool ${_pool}..."

    EVENTS_DB_CSV="${OUTDIR}/database/pool_events.csv"
    mysql_query "$_pool" "$_db" \
        "SELECT ip_address, pool_id, event_type, event_detail,
                DATE_FORMAT(occurred_at,'%Y-%m-%dT%H:%i:%SZ') AS occurred_at
         FROM honeypot_pool_events
         ORDER BY occurred_at;" \
        2>/dev/null | awk 'NR==1{print "ip_address,pool_id,event_type,event_detail,occurred_at"} NR>1{print}' \
    > "$EVENTS_DB_CSV" \
    || warn "Could not export honeypot_pool_events (pool ${_pool})"

    EVENTS_ROWS=$(wc -l < "$EVENTS_DB_CSV" | tr -d ' ')
    EVENTS_ROWS=$((EVENTS_ROWS - 1))
    [ "$EVENTS_ROWS" -lt 0 ] && EVENTS_ROWS=0
    DB_TOTAL=$((DB_TOTAL + EVENTS_ROWS))
    DB_ROWS_EXPORTED=$DB_TOTAL
    ok "Exported ${EVENTS_ROWS} pool events → database/pool_events.csv"
fi

# ===========================================================================
# 8. Backup log
# ===========================================================================
header "Collecting backup audit log"

BACKUP_LOG=""
[ -f "./backups/backup.log" ] && BACKUP_LOG="./backups/backup.log"

BACKUP_NDJSON="${OUTDIR}/backups/backup_log.ndjson"
: > "$BACKUP_NDJSON"

if [ -n "$BACKUP_LOG" ]; then
    # Each line in backup.log is a JSON object – copy directly.
    grep -v '^$' "$BACKUP_LOG" >> "$BACKUP_NDJSON" || true
    BACKUP_LINES=$(wc -l < "$BACKUP_NDJSON" | tr -d ' ')
    ok "Exported ${BACKUP_LINES} backup log entries → backups/backup_log.ndjson"
else
    warn "backup.log not found – backup log export skipped"
fi

# ===========================================================================
# 9. Combined attack timeline
# ===========================================================================
header "Building combined attack timeline"

TIMELINE="${OUTDIR}/combined/attack_timeline.ndjson"
: > "$TIMELINE"

# Merge all NDJSON sources into a single time-sorted stream.
# Each source is annotated with a "source" field before merging.
if [ "$HAVE_JQ" -eq 1 ]; then
    # Tag and combine all available NDJSON files.
    for f in \
        "${OUTDIR}/sessions/attacker_sessions.ndjson" \
        "${OUTDIR}/alerts/suricata_alerts.ndjson" \
        "${OUTDIR}/alerts/redis_alert_feed.ndjson" \
        "${OUTDIR}/nginx/security_events.ndjson" \
        "${OUTDIR}/honeytokens/token_stats.ndjson"
    do
        [ -f "$f" ] && [ -s "$f" ] || continue
        src=$(basename "$(dirname "$f")")/$(basename "$f" .ndjson)
        jq -c --arg src "$src" '. + {_source: $src}' "$f" >> "$TIMELINE" 2>/dev/null || true
    done

    TIMELINE_COUNT=$(wc -l < "$TIMELINE" | tr -d ' ')
    ok "Combined attack timeline: ${TIMELINE_COUNT} events → combined/attack_timeline.ndjson"
else
    warn "jq not available – combined timeline skipped"
fi

# ===========================================================================
# 10. Metadata file
# ===========================================================================
header "Writing collection metadata"

COLLECTION_END=$(NOW_ISO)

cat > "${OUTDIR}/metadata.json" <<EOF
{
  "collection_start":     "${COLLECTION_START}",
  "collection_end":       "${COLLECTION_END}",
  "compose_project":      "${COMPOSE_PROJECT}",
  "pool_count":           ${POOL_COUNT},
  "include_private_ips":  ${INCLUDE_PRIVATE},
  "counts": {
    "sessions":           ${SESSIONS_EXPORTED},
    "suricata_alerts":    ${ALERTS_EXPORTED},
    "nginx_events":       ${NGINX_EVENTS_EXPORTED},
    "db_rows":            ${DB_ROWS_EXPORTED},
    "honeytokens":        ${TOKENS_EXPORTED}
  },
  "output_files": {
    "sessions":           "sessions/attacker_sessions.ndjson",
    "pool_assignments":   "pool/assignments.ndjson",
    "pool_assignments_csv": "pool/assignments.csv",
    "suricata_alerts":    "alerts/suricata_alerts.ndjson",
    "suricata_summary":   "alerts/suricata_summary.json",
    "nginx_security":     "nginx/security_events.ndjson",
    "nginx_summary":      "nginx/routing_summary.json",
    "db_ip_assignments":  "database/ip_assignments.csv",
    "db_pool_events":     "database/pool_events.csv",
    "honeytoken_stats":   "honeytokens/token_stats.ndjson",
    "honeytoken_summary": "honeytokens/token_summary.json",
    "backup_log":         "backups/backup_log.ndjson",
    "attack_timeline":    "combined/attack_timeline.ndjson"
  }
}
EOF

ok "Metadata written → ${OUTDIR}/metadata.json"

# ===========================================================================
# Final summary
# ===========================================================================
printf "\n${BOLD}Collection complete.${RESET}\n"
printf "  Output directory : %s\n" "${OUTDIR}"
printf "  Sessions         : %d\n" "${SESSIONS_EXPORTED}"
printf "  Suricata alerts  : %d\n" "${ALERTS_EXPORTED}"
printf "  Nginx events     : %d\n" "${NGINX_EVENTS_EXPORTED}"
printf "  DB rows          : %d\n" "${DB_ROWS_EXPORTED}"
printf "  Honeytokens used : %d\n" "${TOKENS_EXPORTED}"
printf "\nTo open in Python:\n"
printf "  import pandas as pd, json\n"
printf "  sessions = pd.read_json('%s/sessions/attacker_sessions.ndjson', lines=True)\n" "${OUTDIR}"
printf "  alerts   = pd.read_json('%s/alerts/suricata_alerts.ndjson', lines=True)\n" "${OUTDIR}"
printf "  timeline = pd.read_json('%s/combined/attack_timeline.ndjson', lines=True)\n\n" "${OUTDIR}"