#!/bin/bash
# replicate_content_to_honeypot.sh - Periodically mirrors production's
# content (pages, posts, products, and the taxonomy/media metadata that
# renders them) into each honeypot pool database, so a honeypot never
# silently goes stale relative to the real site.
#
# Run by the `honeypot_content_sync` service (docker-compose.yml) in a
# `while true` loop, once every REPLICATION_INTERVAL_SECONDS.
#
# WHAT GETS REPLICATED (deliberately a strict allow-list, not "everything"):
#   wp_posts        - post_type IN (page, post, product, product_variation,
#                      attachment), post_status IN (publish, inherit)
#   wp_postmeta     - scoped to the post IDs above (prices, SKUs, attachment
#                      metadata / _thumbnail_id, ...)
#   wp_term_relationships - scoped to the post IDs above (category/tag/
#                      product_cat assignments)
#   wp_terms, wp_term_taxonomy - copied in full each cycle (small reference
#                      tables; REPLACE INTO, not scoped -- see below)
#   wp_wc_product_meta_lookup  - scoped to the product IDs above, only if the
#                      table exists (WooCommerce-version-dependent)
#
# NEVER REPLICATED, ON PURPOSE: wp_users, wp_usermeta, or any WooCommerce
# order/customer/payment table (wp_wc_orders*, wp_woocommerce_order_*,
# wp_wc_customer_lookup, wp_woocommerce_payment_tokens*, wp_woocommerce_api_keys,
# wp_woocommerce_sessions, ...). Real customer/order data must never reach a
# honeypot database -- this is the same principle
# honeypot_database_migrations/01_clean-honeypot-data.sql already enforces
# for the one-time initial seed; this script must not reintroduce it on an
# ongoing basis. The table list above is an allow-list, not a "copy
# everything except" list, specifically so a schema change on production
# can't accidentally start leaking a new sensitive table here.
#
# ZERO-DOWNTIME / NON-DESTRUCTIVE APPLY STRATEGY:
#   Never DROP/recreate a table (that's what would actually cause visible
#   downtime on a honeypot pool's live DB, mid-attacker-session). Instead:
#     - wp_posts/wp_postmeta/wp_term_relationships/wp_wc_product_meta_lookup:
#       DELETE rows scoped to the EXACT production ID set, then INSERT fresh
#       copies of those same rows, all in one short transaction. Scoped
#       deletes mean anything an attacker added (their own posts, uploaded-
#       shell metadata, unrelated rows) is never touched -- same "never
#       destroy evidence" principle docker-compose.yml's init_setup already
#       documents for its file-sync step.
#     - wp_terms/wp_term_taxonomy: REPLACE INTO the full current production
#       content, no delete/scoping -- same non-destructive add/update-only
#       pattern init_setup's sync_files() already uses for files.
#   The production-side read uses --single-transaction so it never locks
#   production tables either.
#
# EXPLOIT GATING (coordinates with pool_router.lua's is_pool_healthy()):
#   Around each pool's own apply step, this script sets/clears a short-TTL
#   Redis flag (honeypot_pool_replicating:<N>). init_worker.lua mirrors that
#   into the shared dict pool_router.lua's is_pool_healthy() already reads,
#   so a pool mid-replication is transparently skipped for NEW attacker
#   assignments (via the existing unhealthy-pool failover path) and
#   already-bound attackers on that pool are transparently served by another
#   pool for the few seconds the sync takes -- no new blocking logic, no
#   dropped connections. See pool_router.lua for the other half of this.
#
# Pools are replicated ONE AT A TIME, never concurrently, so at least 2 of 3
# pools are always fully available throughout every cycle.

set -eu

MYSQL_USER="production_user"
MYSQL_DATABASE="production_database"
PROD_HOST="production_database"

POOL_HOSTS="honeypot_database_1 honeypot_database_2 honeypot_database_3"
POOL_NUMS="1 2 3"

REDIS_HOST="${REDIS_HOST:-session_store}"
REPLICATION_INTERVAL_SECONDS="${REPLICATION_INTERVAL_SECONDS:-300}"

WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

log() {
    echo "[content-sync $(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"
}

# Pool number -> that pool's own DB user password (pool 1 shares
# MYSQL_PASSWORD with production; pools 2/3 were rotated to their own
# password by honeypot_db_migration -- see docker-compose.yml).
pool_password() {
    case "$1" in
        1) echo "$MYSQL_PASSWORD" ;;
        2) echo "$MYSQL_PASSWORD_POOL_2" ;;
        3) echo "$MYSQL_PASSWORD_POOL_3" ;;
    esac
}

pool_host() {
    case "$1" in
        1) echo "honeypot_database_1" ;;
        2) echo "honeypot_database_2" ;;
        3) echo "honeypot_database_3" ;;
    esac
}

# Deliberately never fatal (the caller does NOT need `|| true`): losing this
# flag for one cycle only means pool_router.lua's is_pool_healthy() keeps
# treating the pool as healthy during its replication window (its documented
# default for missing data) -- a missed optimization, not a correctness
# problem -- and must never be allowed to abort the whole sync cycle over a
# transient Redis hiccup.
redis_set_replicating() {
    redis-cli -h "$REDIS_HOST" -a "$REDIS_PASSWORD" --no-auth-warning \
        SET "honeypot_pool_replicating:$1" 1 EX 30 >/dev/null \
        || log "pool $1: could not set replicating flag in Redis (continuing without it)"
}

redis_clear_replicating() {
    redis-cli -h "$REDIS_HOST" -a "$REDIS_PASSWORD" --no-auth-warning \
        DEL "honeypot_pool_replicating:$1" >/dev/null \
        || log "pool $1: could not clear replicating flag in Redis (will self-expire via its 30s TTL)"
}

prod_mysql() {
    mysql -h "$PROD_HOST" -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" -N "$@"
}

prod_mysqldump() {
    mysqldump -h "$PROD_HOST" -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" \
        --single-transaction --no-create-info --skip-add-drop-table \
        --skip-triggers --skip-add-locks --skip-comments --compact "$@"
}

# ---------------------------------------------------------------------------
# build_sync_sql: read production's current content ID set once, dump it,
# and write one complete apply script (delete-scoped + fresh inserts) to
# $WORKDIR/content_sync.sql. Re-used unmodified across all three pools, since
# production's content is read once per cycle, not once per pool.
#
# Returns 1 (nothing written) if production currently has no matching
# content -- avoids ever emitting "WHERE id IN ()", which is invalid SQL.
# ---------------------------------------------------------------------------
build_sync_sql() {
    local ids table_exists sql_file="$WORKDIR/content_sync.sql"

    ids=$(prod_mysql "$MYSQL_DATABASE" -e \
        "SELECT GROUP_CONCAT(ID) FROM wp_posts WHERE post_type IN ('page','post','product','product_variation','attachment') AND post_status IN ('publish','inherit')")

    if [ -z "$ids" ] || [ "$ids" = "NULL" ]; then
        log "production has no page/post/product/attachment content yet -- skipping this cycle"
        return 1
    fi

    table_exists=$(prod_mysql "$MYSQL_DATABASE" -e \
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='$MYSQL_DATABASE' AND table_name='wp_wc_product_meta_lookup'")

    {
        echo "SET FOREIGN_KEY_CHECKS=0;"
        echo "START TRANSACTION;"
        echo "DELETE FROM wp_postmeta WHERE post_id IN ($ids);"
        echo "DELETE FROM wp_term_relationships WHERE object_id IN ($ids);"
        if [ "$table_exists" = "1" ]; then
            echo "DELETE FROM wp_wc_product_meta_lookup WHERE product_id IN ($ids);"
        fi
        echo "DELETE FROM wp_posts WHERE ID IN ($ids);"
    } > "$sql_file"

    # Parents before children: wp_posts rows must exist before wp_postmeta /
    # wp_term_relationships rows that reference them are inserted.
    prod_mysqldump --where="ID IN ($ids)" "$MYSQL_DATABASE" wp_posts >> "$sql_file"
    prod_mysqldump --where="post_id IN ($ids)" "$MYSQL_DATABASE" wp_postmeta >> "$sql_file"
    prod_mysqldump --where="object_id IN ($ids)" "$MYSQL_DATABASE" wp_term_relationships >> "$sql_file"
    if [ "$table_exists" = "1" ]; then
        prod_mysqldump --where="product_id IN ($ids)" "$MYSQL_DATABASE" wp_wc_product_meta_lookup >> "$sql_file"
    fi

    # Small reference tables: full add/update-only refresh, no prior DELETE
    # (mirrors init_setup's sync_files() non-destructive philosophy).
    prod_mysqldump --replace "$MYSQL_DATABASE" wp_terms wp_term_taxonomy >> "$sql_file"

    {
        echo "COMMIT;"
        echo "SET FOREIGN_KEY_CHECKS=1;"
    } >> "$sql_file"

    local id_count
    id_count=$(echo "$ids" | tr ',' '\n' | wc -l)
    log "built sync script covering $id_count production content item(s)"
    return 0
}

replicate_to_pool() {
    local pool_num="$1" db_host db_pass
    db_host=$(pool_host "$pool_num")
    db_pass=$(pool_password "$pool_num")

    log "pool $pool_num ($db_host): replication starting"
    redis_set_replicating "$pool_num"

    if mysql -h "$db_host" -u"$MYSQL_USER" -p"$db_pass" "$MYSQL_DATABASE" < "$WORKDIR/content_sync.sql"; then
        log "pool $pool_num ($db_host): replication complete"
    else
        log "pool $pool_num ($db_host): replication FAILED -- pool DB left as-is, will retry next cycle"
    fi

    redis_clear_replicating "$pool_num"
}

sync_cycle() {
    if ! build_sync_sql; then
        return
    fi

    for pool_num in $POOL_NUMS; do
        replicate_to_pool "$pool_num"
        # Small stagger between pools -- no correctness requirement, just
        # avoids piling all three pools' DB load onto the exact same instant.
        sleep 2
    done
}

log "honeypot content sync starting -- interval ${REPLICATION_INTERVAL_SECONDS}s"

while true; do
    sync_cycle || log "sync cycle failed, will retry next interval"
    sleep "$REPLICATION_INTERVAL_SECONDS"
done
