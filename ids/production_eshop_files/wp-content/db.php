<?php
/**
 * wp-content/db.php  --  Per-request database router (WordPress "db" drop-in).
 *
 * This is the heart of the single-eshop / two-database honeynet topology
 * (see ARCHITECTURE.md and docker-compose.yml). Instead of running a separate
 * WordPress container per honeypot pool, ONE production_eshop serves every
 * request and, on each request, connects $wpdb to EITHER:
 *
 *   - the PRODUCTION database (real customers/orders/content), or
 *   - the HONEYPOT database (a cleaned, dummy-data clone kept content-synced
 *     with production by honeypot_content_sync),
 *
 * chosen by the reverse proxy's per-session threat decision. WordPress loads
 * wp-content/db.php (a "drop-in") before almost anything else and lets it
 * define the global $wpdb, which is exactly the seam needed to swap databases
 * transparently -- no WordPress core/plugin/theme code is aware of it, so an
 * attacker sees one ordinary WordPress site whether they land on production
 * or the honeypot database.
 *
 * TRUST MODEL (important):
 *   The choice comes from the request header X-Honeypot-Backend, which the
 *   reverse proxy (reverse_proxy_enhanced/nginx.conf) sets AUTHORITATIVELY
 *   from its Lua threat-analysis routing decision and ALWAYS overwrites
 *   (proxy_set_header) so a client-supplied copy can never survive.
 *   production_eshop publishes no host port -- the only path to this PHP is
 *   through that proxy -- so a client cannot reach PHP with a forged header.
 *   Default (header absent or anything other than "honeypot") is PRODUCTION,
 *   i.e. fail-safe toward the real site only when the proxy explicitly and
 *   trustedly says "honeypot"; a missing header never silently exposes the
 *   honeypot DB as production or vice-versa beyond this documented default.
 *
 * WHAT THIS CANNOT ISOLATE (see the "coverage gaps" report accompanying this
 * change): this drop-in isolates DATABASE-layer effects only. production and
 * honeypot share ONE WordPress filesystem and ONE PHP runtime, so file writes
 * (webshell uploads, plugin/theme file edits, path traversal reads/writes) and
 * any code-execution (RCE) are NOT isolated -- an attacker with code execution
 * can read the production credentials below and connect to the production
 * database directly, bypassing this routing entirely.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/*
 * Resolve the routing decision. Only the exact value "honeypot" (case-
 * insensitive) diverts; everything else -- including a missing header -- is
 * production, the safe default.
 */
$honeypot_db_active = (
	isset( $_SERVER['HTTP_X_HONEYPOT_BACKEND'] )
	&& strtolower( trim( (string) $_SERVER['HTTP_X_HONEYPOT_BACKEND'] ) ) === 'honeypot'
);

/*
 * Honeypot database connection parameters come from the container environment
 * (HONEYPOT_DB_* set on production_eshop in docker-compose.yml), read via
 * getenv() -- available under the official image's apache/mod_php, the same
 * way the image's own entrypoint reads WORDPRESS_DB_*. Each falls back to the
 * production value so a partially-configured honeypot still connects somewhere
 * sane rather than fataling; HONEYPOT_DB_HOST is the one that actually differs
 * in practice (a different MySQL host with the dummy-data clone).
 */
if ( $honeypot_db_active ) {
	$hp_host = getenv( 'HONEYPOT_DB_HOST' );
	$hp_user = getenv( 'HONEYPOT_DB_USER' );
	$hp_pass = getenv( 'HONEYPOT_DB_PASSWORD' );
	$hp_name = getenv( 'HONEYPOT_DB_NAME' );

	$db_host = ( $hp_host !== false && $hp_host !== '' ) ? $hp_host : DB_HOST;
	$db_user = ( $hp_user !== false && $hp_user !== '' ) ? $hp_user : DB_USER;
	$db_pass = ( $hp_pass !== false ) ? $hp_pass : DB_PASSWORD;
	$db_name = ( $hp_name !== false && $hp_name !== '' ) ? $hp_name : DB_NAME;
	$active_backend = 'honeypot';
} else {
	$db_host = DB_HOST;
	$db_user = DB_USER;
	$db_pass = DB_PASSWORD;
	$db_name = DB_NAME;
	$active_backend = 'production';
}

/*
 * Expose which backend this request bound to, for the mu-plugin that emits the
 * X-DB-Backend response header (debugging/verification) and for logging. Never
 * printed to normal visitors.
 */
if ( ! defined( 'HONEYPOT_ACTIVE_DB_BACKEND' ) ) {
	define( 'HONEYPOT_ACTIVE_DB_BACKEND', $active_backend );
}

/*
 * WordPress's wpdb class is already loaded by the time a db drop-in runs
 * (wp-includes/load.php's require_wp_db()). Construct $wpdb exactly as core
 * would, just with the per-request host/credentials selected above. The
 * constructor connects immediately, matching core's own behaviour. Prefix is
 * set here defensively; wp-settings.php also calls $wpdb->set_prefix() right
 * after this drop-in returns.
 */
$wpdb = new wpdb( $db_user, $db_pass, $db_name, $db_host );

if ( isset( $GLOBALS['table_prefix'] ) && $GLOBALS['table_prefix'] !== '' ) {
	$wpdb->set_prefix( $GLOBALS['table_prefix'] );
}
