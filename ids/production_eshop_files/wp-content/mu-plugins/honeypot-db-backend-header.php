<?php
/**
 * Plugin Name: Honeypot DB Backend Header
 * Description: Exposes WHICH database container actually served this request
 *              (production vs honeypot) in the single-eshop / two-database
 *              topology, by running a real SELECT against the resolved $wpdb
 *              and reporting the result in response headers. The dashboard's
 *              Exploits page reads these to show a "database container response"
 *              card in the Threat analyzer GUI, exposing the actual per-request
 *              database resolution rather than just the proxy's routing intent.
 *
 * SECURITY: gated behind the same INTERNAL_TEST_SECRET the reverse proxy uses
 * for its X-Route-Target / X-Threat-Score debug headers. A real attacker never
 * sees these headers (that would reveal they are in a honeypot); they are only
 * emitted when the caller presents the shared secret in X-Internal-Test-Auth.
 * The secret is compared in constant time and the whole thing is a no-op when
 * the secret is unset.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Hooked on 'init' (not 'send_headers') so the headers are emitted for EVERY
// request type before its output begins -- including REST (/wp-json/...) and
// XML-RPC, which don't fire the front-end send_headers action but still run
// through 'init'. headers_sent() guards the rare case where output already
// started.
add_action( 'init', function () {
	if ( headers_sent() ) {
		return;
	}

	$secret = getenv( 'INTERNAL_TEST_SECRET' );
	$auth   = isset( $_SERVER['HTTP_X_INTERNAL_TEST_AUTH'] ) ? (string) $_SERVER['HTTP_X_INTERNAL_TEST_AUTH'] : '';
	if ( ! $secret || $secret === '' || ! hash_equals( (string) $secret, $auth ) ) {
		return; // not an authenticated internal test request -- stay invisible.
	}

	// The database this request was routed to (set by wp-content/db.php from
	// the proxy's X-Honeypot-Backend header before WordPress loaded).
	$backend = defined( 'HONEYPOT_ACTIVE_DB_BACKEND' ) ? HONEYPOT_ACTIVE_DB_BACKEND : 'production';

	global $wpdb;
	$db_host = ( $wpdb && isset( $wpdb->dbhost ) ) ? (string) $wpdb->dbhost : '';

	// Run REAL SELECTs against the resolved $wpdb -- this is the actual proof
	// that queries were served by that specific database container:
	//   @@hostname          -> the mysqld container that answered the query
	//   COUNT(*) wp_options -> a data SELECT that returns a row count
	$server_hostname = '';
	$options_rows    = '';
	if ( $wpdb ) {
		$server_hostname = (string) $wpdb->get_var( 'SELECT @@hostname' );
		$options_rows    = (string) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . $wpdb->options );
	}

	header( 'X-DB-Backend: ' . $backend );
	header( 'X-DB-Host: ' . $db_host );
	header( 'X-DB-Server: ' . $server_hostname );
	// A compact human-readable summary of the SELECTs that were executed.
	header( 'X-DB-Probe: SELECT @@hostname=' . $server_hostname
		. '; SELECT COUNT(*) FROM ' . ( $wpdb ? $wpdb->options : 'wp_options' ) . '=' . $options_rows );
}, 1 );
