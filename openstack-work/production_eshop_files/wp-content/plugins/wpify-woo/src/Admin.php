<?php

namespace WpifyWoo;

defined( 'ABSPATH' ) || exit;

use WpifyWooDeps\Wpify\Log\RotatingFileLog;

/**
 * Class Admin
 *
 * @package WpifyWoo
 * @property Plugin $plugin
 */
class Admin {
	public function __construct(
		private RotatingFileLog $log
	) {
		add_action( 'admin_init', [ $this, 'maybe_download_log' ] );
	}

	public function maybe_download_log() {
		global $wpdb;
		if ( ! isset( $_GET['wpify-action'] ) || $_GET['wpify-action'] !== 'download-log' ) {
			return;
		}

		if ( ! isset( $_GET['wpify-nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['wpify-nonce'] ) ), 'download-log' ) ) {
			wp_die( esc_html__( 'Invalid nonce.', 'wpify-woo' ) );
		}

		if ( ! current_user_can( 'administrator' ) ) {
			wp_die( esc_html__( 'Only user with administrator role can export logs.', 'wpify-woo' ) );
		}

		exit();
	}

	private function array_to_csv_download( $array, $filename = "wpify-log.csv", $delimiter = ";" ) {
		// open raw memory as file so no temp files needed, you might run out of memory though
		$f = fopen( 'php://memory', 'w' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Writing to an in-memory PHP stream, not the filesystem; WP_Filesystem is not applicable.
		// loop over the input array
		foreach ( $array as $line ) {
			// generate csv lines from the inner arrays
			fputcsv( $f, $line, $delimiter );
		}
		// reset the file pointer to the start of the file
		fseek( $f, 0 );
		// tell the browser it's going to be a csv file
		header( 'Content-Type: application/csv' );
		// tell the browser we want to save it instead of displaying it
		header( 'Content-Disposition: attachment; filename="' . $filename . '";' );
		// make php send the generated csv lines to the browser
		fpassthru( $f );
	}
}
