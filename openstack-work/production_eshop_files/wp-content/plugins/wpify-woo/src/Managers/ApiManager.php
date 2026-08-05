<?php

namespace WpifyWoo\Managers;

defined( 'ABSPATH' ) || exit;

use WpifyWoo\Api\FeedApi;
use WpifyWoo\Api\SettingsApi;
use WpifyWoo\Plugin;

/**
 * Class ApiManager
 * @package WpifyWoo\Managers
 * @property Plugin $plugin
 */
class ApiManager {

	public const REST_NAMESPACE = 'wpify-woo/v1';
	public const NONCE_ACTION = 'wp_rest';

	public function __construct(
		SettingsApi $settings_api,
		FeedApi $feed_api
	) {

	}

	public function get_rest_url() {
		return rest_url( $this->get_rest_namespace() );
	}

	public function get_rest_namespace() {
		return $this::REST_NAMESPACE;
	}

	public function get_nonce_action() {
		return $this::NONCE_ACTION;
	}

	public function setup() {
		add_action( 'init', array( $this, 'enable_wc_frontend_in_rest' ) );
	}

	public function enable_wc_frontend_in_rest() {
		if ( ! function_exists( 'WC' ) || ! WC() ) {
			return;
		}

		if ( ! WC()->is_rest_api_request() ) {
			return;
		}

		WC()->frontend_includes();

		if ( null === WC()->cart && function_exists( 'wc_load_cart' ) ) {
			wc_load_cart();
		}

		WC()->session->set_customer_session_cookie( true );
	}


	/**
	 * We have to tell WC that this should not be handled as a REST request.
	 * Otherwise we can't use the product loop template contents properly.
	 * Since WooCommerce 3.6
	 *
	 * @param bool $is_rest_api_request
	 *
	 * @return bool
	 */
	public function simulate_as_not_request( $is_rest_api_request ) {
		if ( empty( $_SERVER['REQUEST_URI'] ) ) {
			return $is_rest_api_request;
		}

		// Bail early if this is not our request.
		if ( false === strpos( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ), $this->get_rest_namespace() ) ) {
			return $is_rest_api_request;
		}

		return false;
	}
}
