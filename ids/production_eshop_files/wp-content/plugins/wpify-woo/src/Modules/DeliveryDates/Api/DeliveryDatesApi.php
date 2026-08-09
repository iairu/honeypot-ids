<?php

namespace WpifyWoo\Modules\DeliveryDates\Api;

defined( 'ABSPATH' ) || exit;

use WC_Product;
use WP_REST_Response;
use WP_REST_Server;
use WpifyWoo\Managers\ApiManager;
use WpifyWoo\Modules\DeliveryDates\DeliveryDatesModule;
use WpifyWoo\Plugin;
use WpifyWooDeps\Wpify\Core\Abstracts\AbstractRest;

/**
 * @property Plugin $plugin
 */
class DeliveryDatesApi extends \WP_REST_Controller {
	public function __construct(
		private  DeliveryDatesModule $module
	) {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	/**
	 * Register the routes for the objects of the controller.
	 */
	public function register_routes() {
		register_rest_route(
			ApiManager::REST_NAMESPACE,
			'delivery-dates-country',
			array(
				array(
					'methods'             => WP_REST_Server::READABLE,
					'callback'            => array( $this, 'set_shipping_country' ),
					'permission_callback' => '__return_true',
					'args'                => array(
						'country' => array(
							'required' => true,
						),
					),
				),
			)
		);

		register_rest_route(
			ApiManager::REST_NAMESPACE,
			'delivery-dates-render',
			array(
				array(
					'methods'             => WP_REST_Server::READABLE,
					'callback'            => array( $this, 'render_delivery_dates' ),
					'permission_callback' => '__return_true',
					'args'                => array(
						'product_id' => array(
							'required' => true,
						),
					),
				),
			)
		);
	}

	/**
	 * @param \WP_REST_Request $request Full data about the request.
	 *
	 * @return \WP_REST_Response
	 */
	public function set_shipping_country( $request ): WP_REST_Response {

		if ( apply_filters( 'wpify_woo_delivery_dates_disable_change_country', false ) ) {
			return new WP_REST_Response( '', 204 );
		}

		$country = strtoupper( sanitize_text_field( (string) $request->get_param( 'country' ) ) );

		if ( ! preg_match( '/^[A-Z]{2}$/', $country ) ) {
			return new WP_REST_Response( '', 204 );
		}

		if ( empty(WC()->customer->get_billing_address())) {
			WC()->customer->set_billing_country( $country );
		}

		if ( empty(WC()->customer->get_shipping_address())) {
			WC()->customer->set_shipping_country( $country );
		}

		return new WP_REST_Response( array( 'country' => $country ), 200 );
	}

	/**
	 * @param \WP_REST_Request $request Full data about the request.
	 *
	 * @return \WP_REST_Response|\WP_Error
	 */
	public function render_delivery_dates( $request ) {
		$product_id = absint( $request->get_param( 'product_id' ) );
		if ( ! $product_id ) {
			return new \WP_Error( 'invalid-product', __( 'Invalid product ID.', 'wpify-woo' ) );
		}

		$product = wc_get_product( $product_id );
		if ( ! $product instanceof WC_Product ) {
			return new \WP_Error( 'product-not-found', __( 'Product not found.', 'wpify-woo' ) );
		}

		if ( 'publish' !== $product->get_status() && ! current_user_can( 'edit_post', $product_id ) ) {
			return new \WP_Error( 'product-not-found', __( 'Product not found.', 'wpify-woo' ), array( 'status' => 404 ) );
		}

		$GLOBALS['product'] = $product; // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Setting the WooCommerce global product so the template renders for the requested product.
		$html               = $this->module->get_delivery_date_html( true );

		return new WP_REST_Response( array( 'html' => $html ), 200 );
	}
}
