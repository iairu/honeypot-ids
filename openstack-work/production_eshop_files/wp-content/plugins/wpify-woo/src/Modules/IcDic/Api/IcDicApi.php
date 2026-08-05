<?php

namespace WpifyWoo\Modules\IcDic\Api;

defined( 'ABSPATH' ) || exit;

use Exception;
use WP_REST_Response;
use WP_REST_Server;
use WpifyWoo\Managers\ApiManager;
use WpifyWoo\Modules\IcDic\IcDicModule;
use WpifyWoo\Plugin;
use WpifyWooDeps\DragonBe\Vies\Vies;
use WpifyWooDeps\h4kuna\Ares;
use WpifyWooDeps\h4kuna\Ares\Exceptions\IdentificationNumberNotFoundException;

/**
 * @property Plugin $plugin
 */
class IcDicApi extends \WP_REST_Controller {

	/** @var IcDicModule $module */
	private $module;

	/**
	 * ExampleApi constructor.
	 */
	public function __construct( IcDicModule $module ) {
		$this->module = $module;
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	/**
	 * Register the routes for the objects of the controller.
	 */
	public function register_routes() {
		register_rest_route(
			ApiManager::REST_NAMESPACE,
			'icdic',
			array(
				array(
					'methods'             => WP_REST_Server::READABLE,
					'callback'            => array( $this, 'get_company_details' ),
					'permission_callback' => '__return_true',
					'args'                => array(
						'in' => array(
							'required' => true,
						),
					),
				),
			)
		);

		register_rest_route(
			ApiManager::REST_NAMESPACE,
			'icdic-vies',
			array(
				array(
					'methods'             => WP_REST_Server::READABLE,
					'callback'            => array( $this, 'get_valid_vies' ),
					'permission_callback' => '__return_true',
					'args'                => array(
						'in' => array(
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
	 * @return \WP_Error|\WP_REST_Request|\WP_REST_Response | bool
	 */
	public function get_company_details( $request ) {
		if ( $this->is_rate_limited() ) {
			return new \WP_Error( 'rate-limited', __( 'Too many requests. Please try again later.', 'wpify-woo' ), array( 'status' => 429 ) );
		}

		$ic = $request->get_param( 'in' );

		if ( ! is_numeric( $ic ) ) {
			return new \WP_Error( 'not-found', __( 'The entered Identification Number has not been found in ARES, please enter valid Identification number.', 'wpify-woo' ) );
		}

		try {
			$ares    = ( new Ares\AresFactory() )->create();
			$record  = $ares->loadBasic( $ic );
			$details = array(
				'billing_company'   => $record->company,
				'billing_ic'        => $record->in,
				'billing_address_1' => sprintf( '%s %s', $record->street, $record->house_number ),
				'billing_city'      => $record->city,
				'billing_postcode'  => $record->zip,
				'billing_dic'       => $record->tin,
			);

			$details = apply_filters( 'wpify_woo_icdic_ares_details', $details, $record );

			return new WP_REST_Response( array( 'details' => $details ), 200 );
		} catch ( IdentificationNumberNotFoundException $e ) {
			return new \WP_Error( 'not-found', __( 'The entered Identification Number has not been found in ARES, please enter valid Identification number.', 'wpify-woo' ) );
		} catch ( Ares\Exceptions\ServerResponseException $e ) {
			return new \WP_Error( 'ares-server-error', __( 'Invalid response from ARES.', 'wpify-woo' ) );
		}
	}


	/**
	 * @param \WP_REST_Request $request Full data about the request.
	 *
	 * @return \WP_Error|\WP_REST_Request|\WP_REST_Response | bool
	 */
	public function get_valid_vies( $request ) {
		if ( $this->is_rate_limited() ) {
			return new \WP_Error( 'rate-limited', __( 'Too many requests. Please try again later.', 'wpify-woo' ), array( 'status' => 429 ) );
		}

		$dic                   = strtoupper( preg_replace( '/[^A-Za-z0-9]/', '', (string) $request->get_param( 'in' ) ) );
		$country               = substr( $dic, 0, 2 );
		$vat_extempt_countries = $this->module->get_setting( 'zero_tax_for_vat_countries' );
		$error_text            = __( 'The entered number did not pass the VIES validation. Check if it is correct.', 'wpify-woo' );

		if ( ! empty( $vat_extempt_countries ) && in_array( $country, $vat_extempt_countries ) ) {
			$error_text .= ' ' . __( 'Zero VAT could not be applied.', 'wpify-woo' );
		}

		// Check if VIES validation is enabled
		if ( ! $this->module->get_setting( 'validate_vies' ) ) {
			return new WP_REST_Response( array( 'validation' => 'skipped' ), 200 );
		}

		$is_valid = $this->module->is_valid_dic( $dic );

		if ( ! $is_valid && $this->module->get_last_vies_result() === 'error' ) {
			return new WP_REST_Response( array( 'validation' => 'unavailable' ), 200 );
		}

		// If VIES validation fails and vies_fails is disabled, return error (blocks order)
		if ( ! $is_valid && $this->module->get_setting( 'vies_fails' ) !== true ) {
			return new \WP_Error( 'not-found', $error_text );
		}

		// If VIES validation fails but vies_fails is enabled, return passed with warning
		if ( ! $is_valid && $this->module->get_setting( 'vies_fails' ) === true ) {
			return new WP_REST_Response( array( 
				'validation' => 'passed',
				'warning' => $error_text
			), 200 );
		}

		// Return validation result - BlockSupport will handle VAT exempt logic
		return new WP_REST_Response( array( 'validation' => 'passed' ), 200 );
	}

	/**
	 * Simple per-IP throttle for the public ARES/VIES lookup endpoints.
	 * These stay unauthenticated (guest checkout), so this caps abuse that
	 * would otherwise proxy outbound requests to the external registries.
	 *
	 * @return bool True when the current client has exceeded the limit.
	 */
	private function is_rate_limited(): bool {
		$ip    = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '0.0.0.0';
		$key   = 'wpify_woo_icdic_rl_' . md5( $ip );
		$count = (int) get_transient( $key );

		if ( $count >= 60 ) {
			return true;
		}

		set_transient( $key, $count + 1, MINUTE_IN_SECONDS );

		return false;
	}

	/**
	 * Check if a given request has access to create items
	 *
	 * @param \WP_REST_Request $request Full data about the request.
	 *
	 * @return \WP_Error|bool
	 */
	public function create_item_permissions_check( $request ) {
		return true;
	}

	/**
	 * Prepare the item for the REST response
	 *
	 * @param mixed            $item    WordPress representation of the item.
	 * @param \WP_REST_Request $request Request object.
	 *
	 * @return mixed
	 */
	public function prepare_item_for_response( $item, $request ) {
		return array();
	}
}
