<?php

namespace WpifyWoo\Modules\IcDic;

defined( 'ABSPATH' ) || exit;

use Automattic\WooCommerce\Blocks\Package;
use Automattic\WooCommerce\Blocks\Domain\Services\CheckoutFields;
use WP_Error;
use WpifyWooDeps\h4kuna\Ares\AresFactory;
use WpifyWooDeps\h4kuna\Ares\Exceptions\IdentificationNumberNotFoundException;


class BlockSupport {
	public $module = null;
	private $current_checkout_country = null;

	public function __construct( $module ) {
		$this->module = $module;
		add_action( 'woocommerce_init', [ $this, 'add_checkout_fields' ] );
		add_action( 'wp_footer', [ $this, 'add_placeholder' ] );
		//add_action( 'woocommerce_store_api_checkout_order_processed', [ $this, 'save_metadata' ] );
		add_filter( 'woocommerce_set_additional_field_value', [ $this, 'save_metadata_back_compatibility' ], 10, 4 );
		add_action( 'woocommerce_sanitize_additional_field', [ $this, 'sanitize_ic_dic_fields' ] );
		add_filter( 'woocommerce_store_api_cart_errors', [ $this, 'validate_cart' ], 10, 2 );
		// Default values from meta (Backward compatibility)
		add_filter( 'woocommerce_get_default_value_for_wpify/company', function ( $value, $group, $wc_object ) {
			return $wc_object->get_billing_company();
		}, 10, 3 );
		add_filter( 'woocommerce_get_default_value_for_wpify/ic', function ( $value, $group, $wc_object ) {
			return $wc_object->get_meta( '_billing_ic' ) ?: $wc_object->get_meta( 'billing_ic' );
		}, 10, 3 );
		add_filter( 'woocommerce_get_default_value_for_wpify/dic', function ( $value, $group, $wc_object ) {
			return $wc_object->get_meta( '_billing_dic' ) ?: $wc_object->get_meta( 'billing_dic' );
		}, 10, 3 );
		add_filter( 'woocommerce_get_default_value_for_wpify/dic-dph', function ( $value, $group, $wc_object ) {
			return $wc_object->get_meta( '_billing_dic_dph' ) ?: $wc_object->get_meta( 'billing_dic_dph' );
		}, 10, 3 );
		add_filter( 'woocommerce_get_default_value_for_wpify/ic_dic_toggle', function ( $value, $group, $wc_object ) {
			if ( $value ) {
				return $value;
			}
			// Auto-enable toggle if customer has any company data
			$ic      = $wc_object->get_meta( '_billing_ic' ) ?: $wc_object->get_meta( 'billing_ic' );
			$dic     = $wc_object->get_meta( '_billing_dic' ) ?: $wc_object->get_meta( 'billing_dic' );
			$company = $wc_object->get_billing_company();

			return ( $ic || $dic || $company ) ? '1' : $value;
		}, 10, 3 );
		add_action( 'woocommerce_validate_additional_field', [ $this, 'validate_ic_dic_fields' ], 10, 3 );
		// Hook to capture current country from checkout data during validation
		add_action( 'woocommerce_store_api_checkout_update_customer_from_request', [ $this, 'capture_country_before_validation' ], 5, 2 );

		// Final VIES validation on order submission (both checkouts)
		add_action( 'rest_api_init', [ $this, 'register_block_checkout_vies_validation' ], 5 );

		// Ensure VAT exempt is set before order totals calculation
		add_action( 'woocommerce_store_api_checkout_update_customer_from_request', [ $this, 'ensure_vat_exempt_from_checkout_data' ], 20, 2 );

		// Log VAT exempt decision after order is created
		add_action( 'woocommerce_store_api_checkout_order_processed', [ $this, 'log_order_vat_exempt_decision' ] );

		// Hide IC/DIC fields from My Account > Account Details page using CSS
		add_action( 'woocommerce_edit_account_form_start', [ $this, 'hide_ic_dic_fields_with_css' ] );

		$this->register_vat_exempt_callback();
	}

	public function add_checkout_fields() {
		if ( ! function_exists( 'woocommerce_register_additional_checkout_field' ) ) {
			return;
		}

		woocommerce_register_additional_checkout_field(
			array(
				'id'       => 'wpify/ic_dic_toggle',
				'label'    => __( 'I\'m shopping for a company', 'wpify-woo' ),
				'location' => 'contact',
				'type'     => 'checkbox',
				'default'  => 0,
			),
		);
		woocommerce_register_additional_checkout_field(
			array(
				'id'                => 'wpify/ic',
				'label'             => __( 'Identification no.', 'wpify-woo' ),
				'location'          => 'contact',
				'type'              => 'text',
				'meta_key'          => '_billing_ic', // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- Field registration config for WooCommerce checkout, not a database query.
				'sanitize_callback' => function ( $field_value ) {
					return str_replace( ' ', '', $field_value );
				},
			),

		);
		woocommerce_register_additional_checkout_field(
			array(
				'id'       => 'wpify/company',
				'label'    => __( 'Company', 'wpify-woo' ),
				'location' => 'contact',
				'type'     => 'text',

			),

		);
		woocommerce_register_additional_checkout_field(
			array(
				'id'                => 'wpify/dic',
				'label'             => __( 'VAT no.', 'wpify-woo' ),
				'location'          => 'contact',
				'type'              => 'text',
				'meta_key'          => '_billing_dic', // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- Field registration config for WooCommerce checkout, not a database query.
				'sanitize_callback' => function ( $field_value ) {
					return strtoupper( str_replace( ' ', '', $field_value ) );
				},
			),
		);
		woocommerce_register_additional_checkout_field(
			array(
				'id'                => 'wpify/dic-dph',
				'label'             => __( 'In VAT no.', 'wpify-woo' ),
				'location'          => 'contact',
				'type'              => 'text',
				'meta_key'          => '_billing_dic_dph', // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- Field registration config for WooCommerce checkout, not a database query.
				'sanitize_callback' => function ( $field_value ) {
					return strtoupper( str_replace( ' ', '', $field_value ) );
				},
			),
		);
	}

	public function add_placeholder() {
		// Mount the block checkout app only on the checkout page. Elsewhere (e.g. My
		// Account) it boots WC Blocks + fires a Store API cart request that creates a
		// session mid-request, invalidating the login nonce and breaking login.
		if ( ! is_checkout() ) {
			return;
		}

		echo '<div data-app="wpify-ic-dic"></div>';
	}

	public function register_vat_exempt_callback() {
		woocommerce_store_api_register_update_callback(
			[
				'namespace' => 'wpify_ic_dic',
				'callback'  => array( $this, 'set_customer_vat_extempt' ),
			]
		);
	}

	public function sanitize_ic_dic_fields( $value, $key = null ) {
		// Handle both old and new callback signatures
		if ( $key === null && is_string( $value ) ) {
			// Skip sanitization without key to avoid affecting company field
			return $value;
		} elseif ( $key !== null && in_array( $key, array( 'wpify/ic', 'wpify/dic', 'wpify/dic-dph' ) ) ) {
			// Only sanitize IC/DIC fields
			$value = str_replace( ' ', '', $value );
			$value = strtoupper( $value );
		}

		return $value;
	}

	public function validate_ic_dic_fields( \WP_Error $errors, $field_key, $field_value ) {
		if ( $field_key !== 'wpify/dic' && $field_key !== 'wpify/dic-dph' && $field_key !== 'wpify/ic' ) {
			return $errors;
		}

		// Get country from multiple sources - block checkout may have newer data
		$country = null;

		// Check php://input for block checkout data first (most reliable)
		$input = file_get_contents( 'php://input' );
		if ( $input ) {
			$input_data = json_decode( $input, true );
			if ( ! empty( $input_data['billing_address']['country'] ) ) {
				$country = sanitize_text_field( $input_data['billing_address']['country'] );
			}
		}

		// Try captured country from our hook
		if ( empty( $country ) && ! empty( $this->current_checkout_country ) ) {
			$country = $this->current_checkout_country;
		}

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Read-only country detection during WooCommerce checkout, which handles its own nonce verification.
		// Try to get country from POST data
		if ( empty( $country ) && ! empty( $_POST['billing_country'] ) ) {
			$country = sanitize_text_field( wp_unslash( $_POST['billing_country'] ) );
		}

		// Try from additional fields (for block checkout)
		if ( empty( $country ) && ! empty( $_POST['wc-additional-fields-data'] ) ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- JSON string decoded below; the extracted country value is sanitized individually.
			$additional_data = json_decode( wp_unslash( $_POST['wc-additional-fields-data'] ), true );
			if ( ! empty( $additional_data['billing_country'] ) ) {
				$country = sanitize_text_field( $additional_data['billing_country'] );
			}
		}
		// phpcs:enable WordPress.Security.NonceVerification.Missing


		// Fallback to customer object
		if ( empty( $country ) && ! empty( WC()->customer ) ) {
			$country = WC()->customer->get_billing_country();
		}

		// Last resort - session
		if ( empty( $country ) ) {
			wc_load_cart();
			$country = WC()->session->customer['country'] ?? '';
		}

		// Validation processing - detailed logging moved to order creation

		// For IC field, skip server-side validation for block checkout since we can't reliably get current country
		if ( 'wpify/ic' === $field_key ) {
			return $errors; // Skip IC validation for block checkout - frontend handles it
		}

		// ARES validation only for Czech IC numbers
		if ( 'wpify/ic' === $field_key
		     && $this->module->get_setting( 'validate_ares' )
		     && $country === 'CZ'
		     && in_array( 'order_submit', $this->module->get_setting( 'validate_ares' ) )
		     && ! empty( $field_value )
		) {
			$ares = ( new AresFactory() )->create();
			$ic   = sanitize_text_field( $field_value );

			if ( ! is_numeric( $ic ) ) {
				$errors->add( 'validation', __( 'Please enter valid IC', 'wpify-woo' ) );
			} else {
				try {
					$ares->loadBasic( $ic );
				} catch ( IdentificationNumberNotFoundException $e ) {
					$errors->add( 'validation', __( 'The entered Company Number has not been found in ARES, please enter valid company number.', 'wpify-woo' ) );
				}
			}
		}

		// VIES validation moved to final order submission - no longer validate during field input

		return $errors;
	}

	public function save_metadata( $order ) {
		$checkout_fields                 = Package::container()->get( CheckoutFields::class );
		$order_additional_billing_fields = $checkout_fields->get_all_fields_from_object( $order ); // array( 'my-plugin-namespace/my-field' => 'my-value' );

		if ( isset( $order_additional_billing_fields['wpify/company'] ) ) {
			update_post_meta( $order->get_id(), '_billing_company', $order_additional_billing_fields['wpify/company'] );
		}

		if ( isset( $order_additional_billing_fields['wpify/ic'] ) ) {
			update_post_meta( $order->get_id(), '_billing_ic', $order_additional_billing_fields['wpify/ic'] );
		}

		if ( isset( $order_additional_billing_fields['wpify/dic'] ) ) {
			update_post_meta( $order->get_id(), '_billing_dic', $order_additional_billing_fields['wpify/dic'] );
		}

		if ( isset( $order_additional_billing_fields['wpify/dic-dph'] ) ) {
			update_post_meta( $order->get_id(), '_billing_dic_dph', $order_additional_billing_fields['wpify/dic-dph'] );
		}
	}

	public function save_metadata_back_compatibility( $key, $value, $group, $wc_object ) {
		if ( $key === 'wpify/company' ) {
			$wc_object->set_billing_company( $value );
			$wc_object->save();

			return;
		}

		$meta_key = match ( $key ) {
			'wpify/ic' => '_billing_ic',
			'wpify/dic' => '_billing_dic',
			'wpify/dic-dph' => '_billing_dic_dph',
			default => null,
		};

		if ( $meta_key ) {
			$wc_object->update_meta_data( $meta_key, $value, true );
		}
	}

	public function set_customer_vat_extempt( $data ) {
		$customer = WC()->customer;
		$customer->set_is_vat_exempt( false );

		// Handle dic_cleared - clear stored DIC but still recalculate VAT (for export scenarios)
		if ( isset( $data['validation'] ) && $data['validation'] === 'dic_cleared' ) {
			$customer->delete_meta_data( 'billing_dic' );
			$customer->delete_meta_data( 'billing_dic_dph' );
			$customer->save();
			// Continue to recalculate VAT exempt (export may still apply without DIC)
		}

		// Handle failed validation - skip VAT exempt (no valid DIC)
		if ( isset( $data['validation'] ) && $data['validation'] === 'failed' ) {
			// Recalculate cart to reflect no VAT exempt
			if ( WC()->cart ) {
				WC()->cart->calculate_totals();
			}
			return;
		}

		if ( ! $this->module->is_vat_exempt_enabled() ) {
			return;
		}

		$billing_country  = $data['country'] ?? $customer->get_billing_country();
		// Use shipping_country from JS data if available, otherwise fallback to customer/billing
		$shipping_country = $data['shipping_country'] ?? $this->module->get_shipping_country_with_fallback( $customer, $billing_country );
		// For dic_cleared, DIC should be empty
		$dic = ( isset( $data['validation'] ) && $data['validation'] === 'dic_cleared' )
			? ''
			: ( $data['dic'] ?? $this->module->get_vat_id_from_source( $customer, $billing_country ) );

		$this->module->apply_vat_exempt_state( $billing_country, $shipping_country, $dic ?: '' );
		$customer->save();

		// Force cart recalculation to reflect VAT exempt change
		if ( WC()->cart ) {
			// Clear all session cart data to force fresh calculation
			WC()->cart->set_totals( array() );
			WC()->cart->calculate_totals();

			// Invalidate Store API cart cache
			// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- WooCommerce core hook name.
			do_action( 'woocommerce_cart_item_removed', '', WC()->cart );
		}
	}


	public function capture_country_before_validation( $customer, $request ) {
		// Capture country from request data before validation
		$data = $request->get_json_params();
		if ( ! empty( $data['billing_address']['country'] ) ) {
			$this->current_checkout_country = $data['billing_address']['country'];
		}
	}

	public function ensure_vat_exempt_from_checkout_data( $customer, $request ) {
		WC()->customer->set_is_vat_exempt( false );

		if ( ! $this->module->is_vat_exempt_enabled() ) {
			return;
		}

		$data              = $request->get_json_params();
		$billing_country   = $data['billing_address']['country'] ?? '';
		$shipping_country  = $data['shipping_address']['country'] ?? $billing_country;
		$additional_fields = $data['additional_fields'] ?? array();
		$dic               = $this->module->get_vat_id_from_block_checkout( $additional_fields, $billing_country );

		$this->module->apply_vat_exempt_state( $billing_country, $shipping_country, $dic );
	}

	public function validate_cart( $cart_errors, $cart ) {
		return $cart_errors;
	}

	/**
	 * Register VIES validation for block checkout on final order submission
	 */
	public function register_block_checkout_vies_validation() {
		static $registered = false;
		if ( $registered ) {
			return;
		}
		$registered = true;

		// Register VIES validation on final checkout submission for blocks
		add_action( 'rest_pre_dispatch', array( $this, 'validate_vies_before_block_checkout' ), 10, 3 );
	}

	/**
	 * Validate VIES before block checkout is processed (only on final submission)
	 */
	public function validate_vies_before_block_checkout( $result, $server, $request ) {
		if ( $request->get_route() !== '/wc/store/v1/checkout' || $request->get_method() !== 'POST' ) {
			return $result;
		}

		$body              = $request->get_json_params();
		$additional_fields = $body['additional_fields'] ?? array();
		$billing_country   = $body['billing_address']['country'] ?? '';
		$dic               = $this->module->get_vat_id_from_block_checkout( $additional_fields, $billing_country );

		// Track skipped cases for logging
		if ( ! $this->module->get_setting( 'validate_vies' ) ) {
			$this->module->set_last_vies_result( 'skipped' );
			return $result;
		}

		if ( empty( $dic ) ) {
			$this->module->set_last_vies_result( 'skipped' );
			return $result;
		}

		// is_valid_dic() sets last_vies_result internally
		if ( $this->module->is_valid_dic( $dic ) ) {
			return $result;
		}

		// vies_fails = true means allow order even if VIES fails (but no VAT exempt)
		if ( $this->module->get_setting( 'vies_fails' ) === true ) {
			return $result;
		}

		$field_key = $billing_country === 'SK' ? 'wpify/dic-dph' : 'wpify/dic';
		$message   = $billing_country === 'SK'
			? __( 'The entered IN VAT Number has not been found in VIES, please enter valid IN VAT number.', 'wpify-woo' )
			: __( 'The entered VAT Number has not been found in VIES, please enter valid VAT number.', 'wpify-woo' );

		return new \WP_Error(
			'vies_validation_failed',
			$message,
			array(
				'status'            => 400,
				'validation_errors' => array(
					array(
						'code'    => 'dic_invalid',
						'message' => $message,
						'data'    => array( 'field' => $field_key ),
					),
				),
			)
		);
	}

	public function log_order_vat_exempt_decision( $order ) {
		$billing_country  = $order->get_billing_country();
		$shipping_country = $this->module->get_shipping_country_with_fallback( $order, $billing_country );
		$shop_country     = wc_get_base_location()['country'];
		$dic              = $this->module->get_vat_id_from_source( $order, $billing_country );

		// Calculate VAT exempt using new logic
		$vat_exempt_result = $this->module->should_exempt_vat(
			$billing_country,
			$shipping_country,
			$dic ?: '',
			false // Will validate via VIES if needed
		);

		// Save VAT exempt metadata to order
		$this->module->save_vat_exempt_meta( $order, $vat_exempt_result );

		// Detect actual VAT exempt from order totals
		$actual_vat_exempt = ( $order->get_total_tax() == 0 && $order->get_total() > 0 );

		// Log the decision
		$this->module->log->info( 'Order VAT Exempt Decision', [
			'order_id'              => $order->get_id(),
			'order_number'          => $order->get_order_number(),
			'billing_country'       => $billing_country,
			'shipping_country'      => $shipping_country,
			'shop_country'          => $shop_country,
			'submitted_ic'          => $order->get_meta( '_billing_ic' ) ?: null,
			'submitted_dic'         => $dic,
			'actual_vat_exempt'     => $actual_vat_exempt,
			'calculated_vat_exempt' => $vat_exempt_result['exempt'],
			'vat_exempt_reason'     => $vat_exempt_result['reason'],
			'order_total'           => $order->get_total(),
			'tax_total'             => $order->get_total_tax(),
			'context'               => 'Order created - Block checkout',
			// Validation results
			'validations'           => [
				'ares_result' => $this->module->get_last_ares_result() ?? 'frontend_only',
				'vies_result' => $this->module->get_last_vies_result(),
			],
			// Settings for debugging
			'settings'              => [
				'woo_tax_based_on'            => get_option( 'woocommerce_tax_based_on', 'shipping' ),
				'validate_ares'               => $this->module->get_setting( 'validate_ares' ),
				'validate_vies'               => $this->module->get_setting( 'validate_vies' ),
				'vies_fails'                  => $this->module->get_setting( 'vies_fails' ),
				'enable_eu_reverse_charge'    => $this->module->get_setting( 'enable_eu_reverse_charge' ),
				'enable_third_country_export' => $this->module->get_setting( 'enable_third_country_export' ),
			],
		] );
	}

	/**
	 * Hide IC/DIC fields from My Account > Account Details page using CSS
	 * These fields should only be visible in the Billing Address section
	 */
	public function hide_ic_dic_fields_with_css() {
		// Only output CSS on the account edit page
		if ( ! is_account_page() ) {
			return;
		}
		?>
		<style type="text/css">
			/* Hide IC/DIC fields from My Account > Account Details form */
			.woocommerce-EditAccountForm p[id*="wpify/ic_dic_toggle"],
			.woocommerce-EditAccountForm p[id*="wpify/ic"],
			.woocommerce-EditAccountForm p[id*="wpify/dic"],
			.woocommerce-EditAccountForm p[id*="wpify/dic-dph"],
			.woocommerce-EditAccountForm p[id*="wpify/company"] {
				display: none !important;
			}
		</style>
		<?php
	}
}
