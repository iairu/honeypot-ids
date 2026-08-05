<?php

namespace WpifyWoo\Modules\HeurekaOverenoZakazniky;

defined( 'ABSPATH' ) || exit;

/**
 * Block checkout support for Heureka Ověřeno Zákazníky
 */
class BlockSupport {
	private $module;

	public function __construct( $module ) {
		$this->module = $module;

		add_action( 'woocommerce_init', [ $this, 'register_checkout_fields' ] );
		add_action( 'wp_footer', [ $this, 'add_block_placeholder' ] );
		add_action( 'woocommerce_store_api_checkout_order_processed', [ $this, 'handle_block_checkout_order' ] );
		add_filter( 'woocommerce_set_additional_field_value', [ $this, 'save_field_metadata' ], 10, 4 );
	}

	/**
	 * Register additional checkout fields for block checkout
	 */
	public function register_checkout_fields() {
		if ( ! function_exists( 'woocommerce_register_additional_checkout_field' ) ) {
			return;
		}

		// Only register if opt-out is enabled
		if ( ! $this->module->get_setting( 'enable_optout' ) ) {
			return;
		}

		$field_label = $this->module->get_setting( 'enable_optout_text' );

		woocommerce_register_additional_checkout_field(
			array(
				'id'       => 'wpify/heureka_optout',
				'label'    => $field_label,
				'location' => 'order',
				'type'     => 'checkbox',
				'default'  => 0,
				'meta_key' => '_wpify_woo_heureka_optout_choice', // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- WooCommerce checkout field registration argument, not a direct DB query.
			)
		);
	}

	/**
	 * Add placeholder for React component (if needed for custom styling)
	 */
	public function add_block_placeholder() {
		if ( ! is_checkout() || ! $this->module->get_setting( 'enable_optout' ) ) {
			return;
		}

		echo '<div data-wpify-heureka-block-support="true" style="display:none;"></div>';
	}

	/**
	 * Handle order processing for block checkout
	 */
	public function handle_block_checkout_order( $order ) {
		if ( ! $this->module->get_setting( 'api_key' ) ) {
			return;
		}

		// Check if data is already processed
		if ( $order->meta_exists( '_wpify_woo_heureka_optout_agreement' ) ) {
			return;
		}

		$use_optin = $this->module->get_setting( 'optin_mode' );
		$checkbox_value = $order->get_meta( '_wpify_woo_heureka_optout_choice' );

		$should_send = false;

		if ( $use_optin ) {
			// OPT-IN mode: send only if checkbox is checked
			$should_send = !empty( $checkbox_value );
			$agreement_status = !empty( $checkbox_value ) ? 'yes' : 'no';
		} else {
			// OPT-OUT mode: send unless checkbox is checked
			$should_send = empty( $checkbox_value );
			$agreement_status = empty( $checkbox_value ) ? 'yes' : 'no';
		}

		// Send to Heureka if conditions are met
		if ( $should_send ) {
			if ( $this->module->get_setting( 'send_async' ) ) {
				$this->module->schedule_event( $order->get_id() );
			} else {
				$this->module->send_order_to_heureka( $order->get_id() );
			}
		} else {
			// Save agreement status
			$order->update_meta_data( '_wpify_woo_heureka_optout_agreement', 'no' );
			/* translators: %s: Yes or No answer */
			$order->add_order_note( sprintf( __( 'Heureka: Agree with the satisfaction questionnaire: %s', 'wpify-woo' ), __( 'No', 'wpify-woo' ) ) );
			$order->save();
		}
	}

	/**
	 * Save additional field metadata with backward compatibility
	 */
	public function save_field_metadata( $key, $value, $group, $wc_object ) {
		if ( $key === 'wpify/heureka_optout' ) {
			$wc_object->update_meta_data( '_wpify_woo_heureka_optout_choice', $value );
		}
	}
}
