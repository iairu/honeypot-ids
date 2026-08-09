<?php

namespace WpifyWoo;

defined( 'ABSPATH' ) || exit;

use WpifyWoo\Admin\Settings;

/**
 * Class WooCommerceIntegration
 *
 * @package WpifyWoo
 * @property Plugin $plugin
 */
class WooCommerceIntegration {

	const OPTION_NAME = 'wpify-woo-settings';

	/**
	 * Setup
	 *
	 * @return bool|void
	 */
	public function __construct() {
	}

	public function register_settings() {
		/** @var Settings $admin_settings */
		wpify_woo_container()->get( Settings::class )->setup();
	}

	/**
	 * Check if a module is enabled
	 *
	 * @param string $module Module name.
	 *
	 * @return bool
	 */
	public function is_module_enabled( string $module ): bool {
		return in_array( $module, $this->get_enabled_modules(), true );
	}

	/**
	 * Get an array of enabled modules
	 *
	 * @return array
	 */
	public function get_enabled_modules(): array {
		return $this->get_settings( 'general' )['enabled_modules'] ?? array();
	}

	/**
	 * Get settings for a specific module
	 *
	 * @param string $module Module name.
	 *
	 * @return array
	 */
	public function get_settings( string $module ): array {
		return get_option( $this->get_settings_name( $module ), array() );
	}

	public function get_settings_name( string $module ): string {
		return sprintf( '%s-%s', $this::OPTION_NAME, $module );
	}

	/**
	 * Get list of shipping methods for options
	 *
	 * @return array
	 */
	public function get_shipping_methods_option( array $args = [] ): array {
		$search           = sanitize_title( $args['search'] ?? '' );
		$shipping_methods = [];

		foreach ( $this->get_all_zones() as $zone ) {
			$name = $zone['zone_name'];

			foreach ( $zone['shipping_methods'] as $shipping ) {
				/** @var $shipping \WC_Shipping_Flat_Rate */
				$label = sprintf( '%s: %s', $name, $shipping->get_title() );

				if ( ! empty( $search ) ) {
					if ( strpos( sanitize_title( $label ), $search ) === false ) {
						continue;
					}
				}

				$shipping_methods[] = array(
					'label' => $label,
					'value' => $shipping->get_rate_id(),
				);
			}
		}

		return $shipping_methods;
	}

	public function get_avaliable_shipping_methods() {
		$shipping_methods = array();

		$zones = \WC_Shipping_Zones::get_zones();
		//$default_zone = \WC_Shipping_Zones::get_zone_by('zone_id',0);

		foreach ( $zones as $zone ) {
			$name = $zone['zone_name'];
			foreach ( $zone['shipping_methods'] as $shipping ) {
				$shipping_methods[ $shipping->id . ':' . $shipping->instance_id ] = $name . ': ' . $shipping->method_title;
			}
		}

		return $shipping_methods;
	}

	public function get_gateways( array $args = [] ) {
		$search             = sanitize_title( $args['search'] ?? '' );
		$gateways           = array();
		$available_gateways = WC()->payment_gateways()->payment_gateways();
		foreach ( $available_gateways as $key => $gateway ) {
			if ( ! empty( $search ) ) {
				if ( strpos( sanitize_title( $gateway->title ), $search ) === false ) {
					continue;
				}
			}

			$gateways[] = array(
				'label' => $gateway->title,
				'value' => $key,
			);
		}

		return $gateways;
	}

	public function get_order_statuses( array $args = [] ) {
		$search   = sanitize_title( $args['search'] ?? '' );
		$statuses = wc_get_order_statuses();
		$result   = [];
		foreach ( $statuses as $id => $label ) {
			if ( ! empty( $search ) ) {
				if ( strpos( sanitize_title( $label ), $search ) === false ) {
					continue;
				}
			}

			$result[] = [
				'label' => $label,
				'value' => str_replace( 'wc-', '', $id ),
			];
		}

		return $result;
	}

	public function get_emails_select( array $args = [] ) {
		$search = sanitize_title( $args['search'] ?? '' );
		$emails = [];
		foreach ( WC()->mailer()->get_emails() as $wc_email ) {
			$label = $wc_email->title . ' - ' . esc_html( $wc_email->is_customer_email() ? __( 'Customer', 'wpify-woo' ) : $wc_email->get_recipient() );
			if ( ! empty( $search ) ) {
				if ( strpos( sanitize_title( $label ), $search ) === false ) {
					continue;
				}
			}

			$emails[] = [
				'label' => $label,
				'value' => $wc_email->id,
			];
		}

		return $emails;
	}

	public function get_countries_select( array $args = [] ) {
		$countries = WC()->countries->get_allowed_countries();
		$search    = sanitize_title( $args['search'] ?? '' );
		$options   = [];

		foreach ( $countries as $key => $val ) {
			if ( ! empty( $search ) ) {
				if ( strpos( sanitize_title( $val ), $search ) === false ) {
					continue;
				}
			}

			$options[] = [
				'label' => $val,
				'value' => $key,
			];
		}

		if ( isset( $args['qr_type'] ) && ! empty( $args['qr_type'] ) ) {
			switch ( $args['qr_type'] ) {
				case 'cz':
					$options = array_filter( $options, function ( $country ) {
						return $country['value'] == 'CZ';
					} );
					break;
				case 'sk':
					$options = array_filter( $options, function ( $country ) {
						return $country['value'] == 'SK';
					} );
					break;
				case 'hu':
					$options = array_filter( $options, function ( $country ) {
						return $country['value'] == 'HU';
					} );
					break;
			};
		}

		return $options;
	}

	public function get_currencies_select( array $args = [] ) {
		$search     = sanitize_title( $args['search'] ?? '' );
		$currencies = [];
		foreach ( get_woocommerce_currencies() as $key => $val ) {
			if ( ! empty( $search ) ) {
				if ( strpos( sanitize_title( $val ), $search ) === false ) {
					continue;
				}
			}

			$currencies[] = [
				'label' => $val,
				'value' => $key,
			];
		}

		return $currencies;
	}

	public function get_language_select( array $args = [] ) {
		$search    = sanitize_title( $args['search'] ?? '' );
		$languages = [];
		foreach ( get_available_languages() as $val ) {
			if ( ! empty( $search ) ) {
				if ( strpos( sanitize_title( $val ), $search ) === false ) {
					continue;
				}
			}

			$languages[] = [
				'label' => $val,
				'value' => $val,
			];
		}

		return $languages;
	}

	/**
	 * Get all shipping zones
	 *
	 * @return array
	 */
	public function get_all_zones(): array {
		$zones        = \WC_Shipping_Zones::get_zones();
		$default_zone = new \WC_Shipping_Zone( 0 );

		if ( empty( $default_zone->get_shipping_methods() ) ) {
			return $zones;
		}

		$zones[ $default_zone->get_id() ]                            = $default_zone->get_data();
		$zones[ $default_zone->get_id() ]['formatted_zone_location'] = __( 'Other regions', 'wpify-woo' );
		$zones[ $default_zone->get_id() ]['shipping_methods']        = $default_zone->get_shipping_methods();

		return $zones;
	}

	public function is_block_checkout(): bool {
		return \WC_Blocks_Utils::has_block_in_page( wc_get_page_id( 'checkout' ), 'woocommerce/checkout' );
	}

	public function is_block_cart(): bool {
		return \WC_Blocks_Utils::has_block_in_page( wc_get_page_id( 'cart' ), 'woocommerce/cart' );
	}
}
