<?php

namespace WpifyWoo\Modules\Vocative;

defined( 'ABSPATH' ) || exit;

use WpifyWoo\Plugin;
use WpifyWoo\WooCommerceIntegration;
use WpifyWooDeps\Wpify\WooCore\Abstracts\AbstractModule;
use WpifyWooDeps\Inflection;

class VocativeModule extends AbstractModule {

	public function __construct(
		private WooCommerceIntegration $woocommerce_integration,
	) {
		parent::__construct();

		add_filter( 'woocommerce_mail_callback_params', array( $this, 'change_name_to_vocative' ), 20, 2 );
	}

	/**
	 * Module ID
	 * @return string
	 */
	public function id(): string {
		return 'vocative';
	}

	public function plugin_slug(): string {
		return Plugin::PLUGIN_SLUG;
	}

	/**
	 * Module documentation path
	 *
	 * @return string
	 */
	public function get_documentation_path(): string {
		return 'wpify-woo/modules/vocative';
	}

	/**
	 * Module settings
	 *
	 * @return array[]
	 */
	public function settings(): array {
		$settings = array(
			array(
				'id'    => 'vocative_title',
				'type'  => 'title',
				'label' => __( 'Vocative in Woo Emails', 'wpify-woo' ),
				'desc'  => __( 'Automatically changes the salutation in Woo emails to vocative.', 'wpify-woo' ),
			),
			array(
				'id'    => 'replace_first_name',
				'type'  => 'text',
				'label' => __( 'Replace first name', 'wpify-woo' ),
				'desc'  => sprintf( __( 'By default, WooCommerce uses first name only in the emails. You can set here to replace the "Hi {first_name}" text. Use {first_name}, {last_name} and {full_name} tags, ie set "Hi {full_name}" as the value.',
					'wpify-woo' ) ),
			),
			array(
				'id'      => 'allowed_languages',
				'type'    => 'multi_select',
				'label'   => __( 'Allowed languages', 'wpify-woo' ),
				'desc'    => sprintf( __( 'Select languages where you want to use the vocative in emails. If you don`t select any language, the vocative will be used in all languages.',
					'wpify-woo' ) ),
				'options'      => function ($args) {
					return $this->woocommerce_integration->get_language_select($args);
				},
				'async'        => true,
				'async_params' => array(
					'tab'       => 'wpify-woo-settings',
					'section'   => $this->id(),
					'module_id' => $this->id(),
				),
			),
		);

		return $settings;
	}

	/**
	 * Module name
	 * @return string
	 */
	public function name(): string {
		return __( 'Emails Vocative', 'wpify-woo' );
	}

	/**
	 * Change name to vocative
	 *
	 * @param $params
	 * @param $email
	 *
	 * @return mixed
	 */
	public function change_name_to_vocative( $params, $email ) {
		if ( ! is_a( $email->object, '\WC_Order' ) ) {
			return $params;
		}
		$allowed_languages = $this->get_setting( 'allowed_languages' ) ?? [];

		if (
			is_array( $allowed_languages )
			&& ! empty( $allowed_languages )
			&& ! in_array( get_locale(), $allowed_languages )
		) {
			return $params;
		}

		$first_name              = $email->object->get_billing_first_name();
		/* translators: %s: Customer first name. */
		$original_text           = sprintf( __( 'Hi %s,', 'woocommerce' ), $first_name ); // phpcs:ignore WordPress.WP.I18n.TextDomainMismatch -- Intentionally uses the WooCommerce text domain to match WooCommerce's own translated email greeting for string replacement.
		$inflection              = new Inflection();
		$to_inflect              = $first_name;
		$replace_first_name_text = $this->get_setting( 'replace_first_name' );

		if ( $replace_first_name_text ) {
			$replaces = [
				'{first_name}' => $this->get_vocative( $inflection, $email->object->get_billing_first_name() ),
				'{last_name}'  => $this->get_vocative( $inflection, $email->object->get_billing_last_name() ),
				'{full_name}'  => $this->get_vocative( $inflection, $email->object->get_formatted_billing_full_name() ),
			];
			$text     = str_replace( array_keys( $replaces ), array_values( $replaces ), $replace_first_name_text );
		} else {
			$inflected = $this->get_vocative( $inflection, $to_inflect );
			$text      = str_replace( $first_name, $inflected, $original_text );
		}

		$params[2] = str_replace( $original_text, $text, $params[2] );

		return $params;
	}

	public function get_vocative( Inflection $inflection, $name ) {
		// Exceptions
		if ( preg_match( "/nis$/", $name ) ) {
			// Yannis/Janis
			return preg_replace( "/nis$/", "nisi", $name );
		}

		$inflected = $inflection->inflect( $name );

		return $inflected[5];
	}
}
