<?php

namespace WpifyWoo\Modules\IcDic;

defined( 'ABSPATH' ) || exit;

use Exception;
use WC_Data;
use WC_Order;
use WpifyWoo\Plugin;
use WpifyWoo\WooCommerceIntegration;
use WpifyWooDeps\Wpify\WooCore\Abstracts\AbstractModule;
use WpifyWoo\Managers\ApiManager;
use WpifyWoo\Modules\IcDic\Api\IcDicApi;
use WpifyWooDeps\DragonBe\Vies\Vies;
use WpifyWooDeps\DragonBe\Vies\ViesException;
use WpifyWooDeps\DragonBe\Vies\ViesServiceException;
use WpifyWooDeps\h4kuna\Ares;
use WpifyWooDeps\h4kuna\Ares\Exceptions\IdentificationNumberNotFoundException;
use WpifyWooDeps\Wpify\Asset\AssetFactory;
use WpifyWooDeps\Wpify\PluginUtils\PluginUtils;
use WpifyWooDeps\Wpify\Log\RotatingFileLog;

/**
 * Class IcDicModule
 *
 * @package WpifyWoo\Modules\IcDic
 */
class IcDicModule extends AbstractModule {
	const MODULE_ID = 'ic_dic';

	/**
	 * Last VIES validation result for current request
	 * Values: 'valid', 'invalid', 'error', 'skipped', null
	 */
	private ?string $last_vies_result = null;

	/**
	 * Last ARES validation result for current request
	 * Values: 'valid', 'invalid', 'error', 'skipped', null
	 */
	private ?string $last_ares_result = null;

	public function __construct(
		private AssetFactory $asset_factory,
		private PluginUtils $plugin_utils,
		private ApiManager $api_manager,
		private WooCommerceIntegration $woo_integration,
		public RotatingFileLog $log,
	) {
		parent::__construct();
		$this->setup();
	}

	/**
	 * Get last VIES validation result
	 *
	 * @return string|null 'valid', 'invalid', 'error', 'skipped', or null if not yet validated
	 */
	public function get_last_vies_result(): ?string {
		return $this->last_vies_result;
	}

	/**
	 * Set last VIES validation result (for external callers like BlockSupport)
	 *
	 * @param string $result 'valid', 'invalid', 'error', or 'skipped'
	 */
	public function set_last_vies_result( string $result ): void {
		$this->last_vies_result = $result;
	}

	/**
	 * Get last ARES validation result
	 *
	 * @return string|null 'valid', 'invalid', 'error', 'skipped', 'not_applicable', or null
	 */
	public function get_last_ares_result(): ?string {
		return $this->last_ares_result;
	}

	/**
	 * Setup
	 *
	 * @return void
	 */
	public function setup() {
		add_filter( 'woocommerce_checkout_fields', array( $this, 'adjust_checkout_fields' ) );
		add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_scripts' ) );
		add_filter( 'woocommerce_default_address_fields', array( $this, 'adjust_fields_priority' ) );
		add_filter( 'woocommerce_order_formatted_billing_address', array( $this, 'add_fields_to_address' ), 10, 2 );
		add_filter( 'woocommerce_formatted_address_replacements', array( $this, 'replace_tags_in_emails' ), 10, 2 );
		add_filter( 'woocommerce_localisation_address_formats', array( $this, 'localisation_address_formats' ) );
//		add_filter( 'woocommerce_admin_order_data_after_billing_address', array(
//			$this,
//			'display_block_fields_in_admin'
//		) );
		add_action( 'woocommerce_after_checkout_validation', array( $this, 'checkout_validation' ), 10, 2 );
		add_action( 'woocommerce_after_checkout_validation', array( $this, 'apply_vat_exempt_on_classic_checkout' ), 20, 2 );
		add_action( 'woocommerce_checkout_order_processed', array( $this, 'log_order_vat_exempt_decision' ), 10, 3 );
		add_action( 'init', array( $this, 'add_rest_api' ) );

		// Display VAT exempt info in admin order
		add_action( 'woocommerce_admin_order_data_after_billing_address', array( $this, 'display_vat_exempt_info_in_admin' ) );

		if ( $this->get_setting( 'autofill_ares' ) ) {
			if ( 'before_customer_details' === $this->get_setting( 'autofill_ares_position' ) ) {
				add_action( 'woocommerce_checkout_before_customer_details', array( $this, 'render_ares' ) );
			} elseif ( 'after_company_checkbox' === $this->get_setting( 'autofill_ares_position' ) ) {
				add_filter( 'woocommerce_form_field', [ $this, 'add_ares_autofill_to_company_field' ], 10, 2 );
			} elseif ( 'after_ic_field' === $this->get_setting( 'autofill_ares_position' ) ) {
				add_filter( 'woocommerce_form_field', [ $this, 'add_ares_autofill_to_ic_field' ], 10, 2 );
			}
		}

		add_filter( 'woocommerce_billing_fields', array( $this, 'in_vat_woocommerce_billing' ) );
		add_filter( 'woocommerce_admin_billing_fields', array( $this, 'in_vat_woocommerce_billing_admin' ) );
		add_filter( 'woocommerce_customer_meta_fields', array( $this, 'in_vat_woocommerce_billing_profile' ), 10, 1 );
		add_filter(
			'woocommerce_my_account_my_address_formatted_address',
			array(
				$this,
				'add_in_vat_to_address',
			),
			10,
			3
		);
		add_action( 'wp', array( $this, 'set_customer_vat_extempt' ) ); // Only on frontend pages, not admin/ajax
		add_action( 'woocommerce_checkout_update_order_review', array( $this, 'set_vat_extempt_on_order_review' ) );
		add_filter( 'post_class', array( $this, 'add_post_class' ), 10, 3 );
		add_filter( 'woocommerce_ajax_get_customer_details', array( $this, 'autofill_vat_fields_in_admin' ), 10, 3 );


		new BlockSupport( $this );
	}

	/**
	 * Module ID
	 *
	 * @return string
	 */
	public function id(): string {
		return self::MODULE_ID;
	}

	/**
	 * Module name
	 *
	 * @return mixed
	 */
	public function name() {
		return __( 'Checkout IČ and DIČ', 'wpify-woo' );
	}

	/**
	 * Plugin slug
	 *
	 * @return string
	 */

	public function plugin_slug(): string {
		return Plugin::PLUGIN_SLUG;
	}

	/**
	 * Module documentation path
	 *
	 * @return string
	 */
	public function get_documentation_path(): string {
		return 'wpify-woo/modules/ic-dic';
	}

	/**
	 * Enqueue frontend scripts
	 */
	public function enqueue_scripts() {
		if ( ! is_checkout() && ! is_account_page() ) {
			return;
		}

		$this->asset_factory->wp_script( $this->plugin_utils->get_plugin_path( 'build/icdic.css' ) );
		$this->asset_factory->wp_script( $this->plugin_utils->get_plugin_path( 'build/icdic.js' ), array(
			'handle'    => 'wpify-woo-ic-dic',
			'in_footer' => true,
			'variables' => array(
				'wpifyWooIcDic' => array(
					'restUrl'           => $this->api_manager->get_rest_url(),
					'position'          => $this->get_setting( 'autofill_ares_position' ),
					'requireCompany'    => 'hidden' !== get_option( 'woocommerce_checkout_company_field', 'optional' ) ? $this->get_setting( 'required_company' ) : false,
					'moveCompany'       => $this->get_setting( 'move_company_field' ),
					'requireVatFields'  => $this->get_setting( 'required_ic' ),
					'optionalText'      => '(' . esc_html__( 'optional', 'wpify-woo' ) . ')',
					'changePlaceholder' => $this->get_setting( 'change_placeholder' ),
					'checkingText'      => __( 'Checking in', 'wpify-woo' ),
					'validateAres'      => $this->get_setting( 'validate_ares' ),
				),
			),
		) );
		add_action( 'wp_enqueue_scripts', function () {
			// Block checkout assets belong on the checkout page only, not on My Account.
			if ( ! is_checkout() ) {
				return;
			}

			$this->asset_factory->wp_script( $this->plugin_utils->get_plugin_path( 'build/icdic-blocks.js' ), array(
				'handle'       => 'wpify-woo-ic-dic-blocks',
				'in_footer'    => true,
				'variables'    => array(
					'wpifyWooIcDic' => array(
						'restUrl'           => $this->api_manager->get_rest_url(),
						'position'          => $this->get_setting( 'autofill_ares_position' ),
						'requireCompany'    => 'hidden' !== get_option( 'woocommerce_checkout_company_field', 'optional' ) ? $this->get_setting( 'required_company' ) : false,
						'moveCompany'       => $this->get_setting( 'move_company_field' ),
						'requireVatFields'  => $this->get_setting( 'required_ic' ),
						'optionalText'      => '(' . esc_html__( 'optional', 'wpify-woo' ) . ')',
						'changePlaceholder' => $this->get_setting( 'change_placeholder' ),
						'checkingText'      => __( 'Checking in', 'wpify-woo' ),
						'autofillAresText'  => $this->get_setting( 'autofill_ares_text' ) ?: __( 'Autofill from Ares', 'wpify-woo' ),
						'searchAresText'    => $this->get_setting( 'submit_ares_text' ) ?: __( 'Search in Ares', 'wpify-woo' ),
						'validateVies'      => $this->get_setting( 'validate_vies' ),
						'viesFails'         => $this->get_setting( 'vies_fails' ),
						'validateAres'      => $this->get_setting( 'validate_ares' ),
					),
				),
				'dependencies' => array( 'wc-blocks-data-store', 'wc-blocks-checkout' ),
			) );
		}, 1000 );
	}


	/**
	 * Add settings
	 *
	 * @return array
	 */
	public function settings(): array {
		return array(
			array(
				'id'    => 'move_company_field',
				'type'  => 'toggle',
				'label' => __( 'Move company field', 'wpify-woo' ),
				'title' => __( 'Check if you want to move the company field to the extra VAT fields or under the checkbox "I\'m shopping for a company" if enabled.', 'wpify-woo' ),
				'desc'  => __( 'Valid for classic checkout only. Does not affect block checkout.', 'wpify-woo' ),
			),
			array(
				'id'    => 'move_vat_fields',
				'type'  => 'toggle',
				'label' => __( 'Move VAT fields', 'wpify-woo' ),
				'title' => __( 'Check if you want to move the VAT fields to the top of the checkout form to the "Company" field', 'wpify-woo' ),
				'desc'  => __( 'Valid for classic checkout only. Does not affect block checkout.', 'wpify-woo' ),
			),
			array(
				'id'    => 'show_checkbox',
				'type'  => 'toggle',
				'label' => __( 'Show "I\'m shopping for a company" checkbox', 'wpify-woo' ),
				'title' => __( 'Check if want to show the checkbox "I\'m shopping for a company" - the extra fields will show only if the checkbox is checked.', 'wpify-woo' ),
				'desc'  => __( 'Valid for classic checkout only. Does not affect block checkout.', 'wpify-woo' ),
			),
			array(
				'id'    => 'narrow_vat_fields',
				'type'  => 'toggle',
				'label' => __( 'Half width VAT fields', 'wpify-woo' ),
				'title' => __( 'Check if you want to display VAT fields in half width side by side in the checkout.', 'wpify-woo' ),
				'desc'  => __( 'Valid for classic checkout only. Does not affect block checkout.', 'wpify-woo' ),
			),
			array(
				'id'    => 'change_placeholder',
				'type'  => 'toggle',
				'label' => __( 'Placeholder as number', 'wpify-woo' ),
				'title' => __( 'Check if you want the placeholder of VAT fields to be an example of how to fill the field.', 'wpify-woo' ),
				'desc'  => __( 'Valid for classic checkout only. Does not affect block checkout.', 'wpify-woo' ),
			),
			array(
				'id'    => 'validate_format',
				'type'  => 'toggle',
				'label' => __( 'Validate number format', 'wpify-woo' ),
				'title' => __( 'Check if you want to check if the numbers entered are in a valid format when sending order. Checks for States CZ, SK, PL, HU, DE', 'wpify-woo' ),
				'desc'  => __( 'Valid for classic checkout only. Does not affect block checkout.', 'wpify-woo' ),
			),
			array(
				'id'    => 'required_company',
				'type'  => 'toggle',
				'label' => __( 'Required "Company" field for companies', 'wpify-woo' ),
				'title' => __( 'Check if you want to set "Company" field as required if the checkbox "I\'m shopping for a company" is checked.', 'wpify-woo' ),
				'desc'  => __( 'Valid for classic checkout only. Does not affect block checkout.', 'wpify-woo' ),
			),
			array(
				'id'      => 'required_ic',
				'type'    => 'select',
				'label'   => __( 'Required identification number field for companies', 'wpify-woo' ),
				'desc'    => sprintf( '%s %s', __( 'Choose when the identification number field to be required.', 'wpify-woo' ), __( 'Valid for classic checkout only. Does not affect block checkout.', 'wpify-woo' ) ),
				'options' => array(
					array(
						'label' => __( 'If the "I\'m shopping for a company" is checked', 'wpify-woo' ),
						'value' => 'if_checkbox',
					),
					array(
						'label' => __( 'If the company field is filled', 'wpify-woo' ),
						'value' => 'if_company',
					),
				),
			),
			array(
				'id'      => 'validate_ares',
				'type'    => 'multi_toggle',
				'label'   => __( 'Validate entered identification number from ARES', 'wpify-woo' ),
				'desc'    => __( 'Check if want to validate the entered identification number with ARES.', 'wpify-woo' ),
				'options' => array(
					array(
						'label' => __( 'After entering identification number on the checkout form', 'wpify-woo' ),
						'value' => 'ic_entered',
					),
					array(
						'label' => __( 'After submitting the order', 'wpify-woo' ),
						'value' => 'order_submit',
					),
				),
			),
			array(
				'id'    => 'autofill_ares',
				'type'  => 'toggle',
				'label' => __( 'Autofill from ARES', 'wpify-woo' ),
				'title' => __( 'Enable if you want to display "Fill automatically from ARES" at the top of checkout form.', 'wpify-woo' ),
				'desc'  => __( 'Valid for classic checkout only. Does not affect block checkout.', 'wpify-woo' ),
			),
			array(
				'id'            => 'autofill_ares_text',
				'type'          => 'text',
				'label'         => __( 'Autofill from ARES text', 'wpify-woo' ),
				'desc'          => __( 'Enter the text that will appear on top of the checkout.', 'wpify-woo' ),
				'default_value' => __( 'Autofill from Ares', 'wpify-woo' ),
			),
			array(
				'id'            => 'submit_ares_text',
				'type'          => 'text',
				'label'         => __( 'ARES submit button text', 'wpify-woo' ),
				'desc'          => __( 'Enter the text for the button sending the request to ARES.', 'wpify-woo' ),
				'default_value' => __( 'Search in ARES', 'wpify-woo' ),
			),
			array(
				'id'            => 'autofill_ares_position',
				'type'          => 'select',
				'label'         => __( 'Autofill ARES position', 'wpify-woo' ),
				'desc'          => sprintf( '%s %s', __( 'Select the position for the autofill.', 'wpify-woo' ), __( 'Valid for classic checkout only. Does not affect block checkout.', 'wpify-woo' ) ),
				'default_value' => 'before_customer_details',
				'options'       => [
					[
						'label' => __( 'Before customer details', 'wpify-woo' ),
						'value' => 'before_customer_details',
					],
					[
						'label' => __( 'After "I\'m shopping for a company" checkbox', 'wpify-woo' ),
						'value' => 'after_company_checkbox',
					],
					[
						'label' => __( 'After "IC" field', 'wpify-woo' ),
						'value' => 'after_ic_field',
					],
				],
			),
			array(
				'id'    => 'validate_vies',
				'type'  => 'toggle',
				'label' => __( 'Validate VAT number in VIES', 'wpify-woo' ),
				'title' => __( 'Check if want to validate the entered VAT with VIES (IN VAT for SK).', 'wpify-woo' ),
			),
			array(
				'id'    => 'vies_fails',
				'type'  => 'toggle',
				'label' => __( 'Send an order even if it fails validation in VIES', 'wpify-woo' ),
				'title' => __( 'Check if you want to validate the Tax Identification Number immediately after entering and allow the order to be sent even if the validation in VIES fails. If the Tax ID falls under the set countries for zero VAT, then zero VAT will not be applied.',
					'wpify-woo' ),
			),
			array(
				'id'           => 'zero_tax_for_vat_countries',
				'type'         => 'multi_select',
				'label'        => __( 'Zero tax for VAT numbers in (DEPRECATED)', 'wpify-woo' ),
				'desc'         => __( 'DEPRECATED: Use "Enable EU Reverse Charge" and "Enable Third Country Export" settings below instead. This setting is kept only for backward compatibility.', 'wpify-woo' ),
				'async_params' => [
					'module_id' => $this->id(),
				],
				'options'      => function () {
					return $this->get_eu_countries();
				},
				'multi'        => true,
				'default'      => array(),
				'disabled'     => true,
			),
			// New VAT exempt settings
			array(
				'id'    => 'vat_exempt_separator',
				'type'  => 'title',
				'title' => __( 'VAT Exemption Settings', 'wpify-woo' ),
				'desc' => sprintf(
				/* translators: %s: link to WooCommerce tax settings */
					__( 'VAT exemption uses the WooCommerce setting "Calculate tax based on" (%s). If set to "Customer billing address", billing country is used for VAT determination (typical for services). Otherwise, shipping country is used (typical for goods).', 'wpify-woo' ),
					'<a href="' . admin_url( 'admin.php?page=wc-settings&tab=tax' ) . '">' . __( 'WooCommerce → Settings → Tax', 'wpify-woo' ) . '</a>'
				),
			),
			array(
				'id'    => 'enable_eu_reverse_charge',
				'type'  => 'toggle',
				'label' => __( 'Enable EU Reverse Charge', 'wpify-woo' ),
				'title' => __( 'Enable reverse charge mechanism for B2B sales within EU', 'wpify-woo' ),
				'desc'  => __( 'When enabled, orders with valid EU VAT ID (verified via VIES) shipped to another EU country will be exempt from VAT. The invoice should include "Reverse charge" notice.', 'wpify-woo' ),
			),
			array(
				'id'    => 'enable_third_country_export',
				'type'  => 'toggle',
				'label' => __( 'Enable Third Country Export (VAT exempt)', 'wpify-woo' ),
				'title' => __( 'Enable VAT exemption for exports to non-EU countries', 'wpify-woo' ),
				'desc'  => __( 'When enabled, orders shipped to countries outside the EU will be exempt from VAT. This applies to both B2B and B2C customers. Note: You need customs documentation to prove the export.', 'wpify-woo' ),
			),
		);
	}

	private function get_eu_countries() {
		$countries = Vies::listEuropeanCountries();

		array_walk(
			$countries,
			function ( &$country, $code ) {
				$country = array(
					'label' => $country . ' (' . $code . ')',
					'value' => $code,
				);
			}
		);

		return array_values( $countries );
	}

	/**
	 * Get EU country codes as simple array
	 *
	 * @return array
	 */
	public function get_eu_country_codes(): array {
		$eu_countries = WC()->countries->get_european_union_countries();

		/**
		 * Filter the list of EU country codes.
		 *
		 * Useful for adding/removing countries from the EU list (e.g., after Brexit).
		 *
		 * @param array $eu_countries Array of EU country codes.
		 */
		return apply_filters( 'wpify_woo_icdic_eu_country_codes', $eu_countries );
	}

	/**
	 * Check if any VAT exempt functionality is enabled
	 *
	 * @return bool
	 */
	public function is_vat_exempt_enabled(): bool {
		return $this->get_setting( 'enable_eu_reverse_charge' )
			|| $this->get_setting( 'enable_third_country_export' )
			|| ! empty( $this->get_setting( 'zero_tax_for_vat_countries' ) );
	}

	/**
	 * Get VAT ID from customer or order based on billing country
	 *
	 * For Slovakia (SK), uses billing_dic_dph field.
	 * For other countries, uses billing_dic field.
	 *
	 * @param \WC_Customer|\WC_Order $source          Customer or Order object
	 * @param string                 $billing_country Billing country code
	 *
	 * @return string VAT ID or empty string
	 */
	public function get_vat_id_from_source( $source, string $billing_country ): string {
		$meta_key = $billing_country === 'SK' ? 'billing_dic_dph' : 'billing_dic';

		if ( $source instanceof \WC_Order ) {
			return $source->get_meta( '_' . $meta_key ) ?: '';
		}

		return $source->get_meta( $meta_key ) ?: '';
	}

	/**
	 * Get shipping country with billing country fallback
	 *
	 * @param \WC_Customer|\WC_Order $source          Customer or Order object
	 * @param string                 $billing_country Billing country code
	 *
	 * @return string Shipping country code
	 */
	public function get_shipping_country_with_fallback( $source, string $billing_country ): string {
		$shipping = $source->get_shipping_country();

		return ! empty( $shipping ) ? $shipping : $billing_country;
	}

	/**
	 * Get VAT ID from form data array based on billing country
	 *
	 * @param array  $data            Form data array
	 * @param string $billing_country Billing country code
	 *
	 * @return string VAT ID or empty string
	 */
	public function get_vat_id_from_form_data( array $data, string $billing_country ): string {
		if ( $billing_country === 'SK' ) {
			return $data['billing_dic_dph'] ?? '';
		}

		return $data['billing_dic'] ?? '';
	}

	/**
	 * Get VAT ID from block checkout additional_fields
	 *
	 * @param array  $additional_fields Block checkout additional_fields array
	 * @param string $billing_country   Billing country code
	 *
	 * @return string VAT ID or empty string
	 */
	public function get_vat_id_from_block_checkout( array $additional_fields, string $billing_country ): string {
		if ( $billing_country === 'SK' ) {
			return $additional_fields['wpify/dic-dph'] ?? '';
		}

		return $additional_fields['wpify/dic'] ?? '';
	}

	/**
	 * Validate VAT ID for VAT exemption (reverse charge) purposes
	 *
	 * IMPORTANT: For VAT exemption (reverse charge), the VAT ID must be actually valid.
	 * The vies_fails setting only controls whether to BLOCK checkout, not whether to apply exemption.
	 *
	 * Logic:
	 * - If validate_vies is disabled: VAT ID is considered valid (basic format check only)
	 * - If validate_vies is enabled: VAT ID must be validated by VIES
	 *   - If VIES returns valid: exempt = true
	 *   - If VIES returns invalid/fails: exempt = false (regardless of vies_fails setting)
	 *
	 * The vies_fails setting is handled separately in checkout validation:
	 * - vies_fails = false: Block checkout if VIES fails
	 * - vies_fails = true: Allow checkout but order will have VAT (no exemption)
	 *
	 * @param string $vat_id The VAT ID to validate
	 * @param bool   $already_validated Whether the VAT ID was already validated as valid
	 *
	 * @return bool Whether the VAT ID is valid for VAT exemption
	 */
	public function validate_vat_id_for_exempt( string $vat_id, bool $already_validated = false ): bool {
		// If already validated as valid (e.g., during checkout), trust the result
		if ( $already_validated ) {
			$is_valid = true;
		} elseif ( strlen( $vat_id ) < 3 || ! preg_match( '/^[A-Z]{2}/', strtoupper( $vat_id ) ) ) {
			// Basic format check - must have at least 2 letter country prefix
			$is_valid = false;
		} elseif ( ! $this->get_setting( 'validate_vies' ) ) {
			// If VIES validation is disabled, accept the VAT ID without VIES check
			// (shop owner takes responsibility for validity)
			$is_valid = true;
		} else {
			// VIES validation is enabled - VAT ID must be actually valid for exemption
			// Note: vies_fails setting does NOT affect this - it only controls checkout blocking
			$is_valid = $this->is_valid_dic( $vat_id );
		}

		/**
		 * Filter whether a VAT ID is valid for VAT exemption purposes.
		 *
		 * Allows custom VAT ID validation logic (e.g., local database, custom API).
		 *
		 * @param bool   $is_valid Whether the VAT ID is considered valid.
		 * @param string $vat_id   The VAT ID being validated.
		 */
		return apply_filters( 'wpify_woo_icdic_vat_id_valid_for_exempt', $is_valid, $vat_id );
	}

	/**
	 * Determine if VAT should be exempt and why
	 *
	 * This is the main method for determining VAT exemption based on:
	 * - EU Reverse Charge (B2B within EU with valid VAT ID)
	 * - Third Country Export (shipping outside EU)
	 *
	 * @param string $billing_country  Customer billing country code
	 * @param string $shipping_country Customer shipping country code
	 * @param string $vat_id           Customer VAT ID (DIČ/IČ DPH)
	 * @param bool   $vat_id_validated Whether VAT ID has been validated via VIES
	 *
	 * @return array{
	 *     exempt: bool,
	 *     reason: string
	 * }
	 */
	public function should_exempt_vat( string $billing_country, string $shipping_country, string $vat_id = '', bool $vat_id_validated = false ): array {
		$shop_country = wc_get_base_location()['country'];

		// Determine destination country based on WooCommerce tax setting
		// 'billing' = services (use billing country), otherwise = goods (use shipping country)
		$tax_based_on = get_option( 'woocommerce_tax_based_on', 'shipping' );
		if ( $tax_based_on === 'billing' ) {
			// Services - use billing country (where customer is established)
			$destination_country = $billing_country;
		} else {
			// Goods - use shipping country (where goods are delivered)
			$destination_country = ! empty( $shipping_country ) ? $shipping_country : $billing_country;
		}

		/**
		 * Filter the destination country used for VAT exempt determination.
		 *
		 * Useful for integrating geolocation or custom country logic.
		 *
		 * @param string $destination_country The determined destination country code.
		 * @param string $billing_country     The billing country code.
		 * @param string $shipping_country    The shipping country code.
		 * @param string $shop_country        The shop's base country code.
		 */
		$destination_country = apply_filters(
			'wpify_woo_icdic_destination_country',
			$destination_country,
			$billing_country,
			$shipping_country,
			$shop_country
		);

		// 1. DOMESTIC SALE - most common case, return early
		// No VAT exemption possible when destination = shop country
		if ( $destination_country === $shop_country ) {
			$result = array(
				'exempt' => false,
				'reason' => 'domestic',
			);

			/** This filter is documented below */
			return apply_filters( 'wpify_woo_icdic_vat_exempt_result', $result, $billing_country, $shipping_country, $vat_id, $destination_country );
		}

		$eu_countries      = $this->get_eu_country_codes();
		$is_eu_destination = in_array( $destination_country, $eu_countries, true );

		// 2. EXPORT - destination outside EU
		// Always VAT exempt for both B2B and B2C when enabled
		if ( $this->get_setting( 'enable_third_country_export' ) && ! $is_eu_destination ) {
			$result = array(
				'exempt' => true,
				'reason' => 'export',
			);

			/** This filter is documented below */
			return apply_filters( 'wpify_woo_icdic_vat_exempt_result', $result, $billing_country, $shipping_country, $vat_id, $destination_country );
		}

		// 3. EU REVERSE CHARGE - B2B within EU (destination != shop country already checked)
		if ( $this->get_setting( 'enable_eu_reverse_charge' ) && $is_eu_destination && ! empty( $vat_id ) ) {
			$is_valid_vat = $this->validate_vat_id_for_exempt( $vat_id, $vat_id_validated );
			if ( $is_valid_vat ) {
				$result = array(
					'exempt' => true,
					'reason' => 'reverse_charge',
				);

				/** This filter is documented below */
				return apply_filters( 'wpify_woo_icdic_vat_exempt_result', $result, $billing_country, $shipping_country, $vat_id, $destination_country );
			}
		}

		// 4. LEGACY - old zero_tax_for_vat_countries setting (only if new settings disabled)
		if ( ! $this->get_setting( 'enable_eu_reverse_charge' ) && ! $this->get_setting( 'enable_third_country_export' ) ) {
			$legacy_countries = $this->get_setting( 'zero_tax_for_vat_countries' );
			if ( ! empty( $legacy_countries ) && ! empty( $vat_id ) ) {
				if ( in_array( $destination_country, $legacy_countries, true ) ) {
					$is_valid_vat = $this->validate_vat_id_for_exempt( $vat_id, $vat_id_validated );
					if ( $is_valid_vat ) {
						$result = array(
							'exempt' => true,
							'reason' => 'legacy',
						);

						/** This filter is documented below */
						return apply_filters( 'wpify_woo_icdic_vat_exempt_result', $result, $billing_country, $shipping_country, $vat_id, $destination_country );
					}
				}
			}
		}

		// 5. DEFAULT - no exemption (EU B2C or invalid/missing VAT ID)
		$result = array(
			'exempt' => false,
			'reason' => 'standard',
		);

		/**
		 * Filter the VAT exempt result.
		 *
		 * Allows overriding the VAT exemption decision.
		 *
		 * @param array  $result {
		 *     The VAT exempt result.
		 *
		 *     @type bool   $exempt Whether VAT is exempt.
		 *     @type string $reason The reason code (domestic, export, reverse_charge, legacy, standard).
		 * }
		 * @param string $billing_country     The billing country code.
		 * @param string $shipping_country    The shipping country code.
		 * @param string $vat_id              The VAT ID.
		 * @param string $destination_country The destination country used for determination.
		 */
		return apply_filters( 'wpify_woo_icdic_vat_exempt_result', $result, $billing_country, $shipping_country, $vat_id, $destination_country );
	}

	/**
	 * Save VAT exempt metadata to order
	 *
	 * Note: is_vat_exempt is saved automatically by WooCommerce,
	 * we only save the reason for the exemption.
	 *
	 * @param \WC_Order $order
	 * @param array     $vat_exempt_result Result from should_exempt_vat()
	 */
	public function save_vat_exempt_meta( \WC_Order $order, array $vat_exempt_result ): void {
		// is_vat_exempt is saved by WooCommerce automatically, we only save the reason
		$order->update_meta_data( '_wpify_vat_exempt_reason', $vat_exempt_result['reason'] );
		$order->save();
	}

	/**
	 * Apply VAT exempt state on the current customer.
	 *
	 * SSOT for the "evaluate decision + set on customer + optionally recalc cart"
	 * pattern. All entry points (wp hook, classic AJAX, classic submit, block REST,
	 * block store-api callback) delegate to this method. Input extraction stays
	 * in callers — they each know their source (POST, JSON, customer meta).
	 *
	 * @param string $billing_country
	 * @param string $shipping_country
	 * @param string $vat_id
	 * @param bool   $vat_id_validated Pass true if VIES already validated as valid in same request.
	 * @param bool   $recalc_cart      Force cart recalculation after applying.
	 * @return array{exempt: bool, reason: string}
	 */
	public function apply_vat_exempt_state(
		string $billing_country,
		string $shipping_country,
		string $vat_id = '',
		bool $vat_id_validated = false,
		bool $recalc_cart = false
	): array {
		$result = $this->should_exempt_vat( $billing_country, $shipping_country, $vat_id, $vat_id_validated );

		if ( ! empty( WC()->customer ) ) {
			WC()->customer->set_is_vat_exempt( $result['exempt'] );
		}

		if ( $recalc_cart && ! empty( WC()->cart ) ) {
			WC()->cart->calculate_totals();
		}

		return $result;
	}

	/**
	 * Get VAT exempt info from order
	 *
	 * @param \WC_Order $order
	 *
	 * @return array{
	 *     exempt: bool,
	 *     reason: string
	 * }
	 */
	public function get_order_vat_exempt_info( \WC_Order $order ): array {
		return array(
			'exempt' => $order->get_meta( 'is_vat_exempt' ) === 'yes', // WooCommerce standard meta
			'reason' => $order->get_meta( '_wpify_vat_exempt_reason' ) ?: 'standard',
		);
	}

	/**
	 * Adjust the checkout fields
	 *
	 * @param array $fields Array of the checkout fields.
	 *
	 * @return array
	 */
	public function adjust_checkout_fields( array $fields ): array {
		$fields_default = $this->in_vat_woocommerce_billing( $fields );

		$temp_ic = ! empty( $fields['billing']['billing_ic'] ) && is_array( $fields['billing']['billing_ic'] )
			? $fields['billing']['billing_ic']
			: $fields_default['billing_ic'];
		unset( $fields['billing']['billing_ic'] );

		$temp_dic = ! empty( $fields['billing']['billing_dic'] ) && is_array( $fields['billing']['billing_dic'] )
			? $fields['billing']['billing_dic']
			: $fields_default['billing_dic'];
		unset( $fields['billing']['billing_dic'] );

		$temp_dic_dph = ! empty( $fields['billing']['billing_dic_dph'] ) && is_array( $fields['billing']['billing_dic_dph'] )
			? $fields['billing']['billing_dic_dph']
			: $fields_default['billing_dic_dph'];
		unset( $fields['billing']['billing_dic_dph'] );

		$extra_billing_fields = array();
		$classes              = array( 'form-row-wide' );

		if ( $this->get_setting( 'show_checkbox' ) ) {
			$extra_billing_fields['company_details'] = array(
				'type'     => 'checkbox',
				'label'    => __( 'I\'m shopping for a company', 'wpify-woo' ),
				'required' => false,
				'class'    => array( 'form-row-wide', 'wpify-woo-ic-dic__toggle' ),
				'priority' => $this->get_setting( 'move_vat_fields' ) ? 31 : 200,
			);

			$classes[] = 'wpify-woo-ic-dic__company_field';
		}

		if ( ! empty( $this->get_setting( 'validate_ares' ) ) && in_array( 'ic_entered', $this->get_setting( 'validate_ares' ) ) ) {
			$classes[] = 'wpify-woo-ic--validate';
		}

		if (
			! empty( $this->get_setting( 'validate_vies' ) ) && $this->get_setting( 'validate_vies' ) === true
		) {
			$classes[] = 'wpify-woo-vies--validate';
		}

		if ( $this->get_setting( 'move_company_field' ) && ! empty( $fields['billing']['billing_company'] ) ) {
			$temp_company = $fields['billing']['billing_company'];
			unset( $fields['billing']['billing_company'] );
			$extra_billing_fields['billing_company'] = array_merge(
				$temp_company,
				array(
					'class'    => $classes,
					'priority' => $this->get_setting( 'move_vat_fields' ) ? 32 : ( 'after_ic_field' === $this->get_setting( 'autofill_ares_position' ) ? 214 : 210 ),
				)
			);
		} else {
			$fields['billing']['billing_company']['classes'] = $classes;
		}

		$extra_billing_fields['billing_ic'] = array_merge(
			$temp_ic,
			array(

				'class'    => $classes,
				'priority' => $this->get_setting( 'move_vat_fields' ) ? 33 : 211,
			)
		);

		$extra_billing_fields['billing_dic'] = array_merge(
			$temp_dic,
			array(
				'class'    => $classes,
				'priority' => $this->get_setting( 'move_vat_fields' ) ? 34 : 212,
			)
		);

		$extra_billing_fields['billing_dic_dph'] = array_merge(
			$temp_dic_dph,
			array(
				'class'    => $classes,
				'priority' => $this->get_setting( 'move_vat_fields' ) ? 35 : 213,
			)
		);

		if ( $this->get_setting( 'narrow_vat_fields' ) ) {
			$extra_billing_fields['billing_ic']['class'][0]      = 'form-row-first';
			$extra_billing_fields['billing_dic']['class'][0]     = 'form-row-last';
			$extra_billing_fields['billing_dic_dph']['class'][0] = 'form-row-first';
		}

		$fields['billing'] = array_merge( $fields['billing'], $extra_billing_fields );

		return $fields;
	}

	public function in_vat_woocommerce_billing( $fields = array() ) {
		$fields['billing_ic'] = array(
			'label'       => __( 'Identification no.', 'wpify-woo' ),
			'placeholder' => __( 'Your company\'s identification number', 'wpify-woo' ),
			'required'    => false,
			'type'        => 'text',
		);

		$fields['billing_dic'] = array(
			'label'       => __( 'VAT no.', 'wpify-woo' ),
			'placeholder' => __( 'Your company\'s VAT number', 'wpify-woo' ),
			'required'    => false,
			'type'        => 'text',
		);

		$fields['billing_dic_dph'] = array(
			'label'       => __( 'IN VAT no.', 'wpify-woo' ),
			'placeholder' => __( 'Your company\'s VAT Identification number', 'wpify-woo' ),
			'required'    => false,
			'type'        => 'text',
		);

		return $fields;
	}

	/**
	 * Add editable in vat billing fields in order admin
	 *
	 * @param array $fields
	 *
	 * @return array
	 */
	public function in_vat_woocommerce_billing_admin( array $fields ): array {
		if ( isset( $fields['wpify/company'] ) ) {
			unset( $fields['wpify/company'] );
		}
		if ( isset( $fields['wpify/ic_dic_toggle'] ) ) {
			unset( $fields['wpify/ic_dic_toggle'] );
		}
		if ( isset( $fields['wpify/ic'] ) ) {
			unset( $fields['wpify/ic'] );
		}
		if ( isset( $fields['wpify/dic'] ) ) {
			unset( $fields['wpify/dic'] );
		}
		if ( isset( $fields['wpify/dic-dph'] ) ) {
			unset( $fields['wpify/dic-dph'] );
		}

		$fields['ic'] = array(
			'label'         => __( 'Identification no.', 'wpify-woo' ),
			'show'          => false,
			'wrapper_class' => '',
			'style'         => '',
		);

		$fields['dic'] = array(
			'label'         => __( 'VAT no.', 'wpify-woo' ),
			'show'          => false,
			'wrapper_class' => 'last',
			'style'         => '',
		);

		$fields['dic_dph'] = array(
			'label'         => __( 'IN VAT no.', 'wpify-woo' ),
			'show'          => false,
			'wrapper_class' => '',
			'style'         => '',
		);

		return $fields;
	}

	/**
	 * Add editable in vat billing fields in user profile
	 *
	 * @param $fields
	 *
	 * @return array
	 */
	function in_vat_woocommerce_billing_profile( $fields ): array {
		$fields['billing']['fields']['billing_ic'] = array(
			'label'       => __( 'Identification no.', 'wpify-woo' ),
			'description' => '',
		);

		$fields['billing']['fields']['billing_dic'] = array(
			'label'       => __( 'VAT no.', 'wpify-woo' ),
			'description' => '',
		);

		$fields['billing']['fields']['billing_dic_dph'] = array(
			'label'       => __( 'IN VAT no.', 'wpify-woo' ),
			'description' => '',
		);

		return $fields;
	}

	/**
	 * Adjust checkout fields priorities
	 *
	 * @param array $fields Array of the fields.
	 *
	 * @return mixed
	 */
	public function adjust_fields_priority( array $fields ): array {
		if ( $this->get_setting( 'move_company_field' && ! $this->get_setting( 'move_vat_fields' ) ) ) {
			$fields['company']['priority'] = 210;
		}

		return $fields;
	}

	/**
	 * Add details to localisation address formats
	 *
	 * @param array $address_formats Address formats.
	 *
	 * @return mixed
	 */
	public function localisation_address_formats( array $address_formats ): array {
		if ( $this->woo_integration->is_block_checkout() && is_checkout() || apply_filters( 'wpify_woo_add_ic_dic_to_address', true ) === false ) {
			return $address_formats;
		}

		foreach ( $address_formats as $key => $format ) {
			$address_formats[ $key ] = $format . "\n{billing_ic}\n{billing_dic}\n{billing_dic_dph}";
		}

		return $address_formats;
	}

//	public function display_block_fields_in_admin( $order ) {
//		$billing_ic      = $order->get_meta( '_billing_ic', true );
//		$billing_dic     = $order->get_meta( '_billing_dic', true );
//		$billing_dic_dph = $order->get_meta( '_billing_dic_dph', true );
//
//		echo '<div class="address"><p>';
//		if ( $billing_ic ) {
//			echo '<span>' . __( 'Identification no.', 'wpify-woo' ) . ':</span> ' . esc_html( $billing_ic );
//		}
//		if ( $billing_dic ) {
//			echo '<br><span>' . __( 'VAT no.', 'wpify-woo' ) . ':</span> ' . esc_html( $billing_dic );
//		}
//		if ( $billing_dic_dph ) {
//			echo '<br><span>' . __( 'IN VAT no.', 'wpify-woo' ) . ':</span> ' . esc_html( $billing_dic_dph );
//		}
//		echo '</p></div>';
//	}

	/**
	 * Add the fields values to the address
	 *
	 * @param array    $address Address.
	 * @param WC_Order $order   Order.
	 *
	 * @return array
	 */
	public function add_fields_to_address( array $address, WC_Order $order ): array {
		$address['billing_ic']      = $order->get_meta( '_billing_ic', true );
		$address['billing_dic']     = $order->get_meta( '_billing_dic', true );
		$address['billing_dic_dph'] = $order->get_meta( '_billing_dic_dph', true );

		return $address;
	}

	/**
	 * Replace the tags in emails
	 *
	 * @param array $replacements Array of replacements.
	 * @param array $args         Array of the available args.
	 *
	 * @return array
	 */
	public function replace_tags_in_emails( array $replacements, array $args ): array {
		if ( ! empty( $args['billing_ic'] ) ) {
			$replacements['{billing_ic}'] = sprintf( '%s: %s', __( 'Identification no.', 'wpify-woo' ), $args['billing_ic'] );
		} else {
			$replacements['{billing_ic}'] = '';
		}

		if ( ! empty( $args['billing_dic'] ) ) {
			$replacements['{billing_dic}'] = sprintf( '%s: %s', __( 'VAT no.', 'wpify-woo' ), $args['billing_dic'] );
		} else {
			$replacements['{billing_dic}'] = '';
		}

		if ( ! empty( $args['billing_dic_dph'] ) ) {
			$replacements['{billing_dic_dph}'] = sprintf( '%s: %s', __( 'IN VAT no.', 'wpify-woo' ), $args['billing_dic_dph'] );
		} else {
			$replacements['{billing_dic_dph}'] = '';
		}

		return $replacements;
	}

	/**
	 * Validate the checkout
	 *
	 * @param array $fields Array of the fields.
	 * @param       $errors
	 */
	public function checkout_validation( $fields, $errors ) {
		// WooCommerce verifies the checkout nonce before running validation hooks.
		// phpcs:disable WordPress.Security.NonceVerification.Missing
		$country         = isset( $_POST['billing_country'] ) ? sanitize_text_field( wp_unslash( $_POST['billing_country'] ) ) : '';
		$billing_ic      = isset( $_POST['billing_ic'] ) ? sanitize_text_field( wp_unslash( $_POST['billing_ic'] ) ) : '';
		$billing_dic     = isset( $_POST['billing_dic'] ) ? sanitize_text_field( wp_unslash( $_POST['billing_dic'] ) ) : '';
		$billing_dic_dph = isset( $_POST['billing_dic_dph'] ) ? sanitize_text_field( wp_unslash( $_POST['billing_dic_dph'] ) ) : '';
		$billing_company = isset( $_POST['billing_company'] ) ? sanitize_text_field( wp_unslash( $_POST['billing_company'] ) ) : '';
		$company_details = isset( $_POST['company_details'] ) ? sanitize_text_field( wp_unslash( $_POST['company_details'] ) ) : '';
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		// ARES validation (only for CZ)
		if ( $country !== 'CZ' ) {
			$this->last_ares_result = 'not_applicable';
		} elseif ( ! $this->get_setting( 'validate_ares' )
			|| ! in_array( 'order_submit', $this->get_setting( 'validate_ares' ) )
		) {
			$this->last_ares_result = 'skipped';
		} elseif ( empty( $billing_ic ) ) {
			$this->last_ares_result = 'skipped';
		} else {
			$ares = ( new Ares\AresFactory() )->create();
			$ic   = $billing_ic;

			if ( ! is_numeric( $ic ) ) {
				$this->last_ares_result = 'invalid';
				$errors->add( 'validation', __( 'Please enter valid IC', 'wpify-woo' ) );
			} else {
				try {
					$ares->loadBasic( $ic );
					$this->last_ares_result = 'valid';
				} catch ( IdentificationNumberNotFoundException $e ) {
					$this->last_ares_result = 'invalid';
					$errors->add( 'validation', __( 'The entered Company Number has not been found in ARES, please enter valid company number.', 'wpify-woo' ) );
				} catch ( Exception $e ) {
					$this->last_ares_result = 'error';
					$this->log->error( 'ARES ERROR', array(
						'code'    => $e->getCode(),
						'message' => $e->getMessage(),
					) );
				}
			}
		}

		// VIES validation
		if ( ! $this->get_setting( 'validate_vies' ) ) {
			$this->last_vies_result = 'skipped';
		} else {
			$dic_dph = $country === 'SK' ? $billing_dic_dph : $billing_dic;

			if ( empty( $dic_dph ) ) {
				$this->last_vies_result = 'skipped';
			} elseif ( ! $this->is_valid_dic( $dic_dph ) && $this->get_last_vies_result() !== 'error' ) {
				// is_valid_dic already sets last_vies_result
				if ( $this->get_setting( 'vies_fails' ) !== true ) {
					$error_msg = $country === 'SK'
						? __( 'The entered IN VAT Number has not been found in VIES, please enter valid IN VAT number.', 'wpify-woo' )
						: __( 'The entered VAT Number has not been found in VIES, please enter valid VAT number.', 'wpify-woo' );
					$errors->add( 'validation', $error_msg );
				}
			}
			// Note: is_valid_dic() already sets last_vies_result for valid/invalid/error cases
		}

		if ( $this->get_setting( 'validate_format' ) ) {
			if ( ! empty( $billing_ic ) && ! preg_match( '~^\d{8,}$~', $billing_ic ) ) {
				$errors->add( 'validation', __( 'The entered Company Number is not in the required format (8 or more digits without spaces).', 'wpify-woo' ) );
			}

			if ( $country === 'SK' ) {
				if ( ! empty( $billing_dic ) && ! preg_match( '~^\d{10}$~', $billing_dic ) ) {
					$errors->add( 'validation', __( 'The entered VAT Number is not in the required format (10 digits without spaces).', 'wpify-woo' ) );
				}
				if ( ! empty( $billing_dic_dph ) && ! preg_match( '~^SK\d{10}$~', $billing_dic_dph ) ) {
					$errors->add( 'validation', __( 'The entered IN VAT Number is not in the required format (prefix SK + 10 digits without spaces).', 'wpify-woo' ) );
				}
			} elseif (
				in_array( $country, [ 'CZ', 'PL', 'HU', 'DE' ] )
				&&
				! empty( $billing_dic )
				&& ! preg_match( '~^' . $country . '\d{8,10}$~', $billing_dic )
			) {
				/* translators: %s: country code prefix */
				$errors->add( 'validation', sprintf( __( 'The entered VAT Number is not in the required format (prefix %s + 8–10 digits without spaces).', 'wpify-woo' ), $country ) );
			}
		}

		if ( $country === 'SK' && ! empty( $billing_dic_dph ) && ! empty( $billing_dic ) ) {
			$dic     = $billing_dic;
			$dic_dph = $billing_dic_dph;

			if ( 'SK' . $dic !== $dic_dph ) {
				$errors->add( 'validation', __( 'The entered VAT Number must be same as IN VAT without SK.', 'wpify-woo' ) );
			}
		}


		$is_required = '</strong> ' . _x( 'is a required field when purchasing for a company.', 'checkout-validation', 'wpify-woo' );

		if ( ! empty( $this->get_setting( 'required_company' ) )
			 && get_option( 'woocommerce_checkout_company_field', 'optional' ) !== 'hidden'
			 && $this->get_setting( 'required_company' )
			 && ! empty( $company_details )
			 && $company_details === '1'
			 && empty( $billing_company )
		) {
			$company_field_label = __( 'Company name', 'wpify-woo' ) . $is_required;
			/* translators: %s: field label */
			$errors->add( 'validation', '<strong>' . sprintf( _x( 'Billing %s', 'checkout-validation', 'wpify-woo' ), $company_field_label ) );
		}

		if ( ( ! empty( $this->get_setting( 'required_ic' ) )
			   && 'if_checkbox' === $this->get_setting( 'required_ic' )
			   && ! empty( $company_details )
			   && $company_details === '1'
			 )
			 || ( ! empty( $this->get_setting( 'required_ic' ) )
				  && 'if_company' === $this->get_setting( 'required_ic' )
				  && ! empty( $billing_company )
			 )
		) {
			if ( empty( $billing_ic ) ) {
				$ic_field_label = __( 'Identification no.', 'wpify-woo' ) . $is_required;
				/* translators: %s: field label */
				$errors->add( 'validation', '<strong>' . sprintf( _x( 'Billing %s', 'checkout-validation', 'wpify-woo' ), $ic_field_label ) );
			}
		}
	}

	/**
	 * Check if VAT ID is valid via VIES
	 *
	 * Results are cached in WC session to avoid multiple VIES calls.
	 * Cache stores 'valid', 'invalid', or null (not checked yet).
	 *
	 * @param string $dic VAT ID to validate
	 *
	 * @return bool Whether the VAT ID is valid
	 */
	public function is_valid_dic( $dic ): bool {
		if ( empty( $dic ) ) {
			return false;
		}

		$dic       = strtoupper( $dic );
		$cache_key = 'wpify_woo_dic_valid_v2_' . $dic;

		/**
		 * Filter to bypass VIES validation entirely.
		 *
		 * Return a boolean to skip VIES and use the returned value.
		 * Return null to continue with normal VIES validation.
		 *
		 * @param bool|null $pre_result Return bool to bypass VIES, null to continue.
		 * @param string    $dic        The VAT ID being validated.
		 */
		$pre_result = apply_filters( 'wpify_woo_icdic_pre_vies_validation', null, $dic );
		if ( $pre_result !== null ) {
			$this->last_vies_result = $pre_result ? 'valid' : 'invalid';

			return (bool) $pre_result;
		}

		// Check session cache first
		if ( ! empty( WC()->session ) ) {
			$cached = WC()->session->get( $cache_key );
			// Distinguish between "not cached" (null) and "cached as invalid" ('invalid')
			if ( $cached === 'valid' ) {
				$this->last_vies_result = 'valid';

				return true;
			}
			if ( $cached === 'invalid' ) {
				$this->last_vies_result = 'invalid';

				return false;
			}
		}

		$current_country = substr( $dic, 0, 2 );
		$current_vat_no  = substr( $dic, 2 );

		if ( is_numeric( $current_country ) ) {
			$this->last_vies_result = 'invalid';

			return false;
		}

		$vies     = new Vies();
		$is_valid = false;
		$is_error = false;

		try {
			if ( $vies->getHeartBeat() ) {
				$is_valid = $vies->validateVat( $current_country, $current_vat_no )->isValid();
			} else {
				$is_valid = $vies->validateVatSum( $current_country, $current_vat_no );
			}
		} catch ( Exception $e ) {
			$this->log->error( 'VIES ERROR', array(
				'code'    => $e->getCode(),
				'message' => $e->getMessage(),
			) );
			$is_valid = false;
			$is_error = true;
		}

		/**
		 * Filter the VIES validation result.
		 *
		 * @param bool   $is_valid The VIES validation result.
		 * @param string $dic      The VAT ID that was validated.
		 */
		$is_valid = apply_filters( 'wpify_woo_icdic_vies_validation_result', $is_valid, $dic );

		// Store result for order logging
		$this->last_vies_result = $is_error ? 'error' : ( $is_valid ? 'valid' : 'invalid' );

		// Cache the result in session
		if ( ! $is_error && ! empty( WC()->session ) ) {
			WC()->session->set( $cache_key, $is_valid ? 'valid' : 'invalid' );
		}

		return $is_valid;
	}

	public function add_rest_api() {
		wpify_woo_container()->get( IcDicApi::class );
	}

	public function add_in_vat_to_address( $address, $customer_id, $name ) {
		$address[ $name . '_ic' ]      = get_user_meta( $customer_id, $name . '_ic', true );
		$address[ $name . '_dic' ]     = get_user_meta( $customer_id, $name . '_dic', true );
		$address[ $name . '_dic_dph' ] = get_user_meta( $customer_id, $name . '_dic_dph', true );

		return $address;
	}

	public function set_customer_vat_extempt() {
		// Only run on frontend pages, skip admin and AJAX
		if ( is_admin() || wp_doing_ajax() ) {
			return;
		}

		// Skip if WooCommerce customer is not available
		if ( empty( WC()->customer ) ) {
			return;
		}

		// Check if any VAT exempt functionality is configured
		if ( ! $this->is_vat_exempt_enabled() ) {
			return;
		}

		$customer         = WC()->customer;
		$billing_country  = $customer->get_billing_country();
		$shipping_country = $this->get_shipping_country_with_fallback( $customer, $billing_country );
		$dic              = $this->get_vat_id_from_source( $customer, $billing_country );

		$this->apply_vat_exempt_state( $billing_country, $shipping_country, $dic );
	}

	public function log_order_vat_exempt_decision( $order_id, $posted_data, $order ) {
		$billing_country  = $order->get_billing_country();
		$shipping_country = $this->get_shipping_country_with_fallback( $order, $billing_country );
		$shop_country     = wc_get_base_location()['country'];
		$dic              = $this->get_vat_id_from_source( $order, $billing_country );

		// Calculate VAT exempt using new logic
		$vat_exempt_result = $this->should_exempt_vat(
			$billing_country,
			$shipping_country,
			$dic ?: '',
			false // Will validate via VIES if needed
		);

		// Save VAT exempt metadata to order
		$this->save_vat_exempt_meta( $order, $vat_exempt_result );

		// Detect actual VAT exempt from order totals
		$actual_vat_exempt = ( $order->get_total_tax() == 0 && $order->get_total() > 0 );

		// Log the decision
		$this->log->info( 'Order VAT Exempt Decision', [
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
			'context'               => 'Order created - Classic checkout',
			// Validation results
			'validations'           => [
				'ares_result' => $this->get_last_ares_result(),
				'vies_result' => $this->get_last_vies_result(),
			],
			// Settings for debugging
			'settings'              => [
				'woo_tax_based_on'            => get_option( 'woocommerce_tax_based_on', 'shipping' ),
				'validate_ares'               => $this->get_setting( 'validate_ares' ),
				'validate_vies'               => $this->get_setting( 'validate_vies' ),
				'vies_fails'                  => $this->get_setting( 'vies_fails' ),
				'enable_eu_reverse_charge'    => $this->get_setting( 'enable_eu_reverse_charge' ),
				'enable_third_country_export' => $this->get_setting( 'enable_third_country_export' ),
			],
		] );
	}

	/**
	 * Check if VAT should be exempt based on DIC and shipping country
	 *
	 * @deprecated Use should_exempt_vat() instead
	 *
	 * @param string $dic
	 * @param string $shipping_country
	 *
	 * @return bool
	 */
	public function is_vat_extempt( $dic, $shipping_country = '' ): bool {
		if ( ! $dic ) {
			return false;
		}

		$current_country = substr( $dic, 0, 2 );

		// Check applicability FIRST - if not applicable, don't waste time on VIES validation
		$is_applicable = $this->is_vat_extempt_applicable( $current_country, $shipping_country );
		if ( ! $is_applicable ) {
			return false; // Skip expensive VIES validation if result would be false anyway
		}

		$current_vat_no = substr( $dic, 2 );
		$vies           = new Vies();
		$is_valid       = false;

		try {
			if ( $this->get_setting( 'validate_vies' ) && $vies->getHeartBeat() ) {
				$is_valid = $vies->validateVat( $current_country, $current_vat_no )->isValid();
			} else {
				$is_valid = $vies->validateVatSum( $current_country, $current_vat_no );
			}
		} catch ( ViesException|ViesServiceException $e ) {
			$is_valid = false;
		}

		return $is_valid;
	}

	/**
	 * Check if VAT exempt is applicable for given countries
	 *
	 * @deprecated Use should_exempt_vat() instead
	 *
	 * @param string $billing_country
	 * @param string $shipping_country
	 *
	 * @return bool
	 */
	public function is_vat_extempt_applicable( $billing_country, $shipping_country = '' ) {
		$vat_extempt_countries = $this->get_setting( 'zero_tax_for_vat_countries' );
		$shop_country          = wc_get_base_location()['country'];

		if ( ! $shipping_country ) {
			$shipping_country = ! empty( WC()->customer ) && WC()->customer->get_shipping_country() ? WC()->customer->get_shipping_country() : $billing_country;
		}

		if ( $billing_country === $shop_country ) {
			return false;
		}

		return $shipping_country != $shop_country && in_array( $shipping_country, $vat_extempt_countries );
	}

	public function set_vat_extempt_on_order_review( $strdata ) {
		$data = array();
		wp_parse_str( $strdata, $data );

		if ( ! $this->is_vat_exempt_enabled() ) {
			return;
		}

		$billing_country = $data['billing_country'] ?? '';
		$dic             = $this->get_vat_id_from_form_data( $data, $billing_country );

		// Determine shipping country
		$ship_to_different = isset( $data['ship_to_different_address'] ) && $data['ship_to_different_address'] === '1';
		$shipping_country  = $ship_to_different && ! empty( $data['shipping_country'] )
			? $data['shipping_country']
			: $billing_country;

		$this->apply_vat_exempt_state( $billing_country, $shipping_country, $dic );
	}

	/**
	 * Apply VAT exempt during Classic checkout submit.
	 *
	 * Safety net: ensures VAT exempt reflects the actually submitted form data
	 * before the order is created, regardless of whether the last
	 * update_order_review AJAX captured the current DIC value (race condition).
	 * Mirrors BlockSupport::ensure_vat_exempt_from_checkout_data() for Classic.
	 *
	 * @param array     $posted_data Sanitized posted checkout data.
	 * @param \WP_Error $errors      Validation errors.
	 */
	public function apply_vat_exempt_on_classic_checkout( $posted_data, $errors ): void {
		if ( ! $this->is_vat_exempt_enabled() ) {
			return;
		}

		if ( $errors->has_errors() ) {
			return;
		}

		$billing_country = $posted_data['billing_country'] ?? '';
		if ( empty( $billing_country ) ) {
			return;
		}

		$dic = $this->get_vat_id_from_form_data( $posted_data, $billing_country );

		$ship_to_different = ! empty( $posted_data['ship_to_different_address'] );
		$shipping_country  = $ship_to_different && ! empty( $posted_data['shipping_country'] )
			? $posted_data['shipping_country']
			: $billing_country;

		// checkout_validation (priority 10) already ran VIES; trust its result.
		$vat_id_validated = $this->last_vies_result === 'valid';

		$this->apply_vat_exempt_state( $billing_country, $shipping_country, $dic, $vat_id_validated, true );
	}

	public function add_ares_autofill_to_company_field( $field, $key ) {
		if ( 'company_details' === $key ) {
			ob_start(); ?>
			<div class="form-row">
				<?php $this->render_ares(); ?>
			</div>
			<?php
			$field = $field . ob_get_clean();
		}

		return $field;
	}

	public function add_ares_autofill_to_ic_field( $field, $key ) {
		if ( 'billing_ic' === $key ) {
			ob_start(); ?>
			<style type="text/css">
				#wpify-woo-icdic__ares-autofill-button, #ares_in {
					display: none;
				}

				.wpify-woo-icdic__ares-autofill {
					display: block;
				}
			</style>
			<div class="form-row wpify-woo-ic-dic__company_field">
				<?php $this->render_ares(); ?>
			</div>
			<?php
			$field = $field . ob_get_clean();
		}

		return $field;
	}


	public function render_ares() {
		if ( ! $this->get_setting( 'autofill_ares' ) ) {
			return;
		} ?>
		<div id="wpify-woo-ares-autofill">
			<a href="#"
			   id="wpify-woo-icdic__ares-autofill-button"><?php echo esc_html( $this->get_setting( 'autofill_ares_text' ) ); ?></a>
			<div class="wpify-woo-icdic__ares-autofill">
				<input type="text" name="ares_vat_no" id="ares_in"
					   placeholder="<?php esc_attr_e( 'Identification number', 'wpify-woo' ); ?>"/>
				<input type="button"
					   value="<?php echo esc_attr( $this->get_setting( 'submit_ares_text' ) ?: __( 'Search in ARES', 'wpify-woo' ) ); ?>"
					   id="wpify-woo-icdic__ares-submit"/>
				<div id="wpify-woo-icdic__ares-result"></div>
			</div>
		</div>
		<?php
	}

	public function autofill_vat_fields_in_admin( $data, $customer, $user_id ) {
		$data['billing']['ic']      = get_user_meta( $user_id, 'billing_ic', true );
		$data['billing']['dic']     = get_user_meta( $user_id, 'billing_dic', true );
		$data['billing']['dic_dph'] = get_user_meta( $user_id, 'billing_dic_dph', true );

		return $data;
	}

	public function add_post_class( $classes, $class, $post_id ) {
		if ( get_post_type( $post_id ) === 'shop_order' ) {
			$order = wc_get_order( $post_id );
			if ( ! $order ) {
				return $classes;
			}

			// Use stored meta data instead of recalculating
			$vat_info = $this->get_order_vat_exempt_info( $order );

			if ( $vat_info['exempt'] ) {
				$classes[] = 'vat-exempt';
			}
		}

		return $classes;
	}

	/**
	 * Display VAT exempt information in admin order details
	 *
	 * @param WC_Order $order
	 */
	public function display_vat_exempt_info_in_admin( $order ) {
		$vat_info = $this->get_order_vat_exempt_info( $order );

		// Only display if there's VAT exempt info
		if ( $vat_info['reason'] === 'standard' && ! $vat_info['exempt'] ) {
			return;
		}

		$reason_labels = array(
			'reverse_charge' => __( 'EU Reverse Charge', 'wpify-woo' ),
			'export'         => __( 'Third Country Export', 'wpify-woo' ),
			'legacy'         => __( 'VAT Exempt (Legacy)', 'wpify-woo' ),
			'standard'       => __( 'Standard (with VAT)', 'wpify-woo' ),
		);

		$reason_label = $reason_labels[ $vat_info['reason'] ] ?? $vat_info['reason'];
		$status_class = $vat_info['exempt'] ? 'vat-exempt-yes' : 'vat-exempt-no';
		$status_label = $vat_info['exempt'] ? __( 'Yes', 'wpify-woo' ) : __( 'No', 'wpify-woo' );

		?>
		<div class="wpify-vat-exempt-info" style="margin-top: 15px; padding: 10px; background: #f8f8f8; border-left: 4px solid <?php echo $vat_info['exempt'] ? '#46b450' : '#ddd'; ?>;">
			<h4 style="margin: 0 0 8px 0;"><?php esc_html_e( 'VAT Exemption Status', 'wpify-woo' ); ?></h4>
			<p style="margin: 4px 0;">
				<strong><?php esc_html_e( 'VAT Exempt:', 'wpify-woo' ); ?></strong>
				<span class="<?php echo esc_attr( $status_class ); ?>" style="color: <?php echo $vat_info['exempt'] ? '#46b450' : '#666'; ?>; font-weight: bold;">
					<?php echo esc_html( $status_label ); ?>
				</span>
			</p>
			<p style="margin: 4px 0;">
				<strong><?php esc_html_e( 'Reason:', 'wpify-woo' ); ?></strong>
				<?php echo esc_html( $reason_label ); ?>
			</p>
		</div>
		<?php
	}


}
