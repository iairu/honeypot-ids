<?php

namespace WpifyWoo\Modules\ZboziConversions;

defined( 'ABSPATH' ) || exit;

use WpifyWoo\Plugin;
use WpifyWooDeps\Wpify\WooCore\Abstracts\AbstractModule;
use WpifyWoo\WooCommerceIntegration;

class ZboziConversionsModule extends AbstractModule {
	public function __construct() {
		parent::__construct();
		$this->setup();
	}

	/**
	 * @return void
	 */
	public function setup() {
		add_action( 'woocommerce_thankyou', [ $this, 'tracking_code' ] );

		if (
				function_exists( 'wpify_woo_zbozi_conversions_container' ) &&
				wpify_woo_container()->get( WooCommerceIntegration::class )->is_module_enabled( 'zbozi_conversions' )
		) {
			add_action( 'admin_notices', [ $this, 'duplicity_code_notice' ] );
		}
	}

	/**
	 * Module ID
	 * @return string
	 */
	public function id(): string {
		return 'zbozi_conversions_lite';
	}

	/**
	 * Module name
	 * @return string
	 */
	public function name(): string {
		return __( 'Zbozi.cz/Sklik Conversions Limited', 'wpify-woo' );
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
		return 'wpify-woo/modules/zbozi-conversions';
	}

	/**
	 * Module settings
	 *
	 * @return array[]
	 */
	public function settings(): array {
		$settings = array(
				array(
						'label' => __( 'Shop ID', 'wpify-woo' ),
						'desc'  => __( 'Enter Shop ID for Zbozi.cz', 'wpify-woo' ),
						'id'    => 'shop_id',
						'type'  => 'text',
				),
				array(
						'label' => __( 'Private Key', 'wpify-woo' ),
						'desc'  => __( 'Enter private key for Zbozi.cz', 'wpify-woo' ),
						'id'    => 'private_key',
						'type'  => 'text',
				),
				array(
						'label' => __( 'Sklik ID', 'wpify-woo' ),
						'desc'  => __( 'Enter Sklik ID if you want to enable conversions for Sklik.cz', 'wpify-woo' ),
						'id'    => 'sklik_id',
						'type'  => 'text',
				),
				array(
						'type'  => 'title',
						'title' => __( 'Marketing cookie', 'wpify-woo' ),
						'desc'  => __( 'You need consent from the visitor for marketing cookies. If you don`t enter the name and value of the marketing cookie the Seznam will process the data as if consent had been given.', 'wpify-woo' ),
				),
				array(
						'id'    => 'cookie_name',
						'type'  => 'text',
						'label' => __( 'Marketing cookie name', 'wpify-woo' ),
						'desc'  => __( 'Enter the name of the cookie that represents the agreed marketing cookies. For example, in the case of using the "Complianz" plugin, this is <code>cmplz_marketing</code>.', 'wpify-woo' ),
				),
				array(
						'id'    => 'cookie_value',
						'type'  => 'text',
						'label' => __( 'Marketing cookie value', 'wpify-woo' ),
						'desc'  => __( 'Enter the value of the cookie that represents the agreed marketing cookies. For example, in the case of using the "Complianz" plugin, this is <code>allow</code>.', 'wpify-woo' ),
				),
				array(
						'id'      => 'wpify_pro_notice',
						'type'    => 'html',
						/* translators: %s: URL to premium extension */
				'content' => sprintf( '<div class="notice notice-warning"><p>%s</p></div>', sprintf( __( 'This module sends only limited conversion measurements using frontend code. For a more detailed standard measurement with also backend sending data for Zboží.cz, please install the premium extension <a href="%s" target="_blank">WPify Woo Zbozi.cz Conversion tracking </a>. This premium extension also allows you to send a customer satisfaction survey.', 'wpify-woo' ), __( 'https://wpify.io/product/wpify-woo-zbozi-cz-conversion-tracking/', 'wpify-woo' ) ) ),
				)
		);

		return $settings;
	}

	/**
	 * Render conversion script on thank you page
	 *
	 * @param $order_id
	 */
	public function tracking_code( $order_id ) {
		if ( ! $this->get_setting( 'shop_id' ) || apply_filters( 'wpify_woo_zbozi_conversion_render_code', true ) === false ) {
			return;
		}
		$parameters   = $this->get_parameters( $order_id );
		$cookie_name  = $this->get_setting( 'cookie_name' );
		$cookie_value = $this->get_setting( 'cookie_value' );

		?>
		<!-- Zbozi.cz / Sklik conversion Limited -->
		<?php // phpcs:ignore WordPress.WP.EnqueuedResources.NonEnqueuedScript -- Inline third-party tracking snippet. ?>
		<script type="text/javascript" src="https://c.seznam.cz/js/rc.js"></script>
		<script>
			(function() {
				function getCookie(name) {
					var nameEQ = name + "=";
					var ca = document.cookie.split(';');
					for (var i = 0; i < ca.length; i++) {
						var c = ca[i];
						while (c.charAt(0) === ' ') c = c.substring(1, c.length);
						if (c.indexOf(nameEQ) === 0) {
							return decodeURIComponent(c.substring(nameEQ.length, c.length));
						}
					}
					return null;
				}

				var consent = 1;
				<?php if ( $cookie_name && $cookie_value ) : ?>
				var value = getCookie("<?php echo esc_js( $cookie_name ); ?>");
				if (value && (value === "<?php echo esc_js( $cookie_value ); ?>" || value.includes("<?php echo esc_js( $cookie_value ); ?>"))) {
					consent = 1;
				} else {
					consent = 0;
				}
				<?php endif; ?>

				// Idempotence — woocommerce_thankyou fires on every order-received page visit
				// (refresh, return from email link), so without this guard Sklik/Zbozi receive
				// the same conversion multiple times.
				var storageKey = 'zbozi_conversion_sent_<?php echo esc_js( (string) $order_id ); ?>';
				if (sessionStorage.getItem(storageKey)) { return; }
				sessionStorage.setItem(storageKey, '1');

				var conversionConf = {
					<?php
					foreach ( $parameters as $key => $parameter ) {
						// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Internally generated conversion parameters (keys and numeric/quoted values) written into an inline tracking script.
						echo $key . ': ' . $parameter . ', ';
					}
					?>
					consent: consent
				};
				if (window.rc && window.rc.conversionHit) {
					window.rc.conversionHit(conversionConf);
				}
				console.log('conversionConf', conversionConf);
			})();
		</script>
	<?php }

	/**
	 * Get parameters for conversion code
	 *
	 * @param $order_id
	 *
	 * @return mixed|void
	 */
	public function get_parameters( $order_id ) {
		$parameters = array();

		$shop_id = (int) $this->get_setting( 'shop_id' );
		if ( $shop_id ) {
			$parameters['zboziId'] = $shop_id;
			$parameters['orderId'] = '"' . $order_id . '"';
		}

		$parameters['zboziType'] = '"limited"';

		$sklik_id = $this->get_setting( 'sklik_id' );
		if ( $sklik_id ) {
			$wc_order = wc_get_order( $order_id );

			$parameters['id']    = $sklik_id;
			$parameters['value'] = $wc_order->get_total();
		}

		return apply_filters( 'wpify_woo_zbozi_conversion_script_parameters', $parameters );
	}

	/**
	 * Notice that the Zbozi.cz/Sklik Conversions pro plugin is also active
	 */
	function duplicity_code_notice() {
		$title  = __( 'Duplicate conversion code may be generated for Zbozi.cz/Sklik', 'wpify-woo' );
		$string = __( 'The <b>Zbozi.cz/Sklik Conversions Limited</b> module is active at the same time as the premium extension <b>Zbozi.cz/Sklik Conversions</b>. If you have both modules active and there will be duplicate generation of the queue conversion code once for limited and once for standard conversion measurement and measurement errors may occur. Please deactivate one of these modules.', 'wpify-woo' );
		printf( '<div class="notice notice-warning"><h2>%s</h2><p>%s</p></div>', esc_html( $title ), wp_kses_post( $string ) );
	}
}
