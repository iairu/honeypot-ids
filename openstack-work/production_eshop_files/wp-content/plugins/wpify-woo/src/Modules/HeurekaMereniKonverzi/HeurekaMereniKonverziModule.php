<?php

namespace WpifyWoo\Modules\HeurekaMereniKonverzi;

defined( 'ABSPATH' ) || exit;

use WpifyWoo\Plugin;
use WpifyWooDeps\Wpify\WooCore\Abstracts\AbstractModule;
use WpifyWoo\Models\WooOrderModel;
use WpifyWoo\Repositories\WooOrderRepository;
use WpifyWooDeps\Wpify\Model\OrderItem;


/**
 * Class HeurekaOverenoZakaznikyModule
 *
 * @package WpifyWoo\Modules\HeurekaOverenoZakazniky
 */
class HeurekaMereniKonverziModule extends AbstractModule {

	const MODULE_ID = 'heureka_mereni_konverzi';

	public function __construct(
		private WooOrderRepository $woo_order_repository,
	) {
		parent::__construct();
		$this->setup();
	}

	/**
	 * Setup
	 * @return void
	 */
	public function setup() {
		add_action( 'woocommerce_thankyou', array( $this, 'render_tracking_code' ) );
		add_action( 'wp_footer', array( $this, 'render_product_tracking_code' ) );
	}

	/**
	 * Get the module ID
	 * @return string
	 */
	public function id(): string {
		return self::MODULE_ID;
	}

	/**
	 * Set module name
	 * @return string
	 */
	public function name(): string {
		return __( 'Heureka Měření konverzí', 'wpify-woo' );
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
		return 'wpify-woo/modules/heureka-conversions';
	}

	/**
	 *  Get the settings
	 *
	 * @return array[]
	 */
	public function settings(): array {
		return array(
			array(
				'id'    => 'api_key',
				'type'  => 'text',
				'label' => __( 'Public key for conversions', 'wpify-woo' ),
				'desc'  => __( 'Enter the public key for the conversion measurement code.', 'wpify-woo' ),
			),
			array(
				'id'      => 'country',
				'type'    => 'select',
				'options' => [
					[
						'label' => 'CZ',
						'value' => 'cz',
					],
					[
						'label' => 'SK',
						'value' => 'sk',
					],
				],
				'label'   => __( 'Country', 'wpify-woo' ),
				'desc'    => __( 'Select country for tracking', 'wpify-woo' ),
				'default' => 'cz'
			),
		);
	}

	/**
	 *
	 */
	public function render_tracking_code( $order_id ) {
		$api_key = $this->get_setting( 'api_key' );
		if ( ! $api_key ) {
			return;
		}

		/** @var WooOrderModel $order */
		$order    = $this->woo_order_repository->get( $order_id );
		$products = [];
		foreach ( $order->line_items as $item ) {
			/** @var OrderItem $item */
			$products[] = [
				'add_product',
				(string) $item->product_id,
				$item->name,
				(string) $item->get_unit_price_tax_included(),
				(string) $item->quantity,
			];
		}
		$additional = [];
		foreach ( $order->shipping_items as $item ) {
			/** @var \WpifyWooDeps\Wpify\Model\OrderItemShipping $item */
			$additional[] = [
				'add_additional_item',
				$item->name,
				(string) $item->get_unit_price_tax_included(),
				(string) $item->quantity,
			];
		}
		foreach ( $order->fee_items as $item ) {
			/** @var \WpifyWooDeps\Wpify\Model\OrderItemFee $item */
			$additional[] = [
				'add_additional_item',
				$item->name,
				(string) $item->get_unit_price_tax_included(),
				"1",
			];
		}
		$country = $this->get_setting( 'country' ) ?: 'cz';
		$url     = '//www.heureka.cz/ocm/sdk.js?version=2&page=thank_you';
		if ( 'sk' === $country ) {
			$url = '//www.heureka.sk/ocm/sdk.js?version=2&page=thank_you';
		}
		$url = apply_filters( 'wpify_woo_heureka_mereni_konverzi_url', $url );
		?>
		<!-- Heureka.cz THANK YOU PAGE script -->
		<script>
			(function (t, r, a, c, k, i, n, g) {
				t['ROIDataObject'] = k;
				t[k] = t[k] || function () {
					(t[k].q = t[k].q || []).push(arguments)
				}, t[k].c = i;
				n = r.createElement(a),
					g = r.getElementsByTagName(a)[0];
				n.async = 1;
				n.src = c;
				g.parentNode.insertBefore(n, g)
			})(window, document, 'script', '<?php echo esc_url( $url ); ?>', 'heureka', '<?php echo esc_js( $country ); ?>');

			// Idempotence — woocommerce_thankyou fires on every order-received page visit
			// (refresh, return from email link), so without this guard Heureka receives the
			// same conversion multiple times and rejects it with DUPLICATE_ORDER_ID.
			if (!sessionStorage.getItem('heureka_conversion_sent_<?php echo esc_js( (string) $order->id ); ?>')) {
				sessionStorage.setItem('heureka_conversion_sent_<?php echo esc_js( (string) $order->id ); ?>', '1');

				heureka('authenticate', '<?php echo esc_attr( $api_key ); ?>');

				heureka('set_order_id', '<?php echo esc_attr( $order->id ); ?>');
				<?php foreach ( $products as $item ) { ?>
				heureka(<?php echo implode( ',', array_map( 'json_encode', $item ) ); ?>);
				<?php }?>
				<?php foreach ( $additional as $item ) { ?>
				heureka(<?php echo implode( ',', array_map( 'json_encode', $item ) ); ?>);
				<?php }?>
				heureka('set_total_vat', '<?php echo esc_attr( $order->get_wc_order()->get_total() ); ?>');
				heureka('set_currency', '<?php echo esc_attr( $order->get_wc_order()->get_currency() ); ?>');
				heureka('send', 'Order');
			}
		</script>
		<!-- End Heureka.cz THANK YOU PAGE script -->
		<?php
	}

	/**
	 *
	 */
	public function render_product_tracking_code() {
		$api_key = $this->get_setting( 'api_key' );
		if ( ! $api_key || ! is_product() ) {
			return;
		}
		$country = $this->get_setting( 'country' ) ?: 'cz';
		$url     = '//www.heureka.cz/ocm/sdk.js?version=2&page=product_detail';
		if ( 'sk' === $country ) {
			$url = '//www.heureka.sk/ocm/sdk.js?version=2&page=product_detail';
		}
		$url = apply_filters( 'wpify_woo_heureka_mereni_konverzi_url', $url );
		?>
		<!-- Heureka.cz PRODUCT DETAIL script -->
		<script>
			(function (t, r, a, c, k, i, n, g) {
				t['ROIDataObject'] = k;
				t[k] = t[k] || function () {
					(t[k].q = t[k].q || []).push(arguments)
				}, t[k].c = i;
				n = r.createElement(a),
					g = r.getElementsByTagName(a)[0];
				n.async = 1;
				n.src = c;
				g.parentNode.insertBefore(n, g)
			})(window, document, 'script', '<?php echo esc_url( $url ); ?>', 'heureka', '<?php echo esc_js( $country ); ?>');
		</script>
		<!-- End Heureka.cz PRODUCT DETAIL script -->
		<?php
	}
}
