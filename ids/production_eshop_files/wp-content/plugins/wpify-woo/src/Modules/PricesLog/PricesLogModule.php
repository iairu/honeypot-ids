<?php

namespace WpifyWoo\Modules\PricesLog;

defined( 'ABSPATH' ) || exit;

use WP_Error;
use WP_Post;
use WpifyWoo\Plugin;
use WpifyWooDeps\Wpify\WooCore\Abstracts\AbstractModule;

class PricesLogModule extends AbstractModule {
	private PricesLogRepository $prices_log_repository;

	public function __construct(
		PricesLogRepository $prices_log_repository,
	) {
		parent::__construct();
		$this->prices_log_repository = $prices_log_repository;

		$this->setup();
	}

	/**
	 * @return void
	 */
	public function setup() {
		add_action( 'woocommerce_update_product', [ $this, 'handle_save_log' ] );
		add_action( 'woocommerce_new_product', [ $this, 'handle_save_log' ] );
		add_filter( 'woocommerce_product_data_tabs', [ $this, 'product_tabs' ], 10, 1 );
		add_action( 'woocommerce_product_data_panels', [ $this, 'product_tab_content' ] );
		add_action( 'woocommerce_product_options_pricing', [ $this, 'display_lowest_price' ] );
		add_action( 'woocommerce_variation_options_pricing', [ $this, 'variation_lowest_price' ], 10, 3 );

		add_shortcode( 'wpify_woo_lowest_price', array( $this, 'display_lowest_price_shortcode' ) );
	}

	function id() {
		return 'prices_log';
	}

	public function name() {
		return __( 'Prices Log', 'wpify-woo' );
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
		return 'wpify-woo/modules/prices-log';
	}

	/**
	 * @return array[]
	 */
	public function settings(): array {
		$settings = array(
			array(
				'type'  => 'title',
				'label' => __( 'Recording product price history', 'wpify-woo' ),
				'desc'  => __( 'Product prices are logged whenever they change. The lowest price recorded in the last 30 days is displayed below the product price field.',
					'wpify-woo' ),
			),
		);

		return $settings;
	}


	/**
	 * Handle saving prices
	 *
	 * @param $product_id
	 *
	 * @throws \Exception
	 */
	public function handle_save_log( $product_id ) {
		$product = wc_get_product( $product_id );
		if ( ! $product ) {
			return;
		}

		if ( $product->is_type( 'variable' ) ) {
			/** @var \WC_Product_Variable $product */
			$variations = $product->get_available_variations();

			foreach ( $variations as $variation ) {
				$variation = wc_get_product( $variation['variation_id'] );

				$this->save_log( $variation );
			}
		} else {
			$this->save_log( $product );
		}
	}

	/**
	 * Save price into log
	 *
	 * @param \WC_Product|\WC_Product_Variation $product
	 *
	 * @throws \Exception
	 */
	public function save_log( $product ) {
		$log  = $this->prices_log_repository->create();
		$last = $this->prices_log_repository->get_last_by_product_id( $product->get_id() );
		if ( $last && floatval( $last->regular_price ) === floatval( $product->get_regular_price() ) && floatval( $last->sale_price ) === floatval( $product->get_sale_price() ) ) {
			return;
		}

		$log->product_id    = $product->get_id();
		$log->regular_price = $product->get_regular_price();
		$log->sale_price    = $product->get_sale_price();

		$log->created_at = current_time( 'mysql' );
		$this->prices_log_repository->save( $log );
	}

	/**
	 * Add product tab
	 *
	 * @param $default_tabs
	 *
	 * @return array
	 */
	public function product_tabs( $default_tabs ): array {
		$default_tabs['wpify_prices_log'] = array(
			'target'   => 'wpify_prices_log',
			'label'    => __( 'Prices log', 'wpify-woo' ),
			'priority' => 60,
			'class'    => array(),
		);

		return $default_tabs;
	}

	/**
	 * Content of Price log tab
	 */
	public function product_tab_content() {
		global $product;

		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Display-only admin screen reading a WooCommerce post ID.
		if ( ! $product && isset( $_GET['post'] ) ) {
			// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- WooCommerce core global.
			$product = wc_get_product( absint( wp_unslash( $_GET['post'] ) ) );
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		if ( empty( $product ) ) {
			return;
		}

		?>
		<div id="wpify_prices_log" class="panel woocommerce_options_panel">
			<?php
			if ( $product->is_type( 'variable' ) ) {
				/** @var \WC_Product_Variable $product */
				$variations = $product->get_available_variations();

				foreach ( $variations as $variation ) {
					$this->display_log_table( $variation['variation_id'] );
				}
			} else {
				$this->display_log_table( $product->get_id() );
			}
			?>
		</div>
		<?php
	}

	/**
	 * Render price log table
	 *
	 * @param $id
	 */
	public function display_log_table( $id ) {
		?>
		<table class="wp-list-table widefat fixed striped table-view-list">
			<thead>
			<tr>
				<th>Product ID</th>
				<th>Regular price</th>
				<th>Sale price</th>
				<th>Date</th>
			</tr>
			</thead>
			<tbody>
			<?php foreach ( array_reverse( $this->prices_log_repository->find_by_product_id( $id ) ) as $item ) { ?>
				<tr>
					<td><?php echo esc_html( $item->product_id ); ?></td>
					<td><?php echo esc_html( $item->regular_price ); ?></td>
					<td><?php echo esc_html( $item->sale_price ); ?></td>
					<td><?php echo esc_html( $item->created_at ); ?></td>
				</tr>
			<?php } ?>

			</tbody>

		</table>
	<?php }

	/**
	 * Get the lowest price last 30 days
	 *
	 * @param $id
	 */
	public function get_lowest_price( $id ) {
		$price = $this->prices_log_repository->find_lowest_price( $id ) ?: 0;
		if ( ! $price ) {
			$p = wc_get_product( $id );
			if ( $p ) {
				$price = $p->get_price();
			}
		}

		return floatval( $price );
	}

	/**
	 * Lowest price for variation product
	 *
	 * @param int     $loop           Position in the loop.
	 * @param array   $variation_data Variation data.
	 * @param WP_Post $variation      Post data.
	 */
	public function variation_lowest_price( $loop, $variation_data, $variation ) {
		$this->display_lowest_price( $variation->ID );
	}

	/**
	 * Display the lowest price last 30 days
	 *
	 * @param $id
	 */
	public function display_lowest_price( $id ) {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Display-only admin screen reading a WooCommerce post ID.
		if ( ! $id && isset( $_GET['post'] ) ) {
			$id = absint( wp_unslash( $_GET['post'] ) );
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		if ( ! $id ) {
			return;
		}

		$price = $this->get_lowest_price( $id );
		if ( ! $price ) {
			return;
		}

		$tax_label = wc_prices_include_tax()
			? __( 'incl. tax', 'wpify-woo' )
			: __( 'excl. tax', 'wpify-woo' );

		echo wp_kses_post(
			sprintf(
				'<p class="form-row form-row-full">%s: %s <small>(%s)</small></p>',
				esc_html__( 'The lowest price for the last 30 days', 'wpify-woo' ),
				wc_price( $price ),
				esc_html( $tax_label )
			)
		);
	}

	public function display_lowest_price_shortcode() {
		$id      = get_the_ID();
		$product = wc_get_product( $id );
		$price   = $this->get_lowest_price( $id );

		if ( ! $product ) {
			return wc_price( $price );
		}

		$display_price = wc_get_price_to_display( $product, array( 'price' => $price ) );

		return wc_price( $display_price ) . $product->get_price_suffix( $display_price );
	}
}
