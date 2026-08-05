<?php

namespace WpifyWoo\Modules\Prices;

defined( 'ABSPATH' ) || exit;

use WpifyWoo\Plugin;
use WpifyWooDeps\Wpify\WooCore\Abstracts\AbstractModule;
use WpifyWooDeps\Wpify\Asset\AssetFactory;
use WpifyWooDeps\Wpify\CustomFields\CustomFields;
use WpifyWooDeps\Wpify\PluginUtils\PluginUtils;

class PricesModule extends AbstractModule {
	public function __construct(
		private CustomFields $custom_fields,
		private AssetFactory $asset_factory,
		private PluginUtils $plugin_utils,
	) {
		parent::__construct();
		$this->setup();
	}

	/**
	 * @return void
	 */
	public function setup() {
		add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_scripts' ) );
		add_action( 'init', array( $this, 'custom_price_fields' ), 12 );
		add_filter( 'woocommerce_get_price_html', array( $this, 'edit_price_html' ), 999, 2 );
		add_filter( 'woocommerce_locate_template', array( $this, 'get_edited_template' ), 1, 3 );

		if ( ! empty( $this->get_setting( 'custom_prices_custom_location' ) ) ) {
			add_action( $this->get_setting( 'custom_prices_custom_location' ), array(
				$this,
				'display_custom_prices',
			) );
		} elseif ( ! empty( $this->get_setting( 'custom_prices_location' ) ) ) {
			if ( 'after_price' === $this->get_setting( 'custom_prices_location' ) ) {
				$priority = 12;
			} elseif ( 'before_price' === $this->get_setting( 'custom_prices_location' ) ) {
				$priority = 9;
			}

			if ( isset( $priority ) ) {
				add_action( 'woocommerce_single_product_summary', array( $this, 'display_custom_prices' ), $priority );
			}
		}
	}

	function id() {
		return 'prices';
	}

	public function name() {
		return __( 'Prices', 'wpify-woo' );
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
		return 'wpify-woo/modules/prices';
	}

	/**
	 * @return array
	 */
	public function settings(): array {
		return array(
			array(
				'id'      => 'price_notices',
				'type'    => 'multi_group',
				'title'   => 'Default price notices',
				'buttons' => array(
					'add' => __( 'Add notice', 'wpify-woo' ),
				),
				'items'   => array(
					array(
						'id'    => 'price_notice',
						'type'  => 'textarea',
						'label' => __( 'Price notice', 'wpify-woo' ),
					),
					array(
						'id'      => 'price_notice_condition',
						'type'    => 'select',
						'label'   => __( 'When notice display', 'wpify-woo' ),
						'options' => array(
							array(
								'label' => __( 'Always', 'wpify-woo' ),
								'value' => 'always',
							),
							array(
								'label' => __( 'If product is in sale', 'wpify-woo' ),
								'value' => 'in_sale',
							),
							array(
								'label' => __( 'If product is not in sale', 'wpify-woo' ),
								'value' => 'not_in_sale',
							),
							array(
								'label' => __( 'If product is on backorder', 'wpify-woo' ),
								'value' => 'on_backorder',
							),
						),
						'default' => 'always',
					),
					array(
						'id'      => 'price_notice_location',
						'type'    => 'select',
						'label'   => __( 'Price notice display location', 'wpify-woo' ),
						'options' => array(
							array(
								'label' => __( 'Before price html', 'wpify-woo' ),
								'value' => 'before_price_html',
							),
							array(
								'label' => __( 'After price html', 'wpify-woo' ),
								'value' => 'after_price_html',
							),
							array(
								'label' => __( 'After del element in price html', 'wpify-woo' ),
								'value' => 'after_del_price',
							),
						),
						'default' => 'after_price_html',
					),
				)
			),
			array(
				'id'      => 'custom_prices',
				'type'    => 'multi_group',
				'title'   => 'Custom prices',
				'buttons' => array(
					'add' => __( 'Add price', 'wpify-woo' ),
				),
				'items'   => array(
					array(
						'id'    => 'label',
						'type'  => 'text',
						'label' => __( 'Price label', 'wpify-woo' ),
					),
//					array(
//						'id'    => 'show_label',
//						'type'  => 'toggle',
//						'label' => __( 'Show label on frontend', 'wpify-woo' ),
//					),
					array(
						'id'      => 'type',
						'type'    => 'select',
						'label'   => __( 'Price type', 'wpify-woo' ),
						'desc'    => __( 'Choose price type. For the lowest price for the last 30 days from the Price Log module - module must be active.', 'wpify-woo' ),
						'options' => array(
							array(
								'label' => __( 'Custom price', 'wpify-woo' ),
								'value' => 'custom',
							),
							array(
								'label' => __( 'Lowest price in 30 days', 'wpify-woo' ),
								'value' => 'lowest',
							),
							array(
								'label' => __( 'Price by unit', 'wpify-woo' ),
								'value' => 'by_unit',
							),
						),
						'default' => 'custom',
					),
					array(
						'id'    => 'price_info',
						'type'  => 'textarea',
						'label' => __( 'Price more info', 'wpify-woo' ),
					),
					array(
						'id'    => 'regular_price_label',
						'type'  => 'text',
						'label' => __( 'Regular price label', 'wpify-woo' ),
					),
					array(
						'id'    => 'badge_label',
						'type'  => 'text',
						'label' => __( 'Badge label', 'wpify-woo' ),
					),
					array(
						'id'    => 'badge_class',
						'type'  => 'text',
						'label' => __( 'Custom badge css class', 'wpify-woo' ),
					),
					array(
						'id'      => 'price_condition',
						'type'    => 'select',
						'label'   => __( 'When price display', 'wpify-woo' ),
						'options' => array(
							array(
								'label' => __( 'Always', 'wpify-woo' ),
								'value' => '',
							),
							array(
								'label' => __( 'If product is in sale', 'wpify-woo' ),
								'value' => 'in_sale',
							),
							array(
								'label' => __( 'If product is not in sale', 'wpify-woo' ),
								'value' => 'not_in_sale',
							),
							array(
								'label' => __( 'If product is on backorder', 'wpify-woo' ),
								'value' => 'on_backorder',
							),
						),
						'default' => '',
					),
					array(
						'type'      => 'hidden',
						'id'        => 'uuid',
						'generator' => 'uuid',
					),
				)
			),
			array(
				'id'      => 'custom_prices_location',
				'type'    => 'select',
				'label'   => __( 'Custom prices display location', 'wpify-woo' ),
				'options' => array(
					array(
						'label' => __( 'Before price outside price html', 'wpify-woo' ),
						'value' => 'before_price',
					),
					array(
						'label' => __( 'After price outside price html', 'wpify-woo' ),
						'value' => 'after_price',
					),
					array(
						'label' => __( 'Before price inside price html', 'wpify-woo' ),
						'value' => 'before_price_html',
					),
					array(
						'label' => __( 'After price inside price html', 'wpify-woo' ),
						'value' => 'after_price_html',
					),
				),
				'default' => 'before_price',
			),
			array(
				'id'    => 'custom_prices_custom_location',
				'type'  => 'text',
				'label' => __( 'Custom location hook', 'wpify-woo' ),
				'desc'  => __( 'Insert hook of location where you want show custom prices block.', 'wpify-woo' ),
			),
		);
	}

	/**
	 * Get edited Woocommerce template from module directory
	 *
	 * @param $template
	 * @param $template_name
	 * @param $template_path
	 *
	 * @return string
	 */
	public function get_edited_template( $template, $template_name, $template_path ) {
		global $woocommerce;
		$_template = $template;
		if ( ! $template_path ) {
			$template_path = $woocommerce->template_url;
		}

		$plugin_path = untrailingslashit( __DIR__ ) . '/woocommerce/';

		// Look within passed path within the theme - this is priority
		$template = locate_template(
			array(
				$template_path . $template_name,
				$template_name,
			)
		);

		if ( ! $template && file_exists( $plugin_path . $template_name ) ) {
			$template = $plugin_path . $template_name;
		}

		if ( ! $template ) {
			$template = $_template;
		}

		return $template;
	}

	/**
	 * Enqueue frontend scripts
	 */
	public function enqueue_scripts() {
		$this->asset_factory->wp_script( $this->plugin_utils->get_plugin_path( 'build/prices.css' ) );
	}

	/**
	 * Add info and label into product price html
	 *
	 * @param string      $price
	 * @param \WC_Product $product
	 *
	 * @return mixed
	 */
	function edit_price_html( $price, $product ) {
		global $woocommerce_loop;

		if ( ! is_product() || ! empty( $woocommerce_loop['name'] ) ) {
			return $price;
		}

		// Add price info
		$price_notices = $this->get_setting( 'price_notices' );
		if ( is_array( $price_notices ) ) {
			foreach ( $price_notices as $notice ) {
				if (
					! isset( $notice['price_notice'] ) || empty( $notice['price_notice'] ) ||
					! isset( $notice['price_notice_condition'] ) || empty( $notice['price_notice_condition'] )
				) {
					continue;
				}

				if (
					'in_sale' === $notice['price_notice_condition'] && ! $product->is_on_sale() ||
					'not_in_sale' === $notice['price_notice_condition'] && $product->is_on_sale() ||
					'on_backorder' === $notice['price_notice_condition'] && ! $product->is_on_backorder()
				) {
					continue;
				}

				ob_start();
				?>
				<span class="wpify-woo-prices__price-info">
					<?php esc_html_e( '?', 'wpify-woo' ); ?>
					<span class="wpify-woo-prices__price-info__text">
						<?php echo wp_kses_post( $notice['price_notice'] ); ?>
					</span>
				</span>
				<?php
				$notice_html = ob_get_clean();

				if ( $notice['price_notice_location'] === 'after_del_price' && str_contains( $price, '</del>' ) ) {
					$price_array    = explode( '</del>', $price );
					$price_array[0] = $price_array[0] . '</del>' . $notice_html;
					$price          = implode( '', $price_array );

				} elseif ( $notice['price_notice_location'] === 'before_price_html' ) {
					$price = $notice_html . ' ' . $price;

				} else {
					$price = $price . ' ' . $notice_html;
				}

				break;
			}
		}

		// Add regular price label
		$custom_prices = $this->get_setting( 'custom_prices' );

		if ( is_array( $custom_prices ) ) {
			foreach ( $custom_prices as $custom_price ) {
				$custom_prices_meta = get_post_meta( $product->get_id(), '_custom_prices', true );
				$has_price          = 'lowest' === $custom_price['type'] || ( ! empty( $custom_prices_meta ) && isset( $custom_prices_meta[ $custom_price['uuid'] ] ) );

				if ( ! $this->should_display_custom_price( $custom_price, $product ) ) {
					continue;
				}

				if ( $has_price && isset( $custom_price['regular_price_label'] ) && ! empty( $custom_price['regular_price_label'] ) ) {
					$price = '<span class="wpify-woo-prices__regular-price-label">' . $custom_price['regular_price_label'] . '</span> ' . $price;
					break;
				}
			}
		}

		// Add custom prices into price html
		$custom_prices_location = $this->get_setting( 'custom_prices_location' );

		if ( ! empty( $custom_prices_location ) && empty( $this->get_setting( 'custom_prices_custom_location' ) ) ) {
			if ( 'before_price_html' === $custom_prices_location ) {
				$price = $this->get_custom_prices_html( $custom_prices, true ) . $price;
			} elseif ( 'after_price_html' === $custom_prices_location ) {
				$price = $price . $this->get_custom_prices_html( $custom_prices, true );
			}
		}

		return $price;
	}

	/**
	 * Display custom prices in product page
	 */
	function display_custom_prices() {
		$custom_prices = $this->get_setting( 'custom_prices' );

		if ( ! is_array( $custom_prices ) ) {
			return;
		}

		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Method returns trusted price markup.
		echo $this->get_custom_prices_html( $custom_prices );
	}


	/**
	 * Display custom prices in product page
	 *
	 * @param array $custom_prices Custom prices setting
	 * @param bool  $in_html       rendered inside price html?
	 *
	 * @return false|string
	 */
	function get_custom_prices_html( $custom_prices, $in_html = false ) {
		$wrapper = $in_html ? 'span' : 'div';
		$line    = $in_html ? 'span' : 'p';

		global $product;

		ob_start();
		?>
		<<?php echo esc_html( $wrapper ); ?> class="wpify-woo-prices">
		<?php
		$custom_prices_vales = get_post_meta( get_the_ID(), '_custom_prices', true );

		foreach ( $custom_prices as $price ) {
			if ( ! $this->should_display_custom_price( $price, $product ) ) {
				continue;
			}

			$price['suffix'] = '';
			if ( ! isset( $price['type'] ) ) {
				if ( isset( $price['lowest_price'] ) && $price['lowest_price'] ) {
					$price['type'] = 'lowest';
				} else {
					$price['type'] = 'custom';
				}
			}
			if ( 'lowest' === $price['type'] ) {
				$module    = wpify_woo_container()->get( \WpifyWoo\Modules\PricesLog\PricesLogModule::class );
				$raw_price = $module->get_lowest_price( get_the_ID() );

				if ( $product ) {
					$price['value']  = wc_get_price_to_display( $product, array( 'price' => $raw_price ) );
					$price['suffix'] = $product->get_price_suffix( $price['value'] );
				} else {
					$price['value'] = $raw_price;
				}
			} elseif ( 'by_unit' === $price['type'] ) {
				if ( ! $custom_prices_vales || ! isset( $custom_prices_vales[ $price['uuid'] ] ) ) {
					continue;
				}
				$unit_data = $custom_prices_vales[ $price['uuid'] ];
				if ( empty( $unit_data['quantity'] ) ) {
					continue;
				}
				$price['value']  = floatval( $product->get_price() ) / floatval( $unit_data['quantity'] );
				$price['suffix'] = '/' . $unit_data['unit'];
			} else {
				if ( ! $custom_prices_vales ) {
					continue;
				}

				$price['value'] = $custom_prices_vales[ $price['uuid'] ] ?? 0;
			}

			/**
			 * Filter to edit price data
			 *
			 * @var array $price Price data
			 */
			$price = apply_filters( 'wpify_woo_prices_data', $price );

			if ( empty( $price['value'] ) ) {
				continue;
			}

			// Get price with multi currency support
			// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- WooCommerce Multilingual (WCML) core hook.
			$price['value'] = apply_filters( 'wcml_raw_price_amount', floatval( $price['value'] ) );

			?>
			<<?php echo esc_html( $line ); ?> class="wpify-woo-prices__price">
			<?php
			// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Contains wc_price() HTML and price suffix markup.
			echo wp_kses_post( ( $price['label'] ?: '' ) . ' ' . wc_price( $price['value'] ) . $price['suffix'] );

			if ( ! empty( $price['price_info'] ) ) {
				?>
				<span class="wpify-woo-prices__price-info">
					 		<?php esc_html_e( '?', 'wpify-woo' ); ?>
							<span class="wpify-woo-prices__price-info__text">
								<?php echo wp_kses_post( $price['price_info'] ); ?>
							</span>
						</span>
				<?php
			}
			?>
			</<?php echo esc_html( $line ); ?>>
			<?php
		}

		?>
		</<?php echo esc_html( $wrapper ); ?>>
		<?php

		return ob_get_clean();
	}

	public function should_display_custom_price( $custom_price, $product ) {
		$condition = ! empty( $custom_price['price_condition'] ) ? $custom_price['price_condition'] : '';

		$display = true;
		if (
			'in_sale' === $condition && ! $product->is_on_sale() ||
			'not_in_sale' === $condition && $product->is_on_sale() ||
			'on_backorder' === $condition && ! $product->is_on_backorder()
		) {
			$display = false;
		}

		return apply_filters( 'wpify_woo_prices_should_display_price', $display, $custom_price, $product );
	}

	/**
	 * Add price fields into general tab in product admin page
	 */
	function custom_price_fields() {
		$custom_prices = $this->get_setting( 'custom_prices' );

		if ( ! is_array( $custom_prices ) ) {
			return;
		}

		$items = [];
		foreach ( $custom_prices as $price ) {
			if ( ! isset( $price['type'] ) || ! $price['type'] ) {
				if ( isset( $price['lowest_price'] ) && $price['lowest_price'] ) {
					$price['type'] = 'lowest';
				} else {
					$price['type'] = 'custom';
				}
			}

			if ( 'lowest' === $price['type'] ) {
				continue;
			} elseif ( 'by_unit' === $price['type'] ) {
				$items[] = array(
					'id'    => $price['uuid'],
					'type'  => 'group',
					'label' => __( 'Price by unit', 'wpify-woo' ),
					'items' => array(
						array(
							'id'    => 'unit',
							'label' => __( 'Package unit', 'wpify-woo' ),
							'type'  => 'text',
						),
						array(
							'id'    => 'quantity',
							'label' => __( 'Number of units', 'wpify-woo' ),
							'type'  => 'number',
						),
					),
				);
				continue;
			}

			$items[] = array(
				'id'    => $price['uuid'],
				'label' => sprintf( '%s (%s)', $price['label'] ?: __( 'Custom price', 'wpify-woo' ), get_woocommerce_currency_symbol() ),
				'type'  => 'number',
			);
		}

		$this->custom_fields->create_product_options(
			array(
				'tab'   => array(
					'id'       => 'general',
					'priority' => 10,
					'label'    => __( 'General', 'wpify-woo' ),
					'target'   => 'general_product_data'
				),
				'items' => array(
					array(
						'id'    => '_custom_prices',
						'type'  => 'group',
						'items' => $items,
					),
				),
			),
		);


		// TODO support for variations
//		$this->custom_fields->create_product_variation_options(
//			array(
//				'after' => 'pricing',
//				'tab'   => array(
//					'id'    => 'general',
//					'label' => __( 'General', 'woocommerce' ),
//				),
//				'items' => array(
//					array(
//						'id'    => '_custom_prices',
//						'type'  => 'group',
//						'items' => $items,
//					)
//				),
//			)
//		);
	}
}
