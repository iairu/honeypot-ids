<?php

namespace WpifyWoo\Modules\DeliveryDates;

defined( 'ABSPATH' ) || exit;

use WC_Product;
use WC_Shipping_Zones;
use WpifyWoo\Plugin;
use WpifyWooDeps\Wpify\WooCore\Abstracts\AbstractModule;
use WpifyWoo\Managers\ApiManager;
use WpifyWoo\Modules\DeliveryDates\Api\DeliveryDatesApi;
use WpifyWooDeps\Wpify\Asset\AssetFactory;
use WpifyWooDeps\Wpify\CustomFields\CustomFields;
use WpifyWooDeps\Wpify\PluginUtils\PluginUtils;

class DeliveryDatesModule extends AbstractModule {

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
		add_action( 'init', array( $this, 'product_metabox' ) );
		add_action( 'init', array( $this, 'add_rest_api' ) );
		add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_scripts' ) );

		if ( is_array( $this->get_setting( 'display_locations' ) ) ) {
			foreach ( $this->get_setting( 'display_locations' ) as $location ) {
				add_action( $location, array( $this, 'display_delivery_date' ) );
			}
		}

		add_action( 'admin_init', array( $this, 'convert_old_product_data' ) );
		add_action( 'admin_init', array( $this, 'convert_old_settings' ) );
		add_action( 'wp_ajax_wpify_delivery_dates_dismiss_notice', array(
			$this,
			'wpify_delivery_dates_dismiss_admin_notice',
		) );
		add_action( 'admin_enqueue_scripts', array( $this, 'make_delivery_dates_admin_notice_dismissable' ) );
		add_action( 'admin_notices', array( $this, 'maybe_show_notice' ) );
		add_shortcode( 'wpify_woo_delivery_dates', array( $this, 'delivery_date_shortcode' ) );
	}

	function id() {
		return 'delivery_dates';
	}

	public function name() {
		return __( 'Delivery dates', 'wpify-woo' );
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
		return 'wpify-woo/modules/delivery-dates';
	}

	/**
	 * @return array[]
	 */
	public function settings(): array {
		$locations = [
			'woocommerce_single_product_summary',
			'woocommerce_before_add_to_cart_form',
			'woocommerce_before_variations_form',
			'woocommerce_before_add_to_cart_button',
			'woocommerce_before_add_to_cart_quantity',
			'woocommerce_after_add_to_cart_quantity',
			'woocommerce_after_add_to_cart_button',
			'woocommerce_after_add_to_cart_form',
			'woocommerce_after_variations_form',
			'woocommerce_product_meta_start',
			'woocommerce_product_meta_end',
			'woocommerce_after_single_product_summary',
		];
		$settings  = array(
			array(
				'id'      => 'delivery_days',
				'type'    => 'multi_group',
				'title'   => 'Delivery days',
				'buttons' => array(
					'add' => __( 'Add delivery days', 'wpify-woo' ),
				),
				'items'   => array(
					array(
						'id'    => 'group_title',
						'type'  => 'text',
						'label' => __( 'Group title', 'wpify-woo' ),
					),
					array(
						'id'    => 'delivery_order_time',
						'type'  => 'time',
						'label' => __( 'Bridging time to next day', 'wpify-woo' ),
						'desc'  => __( 'If this time is exceeded, the next day will count for delivery.', 'wpify-woo' ),
					),
					array(
						'id'    => 'delivery_days_in_stock',
						'type'  => 'text',
						'label' => __( 'In stock delivery days', 'wpify-woo' ),
						'desc'  => __( 'Enter a number indicating the number of days, a range in <code>1-2</code> format, or any text. Leave blank to not show.', 'wpify-woo' ),
					),
					array(
						'id'    => 'delivery_days_out_of_stock',
						'type'  => 'text',
						'label' => __( 'Out of stock delivery days', 'wpify-woo' ),
						'desc'  => __( 'Enter a number indicating the number of days, a range in <code>1-2</code> format, or any text. Leave blank to not show.', 'wpify-woo' ),
					),
					array(
						'id'    => 'delivery_days_backorder',
						'type'  => 'text',
						'label' => __( 'On backorder delivery days', 'wpify-woo' ),
						'desc'  => __( 'Enter a number indicating the number of days, a range in <code>1-2</code> format, or any text. Leave blank to not show.', 'wpify-woo' ),
					),
					array(
						'id'    => 'skip_weekends',
						'type'  => 'toggle',
						'title' => __( 'Skip weekends', 'wpify-woo' ),
					),
					array(
						'id'         => 'delivery_date_message',
						'type'       => 'text',
						'label'      => __( 'Delivery date message', 'wpify-woo' ),
						'desc'       => __( 'Use <code>{date}</code> code to render calculated date in messsage.', 'wpify-woo' ),
						'default'    => __( 'Delivered on {date}', 'wpify-woo' ),
						'unfiltered' => true
					),
					array(
						'id'    => 'delivery_date_info',
						'type'  => 'wysiwyg',
						'label' => __( 'Delivery date more info', 'wpify-woo' ),
						'desc'  => __( 'Use <code>{date}</code> code to render calculated date in messsage.', 'wpify-woo' ),
					),
					array(
						'id'      => 'shipping_methods',
						'label'   => __( 'Display shipping methods', 'wpify-woo' ),
						'type'    => 'multiselect',
						'multi'   => true,
						'desc'    => __( 'Select the shipping methods that appear in more information.', 'wpify-woo' ),
						'options' => $this->get_shipping_methods_option(),
					),
					array(
						'type'      => 'hidden',
						'id'        => 'uuid',
						'generator' => 'uuid',
					),

				),
			),
			array(
				'id'      => 'delivery_date_format',
				'type'    => 'text',
				'label'   => __( 'Delivery date format', 'wpify-woo' ),
				'default' => 'd.m.',
			),
			array(
				'id'    => 'date_as_text',
				'type'  => 'toggle',
				'title' => __( 'Today and tomorrow as text', 'wpify-woo' ),
			),
			array(
				'id'    => 'title',
				'type'  => 'text',
				'label' => __( 'Title of delivery date block', 'wpify-woo' ),
			),
			array(
				'id'    => 'country_select_label',
				'type'  => 'text',
				'label' => __( 'Label of country selector', 'wpify-woo' ),
			),
			array(
				'id'      => 'more_info_label',
				'type'    => 'text',
				'label'   => __( 'More info link label', 'wpify-woo' ),
				'default' => __( 'more info', 'wpify-woo' ),
			),
			array(
				'id'         => 'payments_message',
				'type'       => 'text',
				'label'      => __( 'Payment methods message', 'wpify-woo' ),
				'desc'       => __( 'Insert payment methods message. Leave empty to not show.', 'wpify-woo' ),
				'unfiltered' => true
			),
			array(
				'id'    => 'payments_info',
				'type'  => 'wysiwyg',
				'label' => __( 'Payment methods more info', 'wpify-woo' ),
			),
			array(
				'id'           => 'display_locations',
				'type'         => 'multi_select',
				'label'        => __( 'Display locations', 'wpify-woo' ),
				'options'      => function () use ( $locations ) {
					return array_map( function ( $item ) {
						return [
							'label' => $item,
							'value' => $item,
						];
					}, $locations );
				},
				'async_params' => [
					'module_id' => $this->id(),
				],
			),
			array(
				'id'    => 'render_async',
				'type'  => 'toggle',
				'title' => __( 'Render delivery details asynchronously (cache-friendly)', 'wpify-woo' ),
				'desc'  => __( 'When enabled, delivery details are fetched via REST API after page load.', 'wpify-woo' ),
			),

		);

		return $settings;
	}


	/**
	 * Product options
	 */
	public function product_metabox() {
		$delivery_days = $this->get_setting( 'delivery_days' ) ?? [];
		$items         = [];

		foreach ( $delivery_days as $key => $group ) {
			$items[] = array(
				'id'    => 'delivery_dates_' . $group['uuid'] ?? $key,
				'type'  => 'group',
				'items' => array(
					array(
						'type' => 'title',
						'desc' => $group['group_title'],
					),
					array(
						'id'    => 'delivery_days_in_stock',
						'type'  => 'text',
						'label' => __( 'In stock delivery days', 'wpify-woo' ),
						'desc'  => __( 'Override the default value from the settings.', 'wpify-woo' ),
					),
					array(
						'id'    => 'delivery_days_out_of_stock',
						'type'  => 'text',
						'label' => __( 'Out of stock delivery days', 'wpify-woo' ),
						'desc'  => __( 'Override the default value from the settings.', 'wpify-woo' ),
					),
					array(
						'id'    => 'delivery_days_backorder',
						'type'  => 'text',
						'label' => __( 'On backorder delivery days', 'wpify-woo' ),
						'desc'  => __( 'Override the default value from the settings.', 'wpify-woo' ),
					),
				),
			);
		}

		$this->custom_fields->create_product_options(
			[
				'tab'   => array(
					'id'       => 'wpify_woo_delivery_dates',
					'label'    => __( 'Delivery dates', 'wpify-woo' ),
					'priority' => 100,
					'class'    => array(),
				),
				'items' => array(
					array(
						'id'    => '_wpify_woo_delivery_dates',
						'type'  => 'group',
						'items' => $items,
					),

				),
			]
		);
	}

	/**
	 * Get list of shipping methods for options
	 *
	 * @return array
	 */
	public function get_shipping_methods_option(): array {
		if ( ! is_admin() ) {
			return array();
		}

		$shipping_methods = [];

		foreach ( $this->get_all_zones() as $zone ) {
			$name = $zone['zone_name'];

			foreach ( $zone['shipping_methods'] as $shipping ) {
				/** @var $shipping \WC_Shipping_Flat_Rate */
				$shipping_methods[] = array(
					'label' => sprintf( '%s: %s', $name, $shipping->get_title() ),
					'value' => $shipping->get_rate_id(),
				);
			}
		}

		return $shipping_methods;
	}

	/**
	 * Enqueue frontend scripts
	 */
	public function enqueue_scripts() {
		$this->asset_factory->wp_script( $this->plugin_utils->get_plugin_path( 'build/delivery-dates.css' ) );
		$this->asset_factory->wp_script( $this->plugin_utils->get_plugin_path( 'build/delivery-dates.js' ), array(
			'handle'    => 'wpify-woo-delivery-dates',
			'in_footer' => true,
			'variables' => array(
				'wpifyDeliveryDates' => array(
					'namespace' => ApiManager::REST_NAMESPACE,
				),
			),
		) );
	}

	/**
	 * Init Rest API
	 *
	 * @throws \WpifyWooDeps\Wpify\Core\Exceptions\ComponentInitFailureException
	 * @throws \WpifyWooDeps\Wpify\Core\Exceptions\PluginException
	 */
	public function add_rest_api() {
		wpify_woo_container()->get( DeliveryDatesApi::class );
	}

	/**
	 * Get all shipping zones
	 *
	 * @return array
	 */
	public function get_all_zones(): array {
		$zones        = WC_Shipping_Zones::get_zones();
		$default_zone = new \WC_Shipping_Zone( 0 );

		if ( empty( $default_zone->get_shipping_methods() ) ) {
			return $zones;
		}

		$zones[ $default_zone->get_id() ]                            = $default_zone->get_data();
		$zones[ $default_zone->get_id() ]['formatted_zone_location'] = __( 'Other regions', 'wpify-woo' );
		$zones[ $default_zone->get_id() ]['shipping_methods']        = $default_zone->get_shipping_methods();

		return $zones;
	}

	/**
	 * Get zone ID for a given country code.
	 *
	 * Supports zone locations by country, continent, or world.
	 *
	 * @param string $country_code Two-letter ISO country code (e.g. 'CZ')
	 * @param array  $zones        All shipping zones with locations
	 *
	 * @return int|null
	 */
	public function get_zone_id_for_country( string $country_code, array $zones ): ?int {
		// First, get full info about country (from WC)
		$wc_countries   = new \WC_Countries();
		$continent_code = $wc_countries->get_continent_code_for_country( $country_code );

		foreach ( $zones as $zone ) {
			if ( ! isset( $zone['zone_locations'] ) || ! is_array( $zone['zone_locations'] ) ) {
				continue;
			}

			foreach ( $zone['zone_locations'] as $location ) {
				// Match by exact country
				if ( $location->type === 'country' && $location->code === $country_code ) {
					return $zone['id'];
				}

				// Match by continent
				if ( $location->type === 'continent' && $location->code === $continent_code ) {
					return $zone['id'];
				}

				// Match "worldwide"
				if ( $location->type === 'world' ) {
					return $zone['id'];
				}
			}
		}

		return null;
	}

	/**
	 * Get formatted date or date name
	 *
	 * @param string|float $days       number of days or string
	 * @param array        $days_group array of delivery date group settings
	 *
	 * @return string
	 */
	public function get_formatted_date( $days, $days_group ): string {
		$format     = $this->get_setting( 'delivery_date_format' );
		$type       = $days_group['skip_weekends'] ? 'weekdays' : 'days';
		$order_time = $days_group['delivery_order_time'];
		$today      = current_time( 'Y-m-d' );
		$days       = (int) $days;

		if (
			( strtotime( current_time( 'H:i' ) ) > strtotime( $order_time ) )
			|| // překlenutí času na další den
			( wp_date( 'N', strtotime( $today ) ) >= 6 && $days_group['skip_weekends'] ) // překlenutí wíkendu o další den
		) {
			$days += 1;
		}

		$days = strtotime( sprintf( '+ %s %s', $days, $type ), strtotime( $today ) );
		$date = date_i18n( $format, $days );

		if ( $this->get_setting( 'date_as_text' ) ) {
			if ( strtotime( $today ) === strtotime( wp_date( 'Y-m-d', $days ) ) ) {
				return __( 'Today', 'wpify-woo' );
			} elseif ( strtotime( $today . ' +1 day' ) === strtotime( wp_date( 'Y-m-d', $days ) ) ) {
				return __( 'Tomorrow', 'wpify-woo' );
			}
		}

		return $date;
	}

	public function get_delivery_date_data( WC_Product $product ): array {
		$delivery_groups = $this->resolve_delivery_date_groups( $product );

		foreach ( $delivery_groups as $group ) {
			if ( empty( $group['is_visible'] ) ) {
				continue;
			}

			return array(
				'status'  => $this->get_product_delivery_status( $product ),
				'title'   => (string) $this->get_setting( 'title' ),
				'message' => html_entity_decode(
					wp_strip_all_tags( str_replace( '{date}', $group['data']['date'], $group['data']['message'] ) ),
					ENT_QUOTES | ENT_HTML5,
					'UTF-8'
				),
				'date'          => (string) ( $group['data']['date'] ?? '' ),
				'specific_date' => (string) ( $group['data']['date'] ?? '' ),
				'score'         => $group['score'],
			);
		}

		return array();
	}

	/**
	 * Return table of delivery methods
	 *
	 * @param array  $methods_ids        delivery methods ids
	 * @param array  $shipping_countries shipping countries from WC settings
	 * @param array  $shipping_zones     all shipping zones
	 * @param string $actual_country     code of actual country
	 *
	 * @throws \Exception
	 */
	public function display_delivery_methods( $methods_ids, $shipping_zones, $actual_zone_id ) {
		// Get array of allowed countries names
		$zone_countries = [];
		foreach ( $shipping_zones as $key => $zone ) {
			$zone_countries[ $key ] = $zone['formatted_zone_location'];
		}

		// Render list of shipping methods by country
		foreach ( $shipping_zones as $key => $zone ) {
			// Remove unassigned shipping methods
			foreach ( $zone['shipping_methods'] as $shipping_key => $method ) {
				if ( ! in_array( $method->get_rate_id(), $methods_ids ) ) {
					unset( $shipping_zones[ $key ]['shipping_methods'][ $shipping_key ] );
				}
			}

			// Skip zones without shipping methods
			if ( empty( $shipping_zones[ $key ]['shipping_methods'] ) ) {
				continue;
			}

			// Get selected country
			$selected = $actual_zone_id;
			$show     = $selected == $zone['id'];

			// Show all methods if selector is disabled
			if ( apply_filters( 'wpify_woo_delivery_dates_disable_country_select', false ) ) {
				$show = true;
			}
			?>

			<div id="zone-<?php echo esc_attr( $zone['id'] ); ?>"
				 class="wpify-woo-delivery-date__shipping-methods <?php echo $show ? 'show' : ''; ?>">
				<table>

					<?php
					foreach ( $shipping_zones[ $key ]['shipping_methods'] as $method ) {
						// Skip disabled methods
						if ( $method->enabled !== 'yes' ) {
							continue;
						}

						// set data
						$line_data = array(
							'title' => $method->title,
							'price' => is_object( 'WC_Shipping_Free_Shipping' ) || empty( $method->cost ) ? '' : wc_price( $method->cost ),
						);

						/**
						 * Filter to change shipping methods line data
						 *
						 * @param array  $line_data current line data
						 * @param object $method    shipping methods data
						 */
						$line_data = apply_filters( 'wpify_woo_delivery_dates_shipping_table_line', $line_data, $method );

						?>
						<tr>
							<th><?php echo esc_html( $line_data['title'] ); ?></th>
							<td><?php echo wp_kses_post( $line_data['price'] ); ?></td>
						</tr>
						<?php
					}
					?>
				</table>
			</div>
			<?php
		}
	}

	/**
	 * Return table of payment methods
	 */
	public function display_payment_methods() {
		$gateways = WC()->payment_gateways->get_available_payment_gateways();

		if ( $gateways ) {
			?>
			<table class="wpify-woo-delivery-date__payments">
				<?php
				foreach ( $gateways as $gateway ) {
					// Skip disabled gateways
					if ( $gateway->enabled !== 'yes' ) {
						continue;
					}

					// set data
					$line_data = array(
						'title' => $gateway->title,
						'price' => '',
					);

					/**
					 * Filter to change gateway line data
					 *
					 * @param array  $line_data current line data
					 * @param object $gateway   gateway data
					 */
					$line_data = apply_filters( 'wpify_woo_delivery_dates_payment_table_line', $line_data, $gateway );

					?>
					<tr>
						<th><?php echo esc_html( $line_data['title'] ); ?></th>
						<td><?php echo wp_kses_post( $line_data['price'] ); ?></td>
					</tr>
					<?php
				}
				?>
			</table>
			<?php
		}
	}

	/**
	 * Return country selector
	 *
	 * @param array  $shipping_countries shipping countries from WC settings
	 * @param array  $shipping_zones     all shipping zones
	 * @param array  $zone_countries     country names from zones
	 * @param string $actual_country     code of actual country
	 */
	public function display_country_select( $shipping_countries, $shipping_zones, $actual_zone_id ) {
		/**
		 * Filter to disable country selector
		 */
		if ( apply_filters( 'wpify_woo_delivery_dates_disable_country_select', false ) ) {
			return;
		}

		// Show country selector if set is multiple shipping zones
		if ( 1 < count( $shipping_zones ) ) {
			$country_select_label = $this->get_setting( 'country_select_label' );

			if ( $country_select_label ) {
				?>
				<label for="shipping_country"
					   class="wpify-woo-delivery-date__country-select-label">
					<?php echo esc_html( $country_select_label ); ?>
				</label>
				<?php
			} else {
				?>
				<label for="shipping_country"
					   class="screen-reader-text">
					<?php esc_html_e( 'Country / region:', 'wpify-woo' ); ?>
				</label>
				<?php
			}
			?>
			<select name="shipping_country" id="shipping_country"
					class="wpify-woo-delivery-date__country-select">
				<?php
				foreach ( $shipping_zones as $zone ) {
					// Skip zones without shipping methods
					if ( empty( $zone['shipping_methods'] ) ) {
						continue;
					}

					$selected     = $actual_zone_id === $zone['id'];
					$country_code = array_search( $zone['formatted_zone_location'], $shipping_countries );
					echo '<option value="zone-' . esc_attr( $zone['id'] ) . '" data-country="' . esc_attr( $country_code ) . '" ' . selected( $selected, true, false ) . '>' . esc_html( $zone['formatted_zone_location'] ) . '</option>';
				}
				?>
			</select>

			<?php
		}
	}

	/**
	 * Get html for delivery dates
	 *
	 * @param bool $force_sync Skip async placeholder rendering.
	 *
	 * @return string
	 */
	public function get_delivery_date_html( bool $force_sync = false ): string {
		global $product;

		$delivery_days = $this->get_setting( 'delivery_days' );

		if ( ! $product || empty( $delivery_days ) || empty( WC()->countries ) ) {
			return '';
		}

		if ( $this->get_setting( 'render_async' ) && ! $force_sync ) {
			$product_id = $product->get_id();
			if ( ! $product_id ) {
				return '';
			}

			return sprintf(
				'<div class="wpify-woo-delivery-date wpify-woo-delivery-date--async" data-product-id="%d"></div>',
				(int) $product_id
			);
		}

		$shipping_countries = WC()->countries->get_shipping_countries();
		$actual_country     = ! empty( WC()->customer ) && WC()->customer->get_shipping_country() ? WC()->customer->get_shipping_country() : WC()->countries->get_base_country();
		$shipping_zones     = $this->get_all_zones();
		$actual_zone_id     = $this->get_zone_id_for_country( $actual_country, $shipping_zones );

		if ( ! $actual_zone_id ) {
			$actual_zone_id = array_key_first( $shipping_zones );
		}

		ob_start();
		?>
		<div class="wpify-woo-delivery-date">
			<?php
			$title = $this->get_setting( 'title' );
			if ( $title ) {
				echo '<h3 class="wpify-woo-delivery-date__title">' . esc_html( $title ) . '</h3>';
			}

			$this->display_country_select( $shipping_countries, $shipping_zones, $actual_zone_id );

			foreach ( $this->resolve_delivery_date_groups( $product ) as $group ) {
				$key            = $group['key'];
				$data           = $group['data'];
				$allowed_zones  = $group['allowed_zones'];
				$selected       = $group['selected_zone_id'];
				$shipping_zones = $group['shipping_zones'];
				$more_info      = $data['more_info_label'] && ( $data['more_info_text'] || $data['shipping_methods'] );
				$message        = str_replace( '{date}', '<span class="date">' . $data['date'] . '</span>', $data['message'] );
				$more_info_text = str_replace( '{date}', '<span class="date">' . $data['date'] . '</span>', $data['more_info_text'] );
				?>
				<div class="wpify-woo-delivery-date__line"
					 data-zones='[<?php echo esc_attr( implode( ',', $allowed_zones ) ); ?>]'
					 style="<?php echo esc_attr( ! in_array( '"zone-' . $selected . '"', $allowed_zones ) ? 'display:none' : '' ); ?>">
					<p>
						<?php echo wp_kses_post( $message ); ?>
						<?php if ( $more_info ) { ?>
							<a href="#<?php echo esc_attr( $key ); ?>"
							   data-id="wpify-woo-delivery-date-<?php echo esc_attr( $key ); ?>"><?php echo esc_html( $data['more_info_label'] ); ?></a>
						<?php } ?>
					</p>
					<?php if ( $more_info ) { ?>
						<div id="wpify-woo-delivery-date-<?php echo esc_attr( $key ); ?>" class="wpify-woo-delivery-date__info">
							<?php echo apply_filters( 'the_content', $more_info_text ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped, WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Core the_content filter output is display-safe. ?>
							<?php
							if ( $data['shipping_methods'] ) {
								$this->display_delivery_methods( $data['shipping_methods'], $shipping_zones, $actual_zone_id );
							} ?>
						</div>
					<?php } ?>
				</div>
				<?php
			} ?>

			<?php
			$payments_data = array(
				'message'         => $this->get_setting( 'payments_message' ),
				'more_info_label' => $this->get_setting( 'more_info_label' ),
				'more_info_text'  => $this->get_setting( 'payments_info' ),
			);
			/**
			 * Filter to change delivery date payments message
			 *
			 * @param array $payments_data data from settings
			 */
			$payments_data = apply_filters( 'wpify_woo_delivery_dates_payments_data', $payments_data );

			if ( ! empty( $payments_data['message'] ) ) {
				?>
				<p class="wpify-woo-delivery-date__line">
					<?php echo wp_kses_post( $payments_data['message'] ); ?>
					<a href="#"
					   data-id="wpify-woo-delivery-date-payment"><?php echo esc_html( $payments_data['more_info_label'] ); ?></a>
				</p>
				<div id="wpify-woo-delivery-date-payment" class="wpify-woo-delivery-date__info">
					<?php echo wp_kses_post( $payments_data['more_info_text'] ?? '' ); ?>
					<?php $this->display_payment_methods(); ?>
				</div>
				<?php
			}
			?>
		</div>
		<?php

		return ob_get_clean();
	}

	/**
	 * Render html
	 */
	public function display_delivery_date() {
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Returns trusted, internally-escaped plugin markup.
		echo $this->get_delivery_date_html();
	}

	/**
	 * Render the [wpify_woo_delivery_dates] shortcode.
	 *
	 * @return string
	 */
	public function delivery_date_shortcode(): string {
		return $this->get_delivery_date_html();
	}

	private function resolve_delivery_date_groups( WC_Product $product ): array {
		$delivery_days = $this->get_setting( 'delivery_days' );

		if ( empty( $delivery_days ) || empty( WC()->countries ) ) {
			return array();
		}

		$actual_country = ! empty( WC()->customer ) && WC()->customer->get_shipping_country() ? WC()->customer->get_shipping_country() : WC()->countries->get_base_country();
		$shipping_zones = $this->get_all_zones();
		$actual_zone_id = $this->get_zone_id_for_country( $actual_country, $shipping_zones );

		if ( ! $actual_zone_id ) {
			$actual_zone_id = array_key_first( $shipping_zones );
		}

		$custom_dates = $product->get_meta( '_wpify_woo_delivery_dates' );

		if ( empty( $custom_dates ) && $product->is_type( 'variation' ) ) {
			$parent_product = wc_get_product( $product->get_parent_id() );
			if ( $parent_product instanceof WC_Product ) {
				$custom_dates = $parent_product->get_meta( '_wpify_woo_delivery_dates' );
			}
		}

		$groups = array();

		foreach ( $delivery_days as $key => $days_group ) {
			if ( $product->is_on_backorder() ) {
				$custom_date = $custom_dates[ 'delivery_dates_' . $days_group['uuid'] ]['delivery_days_backorder'] ?? null;
				$days        = ! empty( $custom_date ) || $custom_date === '0' ? $custom_date : $days_group['delivery_days_backorder'];
			} elseif ( $product->is_in_stock() ) {
				$custom_date = $custom_dates[ 'delivery_dates_' . $days_group['uuid'] ]['delivery_days_in_stock'] ?? null;
				$days        = ! empty( $custom_date ) || $custom_date === '0' ? $custom_date : $days_group['delivery_days_in_stock'];
			} else {
				$custom_date = $custom_dates[ 'delivery_dates_' . $days_group['uuid'] ]['delivery_days_out_of_stock'] ?? null;
				$days        = ! empty( $custom_date ) || $custom_date === '0' ? $custom_date : $days_group['delivery_days_out_of_stock'];
			}

			$days = apply_filters( 'wpify_woo_delivery_dates_days', $days, $product, $days_group );

			if ( ( empty( $days ) && $days !== '0' ) || $days === '-' ) {
				continue;
			}

			$data = array(
				'date' => $days,
			);

			if ( is_numeric( $days ) ) {
				$data['date'] = $this->get_formatted_date( $days, $days_group );
			}

			if ( is_string( $days ) && str_contains( $days, '-' ) ) {
				$range = explode( '-', $days );
				$dates = array();

				foreach ( $range as $day ) {
					$dates[] = $this->get_formatted_date( $day, $days_group );
				}

				$data['date'] = implode( '–', $dates );
			}

			$data['message']          = $days_group['delivery_date_message'] ?? '';
			$data['more_info_label']  = $this->get_setting( 'more_info_label' );
			$data['more_info_text']   = $days_group['delivery_date_info'] ?? null;
			$data['shipping_methods'] = $days_group['shipping_methods'] ?? [];
			$data                     = apply_filters( 'wpify_woo_delivery_dates_data', $data );

			if ( empty( $data['message'] ) ) {
				continue;
			}

			$group_shipping_zones = $shipping_zones;
			$allowed_zones        = array();

			foreach ( $group_shipping_zones as $zone_key => $zone ) {
				if ( ! empty( $data['shipping_methods'] ) ) {
					foreach ( $zone['shipping_methods'] as $shipping_key => $method ) {
						if ( ! in_array( $method->get_rate_id(), $data['shipping_methods'] ) ) {
							unset( $group_shipping_zones[ $zone_key ]['shipping_methods'][ $shipping_key ] );
						}
					}

					if ( empty( $group_shipping_zones[ $zone_key ]['shipping_methods'] ) ) {
						continue;
					}
				}

				$allowed_zones[] = '"zone-' . $zone_key . '"';
			}

			$groups[] = array(
				'key'              => $key,
				'data'             => $data,
				'allowed_zones'    => $allowed_zones,
				'selected_zone_id' => $actual_zone_id,
				'shipping_zones'   => $group_shipping_zones,
				'is_visible'       => in_array( '"zone-' . $actual_zone_id . '"', $allowed_zones, true ),
				'score'            => $this->get_delivery_days_score( $days ),
			);
		}

		return $groups;
	}

	private function get_delivery_days_score( $days ): int {
		if ( is_numeric( $days ) ) {
			return (int) $days;
		}

		if ( is_string( $days ) && str_contains( $days, '-' ) ) {
			$range = array_filter(
				array_map( 'trim', explode( '-', $days ) ),
				'is_numeric'
			);

			if ( ! empty( $range ) ) {
				return max( array_map( 'intval', $range ) );
			}
		}

		return 0;
	}

	private function get_product_delivery_status( WC_Product $product ): string {
		if ( $product->is_on_backorder() ) {
			return 'onbackorder';
		}

		if ( $product->is_in_stock() ) {
			return 'instock';
		}

		return 'outofstock';
	}

	/**
	 * Convert old product data to new structure
	 */
	public function convert_old_product_data() {
		if ( ! isset( $_GET['wpify-delivery-dates-convert-data'] ) ) {
			return;
		}
		if ( ! wp_verify_nonce( isset( $_GET['_wpnonce'] ) ? sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ) ) : '', 'wpify-delivery-dates-convert-data' ) ) {
			return;
		}

		$delivery_days = $this->get_setting( 'delivery_days' ) ?? [];

		if ( ! isset( $delivery_days[0]['uuid'] ) ) {
			$return_url = add_query_arg( array(
				'wpf-delivery-dates-data-migrated' => 'migrate-error',
			), $this->get_settings_url() );

			wp_safe_redirect( $return_url, 302, 'WPifyWooDeliveryDates' );
			exit();
		}

		$params = array(
			'post_type'      => 'product',
			// phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_query -- One-time admin data-migration lookup.
			'meta_query'     => array(
				array(
					'key' => '_wpify_woo_delivery_dates',
				),
			),
			'posts_per_page' => - 1,

		);

		$products = get_posts( $params );
		$success  = 0;

		foreach ( $products as $product ) {
			$post_meta = get_post_meta( $product->ID, '_wpify_woo_delivery_dates', true );

			if ( empty( $post_meta ) ) {
				continue;
			}

			$new_meta = [];
			foreach ( $delivery_days as $key => $day ) {
				if ( isset( $post_meta[ 'delivery_dates_' . $day['uuid'] ] ) ) {
					continue;
				};

				$new_meta[ 'delivery_dates_' . $day['uuid'] ] = $post_meta[ 'delivery_dates_' . $key ];
			}

			if ( ! empty( $new_meta ) ) {
				update_post_meta( $product->ID, '_wpify_woo_delivery_dates', $new_meta );
				$success += 1;
			}
		}

		$return_url = add_query_arg( array(
			'wpf-delivery-dates-data-migrated' => 'migrate-data',
			'success'                          => $success,
		), $this->get_settings_url() );

		wp_safe_redirect( $return_url, 302, 'WPifyWooDeliveryDates' );
		exit();
	}

	/**
	 * Convert old settings to new one
	 */
	public function convert_old_settings() {
		if ( get_option( 'wpify-woo-delivery-days-option-update' ) ) {
			return;
		}

		$options = get_option( $this->get_option_key() );
		if ( ! isset( $options['delivery_days'] ) || empty( $options['delivery_days'] ) ) {
			return;
		}

		foreach ( $options['delivery_days'] as $key => $delivery_day ) {
			$message        = $delivery_day['delivery_date_message'] ?? '';
			$more_info_text = $delivery_day['delivery_date_info'] ?? null;

			$options['delivery_days'][ $key ]['delivery_date_message'] = str_replace( '%date%', '{date}', $message );
			$options['delivery_days'][ $key ]['delivery_date_info']    = str_replace( '%date%', '{date}', $more_info_text );
		}

		update_option( $this->get_option_key(), $options );
		update_option( 'wpify-woo-delivery-days-option-update', true );
	}

	/**
	 * Show admin notices
	 */
	public function maybe_show_notice() {
		// Read-only admin notice shown after a nonce-verified redirect; no state change here.
		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		$process = isset( $_GET['wpf-delivery-dates-data-migrated'] )
			? sanitize_text_field( wp_unslash( $_GET['wpf-delivery-dates-data-migrated'] ) )
			: null;

		if ( ! empty( $process ) ) {
			$success = isset( $_GET['success'] )
				? sanitize_text_field( wp_unslash( $_GET['success'] ) )
				: '';
			// phpcs:enable WordPress.Security.NonceVerification.Recommended
			if ( $process === 'migrate-data' ) {
				/* translators: %s: number of products migrated */
				$string = sprintf( __( 'Wpify Woo delivery date data migration is success for %s products.', 'wpify-woo' ), (int) $success );
			} else {
				$string = sprintf( __( 'Wpify Woo delivery date data migration failed.', 'wpify-woo' ), (int) $success );
			}

			printf( '<div class="notice-success notice"><p>%s</p></div>', esc_html( $string ) );
		}
	}

	/**
	 * Save the information that you dismissed the message
	 */
	public function wpify_delivery_dates_dismiss_admin_notice() {
		if ( ! current_user_can( 'manage_woocommerce' )
			|| ! check_ajax_referer( 'wpify_delivery_dates_dismiss_notice', 'nonce', false ) ) {
			wp_send_json_error( '', 403 );
		}

		update_option( 'wpify_delivery_dates_admin_notice_dismissed', true );
		wp_send_json_success();
	}

	/**
	 * Dismiss the message
	 */
	public function make_delivery_dates_admin_notice_dismissable() {
		if ( get_option( 'wpify_delivery_dates_admin_notice_dismissed' ) ) {
			return;
		}

		$nonce  = wp_create_nonce( 'wpify_delivery_dates_dismiss_notice' );
		$script = "jQuery(document).on('click','.wpify-delivery-dates-notice .notice-dismiss',function(){jQuery.post(ajaxurl,{action:'wpify_delivery_dates_dismiss_notice',nonce:'" . esc_js( $nonce ) . "'});});";
		wp_add_inline_script( 'jquery', $script );
	}

}
