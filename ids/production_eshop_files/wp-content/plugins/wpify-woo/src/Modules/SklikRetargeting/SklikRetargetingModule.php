<?php

namespace WpifyWoo\Modules\SklikRetargeting;

defined( 'ABSPATH' ) || exit;

use WC_Product;
use WpifyWoo\Plugin;
use WpifyWooDeps\Wpify\WooCore\Abstracts\AbstractModule;
use WpifyWooFeeds\Feeds\Zbozi\Settings as ZboziFeedSettings;

class SklikRetargetingModule extends AbstractModule {

	public function __construct(
		private CombinationDataBuilder $combination_builder
	) {
		parent::__construct();

		add_filter( 'wp_footer', array( $this, 'render_code' ), 20, 2 );
	}

	/**
	 * Module ID
	 * @return string
	 */
	public function id(): string {
		return 'sklik_retargeting';
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
		return 'wpify-woo/modules/sklik-retargeting';
	}

	/**
	 * Module name
	 *
	 * @return string
	 */
	public function name(): string {
		return __( 'Sklik retargeting', 'wpify-woo' );
	}

	/**
	 * Module settings
	 *
	 * @return array[]
	 */
	public function settings(): array {
		$settings = array(
			array(
				'id'    => 'rtg_id',
				'type'  => 'text',
				'label' => __( 'Identifier retargeting', 'wpify-woo' ),
				'desc'  => __( 'Enter your unique identifier for the <code>rtgId</code> that can be found in Sklik interface', 'wpify-woo' ),
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
				'type'  => 'title',
				'title' => __( 'Advanced data', 'wpify-woo' ),
				'desc'  => __( 'Advanced data are optional parameters that help to better target advertising.', 'wpify-woo' ),
			),
			array(
				'id'    => 'item_id',
				'type'  => 'toggle',
				'title' => __( 'Add E-shop offer identifier', 'wpify-woo' ),
				/* translators: %1$s: URL to Sklik Help about itemId parameter */
			'desc'  => sprintf( __( 'Check if <code>itemId</code> should be added to the code. More information about this parameter can be found in <a href="%1$s" target="_blank">Sklik Help</a>.', 'wpify-woo' ), 'https://napoveda.sklik.cz/cileni/retargeting/pokrocily-retargetingovy-kod/pokrocile-nastaveni-rtg-kodu-item_id/' ),
			),
			array(
				'id'    => 'custom_item_id',
				'type'  => 'text',
				'label' => __( 'Custom E-shop offer identifier', 'wpify-woo' ),
				'desc'  => __( 'Enter the key of the custom field of product you want to use for the <code>itemId</code> parameter. The product ID is used by default.', 'wpify-woo' ),
			),
		);

		if ( function_exists( 'wpify_woo_feeds_container' ) ) {
			$settings[] = array(
				'id'    => 'feed_category',
				'type'  => 'toggle',
				'title' => __( 'Use category identifier from Wpify Woo Feed', 'wpify-woo' ),
				'desc'  => __( 'Check if you want use category identifier from Wpify Woo Feeds plugin.', 'wpify-woo' ),
			);
		} else {
			/* translators: %s: URL to Wpify Woo Feeds plugin */
		$notice     = sprintf( __( 'If you want add automatically category identifier from feed settings. Install and use <a href="%s" target="_blank">Wpify Woo Feeds</a> plugin.', 'wpify-woo' ), __( 'https://wpify.io/product/wpify-woo-feeds/', 'wpify-woo' ) );
			$settings[] = array(
				'id'      => 'wpify_feed_notice',
				'type'    => 'html',
				'title'   => __( 'Use category identifier from Wpify Woo Feed', 'wpify-woo' ),
				'content' => sprintf( '<div class="notice notice-warning"><p>%s</p></div>', $notice ),
			);
		}

		$settings[] = array(
			'id'    => 'custom_category',
			'type'  => 'text',
			'label' => __( 'Custom category identifier', 'wpify-woo' ),
			/* translators: %1$s: URL to Sklik Help about category parameter */
			'desc'  => sprintf( __( 'Enter the meta data key of category you use to fill in the category for the Zbozi.cz XML feed. More information about <code>category</code> parameter can be found in <a href="%1$s" target="_blank">Sklik Help</a>.', 'wpify-woo' ), 'https://napoveda.sklik.cz/cileni/retargeting/pokrocily-retargetingovy-kod/pokrocile-nastaveni-rtg-kodu-category/' ),
		);

		return $settings;
	}

	/**
	 * Render retargeting code in wp footer
	 */
	public function render_code() {
		if ( ! $this->get_setting( 'rtg_id' ) || apply_filters( 'wpify_woo_sklik_retargeting_render_code', true ) === false ) {
			return;
		}

		$parameters   = $this->get_parameters();
		$cookie_name  = $this->get_setting( 'cookie_name' );
		$cookie_value = $this->get_setting( 'cookie_value' );

		$variation_map_json = null;
		if ( is_product() ) {
			$rendered_product = wc_get_product( get_the_ID() );
			if ( $rendered_product instanceof \WC_Product_Variable ) {
				$custom_item_id_meta = (string) $this->get_setting( 'custom_item_id' ) ?: null;
				$variation_map       = $this->combination_builder->build_variation_combo_map( $rendered_product, $custom_item_id_meta );
				if ( ! empty( $variation_map ) ) {
					$variation_map_json = wp_json_encode( $variation_map );
				}
			}
		}

		?>
		<!-- Sklik retargeting -->
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

				var retargetingConf = {
					<?php
					foreach ( $parameters as $key => $parameter ) {
						// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Internally generated retargeting parameters (keys and numeric/quoted values) written into an inline tracking script.
						echo $key . ': ' . $parameter . ', ';
					}
					?>
					consent: consent
				};
				if (window.rc && window.rc.retargetingHit) {
					window.rc.retargetingHit(retargetingConf);
				}
				console.log('retargetingConf', retargetingConf);

				<?php if ( $variation_map_json ) : ?>
				var wpifyWooSklikVariationMap = <?php echo $variation_map_json; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Value already produced by wp_json_encode(); safe for inline script output. ?>;
				if (window.jQuery) {
					jQuery(function ($) {
						var $form = $('.variations_form').first();
						if (!$form.length) {
							return;
						}
						$form.on('found_variation', function (event, variation) {
							var vid = variation && variation.variation_id;
							if (!vid) {
								return;
							}
							var combos = wpifyWooSklikVariationMap[vid] || [];
							if (!combos.length) {
								return;
							}
							var slugs = {};
							$form.find('.variations select').each(function () {
								var name = $(this).attr('data-attribute_name') || $(this).attr('name');
								if (!name) {
									return;
								}
								slugs[name.replace(/^attribute_/, '')] = $(this).val() || '';
							});
							var matched = null;
							for (var i = 0; i < combos.length; i++) {
								var attrs = combos[i].slug_attrs || {};
								var ok = true;
								for (var tax in attrs) {
									if (!Object.prototype.hasOwnProperty.call(attrs, tax)) {
										continue;
									}
									if (slugs[tax] !== attrs[tax]) {
										ok = false;
										break;
									}
								}
								if (ok) {
									matched = combos[i];
									break;
								}
							}
							if (matched && window.rc && window.rc.retargetingHit) {
								var hit = {};
								for (var k in retargetingConf) {
									if (Object.prototype.hasOwnProperty.call(retargetingConf, k)) {
										hit[k] = retargetingConf[k];
									}
								}
								hit.itemId = String(matched.id);
								window.rc.retargetingHit(hit);
								console.log('retargetingConf (variation)', hit);
							}
						});
					});
				}
				<?php endif; ?>
			})();
		</script>
		<?php
	}

	/**
	 * Get parameters for retargeting code
	 */
	public function get_parameters() {
		$parameters = array(
			'rtgId' => esc_attr( $this->get_setting( 'rtg_id' ) ),
		);

		$item_id = $this->get_setting( 'item_id' );
		if ( $item_id && is_product() ) {
			$parameters['itemId']   = '"' . $this->get_item_ids() . '"';
			$parameters['pageType'] = '"offerdetail"';
		}

		if ( is_product_category() ) {
			$category      = '';
			$feed_category = $this->get_setting( 'feed_category' );
			if ( $feed_category && function_exists( 'wpify_woo_feeds_container' ) ) {
				$category = wpify_woo_feeds_container()->get( ZboziFeedSettings::CLASS )->get_option( 'category_' . get_the_id() );
			}

			$custom_category = $this->get_setting( 'custom_category' );
			if ( empty( $category ) && $custom_category ) {
				$category = get_term_meta( get_the_ID(), $custom_category, true );
			}

			if ( $category ) {
				$parameters['category'] = '"' . $category . '"';
				$parameters['pageType'] = '"category"';
			}
		}

		return apply_filters( 'wpify_woo_sklik_retargeting_parameters', $parameters );
	}

	public function get_item_ids(): string {
		/** @var $product WC_Product */
		$product = wc_get_product( get_the_ID() );
		if ( ! $product ) {
			return '';
		}

		$custom_item_id = (string) $this->get_setting( 'custom_item_id' ) ?: null;

		if ( $product->is_type( 'variable' ) && $product instanceof \WC_Product_Variable ) {
			$map     = $this->combination_builder->build_variation_combo_map( $product, $custom_item_id );
			$initial = $this->combination_builder->resolve_initial_combo_id( $map );
			if ( null !== $initial ) {
				return $initial;
			}
		}

		if ( $custom_item_id ) {
			$meta = $product->get_meta( $custom_item_id );
			if ( $meta ) {
				return (string) $meta;
			}
		}

		return (string) get_the_ID();
	}

}
