<?php
/**
 * Single Product Sale Flash
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly
}

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template-scoped variables in a WooCommerce template override.

global $post, $product;

?>
<?php if ( $product->is_on_sale() ) : ?>

	<?php
	// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped, WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- WooCommerce core hook returning trusted markup.
	echo apply_filters( 'woocommerce_sale_flash', '<span class="onsale">' . esc_html__( 'Sale!', 'wpify-woo' ) . '</span>', $post, $product );
	?>

<?php
else :
	$custom_prices = wpify_woo_container()->get( WpifyWoo\Modules\Prices\PricesModule::class )->get_setting( 'custom_prices' );

	if ( is_array( $custom_prices ) ) {
		foreach ( $custom_prices as $price ) {
			$custom_prices_meta = get_post_meta( $product->get_id(), '_custom_prices', true );
			$has_price          = ! empty( $custom_prices_meta ) && isset( $custom_prices_meta[ $price['uuid'] ] );

			if ( $has_price && isset( $price['badge_label'] ) && ! empty( $price['badge_label'] ) ) {
				echo '<span class="wpify-woo-prices__badge ' . esc_attr( $price['badge_class'] ?: 'onsale' ) . '">' . wp_kses_post( $price['badge_label'] ) . '</span>';
				break;
			}
		}
	}

endif;

// phpcs:enable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound
