<?php
/**
 * The Template for displaying product archives, including the main shop page which is a post type archive
 *
 * This template can be overridden by copying it to yourtheme/woocommerce/archive-product.php.
 *
 * HOWEVER, on occasion WooCommerce will need to update template files and you
 * (the theme developer) will need to copy the new files to your theme to
 * maintain compatibility. We try to do this as little as possible, but it does
 * happen. When this occurs the version of the template file will be bumped and
 * the readme will list any important changes.
 *
 * @see https://woocommerce.com/document/template-structure/
 * @package WooCommerce\Templates
 * @version 8.6.0
 */

defined( 'ABSPATH' ) || exit;

get_header( 'shop' ); 
$omega_storefront_layout = omega_storefront_get_final_sidebar_layout();
$omega_storefront_sidebar_column_class = ($omega_storefront_layout === 'right-sidebar') ? 'column-order-1' : 'column-order-2';
?>

<div class="singular-main-block">
	<div class="wrapper">
		<div class="column-row <?php echo esc_attr($omega_storefront_layout === 'no-sidebar' ? 'no-sidebar-layout' : ''); ?>">
			<div id="primary" class="content-area <?php echo esc_attr( $omega_storefront_sidebar_column_class ); ?>">
				<?php
				// Remove WooCommerce default primary wrapper to prevent duplication
				remove_action( 'woocommerce_before_main_content', 'woocommerce_output_content_wrapper', 10 );
				remove_action( 'woocommerce_after_main_content', 'woocommerce_output_content_wrapper_end', 10 );

				// WooCommerce wrapper opens
				do_action( 'woocommerce_before_main_content' ); 
				?>
				<?php
				do_action( 'woocommerce_shop_loop_header' );

				if ( woocommerce_product_loop() ) {

					do_action( 'woocommerce_before_shop_loop' );

					woocommerce_product_loop_start();

					if ( wc_get_loop_prop( 'total' ) ) {
						while ( have_posts() ) {
							the_post();
							do_action( 'woocommerce_shop_loop' );
							wc_get_template_part( 'content', 'product' );
						}
					}

					woocommerce_product_loop_end();
					do_action( 'woocommerce_after_shop_loop' );

				} else {
					do_action( 'woocommerce_no_products_found' );
				}
				?>
			</div> <!-- #primary ends here -->

			<?php
			// WooCommerce wrapper closes
			do_action( 'woocommerce_after_main_content' );
			
			// Sidebar
			if ($omega_storefront_layout !== 'no-sidebar') : do_action('woocommerce_sidebar'); endif;
			?>
		</div>
	</div>
</div>



<?php get_footer( 'shop' );
