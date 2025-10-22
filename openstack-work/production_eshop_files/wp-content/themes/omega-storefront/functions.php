<?php
/**
 * Omega Storefront functions and definitions
 * @package Omega Storefront
 */

if ( ! function_exists( 'omega_storefront_after_theme_support' ) ) :

	function omega_storefront_after_theme_support() {
		
		add_theme_support( 'automatic-feed-links' );

		add_theme_support('woocommerce');
        add_theme_support('wc-product-gallery-zoom');
        add_theme_support('wc-product-gallery-lightbox');
        add_theme_support('wc-product-gallery-slider');
        add_theme_support('woocommerce', array(
            'gallery_thumbnail_image_width' => 300,
        ));

        load_theme_textdomain( 'omega-storefront', get_template_directory() . '/languages' );
		
		add_theme_support(
			'custom-background',
			array(
				'default-color' => 'ffffff',
			)
		);

		$GLOBALS['content_width'] = apply_filters( 'omega_storefront_content_width', 1140 );
		
		add_theme_support( 'post-thumbnails' );

		add_theme_support(
			'custom-logo',
			array(
				'height'      => 270,
				'width'       => 90,
				'flex-height' => true,
				'flex-width'  => true,
			)
		);
		
		add_theme_support( 'title-tag' );

		add_theme_support(
			'html5',
			array(
				'search-form',
				'comment-form',
				'comment-list',
				'gallery',
				'caption',
				'script',
				'style',
			)
		);

		add_theme_support( 'post-formats', array(
			'video',  
			'audio',  
			'gallery',
			'quote',  
			'image',  
			'link',   
			'status', 
			'aside',  
			'chat',   
		) );
		
		add_theme_support( 'align-wide' );
		add_theme_support( 'responsive-embeds' );
		add_theme_support( 'wp-block-styles' );

		require get_template_directory() . '/inc/metabox.php';
		require get_template_directory() . '/inc/homepage-setup/homepage-setup-settings.php';

		if (! defined( 'OMEGA_STOREFRONT_DOCS_PRO' ) ){
		define('OMEGA_STOREFRONT_DOCS_PRO',__('https://layout.omegathemes.com/steps/pro-omega-storefront/','omega-storefront'));
		}
		if (! defined( 'OMEGA_STOREFRONT_BUY_NOW' ) ){
		define('OMEGA_STOREFRONT_BUY_NOW',__('https://www.omegathemes.com/products/storefront-wordpress-theme','omega-storefront'));
		}
		if (! defined( 'OMEGA_STOREFRONT_SUPPORT_FREE' ) ){
		define('OMEGA_STOREFRONT_SUPPORT_FREE',__('https://wordpress.org/support/theme/omega-storefront/','omega-storefront'));
		}
		if (! defined( 'OMEGA_STOREFRONT_REVIEW_FREE' ) ){
		define('OMEGA_STOREFRONT_REVIEW_FREE',__('https://wordpress.org/support/theme/omega-storefront/reviews/#new-post','omega-storefront'));
		}
		if (! defined( 'OMEGA_STOREFRONT_DEMO_PRO' ) ){
		define('OMEGA_STOREFRONT_DEMO_PRO',__('https://layout.omegathemes.com/omega-storefront/','omega-storefront'));
		}
		if (! defined( 'OMEGA_STOREFRONT_LITE_DOCS_PRO' ) ){
		define('OMEGA_STOREFRONT_LITE_DOCS_PRO',__('https://layout.omegathemes.com/steps/free-omega-storefront/','omega-storefront'));
		}
		if (! defined( 'OMEGA_STOREFRONT_BUNDLE_BUTTON' ) ){
			define('OMEGA_STOREFRONT_BUNDLE_BUTTON',__('https://www.omegathemes.com/products/wp-theme-bundle','omega-storefront'));
		}

	}

endif;

add_action( 'after_setup_theme', 'omega_storefront_after_theme_support' );

/**
 * Register and Enqueue Styles.
 */
function omega_storefront_register_styles() {

	wp_enqueue_style( 'dashicons' );

    $omega_storefront_theme_version = wp_get_theme()->get( 'Version' );
	$omega_storefront_fonts_url = omega_storefront_fonts_url();
    if( $omega_storefront_fonts_url ){
    	require_once get_theme_file_path( 'lib/custom/css/wptt-webfont-loader.php' );
        wp_enqueue_style(
			'omega-storefront-google-fonts',
			wptt_get_webfont_url( $omega_storefront_fonts_url ),
			array(),
			$omega_storefront_theme_version
		);
    }

    wp_enqueue_style( 'swiper', get_template_directory_uri() . '/lib/swiper/css/swiper-bundle.min.css');
    wp_enqueue_style( 'owl.carousel', get_template_directory_uri() . '/lib/custom/css/owl.carousel.min.css');
	wp_enqueue_style( 'omega-storefront-style', get_stylesheet_uri(), array(), $omega_storefront_theme_version );

	wp_enqueue_style( 'omega-storefront-style', get_stylesheet_uri() );
	require get_parent_theme_file_path( '/custom_css.php' );
	wp_add_inline_style( 'omega-storefront-style',$omega_storefront_custom_css );

	$omega_storefront_css = '';

	if ( get_header_image() ) :

		$omega_storefront_css .=  '
			.main-header{
				background-image: url('.esc_url(get_header_image()).');
				-webkit-background-size: cover !important;
				-moz-background-size: cover !important;
				-o-background-size: cover !important;
				background-size: cover !important;
			}';

	endif;

	wp_add_inline_style( 'omega-storefront-style', $omega_storefront_css );

	if ( is_singular() && comments_open() && get_option( 'thread_comments' ) ) {
		wp_enqueue_script( 'comment-reply' );
	}	

	wp_enqueue_script( 'imagesloaded' );
    wp_enqueue_script( 'masonry' );
	wp_enqueue_script( 'swiper', get_template_directory_uri() . '/lib/swiper/js/swiper-bundle.min.js', array('jquery'), '', 1);
	wp_enqueue_script( 'omega-storefront-custom', get_template_directory_uri() . '/lib/custom/js/theme-custom-script.js', array('jquery'), '', 1);
	wp_enqueue_script( 'owl.carousel', get_template_directory_uri() . '/lib/custom/js/owl.carousel.js', array('jquery'), '', 1);

    // Global Query
    if( is_front_page() ){

    	$omega_storefront_posts_per_page = absint( get_option('posts_per_page') );
        $omega_storefront_c_paged = ( get_query_var( 'page' ) ) ? absint( get_query_var( 'page' ) ) : 1;
        $omega_storefront_posts_args = array(
            'posts_per_page'        => $omega_storefront_posts_per_page,
            'paged'                 => $omega_storefront_c_paged,
        );
        $omega_storefront_posts_qry = new WP_Query( $omega_storefront_posts_args );
        $max = $omega_storefront_posts_qry->max_num_pages;

    }else{
        global $wp_query;
        $max = $wp_query->max_num_pages;
        $omega_storefront_c_paged = ( get_query_var( 'paged' ) > 1 ) ? get_query_var( 'paged' ) : 1;
    }

    $omega_storefront_default = omega_storefront_get_default_theme_options();
    $omega_storefront_pagination_layout = get_theme_mod( 'omega_storefront_pagination_layout',$omega_storefront_default['omega_storefront_pagination_layout'] );
}

add_action( 'wp_enqueue_scripts', 'omega_storefront_register_styles',200 );

function omega_storefront_admin_enqueue_scripts_callback() {
    if ( ! did_action( 'wp_enqueue_media' ) ) {
    wp_enqueue_media();
    }
    wp_enqueue_script('omega-storefront-uploaderjs', get_stylesheet_directory_uri() . '/lib/custom/js/uploader.js', array(), "1.0", true);
}
add_action( 'admin_enqueue_scripts', 'omega_storefront_admin_enqueue_scripts_callback' );

/**
 * Register navigation menus uses wp_nav_menu in five places.
 */
function omega_storefront_menus() {

	$omega_storefront_locations = array(
		'omega-storefront-primary-menu'  => esc_html__( 'Primary Menu', 'omega-storefront' ),
	);

	register_nav_menus( $omega_storefront_locations );
}

add_action( 'init', 'omega_storefront_menus' );

add_filter('loop_shop_columns', 'omega_storefront_loop_columns');
if (!function_exists('omega_storefront_loop_columns')) {
	function omega_storefront_loop_columns() {
		$omega_storefront_columns = get_theme_mod( 'omega_storefront_per_columns', 3 );
		return $omega_storefront_columns;
	}
}

add_filter( 'loop_shop_per_page', 'omega_storefront_per_page', 20 );
function omega_storefront_per_page( $omega_storefront_cols ) {
  	$omega_storefront_cols = get_theme_mod( 'omega_storefront_product_per_page', 9 );
	return $omega_storefront_cols;
}

add_filter( 'woocommerce_output_related_products_args', 'omega_storefront_products_args' );

function omega_storefront_products_args( $omega_storefront_args ) {

    $omega_storefront_args['posts_per_page'] = get_theme_mod( 'omega_storefront_custom_related_products_number', 6 );

    $omega_storefront_args['columns'] = get_theme_mod( 'omega_storefront_custom_related_products_number_per_row', 3 );

    return $omega_storefront_args;
}

require get_template_directory() . '/inc/custom-header.php';
require get_template_directory() . '/classes/class-svg-icons.php';
require get_template_directory() . '/classes/class-walker-menu.php';
require get_template_directory() . '/inc/customizer/customizer.php';
require get_template_directory() . '/inc/custom-functions.php';
require get_template_directory() . '/inc/template-tags.php';
require get_template_directory() . '/classes/body-classes.php';
require get_template_directory() . '/inc/widgets/widgets.php';
require get_template_directory() . '/inc/pagination.php';
require get_template_directory() . '/lib/breadcrumbs/breadcrumbs.php';
require get_template_directory() . '/lib/custom/css/dynamic-style.php';


function omega_storefront_remove_customize_register() {
    global $wp_customize;

    $wp_customize->remove_setting( 'display_header_text' );
    $wp_customize->remove_control( 'display_header_text' );

}

add_action( 'customize_register', 'omega_storefront_remove_customize_register', 11 );

// Apply styles based on customizer settings

function omega_storefront_radio_sanitize(  $omega_storefront_input, $omega_storefront_setting  ) {
	$omega_storefront_input = sanitize_key( $omega_storefront_input );
	$omega_storefront_choices = $omega_storefront_setting->manager->get_control( $omega_storefront_setting->id )->choices;
	return ( array_key_exists( $omega_storefront_input, $omega_storefront_choices ) ? $omega_storefront_input : $omega_storefront_setting->default );
}
require get_template_directory() . '/inc/general.php';

function omega_storefront_sticky_sidebar_enabled() {
    $omega_storefront_sticky_sidebar = get_theme_mod('omega_storefront_sticky_sidebar', true);
    
    if ($omega_storefront_sticky_sidebar == false) {
        $omega_storefront_custom_css = ".widget-area-wrapper { position: relative !important; }";
        wp_add_inline_style('omega-storefront-style', $omega_storefront_custom_css);
    }
}
add_action('wp_enqueue_scripts', 'omega_storefront_sticky_sidebar_enabled');

add_filter( 'woocommerce_enable_setup_wizard', '__return_false' );

// NOTICE FUNCTION

function omega_storefront_admin_notice() { 
    global $pagenow;
    $theme_args = wp_get_theme();
    $meta = get_option( 'omega_storefront_admin_notice' );
    $name = $theme_args->get( 'Name' );
    $current_screen = get_current_screen();

    if ( ! $meta ) {
        if ( is_network_admin() ) {
            return;
        }

        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        if ( $current_screen->base != 'appearance_page_omegastorefront-wizard' ) {
            ?>
            <div class="notice notice-success notice-content">
                <h2><?php esc_html_e('Welcome! Thank you for choosing Omega Storefront. Let’s Set Up Your Website!', 'omega-storefront') ?> </h2>
                <p><?php esc_html_e('Before you dive into customization, let’s go through a quick setup process to ensure everything runs smoothly. Click below to start setting up your website in minutes!', 'omega-storefront') ?> </p>
                <div class="info-link">
                    <a href="<?php echo esc_url( admin_url( 'themes.php?page=omegastorefront-wizard' ) ); ?>"><?php esc_html_e('Get Started with Omega Storefront', 'omega-storefront'); ?></a>
                </div>
                <p class="dismiss-link"><strong><a href="?omega_storefront_admin_notice=1"><?php esc_html_e( 'Dismiss', 'omega-storefront' ); ?></a></strong></p>
            </div>
            <?php
        }
    }
}
add_action( 'admin_notices', 'omega_storefront_admin_notice' );

if ( ! function_exists( 'omega_storefront_update_admin_notice' ) ) :
/**
 * Updating admin notice on dismiss
 */
function omega_storefront_update_admin_notice() {
    if ( isset( $_GET['omega_storefront_admin_notice'] ) && $_GET['omega_storefront_admin_notice'] == '1' ) {
        update_option( 'omega_storefront_admin_notice', true );
    }
}
endif;
add_action( 'admin_init', 'omega_storefront_update_admin_notice' );

// After Switch theme function
add_action( 'after_switch_theme', 'omega_storefront_getstart_setup_options' );
function omega_storefront_getstart_setup_options() {
    update_option( 'omega_storefront_admin_notice', false );
}