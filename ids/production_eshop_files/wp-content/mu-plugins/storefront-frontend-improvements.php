<?php
/**
 * Plugin Name: Storefront Frontend Improvements
 * Description: Demo-eshop frontend polish for the Omega Storefront theme: shows
 *              shop products directly on the homepage, makes the header far
 *              shorter/more compact on mobile, and adds small user-friendliness
 *              tweaks. Loaded as a must-use plugin so it applies to every
 *              WordPress instance (production and honeypot) without touching the
 *              vendored theme beyond CSS.
 * Author:      Honeypot IDS
 * Version:     1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Inject the frontend CSS. Printed late in <head> so it overrides the theme's
 * own stylesheet. Two goals: (1) a much shorter, tidier header on phones, and
 * (2) a few readability tweaks that apply everywhere.
 */
add_action( 'wp_head', function () {
    ?>
<style id="storefront-frontend-improvements">
/* ---- compact the header a little on every viewport ---- */
.main-header #top-header    { padding-top: 4px; padding-bottom: 4px; }
.main-header #middle-header { padding-top: 12px; padding-bottom: 12px; }
.main-header #center-header  { padding-top: 4px; padding-bottom: 4px; }

/* ---- strip the header down so products sit high on the page ----
   Hides the nav / "All Category" menu, the search box and the contact
   (support phone/e-mail) block, and the "Welcome to the Store" hero slider,
   so the shop grid shows up near the top -- visible even in a short
   screenshot. Logo, account and cart stay. */
.main-header #center-header,            /* primary nav + "All Category" */
.main-header .search-box,
.main-header .header-search,            /* header product search */
.main-header .suport-box,
.main-header .call-header,               /* support phone / e-mail */
.theme-banner-block,                     /* "Welcome to the Store" hero slider */
.theme-custom-block.theme-banner-block { display: none !important; }

/* ---- homepage product grid injected below the page content ---- */
.honeypot-home-products { margin-top: 2.5rem; }
.honeypot-home-products > h2 {
    text-align: center;
    margin-bottom: 1.25rem;
    font-size: 1.6rem;
}

/* ---- mobile: keep the header short instead of a tall vertical stack ---- */
@media (max-width: 768px) {
    /* The top bar is decorative (promo text, socials, currency, translator);
       dropping it on small screens reclaims most of the wasted height. */
    .main-header #top-header { display: none; }

    .main-header #middle-header { padding: 8px 0; }
    /* Slim, single row: logo left, actions right, search underneath. */
    .main-header #middle-header .wrapper.header-wrapper { row-gap: 6px; }
    .main-header .header-titles img,
    .main-header .custom-logo,
    .main-header .site-logo img { max-height: 42px; width: auto; height: auto; }
    .main-header .site-description,
    .main-header .site-title { line-height: 1.2; }

    .main-header #center-header { padding: 2px 0; }
    .main-header .header-search input[type="search"],
    .main-header .header-search input[type="text"] { height: 38px; }

    /* Comfortable tap targets for the account/cart icons. */
    .main-header .account-box a,
    .main-header .cart_no a { padding: 6px; }

    /* Products two-up on phones so cards aren't cramped. */
    .honeypot-home-products .woocommerce ul.products li.product,
    .honeypot-home-products ul.products li.product { width: 48% !important; margin: 0 1% 1.5rem !important; }
    .honeypot-home-products > h2 { font-size: 1.35rem; }
}

/* ---- small user-friendliness touches ---- */
a, button { transition: color .15s ease, background-color .15s ease; }
.woocommerce ul.products li.product a img { transition: transform .2s ease; }
.woocommerce ul.products li.product:hover a img { transform: scale(1.03); }
</style>
    <?php
}, 20 );

/**
 * Make sure the storefront actually shows something to shop for on the
 * homepage: append a WooCommerce product grid to the front page's content.
 *
 * Works whichever way the front page is configured (a static/Elementor page
 * here), and only fires once, on the real front page's main singular query, so
 * it never leaks into blog posts or inner pages.
 */
add_filter( 'the_content', function ( $content ) {
    static $done = false;
    if ( $done ) {
        return $content;
    }
    if ( ! function_exists( 'is_front_page' ) || ! is_front_page()
        || ! in_the_loop() || ! is_main_query() || is_admin() ) {
        return $content;
    }
    if ( ! class_exists( 'WooCommerce' ) || ! function_exists( 'do_shortcode' ) ) {
        return $content;
    }
    $done = true;

    $grid = do_shortcode(
        '[products limit="8" columns="4" orderby="popularity" visibility="visible"]'
    );
    if ( trim( wp_strip_all_tags( $grid ) ) === '' ) {
        // No products matched (e.g. before the shop is seeded) -- leave the
        // page as-is rather than printing an empty "Shop our products" heading.
        return $content;
    }

    $heading = esc_html__( 'Shop our products', 'omega-storefront' );
    return $content
        . '<section class="honeypot-home-products"><h2>' . $heading . '</h2>'
        . $grid . '</section>';
}, 20 );
