<?php
/**
 * Plugin Name: Fernhill Storefront
 * Description: Branding, homepage, product-page extras and shop behaviour for the
 *              Fernhill Coffee Roasters demo store. A must-use plugin so it applies
 *              identically to production and every honeypot pool.
 * Version:     2.0.0
 *
 * Design rule: everything a visitor sees must come from data the honeypot
 * content sync replicates (posts, postmeta, terms, attachments) or from code and
 * option filters in this file. Options, comments, nav-menu items and term meta
 * are NOT replicated, so none of them are used for presentation -- reviews are
 * postmeta, menus are built here, and site settings are filtered below.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

const FH_FREE_SHIPPING_MIN = 45;
const FH_PHONE             = '(503) 555-0142';
const FH_EMAIL             = 'hello@fernhillroasters.com';

/* ------------------------------------------------------------------ settings */

/** Site and store settings, identical on every instance (see header note). */
add_action( 'init', function () {
    $settings = array(
        'blogname'                          => 'Fernhill Coffee Roasters',
        'blogdescription'                   => 'Small-batch coffee & brewing gear, roasted fresh in Portland, Oregon',
        'woocommerce_store_address'         => '412 SE Alder Street',
        'woocommerce_store_city'            => 'Portland',
        'woocommerce_default_country'       => 'US:OR',
        'woocommerce_store_postcode'        => '97214',
        'woocommerce_currency'              => 'USD',
        'woocommerce_email_from_name'       => 'Fernhill Coffee Roasters',
        'woocommerce_email_from_address'    => FH_EMAIL,
        'woocommerce_stock_format'          => 'low_amount',
        'woocommerce_notify_low_stock_amount' => '8',
        // WooCommerce ships new installs in "coming soon" mode, which replaces the
        // shop, product and cart pages with a placeholder. Never on here.
        'woocommerce_coming_soon'           => 'no',
        'woocommerce_store_pages_only'      => 'no',
        'woocommerce_enable_reviews'        => 'yes',
        'woocommerce_enable_review_rating'  => 'yes',
        'woocommerce_enable_ajax_add_to_cart' => 'yes',
    );
    foreach ( $settings as $key => $value ) {
        add_filter( 'pre_option_' . $key, static fn() => $value );
    }
    // Front page / posts page by slug (page IDs are the same everywhere, but the
    // options that point at them are not replicated).
    $by_slug = static function ( $slug ) {
        static $cache = array();
        if ( ! array_key_exists( $slug, $cache ) ) {
            $page         = get_page_by_path( $slug );
            $cache[ $slug ] = $page ? (int) $page->ID : 0;
        }
        return $cache[ $slug ];
    };
    add_filter( 'pre_option_show_on_front', static fn( $v ) => $by_slug( 'home' ) ? 'page' : $v );
    add_filter( 'pre_option_page_on_front', static fn( $v ) => $by_slug( 'home' ) ?: $v );
    add_filter( 'pre_option_page_for_posts', static fn( $v ) => $by_slug( 'journal' ) ?: $v );
    add_filter( 'pre_option_wp_page_for_privacy_policy', static fn( $v ) => $by_slug( 'privacy-policy' ) ?: $v );

    // No sidebars anywhere: a storefront, not a blog template.
    foreach ( array( 'global', 'page', 'post' ) as $scope ) {
        add_filter( "theme_mod_omega_storefront_{$scope}_sidebar_layout", static fn() => 'no-sidebar' );
    }
    add_filter( 'theme_mod_omega_storefront_per_columns', static fn() => 4 );
    add_filter( 'theme_mod_omega_storefront_custom_related_products_number', static fn() => 4 );
    add_filter( 'theme_mod_omega_storefront_custom_related_products_number_per_row', static fn() => 4 );
    add_filter( 'theme_mod_omega_storefront_product_per_page', static fn() => 12 );
}, 1 );

add_filter( 'loop_shop_per_page', static fn() => 12, 20 );
add_filter( 'loop_shop_columns', static fn() => 4, 20 );
add_filter( 'woocommerce_product_related_products_heading', static fn() => 'You might also like' );
add_filter( 'woocommerce_upsell_display_args', static fn( $a ) => array_merge( $a, array( 'posts_per_page' => 4, 'columns' => 4 ) ) );
add_filter( 'woocommerce_output_related_products_args', static fn( $a ) => array_merge( $a, array( 'posts_per_page' => 4, 'columns' => 4 ) ) );

/**
 * Catalog order identical across production and honeypot databases: only
 * orderings built from replicated data (menu order, price, name, date) -- never
 * popularity, which only production accrues.
 */
add_filter( 'woocommerce_default_catalog_orderby', static fn() => 'menu_order' );
add_filter( 'woocommerce_catalog_orderby', static function () {
    return array(
        'menu_order' => __( 'Featured', 'omega-storefront' ),
        'price'      => __( 'Price: low to high', 'omega-storefront' ),
        'price-desc' => __( 'Price: high to low', 'omega-storefront' ),
        'date'       => __( 'Newest first', 'omega-storefront' ),
        'title'      => __( 'Name: A to Z', 'omega-storefront' ),
    );
} );
add_filter( 'woocommerce_get_catalog_ordering_args', static function ( $args ) {
    if ( empty( $args['orderby'] ) || in_array( $args['orderby'], array( 'popularity', 'rating' ), true ) ) {
        $args['orderby']  = 'menu_order title';
        $args['order']    = 'ASC';
        $args['meta_key'] = '';
    }
    return $args;
}, 20 );

/* -------------------------------------------------------------------- assets */

function fh_asset( $file ) {
    return get_template_directory_uri() . '/assets/fernhill/' . ltrim( $file, '/' );
}

add_action( 'wp_enqueue_scripts', static function () {
    $dir = get_template_directory() . '/assets/fernhill/';
    // Cache-bust with our own parameter: production-hardening.php strips ?ver=,
    // and the proxy caches static assets by URL, so an edited file would otherwise
    // keep being served stale.
    $css = add_query_arg( 'fhv', (string) @filemtime( $dir . 'fernhill.css' ), fh_asset( 'fernhill.css' ) );
    $js  = add_query_arg( 'fhv', (string) @filemtime( $dir . 'fernhill.js' ), fh_asset( 'fernhill.js' ) );
    wp_enqueue_style( 'fernhill', $css, array( 'omega-storefront-style' ), null );
    wp_enqueue_script( 'fernhill', $js, array(), null, true );
}, 300 );

add_action( 'wp_head', static function () {
    echo '<link rel="icon" href="' . esc_url( fh_asset( 'img/icon.png' ) ) . '" type="image/png">' . "\n";
    echo '<meta name="theme-color" content="#2f5d3a">' . "\n";
    $org = array(
        '@context' => 'https://schema.org', '@type' => 'Organization', 'name' => 'Fernhill Coffee Roasters',
        'url' => home_url( '/' ), 'logo' => fh_asset( 'img/logo-dark.png' ),
        'address' => array( '@type' => 'PostalAddress', 'streetAddress' => '412 SE Alder Street', 'addressLocality' => 'Portland', 'addressRegion' => 'OR', 'postalCode' => '97214', 'addressCountry' => 'US' ),
        'telephone' => FH_PHONE, 'email' => FH_EMAIL,
    );
    echo '<script type="application/ld+json">' . wp_json_encode( $org, JSON_UNESCAPED_SLASHES ) . "</script>\n";
}, 5 );
// The theme prints its own (default WordPress) site icon; ours replaces it.
add_filter( 'get_site_icon_url', static fn() => fh_asset( 'img/icon.png' ) );

/* ------------------------------------------------------------- navigation */

/** Primary navigation, built from product categories (terms ARE replicated). */
function fh_primary_nav() {
    $items = array();
    $cats  = get_terms( array( 'taxonomy' => 'product_cat', 'hide_empty' => false, 'parent' => 0 ) );
    $order = array( 'coffee', 'brewing-gear', 'drinkware', 'apparel-merch', 'gifts-subscriptions' );
    // Short labels for the header bar; $item[3] carries the full category name.
    $short = array( 'coffee' => 'Coffee', 'brewing-gear' => 'Brewing Gear', 'drinkware' => 'Drinkware', 'apparel-merch' => 'Merch', 'gifts-subscriptions' => 'Gifts' );
    if ( ! is_wp_error( $cats ) ) {
        usort( $cats, static function ( $a, $b ) use ( $order ) {
            $ia = array_search( $a->slug, $order, true );
            $ib = array_search( $b->slug, $order, true );
            return ( false === $ia ? 99 : $ia ) <=> ( false === $ib ? 99 : $ib );
        } );
        foreach ( $cats as $c ) {
            // Only our own categories: honeypot pools never delete terms, so a
            // pool seeded before the catalog change may still hold stale ones.
            if ( in_array( $c->slug, $order, true ) ) {
                $items[] = array( $short[ $c->slug ] ?? $c->name, get_term_link( $c ), $c->slug, $c->name );
            }
        }
    }
    foreach ( array( 'journal' => 'Journal', 'about' => 'Our Story' ) as $slug => $label ) {
        $p = get_page_by_path( $slug );
        if ( $p ) {
            $items[] = array( $label, get_permalink( $p ), $slug, $label );
        }
    }
    return $items;
}

function fh_page_link( $slug, $fallback = '#' ) {
    $p = get_page_by_path( $slug );
    return $p ? get_permalink( $p ) : $fallback;
}

/** Cart count and total in the header, kept live through WooCommerce fragments. */
function fh_cart_html() {
    $count = function_exists( 'WC' ) && WC()->cart ? WC()->cart->get_cart_contents_count() : 0;
    $total = function_exists( 'WC' ) && WC()->cart ? WC()->cart->get_cart_subtotal() : '';
    return '<a class="fh-cart" href="' . esc_url( wc_get_cart_url() ) . '" aria-label="Cart">'
        . '<svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true"><path d="M6 6h15l-1.6 9H8L6 3H2" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><circle cx="9" cy="20" r="1.6" fill="currentColor"/><circle cx="18" cy="20" r="1.6" fill="currentColor"/></svg>'
        . '<span class="fh-cart-count">' . (int) $count . '</span>'
        . ( $count ? '<span class="fh-cart-total">' . wp_kses_post( $total ) . '</span>' : '' ) . '</a>';
}
add_filter( 'woocommerce_add_to_cart_fragments', static function ( $f ) {
    $f['a.fh-cart'] = fh_cart_html();
    return $f;
} );

/* ------------------------------------------------------ forms (no plugin) */

add_action( 'admin_post_nopriv_fh_newsletter', 'fh_handle_forms' );
add_action( 'admin_post_fh_newsletter', 'fh_handle_forms' );
add_action( 'admin_post_nopriv_fh_contact', 'fh_handle_forms' );
add_action( 'admin_post_fh_contact', 'fh_handle_forms' );
function fh_handle_forms() {
    $action = isset( $_POST['action'] ) ? sanitize_key( wp_unslash( $_POST['action'] ) ) : '';
    $back   = wp_get_referer() ?: home_url( '/' );
    if ( ! isset( $_POST['_fh'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_fh'] ) ), 'fh_form' ) ) {
        wp_safe_redirect( add_query_arg( 'fh', 'error', $back ) );
        exit;
    }
    $email = isset( $_POST['email'] ) ? sanitize_email( wp_unslash( $_POST['email'] ) ) : '';
    if ( ! is_email( $email ) ) {
        wp_safe_redirect( add_query_arg( 'fh', 'invalid', $back ) );
        exit;
    }
    if ( 'fh_contact' === $action ) {
        $msg = isset( $_POST['message'] ) ? sanitize_textarea_field( wp_unslash( $_POST['message'] ) ) : '';
        wp_mail( FH_EMAIL, 'Website enquiry from ' . $email, $msg, array( 'Reply-To: ' . $email ) );
        wp_safe_redirect( add_query_arg( 'fh', 'sent', $back ) );
    } else {
        wp_safe_redirect( add_query_arg( 'fh', 'subscribed', $back ) );
    }
    exit;
}

function fh_notice() {
    $map = array(
        'sent' => array( 'ok', 'Thanks! Your message is on its way. We will reply within one business day.' ),
        'subscribed' => array( 'ok', 'You are on the list. Check your inbox to confirm.' ),
        'invalid' => array( 'err', 'That email address does not look right. Please try again.' ),
        'error' => array( 'err', 'Something went wrong. Please try again.' ),
    );
    $k = isset( $_GET['fh'] ) ? sanitize_key( wp_unslash( $_GET['fh'] ) ) : '';
    return isset( $map[ $k ] ) ? '<p class="fh-notice fh-notice-' . $map[ $k ][0] . '">' . esc_html( $map[ $k ][1] ) . '</p>' : '';
}

function fh_newsletter_form( $class = '' ) {
    return '<form class="fh-newsletter ' . esc_attr( $class ) . '" method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">'
        . '<input type="hidden" name="action" value="fh_newsletter">' . wp_nonce_field( 'fh_form', '_fh', true, false )
        . '<label class="screen-reader-text" for="fh-nl-email">Email address</label>'
        . '<input id="fh-nl-email" type="email" name="email" placeholder="Your email address" required>'
        . '<button type="submit">Subscribe</button></form>';
}

add_shortcode( 'fernhill_contact_form', static function () {
    return fh_notice() . '<form class="fh-contact-form" method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">'
        . '<input type="hidden" name="action" value="fh_contact">' . wp_nonce_field( 'fh_form', '_fh', true, false )
        . '<h2>Send us a message</h2>'
        . '<p><label>Your name<input type="text" name="name" required></label></p>'
        . '<p><label>Email<input type="email" name="email" required></label></p>'
        . '<p><label>Topic<select name="topic"><option>Order question</option><option>Subscription</option><option>Wholesale</option><option>Something else</option></select></label></p>'
        . '<p><label>Message<textarea name="message" rows="5" required></textarea></label></p>'
        . '<p><button type="submit" class="button">Send message</button></p></form>';
} );

/* --------------------------------------------------------------- home page */

function fh_stars( $n, $size = 16 ) {
    $out = '<span class="fh-stars" aria-label="' . esc_attr( $n ) . ' out of 5">';
    for ( $i = 1; $i <= 5; $i++ ) {
        $out .= '<svg viewBox="0 0 24 24" width="' . (int) $size . '" height="' . (int) $size . '" class="' . ( $i <= round( $n ) ? 'on' : 'off' ) . '"><path d="M12 2.5l2.9 6.1 6.6.8-4.9 4.6 1.3 6.6L12 17.3 6.1 20.6l1.3-6.6L2.5 9.4l6.6-.8z"/></svg>';
    }
    return $out . '</span>';
}

add_shortcode( 'fernhill_home', static function () {
    $o = '';
    $shop = function_exists( 'wc_get_page_permalink' ) ? wc_get_page_permalink( 'shop' ) : home_url( '/shop/' );
    $coffee = get_term_by( 'slug', 'coffee', 'product_cat' );
    $kit = get_page_by_path( 'pour-over-starter-kit', OBJECT, 'product' );
    $sub = get_page_by_path( 'coffee-club-subscription', OBJECT, 'product' );

    // Hero
    $o .= '<section class="fh-hero" style="background-image:url(' . esc_url( fh_asset( 'img/hero.jpg' ) ) . ')"><div class="fh-wrap"><div class="fh-hero-copy">'
        . '<p class="fh-eyebrow">Roasted fresh in Portland, Oregon</p>'
        . '<h1>Coffee worth<br>waking up for.</h1>'
        . '<p class="fh-hero-sub">Small-batch roasts from farms we know by name, shipped within 24 hours of the drum.</p>'
        . '<p class="fh-hero-cta"><a class="fh-btn fh-btn-light" href="' . esc_url( $coffee ? get_term_link( $coffee ) : $shop ) . '">Shop coffee</a>'
        . ( $kit ? '<a class="fh-btn fh-btn-ghost" href="' . esc_url( get_permalink( $kit ) ) . '">Pour-over starter kit</a>' : '' ) . '</p>'
        . '</div></div></section>';

    // Value props
    $props = array(
        array( 'Roasted to order', 'Monday and Thursday, shipped within 24 hours.', '<path d="M12 3c3 4 5 6.5 5 10a5 5 0 01-10 0c0-1.8.8-3.2 2-4.5.3 1.4 1 2.3 2 2.8C11.2 9.3 11.4 6.5 12 3z"/>' ),
        array( 'Free shipping over $' . FH_FREE_SHIPPING_MIN, 'Carbon-neutral delivery, tracked to your door.', '<path d="M3 7h11v9H3zM14 10h4l3 3v3h-7M7 19a2 2 0 100-4 2 2 0 000 4zM17 19a2 2 0 100-4 2 2 0 000 4z"/>' ),
        array( '30-day happiness guarantee', 'Not in love with it? We will make it right.', '<path d="M12 21s-7-4.4-7-10a4 4 0 017-2.6A4 4 0 0119 11c0 5.6-7 10-7 10z"/>' ),
        array( 'Directly sourced', 'Every bag names its farm, altitude and process.', '<path d="M12 3v18M12 8c-4 0-6-2-6-5 4 0 6 2 6 5zm0 6c4 0 6-2 6-5-4 0-6 2-6 5zm0 5c-3 0-5-1.5-5-4 3 0 5 1.5 5 4z"/>' ),
    );
    $o .= '<section class="fh-usps"><div class="fh-wrap fh-usp-grid">';
    foreach ( $props as $p ) {
        $o .= '<div class="fh-usp"><svg viewBox="0 0 24 24" width="30" height="30" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">' . $p[2] . '</svg><div><strong>' . esc_html( $p[0] ) . '</strong><span>' . esc_html( $p[1] ) . '</span></div></div>';
    }
    $o .= '</div></section>';

    // Category tiles
    $o .= '<section class="fh-section"><div class="fh-wrap"><header class="fh-section-head"><h2>Shop by category</h2><a href="' . esc_url( $shop ) . '">View everything &rarr;</a></header><div class="fh-tiles">';
    foreach ( fh_primary_nav() as $item ) {
        if ( in_array( $item[2], array( 'journal', 'about' ), true ) ) {
            continue;
        }
        $o .= '<a class="fh-tile" href="' . esc_url( $item[1] ) . '"><img loading="lazy" src="' . esc_url( fh_asset( 'img/cat-' . $item[2] . '.jpg' ) ) . '" alt="' . esc_attr( $item[3] ) . '"><span>' . esc_html( $item[3] ) . '</span></a>';
    }
    $o .= '</div></div></section>';

    // Best sellers
    $o .= '<section class="fh-section fh-section-sand"><div class="fh-wrap"><header class="fh-section-head"><h2>Customer favourites</h2><a href="' . esc_url( $shop ) . '">Shop all &rarr;</a></header>'
        . do_shortcode( '[products visibility="featured" limit="4" columns="4" orderby="menu_order" order="ASC"]' ) . '</div></section>';

    // Story
    $o .= '<section class="fh-section"><div class="fh-wrap fh-split"><img loading="lazy" src="' . esc_url( fh_asset( 'img/journal-roast.jpg' ) ) . '" alt="Roast day at Fernhill">'
        . '<div><p class="fh-eyebrow">Our story</p><h2>Roasted twice a week. Never sat on a shelf.</h2>'
        . '<p>We buy small lots directly from growers we have visited, roast them in 12 kg batches on a restored 1970s drum roaster, and ship within 24 hours. That is why a bag of Fernhill tastes like it was roasted last Monday: because it was.</p>'
        . '<p><a class="fh-btn" href="' . esc_url( fh_page_link( 'about' ) ) . '">Read our story</a></p></div></div></section>';

    // On sale
    $sale = do_shortcode( '[sale_products limit="4" columns="4" orderby="menu_order" order="ASC"]' );
    if ( trim( wp_strip_all_tags( $sale ) ) !== '' ) {
        $o .= '<section class="fh-section"><div class="fh-wrap"><header class="fh-section-head"><h2>On sale now</h2></header>' . $sale . '</div></section>';
    }

    // Testimonials
    $quotes = array(
        array( 'The House Blend is the first coffee my whole family agrees on. It arrived two days after roasting and you can tell.', 'Maya R.', 'Seattle, WA' ),
        array( 'The starter kit turned my sad drip coffee into a ritual. The brewing card is genius.', 'Daniel K.', 'Austin, TX' ),
        array( 'Subscribed in March. Not a single bad bag since, and the packaging is fully recyclable. Love that.', 'Priya S.', 'Chicago, IL' ),
    );
    $o .= '<section class="fh-section fh-section-sand"><div class="fh-wrap"><header class="fh-section-head"><h2>Loved by coffee people</h2></header><div class="fh-quotes">';
    foreach ( $quotes as $q ) {
        $o .= '<figure class="fh-quote">' . fh_stars( 5, 18 ) . '<blockquote>&ldquo;' . esc_html( $q[0] ) . '&rdquo;</blockquote><figcaption><strong>' . esc_html( $q[1] ) . '</strong> &middot; ' . esc_html( $q[2] ) . '</figcaption></figure>';
    }
    $o .= '</div></div></section>';

    // Subscription banner
    if ( $sub ) {
        $o .= '<section class="fh-section"><div class="fh-wrap"><div class="fh-banner"><div><p class="fh-eyebrow">Coffee Club</p><h2>Never run out of great coffee.</h2>'
            . '<p>Fresh-roasted beans on your schedule. Skip, pause or cancel anytime.</p></div>'
            . '<a class="fh-btn fh-btn-light" href="' . esc_url( get_permalink( $sub ) ) . '">Start your subscription</a></div></div></section>';
    }

    // Journal
    $posts = get_posts( array( 'numberposts' => 3, 'post_status' => 'publish', 'orderby' => 'date', 'order' => 'DESC' ) );
    if ( $posts ) {
        $o .= '<section class="fh-section"><div class="fh-wrap"><header class="fh-section-head"><h2>From the journal</h2><a href="' . esc_url( fh_page_link( 'journal' ) ) . '">All articles &rarr;</a></header><div class="fh-posts">';
        foreach ( $posts as $p ) {
            $cat = get_the_category( $p->ID );
            $o  .= '<a class="fh-post" href="' . esc_url( get_permalink( $p ) ) . '">' . get_the_post_thumbnail( $p, 'large', array( 'loading' => 'lazy' ) )
                . '<span class="fh-post-cat">' . esc_html( $cat ? $cat[0]->name : '' ) . '</span><h3>' . esc_html( get_the_title( $p ) ) . '</h3><p>' . esc_html( wp_trim_words( get_the_excerpt( $p ), 22 ) ) . '</p></a>';
        }
        $o .= '</div></div></section>';
    }
    return $o;
} );

/* -------------------------------------------------------------- shop pages */

/** Short tasting notes under each coffee in listings. */
add_action( 'woocommerce_after_shop_loop_item_title', static function () {
    global $product;
    if ( ! $product ) {
        return;
    }
    $notes = $product->get_attribute( 'Tasting notes' );
    if ( $notes ) {
        echo '<p class="fh-notes">' . esc_html( $notes ) . '</p>';
    }
}, 6 );

/** "Best seller" / "New" badge from postmeta. */
add_action( 'woocommerce_before_shop_loop_item_title', static function () {
    global $product;
    $b = $product ? get_post_meta( $product->get_id(), '_fh_badge', true ) : '';
    if ( $b ) {
        echo '<span class="fh-badge fh-badge-' . esc_attr( $b ) . '">' . ( 'bestseller' === $b ? 'Best seller' : 'New' ) . '</span>';
    }
}, 9 );
add_action( 'woocommerce_before_single_product_summary', static function () {
    global $product;
    $b = $product ? get_post_meta( $product->get_id(), '_fh_badge', true ) : '';
    if ( $b ) {
        echo '<span class="fh-badge fh-badge-' . esc_attr( $b ) . '">' . ( 'bestseller' === $b ? 'Best seller' : 'New' ) . '</span>';
    }
}, 9 );

/** Trust points under the add-to-cart button. */
add_action( 'woocommerce_single_product_summary', static function () {
    echo '<ul class="fh-trust">'
        . '<li><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M3 7h11v9H3zM14 10h4l3 3v3h-7"/><circle cx="7" cy="18" r="1.6"/><circle cx="17" cy="18" r="1.6"/></svg>Free shipping over $' . FH_FREE_SHIPPING_MIN . '</li>'
        . '<li><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M12 3c3 4 5 6.5 5 10a5 5 0 01-10 0c0-1.8.8-3.2 2-4.5"/></svg>Roasted to order, ships within 24 h</li>'
        . '<li><svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M12 21s-7-4.4-7-10a4 4 0 017-2.6A4 4 0 0119 11c0 5.6-7 10-7 10z"/></svg>30-day happiness guarantee</li></ul>';
}, 45 );

/** Reviews (from postmeta) and a brewing guide tab. */
add_filter( 'woocommerce_product_tabs', static function ( $tabs ) {
    global $product;
    if ( ! $product ) {
        return $tabs;
    }
    $id      = $product->get_id();
    $reviews = json_decode( (string) get_post_meta( $id, '_fh_reviews', true ), true );
    unset( $tabs['reviews'] );
    if ( is_array( $reviews ) && $reviews ) {
        $tabs['reviews'] = array( 'title' => 'Reviews (' . count( $reviews ) . ')', 'priority' => 30, 'callback' => 'fh_reviews_tab' );
    }
    $brew = get_post_meta( $id, '_fh_brew', true );
    if ( $brew ) {
        $tabs['brew'] = array( 'title' => 'How to brew', 'priority' => 25, 'callback' => static function () use ( $brew ) {
            echo '<h2>How to brew it</h2><p>' . esc_html( ucfirst( $brew ) ) . '</p>';
        } );
    }
    if ( isset( $tabs['additional_information'] ) ) {
        $tabs['additional_information']['title'] = 'Details';
    }
    return $tabs;
} );

function fh_reviews_tab() {
    global $product;
    $reviews = json_decode( (string) get_post_meta( $product->get_id(), '_fh_reviews', true ), true ) ?: array();
    $count   = count( $reviews );
    $avg     = $count ? array_sum( array_column( $reviews, 'rating' ) ) / $count : 0;
    $dist    = array_fill( 1, 5, 0 );
    foreach ( $reviews as $r ) {
        $dist[ (int) $r['rating'] ]++;
    }
    echo '<div class="fh-reviews"><div class="fh-reviews-summary"><div class="fh-avg">' . esc_html( number_format( $avg, 1 ) ) . '</div>' . fh_stars( $avg, 20 )
        . '<p>Based on ' . (int) $count . ' reviews</p></div><div class="fh-reviews-bars">';
    for ( $s = 5; $s >= 1; $s-- ) {
        $pct = $count ? round( 100 * $dist[ $s ] / $count ) : 0;
        echo '<div class="fh-bar"><span>' . $s . ' star</span><i><b style="width:' . (int) $pct . '%"></b></i><span>' . (int) $dist[ $s ] . '</span></div>';
    }
    echo '</div></div><ol class="fh-review-list">';
    foreach ( $reviews as $r ) {
        echo '<li><div class="fh-review-head">' . fh_stars( $r['rating'], 15 ) . '<strong>' . esc_html( $r['author'] ) . '</strong><span class="fh-verified">Verified buyer</span>'
            . '<time>' . esc_html( date_i18n( 'F j, Y', strtotime( $r['date'] ) ) ) . '</time></div><p>' . esc_html( $r['text'] ) . '</p></li>';
    }
    echo '</ol><p class="fh-muted">Only customers who bought this product can leave a review.</p>';
}

/** Free-shipping progress on the cart page. */
add_action( 'woocommerce_before_cart_table', static function () {
    if ( ! WC()->cart ) {
        return;
    }
    $sub  = (float) WC()->cart->get_subtotal();
    $left = FH_FREE_SHIPPING_MIN - $sub;
    $pct  = max( 0, min( 100, 100 * $sub / FH_FREE_SHIPPING_MIN ) );
    echo '<div class="fh-ship-progress"><p>' . ( $left > 0
        ? 'You are <strong>' . wc_price( $left ) . '</strong> away from free shipping.'
        : 'You have unlocked <strong>free shipping</strong>.' )
        . '</p><i><b style="width:' . (int) $pct . '%"></b></i></div>';
} );

/* -------------------------------------------------------- misc front-end */

add_filter( 'excerpt_length', static fn() => 24, 999 );
add_filter( 'excerpt_more', static fn() => '&hellip;' );

// Cookie notice (dismissal remembered in localStorage by fernhill.js).
add_action( 'wp_footer', static function () {
    echo '<div class="fh-cookie" id="fh-cookie" hidden><p>We use cookies to keep your cart, remember your preferences and understand how the site is used. '
        . '<a href="' . esc_url( fh_page_link( 'privacy-policy' ) ) . '">Privacy policy</a></p>'
        . '<button type="button" data-fh-cookie="accept">Accept</button><button type="button" class="fh-ghost" data-fh-cookie="decline">Decline</button></div>';
}, 20 );

add_filter( 'body_class', static function ( $c ) {
    $c[] = 'fh-store';
    return $c;
} );
