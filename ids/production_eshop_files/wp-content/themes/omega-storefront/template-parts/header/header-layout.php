<?php
/**
 * Header Layout -- Fernhill storefront header (replaces the stock Omega header).
 * Data comes from the fernhill-storefront mu-plugin helpers.
 * @package Omega Storefront
 */
$fh_nav   = function_exists( 'fh_primary_nav' ) ? fh_primary_nav() : array();
$fh_shop  = function_exists( 'wc_get_page_permalink' ) ? wc_get_page_permalink( 'shop' ) : home_url( '/shop/' );
$fh_acct  = function_exists( 'wc_get_page_permalink' ) ? wc_get_page_permalink( 'myaccount' ) : '#';
$fh_logo  = function_exists( 'fh_asset' ) ? fh_asset( 'img/logo-dark.png' ) : '';
?>
<div class="fh-announce" role="region" aria-label="Announcements">
    <div class="fh-wrap fh-announce-inner">
        <div class="fh-announce-msgs" data-fh-rotate>
            <span class="is-on">Free shipping on orders over $45</span>
            <span>Roasted Monday &amp; Thursday &middot; shipped within 24 hours</span>
            <span>New: Ethiopia Guji Natural &amp; Kenya Nyeri AA are here</span>
        </div>
        <nav class="fh-announce-links" aria-label="Help">
            <a href="<?php echo esc_url( function_exists( 'fh_page_link' ) ? fh_page_link( 'shipping-returns' ) : '#' ); ?>">Shipping &amp; returns</a>
            <a href="<?php echo esc_url( function_exists( 'fh_page_link' ) ? fh_page_link( 'faq' ) : '#' ); ?>">FAQ</a>
            <a href="<?php echo esc_url( function_exists( 'fh_page_link' ) ? fh_page_link( 'contact' ) : '#' ); ?>">Contact</a>
        </nav>
    </div>
</div>
<header class="fh-header" id="fh-header">
    <div class="fh-wrap fh-header-main">
        <button class="fh-burger" type="button" aria-label="Menu" aria-expanded="false" aria-controls="fh-nav" data-fh-toggle="nav">
            <span></span><span></span><span></span>
        </button>
        <a class="fh-logo" href="<?php echo esc_url( home_url( '/' ) ); ?>" aria-label="<?php bloginfo( 'name' ); ?> home">
            <?php if ( $fh_logo ) : ?><img src="<?php echo esc_url( $fh_logo ); ?>" alt="<?php bloginfo( 'name' ); ?>" width="360" height="90"><?php else : bloginfo( 'name' ); endif; ?>
        </a>
        <nav class="fh-nav" id="fh-nav" aria-label="Primary">
            <ul>
                <li><a href="<?php echo esc_url( $fh_shop ); ?>">Shop all</a></li>
                <?php foreach ( $fh_nav as $item ) : ?>
                    <li><a href="<?php echo esc_url( $item[1] ); ?>"><?php echo esc_html( $item[0] ); ?></a></li>
                <?php endforeach; ?>
            </ul>
        </nav>
        <div class="fh-tools">
            <button class="fh-iconbtn" type="button" aria-label="Search" data-fh-toggle="search">
                <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="11" cy="11" r="6.5"/><path d="M16 16l4.5 4.5"/></svg>
            </button>
            <a class="fh-iconbtn" href="<?php echo esc_url( $fh_acct ); ?>" aria-label="<?php echo is_user_logged_in() ? 'My account' : 'Sign in'; ?>">
                <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="12" cy="8" r="4"/><path d="M4 21c1-4.5 4-6.5 8-6.5s7 2 8 6.5"/></svg>
            </a>
            <?php echo function_exists( 'fh_cart_html' ) ? fh_cart_html() : ''; // phpcs:ignore ?>
        </div>
    </div>
    <div class="fh-search" id="fh-search" hidden>
        <div class="fh-wrap">
            <form role="search" method="get" action="<?php echo esc_url( home_url( '/' ) ); ?>">
                <input type="hidden" name="post_type" value="product">
                <label class="screen-reader-text" for="fh-search-input">Search products</label>
                <input id="fh-search-input" type="search" name="s" placeholder="Search coffee, brewers, mugs&hellip;" value="<?php echo esc_attr( get_search_query() ); ?>">
                <button type="submit">Search</button>
            </form>
        </div>
    </div>
</header>
