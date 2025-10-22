<?php
/**
 * Omega Storefront Dynamic Styles
 *
 * @package Omega Storefront
 */

// Enqueue the main stylesheet
function omega_storefront_enqueue_styles() {
    // Replace 'your-main-stylesheet-handle' with your actual stylesheet handle
    wp_enqueue_style('omega-storefront-style', get_stylesheet_uri());
}
add_action('wp_enqueue_scripts', 'omega_storefront_enqueue_styles');

// Function to add dynamic CSS
function omega_storefront_dynamic_css() {
    // Get default theme options
    $omega_storefront_default = omega_storefront_get_default_theme_options();

    // Sanitize and get theme customizations
    $omega_storefront_default_text_color = esc_attr(get_theme_mod('omega_storefront_default_text_color', '')); // Default value if needed
    $omega_storefront_logo_width_range = absint(get_theme_mod('omega_storefront_logo_width_range', $omega_storefront_default['omega_storefront_logo_width_range']));
    $omega_storefront_breadcrumb_font_size = absint(get_theme_mod('omega_storefront_breadcrumb_font_size', $omega_storefront_default['omega_storefront_breadcrumb_font_size']));
    $omega_storefront_menu_font_size = absint(get_theme_mod('omega_storefront_menu_font_size', $omega_storefront_default['omega_storefront_menu_font_size']));
    $omega_storefront_border_color = esc_attr(get_theme_mod('omega_storefront_border_color', '')); // Default value if needed
    $omega_storefront_background_color = '#' . ltrim(esc_attr(get_theme_mod('background_color', $omega_storefront_default['omega_storefront_background_color'])), '#');

    // Create dynamic CSS
    $omega_storefront_dynamic_css = "
        body,
        .offcanvas-wraper,
        .header-searchbar-inner {
            background-color: {$omega_storefront_background_color};
        }

        a:not(:hover):not(:focus):not(.btn-fancy),
        body, button, input, select, optgroup, textarea {
            color: {$omega_storefront_default_text_color};
        }

        .site-topbar, .site-navigation,
        .offcanvas-main-navigation li,
        .offcanvas-main-navigation .sub-menu,
        .offcanvas-main-navigation .submenu-wrapper .submenu-toggle,
        .post-navigation,
        .widget .tab-head .twp-nav-tabs,
        .widget-area-wrapper .widget,
        .footer-widgetarea,
        .site-info,
        .right-sidebar .widget-area-wrapper,
        .left-sidebar .widget-area-wrapper,
        .widget-title,
        .widget_block .wp-block-group > .wp-block-group__inner-container > h2,
        input[type='text'],
        input[type='password'],
        input[type='email'],
        input[type='url'],
        input[type='date'],
        input[type='month'],
        input[type='time'],
        input[type='datetime'],
        input[type='datetime-local'],
        input[type='week'],
        input[type='number'],
        input[type='search'],
        input[type='tel'],
        input[type='color'],
        textarea {
            border-color: {$omega_storefront_border_color};
        }

        .site-logo .custom-logo-link img{
            width: {$omega_storefront_logo_width_range}px;
            object-fit: object-fit  ;
        }

        .site-navigation .primary-menu > li a {
            font-size: {$omega_storefront_menu_font_size}px;
        }

        .breadcrumbs,.woocommerce-breadcrumb {
            font-size: {$omega_storefront_breadcrumb_font_size}px !important;
        }
    ";

    // Add inline styles to the main stylesheet
    wp_add_inline_style('omega-storefront-style', $omega_storefront_dynamic_css); // Replace with your actual stylesheet handle
}

add_action('wp_enqueue_scripts', 'omega_storefront_dynamic_css');