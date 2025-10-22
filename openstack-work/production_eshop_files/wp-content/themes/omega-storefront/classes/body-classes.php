<?php
/**
 * Body Classes.
 * @package Omega Storefront
 */

if (!function_exists('omega_storefront_body_classes')) :

    function omega_storefront_body_classes($omega_storefront_classes)
    {
        $omega_storefront_defaults = omega_storefront_get_default_theme_options();
        $omega_storefront_layout = omega_storefront_get_final_sidebar_layout();

        // Adds a class of hfeed to non-singular pages.
        if (!is_singular()) {
            $omega_storefront_classes[] = 'hfeed';
        }

        // Sidebar layout logic
        $omega_storefront_classes[] = $omega_storefront_layout;

        // Copyright alignment
        $copyright_alignment = get_theme_mod('omega_storefront_copyright_alignment', 'Default');
        $omega_storefront_classes[] = 'copyright-' . strtolower($copyright_alignment);

        return $omega_storefront_classes;
    }

endif;

add_filter('body_class', 'omega_storefront_body_classes');