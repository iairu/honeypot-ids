#!/bin/sh
# seed_elementor_pages.sh - Authors two Elementor-built pages (a homepage
# hero + an "About Us" page) for the demo storefront. Called from
# seed_production_db.sh, which handles idempotency/FORCE_RESEED at the
# WordPress-install level -- this script just runs once per fresh
# install, same as everything else it's called alongside.
#
# Builds the Elementor element tree as native PHP arrays inside a single
# `wp eval` call and json_encode()'s it from there, rather than trying to
# shell-quote a large JSON blob into a `wp post meta update` command-line
# argument -- avoids an entire class of quoting bugs for comparatively
# complex, nested data.
set -eu

WP="wp --allow-root --path=/var/www/html"

$WP eval '
$home_id = wp_insert_post([
    "post_title"   => "Home",
    "post_status"  => "publish",
    "post_type"    => "page",
    "post_content" => "",
]);

# Homepage is intentionally left with no Elementor hero: the demo storefront
# shows the product grid directly on the homepage (injected by the
# storefront-frontend-improvements must-use plugin), rather than a
# "Welcome to the Store" hero banner.
$home_elements = [];

update_post_meta($home_id, "_elementor_data", wp_slash(json_encode($home_elements)));
update_post_meta($home_id, "_elementor_edit_mode", "builder");
update_post_meta($home_id, "_elementor_template_type", "wp-page");
update_post_meta($home_id, "_elementor_version", ELEMENTOR_VERSION);

update_option("show_on_front", "page");
update_option("page_on_front", $home_id);

$about_id = wp_insert_post([
    "post_title"   => "About Us",
    "post_status"  => "publish",
    "post_type"    => "page",
    "post_content" => "",
]);

$about_elements = [[
    "id" => "abouts001",
    "elType" => "section",
    "settings" => ["layout" => "boxed"],
    "elements" => [[
        "id" => "aboutcol01",
        "elType" => "column",
        "settings" => ["_column_size" => 100],
        "elements" => [
            [
                "id" => "abouthead1",
                "elType" => "widget",
                "widgetType" => "heading",
                "settings" => ["title" => "About Us", "size" => "large"],
                "elements" => [],
            ],
            [
                "id" => "abouttext1",
                "elType" => "widget",
                "widgetType" => "text-editor",
                "settings" => ["editor" => "<p>We have been serving customers since day one, offering a hand-picked catalog of everyday essentials.</p>"],
                "elements" => [],
            ],
        ],
        "isInner" => false,
    ]],
    "isInner" => false,
]];

update_post_meta($about_id, "_elementor_data", wp_slash(json_encode($about_elements)));
update_post_meta($about_id, "_elementor_edit_mode", "builder");
update_post_meta($about_id, "_elementor_template_type", "wp-page");
update_post_meta($about_id, "_elementor_version", ELEMENTOR_VERSION);

echo "home_id={$home_id} about_id={$about_id}" . PHP_EOL;
'
