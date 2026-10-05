<?php
/**
 * seed_storefront_content.php -- authors the Fernhill Coffee Roasters catalog,
 * pages and journal posts. Run by seed_wordpress_db.sh via `wp eval-file`, on
 * production only (IMPORT_SAMPLE_CONTENT=1); honeypot pools get the same rows
 * from honeypot_content_sync.
 *
 * Reads /eshop_seed (catalog.json + images; built by eshop_seed/build_assets.py).
 * Idempotent: bails out when the stored catalog version is current, and keys
 * every post on its slug, so a re-run updates instead of duplicating.
 *
 * Only data that honeypot_content_sync replicates (posts, postmeta, terms,
 * attachments) is used for anything a visitor sees. Reviews live in postmeta
 * (_fh_reviews) rather than comments, menus are hardcoded in the theme, and
 * presentation settings come from the storefront mu-plugin's option filters --
 * comments, nav-menu items, options and term meta are NOT replicated.
 */
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

const FH_CATALOG_VERSION = 2;
$dir = '/eshop_seed';

if ( ! is_readable( "$dir/catalog.json" ) ) {
    WP_CLI::warning( 'catalog.json not found -- skipping storefront content.' );
    return;
}
if ( (int) get_option( 'fernhill_catalog_version' ) >= FH_CATALOG_VERSION && ! getenv( 'FORCE_CATALOG' ) ) {
    WP_CLI::log( '  Storefront catalog already at version ' . FH_CATALOG_VERSION . '.' );
    return;
}

require_once ABSPATH . 'wp-admin/includes/file.php';
require_once ABSPATH . 'wp-admin/includes/media.php';
require_once ABSPATH . 'wp-admin/includes/image.php';

$data = json_decode( file_get_contents( "$dir/catalog.json" ), true );
WP_CLI::log( '  Authoring ' . count( $data['products'] ) . ' products...' );

// --- clean out the stock WordPress / WooCommerce sample content -------------
$keep = array_column( $data['products'], 'slug' );
foreach ( get_posts( [ 'post_type' => [ 'product', 'product_variation' ], 'numberposts' => -1, 'post_status' => 'any', 'fields' => 'ids' ] ) as $pid ) {
    $slug = get_post_field( 'post_name', $pid );
    if ( get_post_type( $pid ) === 'product' && in_array( $slug, $keep, true ) ) {
        continue;
    }
    if ( get_post_type( $pid ) === 'product_variation' && in_array( get_post_field( 'post_name', wp_get_post_parent_id( $pid ) ), $keep, true ) ) {
        continue;
    }
    wp_delete_post( $pid, true );
}
foreach ( [ 'hello-world' => 'post', 'sample-page' => 'page' ] as $slug => $type ) {
    $p = get_page_by_path( $slug, OBJECT, $type );
    if ( $p ) {
        wp_delete_post( $p->ID, true );
    }
}
foreach ( get_comments( [ 'status' => 'all', 'number' => 200 ] ) as $c ) {
    wp_delete_comment( $c->comment_ID, true );
}

// --- helpers ---------------------------------------------------------------
$sideload = function ( $file, $title, $post_id = 0 ) {
    if ( ! is_readable( $file ) ) {
        return 0;
    }
    $existing = get_posts( [ 'post_type' => 'attachment', 'name' => sanitize_title( $title ), 'numberposts' => 1, 'fields' => 'ids' ] );
    if ( $existing ) {
        return (int) $existing[0];
    }
    $tmp = wp_tempnam( basename( $file ) );
    copy( $file, $tmp );
    $id = media_handle_sideload( [ 'name' => basename( $file ), 'tmp_name' => $tmp ], $post_id, $title );
    if ( is_wp_error( $id ) ) {
        @unlink( $tmp );
        WP_CLI::warning( "  image $file: " . $id->get_error_message() );
        return 0;
    }
    update_post_meta( $id, '_wp_attachment_image_alt', $title );
    return (int) $id;
};

// --- categories -------------------------------------------------------------
$cat_ids = [];
foreach ( $data['categories'] as $c ) {
    $t = term_exists( $c['slug'], 'product_cat' );
    if ( ! $t ) {
        $t = wp_insert_term( $c['name'], 'product_cat', [ 'slug' => $c['slug'], 'description' => $c['description'] ] );
    } else {
        wp_update_term( $t['term_id'], 'product_cat', [ 'name' => $c['name'], 'description' => $c['description'] ] );
    }
    $cat_ids[ $c['slug'] ] = is_wp_error( $t ) ? 0 : (int) $t['term_id'];
}
// Drop every other product category (the stock sample ones, Uncategorized, ...).
$wanted = array_column( $data['categories'], 'slug' );
foreach ( get_terms( [ 'taxonomy' => 'product_cat', 'hide_empty' => false, 'fields' => 'all' ] ) as $term ) {
    if ( ! in_array( $term->slug, $wanted, true ) && (int) get_option( 'default_product_cat' ) !== (int) $term->term_id ) {
        wp_delete_term( $term->term_id, 'product_cat' );
    }
}

// --- products ---------------------------------------------------------------
$menu_order = 0;
foreach ( $data['products'] as $p ) {
    $existing = get_page_by_path( $p['slug'], OBJECT, 'product' );
    $variable = $p['type'] === 'variable';
    $product  = $existing ? wc_get_product( $existing->ID ) : ( $variable ? new WC_Product_Variable() : new WC_Product_Simple() );
    if ( $existing && ( $product->is_type( 'variable' ) !== $variable ) ) {
        wp_delete_post( $existing->ID, true );
        $product = $variable ? new WC_Product_Variable() : new WC_Product_Simple();
    }

    $product->set_name( $p['name'] );
    $product->set_slug( $p['slug'] );
    $product->set_status( 'publish' );
    $product->set_catalog_visibility( 'visible' );
    $product->set_short_description( $p['short'] );
    $product->set_description( $p['long'] );
    $product->set_sku( $p['sku'] );
    $product->set_manage_stock( true );
    $product->set_stock_quantity( (int) $p['stock'] );
    $product->set_stock_status( 'instock' );
    $product->set_weight( (string) $p['weight'] );
    $product->set_length( (string) $p['dims'][0] );
    $product->set_width( (string) $p['dims'][1] );
    $product->set_height( (string) $p['dims'][2] );
    $product->set_featured( ! empty( $p['featured'] ) );
    $product->set_category_ids( [ $cat_ids[ $p['category'] ] ] );
    $product->set_total_sales( (int) $p['sold'] );
    $product->set_menu_order( ++$menu_order );
    if ( ! $variable ) {
        $product->set_regular_price( (string) $p['price'] );
        $product->set_sale_price( isset( $p['sale'] ) ? (string) $p['sale'] : '' );
    }

    // Attributes: informational ones (Origin, Roast, ...) plus the variation ones.
    $attrs = [];
    $pos   = 0;
    foreach ( $p['attrs'] as $name => $value ) {
        $a = new WC_Product_Attribute();
        $a->set_name( $name );
        $a->set_options( [ $value ] );
        $a->set_position( $pos++ );
        $a->set_visible( true );
        $a->set_variation( false );
        $attrs[] = $a;
    }
    $variation_sets = [];
    if ( $variable && isset( $p['bag_prices'] ) ) {
        $variation_sets['Bag size'] = array_keys( $p['bag_prices'] );
        $variation_sets['Grind']    = $p['grinds'];
    } elseif ( $variable && isset( $p['variants'] ) ) {
        foreach ( $p['variants'] as $vname => $opts ) {
            $variation_sets[ $vname ] = array_keys( $opts );
        }
    }
    foreach ( $variation_sets as $name => $opts ) {
        $a = new WC_Product_Attribute();
        $a->set_name( $name );
        $a->set_options( $opts );
        $a->set_position( $pos++ );
        $a->set_visible( true );
        $a->set_variation( true );
        $attrs[] = $a;
    }
    $product->set_attributes( $attrs );

    $img  = $sideload( "$dir/products/{$p['slug']}.jpg", $p['name'], 0 );
    $img2 = $sideload( "$dir/products/{$p['slug']}-2.jpg", $p['name'] . ' (detail)', 0 );
    if ( $img ) {
        $product->set_image_id( $img );
    }
    if ( $img2 ) {
        $product->set_gallery_image_ids( [ $img2 ] );
    }

    // Reviews: rating summary on the product, texts in postmeta (see header).
    $reviews = $p['reviews'];
    $counts  = [];
    foreach ( $reviews as $r ) {
        $counts[ $r['rating'] ] = ( $counts[ $r['rating'] ] ?? 0 ) + 1;
    }
    $product->set_rating_counts( $counts );
    $product->set_review_count( count( $reviews ) );
    $product->set_average_rating( $reviews ? round( array_sum( array_column( $reviews, 'rating' ) ) / count( $reviews ), 2 ) : 0 );

    $id = $product->save();

    wp_set_object_terms( $id, $p['tags'], 'product_tag' );
    update_post_meta( $id, '_fh_reviews', wp_slash( wp_json_encode( $reviews ) ) );
    update_post_meta( $id, '_fh_badge', $p['badge'] );
    if ( ! empty( $p['brew'] ) ) {
        update_post_meta( $id, '_fh_brew', $p['brew'] );
    }

    // Variations.
    if ( $variable ) {
        $product = wc_get_product( $id );
        foreach ( $product->get_children() as $child ) {
            wp_delete_post( $child, true );
        }
        $combos = [ [] ];
        foreach ( $variation_sets as $name => $opts ) {
            $next = [];
            foreach ( $combos as $combo ) {
                foreach ( $opts as $o ) {
                    $next[] = $combo + [ sanitize_title( $name ) => $o ];
                }
            }
            $combos = $next;
        }
        foreach ( $combos as $combo ) {
            $v = new WC_Product_Variation();
            $v->set_parent_id( $id );
            $v->set_attributes( $combo );
            $price = $p['price'];
            if ( isset( $p['bag_prices'][ $combo['bag-size'] ?? '' ] ) ) {
                $price = $p['bag_prices'][ $combo['bag-size'] ];
                if ( ( $combo['grind'] ?? '' ) === 'Espresso' ) {
                    $price += 0;
                }
            }
            $v->set_regular_price( (string) $price );
            $v->set_manage_stock( false );
            $v->set_stock_status( 'instock' );
            $v->set_status( 'publish' );
            $v->save();
        }
        WC_Product_Variable::sync( $id );
        wc_delete_product_transients( $id );
    }
}

// --- pages ------------------------------------------------------------------
$page = function ( $slug, $title, $content, $parent = 0 ) {
    $existing = get_page_by_path( $slug );
    $args     = [ 'post_type' => 'page', 'post_status' => 'publish', 'post_title' => $title, 'post_name' => $slug,
                  'post_content' => $content, 'post_parent' => $parent, 'comment_status' => 'closed' ];
    if ( $existing ) {
        $args['ID'] = $existing->ID;
        wp_update_post( $args );
        return $existing->ID;
    }
    return wp_insert_post( $args );
};

$pages = require '/eshop_seed/pages.php';
$ids = [];
foreach ( $pages as $slug => $pg ) {
    $ids[ $slug ] = $page( $slug, $pg['title'], $pg['content'] );
}
update_option( 'show_on_front', 'page' );
update_option( 'page_on_front', $ids['home'] );
update_option( 'page_for_posts', $ids['journal'] );
update_option( 'wp_page_for_privacy_policy', $ids['privacy-policy'] );
foreach ( [ 'home' ] as $slug ) {
    delete_post_meta( $ids[ $slug ], '_elementor_edit_mode' );
    delete_post_meta( $ids[ $slug ], '_elementor_data' );
}

// --- journal posts ----------------------------------------------------------
$posts = require '/eshop_seed/journal.php';
$cat_j = [];
foreach ( [ 'Guides', 'Behind the Roast', 'Origins' ] as $name ) {
    $t = term_exists( $name, 'category' );
    $cat_j[ $name ] = $t ? (int) $t['term_id'] : (int) wp_insert_term( $name, 'category' )['term_id'];
}
foreach ( $posts as $post ) {
    $existing = get_page_by_path( $post['slug'], OBJECT, 'post' );
    $args     = [ 'post_type' => 'post', 'post_status' => 'publish', 'post_title' => $post['title'], 'post_name' => $post['slug'],
                  'post_content' => $post['content'], 'post_excerpt' => $post['excerpt'], 'post_date' => $post['date'],
                  'post_category' => [ $cat_j[ $post['category'] ] ], 'comment_status' => 'closed' ];
    if ( $existing ) {
        $args['ID'] = $existing->ID;
    }
    $pid = $existing ? wp_update_post( $args ) : wp_insert_post( $args );
    $att = $sideload( "$dir/site/{$post['image']}", $post['title'], $pid );
    if ( $att ) {
        set_post_thumbnail( $pid, $att );
    }
}
$uncategorized = get_term_by( 'slug', 'uncategorized', 'category' );
if ( $uncategorized && (int) get_option( 'default_category' ) !== $uncategorized->term_id ) {
    wp_delete_term( $uncategorized->term_id, 'category' );
}

flush_rewrite_rules();
update_option( 'fernhill_catalog_version', FH_CATALOG_VERSION );
WP_CLI::success( 'Storefront catalog v' . FH_CATALOG_VERSION . ' authored.' );
