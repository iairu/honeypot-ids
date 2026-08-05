<?php

namespace WpifyWoo\Modules\SklikRetargeting;

defined( 'ABSPATH' ) || exit;

use WC_Product;
use WC_Product_Variable;
use WC_Product_Variation;
use WpifyWooFeeds\Feeds\Zbozi\ProductFeed as ZboziProductFeed;

/**
 * Bridge mezi wpify-woo-feeds (SSOT pro `_Q_` combo IDs) a SklikRetargeting modulem.
 *
 * Nikde negeneruje ID samostatně — jen adaptuje to, co vrací
 * VariationCombinationsTrait, do JS-friendly payloadu pro Sklik retargeting.
 *
 * ID matrix:
 *  - feeds plugin aktivní + expanze ON + variace s "any" attrs → `_Q_{vid}_…`
 *  - feeds plugin aktivní + expanze ON + variace bez "any"     → `variation_id` (single_combination fallback)
 *  - feeds plugin aktivní + expanze OFF                         → `variation_id`
 *  - bez feeds pluginu                                          → `variation_id`
 *  - `custom_item_id` meta key nastavený                        → hodnota meta (fallback path)
 */
class CombinationDataBuilder {

	/**
	 * Mapa `variation_id => [{id, slug_attrs:{tax:slug}}]` pro variable product.
	 * Vždy emituje min. 1 entry per variace.
	 *
	 * @return array<int, array<int, array{id:string, slug_attrs:array<string,string>}>>
	 */
	public function build_variation_combo_map(
		WC_Product_Variable $parent,
		?string $custom_item_id_meta = null
	): array {
		$feed   = $this->get_feed();
		$expand = $feed && $feed->is_combination_expansion_enabled();

		$map = array();
		foreach ( $parent->get_children() as $child_id ) {
			$variation = wc_get_product( $child_id );
			if ( ! $variation instanceof WC_Product_Variation ) {
				continue;
			}

			$fallback_id = $this->resolve_fallback_id( $variation, $custom_item_id_meta );

			if ( $expand ) {
				$combos = $feed->expand_variation_combinations( $variation, $parent, $fallback_id );
			} else {
				$combos = array(
					array(
						'id'         => $fallback_id,
						'attributes' => array(),
					),
				);
			}

			$map[ (int) $child_id ] = array_map(
				fn( array $c ): array => array(
					'id'         => (string) $c['id'],
					'slug_attrs' => $this->resolve_attribute_slugs( $c['attributes'] ?? array() ),
				),
				$combos
			);
		}

		return $map;
	}

	/**
	 * Canonical initial fallback — první combo první variace.
	 *
	 * @param array<int, array<int, array{id:string, slug_attrs:array<string,string>}>> $map
	 */
	public function resolve_initial_combo_id( array $map ): ?string {
		foreach ( $map as $combos ) {
			foreach ( $combos as $combo ) {
				if ( ! empty( $combo['id'] ) ) {
					return (string) $combo['id'];
				}
			}
		}
		return null;
	}

	private function get_feed(): ?ZboziProductFeed {
		if ( ! function_exists( 'wpify_woo_feeds_container' ) ) {
			return null;
		}
		if ( ! class_exists( ZboziProductFeed::class ) ) {
			return null;
		}
		try {
			$feed = wpify_woo_feeds_container()->get( ZboziProductFeed::class );
			return $feed instanceof ZboziProductFeed ? $feed : null;
		} catch ( \Throwable $e ) {
			return null;
		}
	}

	private function resolve_fallback_id( WC_Product $product, ?string $meta_key ): string {
		if ( $meta_key ) {
			$meta = $product->get_meta( $meta_key );
			if ( $meta ) {
				return (string) $meta;
			}
		}
		return (string) $product->get_id();
	}

	/**
	 * Převede `attr_id => term_id` na `taxonomy => term_slug` (= co `.variations select` má jako value).
	 *
	 * @param array<int, int> $attributes
	 * @return array<string, string>
	 */
	private function resolve_attribute_slugs( array $attributes ): array {
		$out = array();
		foreach ( $attributes as $attr_id => $term_id ) {
			$taxonomy = wc_attribute_taxonomy_name_by_id( (int) $attr_id );
			if ( ! $taxonomy ) {
				continue;
			}
			$term = get_term_by( 'id', (int) $term_id, $taxonomy );
			if ( ! $term ) {
				continue;
			}
			$out[ $taxonomy ] = (string) $term->slug;
		}
		return $out;
	}
}
