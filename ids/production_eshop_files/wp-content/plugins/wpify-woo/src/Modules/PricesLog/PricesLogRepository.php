<?php

namespace WpifyWoo\Modules\PricesLog;


defined( 'ABSPATH' ) || exit;

use WpifyWooDeps\Wpify\Model\CustomTableRepository;

/**
 * @method PricesLogModel[] find( array $args = array() )
 * @method PricesLogModel create()
 */
class PricesLogRepository extends CustomTableRepository {
	public function table_name(): string {
		return 'prices_log';
	}

	public function model(): string {
		return PricesLogModel::class;
	}


	public function find_by_product_id( $product_id ): array {
		return $this->find( [
			'where' => [
				'product_id' => $product_id,
			],
		] );
	}

	public function get_last_by_product_id( $product_id ): ?PricesLogModel {
		$items = $this->find( [
			'where'    => [
				'product_id' => $product_id,
			],
			'order_by' => 'created_at DESC',
		] );


		return $items[0] ?? null;
	}

	public function find_lowest_price( $product_id ) {
		if ( ! $product_id ) {
			return null;
		}
		$prices = [];
		foreach ( $this->find_by_product_id( $product_id ) as $item ) {
			if ( strtotime( $item->created_at ) < strtotime( '-30 days' ) ) {
				continue;
			}
			$prices[] = $item->sale_price ?: $item->regular_price;
		}

		if ( empty( $prices ) ) {
			return null;
		}

		return min( $prices );
	}
}
