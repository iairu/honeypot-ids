<?php

namespace WpifyWoo\Modules\HeurekaOverenoZakazniky;

defined( 'ABSPATH' ) || exit;

use WpifyWooDeps\Wpify\Model\CustomTableRepository;

/**
 * @method HeurekaReviewModel[] find( array $args = array() )
 * @method HeurekaReviewModel create()
 */
class HeurekaReviewRepository extends CustomTableRepository {
    public function table_name(): string {
        return 'heureka_reviews';
    }

    public function model(): string {
        return HeurekaReviewModel::class;
    }

    public function find_one_by_rating_id( int $rating_id ): ?HeurekaReviewModel {
        $items = $this->find([
            'where' => [ 'rating_id' => $rating_id ],
            'limit' => 1,
        ]);
        return $items[0] ?? null;
    }

    /**
     * Get latest reviews ordered by unix_timestamp DESC
     * @param int $limit
     * @return HeurekaReviewModel[]
     */
    public function find_latest( int $limit = 10 ): array {
        return $this->find([
            'order_by' => 'unix_timestamp DESC',
            'limit'    => $limit,
        ]);
    }
}

