<?php

namespace WpifyWoo\Managers;

defined( 'ABSPATH' ) || exit;

use WpifyWoo\Modules\PricesLog\PricesLogRepository;
use WpifyWoo\Modules\HeurekaOverenoZakazniky\HeurekaReviewRepository;
use WpifyWoo\Modules\WithdrawalClaims\WithdrawalClaimsRepository;
use WpifyWoo\Plugin;
use WpifyWoo\Repositories\WooOrderRepository;
use WpifyWooDeps\Wpify\Model\Manager;

/**
 * Class RepositoriesManager
 *
 * @package Wpify\Managers
 * @property Plugin $plugin
 */
class RepositoriesManager {
    public function __construct(
        Manager $manager,
        WooOrderRepository $woo_order_repository,
        PricesLogRepository $prices_log_repository,
        HeurekaReviewRepository $heureka_review_repository,
        WithdrawalClaimsRepository $withdrawal_claims_repository
    ) {
        $manager->register_repository( $woo_order_repository );
        $manager->register_repository( $prices_log_repository );
        $manager->register_repository( $heureka_review_repository );
        $manager->register_repository( $withdrawal_claims_repository );
    }
}
