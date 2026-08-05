<?php

namespace WpifyWoo\Repositories;

defined( 'ABSPATH' ) || exit;

use WpifyWoo\Models\WooOrderModel;
use WpifyWoo\Plugin;
use WpifyWoo\PostTypes\WooOrderPostType;
use WpifyWooDeps\Wpify\Model\OrderRepository;

/**
 * @property Plugin $plugin
 */
class WooOrderRepository extends OrderRepository {
	public function model(): string {
		return WooOrderModel::class;
	}
}
