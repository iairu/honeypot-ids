<?php

namespace WpifyWoo\PostTypes;

defined( 'ABSPATH' ) || exit;

use WpifyWoo\Factories\WooOrderFieldsFactory;
use WpifyWoo\Models\WooOrderModel;
use WpifyWoo\Plugin;
use WpifyWooDeps\Wpify\Core\Abstracts\AbstractPostType;

/**
 * Class BookPostType
 *
 * @package WpifyPlugin\Cpt
 * @property Plugin $plugin
 */
class WooOrderPostType {
	public const NAME = 'shop_order';
	protected $register_cpt = false;

	public function __construct(  ) {

	}
	public function post_type_args(): array {
		return array();
	}

	public function post_type_name(): string {
		return $this::NAME;
	}

	public function model(): string {
		return WooOrderModel::class;
	}
}
