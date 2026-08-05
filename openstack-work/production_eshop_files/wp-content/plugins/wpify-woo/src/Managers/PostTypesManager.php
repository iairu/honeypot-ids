<?php

namespace WpifyWoo\Managers;

defined( 'ABSPATH' ) || exit;

use WpifyWoo\Plugin;
use WpifyWoo\PostTypes\WooOrderPostType;

/**
 * Class CptManager
 *
 * @package Wpify\Managers
 * @property Plugin $plugin
 */
class PostTypesManager  {
	public function __construct(
		WooOrderPostType $order_post_type,
	) {
	}
}
