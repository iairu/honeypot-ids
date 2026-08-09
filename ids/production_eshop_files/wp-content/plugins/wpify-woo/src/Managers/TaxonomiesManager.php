<?php

namespace WpifyWoo\Managers;

defined( 'ABSPATH' ) || exit;

use WpifyWoo\Plugin;
use WpifyWooDeps\Wpify\Core\Abstracts\AbstractManager;

/**
 * Class CptManager
 *
 * @package Wpify\Managers
 * @property Plugin $plugin
 */
class TaxonomiesManager extends AbstractManager {
	protected $modules = array();
}
