<?php


defined( 'ABSPATH' ) || exit;

use WpifyWooDeps\DI\Definition\Helper\CreateDefinitionHelper;
use WpifyWooDeps\Wpify\CustomFields\CustomFields;
use WpifyWooDeps\Wpify\Log\RotatingFileLog;
use WpifyWooDeps\Wpify\Model\Manager;
use WpifyWooDeps\Wpify\PluginUtils\PluginUtils;

return array(
	CustomFields::class    => ( new CreateDefinitionHelper() )
		->constructor( plugins_url( 'vendor/wpify-woo/wpify/custom-fields', __FILE__ ) ),
	PluginUtils::class     => ( new CreateDefinitionHelper() )
		->constructor( __DIR__ . '/wpify-woo.php' ),
	Manager::class         => ( new CreateDefinitionHelper() )
		->constructor( [] ),
	RotatingFileLog::class => ( new CreateDefinitionHelper() )
		->constructor( 'wpify-woo', '', null, [ 'parent_slug' => 'wpify' ] ),
);
