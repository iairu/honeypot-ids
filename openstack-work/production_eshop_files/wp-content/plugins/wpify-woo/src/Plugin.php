<?php

namespace WpifyWoo;

defined( 'ABSPATH' ) || exit;

use WpifyWoo\Admin\Settings;
use WpifyWoo\Managers\ApiManager;
use WpifyWoo\Managers\ModulesManager;
use WpifyWoo\Managers\PostTypesManager;
use WpifyWoo\Managers\RepositoriesManager;
use WpifyWooDeps\Wpify\Asset\AssetFactory;
use WpifyWooDeps\Wpify\CustomFields\CustomFields;
use WpifyWooDeps\Wpify\PluginUtils\PluginUtils;
use WpifyWooDeps\Wpify\WooCore\Abstracts\AbstractPlugin;
use WpifyWooDeps\Wpify\WooCore\WpifyWooCore;

/**
 * Class Plugin
 *
 * @package Wpify
 */
class Plugin extends AbstractPlugin {
	protected bool $requires_activation = false;

	/** Plugin version */
	public const VERSION = '5.4.18';

	/** Plugin slug name */
	public const PLUGIN_SLUG = 'wpify-woo';

	/** Plugin namespace */
	public const PLUGIN_NAMESPACE = '\\' . __NAMESPACE__;

	/**
	 * Plugin constructor.
	 *
	 * @param Admin               $admin
	 * @param RepositoriesManager $repositories_manager
	 * @param ApiManager          $api_manager
	 * @param PostTypesManager    $post_types_manager
	 * @param ModulesManager      $modules_manager
	 * @param CustomFields        $wcf
	 * @param AssetFactory        $asset_factory
	 * @param WpifyWooCore        $wpify_woo_core
	 * @param PluginUtils         $plugin_utils
	 * @param Settings            $settings
	 */
	public function __construct(
		Admin $admin,
		RepositoriesManager $repositories_manager,
		ApiManager $api_manager,
		PostTypesManager $post_types_manager,
		ModulesManager $modules_manager,
		CustomFields $wcf,
		AssetFactory $asset_factory,
		WpifyWooCore $wpify_woo_core,
		PluginUtils $plugin_utils,
		Settings $settings
	) {
		parent::__construct( $wpify_woo_core, $plugin_utils );

	}

	/**
	 * Plugin documentation path
	 *
	 * @return string
	 */
	public function get_documentation_path(): string {
		return 'wpify-woo';
	}

	/**
	 * Plugin support url
	 *
	 * @return string
	 */
	public function support_url(): string {
		return 'https://wordpress.org/support/plugin/wpify-woo/';
	}

	/**
	 * Plugin activation and upgrade
	 *
	 * @param $network_wide
	 *
	 * @return void
	 */
	public function activate( $network_wide ) {
	}

	/**
	 * Plugin de-activation
	 *
	 * @param $network_wide
	 *
	 * @return void
	 */
	public function deactivate( $network_wide ) {
	}

	/**
	 * Plugin uninstall
	 *
	 * @return void
	 */
	public function uninstall() {
	}
}
