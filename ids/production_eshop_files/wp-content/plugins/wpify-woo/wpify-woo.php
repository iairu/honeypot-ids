<?php // phpcs:disable PSR1.Files.SideEffects.FoundWithSymbols

defined( 'ABSPATH' ) || exit;

/*
 * Plugin Name: WPify Woo
 * Description: Custom functionality for WooCommerce
 * Version: 5.4.18
 * Requires PHP: 8.1
 * Requires at least: 6.2
 * Author: WPify s.r.o.
 * Author URI: https://www.wpify.io/
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: wpify-woo
 * Domain Path: /languages
 * WC requires at least: 7.0
 * WC tested up to: 10.6
 * Requires Plugins: woocommerce
 * Tested up to: 7.0
*/

use Automattic\WooCommerce\Utilities\FeaturesUtil;
use WpifyWoo\Plugin;
use WpifyWooDeps\DI;

if ( ! defined( 'WPIFY_WOO_MIN_PHP_VERSION' ) ) {
	define( 'WPIFY_WOO_MIN_PHP_VERSION', '8.1.0' );
}

/**
 * Singleton instance function. We will not use a global at all as that defeats the purpose of a singleton
 * and is a bad design overall
 * @SuppressWarnings(PHPMD.StaticAccess)
 * @return WpifyWoo\Plugin
 * @throws Exception
 */
function wpify_woo(): Plugin {
	return wpify_woo_container()->get( Plugin::class );
}

/**
 * This container singleton enables you to setup unit testing by passing an environment file to map classes in Dice
 *
 * @param string $env
 *
 * @return DI\Container
 * @throws Exception
 */
function wpify_woo_container(): DI\Container {
	static $container;

	if ( empty( $container ) ) {
		$definition       = require_once __DIR__ . '/config.php';
		$containerBuilder = new DI\ContainerBuilder();
		$containerBuilder->addDefinitions( $definition );
		$container = $containerBuilder->build();
	}

	return $container;
}

/**
 * Init function shortcut
 */
function wpify_woo_init() {
	wpify_woo();
}

/**
 * Activate function shortcut
 */
function wpify_woo_activate( $network_wide ) {
	register_uninstall_hook( __FILE__, 'wpify_woo_uninstall' );
	wpify_woo()->activate( $network_wide );
}

/**
 * Deactivate function shortcut
 */
function wpify_woo_deactivate( $network_wide ) {
	wpify_woo()->deactivate( $network_wide );
}

/**
 * Uninstall function shortcut
 */
function wpify_woo_uninstall() {
	wpify_woo()->uninstall();
}

/**
 * Error for older php
 */
function wpify_woo_php_upgrade_notice() {
	$info = get_plugin_data( __FILE__ );
	$string = sprintf(
		/* translators: 1: Plugin name, 2: Minimal required PHP version, 3: current PHP version. */
		esc_html__( 'Opps! %1$s requires a minimum PHP version of %2$s. Your current version is: %3$s. Please contact your host to upgrade.', 'wpify-woo' ),
		$info['Name'],
		WPIFY_WOO_MIN_PHP_VERSION,
		PHP_VERSION
	);
	?>
	<div class="error notice">
		<p><?php echo esc_html( $string ); ?></p>
	</div>
	<?php
}

/**
 * Error if vendors autoload is missing
 */
function wpify_woo_php_vendor_missing() {
	$info = get_plugin_data( __FILE__ );
	/* translators: 1: Plugin name */
	$string = sprintf( esc_html__( 'Opps! %1$s is corrupted it seems, please re-install the plugin.', 'wpify-woo' ), $info['Name'] );
	?>
	<div class="error notice">
		<p><?php echo esc_html( $string ); ?></p>
	</div>
	<?php
}

/**
 * WooCommerce not active notice
 */
function wpify_woo_woocommerce_not_active() {
	$info = get_plugin_data( __FILE__ );
	?>
	<div class="error notice">
		<p><?php
			/* translators: 1: Plugin name */
			printf( esc_html__( 'Plugin %s requires WooCommerce. Please install and activate it first.', 'wpify-woo' ), esc_html( $info['Name'] ) );
			?></p>
	</div>
	<?php
}

/**
 * Load plugin textdomain.
 */

/**
 * Check if required plugin is active
 */
function wpify_woo_plugin_is_active( $plugin ) {
	if ( is_multisite() ) {
		$plugins = get_site_option( 'active_sitewide_plugins' );
		if ( isset( $plugins[ $plugin ] ) ) {
			return true;
		}
	}

	if ( in_array( $plugin, (array) get_option( 'active_plugins', array() ), true ) ) {
		return true;
	}

	return false;
}

/**
 * We want to use a fairly modern php version, feel free to increase the minimum requirement
 */
if ( version_compare( PHP_VERSION, WPIFY_WOO_MIN_PHP_VERSION ) < 0 ) {
	add_action( 'admin_notices', 'wpify_woo_php_upgrade_notice' );
} elseif ( ! wpify_woo_plugin_is_active( 'woocommerce/woocommerce.php' ) ) {
	add_action( 'admin_notices', 'wpify_woo_woocommerce_not_active' );
} else {
	if ( file_exists( __DIR__ . '/vendor/wpify-woo/scoper-autoload.php' ) ) {
		include_once __DIR__ . '/vendor/wpify-woo/scoper-autoload.php';
		include_once __DIR__ . '/vendor/autoload.php';

		add_action( 'plugins_loaded', 'wpify_woo_init', 11 );
		register_activation_hook( __FILE__, 'wpify_woo_activate' );
		register_deactivation_hook( __FILE__, 'wpify_woo_deactivate' );
	} else {
		add_action( 'admin_notices', 'wpify_woo_php_vendor_missing' );
	}
}

add_action( 'in_plugin_update_message-wpify-woo/wpify-woo.php', function ( $plugin_data, $response ) {
	if ( ! empty( $response->upgrade_notice ) ) {
		echo '<div style="background: red; color: white; padding: 10px;">' . wp_kses( $response->upgrade_notice, array(
				'a' => array(
					'href'  => array(),
					'title' => array()
				)
			) ) . '</div>';
	}
}, 10, 2 );

add_action( 'before_woocommerce_init', function () {
	if ( class_exists( FeaturesUtil::class ) ) {
		FeaturesUtil::declare_compatibility( 'custom_order_tables', __FILE__ );
		FeaturesUtil::get_features( true,true );
	}
} );
