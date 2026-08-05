<?php

namespace WpifyWoo\Modules\WithdrawalClaims;

defined( 'ABSPATH' ) || exit;

use WpifyWooDeps\Wpify\PluginUtils\PluginUtils;

/**
 * Gutenberg blocks for withdrawal & claim forms.
 *
 * Both blocks are always registered (5.1) — the is_active() guard happens inside
 * the shortcode that the block renders, so the block visually disappears when
 * the corresponding functions are disabled.
 *
 * Editor JS is built via wp-scripts (see webpack.config.js entry
 * `withdrawal-claims-blocks`) into `build/withdrawal-claims-blocks.js` and
 * registered as the handle `wpify-woo-withdrawal-claims-blocks`. Each block.json
 * references this handle in its `editorScript` field.
 */
class BlockSupport {

	private const SCRIPT_HANDLE = 'wpify-woo-withdrawal-claims-blocks';

	private WithdrawalClaimsModule $module;
	private PluginUtils $utils;

	public function __construct( WithdrawalClaimsModule $module, PluginUtils $utils ) {
		$this->module = $module;
		$this->utils  = $utils;
		add_action( 'init', array( $this, 'register_blocks' ), 20 );
	}

	public function register_blocks(): void {
		if ( ! function_exists( 'register_block_type' ) ) {
			return;
		}

		// Register the editor script handle that block.json references.
		// Dependencies are hardcoded — wp-scripts can't auto-detect them from
		// vanilla `window.wp.*` access (only from ES imports). Version comes from
		// the wp-scripts-generated .asset.php (chunk hash for cache busting).
		$asset_file = $this->utils->get_plugin_path( 'build/withdrawal-claims-blocks.asset.php' );
		$version    = '1.0.0';
		if ( file_exists( $asset_file ) ) {
			$asset   = include $asset_file;
			$version = $asset['version'] ?? $version;
		}

		wp_register_script(
			self::SCRIPT_HANDLE,
			$this->utils->get_plugin_url( 'build/withdrawal-claims-blocks.js' ),
			array(
				'wp-blocks',
				'wp-element',
				'wp-block-editor',
				'wp-server-side-render',
				'wp-i18n',
			),
			$version,
			true
		);

		$base = __DIR__ . '/blocks';

		register_block_type(
			$base . '/withdrawal-form',
			array(
				'render_callback' => array( $this, 'render_withdrawal_block' ),
			)
		);

		register_block_type(
			$base . '/claim-form',
			array(
				'render_callback' => array( $this, 'render_claim_block' ),
			)
		);
	}

	public function render_withdrawal_block( array $attributes = array(), string $content = '' ): string {
		return $this->wrap_block( 'withdrawal', $attributes );
	}

	public function render_claim_block( array $attributes = array(), string $content = '' ): string {
		return $this->wrap_block( 'claim', $attributes );
	}

	private function wrap_block( string $type, array $attributes ): string {
		$class     = isset( $attributes['className'] ) ? ' ' . esc_attr( $attributes['className'] ) : '';
		$align     = isset( $attributes['align'] ) ? ' align' . esc_attr( $attributes['align'] ) : '';
		$shortcode = $type === 'withdrawal' ? '[wpify_woo_withdrawal_form]' : '[wpify_woo_claim_form]';

		return sprintf(
			'<div class="wpify-woo-%s-form-block%s%s">%s</div>',
			esc_attr( $type ),
			$class,
			$align,
			do_shortcode( $shortcode )
		);
	}
}
