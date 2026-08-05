<?php

namespace WpifyWoo\Modules\Comments;

defined( 'ABSPATH' ) || exit;

use WP_Error;
use WpifyWoo\Plugin;
use WpifyWooDeps\Wpify\WooCore\Abstracts\AbstractModule;
use WpifyWooDeps\Wpify\CustomFields\CustomFields;

class CommentsModule extends AbstractModule {
	const MODULE_ID = 'comments';

	public function __construct(
		private CustomFields $custom_fields
	) {
		parent::__construct( );
		$this->setup();
	}

	/**
	 * @return void
	 */
	public function setup() {
		add_action( 'woocommerce_review_meta', [ $this, 'display_type' ] );
		add_action( 'init', array( $this, 'register_metabox' ) );
	}

	/**
	 * Module ID
	 *
	 * @return string
	 */
	function id() {
		return self::MODULE_ID;
	}

	/**
	 * Plugin slug
	 *
	 * @return string
	 */
	public function plugin_slug(): string {
		return Plugin::PLUGIN_SLUG;
	}

	/**
	 * Module documentation path
	 *
	 * @return string
	 */
	public function get_documentation_path(): string {
		return 'wpify-woo/modules/comments';
	}

	public function register_metabox() {
		$this->custom_fields->create_comment_metabox(
			[
				'id'    => 'wpify_woo_comments',
				'title' => __( 'WPify Woo Details', 'wpify-woo' ),
				'items' => array(
					array(
						'type'  => 'group',
						'id'    => '_wpify_woo_details',
						'items' => [
							[
								'type'    => 'select',
								'id'      => 'type',
								'title'   => __( 'Comment type', 'wpify-woo' ),
								'options' => function () {
									return array_map( function ( $item ) {
										return [
											'label' => $item['label'],
											'value' => $item['id'],
										];
									}, $this->get_setting( 'comment_types' ) ?: [] );
								},
							],
						],
					),
				),

			]
		);
	}

	/**
	 * @return array[]
	 */
	public function settings(): array {
		$settings = array(
			array(
				'id'    => 'comment_types',
				'type'  => 'multi_group',
				'label' => __( 'Comment types', 'wpify-woo' ),
				'items' => [
					[
						'id'    => 'label',
						'label' => __( 'Label', 'wpify-woo' ),
						'type'  => __( 'text', 'wpify-woo' ),
					],
					[
						'id'        => 'id',
						'type'      => 'hidden',
						'generator' => 'uuid',
					],

				],
			),
		);

		return $settings;
	}

	public function name() {
		return __( 'Comments', 'wpify-woo' );
	}

	public function display_type( $comment ) {
		$details = get_comment_meta( $comment->comment_ID, '_wpify_woo_details', true );
		if ( $details && ! empty( $details['type'] ) && ! empty( $this->get_setting( 'comment_types' ) ) ) {
			foreach ( $this->get_setting( 'comment_types' ) as $comment_type ) {
				if ( $comment_type['id'] === $details['type'] ) { ?>
					<p class="meta">
						<em class="woocommerce-review__type">
							<?php echo esc_html( $comment_type['label'] ); ?>
						</em>
					</p>

				<?php }
			}
		}
	}
}
