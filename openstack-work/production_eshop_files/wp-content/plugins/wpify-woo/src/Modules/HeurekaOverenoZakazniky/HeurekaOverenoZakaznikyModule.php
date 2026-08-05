<?php

namespace WpifyWoo\Modules\HeurekaOverenoZakazniky;

defined( 'ABSPATH' ) || exit;

use ReflectionException;
use WpifyWoo\Plugin;
use WpifyWooDeps\Wpify\Model\OrderItemLine;
use WpifyWooDeps\Wpify\WooCore\Abstracts\AbstractModule;
use WpifyWoo\Models\WooOrderModel;
use WpifyWoo\Repositories\WooOrderRepository;
use WpifyWooDeps\Heureka\ShopCertification;
use WpifyWooDeps\Heureka\ShopCertification\Exception;
use WpifyWooDeps\Wpify\Log\RotatingFileLog;
use WpifyWooDeps\Wpify\Model\Exceptions\RepositoryNotInitialized;

/**
 * Class HeurekaOverenoZakaznikyModule
 *
 * @package WpifyWoo\Modules\HeurekaOverenoZakazniky
 */
class HeurekaOverenoZakaznikyModule extends AbstractModule {
	private $block_support;

	public function __construct(
		private RotatingFileLog $log,
		private WooOrderRepository $woo_order_repository,
		private HeurekaReviewRepository $heureka_review_repository
	) {
		parent::__construct();
		$this->setup();
		$this->init_block_support();
	}

	/**
	 * Setup
	 *
	 * @return void
	 */
	public function setup() {
		add_action( 'woocommerce_checkout_order_created', array( $this, 'send_order_to_heureka_now' ) );
		add_action( 'wpify_woo_heureka_overeno_zakazniky', array( $this, 'send_order_to_heureka' ) );
		add_action( 'woocommerce_checkout_after_terms_and_conditions', array( $this, 'add_optout' ) );
		add_action( 'wp_head', array( $this, 'render_widget' ) );
		add_action( 'admin_init', array( $this, 'handle_actions' ) );

		// Reviews import + display
		add_action( 'init', array( $this, 'maybe_schedule_reviews_import' ) );
		add_action( 'wpify_woo_import_heureka_reviews', array( $this, 'import_heureka_reviews' ) );
		add_shortcode( 'wpify_woo_heureka_reviews', array( $this, 'render_heureka_reviews_shortcode' ) );
		add_action( 'admin_notices', array( $this, 'render_admin_notices' ) );
	}

	/**
	 * Get the module ID
	 *
	 * @return string
	 */
	public function id(): string {
		return 'heureka_overeno_zakazniky';
	}

	public function plugin_slug(): string {
		return Plugin::PLUGIN_SLUG;
	}

	/**
	 * Module documentation path
	 *
	 * @return string
	 */
	public function get_documentation_path(): string {
		return 'wpify-woo/modules/heureka-verified';
	}

	/**
	 *  Get the settings
	 *
	 * @return array[]
	 */
	public function settings(): array {
		$settings = array(
			array(
				'id'      => 'country',
				'type'    => 'select',
				'label'   => __( 'Country', 'wpify-woo' ),
				'desc'    => __( 'Select country', 'wpify-woo' ),
				'options' => array(
					array(
						'label' => __( 'Heureka CZ', 'wpify-woo' ),
						'value' => 'CZ',
					),
					array(
						'label' => __( 'Heureka SK', 'wpify-woo' ),
						'value' => 'SK',
					),
				),
			),
			array(
				'id'    => 'api_key',
				'type'  => 'text',
				'label' => __( 'Api Key', 'wpify-woo' ),
				'desc'  => __( 'Enter the API Key', 'wpify-woo' ),
			),
			array(
				'id'    => 'enable_optout',
				'type'  => 'toggle',
				'label' => __( 'Enable Opt-Out', 'wpify-woo' ),
				'title' => __( 'Check if you want to enable opt out on the checkout', 'wpify-woo' ),
			),
			array(
				'id'      => 'enable_optout_text',
				'type'    => 'text',
				'label'   => __( 'Enable Opt-Out Text', 'wpify-woo' ),
				'desc'    => __( 'Enter the Opt-out text', 'wpify-woo' ),
				'default' => __( "I don't want to receive survey from Heureka ověřeno zákazníky", 'wpify-woo' ),
			),
			array(
				'id'    => 'optin_mode',
				'type'  => 'toggle',
				'label' => __( 'Use Opt-In instead of Opt-Out', 'wpify-woo' ),
				'title' => __( 'Switch the logic to require explicit customer consent (opt-in)', 'wpify-woo' ),
			),
			array(
				'id'    => 'widget_enabled',
				'type'  => 'toggle',
				'label' => __( 'Enable Certification Widget', 'wpify-woo' ),
				'title' => __( 'Enable certification widget.', 'wpify-woo' ),
			),
			array(
				'id'    => 'widget_code',
				'type'  => 'code',
				'label' => __( 'Certification widget code', 'wpify-woo' ),
				'desc'  => __( 'Copy the code from your Heureka account.', 'wpify-woo' ),
			),
			array(
				'id'    => 'send_async',
				'type'  => 'toggle',
				'label' => __( 'Send asynchronously', 'wpify-woo' ),
				'title' => __( 'Send asynchronously', 'wpify-woo' ),
				'desc'  => __( 'By default the order is sent to Heureka synchronously, which is required by Heureka. Under some circumstances this can cause issues - toggle on if you want to schedule the event and send it asynchronously.', 'wpify-woo' ),
			),
		);

		// Reviews import settings
		$settings[] = array(
			'id'    => 'title_reviews',
			'type'  => 'title',
			'title' => __( 'Heureka reviews import', 'wpify-woo' ),
			'desc'  => __( 'Enable importing reviews from Heureka feed and use shortcode [wpify_woo_heureka_reviews count="6"] to display the latest reviews.', 'wpify-woo' ),
		);
		$settings[] = array(
			'id'    => 'reviews_enable',
			'type'  => 'toggle',
			'label' => __( 'Enable reviews import', 'wpify-woo' ),
			'title' => __( 'If enabled, the plugin will import reviews periodically via Action Scheduler.', 'wpify-woo' ),
		);
		$settings[] = array(
			'id'    => 'reviews_feed_url',
			'type'  => 'text',
			'label' => __( 'Reviews feed URL', 'wpify-woo' ),
			'desc'  => __( 'Enter your Heureka reviews XML feed URL.', 'wpify-woo' ),
		);

		$settings[] = array(
			'id'    => 'reviews_shop_certificate_id',
			'type'  => 'text',
			'label' => __( 'Shop certificate ID', 'wpify-woo' ),
			'desc'  => __( 'Your Heureka shop certificate ID (used for the widget).', 'wpify-woo' ),
		);

		$settings[] = array(
			'id'    => 'reviews_shop_id',
			'type'  => 'text',
			'label' => __( 'Heureka Shop ID (numeric)', 'wpify-woo' ),
			'desc'  => __( 'Numeric shop ID used in the widget showWidget call. If empty, the certificate ID will be used.', 'wpify-woo' ),
		);

		$settings[] = array(
			'id'    => 'reviews_shop_name',
			'type'  => 'text',
			'label' => __( 'Heureka Shop Name', 'wpify-woo' ),
			'desc'  => __( 'Shop name used in the widget showWidget call. If empty, the site name will be used.', 'wpify-woo' ),
		);


		$settings[] = array(
			'id'     => 'import_reviews_button',
			'type'   => 'button',
			'desc'   => __( 'Click to import reviews from the configured feed now.', 'wpify-woo' ),
			'label'  => __( 'Import reviews now', 'wpify-woo' ),
			'title'  => __( 'Import reviews', 'wpify-woo' ),
			'url'    => add_query_arg(
				array(
					'wpify-woo-action' => 'import-heureka-reviews',
					'_wpnonce'         => wp_create_nonce( 'wpify-woo-import-heureka-reviews' ),
				),
				$this->get_settings_url()
			),
			'target' => '_self',
		);

		return $settings;
	}

	public function handle_actions() {
		if ( isset( $_GET['wpify-woo-action'] ) && 'import-heureka-reviews' === sanitize_text_field( wp_unslash( $_GET['wpify-woo-action'] ) ) && wp_verify_nonce( isset( $_GET['_wpnonce'] ) ? sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ) ) : '', 'wpify-woo-import-heureka-reviews' ) ) {
			$result = $this->import_heureka_reviews();
			$args   = array( 'wpify-woo-notice' => 'import-heureka-reviews' );
			if ( is_wp_error( $result ) ) {
				$args['status']  = 'error';
				$args['message'] = rawurlencode( $result->get_error_message() );
			} else {
				$args['status']   = 'success';
				$args['imported'] = (string) ( $result['imported'] ?? 0 );
				$args['updated']  = (string) ( $result['updated'] ?? 0 );
			}

			wp_safe_redirect( add_query_arg( $args, $this->get_settings_url() ) );
			exit;
		}
	}

	public function render_admin_notices() {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only admin notice rendered after a nonce-verified redirect.
		if ( ! isset( $_GET['wpify-woo-notice'] ) || 'import-heureka-reviews' !== sanitize_text_field( wp_unslash( $_GET['wpify-woo-notice'] ) ) ) {
			return;
		}
		$status = isset( $_GET['status'] ) ? sanitize_text_field( wp_unslash( $_GET['status'] ) ) : 'success';
		if ( 'error' === $status ) {
			$message = isset( $_GET['message'] ) ? sanitize_text_field( wp_unslash( $_GET['message'] ) ) : __( 'Import failed.', 'wpify-woo' );
			echo '<div class="notice notice-error is-dismissible"><p>' . esc_html__( 'Heureka Reviews import failed:', 'wpify-woo' ) . ' ' . esc_html( $message ) . '</p></div>';

			return;
		}
		$imported = isset( $_GET['imported'] ) ? intval( $_GET['imported'] ) : 0;
		$updated  = isset( $_GET['updated'] ) ? intval( $_GET['updated'] ) : 0;
		// phpcs:enable WordPress.Security.NonceVerification.Recommended
		/* translators: %1$d: number of new reviews imported, %2$d: number of updated reviews */
		echo '<div class="notice notice-success is-dismissible"><p>' . esc_html( sprintf( __( 'Heureka Reviews imported: %1$d new, %2$d updated.', 'wpify-woo' ), $imported, $updated ) ) . '</p></div>';
	}

	/**
	 * Schedule recurring import if enabled; unschedule when disabled or URL missing.
	 */
	public function maybe_schedule_reviews_import() {
		$enabled = (bool) $this->get_setting( 'reviews_enable' );
		$url     = (string) ( $this->get_setting( 'reviews_feed_url' ) ?? '' );

		if ( ! function_exists( 'as_schedule_recurring_action' ) ) {
			return;
		}

		$hook = 'wpify_woo_import_heureka_reviews';

		if ( ! $enabled || empty( $url ) ) {
			// Unschedule any pending recurring imports when disabled
			if ( function_exists( 'as_unschedule_all_actions' ) ) {
				as_unschedule_all_actions( $hook );
			}

			return;
		}

		// Ensure recurring action exists (every 12 hours)
		$next = function_exists( 'as_next_scheduled_action' ) ? as_next_scheduled_action( $hook ) : false;
		if ( ! $next ) {
			as_schedule_recurring_action( time() + HOUR_IN_SECONDS, 12 * HOUR_IN_SECONDS, $hook );
		}
	}

	/**
	 * Import reviews from configured feed URL and save to DB.
	 */
	public function import_heureka_reviews() {
		$url = (string) ( $this->get_setting( 'reviews_feed_url' ) ?? '' );
		if ( empty( $url ) ) {
			return new \WP_Error( 'missing_url', __( 'Reviews feed URL is not set.', 'wpify-woo' ) );
		}

		// Fetch feed
		$response = wp_remote_get( $url, array( 'timeout' => 30 ) );
		if ( is_wp_error( $response ) ) {
			$this->log->error( 'Heureka Reviews: HTTP error', array( 'data' => $response->get_error_message() ) );

			return new \WP_Error( 'http_error', $response->get_error_message() );
		}
		$code = wp_remote_retrieve_response_code( $response );
		$body = wp_remote_retrieve_body( $response );
		if ( 200 !== (int) $code || empty( $body ) ) {
			$this->log->error( 'Heureka Reviews: Invalid response', array( 'data' => array( 'code' => $code ) ) );

			return new \WP_Error( 'invalid_response', __( 'Failed to fetch the reviews feed.', 'wpify-woo' ) );
		}

		// Parse XML
		$xml = @simplexml_load_string( $body );
		if ( ! $xml || ! isset( $xml->review ) ) {
			$this->log->error( 'Heureka Reviews: Failed to parse XML' );

			return new \WP_Error( 'parse_error', __( 'Failed to parse reviews XML feed.', 'wpify-woo' ) );
		}

		$imported = 0;
		$updated  = 0;

		foreach ( $xml->review as $review ) {
			$rating_id = (int) (string) ( $review->rating_id ?? 0 );
			if ( ! $rating_id ) {
				continue;
			}

			$existing = $this->heureka_review_repository->find_one_by_rating_id( $rating_id );
			$model    = $existing ?: $this->heureka_review_repository->create();

			$model->rating_id         = $rating_id;
			$model->source            = (string) ( $review->source ?? '' );
			$model->ordered           = (string) ( $review->ordered ?? '' );
			$model->unix_timestamp    = (int) (string) ( $review->unix_timestamp ?? 0 );
			$model->total_rating      = (string) ( $review->total_rating ?? '' );
			$model->recommends        = (string) ( $review->recommends ?? '' );
			$model->delivery_time     = (string) ( $review->delivery_time ?? '' );
			$model->transport_quality = (string) ( $review->transport_quality ?? '' );
			$model->communication     = (string) ( $review->communication ?? '' );
			$model->pickup_time       = (string) ( $review->pickup_time ?? '' );
			$model->pickup_quality    = (string) ( $review->pickup_quality ?? '' );
			$model->pros              = (string) ( $review->pros ?? '' );
			$model->cons              = (string) ( $review->cons ?? '' );
			$model->summary           = (string) ( $review->summary ?? '' );
			$model->reaction          = (string) ( $review->reaction ?? '' );
			$model->order_id          = (int) (string) ( $review->order_id ?? 0 );

			$this->heureka_review_repository->save( $model );
			if ( $existing ) {
				$updated ++;
			} else {
				$imported ++;
			}
		}

		return array( 'imported' => $imported, 'updated' => $updated );
	}

	/**
	 * Render shortcode [wpify_woo_heureka_reviews count="6"]
	 */
	public function render_heureka_reviews_shortcode( $atts = [] ): string {
		$atts  = shortcode_atts( [
			'count'       => 6,
			'widget'      => '1',
			'button_text' => '',
			'button_url'  => '',
		], $atts );
		$count = max( 1, (int) $atts['count'] );
		$items = $this->heureka_review_repository->find_latest( $count );

		if ( empty( $items ) ) {
			// Still render widget if configured even without items
			$items = [];
		}

		ob_start();
		?>
		<div class="wpify-woo-heureka-reviews">
			<div class="wpify-woo-heureka-reviews__grid">
				<?php
				$cert_id  = trim( (string) ( $this->get_setting( 'reviews_shop_certificate_id' ) ?? '' ) );
				$shop_id  = trim( (string) ( $this->get_setting( 'reviews_shop_id' ) ?? '' ) );
				$shop_id  = $shop_id ?: $cert_id; // fallback to certificate id
				$shopName = trim( (string) ( $this->get_setting( 'reviews_shop_name' ) ?? '' ) );
				$shopName = $shopName ?: get_bloginfo( 'name' );
				$host     = wp_parse_url( home_url(), PHP_URL_HOST );
				$slug     = sanitize_title( str_replace( '.', '-', (string) $host ) );
				$widget   = (string) $atts['widget'];
				if ( $cert_id ) : ?>
					<div class="wpify-woo-heureka-reviews__badge">
						<div id="showHeurekaBadgeHere-<?php echo esc_attr( $widget ); ?>"></div>
						<script type="text/javascript">
							//<![CDATA[
							var _hwq = _hwq || [];
							_hwq.push(['setKey', '<?php echo esc_js( $cert_id ); ?>']);
							_hwq.push(['showWidget', '<?php echo esc_js( $widget ); ?>', '<?php echo esc_js( $shop_id ); ?>', '<?php echo esc_js( $shopName ); ?>', '<?php echo esc_js( $slug ); ?>']);
							(function () {
								var ho = document.createElement('script');
								ho.type = 'text/javascript';
								ho.async = true;
								ho.src = 'https://cz.im9.cz/direct/i/gjs.php?n=wdgt\x26sak=<?php echo rawurlencode( $cert_id ); ?>';
								var s = document.getElementsByTagName('script')[0];
								s.parentNode.insertBefore(ho, s);
							})();
							//]]>
						</script>
					</div>
				<?php endif; ?>
				<div class="wpify-woo-heureka-reviews__list">
					<?php foreach ( $items as $item ) : ?>
						<div class="wpify-woo-heureka-review">
							<div class="wpify-woo-heureka-review__header">
								<div class="wpify-woo-heureka-review__rating"
									 aria-label="<?php echo esc_attr( $item->total_rating ); ?> / 5">
									<?php echo wp_kses_post( $this->render_stars( (float) $item->total_rating ) ); ?>
									<span
										class="wpify-woo-heureka-review__rating-value"><?php echo esc_html( $item->total_rating ); ?>/5</span>
								</div>
								<div
									class="wpify-woo-heureka-review__badge"><?php echo esc_html__( 'Ověřeno zákazníky Heureka', 'wpify-woo' ); ?></div>
							</div>
							<?php if ( ! empty( $item->summary ) ) : ?>
								<div
									class="wpify-woo-heureka-review__summary"><?php echo esc_html( $item->summary ); ?></div>
							<?php endif; ?>
							<?php if ( ! empty( trim( (string) $item->pros ) ) ) : ?>
								<ul class="wpify-woo-heureka-review__pros">
									<?php foreach ( preg_split( "/\r\n|\r|\n/", (string) $item->pros ) as $line ) : if ( '' === trim( $line ) ) {
										continue;
									} ?>
										<li>+ <?php echo esc_html( trim( $line ) ); ?></li>
									<?php endforeach; ?>
								</ul>
							<?php endif; ?>
							<?php if ( ! empty( trim( (string) $item->cons ) ) ) : ?>
								<ul class="wpify-woo-heureka-review__cons">
									<?php foreach ( preg_split( "/\r\n|\r|\n/", (string) $item->cons ) as $line ) : if ( '' === trim( $line ) ) {
										continue;
									} ?>
										<li>- <?php echo esc_html( trim( $line ) ); ?></li>
									<?php endforeach; ?>
								</ul>
							<?php endif; ?>
							<?php if ( ! empty( $item->reaction ) ) : ?>
								<div
									class="wpify-woo-heureka-review__reaction"><?php echo nl2br( esc_html( $item->reaction ) ); ?></div>
							<?php endif; ?>
							<div class="wpify-woo-heureka-review__meta">
								<span
									class="wpify-woo-heureka-review__date"><?php echo esc_html( date_i18n( get_option( 'date_format' ), (int) $item->unix_timestamp ) ); ?></span>
							</div>
						</div>
					<?php endforeach; ?>
					<?php
					$button_url  = trim( (string) $atts['button_url'] );
					$button_text = trim( (string) $atts['button_text'] );
					if ( $button_url ) {
						if ( '' === $button_text ) {
							$button_text = __( 'Show all reviews', 'wpify-woo' );
						}
						echo '<div class="wpify-woo-heureka-reviews__cta">'
							 . '<a class="wpify-woo-heureka-reviews__button" href="' . esc_url( $button_url ) . '" target="_blank" rel="noopener">'
							 . esc_html( $button_text )
							 . '</a>'
							 . '</div>';
					}
					?>
				</div>
			</div>
		</div>
		<style>
			.wpify-woo-heureka-reviews__grid {
				display: grid;
				grid-template-columns:1fr 2fr;
				gap: 24px;
				align-items: start
			}

			@media (max-width: 782px) {
				.wpify-woo-heureka-reviews__grid {
					grid-template-columns:1fr
				}
			}

			.wpify-woo-heureka-reviews__badge {
				position: sticky;
				top: 0
			}

			.wpify-woo-heureka-reviews__list {
				display: grid;
				gap: 24px
			}

			.wpify-woo-heureka-review {
				border: 1px solid #eee;
				border-radius: 8px;
				padding: 16px
			}

			.wpify-woo-heureka-review__header {
				display: flex;
				align-items: center;
				justify-content: space-between;
				margin-bottom: 8px
			}

			.wpify-woo-heureka-review__badge {
				font-size: 12px;
				color: #555;
				background: #f3f4f6;
				border-radius: 999px;
				padding: 4px 10px
			}

			.wpify-woo-heureka-review__rating {
				display: flex;
				align-items: center;
				gap: 8px
			}

			.wpify-woo-heureka-stars {
				color: #f59e0b;
				font-size: 16px;
				line-height: 1
			}

			.wpify-woo-heureka-review__summary {
				font-weight: 600;
				margin: 6px 0
			}

			.wpify-woo-heureka-review__pros, .wpify-woo-heureka-review__cons {
				margin: 6px 0 0 0;
				padding-left: 18px
			}

			.wpify-woo-heureka-review__reaction {
				margin-top: 8px;
				font-style: italic;
				color: #444
			}

			.wpify-woo-heureka-review__meta {
				margin-top: 6px;
				color: #6b7280;
				font-size: 12px
			}

			.wpify-woo-heureka-reviews__cta {
				margin-top: 8px
			}

			.wpify-woo-heureka-reviews__button {
				display: inline-block;
				background: #111827;
				color: #fff;
				text-decoration: none;
				padding: 10px 14px;
				border-radius: 6px
			}

			.wpify-woo-heureka-reviews__button:hover {
				background: #000
			}
		</style>
		<?php
		return (string) ob_get_clean();
	}

	private function render_stars( float $rating ): string {
		$rating = max( 0.0, min( 5.0, $rating ) );
		$full   = (int) floor( $rating );
		$half   = ( $rating - $full ) >= 0.5 ? 1 : 0;
		$empty  = 5 - $full - $half;

		return sprintf(
			'<span class="wpify-woo-heureka-stars">%s%s%s</span>',
			str_repeat( '★', $full ),
			$half ? '☆' : '',
			str_repeat( '☆', $empty )
		);
	}

	/**
	 * Schedule the event
	 *
	 * @param int|string $order_id Order ID.
	 *
	 * @return false|int
	 */
	public function schedule_event( $order_id ) {
		return as_schedule_single_action( time(), 'wpify_woo_heureka_overeno_zakazniky', array( 'order_id' => $order_id ) );
	}

	/**
	 * Send the order to Heureka on order processed hook
	 *
	 * @param int|string $order_id Order ID.
	 *
	 * @return false|int
	 */
	public function send_order_to_heureka_now( $order_id ) {
		if ( ! $this->get_setting( 'api_key' ) ) {
			return false;
		}

		// Get order
		if ( is_a( $order_id, '\WC_Order' ) ) {
			$order    = $order_id;
			$order_id = $order_id->get_id();
		} else {
			$order = wc_get_order( $order_id );
		}

		// Check if data is already send
		if ( $order->meta_exists( '_wpify_woo_heureka_optout_agreement' ) ) {
			return false;
		}

		$use_optin = $this->get_setting( 'optin_mode' );

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Checkout submission is nonce-verified by WooCommerce core; only reads the opt-out checkbox presence.
		// In OPT-IN mode: if checkbox is not checked → do not send
		if ( $use_optin && empty( $_POST['wpify_woo_heureka_optout'] ) ) {
			/* translators: %s: Yes or No answer */
			$order->add_order_note( sprintf( __( 'Heureka: Agree with the satisfaction questionnaire: %s', 'wpify-woo' ), __( 'No', 'wpify-woo' ) ) );
			$order->update_meta_data( '_wpify_woo_heureka_optout_agreement', 'no' );
			$order->save();

			return false;
		}

		// In OPT-OUT mode: if checkbox is checked → do not send
		if ( ! $use_optin && ! empty( $_POST['wpify_woo_heureka_optout'] ) ) {
			/* translators: %s: Yes or No answer */
			$order->add_order_note( sprintf( __( 'Heureka: Agree with the satisfaction questionnaire: %s', 'wpify-woo' ), __( 'No', 'wpify-woo' ) ) );
			$order->update_meta_data( '_wpify_woo_heureka_optout_agreement', 'no' );
			$order->save();

			return false;
		}
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		if ( apply_filters( 'wpify_woo_heureka_disable_send', false, $order ) === true ) {
			$order->add_order_note( __( 'Heureka: Send disabled by custom filter.', 'wpify-woo' ) );

			return false;
		}

		// send data
		if ( $this->get_setting( 'send_async' ) ) {
			$this->schedule_event( $order_id );
		} else {
			$this->send_order_to_heureka( $order_id );
		}
	}

	/**
	 * Send order to Heureka
	 *
	 * @param int|string $order_id Order ID.
	 *
	 * @throws RepositoryNotInitialized
	 */
	public function send_order_to_heureka( $order_id ) {
		/** Order Model. @var WooOrderModel $order */
		$order = $this->woo_order_repository->get( $order_id );

		try {
			$options = array();
			if ( 'CZ' === $this->get_setting( 'country' ) ) {
				$options['service'] = ShopCertification::HEUREKA_CZ;
			} elseif ( 'SK' === $this->get_setting( 'country' ) ) {
				$options['service'] = ShopCertification::HEUREKA_SK;
			}

			$item_ids = [];
			/** @var OrderItemLine $item */
			foreach ( $order->line_items as $item ) {
				$product_id = $item->variation_id ?: $item->product_id;
				$item_ids[] = apply_filters( 'wpify_woo_heureka_overeno_item_id', $product_id, $item );
			}

			$data = apply_filters( 'wpify_woo_heureka_overeno_data', array(
				'email'    => $order->get_wc_order()->get_billing_email(),
				'order_id' => (int) ( $order->get_wc_order()->get_order_number() ?: $order->id ),
				'item_ids' => $item_ids,
			), $order->get_wc_order() );

			$shop_certification = new ShopCertification( $this->get_setting( 'api_key' ), $options, ( new WpRequester() ) );
			$shop_certification->setEmail( $data['email'] );
			$shop_certification->setOrderId( $data['order_id'] );

			foreach ( $data['item_ids'] as $item_id ) {
				$shop_certification->addProductItemId( $item_id );
			}

			$result = $shop_certification->logOrder();
			/* translators: %s: Yes or No answer */
			$order->get_wc_order()->add_order_note( sprintf( __( 'Heureka: Agree with the satisfaction questionnaire: %s', 'wpify-woo' ), __( 'Yes. The order has been sent.', 'wpify-woo' ) ) );
			$order->get_wc_order()->update_meta_data( '_wpify_woo_heureka_optout_agreement', 'yes' );
			$order->get_wc_order()->save();
			$this->log->info(
				sprintf( 'Heureka Overeno: sent order to Heureka.' ),
				array(
					'data'   => $data,
					'result' => $result,
				)
			);
		} catch ( Exception $e ) {
			$this->log->error(
				sprintf( 'Heureka Overeno: error sending to Heureka.' ),
				array(
					'data'     => $data,
					'message'  => $e->getMessage(),
					'settings' => $this->get_settings(),
					'options'  => $options,
				)
			);
		}
	}

	/**
	 * Add optout to checkout
	 */
	public function add_optout() {
		if ( ! $this->get_setting( 'enable_optout' ) || apply_filters( 'wpify_woo_heureka_add_optout', true ) === false ) {
			return;
		}
		?>
		<p class="form-row wpify-woo-heureka-optout">
			<label class="woocommerce-form__label woocommerce-form__label-for-checkbox checkbox">
				<input type="checkbox" class="woocommerce-form__input woocommerce-form__input-checkbox input-checkbox"
					   name="wpify_woo_heureka_optout" style="width: auto;"
					<?php
					checked( isset( $_POST['wpify_woo_heureka_optout'] ), true ); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Checkout field default state, read-only display.
					?>
				/>
				<span
					class="wpify-woo-heureka-optout-checkbox-text"><?php echo esc_html( sanitize_text_field( $this->get_setting( 'enable_optout_text' ) ) ); ?></span>&nbsp;
			</label>
		</p>        <?php
	}

	/**
	 * Render certification widget
	 */
	public function render_widget() {
		if ( empty( $this->get_setting( 'widget_enabled' ) ) || empty( $this->get_setting( 'widget_code' ) ) || apply_filters( 'wpify_woo_heureka_render_widget', true ) === false ) {
			return;
		}

		echo $this->get_setting( 'widget_code' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Admin-configured Heureka certification widget markup output verbatim.
	}

	/**
	 * Initialize block checkout support
	 */
	private function init_block_support() {
		if ( class_exists( '\Automattic\WooCommerce\Blocks\Package' ) ) {
			$this->block_support = new BlockSupport( $this );
		}
	}

	public function name() {
		return __( 'Heureka Ověřeno Zákázníky', 'wpify-woo' );
	}
}
