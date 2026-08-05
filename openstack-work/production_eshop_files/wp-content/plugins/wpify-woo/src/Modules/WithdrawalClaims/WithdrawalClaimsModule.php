<?php

namespace WpifyWoo\Modules\WithdrawalClaims;

defined( 'ABSPATH' ) || exit;

use WC_Order;
use WP_Error;
use WpifyWoo\Modules\WithdrawalClaims\Admin\RequestsListTable;
use WpifyWoo\Modules\WithdrawalClaims\Emails\AdminClaimEmail;
use WpifyWoo\Modules\WithdrawalClaims\Emails\AdminWithdrawalEmail;
use WpifyWoo\Modules\WithdrawalClaims\Emails\CustomerClaimEmail;
use WpifyWoo\Modules\WithdrawalClaims\Emails\CustomerWithdrawalEmail;
use WpifyWoo\Plugin;
use WpifyWoo\WooCommerceIntegration;
use WpifyWooDeps\Wpify\Log\RotatingFileLog;
use WpifyWooDeps\Wpify\PluginUtils\PluginUtils;
use WpifyWooDeps\Wpify\WooCore\Abstracts\AbstractModule;

/**
 * Withdrawal & Claim module — EU Directive 2023/2673 + CZ/SK consumer law.
 *
 * Master switches: page assignments in settings (2.1) — `withdrawal_page_id` and
 * `claim_page_id`. Empty = corresponding functions are disabled for new requests.
 * Read paths (admin overview, metabox, "Submitted requests") are always active.
 */
class WithdrawalClaimsModule extends AbstractModule {

	private const ADMIN_PAGE_SLUG     = 'wpify-woo-requests';
	private const META_PERIOD_START   = '_wpify_woo_period_start';
	private const META_WITHDRAWAL_EXC = '_wpify_woo_withdrawal_excluded';
	private const META_WARRANTY_EXC   = '_wpify_woo_warranty_excluded';
	private const META_PERIOD_OVR     = '_wpify_woo_withdrawal_period_override';
	private const META_WARRANTY_OVR   = '_wpify_woo_warranty_months_override';

	private BlockSupport $block_support;

	public function __construct(
		private WooCommerceIntegration $woocommerce_integration,
		private WithdrawalClaimsRepository $repository,
		private RotatingFileLog $log,
		private PluginUtils $utils,
	) {
		parent::__construct();
		$this->block_support = new BlockSupport( $this, $this->utils );
		$this->setup();
	}

	public function id(): string {
		return 'withdrawal_claims';
	}

	public function name(): string {
		return __( 'Withdrawal & Claim', 'wpify-woo' );
	}

	public function plugin_slug(): string {
		return Plugin::PLUGIN_SLUG;
	}

	public function get_documentation_path(): string {
		return 'wpify-woo/modules/withdrawal-claims';
	}

	/**
	 * Hook registration.
	 *
	 * Shortcodes are always registered (guard inside callback) — see 5.1.
	 * Email classes are conditionally registered per is_active() (write path) — see 8.
	 */
	public function setup(): void {
		// Shortcodes — always registered, guard inside.
		add_shortcode( 'wpify_woo_withdrawal_form', array( $this, 'shortcode_withdrawal' ) );
		add_shortcode( 'wpify_woo_claim_form', array( $this, 'shortcode_claim' ) );

		// HPOS compatibility declaration.
		add_action( 'before_woocommerce_init', array( $this, 'declare_hpos_compatibility' ) );

		// Email registration (write path — guarded inside).
		add_filter( 'woocommerce_email_classes', array( $this, 'register_emails' ) );

		// POST handler.
		add_action( 'init', array( $this, 'maybe_handle_post' ), 20 );

		// Period_start tracking (write path: only matters for new requests).
		add_action( 'woocommerce_order_status_changed', array( $this, 'maybe_save_period_start' ), 10, 4 );

		// My Account integration:
		//  - withdrawal/claim buttons added via the native order actions filter,
		//    but visible only on the order detail (not in the orders list).
		//    The filter is shared by both views — gating is done inside the
		//    callback via is_wc_endpoint_url('view-order').
		//  - submitted-requests history below the customer details.
		add_filter( 'woocommerce_my_account_my_orders_actions', array( $this, 'add_my_orders_actions' ), 10, 2 );
		add_action( 'woocommerce_order_details_after_customer_details', array( $this, 'render_my_account_history' ) );

		// Inject withdrawal link into selected WC emails.
		// Fires AFTER customer details (priority 25 — WC default callbacks run at 10),
		// so the section appears below the customer info block and just before
		// the email footer. Same pattern WPify Woo Fakturoid uses for the invoice link.
		add_action( 'woocommerce_email_customer_details', array( $this, 'inject_link_in_emails' ), 25, 4 );

		// Caching headers on form pages.
		add_action( 'template_redirect', array( $this, 'maybe_disable_caching' ) );

		// REST API endpoints for AJAX form flow.
		add_action( 'rest_api_init', array( $this, 'register_rest_routes' ) );

		// Frontend JS on form pages.
		add_action( 'wp_enqueue_scripts', array( $this, 'maybe_enqueue_frontend' ) );

		// Admin: menu, metabox, list table screen.
		add_action( 'admin_menu', array( $this, 'register_admin_menu' ) );
		add_action( 'add_meta_boxes', array( $this, 'register_admin_metabox' ), 30, 2 );

		// Orders list column (legacy + HPOS).
		add_filter( 'manage_edit-shop_order_columns', array( $this, 'add_orders_list_column' ) );
		add_action( 'manage_shop_order_posts_custom_column', array( $this, 'render_orders_list_column' ), 10, 2 );
		add_filter( 'manage_woocommerce_page_wc-orders_columns', array( $this, 'add_orders_list_column' ) );
		add_action( 'manage_woocommerce_page_wc-orders_custom_column', array( $this, 'render_orders_list_column' ), 10, 2 );

		// Per-product meta tab.
		add_filter( 'woocommerce_product_data_tabs', array( $this, 'add_product_data_tab' ) );
		add_action( 'woocommerce_product_data_panels', array( $this, 'render_product_data_panel' ) );
		add_action( 'woocommerce_process_product_meta', array( $this, 'save_product_meta' ) );
	}

	public function declare_hpos_compatibility(): void {
		if ( class_exists( '\Automattic\WooCommerce\Utilities\FeaturesUtil' ) ) {
			\Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility(
				'custom_order_tables',
				$this->utils->get_plugin_path( 'wpify-woo.php' ),
				true
			);
		}
	}

	// =========================================================================
	// Settings
	// =========================================================================

	public function settings_tabs(): array {
		return array(
			'withdrawal' => __( 'Withdrawal', 'wpify-woo' ),
			'claim'      => __( 'Claim', 'wpify-woo' ),
			'security'   => __( 'Security', 'wpify-woo' ),
		);
	}

	public function settings(): array {
		$async_params = array(
			'tab'       => 'wpify-woo-settings',
			'section'   => $this->id(),
			'module_id' => $this->id(),
		);

		return array(

			// =====================================================================
			// Tab: Withdrawal
			// =====================================================================
			array(
				'id'    => 'withdrawal_intro',
				'type'  => 'title',
				'title' => __( 'Withdrawal from contract', 'wpify-woo' ),
				'desc'  => __( 'Implements the mandatory "Withdraw from contract" button per EU Directive 2023/2673 (effective 19 June 2026). Assign a page below to enable withdrawal functions.', 'wpify-woo' ),
				'tab'   => 'withdrawal',
			),
			array(
				'id'           => 'withdrawal_page_id',
				'type'         => 'post',
				'post_type'    => array( 'page' ),
				'label'        => __( 'Withdrawal page', 'wpify-woo' ),
				'desc'         => __( 'Page where the withdrawal form is rendered (via shortcode or block). Empty = withdrawal functions are disabled — no buttons, no emails, no link injection.', 'wpify-woo' ),
				'async'        => true,
				'async_params' => $async_params,
				'tab'          => 'withdrawal',
			),
			array(
				'id'      => 'withdrawal_period_days',
				'type'    => 'number',
				'label'   => __( 'Withdrawal period (days)', 'wpify-woo' ),
				'desc'    => __( 'How many days the customer has to withdraw. Statutory minimum is 14 in CZ/SK. Higher values are allowed (consumer-friendly).', 'wpify-woo' ),
				'default' => '14',
				'tab'     => 'withdrawal',
			),
			array(
				'id'           => 'period_start_statuses',
				'type'         => 'multi_select',
				'label'        => __( 'Order statuses that start the period', 'wpify-woo' ),
				'desc'         => __( 'When the order first reaches any of these statuses, both the withdrawal countdown (above) and the warranty countdown (Claim tab) start. Default "Completed" works for most shops. If you have a custom status like "Delivered", select that instead — if multiple are selected, the earliest transition wins. For orders created before this module was active, the plugin falls back to the order\'s completion / payment / creation date in that order.', 'wpify-woo' ),
				'options'      => array( $this, 'get_order_statuses_options' ),
				'async'        => true,
				'async_params' => $async_params,
				'default'      => array( 'completed' ),
				'tab'          => 'withdrawal',
			),
			array(
				'id'      => 'withdrawal_button_text',
				'type'    => 'text',
				'label'   => __( 'Button text', 'wpify-woo' ),
				'desc'    => __( 'Text on the button that opens the form (My Account, transactional emails).', 'wpify-woo' ),
				'default' => __( 'Withdraw from contract', 'wpify-woo' ),
				'tab'     => 'withdrawal',
			),
			array(
				'id'      => 'withdrawal_confirm_text',
				'type'    => 'text',
				'label'   => __( 'Confirm button text', 'wpify-woo' ),
				'desc'    => __( 'Text on the final confirmation submit inside the form.', 'wpify-woo' ),
				'default' => __( 'Confirm withdrawal', 'wpify-woo' ),
				'tab'     => 'withdrawal',
			),
			array(
				'id'           => 'inject_link_in_emails',
				'type'         => 'multi_select',
				'label'        => __( 'Inject withdrawal link into these WC emails', 'wpify-woo' ),
				'desc'         => __( 'Selected WooCommerce emails will get a section with a link to the withdrawal form. Link is rendered only if the period is still running and the page above is assigned.', 'wpify-woo' ),
				'options'      => function ( $args ) {
					return $this->woocommerce_integration->get_emails_select( $args );
				},
				'async'        => true,
				'async_params' => $async_params,
				'default'      => array( 'customer_completed_order' ),
				'tab'          => 'withdrawal',
			),
			array(
				'id'      => 'inject_link_heading',
				'type'    => 'text',
				'label'   => __( 'Heading shown above the withdrawal link in emails', 'wpify-woo' ),
				'desc'    => __( 'Headline rendered as <code>h2</code>above the "Withdraw from contract" button in the WC emails selected above.', 'wpify-woo' ),
				'default' => __( 'Need to withdraw from this contract?', 'wpify-woo' ),
				'tab'     => 'withdrawal',
			),
			array(
				'id'      => 'inject_link_description',
				'type'    => 'textarea',
				'label'   => __( 'Description shown above the withdrawal link in emails', 'wpify-woo' ),
				'desc'    => __( 'Short paragraph rendered between the heading and the button.', 'wpify-woo' ),
				'default' => __( 'Use the link below to start the withdrawal process online.', 'wpify-woo' ),
				'tab'     => 'withdrawal',
			),

			// =====================================================================
			// Tab: Claim
			// =====================================================================
			array(
				'id'    => 'claim_intro',
				'type'  => 'title',
				'title' => __( 'Claim (warranty) request', 'wpify-woo' ),
				'desc'  => __( 'Optional. Adds a "File a claim" form for warranty issues. Assign a page below to enable claim functions.', 'wpify-woo' ),
				'tab'   => 'claim',
			),
			array(
				'id'           => 'claim_page_id',
				'type'         => 'post',
				'post_type'    => array( 'page' ),
				'label'        => __( 'Claim page', 'wpify-woo' ),
				'desc'         => __( 'Page where the claim form is rendered. Empty = claim functions are disabled.', 'wpify-woo' ),
				'async'        => true,
				'async_params' => $async_params,
				'tab'          => 'claim',
			),
			array(
				'id'      => 'claim_warranty_months',
				'type'    => 'number',
				'label'   => __( 'Warranty period (months)', 'wpify-woo' ),
				'desc'    => __( 'How many months the warranty lasts. Statutory minimum is 24 in CZ/SK.', 'wpify-woo' ),
				'default' => '24',
				'tab'     => 'claim',
			),
			array(
				'id'      => 'claim_button_text',
				'type'    => 'text',
				'label'   => __( 'Button text', 'wpify-woo' ),
				'desc'    => __( 'Text on the button that opens the form (My Account).', 'wpify-woo' ),
				'default' => __( 'File a claim', 'wpify-woo' ),
				'tab'     => 'claim',
			),
			array(
				'id'      => 'claim_confirm_text',
				'type'    => 'text',
				'label'   => __( 'Confirm button text', 'wpify-woo' ),
				'desc'    => __( 'Text on the final submit button inside the form.', 'wpify-woo' ),
				'default' => __( 'Submit claim', 'wpify-woo' ),
				'tab'     => 'claim',
			),

			// =====================================================================
			// Tab: Security
			// =====================================================================
			array(
				'id'    => 'spam_intro',
				'type'  => 'title',
				'title' => __( 'Spam & abuse protection', 'wpify-woo' ),
				'desc'  => __( 'Two independent layers. Layer A limits successful submissions per order. Layer B limits attempts per IP (counts even failed ones — protects against brute force).', 'wpify-woo' ),
				'tab'   => 'security',
			),
			array(
				'id'      => 'max_requests_per_order',
				'type'    => 'number',
				'label'   => __( 'Max requests per order (Layer A)', 'wpify-woo' ),
				'desc'    => __( 'Maximum number of stored requests on the same order, regardless of type.', 'wpify-woo' ),
				'default' => '5',
				'tab'     => 'security',
			),
			array(
				'id'      => 'min_seconds_between_requests',
				'type'    => 'number',
				'label'   => __( 'Min seconds between requests (Layer A)', 'wpify-woo' ),
				'desc'    => __( 'Minimum gap between two stored requests on the same order. Prevents accidental double-submits.', 'wpify-woo' ),
				'default' => '300',
				'tab'     => 'security',
			),
			array(
				'id'      => 'rate_limit_per_ip_hour',
				'type'    => 'number',
				'label'   => __( 'Max attempts per IP per hour (Layer B)', 'wpify-woo' ),
				'desc'    => __( 'Maximum submission attempts per IP per hour, including validation failures. Use to throttle brute-force attempts.', 'wpify-woo' ),
				'default' => '10',
				'tab'     => 'security',
			),
			array(
				'id'      => 'duplicate_window_hours',
				'type'    => 'number',
				'label'   => __( 'Duplicate content window (hours)', 'wpify-woo' ),
				'desc'    => __( 'Block submission if an identical request (same items + reason) was submitted on the same order within this many hours. Set to 0 to disable.', 'wpify-woo' ),
				'default' => '24',
				'tab'     => 'security',
			),
		);
	}

	public function get_order_statuses_options(): array {
		$options = array();
		foreach ( wc_get_order_statuses() as $key => $label ) {
			$value     = preg_replace( '/^wc-/', '', $key );
			$options[] = array(
				'label' => $label,
				'value' => $value,
			);
		}

		return $options;
	}

	// =========================================================================
	// Master switch — is_active()
	// =========================================================================

	/**
	 * Master switch helper. Whether the given functions (withdrawal or claim)
	 * are active for creating new requests. Read paths ignore this.
	 *
	 * @param string $type withdrawal|claim
	 */
	public function is_active( string $type ): bool {
		$key = $type === 'withdrawal' ? 'withdrawal_page_id' : 'claim_page_id';

		return (int) $this->get_setting( $key ) > 0;
	}

	public function get_page_url( string $type ): string {
		$page_id = (int) $this->get_setting( $type === 'withdrawal' ? 'withdrawal_page_id' : 'claim_page_id' );
		if ( ! $page_id ) {
			return '';
		}
		$url = get_permalink( $page_id );

		return $url ?: '';
	}

	// =========================================================================
	// Period helpers (cascade — tracked + legacy fallback)
	// =========================================================================

	public function maybe_save_period_start( int $order_id, string $old, string $new, $order ): void {
		if ( ! $order instanceof WC_Order ) {
			$order = wc_get_order( $order_id );
		}
		if ( ! $order instanceof WC_Order ) {
			return;
		}

		$statuses = (array) $this->get_setting( 'period_start_statuses' );
		if ( ! in_array( $new, $statuses, true ) ) {
			return;
		}

		if ( $order->get_meta( self::META_PERIOD_START ) ) {
			return;
		}

		// Guard against starting the period today for orders that are already
		// past any reasonable withdrawal/warranty window. A late status change
		// on a years-old order (bulk re-save, admin edit, manual import) would
		// otherwise silently grant a fresh 14-day withdrawal window — letting
		// the customer act on a contract that is long closed. When skipped,
		// period_start_for() falls back to date_completed/paid/created and the
		// item is correctly evaluated as expired.
		$created = $order->get_date_created();
		if ( $created ) {
			$days_w    = max( 1, (int) $this->get_setting( 'withdrawal_period_days' ) );
			$months_c  = max( 1, (int) $this->get_setting( 'claim_warranty_months' ) );
			$max_days  = max( $days_w, $months_c * 31 );
			$cutoff    = ( new \DateTimeImmutable( 'now' ) )->modify( '-' . $max_days . ' days' );
			$created_i = $created instanceof \DateTimeImmutable
				? $created
				: \DateTimeImmutable::createFromInterface( $created );

			if ( $created_i < $cutoff ) {
				return;
			}
		}

		$order->update_meta_data( self::META_PERIOD_START, current_time( 'mysql', true ) );
		$order->save();
	}

	/**
	 * Cascade for period_start (see 6.2).
	 */
	public function period_start_for( WC_Order $order ): \DateTimeInterface {
		$meta = $order->get_meta( self::META_PERIOD_START );
		if ( $meta ) {
			try {
				return new \DateTimeImmutable( $meta );
			} catch ( \Exception $e ) {
				// fall through
			}
		}

		$created = $order->get_date_created();

		// Hard guard for the legacy fallback below: when the order itself is
		// older than any reasonable withdrawal/warranty window, prefer
		// date_created. Otherwise date_completed / date_paid — which WC
		// auto-stamps on the actual status transition — would shift the
		// period to "today" for a years-old order that was just retroactively
		// completed or paid, silently reopening the window.
		if ( $created ) {
			$days_w   = max( 1, (int) $this->get_setting( 'withdrawal_period_days' ) );
			$months_c = max( 1, (int) $this->get_setting( 'claim_warranty_months' ) );
			$max_days = max( $days_w, $months_c * 31 );
			$cutoff   = ( new \DateTimeImmutable( 'now' ) )->modify( '-' . $max_days . ' days' );
			$created_i = $created instanceof \DateTimeImmutable
				? $created
				: \DateTimeImmutable::createFromInterface( $created );

			if ( $created_i < $cutoff ) {
				return $created_i;
			}
		}

		if ( $order->get_date_completed() ) {
			return $order->get_date_completed();
		}
		if ( $order->get_date_paid() ) {
			return $order->get_date_paid();
		}

		return $created ?: new \DateTimeImmutable();
	}

	/**
	 * Resolve the product carrying request-related meta for an order line item.
	 *
	 * For variation order items, meta (exclusion flag, period override) is stored
	 * on the parent product — the variation has no UI for it. Falls back to the
	 * item's own product if it's not a variation or the parent cannot be loaded.
	 */
	private function resolve_meta_product( $item ): ?\WC_Product {
		$product = $item ? $item->get_product() : null;
		if ( $product && $product->is_type( 'variation' ) ) {
			$parent = wc_get_product( $product->get_parent_id() );
			if ( $parent ) {
				return $parent;
			}
		}

		return $product ?: null;
	}

	public function withdrawal_period_end_for( WC_Order $order, ?int $line_item_id = null ): \DateTimeInterface {
		$start    = $this->period_start_for( $order );
		$days     = (int) $this->get_setting( 'withdrawal_period_days' );
		$override = null;

		if ( $line_item_id ) {
			$item = $order->get_item( $line_item_id );
			if ( $item ) {
				$product = $this->resolve_meta_product( $item );
				if ( $product ) {
					$ovr = (int) $product->get_meta( self::META_PERIOD_OVR );
					if ( $ovr > 0 ) {
						$override = $ovr;
					}
				}
			}
		}

		$days  = $override ?? max( 1, $days );
		$start = $this->clamp_start_for_period( $order, $start, $days, 'days' );
		$end   = $start->modify( '+' . $days . ' days' );

		return apply_filters( 'wpify_woo_withdrawal_claims_period_end', $end, $order, 'withdrawal' );
	}

	public function claim_period_end_for( WC_Order $order, ?int $line_item_id = null ): \DateTimeInterface {
		$start    = $this->period_start_for( $order );
		$months   = (int) $this->get_setting( 'claim_warranty_months' );
		$override = null;

		if ( $line_item_id ) {
			$item = $order->get_item( $line_item_id );
			if ( $item ) {
				$product = $this->resolve_meta_product( $item );
				if ( $product ) {
					$ovr = (int) $product->get_meta( self::META_WARRANTY_OVR );
					if ( $ovr > 0 ) {
						$override = $ovr;
					}
				}
			}
		}

		$months = $override ?? max( 1, $months );
		$start  = $this->clamp_start_for_period( $order, $start, $months, 'months' );
		$end    = $start->modify( '+' . $months . ' months' );

		return apply_filters( 'wpify_woo_withdrawal_claims_period_end', $end, $order, 'claim' );
	}

	/**
	 * Per-type guard: if the resolved start sits inside the configured window
	 * but the underlying order itself is older than that window, fall back to
	 * date_created. This stops late status changes (e.g. years-old "pending"
	 * order moved to "completed" today) from reopening a fresh withdrawal /
	 * claim period that the original contract no longer allows.
	 *
	 * @param string $unit "days" or "months"
	 */
	private function clamp_start_for_period( WC_Order $order, \DateTimeInterface $start, int $amount, string $unit ): \DateTimeImmutable {
		$start_i = $start instanceof \DateTimeImmutable
			? $start
			: \DateTimeImmutable::createFromInterface( $start );

		$created = $order->get_date_created();
		if ( ! $created ) {
			return $start_i;
		}

		$created_i = $created instanceof \DateTimeImmutable
			? $created
			: \DateTimeImmutable::createFromInterface( $created );

		$cutoff = ( new \DateTimeImmutable( 'now' ) )->modify( '-' . $amount . ' ' . $unit );

		if ( $created_i < $cutoff && $start_i > $created_i ) {
			return $created_i;
		}

		return $start_i;
	}

	// =========================================================================
	// Eligibility
	// =========================================================================

	/**
	 * Whether a given line item is eligible for the request type.
	 */
	public function is_item_eligible( WC_Order $order, $item, string $type, ?\DateTimeInterface $now = null ): array {
		$now           ??= new \DateTimeImmutable( 'now' );
		$eligible      = true;
		$reason        = '';
		$line_item_id  = $item->get_id();
		$product       = $this->resolve_meta_product( $item );
		$excluded_meta = $type === 'withdrawal' ? self::META_WITHDRAWAL_EXC : self::META_WARRANTY_EXC;

		if ( $product && $product->get_meta( $excluded_meta ) === 'yes' ) {
			$eligible = false;
			$reason   = $type === 'withdrawal'
				? __( 'Excluded by seller (no withdrawal)', 'wpify-woo' )
				: __( 'Excluded by seller (no warranty)', 'wpify-woo' );
		}

		// Refund check: if all units of this line item are already refunded, the
		// customer no longer holds them — exclude from both withdrawal and claim.
		// $item->get_quantity() reflects the current order state (post manual edits);
		// get_qty_refunded_for_item() returns a negative count (refund line items).
		if ( $eligible ) {
			$ordered_qty  = (int) $item->get_quantity();
			$refunded_qty = abs( (int) $order->get_qty_refunded_for_item( $line_item_id ) );
			if ( $ordered_qty > 0 && $refunded_qty >= $ordered_qty ) {
				$eligible = false;
				$reason   = __( 'Item already refunded', 'wpify-woo' );
			}
		}

		if ( $eligible ) {
			$end = $type === 'withdrawal'
				? $this->withdrawal_period_end_for( $order, $line_item_id )
				: $this->claim_period_end_for( $order, $line_item_id );

			if ( $end < $now ) {
				$eligible = false;
				$reason   = $type === 'withdrawal'
					? __( 'Withdrawal period expired', 'wpify-woo' )
					: __( 'Warranty period expired', 'wpify-woo' );
			}
		}

		$result = array(
			'eligible'     => $eligible,
			'reason'       => $reason,
			'line_item_id' => $line_item_id,
		);

		return apply_filters(
			'wpify_woo_withdrawal_claims_is_eligible_item',
			$result,
			$item,
			$order,
			$type
		);
	}

	/**
	 * @return array{items:array, eligible_count:int, ineligible_count:int}
	 */
	public function get_eligible_items( WC_Order $order, string $type ): array {
		$items           = array();
		$eligible_count  = 0;
		$ineligible_count = 0;
		$now             = new \DateTimeImmutable( 'now' );

		foreach ( $order->get_items() as $line_item_id => $item ) {
			$eligibility   = $this->is_item_eligible( $order, $item, $type, $now );
			$ordered_qty   = (int) $item->get_quantity();
			$refunded_qty  = abs( (int) $order->get_qty_refunded_for_item( $line_item_id ) );
			$available_qty = max( 0, $ordered_qty - $refunded_qty );
			$items[]       = array(
				'item'               => $item,
				'line_item_id'       => $line_item_id,
				'name'               => $item->get_name(),
				'quantity'           => $ordered_qty,
				'available_quantity' => $available_qty,
				'eligible'           => $eligibility['eligible'],
				'reason'             => $eligibility['reason'],
			);
			if ( $eligibility['eligible'] ) {
				$eligible_count ++;
			} else {
				$ineligible_count ++;
			}
		}

		return apply_filters(
			'wpify_woo_withdrawal_claims_eligible_items',
			array(
				'items'            => $items,
				'eligible_count'   => $eligible_count,
				'ineligible_count' => $ineligible_count,
			),
			$order,
			$type
		);
	}

	// =========================================================================
	// Auth (5.10) — split resolve by trust level
	// =========================================================================

	public function resolve_order_by_key( string $order_key ): ?WC_Order {
		$id = wc_get_order_id_by_order_key( $order_key );
		if ( ! $id ) {
			return null;
		}
		$order = wc_get_order( $id );

		return $order instanceof WC_Order ? $order : null;
	}

	public function resolve_order_by_identifier( string $identifier ): ?WC_Order {
		// Internal ID path — accept only when the resolved order's own
		// get_order_number() matches the submitted string. Without this guard
		// a sequential-number plugin's custom number can collide with an
		// unrelated order's internal DB ID and this call would return the
		// wrong order (silent email-mismatch failure downstream).
		if ( ctype_digit( $identifier ) ) {
			$order = wc_get_order( (int) $identifier );
			if ( $order instanceof WC_Order
				&& (string) $order->get_order_number() === $identifier
			) {
				return $order;
			}
		}

		// Built-in WC search — HPOS-aware. Plugins like Sequential Order Numbers
		// for WooCommerce extend it via woocommerce_shop_order_search_fields /
		// woocommerce_cot_shop_order_search_results. Match exactly to avoid
		// partial-substring hits.
		foreach ( wc_order_search( $identifier ) as $id ) {
			$order = wc_get_order( (int) $id );
			if ( $order instanceof WC_Order && (string) $order->get_order_number() === $identifier ) {
				return $order;
			}
		}

		// Tolerant fallback — a stray space or a pasted character (NBSP, '#',
		// dash) shouldn't stop the lookup. Always confirms the order's own number
		// normalizes to the same value, so the collision guard above stays intact.
		$order = $this->resolve_order_by_normalized_identifier( $identifier );
		if ( $order instanceof WC_Order ) {
			return $order;
		}

		// Custom order_number plugins not hooked into WC search.
		return apply_filters( 'wpify_woo_withdrawal_claims_resolve_order', null, $identifier );
	}

	/**
	 * Fallback lookup that tolerates formatting differences in the entered number
	 * (accidental space, NBSP, '#', dash, pasted junk). Safe against collisions:
	 * a candidate is returned only when its own visible number normalizes to the
	 * exact same value as the input.
	 */
	private function resolve_order_by_normalized_identifier( string $identifier ): ?WC_Order {
		$normalized = $this->normalize_order_number( $identifier );
		if ( '' === $normalized ) {
			return null;
		}

		$candidates = array();

		// Purely numeric after normalization — may be the raw order ID (e.g. a
		// formatter that only inserts a space into the DB ID).
		if ( ctype_digit( $normalized ) ) {
			$candidates[] = (int) $normalized;
		}

		// Sequential-number plugins that hook into WC search.
		foreach ( wc_order_search( $normalized ) as $id ) {
			$candidates[] = (int) $id;
		}

		foreach ( array_unique( $candidates ) as $id ) {
			$order = wc_get_order( $id );
			if ( $order instanceof WC_Order
				&& $this->normalize_order_number( (string) $order->get_order_number() ) === $normalized
			) {
				return $order;
			}
		}

		return null;
	}

	/**
	 * Strip everything except letters and digits and uppercase the result, so a
	 * stray separator or pasted character no longer breaks matching. Letters are
	 * kept on purpose — distinct series like "A123" and "B123" must not collide.
	 */
	private function normalize_order_number( string $value ): string {
		return strtoupper( (string) preg_replace( '/[^\p{L}\p{N}]+/u', '', $value ) );
	}

	/**
	 * @return WC_Order|WP_Error
	 */
	public function authorize( array $context ) {
		$order = $this->authorize_internal( $context );
		if ( is_wp_error( $order ) ) {
			return $order;
		}

		if ( ! $this->is_order_eligible_for_request( $order ) ) {
			return new WP_Error(
				'order_status_blocked',
				__( 'This order is not eligible for a withdrawal or claim request.', 'wpify-woo' )
			);
		}

		return $order;
	}

	private function authorize_internal( array $context ) {
		// Logged-in WITH trusted order_id (e.g. My Account flow): ownership check.
		// Without trusted order_id, fall through to ORDER_KEY / 2FA — a logged-in
		// admin filling the public form has user_id but no trusted order context.
		if ( ! empty( $context['user_id'] ) && ! empty( $context['order_id'] ) ) {
			$order = wc_get_order( (int) $context['order_id'] );
			if ( ! $order instanceof WC_Order ) {
				return new WP_Error( 'not_found', __( 'Order not found.', 'wpify-woo' ) );
			}
			if ( (int) $order->get_customer_id() !== (int) $context['user_id'] ) {
				return new WP_Error( 'forbidden', __( 'You do not own this order.', 'wpify-woo' ) );
			}

			return $order;
		}

		// Guest with order_key (trusted token).
		if ( ! empty( $context['order_key'] ) ) {
			$order = $this->resolve_order_by_key( (string) $context['order_key'] );

			return $order ?: new WP_Error( 'not_found', __( 'Order not found.', 'wpify-woo' ) );
		}

		// Logged-in user typed their own order number — ownership grants access
		// without forcing billing-email re-entry (user already authenticated via WP login,
		// and their WP account email may differ from the order's billing email).
		if ( ! empty( $context['user_id'] ) && ! empty( $context['identifier'] ) ) {
			$order = $this->resolve_order_by_identifier( (string) $context['identifier'] );
			if ( $order instanceof WC_Order
				&& (int) $order->get_customer_id() === (int) $context['user_id']
			) {
				return $order;
			}
			// Not the owner — fall through to 2FA so the user must prove access via billing email.
		}

		// Guest 2-factor: identifier + billing email match.
		$identifier = trim( (string) ( $context['identifier'] ?? '' ) );
		$email      = trim( (string) ( $context['submitted_email'] ?? '' ) );

		if ( $identifier === '' || $email === '' ) {
			return new WP_Error( 'missing_credentials', __( 'Please provide order number and email.', 'wpify-woo' ) );
		}

		$order = $this->resolve_order_by_identifier( $identifier );
		if ( ! $order instanceof WC_Order ) {
			return new WP_Error( 'not_found', __( 'Order not found.', 'wpify-woo' ) );
		}
		if ( strcasecmp( (string) $order->get_billing_email(), $email ) !== 0 ) {
			return new WP_Error( 'email_mismatch', __( 'The email does not match the order.', 'wpify-woo' ) );
		}

		return $order;
	}

	/**
	 * Whether the order's current status allows new withdrawal/claim requests.
	 * Refunded / cancelled / failed / draft orders represent dead contracts —
	 * no new requests, no buttons in My Account, no email injection. Existing
	 * stored requests (audit) remain visible in admin regardless.
	 *
	 * Status list is filterable for extensions / custom statuses.
	 */
	public function is_order_eligible_for_request( WC_Order $order ): bool {
		$blocked = apply_filters(
			'wpify_woo_withdrawal_claims_blocked_statuses',
			array( 'refunded', 'cancelled', 'failed', 'checkout-draft', 'auto-draft' ),
			$order
		);

		return ! in_array( (string) $order->get_status(), (array) $blocked, true );
	}

	// =========================================================================
	// Bot protection (5.12)
	// =========================================================================

	public function generate_time_trap_value(): string {
		$ts   = time();
		$hash = hash_hmac( 'sha256', (string) $ts, wp_salt( 'auth' ) );

		return $ts . '|' . $hash;
	}

	public function verify_time_trap( string $value, int $min_seconds = 1 ): bool {
		if ( strpos( $value, '|' ) === false ) {
			return false;
		}
		[ $ts, $hash ] = explode( '|', $value, 2 );
		if ( ! ctype_digit( $ts ) ) {
			return false;
		}
		$expected = hash_hmac( 'sha256', $ts, wp_salt( 'auth' ) );
		if ( ! hash_equals( $expected, $hash ) ) {
			return false;
		}

		return ( time() - (int) $ts ) >= $min_seconds;
	}

	public function is_honeypot_tripped( array $post ): bool {
		// Honeypot field name is intentionally non-email-like to avoid browser
		// autofill (e.g. Chrome filling fields whose name contains "email").
		return ! empty( $post['wpify_woo_url'] );
	}

	// =========================================================================
	// Spam protection
	// =========================================================================

	private function rate_limit_key( string $ip ): string {
		return 'wpify_woo_req_attempts_' . md5( $ip );
	}

	private function get_client_ip(): string {
		// Trust REMOTE_ADDR — proxy parsing is responsibility of host config.
		return isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '0.0.0.0';
	}

	public function check_layer_b_attempts( bool $count = true ): bool {
		$ip        = $this->get_client_ip();
		$key       = $this->rate_limit_key( $ip );
		$raw_max   = $this->get_setting( 'rate_limit_per_ip_hour' );
		$max       = is_numeric( $raw_max ) ? max( 1, (int) $raw_max ) : 10;
		$count_now = (int) get_transient( $key );

		if ( $count_now >= $max ) {
			$this->log->warning( 'Rate limit hit', array( 'ip' => $ip ) );

			return false;
		}

		if ( $count ) {
			set_transient( $key, $count_now + 1, HOUR_IN_SECONDS );
		}

		return true;
	}

	/**
	 * @return true|WP_Error
	 */
	public function check_layer_a( int $order_id ) {
		$raw_max = $this->get_setting( 'max_requests_per_order' );
		$max     = is_numeric( $raw_max ) ? max( 1, (int) $raw_max ) : 5;

		$raw_gap = $this->get_setting( 'min_seconds_between_requests' );
		$gap     = is_numeric( $raw_gap ) ? max( 0, (int) $raw_gap ) : 300;

		if ( $this->repository->count_by_order( $order_id ) >= $max ) {
			return new WP_Error( 'too_many', __( 'You have reached the maximum number of requests for this order.', 'wpify-woo' ) );
		}

		if ( $gap > 0 ) {
			$last = $this->repository->find_last_by_order( $order_id );
			if ( $last && ! empty( $last->submitted_at ) ) {
				$last_ts = (int) mysql2date( 'U', $last->submitted_at );
				if ( $last_ts && ( time() - $last_ts ) < $gap ) {
					return new WP_Error( 'too_fast', __( 'Please wait a bit before submitting another request.', 'wpify-woo' ) );
				}
			}
		}

		return true;
	}

	/**
	 * Reject identical resubmits (same items + reason) on the same order within the
	 * configured window. Different items/reason → passes (genuine new request).
	 *
	 * @return true|WP_Error
	 */
	public function check_duplicate_content( int $order_id, string $request_type, string $scope, array $items, string $reason ) {
		$raw_window = $this->get_setting( 'duplicate_window_hours' );
		$window     = is_numeric( $raw_window ) ? (int) $raw_window : 24;
		if ( $window <= 0 ) {
			return true;
		}

		$hash   = $this->content_fingerprint( $request_type, $scope, $items, $reason );
		$recent = $this->repository->find_recent_by_order( $order_id, $window );

		foreach ( $recent as $row ) {
			$existing_items = json_decode( $row->items_json ?? '[]', true );
			$existing_hash  = $this->content_fingerprint( (string) $row->request_type, (string) $row->scope, is_array( $existing_items ) ? $existing_items : array(), (string) $row->reason );
			if ( hash_equals( $hash, $existing_hash ) ) {
				return new WP_Error( 'duplicate_content', __( 'You have already submitted an identical request for this order. We are processing it.', 'wpify-woo' ) );
			}
		}

		return true;
	}

	/**
	 * Canonical fingerprint — order-independent items, trimmed reason, sorted item rows.
	 *
	 * @param array<int, array{line_item_id:int, quantity:int}> $items
	 */
	private function content_fingerprint( string $request_type, string $scope, array $items, string $reason ): string {
		$normalized_items = array();
		foreach ( $items as $row ) {
			$normalized_items[] = array(
				'line_item_id' => (int) ( $row['line_item_id'] ?? 0 ),
				'quantity'     => (int) ( $row['quantity'] ?? 0 ),
			);
		}
		usort(
			$normalized_items,
			static fn( array $a, array $b ): int => $a['line_item_id'] <=> $b['line_item_id']
		);

		return sha1( wp_json_encode( array(
			'type'   => $request_type,
			'scope'  => $scope,
			'items'  => $normalized_items,
			'reason' => trim( $reason ),
		) ) );
	}

	// =========================================================================
	// Shortcodes
	// =========================================================================

	public function shortcode_withdrawal( $atts = array() ): string {
		return $this->render_shortcode( 'withdrawal' );
	}

	public function shortcode_claim( $atts = array() ): string {
		return $this->render_shortcode( 'claim' );
	}

	private function render_shortcode( string $type ): string {
		// Guard: 5.1 — shortcode is always registered, returns '' when the given
		// functions are disabled (front end). In editor/admin previews show a
		// placeholder so admin sees the block exists and knows why it's empty.
		if ( ! $this->is_active( $type ) ) {
			if ( $this->is_admin_preview_context() ) {
				return $this->render_admin_only_placeholder( $type );
			}

			return '';
		}

		// Filter: form param controls which shortcode renders content on shared page.
		// Display-only read; no state change, nonce not applicable.
		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		$requested_form = isset( $_GET['form'] ) ? sanitize_text_field( wp_unslash( $_GET['form'] ) ) : '';
		// phpcs:enable WordPress.Security.NonceVerification.Recommended
		// If ?form= is present and doesn't match this type, render an empty wrapper (anchor only).
		if ( $requested_form !== '' && $requested_form !== $type ) {
			return sprintf( '<section id="wpify-woo-%s-form" class="wpify-woo-form-empty"></section>', esc_attr( $type ) );
		}

		ob_start();
		do_action( 'wpify_woo_withdrawal_claims_form_before', $type, null );
		$context = $this->build_form_context( $type );
		$this->render_form_template( $context );
		do_action( 'wpify_woo_withdrawal_claims_form_after', $type, $context['order'] ?? null );

		return ob_get_clean();
	}

	/**
	 * True when current request is editor/admin (e.g. ServerSideRender REST call).
	 */
	private function is_admin_preview_context(): bool {
		if ( ! current_user_can( 'edit_posts' ) ) {
			return false;
		}

		return is_admin() || ( defined( 'REST_REQUEST' ) && REST_REQUEST );
	}

	/**
	 * Admin-only placeholder shown in editor when the corresponding functions
	 * are not enabled (page not assigned in settings). Helps admin understand
	 * why the block renders nothing on the front end.
	 */
	private function render_admin_only_placeholder( string $type ): string {
		$settings_url = admin_url( 'admin.php?page=wpify/' . $this->id() );
		$type_label   = $type === 'withdrawal'
			? __( 'withdrawal', 'wpify-woo' )
			: __( 'claim', 'wpify-woo' );

		return sprintf(
			'<div style="padding:14px 16px;border:1px dashed #d63638;background:#fcf0f1;color:#3c434a;font-size:13px;">' .
			'<strong>%1$s</strong> %2$s <a href="%3$s">%4$s</a>' .
			'</div>',
			esc_html__( 'Visible to admins only:', 'wpify-woo' ),
			esc_html( sprintf(
				/* translators: %s: type (withdrawal or claim) */
				__( '%s functions are disabled — assign a page in module settings for this form to render on the front end.', 'wpify-woo' ),
				ucfirst( $type_label )
			) ),
			esc_url( $settings_url ),
			esc_html__( 'Open settings', 'wpify-woo' )
		);
	}

	/**
	 * Build context for form template — pre-fill, current step, errors.
	 */
	private function build_form_context( string $type ): array {
		$context = array(
			'type'           => $type,
			'step'           => 'input', // input | confirm | submitted
			'order'          => null,
			'order_key'      => '',
			'order_number'   => '',
			'name'           => '',
			'email'          => '',
			'reason'         => '',
			'scope'          => $type === 'withdrawal' ? 'whole_order' : 'specific_items',
			'selected_items' => array(),
			'eligible'       => null,
			'errors'         => array(),
			'is_trusted'     => false,
			'allow_input'    => true,
			'has_2fa_locked' => false,
			'submitted'      => false,
			'module'         => $this,
			'extra_fields'   => array(),
		);

		// Display-only pre-fill from URL params; no state change, nonce not applicable.
		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		// Submitted state (from PRG redirect).
		if ( isset( $_GET['submitted'] ) && $_GET['submitted'] === '1' ) {
			$context['step']      = 'submitted';
			$context['submitted'] = true;

			return $context;
		}

		// Pre-fill from URL.
		$order_key = isset( $_GET['order_key'] ) ? sanitize_text_field( wp_unslash( $_GET['order_key'] ) ) : '';
		$order_id  = isset( $_GET['order'] ) ? sanitize_text_field( wp_unslash( $_GET['order'] ) ) : '';
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		// Logged-in scenario.
		if ( is_user_logged_in() ) {
			$user                  = wp_get_current_user();
			$context['name']       = trim( $user->first_name . ' ' . $user->last_name ) ?: $user->display_name;
			$context['email']      = $user->user_email;
			$context['is_trusted'] = true;
		}

		// Trusted: order_key from URL.
		if ( $order_key !== '' ) {
			$order = $this->resolve_order_by_key( $order_key );
			if ( $order ) {
				$context['order']        = $order;
				$context['order_key']    = $order_key;
				$context['order_number'] = $order->get_order_number();
				$context['name']         = $order->get_formatted_billing_full_name() ?: $context['name'];
				$context['email']        = $order->get_billing_email() ?: $context['email'];
				$context['is_trusted']   = true;
			}
		} elseif ( $order_id !== '' ) {
			// Untrusted hint: pre-fill order_number only, no item reveal until validated.
			$context['order_number'] = $order_id;
			$context['has_2fa_locked'] = ! is_user_logged_in() || ! $this->order_belongs_to_current_user( $order_id );
			if ( ! $context['has_2fa_locked'] ) {
				$order = $this->resolve_order_by_identifier( $order_id );
				if ( $order instanceof WC_Order ) {
					$context['order'] = $order;
				}
			}
		}

		// Logged-in viewing My Account-linked order: trusted = ownership matches.
		if ( $context['order'] instanceof WC_Order && is_user_logged_in() ) {
			$context['is_trusted'] = ( (int) $context['order']->get_customer_id() === get_current_user_id() );
		}

		// Pull eligibility for trusted scenarios (so items list can render).
		if ( $context['order'] instanceof WC_Order && $context['is_trusted'] ) {
			$context['eligible'] = $this->get_eligible_items( $context['order'], $type );
		}

		return $context;
	}

	private function order_belongs_to_current_user( string $identifier ): bool {
		if ( ! is_user_logged_in() ) {
			return false;
		}
		$order = $this->resolve_order_by_identifier( $identifier );

		return $order instanceof WC_Order && (int) $order->get_customer_id() === get_current_user_id();
	}

	private function render_form_template( array $context ): void {
		$template = $this->utils->get_plugin_path( 'src/Modules/WithdrawalClaims/templates/request-form.php' );
		if ( ! is_readable( $template ) ) {
			return;
		}
		// phpcs:ignore WordPressVIPMinimum.Files.IncludingFile.UsingVariable
		include $template;
	}

	// =========================================================================
	// Extra fields — schema, sanitization, validation, rendering helpers (SSOT)
	// =========================================================================

	/**
	 * Resolve the schema of extra form fields for a given request type.
	 *
	 * Developers register fields via:
	 *     add_filter( 'wpify_woo_withdrawal_claims_form_fields',
	 *                 function ( array $fields, string $type ) { ... } , 10, 2 );
	 *
	 * Each field is an array:
	 *   - id          (string, required)
	 *   - type        (text|email|tel|textarea|select|checkbox; default: text)
	 *   - label       (string, required)
	 *   - placeholder (string, optional)
	 *   - required    (bool, default false)
	 *   - options     (array of [label, value], required for select)
	 *   - sanitize    (callable, optional — overrides type default)
	 *   - validate    (callable, optional — returns WP_Error|true)
	 *
	 * Invalid entries (missing id/label) are silently dropped.
	 *
	 * @return array<int,array<string,mixed>>
	 */
	public function get_extra_fields_schema( string $type ): array {
		$fields = apply_filters( 'wpify_woo_withdrawal_claims_form_fields', array(), $type );
		if ( ! is_array( $fields ) ) {
			return array();
		}

		$normalized = array();
		foreach ( $fields as $field ) {
			if ( ! is_array( $field ) || empty( $field['id'] ) || empty( $field['label'] ) ) {
				continue;
			}
			$normalized[] = array_merge(
				array(
					'type'        => 'text',
					'placeholder' => '',
					'required'    => false,
					'options'     => array(),
					'sanitize'    => null,
					'validate'    => null,
				),
				$field
			);
		}

		return $normalized;
	}

	/**
	 * Pick raw values for the schema-defined fields out of a source array
	 * ($_POST by default, REST request params for the AJAX submit path).
	 * Sanitization happens per-field in {@see sanitize_extra_field()}.
	 *
	 * @return array<string,mixed> id => sanitized value
	 */
	private function collect_extra_fields_from_post( array $schema, ?array $source = null ): array {
		// Nonce verified in maybe_handle_post() before this runs.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$source    = $source ?? $_POST;
		$collected = array();
		foreach ( $schema as $field ) {
			$id    = (string) $field['id'];
			$raw   = $source[ $id ] ?? null;
			$value = $this->sanitize_extra_field( $field, $raw );

			$collected[ $id ] = $value;
		}

		return $collected;
	}

	/**
	 * Sanitize one extra-field value based on its declared type
	 * (or a custom `sanitize` callable if the schema provides one).
	 *
	 * @param mixed $value
	 * @return mixed
	 */
	private function sanitize_extra_field( array $field, $value ) {
		if ( is_callable( $field['sanitize'] ?? null ) ) {
			return call_user_func( $field['sanitize'], $value );
		}

		if ( $value === null ) {
			return ( $field['type'] ?? 'text' ) === 'checkbox' ? false : '';
		}

		switch ( $field['type'] ?? 'text' ) {
			case 'email':
				return sanitize_email( wp_unslash( (string) $value ) );
			case 'tel':
				return preg_replace( '/[^0-9+\s()-]/', '', (string) wp_unslash( $value ) );
			case 'textarea':
				return sanitize_textarea_field( wp_unslash( (string) $value ) );
			case 'checkbox':
				return ! empty( $value );
			case 'select':
				$allowed = array_column( $field['options'] ?? array(), 'value' );
				$clean   = sanitize_text_field( wp_unslash( (string) $value ) );
				return in_array( $clean, $allowed, true ) ? $clean : '';
			case 'text':
			default:
				return sanitize_text_field( wp_unslash( (string) $value ) );
		}
	}

	/**
	 * Validate collected extra-field values against the schema.
	 * Returns WP_Error on first failure, null when everything passes.
	 *
	 * @param array<string,mixed> $values
	 */
	private function validate_extra_fields( array $schema, array $values ): ?\WP_Error {
		foreach ( $schema as $field ) {
			$id    = (string) $field['id'];
			$value = $values[ $id ] ?? '';

			if ( ! empty( $field['required'] ) ) {
				$empty = ( $field['type'] ?? 'text' ) === 'checkbox' ? ! $value : ( $value === '' || $value === null );
				if ( $empty ) {
					return new \WP_Error(
						'extra_field_required',
						sprintf(
							/* translators: %s: field label */
							__( '%s is required.', 'wpify-woo' ),
							$field['label']
						)
					);
				}
			}

			if ( ( $field['type'] ?? '' ) === 'email' && $value !== '' && ! is_email( $value ) ) {
				return new \WP_Error(
					'extra_field_email',
					sprintf(
						/* translators: %s: field label */
						__( '%s must be a valid email address.', 'wpify-woo' ),
						$field['label']
					)
				);
			}

			if ( is_callable( $field['validate'] ?? null ) ) {
				$result = call_user_func( $field['validate'], $value, $field );
				if ( is_wp_error( $result ) ) {
					return $result;
				}
			}
		}

		return null;
	}

	/**
	 * Render the input HTML for one extra field (used inside the request form).
	 *
	 * Returns just the input element (no row wrapper) — the caller decides
	 * surrounding markup (label, error display, layout class).
	 *
	 * @param mixed $value Current value (pre-fill on validation re-render).
	 */
	public function render_extra_field_input( array $field, $value = '' ): string {
		$id          = esc_attr( $field['id'] );
		$name        = esc_attr( $field['id'] );
		$type        = $field['type'] ?? 'text';
		$placeholder = isset( $field['placeholder'] ) ? esc_attr( $field['placeholder'] ) : '';
		// Always defer required to a data attribute; the form JS promotes it to
		// native `required` once the field row is revealed (whether via /validate
		// reveal or on initial page load when the items section is already shown).
		$required    = ! empty( $field['required'] ) ? ' data-extra-required="1"' : '';

		switch ( $type ) {
			case 'textarea':
				return sprintf(
					'<textarea id="%1$s" name="%2$s" placeholder="%3$s" rows="4"%4$s>%5$s</textarea>',
					$id, $name, $placeholder, $required, esc_textarea( (string) $value )
				);

			case 'checkbox':
				return sprintf(
					'<input type="checkbox" id="%1$s" name="%2$s" value="1"%3$s%4$s>',
					$id, $name, checked( ! empty( $value ), true, false ), $required
				);

			case 'select':
				$options_html = '';
				foreach ( (array) ( $field['options'] ?? array() ) as $opt ) {
					if ( ! isset( $opt['value'], $opt['label'] ) ) {
						continue;
					}
					$options_html .= sprintf(
						'<option value="%1$s"%2$s>%3$s</option>',
						esc_attr( $opt['value'] ),
						selected( (string) $value, (string) $opt['value'], false ),
						esc_html( $opt['label'] )
					);
				}
				return sprintf(
					'<select id="%1$s" name="%2$s"%3$s>%4$s</select>',
					$id, $name, $required, $options_html
				);

			case 'email':
			case 'tel':
			case 'text':
			default:
				return sprintf(
					'<input type="%1$s" id="%2$s" name="%3$s" placeholder="%4$s" value="%5$s"%6$s>',
					esc_attr( $type ),
					$id, $name, $placeholder,
					esc_attr( (string) $value ),
					$required
				);
		}
	}

	/**
	 * Render the display value for one extra field (used on admin detail,
	 * customer my-account, and email templates).
	 *
	 * Returns the value as an escaped HTML/text fragment — no row wrapper.
	 *
	 * @param mixed $value
	 * @param bool  $html  true → safe HTML output, false → plain text (for plain emails)
	 */
	public function render_extra_field_value( array $field, $value, bool $html = true ): string {
		$type = $field['type'] ?? 'text';

		if ( $type === 'checkbox' ) {
			return $value ? __( 'Yes', 'wpify-woo' ) : __( 'No', 'wpify-woo' );
		}

		if ( $type === 'select' ) {
			foreach ( (array) ( $field['options'] ?? array() ) as $opt ) {
				if ( isset( $opt['value'] ) && (string) $opt['value'] === (string) $value ) {
					return $html ? esc_html( $opt['label'] ?? $value ) : (string) ( $opt['label'] ?? $value );
				}
			}
			return $html ? esc_html( (string) $value ) : (string) $value;
		}

		if ( $type === 'textarea' ) {
			return $html ? nl2br( esc_html( (string) $value ) ) : (string) $value;
		}

		return $html ? esc_html( (string) $value ) : (string) $value;
	}

	/**
	 * Decode the JSON column into an array — null/garbage tolerant.
	 *
	 * @return array<string,mixed>
	 */
	public function get_request_extra_fields( WithdrawalClaimsModel $req ): array {
		if ( empty( $req->extra_fields_json ) ) {
			return array();
		}
		$decoded = json_decode( $req->extra_fields_json, true );
		return is_array( $decoded ) ? $decoded : array();
	}

	// =========================================================================
	// POST handler
	// =========================================================================

	public function maybe_handle_post(): void {
		if ( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ?? '' ) ) !== 'POST' ) {
			return;
		}
		if ( empty( $_POST['wpify_woo_request_action'] ) ) {
			return;
		}

		$type = isset( $_POST['wpify_woo_request_type'] ) ? sanitize_text_field( wp_unslash( $_POST['wpify_woo_request_type'] ) ) : '';
		if ( ! in_array( $type, array( 'withdrawal', 'claim' ), true ) ) {
			return;
		}
		if ( ! $this->is_active( $type ) ) {
			wp_die( esc_html__( 'This form is not active.', 'wpify-woo' ), '', array( 'response' => 404 ) );
		}

		$action = sanitize_text_field( wp_unslash( $_POST['wpify_woo_request_action'] ) );

		// Nonce.
		if ( ! isset( $_POST['_wpify_woo_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_wpify_woo_nonce'] ) ), 'wpify_woo_request_' . $type ) ) {
			wp_die( esc_html__( 'Invalid request — security check failed. Please reload the page and try again.', 'wpify-woo' ) );
		}

		nocache_headers();

		// Bot protection — silent rejects.
		if ( $this->is_honeypot_tripped( $_POST ) ) {
			$this->log->warning( 'Honeypot tripped', array() );
			$this->silent_redirect_to_thanks( $type );

			return;
		}
		$ttv = isset( $_POST['_form_render_time'] ) ? sanitize_text_field( wp_unslash( $_POST['_form_render_time'] ) ) : '';
		if ( ! $this->verify_time_trap( $ttv ) ) {
			$this->log->warning( 'Time-trap fail', array() );
			$this->silent_redirect_to_thanks( $type );

			return;
		}

		// Layer B (attempts) — counts even failures.
		if ( ! $this->check_layer_b_attempts() ) {
			wp_die( esc_html__( 'Too many attempts. Please try again later.', 'wpify-woo' ) );
		}

		if ( $action === 'submit' ) {
			$this->handle_submit( $type );

			return;
		}

		// Default = preview/confirm flow handled by re-render in shortcode.
	}

	private function silent_redirect_to_thanks( string $type ): void {
		$url = $this->get_page_url( $type );
		if ( $url ) {
			wp_safe_redirect( add_query_arg( array( 'submitted' => '1', 'form' => $type ), $url ) );
			exit;
		}
		exit;
	}

	private function handle_submit( string $type ): void {
		$input = $this->collect_post_input( $type );

		// No-JS two-step reveal: when the user submits the initial auth-only form
		// (no scope/items rendered yet), this POST has no scope/items. We validate
		// auth and redirect to the form with order_key so the next render shows
		// the items section. Mirrors the AJAX /validate flow for users without JS.
		// Nonce verified in maybe_handle_post() before this runs.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( ! isset( $_POST['scope'] ) && ! isset( $_POST['items'] ) ) {
			$auth_context = array(
				'user_id'         => $input['user_id'],
				'order_key'       => $input['order_key'],
				'order_id'        => $input['order_id'],
				'identifier'      => $input['order_number'],
				'submitted_email' => $input['email'],
			);
			$order = $this->authorize( $auth_context );
			if ( is_wp_error( $order ) ) {
				$this->fail_back_to_form( $type, $order->get_error_message() );

				return;
			}

			$url = $this->get_page_url( $type );
			if ( $url ) {
				wp_safe_redirect( add_query_arg( array(
					'order_key' => $order->get_order_key(),
					'form'      => $type,
				), $url ) );
				exit;
			}
			exit;
		}

		$result = $this->process_submission( $type, $input );

		if ( is_wp_error( $result ) ) {
			$this->fail_back_to_form( $type, $result->get_error_message() );

			return;
		}

		// PRG redirect.
		$url = $this->get_page_url( $type );
		if ( $url ) {
			wp_safe_redirect( add_query_arg( array( 'submitted' => '1', 'form' => $type ), $url ) );
			exit;
		}
		exit;
	}

	/**
	 * Normalize $_POST into a uniform input array used by process_submission().
	 */
	private function collect_post_input( ?string $type = null ): array {
		// Nonce verified in maybe_handle_post() before this runs.
		// phpcs:disable WordPress.Security.NonceVerification.Missing
		$items = array();
		if ( isset( $_POST['items'] ) && is_array( $_POST['items'] ) ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Keys and values are cast to int in the loop body.
			foreach ( (array) wp_unslash( $_POST['items'] ) as $line_item_id => $qty ) {
				$items[ (int) $line_item_id ] = (int) $qty;
			}
		}

		$type   = $type ?: ( isset( $_POST['wpify_woo_request_type'] ) ? sanitize_text_field( wp_unslash( $_POST['wpify_woo_request_type'] ) ) : '' );
		$schema = $type !== '' ? $this->get_extra_fields_schema( $type ) : array();
		$extra  = $schema ? $this->collect_extra_fields_from_post( $schema ) : array();

		return array(
			'user_id'      => is_user_logged_in() ? get_current_user_id() : 0,
			'order_key'    => isset( $_POST['order_key'] ) ? sanitize_text_field( wp_unslash( $_POST['order_key'] ) ) : '',
			'order_id'     => isset( $_POST['order_id_trusted'] ) ? absint( $_POST['order_id_trusted'] ) : 0,
			'order_number' => isset( $_POST['order_number'] ) ? sanitize_text_field( wp_unslash( $_POST['order_number'] ) ) : '',
			'email'        => isset( $_POST['email'] ) ? sanitize_email( wp_unslash( $_POST['email'] ) ) : '',
			'name'         => isset( $_POST['name'] ) ? sanitize_text_field( wp_unslash( $_POST['name'] ) ) : '',
			'scope'        => isset( $_POST['scope'] ) ? sanitize_text_field( wp_unslash( $_POST['scope'] ) ) : 'specific_items',
			'items'        => $items,
			'reason'       => isset( $_POST['reason'] ) ? sanitize_textarea_field( wp_unslash( $_POST['reason'] ) ) : '',
			'extra_fields' => $extra,
		);
		// phpcs:enable WordPress.Security.NonceVerification.Missing
	}

	/**
	 * Full validation + persistence pipeline. Used by both the legacy POST handler
	 * (no-JS fallback) and the REST submit endpoint (AJAX path).
	 *
	 * @return int|WP_Error Request ID on success, WP_Error on validation failure.
	 */
	private function process_submission( string $type, array $input ) {
		// Auth.
		$auth_context = array(
			'user_id'         => (int) ( $input['user_id'] ?? 0 ),
			'order_key'       => (string) ( $input['order_key'] ?? '' ),
			'order_id'        => (int) ( $input['order_id'] ?? 0 ),
			'identifier'      => (string) ( $input['order_number'] ?? '' ),
			'submitted_email' => (string) ( $input['email'] ?? '' ),
		);

		$order = $this->authorize( $auth_context );
		if ( is_wp_error( $order ) ) {
			return $order;
		}

		// Spam protection — Layer A.
		$layer_a = $this->check_layer_a( $order->get_id() );
		if ( is_wp_error( $layer_a ) ) {
			return $layer_a;
		}

		// Scope.
		$scope = (string) ( $input['scope'] ?? 'specific_items' );
		if ( ! in_array( $scope, array( 'whole_order', 'specific_items' ), true ) ) {
			$scope = 'specific_items';
		}

		// Eligibility filter.
		$submitted_quantities = is_array( $input['items'] ?? null ) ? $input['items'] : array();
		$eligible    = $this->get_eligible_items( $order, $type );
		$final_items = array();
		foreach ( $eligible['items'] as $row ) {
			if ( ! $row['eligible'] ) {
				continue;
			}
			$line_item_id = (int) $row['line_item_id'];
			$max_qty      = (int) $row['available_quantity'];

			if ( $scope === 'whole_order' ) {
				$qty = $max_qty;
			} else {
				$qty = isset( $submitted_quantities[ $line_item_id ] ) ? max( 0, min( $max_qty, (int) $submitted_quantities[ $line_item_id ] ) ) : 0;
			}

			if ( $qty > 0 ) {
				$final_items[] = array(
					'line_item_id' => $line_item_id,
					'quantity'     => $qty,
				);
			}
		}

		if ( empty( $final_items ) ) {
			return new WP_Error( 'no_items', __( 'No eligible items selected.', 'wpify-woo' ) );
		}

		// Reason.
		$reason = (string) ( $input['reason'] ?? '' );
		if ( $type === 'claim' && trim( $reason ) === '' ) {
			return new WP_Error( 'reason_required', __( 'Please describe the defect.', 'wpify-woo' ) );
		}

		// Extra fields (developer-defined via `wpify_woo_withdrawal_claims_form_fields`).
		$schema       = $this->get_extra_fields_schema( $type );
		$extra_fields = is_array( $input['extra_fields'] ?? null ) ? $input['extra_fields'] : array();
		if ( $schema ) {
			$validation = $this->validate_extra_fields( $schema, $extra_fields );
			if ( is_wp_error( $validation ) ) {
				return $validation;
			}
		}

		// Spam protection — duplicate content guard (after items + reason resolved).
		$duplicate = $this->check_duplicate_content( $order->get_id(), $type, $scope, $final_items, $reason );
		if ( is_wp_error( $duplicate ) ) {
			return $duplicate;
		}

		// Period_end snapshot — earliest among selected items.
		$period_end = null;
		foreach ( $final_items as $row ) {
			$end = $type === 'withdrawal'
				? $this->withdrawal_period_end_for( $order, $row['line_item_id'] )
				: $this->claim_period_end_for( $order, $row['line_item_id'] );
			if ( $period_end === null || $end < $period_end ) {
				$period_end = $end;
			}
		}

		$now  = current_time( 'mysql', true );
		$name = (string) ( $input['name'] ?? '' );
		if ( $name === '' ) {
			$name = (string) $order->get_formatted_billing_full_name();
		}
		$ip = $this->get_client_ip();
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';

		$data = array(
			'request_type'        => $type,
			'order_id'            => (int) $order->get_id(),
			'order_number'        => (string) $order->get_order_number(),
			'customer_email'      => (string) $order->get_billing_email(),
			'customer_name'       => $name,
			'items_json'          => wp_json_encode( $final_items ),
			'reason'              => $reason,
			'scope'               => $scope,
			'status'              => 'submitted',
			'period_end'          => $period_end ? $period_end->format( 'Y-m-d H:i:s' ) : '',
			'submitted_at'        => $now,
			'customer_ip'         => $ip,
			'customer_user_agent' => substr( $ua, 0, 500 ),
			'created_at'          => $now,
			'extra_fields_json'   => $schema ? (string) wp_json_encode( $extra_fields ) : '',
		);

		$data = apply_filters( 'wpify_woo_withdrawal_claims_request_data', $data, $type );

		try {
			$model = $this->repository->create();
			foreach ( $data as $key => $value ) {
				if ( property_exists( $model, $key ) ) {
					$model->{$key} = $value;
				}
			}
			$saved = $this->repository->save( $model );
		} catch ( \Throwable $e ) {
			$this->log->error( 'Failed to save request', array(
				'order_id' => $order->get_id(),
				'message'  => $e->getMessage(),
			) );

			return new WP_Error( 'save_failed', __( 'Could not save your request. Please try again later.', 'wpify-woo' ) );
		}

		$request_id = (int) ( $saved->id ?? $model->id ?? 0 );

		$this->log->info( 'Request submitted', array(
			'request_id' => $request_id,
			'order_id'   => $order->get_id(),
		) );

		$order->add_order_note( sprintf(
			/* translators: 1: type, 2: request id */
			__( 'WPify Woo: %1$s request submitted (#%2$d).', 'wpify-woo' ),
			$type,
			$request_id
		) );

		do_action( 'wpify_woo_withdrawal_claims_request_created', $request_id, (int) $order->get_id(), $type );

		$this->trigger_emails( $type, $request_id );

		return $request_id;
	}

	private function fail_back_to_form( string $type, string $message ): void {
		// Simple: redirect to form with error param.
		$url = $this->get_page_url( $type );
		if ( $url ) {
			wp_safe_redirect( add_query_arg( array( 'form' => $type, 'wcr_err' => rawurlencode( $message ) ), $url ) );
			exit;
		}
		wp_die( esc_html( $message ) );
	}

	private function trigger_emails( string $type, int $request_id ): void {
		if ( ! function_exists( 'WC' ) || ! WC()->mailer() ) {
			return;
		}

		$emails = WC()->mailer()->get_emails();

		$customer_id = $type === 'withdrawal' ? 'WpifyWooWithdrawalCustomerEmail' : 'WpifyWooClaimCustomerEmail';
		$admin_id    = $type === 'withdrawal' ? 'WpifyWooWithdrawalAdminEmail' : 'WpifyWooClaimAdminEmail';

		if ( isset( $emails[ $customer_id ] ) && method_exists( $emails[ $customer_id ], 'trigger' ) ) {
			$emails[ $customer_id ]->trigger( $request_id );
		}
		if ( isset( $emails[ $admin_id ] ) && method_exists( $emails[ $admin_id ], 'trigger' ) ) {
			$emails[ $admin_id ]->trigger( $request_id );
		}
	}

	// =========================================================================
	// REST API (AJAX flow)
	// =========================================================================

	public function register_rest_routes(): void {
		$ns = 'wpify-woo/v1';

		register_rest_route( $ns, '/withdrawal-claims/validate', array(
			'methods'             => 'POST',
			'permission_callback' => '__return_true',
			'callback'            => array( $this, 'rest_validate' ),
		) );

		register_rest_route( $ns, '/withdrawal-claims/submit', array(
			'methods'             => 'POST',
			'permission_callback' => '__return_true',
			'callback'            => array( $this, 'rest_submit' ),
		) );
	}

	/**
	 * AJAX endpoint #1 — validates auth/order in untrusted scenarios and returns
	 * pre-rendered HTML for the eligibility section so JS can reveal it inline.
	 */
	public function rest_validate( \WP_REST_Request $request ): \WP_REST_Response {
		$params = $request->get_json_params();
		if ( ! is_array( $params ) ) {
			$params = $request->get_params();
		}

		$type = sanitize_text_field( (string) ( $params['wpify_woo_request_type'] ?? $params['type'] ?? '' ) );

		if ( ! in_array( $type, array( 'withdrawal', 'claim' ), true ) ) {
			return new \WP_REST_Response( array( 'ok' => false, 'errors' => array( __( 'Invalid form type.', 'wpify-woo' ) ) ), 400 );
		}
		if ( ! $this->is_active( $type ) ) {
			return new \WP_REST_Response( array( 'ok' => false, 'errors' => array( __( 'This form is not available.', 'wpify-woo' ) ) ), 404 );
		}

		// Nonce.
		if ( ! wp_verify_nonce( (string) ( $params['_wpify_woo_nonce'] ?? '' ), 'wpify_woo_request_' . $type ) ) {
			return new \WP_REST_Response( array( 'ok' => false, 'errors' => array( __( 'Security check failed. Please reload the page.', 'wpify-woo' ) ) ), 403 );
		}

		// Bot protection — for /validate we surface a generic error instead of
		// silent rejection. /validate is non-destructive (no DB writes, no email)
		// and silent failure leaves legit users stuck with an unresponsive form
		// (e.g. when browser autofill triggers the honeypot).
		if ( ! empty( $params['wpify_woo_url'] ) ) {
			$this->log->warning( 'Honeypot tripped (validate)', array() );

			return new \WP_REST_Response( array( 'ok' => false, 'errors' => array( __( 'Please reload the page and try again.', 'wpify-woo' ) ) ), 200 );
		}
		if ( ! $this->verify_time_trap( (string) ( $params['_form_render_time'] ?? '' ) ) ) {
			$this->log->warning( 'Time-trap fail (validate)', array() );

			return new \WP_REST_Response( array( 'ok' => false, 'errors' => array( __( 'Please reload the page and try again.', 'wpify-woo' ) ) ), 200 );
		}

		// Layer B.
		if ( ! $this->check_layer_b_attempts() ) {
			return new \WP_REST_Response( array( 'ok' => false, 'errors' => array( __( 'Too many attempts. Please try again later.', 'wpify-woo' ) ) ), 429 );
		}

		$auth_context = array(
			'user_id'         => is_user_logged_in() ? get_current_user_id() : 0,
			'order_key'       => sanitize_text_field( (string) ( $params['order_key'] ?? '' ) ),
			'order_id'        => isset( $params['order_id_trusted'] ) ? absint( $params['order_id_trusted'] ) : 0,
			'identifier'      => sanitize_text_field( (string) ( $params['order_number'] ?? '' ) ),
			'submitted_email' => sanitize_email( (string) ( $params['email'] ?? '' ) ),
		);

		$order = $this->authorize( $auth_context );
		if ( is_wp_error( $order ) ) {
			return new \WP_REST_Response( array( 'ok' => false, 'errors' => array( $order->get_error_message() ) ), 200 );
		}

		// If the order resolved + email matched but there are zero eligible items,
		// don't lock the form — return a clear error so the user can retry with
		// a different order or contact the merchant.
		$eligibility = $this->get_eligible_items( $order, $type );
		if ( (int) ( $eligibility['eligible_count'] ?? 0 ) === 0 ) {
			$msg = $type === 'withdrawal'
				? __( 'This order has no items eligible for withdrawal (the period may have expired or items are excluded).', 'wpify-woo' )
				: __( 'This order has no items eligible for a claim (the warranty may have expired or items are excluded).', 'wpify-woo' );

			return new \WP_REST_Response( array(
				'ok'     => false,
				'errors' => array( $msg ),
			), 200 );
		}

		return new \WP_REST_Response( array(
			'ok'           => true,
			'items_html'   => $this->render_eligibility_section_html( $order, $type ),
			'order_key'    => (string) $order->get_order_key(),
			'order_number' => (string) $order->get_order_number(),
			'name'         => (string) $order->get_formatted_billing_full_name(),
			'email'        => (string) $order->get_billing_email(),
		), 200 );
	}

	/**
	 * AJAX endpoint #2 — full submission (matches no-JS POST handler behavior).
	 */
	public function rest_submit( \WP_REST_Request $request ): \WP_REST_Response {
		$params = $request->get_json_params();
		if ( ! is_array( $params ) ) {
			$params = $request->get_params();
		}

		$type = sanitize_text_field( (string) ( $params['wpify_woo_request_type'] ?? $params['type'] ?? '' ) );

		if ( ! in_array( $type, array( 'withdrawal', 'claim' ), true ) ) {
			return new \WP_REST_Response( array( 'ok' => false, 'errors' => array( __( 'Invalid form type.', 'wpify-woo' ) ) ), 400 );
		}
		if ( ! $this->is_active( $type ) ) {
			return new \WP_REST_Response( array( 'ok' => false, 'errors' => array( __( 'This form is not available.', 'wpify-woo' ) ) ), 404 );
		}

		if ( ! wp_verify_nonce( (string) ( $params['_wpify_woo_nonce'] ?? '' ), 'wpify_woo_request_' . $type ) ) {
			return new \WP_REST_Response( array( 'ok' => false, 'errors' => array( __( 'Security check failed. Please reload the page.', 'wpify-woo' ) ) ), 403 );
		}

		if ( ! empty( $params['wpify_woo_url'] ) ) {
			$this->log->warning( 'Honeypot tripped (submit)', array() );

			return new \WP_REST_Response( array( 'ok' => true, 'silent' => true, 'message' => __( 'Submitted.', 'wpify-woo' ) ), 200 );
		}
		if ( ! $this->verify_time_trap( (string) ( $params['_form_render_time'] ?? '' ) ) ) {
			$this->log->warning( 'Time-trap fail (submit)', array() );

			return new \WP_REST_Response( array( 'ok' => true, 'silent' => true, 'message' => __( 'Submitted.', 'wpify-woo' ) ), 200 );
		}

		if ( ! $this->check_layer_b_attempts() ) {
			return new \WP_REST_Response( array( 'ok' => false, 'errors' => array( __( 'Too many attempts. Please try again later.', 'wpify-woo' ) ) ), 429 );
		}

		$items = array();
		if ( isset( $params['items'] ) && is_array( $params['items'] ) ) {
			foreach ( $params['items'] as $line_item_id => $qty ) {
				$items[ (int) $line_item_id ] = (int) $qty;
			}
		}

		$schema = $this->get_extra_fields_schema( $type );
		$extra  = $schema ? $this->collect_extra_fields_from_post( $schema, $params ) : array();

		$input = array(
			'user_id'      => is_user_logged_in() ? get_current_user_id() : 0,
			'order_key'    => sanitize_text_field( (string) ( $params['order_key'] ?? '' ) ),
			'order_id'     => isset( $params['order_id_trusted'] ) ? absint( $params['order_id_trusted'] ) : 0,
			'order_number' => sanitize_text_field( (string) ( $params['order_number'] ?? '' ) ),
			'email'        => sanitize_email( (string) ( $params['email'] ?? '' ) ),
			'name'         => sanitize_text_field( (string) ( $params['name'] ?? '' ) ),
			'scope'        => sanitize_text_field( (string) ( $params['scope'] ?? 'specific_items' ) ),
			'items'        => $items,
			'reason'       => sanitize_textarea_field( (string) ( $params['reason'] ?? '' ) ),
			'extra_fields' => $extra,
		);

		$result = $this->process_submission( $type, $input );

		if ( is_wp_error( $result ) ) {
			return new \WP_REST_Response( array( 'ok' => false, 'errors' => array( $result->get_error_message() ) ), 200 );
		}

		return new \WP_REST_Response( array(
			'ok'      => true,
			'message' => __( 'Your request has been submitted. A confirmation email has been sent to you.', 'wpify-woo' ),
		), 200 );
	}

	// =========================================================================
	// Frontend asset enqueue
	// =========================================================================

	public function maybe_enqueue_frontend(): void {
		if ( ! is_singular( 'page' ) ) {
			return;
		}
		$id  = get_queried_object_id();
		$wid = (int) $this->get_setting( 'withdrawal_page_id' );
		$cid = (int) $this->get_setting( 'claim_page_id' );
		if ( $id !== $wid && $id !== $cid ) {
			return;
		}

		$asset_file = $this->utils->get_plugin_path( 'build/withdrawal-claims-frontend.asset.php' );
		$version    = '1.0.0';
		if ( file_exists( $asset_file ) ) {
			$asset   = include $asset_file;
			$version = $asset['version'] ?? $version;
		}

		wp_register_script(
			'wpify-woo-withdrawal-claims-frontend',
			$this->utils->get_plugin_url( 'build/withdrawal-claims-frontend.js' ),
			array(),
			$version,
			true
		);

		wp_localize_script(
			'wpify-woo-withdrawal-claims-frontend',
			'wpifyWooWcrConfig',
			array(
				'restUrl'   => esc_url_raw( rest_url( 'wpify-woo/v1/withdrawal-claims' ) ),
				'restNonce' => wp_create_nonce( 'wp_rest' ),
				'i18n'      => array(
					'networkError' => __( 'Network error. Please try again.', 'wpify-woo' ),
					'loading'      => __( 'Working…', 'wpify-woo' ),
					'genericError' => __( 'Something went wrong. Please try again.', 'wpify-woo' ),
				),
			)
		);

		wp_enqueue_script( 'wpify-woo-withdrawal-claims-frontend' );
	}

	// =========================================================================
	// Eligibility section rendering (shared by template + REST validate)
	// =========================================================================

	/**
	 * Renders the items + scope + period info HTML. Used by the form template
	 * (initial render for trusted scenarios) and the REST validate endpoint
	 * (revealing items inline after AJAX auth in untrusted scenarios).
	 */
	public function render_eligibility_section_html( WC_Order $order, string $type ): string {
		$eligible      = $this->get_eligible_items( $order, $type );
		$any_eligible  = $eligible['eligible_count'] > 0;
		$any_inelig    = $eligible['ineligible_count'] > 0;
		$default_scope = $type === 'withdrawal' ? 'whole_order' : 'specific_items';
		$now           = new \DateTimeImmutable( 'now' );

		ob_start();

		// Period info / no-eligible early return.
		if ( ! $any_eligible ) {
			?>
			<p class="woocommerce-info"><?php esc_html_e( 'No eligible items in this order.', 'wpify-woo' ); ?></p>
			<?php

			return ob_get_clean();
		}

		if ( $type === 'withdrawal' ) {
			$end = $this->withdrawal_period_end_for( $order );
			if ( $end >= $now ) {
				?>
				<p>
					<?php
					/* translators: %s: date */
					printf( esc_html__( 'Withdrawal period ends on %s.', 'wpify-woo' ), esc_html( wp_date( wc_date_format(), $end->getTimestamp() ) ) );
					?>
				</p>
				<?php
			}
		} else {
			$end = $this->claim_period_end_for( $order );
			?>
			<p>
				<?php
				/* translators: %s: date */
				printf( esc_html__( 'Warranty valid until %s.', 'wpify-woo' ), esc_html( wp_date( wc_date_format(), $end->getTimestamp() ) ) );
				?>
			</p>
			<?php
		}

		if ( $any_inelig ) {
			?>
			<div class="woocommerce-info" role="alert">
				<?php
				$inelig_count = (int) $eligible['ineligible_count'];
				printf(
					esc_html(
						/* translators: %d: number of items */
						_n(
							'%d item is not eligible and will not be included.',
							'%d items are not eligible and will not be included.',
							$inelig_count,
							'wpify-woo'
						)
					),
					(int) $inelig_count
				);
				?>
			</div>
			<?php
		}

		$items_hidden = $default_scope === 'whole_order';
		?>
		<fieldset class="form-row form-row-wide wpify-woo-scope">
			<legend><?php esc_html_e( 'Scope', 'wpify-woo' ); ?></legend>
			<label>
				<input type="radio" name="scope" value="whole_order" <?php checked( $default_scope, 'whole_order' ); ?>>
				<?php
				echo esc_html(
					sprintf(
						/* translators: %d: number of eligible items */
						_n( 'Whole order (all %d eligible item)', 'Whole order (all %d eligible items)', (int) $eligible['eligible_count'], 'wpify-woo' ),
						(int) $eligible['eligible_count']
					)
				);
				?>
			</label><br>
			<label>
				<input type="radio" name="scope" value="specific_items" <?php checked( $default_scope, 'specific_items' ); ?>>
				<?php esc_html_e( 'Specific items', 'wpify-woo' ); ?>
			</label>
		</fieldset>

		<fieldset class="form-row form-row-wide wpify-woo-items"<?php echo $items_hidden ? ' hidden' : ''; ?>>
			<legend><?php esc_html_e( 'Items', 'wpify-woo' ); ?></legend>
			<table class="shop_table">
				<thead>
				<tr>
					<th></th>
					<th><?php esc_html_e( 'Item', 'wpify-woo' ); ?></th>
					<th><?php esc_html_e( 'Quantity', 'wpify-woo' ); ?></th>
				</tr>
				</thead>
				<tbody>
				<?php foreach ( $eligible['items'] as $row ) :
					$lid           = (int) $row['line_item_id'];
					$available_qty = (int) $row['available_quantity'];
					$ordered_qty   = (int) $row['quantity'];
					$is_one        = $available_qty === 1;
					$is_elig       = (bool) $row['eligible'];
					$reason        = (string) $row['reason'];
					?>
					<tr>
						<td>
							<?php if ( $is_one ) : ?>
								<input type="checkbox"
									   name="items[<?php echo (int) $lid; ?>]"
									   value="1"
									   <?php disabled( ! $is_elig ); ?>
									   <?php echo ! $is_elig ? 'aria-describedby="reason-' . esc_attr( $lid ) . '"' : ''; ?>>
							<?php else : ?>
								<input type="number"
									   name="items[<?php echo (int) $lid; ?>]"
									   value="0"
									   min="0"
									   max="<?php echo (int) $available_qty; ?>"
									   <?php disabled( ! $is_elig ); ?>
									   <?php echo ! $is_elig ? 'aria-describedby="reason-' . esc_attr( $lid ) . '"' : ''; ?>>
							<?php endif; ?>
						</td>
						<td>
							<?php echo esc_html( $row['name'] ); ?>
							<?php if ( ! $is_elig ) : ?>
								<small id="reason-<?php echo esc_attr( $lid ); ?>" style="display:block;color:#b32d2e;">
									<?php echo esc_html( $reason ); ?>
								</small>
							<?php endif; ?>
						</td>
						<td>
							<?php
							if ( $is_one ) {
								esc_html_e( '1 (full)', 'wpify-woo' );
							} elseif ( $available_qty !== $ordered_qty ) {
								/* translators: %d: number of units still available for return after refunds */
								printf( esc_html__( 'of %d available', 'wpify-woo' ), (int) $available_qty );
							} else {
								/* translators: %d: ordered quantity */
								printf( esc_html__( 'of %d ordered', 'wpify-woo' ), (int) $ordered_qty );
							}
							?>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
		</fieldset>
		<?php

		return ob_get_clean();
	}

	// =========================================================================
	// Email registration & injection
	// =========================================================================

	public function register_emails( array $email_classes ): array {
		if ( $this->is_active( 'withdrawal' ) ) {
			$email_classes['WpifyWooWithdrawalCustomerEmail'] = new CustomerWithdrawalEmail( $this->repository, $this->utils );
			$email_classes['WpifyWooWithdrawalAdminEmail']    = new AdminWithdrawalEmail( $this->repository, $this->utils );
		}
		if ( $this->is_active( 'claim' ) ) {
			$email_classes['WpifyWooClaimCustomerEmail'] = new CustomerClaimEmail( $this->repository, $this->utils );
			$email_classes['WpifyWooClaimAdminEmail']    = new AdminClaimEmail( $this->repository, $this->utils );
		}

		return $email_classes;
	}

	public function inject_link_in_emails( $order, $sent_to_admin, $plain_text, $email ): void {
		if ( ! $this->is_active( 'withdrawal' ) || ! $order instanceof WC_Order || $plain_text || $sent_to_admin ) {
			return;
		}
		if ( ! $email || ! is_a( $email, 'WC_Email' ) ) {
			return;
		}
		if ( ! $this->is_order_eligible_for_request( $order ) ) {
			return;
		}

		$selected = (array) $this->get_setting( 'inject_link_in_emails' );
		$selected = apply_filters( 'wpify_woo_withdrawal_claims_inject_link_emails', $selected );
		if ( ! in_array( $email->id, $selected, true ) ) {
			return;
		}

		$page_url = $this->get_page_url( 'withdrawal' );
		if ( ! $page_url ) {
			return;
		}

		// Render only if at least one item is still eligible.
		$eligible = $this->get_eligible_items( $order, 'withdrawal' );
		if ( $eligible['eligible_count'] === 0 ) {
			return;
		}

		$link = add_query_arg(
			array(
				'order_key' => $order->get_order_key(),
				'form'      => 'withdrawal',
			),
			$page_url
		) . '#wpify-woo-withdrawal-form';

		$button_text = $this->get_setting( 'withdrawal_button_text' ) ?: __( 'Withdraw from contract', 'wpify-woo' );
		$heading     = $this->get_setting( 'inject_link_heading' ) ?: __( 'Need to withdraw from this contract?', 'wpify-woo' );
		$description = $this->get_setting( 'inject_link_description' ) ?: __( 'Use the link below to start the withdrawal process online.', 'wpify-woo' );
		$base_color  = get_option( 'woocommerce_email_base_color', '#7f54b3' );
		?>
		<style>
			.wpify-woo-withdrawal-link {
				display: inline-block;
				padding: 10px 20px;
				border-radius: 5px;
				background-color: <?php echo esc_attr( $base_color ); ?>;
				color: #ffffff;
				text-decoration: none;
				font-weight: bold;
			}
			.wpify-woo-withdrawal-link:hover {
				opacity: 0.8;
			}
		</style>
		<section class="wpify-woo-withdrawal-link-section">
			<h2><?php echo esc_html( $heading ); ?></h2>
			<p><?php echo esc_html( $description ); ?></p>
			<p>
				<a class="wpify-woo-withdrawal-link woocommerce-button button" href="<?php echo esc_url( $link ); ?>">
					<?php echo esc_html( $button_text ); ?>
				</a>
			</p>
		</section>
		<?php
	}

	// =========================================================================
	// My Account integration
	// =========================================================================

	/**
	 * Add withdrawal/claim entries to the native order actions array
	 * (woocommerce_my_account_my_orders_actions filter). The same filter feeds
	 * both the My Account → Orders list AND the order detail view (via
	 * templates/order/order-details.php), so we restrict our entries to the
	 * detail view only — the list would be visual clutter.
	 *
	 * Gating:
	 *  - only on view-order endpoint (detail page)
	 *  - is_active() per type (master switch)
	 *  - is_order_eligible_for_request() (status not refunded/cancelled/failed/draft)
	 *  - at least one eligible item
	 *
	 * @param array     $actions Default WC actions.
	 * @param \WC_Order $order   Order being rendered.
	 */
	public function add_my_orders_actions( array $actions, $order ): array {
		// Skip on My Account → Orders list — buttons appear only on the order detail.
		if ( ! is_wc_endpoint_url( 'view-order' ) ) {
			return $actions;
		}
		if ( ! $order instanceof WC_Order ) {
			return $actions;
		}
		if ( ! $this->is_order_eligible_for_request( $order ) ) {
			return $actions;
		}

		foreach ( array( 'withdrawal', 'claim' ) as $type ) {
			if ( ! $this->is_active( $type ) ) {
				continue;
			}
			$page_url = $this->get_page_url( $type );
			if ( ! $page_url ) {
				continue;
			}
			$elig = $this->get_eligible_items( $order, $type );
			if ( (int) $elig['eligible_count'] === 0 ) {
				continue;
			}

			$default_text = $type === 'withdrawal'
				? ( $this->get_setting( 'withdrawal_button_text' ) ?: __( 'Withdraw from contract', 'wpify-woo' ) )
				: ( $this->get_setting( 'claim_button_text' ) ?: __( 'File a claim', 'wpify-woo' ) );

			$args = apply_filters( 'wpify_woo_withdrawal_claims_my_account_button_args', array(
				'text' => $default_text,
				'url'  => add_query_arg( array(
					'order_key' => $order->get_order_key(),
					'form'      => $type,
				), $page_url ) . '#wpify-woo-' . $type . '-form',
				'type' => $type,
			), $order, $type );

			if ( ! empty( $args['url'] ) ) {
				$actions[ 'wpify_' . $type ] = array(
					'url'  => $args['url'],
					'name' => $args['text'],
				);
			}
		}

		return $actions;
	}

	/**
	 * Render the "Submitted requests" history below customer details (read path
	 * — always visible if any requests exist, even when the order is later moved
	 * to refunded/cancelled).
	 *
	 * @param \WC_Order $order
	 */
	public function render_my_account_history( $order ): void {
		if ( ! $order instanceof WC_Order ) {
			return;
		}

		$existing = $this->repository->find_by_order( (int) $order->get_id() );
		if ( empty( $existing ) ) {
			return;
		}

		echo '<section class="wpify-woo-my-account-submitted" style="margin-top:1.5em;">';
		echo '<h2>' . esc_html__( 'Submitted requests', 'wpify-woo' ) . '</h2>';
		echo '<table class="shop_table"><thead><tr><th>' . esc_html__( 'Date', 'wpify-woo' ) . '</th><th>' . esc_html__( 'Type', 'wpify-woo' ) . '</th><th>' . esc_html__( 'Items', 'wpify-woo' ) . '</th></tr></thead><tbody>';
		foreach ( $existing as $req ) {
			$decoded = json_decode( $req->items_json, true );
			$count   = is_array( $decoded ) ? count( $decoded ) : 0;
			printf(
				'<tr><td>%s</td><td>%s</td><td>%d</td></tr>',
				esc_html( $req->submitted_at ? wp_date( wc_date_format() . ' ' . wc_time_format(), strtotime( $req->submitted_at ) ) : '' ),
				esc_html( $req->type_label() ),
				(int) $count
			);

			// Render developer-defined extra fields (e.g., IBAN) as a sub-row.
			$extra_schema = $this->get_extra_fields_schema( $req->request_type );
			$extra_values = $this->get_request_extra_fields( $req );
			$extra_lines  = array();
			foreach ( $extra_schema as $extra_field ) {
				$value = $extra_values[ $extra_field['id'] ] ?? '';
				if ( $value === '' || $value === null || $value === false ) {
					continue;
				}
				$extra_lines[] = sprintf(
					'<strong>%s:</strong> %s',
					esc_html( $extra_field['label'] ),
					$this->render_extra_field_value( $extra_field, $value ) // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- helper escapes internally
				);
			}
			if ( $extra_lines ) {
				printf(
					'<tr><td colspan="3"><small>%s</small></td></tr>',
					implode( ' &nbsp;·&nbsp; ', $extra_lines ) // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				);
			}
		}
		echo '</tbody></table></section>';
	}

	// =========================================================================
	// Caching headers
	// =========================================================================

	public function maybe_disable_caching(): void {
		if ( ! is_singular( 'page' ) ) {
			return;
		}
		$id = get_queried_object_id();
		if ( ! $id ) {
			return;
		}
		$wid = (int) $this->get_setting( 'withdrawal_page_id' );
		$cid = (int) $this->get_setting( 'claim_page_id' );
		if ( $id !== $wid && $id !== $cid ) {
			return;
		}
		if ( ! defined( 'DONOTCACHEPAGE' ) ) {
			// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- WordPress caching-plugin standard constant.
			define( 'DONOTCACHEPAGE', true );
		}
		nocache_headers();
	}

	// =========================================================================
	// Admin: menu + list table + metabox
	// =========================================================================

	public function register_admin_menu(): void {
		add_submenu_page(
			'woocommerce',
			__( 'Withdrawals & Claims', 'wpify-woo' ),
			__( 'Withdrawals & Claims', 'wpify-woo' ),
			'manage_woocommerce',
			self::ADMIN_PAGE_SLUG,
			array( $this, 'render_admin_page' )
		);
	}

	public function render_admin_page(): void {
		if ( ! current_user_can( 'manage_woocommerce' ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'wpify-woo' ) );
		}

		// Detail view? Display-only admin read; capability checked above, nonce not applicable.
		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['request_id'] ) ) {
			$this->render_admin_detail( (int) $_GET['request_id'] );

			return;
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		echo '<div class="wrap">';
		echo '<h1>' . esc_html__( 'Withdrawals & Claims', 'wpify-woo' ) . '</h1>';

		$table = new RequestsListTable( $this->repository );
		$table->prepare_items();
		echo '<form method="get">';
		echo '<input type="hidden" name="page" value="' . esc_attr( self::ADMIN_PAGE_SLUG ) . '">';
		$table->search_box( __( 'Search requests', 'wpify-woo' ), 'wpify_woo_search' );
		$table->display();
		echo '</form>';
		echo '</div>';
	}

	private function render_admin_detail( int $request_id ): void {
		$rows = $this->repository->find( array( 'where' => array( 'id' => $request_id ) ) );
		$req  = $rows[0] ?? null;
		if ( ! $req ) {
			echo '<div class="wrap"><h1>' . esc_html__( 'Request not found', 'wpify-woo' ) . '</h1></div>';

			return;
		}

		if ( isset( $_POST['wpify_woo_save_note'] ) && current_user_can( 'manage_woocommerce' ) ) {
			check_admin_referer( 'wpify_woo_save_request_note_' . $req->id, '_wpify_woo_note_nonce' );
			$req->admin_note = isset( $_POST['wpify_woo_admin_note'] ) ? sanitize_textarea_field( wp_unslash( $_POST['wpify_woo_admin_note'] ) ) : '';
			$this->repository->save( $req );
		}

		$order = wc_get_order( $req->order_id );

		echo '<div class="wrap">';
		/* translators: %d: request ID */
		echo '<h1>' . esc_html( sprintf( __( 'Request #%d', 'wpify-woo' ), $req->id ) ) . '</h1>';
		echo '<p><a href="' . esc_url( admin_url( 'admin.php?page=' . self::ADMIN_PAGE_SLUG ) ) . '">&larr; ' . esc_html__( 'Back to list', 'wpify-woo' ) . '</a></p>';

		$datetime_format = wc_date_format() . ' ' . wc_time_format();

		echo '<table class="form-table"><tbody>';
		printf( '<tr><th>%s</th><td>%s</td></tr>', esc_html__( 'Type', 'wpify-woo' ), esc_html( $req->type_label() ) );
		printf( '<tr><th>%s</th><td>%s</td></tr>', esc_html__( 'Submitted at', 'wpify-woo' ), esc_html( $req->submitted_at ? wp_date( $datetime_format, strtotime( $req->submitted_at ) ) : '' ) );
		printf( '<tr><th>%s</th><td>%s</td></tr>', esc_html__( 'Status', 'wpify-woo' ), esc_html( $req->status_label() ) );
		if ( $order ) {
			printf( '<tr><th>%s</th><td><a href="%s">#%s</a></td></tr>', esc_html__( 'Order', 'wpify-woo' ), esc_url( $order->get_edit_order_url() ), esc_html( $req->order_number ) );
		} else {
			printf( '<tr><th>%s</th><td>%s</td></tr>', esc_html__( 'Order', 'wpify-woo' ), esc_html( $req->order_number ) );
		}
		printf( '<tr><th>%s</th><td>%s</td></tr>', esc_html__( 'Customer', 'wpify-woo' ), esc_html( $req->customer_name . ' <' . $req->customer_email . '>' ) );
		printf( '<tr><th>%s</th><td>%s</td></tr>', esc_html__( 'Period end (at submission)', 'wpify-woo' ), esc_html( $req->period_end ? wp_date( $datetime_format, strtotime( $req->period_end ) ) : '' ) );
		printf( '<tr><th>%s</th><td>%s</td></tr>', esc_html__( 'Scope', 'wpify-woo' ), esc_html( $req->scope_label() ) );
		printf( '<tr><th>%s</th><td>%s</td></tr>', esc_html__( 'Reason', 'wpify-woo' ), nl2br( esc_html( $req->reason ) ) );

		// Developer-defined extra fields captured at submission.
		$extra_schema = $this->get_extra_fields_schema( $req->request_type );
		$extra_values = $this->get_request_extra_fields( $req );
		foreach ( $extra_schema as $extra_field ) {
			$value = $extra_values[ $extra_field['id'] ] ?? '';
			if ( $value === '' || $value === null || $value === false ) {
				continue;
			}
			printf(
				'<tr><th>%s</th><td>%s</td></tr>',
				esc_html( $extra_field['label'] ),
				$this->render_extra_field_value( $extra_field, $value ) // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- helper escapes internally
			);
		}

		echo '</tbody></table>';

		echo '<h2>' . esc_html__( 'Note', 'wpify-woo' ) . '</h2>';
		echo '<form method="post">';
		wp_nonce_field( 'wpify_woo_save_request_note_' . $req->id, '_wpify_woo_note_nonce' );
		echo '<textarea name="wpify_woo_admin_note" rows="4" class="large-text" placeholder="' . esc_attr__( 'Internal note (e.g. processed, awaiting refund, exchange…). Not visible to the customer.', 'wpify-woo' ) . '">' . esc_textarea( $req->admin_note ) . '</textarea>';
		echo '<p>';
		submit_button( __( 'Save note', 'wpify-woo' ), 'secondary', 'wpify_woo_save_note', false );
		echo '</p>';
		echo '</form>';

		// Items
		$decoded = json_decode( $req->items_json, true );
		if ( is_array( $decoded ) ) {
			echo '<h2>' . esc_html__( 'Items', 'wpify-woo' ) . '</h2>';
			echo '<table class="widefat striped"><thead><tr><th>' . esc_html__( 'Item', 'wpify-woo' ) . '</th><th>' . esc_html__( 'Quantity', 'wpify-woo' ) . '</th></tr></thead><tbody>';
			foreach ( $decoded as $row ) {
				$line_item_id = (int) ( $row['line_item_id'] ?? 0 );
				$qty          = (int) ( $row['quantity'] ?? 0 );
				/* translators: %d: order line item number */
				$name         = sprintf( __( 'Item no longer in order (line #%d)', 'wpify-woo' ), $line_item_id );
				if ( $order ) {
					$item = $order->get_item( $line_item_id );
					if ( $item ) {
						$name = $item->get_name();
					}
				}
				printf( '<tr><td>%s</td><td>%d</td></tr>', esc_html( $name ), (int) $qty );
			}
			echo '</tbody></table>';
			echo '<p><em>' . esc_html__( 'Item names/prices are read live from the order. Full historical change log is in the WC order notes.', 'wpify-woo' ) . '</em></p>';
		}

		echo '<p><strong>IP:</strong> ' . esc_html( $req->customer_ip ) . '<br>';
		echo '<strong>UA:</strong> ' . esc_html( $req->customer_user_agent ) . '</p>';

		echo '</div>';
	}

	public function register_admin_metabox( $screen_id, $post_or_order ): void {
		// Register on both legacy and HPOS screens.
		$valid_screens = array( 'shop_order', 'woocommerce_page_wc-orders' );
		if ( ! in_array( $screen_id, $valid_screens, true ) ) {
			return;
		}

		add_meta_box(
			'wpify_woo_requests_metabox',
			__( 'Withdrawal & Claim Requests', 'wpify-woo' ),
			array( $this, 'render_admin_metabox' ),
			$screen_id,
			'side',
			'default'
		);
	}

	public function render_admin_metabox( $post_or_order ): void {
		$order = $post_or_order instanceof WC_Order
			? $post_or_order
			: ( isset( $post_or_order->ID ) ? wc_get_order( $post_or_order->ID ) : null );

		if ( ! $order instanceof WC_Order ) {
			return;
		}

		$requests = $this->repository->find_by_order( (int) $order->get_id() );

		if ( empty( $requests ) ) {
			echo '<p><em>' . esc_html__( 'No requests submitted.', 'wpify-woo' ) . '</em></p>';

			return;
		}

		?>
		<table class="widefat striped" style="margin:0;">
			<thead>
			<tr>
				<th><?php esc_html_e( 'Date', 'wpify-woo' ); ?></th>
				<th><?php esc_html_e( 'Type', 'wpify-woo' ); ?></th>
				<th style="text-align:center;"><?php esc_html_e( 'Items', 'wpify-woo' ); ?></th>
				<th></th>
			</tr>
			</thead>
			<tbody>
			<?php foreach ( $requests as $req ) :
				$decoded = json_decode( $req->items_json, true );
				$count   = is_array( $decoded ) ? count( $decoded ) : 0;
				$url     = add_query_arg(
					array( 'page' => self::ADMIN_PAGE_SLUG, 'request_id' => $req->id ),
					admin_url( 'admin.php' )
				);
				?>
				<tr>
					<td><?php echo esc_html( $req->submitted_at ? wp_date( wc_date_format() . ' ' . wc_time_format(), strtotime( $req->submitted_at ) ) : '' ); ?></td>
					<td><?php echo esc_html( $req->type_label() ); ?></td>
					<td style="text-align:center;"><?php echo (int) $count; ?></td>
					<td><a href="<?php echo esc_url( $url ); ?>"><?php esc_html_e( 'View', 'wpify-woo' ); ?> →</a></td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
		<p style="margin: 12px 0 0;"><small><?php esc_html_e( 'Full order change history is in WC order notes below.', 'wpify-woo' ); ?></small></p>
		<?php
	}

	// =========================================================================
	// Orders list column (legacy + HPOS)
	// =========================================================================

	/**
	 * Add a "Requests" column to the WC orders list. Same callback works for
	 * legacy `manage_edit-shop_order_columns` and HPOS
	 * `manage_woocommerce_page_wc-orders_columns` filters.
	 */
	public function add_orders_list_column( array $columns ): array {
		// Insert after order_status if present, otherwise append.
		$inserted = array();
		foreach ( $columns as $key => $label ) {
			$inserted[ $key ] = $label;
			if ( $key === 'order_status' ) {
				$inserted['wpify_woo_requests'] = esc_html__( 'Withdrawals & Claims', 'wpify-woo' );
			}
		}

		if ( ! isset( $inserted['wpify_woo_requests'] ) ) {
			$inserted['wpify_woo_requests'] = esc_html__( 'Withdrawals & Claims', 'wpify-woo' );
		}

		return $inserted;
	}

	/**
	 * Render the cell for the "Requests" column. Handles both legacy (post ID)
	 * and HPOS (WC_Order object) signatures.
	 *
	 * @param string                $column        Column key.
	 * @param int|\WC_Order|\WP_Post $post_or_order Order ID, WC_Order, or WP_Post.
	 */
	public function render_orders_list_column( string $column, $post_or_order ): void {
		if ( $column !== 'wpify_woo_requests' ) {
			return;
		}

		if ( $post_or_order instanceof WC_Order ) {
			$order_id = (int) $post_or_order->get_id();
		} elseif ( is_numeric( $post_or_order ) ) {
			$order_id = (int) $post_or_order;
		} elseif ( isset( $post_or_order->ID ) ) {
			$order_id = (int) $post_or_order->ID;
		} else {
			return;
		}

		$requests = $this->repository->find_by_order( $order_id );

		if ( empty( $requests ) ) {
			echo '<span aria-hidden="true">—</span>';

			return;
		}

		echo '<ul style="margin:0;padding:0;list-style:none;font-size:11px;line-height:1.6;">';
		foreach ( $requests as $req ) {
			$url = add_query_arg(
				array( 'page' => self::ADMIN_PAGE_SLUG, 'request_id' => $req->id ),
				admin_url( 'admin.php' )
			);
			$date_str = $req->submitted_at ? wp_date( wc_date_format(), strtotime( $req->submitted_at ) ) : '';

			printf(
				'<li><a href="%1$s"><strong>#%2$d</strong></a> %3$s · %4$s</li>',
				esc_url( $url ),
				(int) $req->id,
				esc_html( $req->type_label() ),
				esc_html( $date_str )
			);
		}
		echo '</ul>';
	}

	// =========================================================================
	// Per-product meta tab
	// =========================================================================

	public function add_product_data_tab( array $tabs ): array {
		$tabs['wpify_woo_wc_requests'] = array(
			'label'    => __( 'Withdrawal & Claim', 'wpify-woo' ),
			'target'   => 'wpify_woo_wc_requests_data',
			'class'    => array(),
			'priority' => 70,
		);

		return $tabs;
	}

	public function render_product_data_panel(): void {
		global $post;
		?>
		<div id="wpify_woo_wc_requests_data" class="panel woocommerce_options_panel">
			<?php
			woocommerce_wp_checkbox( array(
				'id'          => self::META_WITHDRAWAL_EXC,
				'label'       => __( 'Excluded from withdrawal', 'wpify-woo' ),
				'description' => __( 'Customer cannot withdraw from contract for this product (custom-made, hygiene, perishable…).', 'wpify-woo' ),
			) );
			woocommerce_wp_checkbox( array(
				'id'          => self::META_WARRANTY_EXC,
				'label'       => __( 'Excluded from warranty/claim', 'wpify-woo' ),
				'description' => __( 'Customer cannot file a claim for this product.', 'wpify-woo' ),
			) );
			woocommerce_wp_text_input( array(
				'id'                => self::META_PERIOD_OVR,
				'type'              => 'number',
				'label'             => __( 'Withdrawal period override (days)', 'wpify-woo' ),
				'description'       => __( 'Leave empty to use the global setting.', 'wpify-woo' ),
				'desc_tip'          => true,
				'custom_attributes' => array( 'min' => '0', 'step' => '1' ),
			) );
			woocommerce_wp_text_input( array(
				'id'                => self::META_WARRANTY_OVR,
				'type'              => 'number',
				'label'             => __( 'Warranty months override', 'wpify-woo' ),
				'description'       => __( 'Leave empty to use the global setting.', 'wpify-woo' ),
				'desc_tip'          => true,
				'custom_attributes' => array( 'min' => '0', 'step' => '1' ),
			) );
			?>
		</div>
		<?php
	}

	public function save_product_meta( int $post_id ): void {
		$product = wc_get_product( $post_id );
		if ( ! $product ) {
			return;
		}

		// WooCommerce verifies the product-save nonce before woocommerce_process_product_meta fires.
		// phpcs:disable WordPress.Security.NonceVerification.Missing
		$product->update_meta_data( self::META_WITHDRAWAL_EXC, isset( $_POST[ self::META_WITHDRAWAL_EXC ] ) ? 'yes' : 'no' );
		$product->update_meta_data( self::META_WARRANTY_EXC, isset( $_POST[ self::META_WARRANTY_EXC ] ) ? 'yes' : 'no' );

		$ovr_days = isset( $_POST[ self::META_PERIOD_OVR ] ) ? (int) $_POST[ self::META_PERIOD_OVR ] : 0;
		$product->update_meta_data( self::META_PERIOD_OVR, $ovr_days > 0 ? $ovr_days : '' );

		$ovr_months = isset( $_POST[ self::META_WARRANTY_OVR ] ) ? (int) $_POST[ self::META_WARRANTY_OVR ] : 0;
		$product->update_meta_data( self::META_WARRANTY_OVR, $ovr_months > 0 ? $ovr_months : '' );
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		$product->save();
	}
}
