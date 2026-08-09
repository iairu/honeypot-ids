<?php

namespace WpifyWoo\Modules\WithdrawalClaims\Admin;

defined( 'ABSPATH' ) || exit;

use WP_List_Table;
use WpifyWoo\Modules\WithdrawalClaims\WithdrawalClaimsModel;
use WpifyWoo\Modules\WithdrawalClaims\WithdrawalClaimsRepository;

if ( ! class_exists( WP_List_Table::class ) ) {
	require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
}

/**
 * Admin requests list — read-only audit view.
 * Read path: always available regardless of is_active() (see 2.8).
 */
class RequestsListTable extends WP_List_Table {

	private WithdrawalClaimsRepository $repository;

	public function __construct( WithdrawalClaimsRepository $repository ) {
		parent::__construct( array(
			'singular' => 'request',
			'plural'   => 'requests',
			'ajax'     => false,
		) );

		$this->repository = $repository;
	}

	public function get_columns(): array {
		return array(
			'submitted_at'  => __( 'Date', 'wpify-woo' ),
			'request_type'  => __( 'Type', 'wpify-woo' ),
			'order'         => __( 'Order', 'wpify-woo' ),
			'customer'      => __( 'Customer', 'wpify-woo' ),
			'period_status' => __( 'Period status (at submission)', 'wpify-woo' ),
			'admin_note'    => __( 'Note', 'wpify-woo' ),
			'actions'       => __( 'Actions', 'wpify-woo' ),
		);
	}

	public function get_sortable_columns(): array {
		return array(
			'submitted_at' => array( 'submitted_at', true ),
			'request_type' => array( 'request_type', false ),
		);
	}

	public function prepare_items(): void {
		$per_page     = 25;
		$current_page = $this->get_pagenum();

		$args = array(
			'order_by' => 'submitted_at DESC',
		);

		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- WP_List_Table display/sort/pagination reads; no state change.
		// Filter: type
		$filter_type = isset( $_GET['filter_type'] ) ? sanitize_text_field( wp_unslash( $_GET['filter_type'] ) ) : '';
		if ( in_array( $filter_type, array( 'withdrawal', 'claim' ), true ) ) {
			$args['where']['request_type'] = $filter_type;
		}

		// Search by order_number / customer email
		$search = isset( $_REQUEST['s'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['s'] ) ) : '';
		if ( $search ) {
			// Simple LIKE — repository doesn't support OR, so we'll filter post-fetch.
		}

		$all = $this->repository->find( $args );

		if ( $search ) {
			$needle = strtolower( $search );
			$all    = array_filter( $all, static function ( WithdrawalClaimsModel $r ) use ( $needle ) {
				return str_contains( strtolower( $r->order_number ), $needle )
					|| str_contains( strtolower( $r->customer_email ), $needle )
					|| str_contains( strtolower( $r->customer_name ), $needle );
			} );
			$all    = array_values( $all );
		}

		// Filter: period status (at submission)
		$filter_period = isset( $_GET['filter_period_status'] ) ? sanitize_text_field( wp_unslash( $_GET['filter_period_status'] ) ) : '';
		if ( in_array( $filter_period, array( 'in', 'expired' ), true ) ) {
			$all = array_values( array_filter( $all, function ( WithdrawalClaimsModel $r ) use ( $filter_period ) {
				$expired_at_submission = ! empty( $r->period_end )
					&& strtotime( $r->period_end ) < strtotime( $r->submitted_at );

				return $filter_period === 'expired' ? $expired_at_submission : ! $expired_at_submission;
			} ) );
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		$total       = count( $all );
		$this->items = array_slice( $all, ( $current_page - 1 ) * $per_page, $per_page );

		$this->set_pagination_args( array(
			'total_items' => $total,
			'per_page'    => $per_page,
			'total_pages' => (int) ceil( $total / $per_page ),
		) );

		$this->_column_headers = array( $this->get_columns(), array(), $this->get_sortable_columns() );
	}

	public function column_submitted_at( WithdrawalClaimsModel $item ): string {
		$ts = strtotime( $item->submitted_at );
		if ( ! $ts ) {
			return '';
		}

		return esc_html( wp_date( wc_date_format() . ' ' . wc_time_format(), $ts ) );
	}

	public function column_request_type( WithdrawalClaimsModel $item ): string {
		return esc_html( $item->type_label() );
	}

	public function column_order( WithdrawalClaimsModel $item ): string {
		$order = wc_get_order( $item->order_id );
		if ( ! $order ) {
			return esc_html( $item->order_number );
		}
		$url = $order->get_edit_order_url();

		return sprintf( '<a href="%s">#%s</a>', esc_url( $url ), esc_html( $item->order_number ) );
	}

	public function column_customer( WithdrawalClaimsModel $item ): string {
		return sprintf(
			'%s<br><small>%s</small>',
			esc_html( $item->customer_name ),
			esc_html( $item->customer_email )
		);
	}

	public function column_period_status( WithdrawalClaimsModel $item ): string {
		if ( empty( $item->period_end ) ) {
			return '<span class="dashicons dashicons-minus" aria-hidden="true"></span>';
		}
		$end_ts = strtotime( $item->period_end );
		$sub_ts = strtotime( $item->submitted_at );
		$expired_at_submission = $end_ts && $sub_ts && $end_ts < $sub_ts;
		$label                 = $expired_at_submission
			? __( 'Expired', 'wpify-woo' )
			: __( 'In period', 'wpify-woo' );
		$color                 = $expired_at_submission ? '#b32d2e' : '#1a7f37';

		return sprintf(
			'<span style="color:%s;">%s</span><br><small>%s: %s</small>',
			esc_attr( $color ),
			esc_html( $label ),
			esc_html__( 'ended', 'wpify-woo' ),
			esc_html( $end_ts ? wp_date( wc_date_format(), $end_ts ) : '' )
		);
	}

	public function column_admin_note( WithdrawalClaimsModel $item ): string {
		if ( $item->admin_note === '' ) {
			return '';
		}

		$preview = mb_strlen( $item->admin_note ) > 60 ? mb_substr( $item->admin_note, 0, 60 ) . '…' : $item->admin_note;

		return esc_html( $preview );
	}

	public function column_actions( WithdrawalClaimsModel $item ): string {
		$url = add_query_arg( array(
			'page'       => 'wpify-woo-requests',
			'request_id' => $item->id,
		), admin_url( 'admin.php' ) );

		return sprintf( '<a href="%s">%s</a>', esc_url( $url ), esc_html__( 'Detail', 'wpify-woo' ) );
	}

	public function column_default( $item, $column_name ): string {
		return '';
	}

	public function no_items(): void {
		esc_html_e( 'No requests submitted yet.', 'wpify-woo' );
	}

	/**
	 * Render filter dropdowns above the table.
	 */
	public function extra_tablenav( $which ): void {
		if ( $which !== 'top' ) {
			return;
		}

		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- WP_List_Table display/sort/pagination reads; no state change.
		$current_type   = isset( $_GET['filter_type'] ) ? sanitize_text_field( wp_unslash( $_GET['filter_type'] ) ) : '';
		$current_period = isset( $_GET['filter_period_status'] ) ? sanitize_text_field( wp_unslash( $_GET['filter_period_status'] ) ) : '';
		// phpcs:enable WordPress.Security.NonceVerification.Recommended
		?>
		<div class="alignleft actions">
			<label class="screen-reader-text"
				   for="filter_type"><?php esc_html_e( 'Filter by type', 'wpify-woo' ); ?></label>
			<select name="filter_type" id="filter_type">
				<option value=""><?php esc_html_e( 'All types', 'wpify-woo' ); ?></option>
				<option value="withdrawal" <?php selected( $current_type, 'withdrawal' ); ?>><?php esc_html_e( 'Withdrawal', 'wpify-woo' ); ?></option>
				<option value="claim" <?php selected( $current_type, 'claim' ); ?>><?php esc_html_e( 'Claim', 'wpify-woo' ); ?></option>
			</select>

			<label class="screen-reader-text"
				   for="filter_period_status"><?php esc_html_e( 'Filter by period status', 'wpify-woo' ); ?></label>
			<select name="filter_period_status" id="filter_period_status">
				<option value=""><?php esc_html_e( 'All period statuses', 'wpify-woo' ); ?></option>
				<option value="in" <?php selected( $current_period, 'in' ); ?>><?php esc_html_e( 'In period (at submission)', 'wpify-woo' ); ?></option>
				<option value="expired" <?php selected( $current_period, 'expired' ); ?>><?php esc_html_e( 'Expired (at submission)', 'wpify-woo' ); ?></option>
			</select>

			<?php submit_button( __( 'Filter', 'wpify-woo' ), '', 'filter_action', false ); ?>
		</div>
		<?php
	}
}
