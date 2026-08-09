<?php

namespace WpifyWoo\Modules\WithdrawalClaims;

defined( 'ABSPATH' ) || exit;

use WpifyWooDeps\Wpify\Model\Attributes\Column;
use WpifyWooDeps\Wpify\Model\Model;

class WithdrawalClaimsModel extends Model {
	#[Column( type: Column::INT, auto_increment: true, primary_key: true )]
	public int $id;

	#[Column( type: Column::VARCHAR )]
	public string $request_type;

	#[Column( type: Column::BIGINT )]
	public int $order_id;

	#[Column( type: Column::VARCHAR )]
	public string $order_number;

	#[Column( type: Column::VARCHAR )]
	public string $customer_email;

	#[Column( type: Column::VARCHAR )]
	public string $customer_name;

	#[Column( type: Column::TEXT )]
	public string $items_json;

	#[Column( type: Column::TEXT )]
	public string $reason;

	/**
	 * JSON-encoded map of developer-defined extra field values (id => value).
	 *
	 * Schema is declared at runtime via the `wpify_woo_withdrawal_claims_form_fields`
	 * filter; this column stores only the captured values, not the schema itself.
	 */
	#[Column( type: Column::TEXT )]
	public string $extra_fields_json;

	#[Column( type: Column::VARCHAR )]
	public string $scope;

	#[Column( type: Column::VARCHAR )]
	public string $status;

	#[Column( type: Column::VARCHAR )]
	public string $period_end;

	#[Column( type: Column::VARCHAR )]
	public string $submitted_at;

	#[Column( type: Column::VARCHAR )]
	public string $customer_ip;

	#[Column( type: Column::VARCHAR )]
	public string $customer_user_agent;

	#[Column( type: Column::VARCHAR )]
	public string $created_at;

	/**
	 * Free-text note for internal use (e.g. "processed", "awaiting refund").
	 * Set only by admins on the request detail screen; never shown to the customer.
	 */
	#[Column( type: Column::TEXT )]
	public string $admin_note = '';

	/**
	 * Human-readable label for {@see self::$request_type}.
	 *
	 * Filter `wpify_woo_withdrawal_claims_request_type_labels` lets extensions
	 * register additional types (key => translated label).
	 */
	public function type_label(): string {
		$labels = apply_filters( 'wpify_woo_withdrawal_claims_request_type_labels', array(
			'withdrawal' => __( 'Withdrawal', 'wpify-woo' ),
			'claim'      => __( 'Claim', 'wpify-woo' ),
		) );

		return $labels[ $this->request_type ] ?? $this->request_type;
	}

	/**
	 * Human-readable label for {@see self::$scope}.
	 *
	 * Filter `wpify_woo_withdrawal_claims_scope_labels` lets extensions
	 * register additional scopes.
	 */
	public function scope_label(): string {
		$labels = apply_filters( 'wpify_woo_withdrawal_claims_scope_labels', array(
			'whole_order'    => __( 'Whole order', 'wpify-woo' ),
			'specific_items' => __( 'Specific items', 'wpify-woo' ),
		) );

		return $labels[ $this->scope ] ?? $this->scope;
	}

	/**
	 * Human-readable label for {@see self::$status}.
	 *
	 * Filter `wpify_woo_withdrawal_claims_status_labels` lets extensions
	 * register custom statuses.
	 */
	public function status_label(): string {
		$labels = apply_filters( 'wpify_woo_withdrawal_claims_status_labels', array(
			'submitted' => __( 'Submitted', 'wpify-woo' ),
		) );

		return $labels[ $this->status ] ?? $this->status;
	}
}
