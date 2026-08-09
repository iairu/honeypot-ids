<?php

namespace WpifyWoo\Modules\WithdrawalClaims\Emails;

defined( 'ABSPATH' ) || exit;

use WpifyWoo\Modules\WithdrawalClaims\WithdrawalClaimsRepository;
use WpifyWooDeps\Wpify\PluginUtils\PluginUtils;

class CustomerWithdrawalEmail extends AbstractRequestEmail {

	public function __construct( WithdrawalClaimsRepository $repository, PluginUtils $utils ) {
		$this->id             = 'wpify_woo_withdrawal_customer';
		$this->customer_email = true;
		$this->title          = __( 'Withdrawal — confirmation to customer', 'wpify-woo' );
		$this->description    = __( 'Confirms receipt of a withdrawal request to the customer (durable medium per Directive 2023/2673).', 'wpify-woo' );
		$this->template_html  = 'emails/customer-request-html.php';
		$this->template_plain = 'emails/customer-request-plain.php';

		parent::__construct( $repository, $utils );
	}

	public function is_customer(): bool {
		return true;
	}

	public function type(): string {
		return 'withdrawal';
	}

	public function get_default_subject(): string {
		return __( 'Withdrawal received — order {order_number}', 'wpify-woo' );
	}

	public function get_default_heading(): string {
		return __( 'Your withdrawal has been received', 'wpify-woo' );
	}
}
