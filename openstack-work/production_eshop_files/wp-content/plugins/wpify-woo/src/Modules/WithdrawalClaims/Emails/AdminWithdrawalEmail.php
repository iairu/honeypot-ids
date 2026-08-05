<?php

namespace WpifyWoo\Modules\WithdrawalClaims\Emails;

defined( 'ABSPATH' ) || exit;

use WpifyWoo\Modules\WithdrawalClaims\WithdrawalClaimsRepository;
use WpifyWooDeps\Wpify\PluginUtils\PluginUtils;

class AdminWithdrawalEmail extends AbstractRequestEmail {

	public function __construct( WithdrawalClaimsRepository $repository, PluginUtils $utils ) {
		$this->id             = 'wpify_woo_withdrawal_admin';
		$this->customer_email = false;
		$this->title          = __( 'Withdrawal — admin notification', 'wpify-woo' );
		$this->description    = __( 'Notifies the shop admin about a new withdrawal request.', 'wpify-woo' );
		$this->template_html  = 'emails/admin-request-html.php';
		$this->template_plain = 'emails/admin-request-plain.php';

		parent::__construct( $repository, $utils );
	}

	public function is_customer(): bool {
		return false;
	}

	public function type(): string {
		return 'withdrawal';
	}

	public function get_default_subject(): string {
		/* translators: 1: site title, 2: order number placeholder */
		return sprintf( __( '[%1$s] New withdrawal request — order %2$s', 'wpify-woo' ), '{site_title}', '{order_number}' );
	}

	public function get_default_heading(): string {
		return __( 'New withdrawal request', 'wpify-woo' );
	}
}
