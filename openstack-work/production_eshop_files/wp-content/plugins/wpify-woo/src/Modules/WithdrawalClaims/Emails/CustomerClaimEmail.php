<?php

namespace WpifyWoo\Modules\WithdrawalClaims\Emails;

defined( 'ABSPATH' ) || exit;

use WpifyWoo\Modules\WithdrawalClaims\WithdrawalClaimsRepository;
use WpifyWooDeps\Wpify\PluginUtils\PluginUtils;

class CustomerClaimEmail extends AbstractRequestEmail {

	public function __construct( WithdrawalClaimsRepository $repository, PluginUtils $utils ) {
		$this->id             = 'wpify_woo_claim_customer';
		$this->customer_email = true;
		$this->title          = __( 'Claim — confirmation to customer', 'wpify-woo' );
		$this->description    = __( 'Confirms receipt of a claim (reklamace) request to the customer.', 'wpify-woo' );
		$this->template_html  = 'emails/customer-request-html.php';
		$this->template_plain = 'emails/customer-request-plain.php';

		parent::__construct( $repository, $utils );
	}

	public function is_customer(): bool {
		return true;
	}

	public function type(): string {
		return 'claim';
	}

	public function get_default_subject(): string {
		return __( 'Claim received — order {order_number}', 'wpify-woo' );
	}

	public function get_default_heading(): string {
		return __( 'Your claim has been received', 'wpify-woo' );
	}
}
