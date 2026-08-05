<?php

namespace WpifyWoo\Modules\WithdrawalClaims\Emails;

defined( 'ABSPATH' ) || exit;

use WpifyWoo\Modules\WithdrawalClaims\WithdrawalClaimsRepository;
use WpifyWooDeps\Wpify\PluginUtils\PluginUtils;

class AdminClaimEmail extends AbstractRequestEmail {

	public function __construct( WithdrawalClaimsRepository $repository, PluginUtils $utils ) {
		$this->id             = 'wpify_woo_claim_admin';
		$this->customer_email = false;
		$this->title          = __( 'Claim — admin notification', 'wpify-woo' );
		$this->description    = __( 'Notifies the shop admin about a new claim (reklamace) request.', 'wpify-woo' );
		$this->template_html  = 'emails/admin-request-html.php';
		$this->template_plain = 'emails/admin-request-plain.php';

		parent::__construct( $repository, $utils );
	}

	public function is_customer(): bool {
		return false;
	}

	public function type(): string {
		return 'claim';
	}

	public function get_default_subject(): string {
		/* translators: 1: site title, 2: order number placeholder */
		return sprintf( __( '[%1$s] New claim request — order %2$s', 'wpify-woo' ), '{site_title}', '{order_number}' );
	}

	public function get_default_heading(): string {
		return __( 'New claim request', 'wpify-woo' );
	}
}
