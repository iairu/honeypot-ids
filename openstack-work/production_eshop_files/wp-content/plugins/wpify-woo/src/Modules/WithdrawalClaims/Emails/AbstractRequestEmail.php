<?php

namespace WpifyWoo\Modules\WithdrawalClaims\Emails;

defined( 'ABSPATH' ) || exit;

use WC_Email;
use WC_Order;
use WpifyWoo\Modules\WithdrawalClaims\WithdrawalClaimsModel;
use WpifyWoo\Modules\WithdrawalClaims\WithdrawalClaimsRepository;
use WpifyWooDeps\Wpify\PluginUtils\PluginUtils;

/**
 * Shared base for withdrawal/claim notification e-mails.
 *
 * Each concrete subclass sets:
 *   - $this->id
 *   - $this->customer_email (true/false)
 *   - $this->title / description / template paths
 *   - request_type via type() method
 */
abstract class AbstractRequestEmail extends WC_Email {

	protected WithdrawalClaimsRepository $repository;
	protected PluginUtils $utils;

	/** @var WithdrawalClaimsModel|null */
	protected $request;

	public function __construct( WithdrawalClaimsRepository $repository, PluginUtils $utils ) {
		$this->repository = $repository;
		$this->utils      = $utils;

		$this->template_base = $this->utils->get_plugin_path( 'src/Modules/WithdrawalClaims/templates/' );

		parent::__construct();

		// Surface configured recipient in WC > Settings > Emails list table.
		// trigger() re-reads it just before sending; customer emails are routed
		// to the order's billing email there.
		if ( ! $this->is_customer() ) {
			$this->recipient = $this->get_option( 'recipient', get_option( 'admin_email' ) );
		}
	}

	/**
	 * Whether this email is for the customer or admin.
	 */
	abstract public function is_customer(): bool;

	/**
	 * Request type — 'withdrawal' or 'claim'.
	 */
	abstract public function type(): string;

	/**
	 * Trigger e-mail by request id.
	 */
	public function trigger( int $request_id ): void {
		// setup_locale() triggers the woocommerce_email_setup_locale filter, which WPML/WCML
		// hooks into to switch the language to the order's customer language. Without it,
		// translatable options (subjects, attachments, …) are read from the wrong language.
		$this->setup_locale();
		try {
			$requests = $this->repository->find( array( 'where' => array( 'id' => $request_id ) ) );
			$request  = $requests[0] ?? null;

			if ( ! $request instanceof WithdrawalClaimsModel ) {
				return;
			}

			if ( $request->request_type !== $this->type() ) {
				return;
			}

			$order = wc_get_order( $request->order_id );
			if ( ! $order instanceof WC_Order ) {
				return;
			}

			$this->request = $request;
			$this->object  = $order;

			$this->placeholders['{order_number}'] = $order->get_order_number();
			$this->placeholders['{order_date}']   = wc_format_datetime( $order->get_date_created() );

			if ( $this->is_customer() ) {
				// Customer emails always go to billing email — see 5.10 (data-leak prevention).
				$recipient = $order->get_billing_email();
			} else {
				// Admin emails go to admin recipient configured in form fields.
				$recipient = $this->get_option( 'recipient', get_option( 'admin_email' ) );
			}

			$recipient = apply_filters(
				'wpify_woo_withdrawal_claims_email_recipient',
				$recipient,
				$request_id,
				$this->is_customer() ? 'customer' : 'admin'
			);

			$this->recipient = $recipient;

			if ( ! $this->is_enabled() || ! $this->get_recipient() ) {
				return;
			}

			do_action( 'wpify_woo_withdrawal_claims_before_email_send', $this, $request_id );

			$success = $this->send(
				$this->get_recipient(),
				$this->get_subject(),
				$this->get_content(),
				$this->get_headers(),
				$this->get_attachments()
			);

			do_action( 'wpify_woo_withdrawal_claims_after_email_send', $this, $request_id, (bool) $success );
		} finally {
			$this->restore_locale();
		}
	}

	/**
	 * Admin notification emails reply-to the customer directly — same convention
	 * WooCommerce core uses for its own new_order/cancelled_order/failed_order
	 * emails (see WC_Email::get_headers()).
	 */
	public function get_headers() {
		$headers = parent::get_headers();

		if ( ! $this->is_customer() && $this->request && is_email( $this->request->customer_email ) ) {
			// Replace WC's default Reply-to (site's from-address) so replying to
			// the admin notification goes straight to the customer.
			$headers  = preg_replace( '/^Reply-to:.*\r\n/mi', '', $headers );
			$name     = sanitize_text_field( trim( $this->request->customer_name ) ) ?: $this->request->customer_email;
			$headers .= 'Reply-to: ' . $name . ' <' . $this->request->customer_email . ">\r\n";
		}

		return $headers;
	}

	public function get_content_html(): string {
		return wc_get_template_html(
			$this->template_html,
			$this->common_template_args( false ),
			'',
			$this->template_base
		);
	}

	public function get_content_plain(): string {
		return wc_get_template_html(
			$this->template_plain,
			$this->common_template_args( true ),
			'',
			$this->template_base
		);
	}

	private function common_template_args( bool $plain_text ): array {
		$submitted_ts = $this->request && ! empty( $this->request->submitted_at )
			? strtotime( $this->request->submitted_at )
			: 0;
		$period_ts    = $this->request && ! empty( $this->request->period_end )
			? strtotime( $this->request->period_end )
			: 0;

		$datetime_format = wc_date_format() . ' ' . wc_time_format();

		return array(
			'email_heading'          => $this->get_heading(),
			'sent_to_admin'          => ! $this->is_customer(),
			'plain_text'             => $plain_text,
			'email'                  => $this,
			'order'                  => $this->object,
			'request'                => $this->request,
			'request_items'          => $this->decode_items(),
			'additional_content'     => $this->get_additional_content(),
			'intro_content'          => $this->get_intro_content(),
			'submitted_at_formatted' => $submitted_ts ? wp_date( $datetime_format, $submitted_ts ) : '',
			'period_end_formatted'   => $period_ts ? wp_date( $datetime_format, $period_ts ) : '',
			'extra_fields'           => $this->decode_extra_fields( $plain_text ),
		);
	}

	/**
	 * Resolve developer-defined extra fields for the current request, pre-rendered.
	 *
	 * Returns a list of `[label, value]` pairs ready for output. Empty values are
	 * skipped so templates can iterate without an additional empty-check.
	 *
	 * @return array<int,array{label:string,value:string}>
	 */
	protected function decode_extra_fields( bool $plain_text ): array {
		if ( ! $this->request instanceof WithdrawalClaimsModel ) {
			return array();
		}

		try {
			$module = wpify_woo_container()->get( \WpifyWoo\Modules\WithdrawalClaims\WithdrawalClaimsModule::class );
		} catch ( \Throwable $e ) {
			return array();
		}

		$schema = $module->get_extra_fields_schema( $this->request->request_type );
		if ( ! $schema ) {
			return array();
		}

		$values = $module->get_request_extra_fields( $this->request );
		$out    = array();
		foreach ( $schema as $field ) {
			$raw = $values[ $field['id'] ] ?? '';
			if ( $raw === '' || $raw === null || $raw === false ) {
				continue;
			}
			$out[] = array(
				'label' => (string) $field['label'],
				'value' => $module->render_extra_field_value( $field, $raw, ! $plain_text ),
			);
		}

		return $out;
	}

	/**
	 * Decode items_json into a normalized array, enriched with current order_item data.
	 */
	protected function decode_items(): array {
		if ( ! $this->request || ! $this->object instanceof WC_Order ) {
			return array();
		}

		$decoded = json_decode( $this->request->items_json, true );
		if ( ! is_array( $decoded ) ) {
			return array();
		}

		$result = array();
		foreach ( $decoded as $row ) {
			$line_item_id = (int) ( $row['line_item_id'] ?? 0 );
			$quantity     = (int) ( $row['quantity'] ?? 0 );
			$item         = $this->object->get_item( $line_item_id );

			if ( $item ) {
				$result[] = array(
					'line_item_id' => $line_item_id,
					'quantity'     => $quantity,
					'name'         => $item->get_name(),
					'item'         => $item,
				);
			} else {
				$result[] = array(
					'line_item_id' => $line_item_id,
					'quantity'     => $quantity,
					/* translators: %d: line item id */
					'name'         => sprintf( __( 'Item no longer in order (line #%d)', 'wpify-woo' ), $line_item_id ),
					'item'         => null,
				);
			}
		}

		return $result;
	}

	public function init_form_fields() {
		$fields = array(
			'enabled'    => array(
				'title'   => __( 'Enable/Disable', 'wpify-woo' ),
				'type'    => 'checkbox',
				'label'   => __( 'Enable this email notification', 'wpify-woo' ),
				'default' => 'yes',
			),
			'subject'    => array(
				'title'       => __( 'Subject', 'wpify-woo' ),
				'type'        => 'text',
				'desc_tip'    => true,
				/* translators: %s: default email subject */
				'description' => sprintf( __( 'Default: %s', 'wpify-woo' ), $this->get_default_subject() ),
				'placeholder' => $this->get_default_subject(),
				'default'     => '',
			),
			'heading'    => array(
				'title'       => __( 'Email heading', 'wpify-woo' ),
				'type'        => 'text',
				'desc_tip'    => true,
				/* translators: %s: default email heading */
				'description' => sprintf( __( 'Default: %s', 'wpify-woo' ), $this->get_default_heading() ),
				'placeholder' => $this->get_default_heading(),
				'default'     => '',
			),
			'email_type' => array(
				'title'       => __( 'Email type', 'wpify-woo' ),
				'type'        => 'select',
				'description' => __( 'Choose which format of email to send.', 'wpify-woo' ),
				'default'     => 'html',
				'class'       => 'email_type wc-enhanced-select',
				'options'     => $this->get_email_type_options(),
				'desc_tip'    => true,
			),
			'intro_content'      => array(
				'title'       => __( 'Intro content', 'wpify-woo' ),
				'description' => __( 'Text shown at the top of the email, above the request details table. For admin emails you can use placeholders {type} and {customer_name}.', 'wpify-woo' ),
				'css'         => 'width:400px; height: 75px;',
				'placeholder' => __( 'N/A', 'wpify-woo' ),
				'type'        => 'textarea',
				'default'     => $this->get_default_intro_content(),
				'desc_tip'    => true,
			),
			'additional_content' => array(
				'title'       => __( 'Additional content', 'wpify-woo' ),
				'description' => __( 'Text shown below the mandatory request details. Use it for next-steps instructions (e.g. "Reply to this email with photos of the defect").', 'wpify-woo' ),
				'css'         => 'width:400px; height: 75px;',
				'placeholder' => __( 'N/A', 'wpify-woo' ),
				'type'        => 'textarea',
				'default'     => $this->get_default_additional_content(),
				'desc_tip'    => true,
			),
		);

		// Admin emails have a recipient field
		if ( ! $this->is_customer() ) {
			$fields = array_merge(
				array(
					'recipient' => array(
						'title'       => __( 'Recipient(s)', 'wpify-woo' ),
						'type'        => 'text',
						/* translators: %s: default admin email address */
						'description' => sprintf( __( 'Comma-separated emails. Defaults to %s.', 'wpify-woo' ), '<code>' . esc_attr( get_option( 'admin_email' ) ) . '</code>' ),
						'placeholder' => '',
						'default'     => '',
						'desc_tip'    => true,
					),
				),
				$fields
			);
		}

		$this->form_fields = $fields;
	}

	public function get_default_additional_content(): string {
		if ( $this->is_customer() ) {
			return __( 'You will be contacted by our team regarding the next steps. If you need to provide additional information (for example photos of a defect for a claim), please reply directly to this email.', 'wpify-woo' );
		}

		return __( 'A new request was submitted. Review the details above and process accordingly.', 'wpify-woo' );
	}

	public function get_default_intro_content(): string {
		if ( $this->is_customer() ) {
			return __( 'We have received your request. This email confirms its receipt as required by Directive (EU) 2023/2673 — please keep it as a record.', 'wpify-woo' );
		}

		return __( 'A new {type} request was submitted by {customer_name}.', 'wpify-woo' );
	}

	/**
	 * Read the configured intro content with placeholder resolution.
	 */
	public function get_intro_content(): string {
		$intro = $this->get_option( 'intro_content', $this->get_default_intro_content() );
		if ( $intro === '' ) {
			$intro = $this->get_default_intro_content();
		}

		return strtr( $intro, array(
			'{type}'          => $this->request ? $this->request->type_label() : '',
			'{customer_name}' => $this->request ? $this->request->customer_name : '',
		) );
	}
}
