<?php

namespace WpifyWoo\Modules\QRPayment;

defined( 'ABSPATH' ) || exit;

use DateTime;
use Exception;
use WC_Email;
use WC_Order;
use WP_Error;
use WpifyWoo\Plugin;
use WpifyWoo\WooCommerceIntegration;
use WpifyWooDeps\Wpify\WooCore\Abstracts\AbstractModule;
use WpifyWooDeps\Rikudou\CzQrPayment\Options\QrPaymentOptions;
use WpifyWooDeps\rikudou\EuQrPayment\Sepa\CharacterSet as EuCharacterSet;
use WpifyWooDeps\rikudou\EuQrPayment\Sepa\Purpose as EuPurpose;
use WpifyWooDeps\hubipe\HuQrPayment\Enums\CharacterSet as HuCharacterSet;
use WpifyWooDeps\hubipe\HuQrPayment\Enums\IdCode as HuIdCode;
use WpifyWooDeps\hubipe\HuQrPayment\Enums\Purpose as HuPurpose;
use WpifyWooDeps\Rikudou\CzQrPayment\QrPayment;
use WpifyWooDeps\Rikudou\Iban\Iban\CzechIbanAdapter;
use WpifyWooDeps\Rikudou\Iban\Iban\IBAN;
use WpifyWooDeps\Wpify\Log\RotatingFileLog;

class QRPaymentModule extends AbstractModule {
	/**
	 * QRPaymentModule constructor
	 *
	 * @param WooCommerceIntegration $woocommerce_integration WooCommerce integration instance
	 * @param RotatingFileLog        $log                     Logger instance
	 */
	public function __construct(
		private WooCommerceIntegration $woocommerce_integration,
		private RotatingFileLog $log
	) {
		parent::__construct();
		$this->setup();
	}

	/**
	 * @return void
	 */
	public function setup() {
		add_action( 'template_redirect', [ $this, 'display_qr_code_on_thankyou' ] );
		add_action( 'wpify_woo_render_qr_code', [ $this, 'display_qr_code' ] );
		add_shortcode( 'wpify_woo_render_qr_code', array( $this, 'display_qr_code_shortcode' ) );

		$email_position_hook = $this->get_setting( 'email_position' ) ?: 'woocommerce_email_before_order_table';
		add_action( $email_position_hook, [ $this, 'display_qr_code_in_email' ], 20, 4 );

		add_action( 'wpo_wcpdf_after_order_details', array( $this, 'display_qr_code_in_wcpdf' ), 10, 2 );
	}

	/**
	 * Display QR code on thank you page based on position setting
	 *
	 * @return void
	 */
	public function display_qr_code_on_thankyou() {
		if ( is_checkout() && ! empty( is_wc_endpoint_url( 'order-received' ) ) ) {
			$position = $this->get_setting( 'thankyou_position' );

			if ( ! empty( $position ) && $position === 'dont_show' ) {
				return;
			}

			if ( $position === 'before_order' ) {
				add_action( 'woocommerce_thankyou', [ $this, 'display_qr_code' ], 1, 1 );
			} elseif ( $position === 'after_thankyou' ) {
				add_action( 'woocommerce_thankyou', [ $this, 'display_qr_code' ], 20, 1 );
			} else {
				add_action( 'woocommerce_before_thankyou', [ $this, 'display_qr_code' ], 10, 1 );
			}
		}
	}

	/**
	 * Module ID
	 *
	 * @return string
	 */
	public function id(): string {
		return 'qr_payment';
	}

	/**
	 * Module name
	 *
	 * @return string
	 */
	public function name(): string {
		return __( 'QR Payment', 'wpify-woo' );
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
		return 'wpify-woo/modules/qr-payment';
	}

	/**
	 * Module settings
	 *
	 * @return array[]
	 */
	public function settings(): array {
		$settings = array(
			array(
				'id'      => 'payment_methods',
				'type'    => 'multi_group',
				'label'   => __( 'Enabled payment methods', 'wpify-woo' ),
				'buttons' => array(
					'add' => __( 'Add payment method', 'wpify-woo' ),
				),
				'items'   => [
					[
						'id'           => 'payment_method',
						'type'         => 'select',
						'label'        => __( 'Payment method', 'wpify-woo' ),
						'options'      => function ( $args ) {
							return $this->woocommerce_integration->get_gateways( $args );
						},
						'async'        => true,
						'async_params' => array(
							'tab'       => 'wpify-woo-settings',
							'section'   => $this->id(),
							'module_id' => $this->id(),
						),
					],
					[
						'id'           => 'enabled_emails',
						'type'         => 'multi_select',
						'label'        => __( 'Show in emails', 'wpify-woo' ),
						'options'      => function ( $args ) {
							return $this->woocommerce_integration->get_emails_select( $args );
						},
						'async'        => true,
						'async_params' => array(
							'tab'       => 'wpify-woo-settings',
							'section'   => $this->id(),
							'module_id' => $this->id(),
						),
					],
					[
						'id'      => 'accounts',
						'type'    => 'multi_group',
						'label'   => __( 'Accounts', 'wpify-woo' ),
						'buttons' => array(
							'add' => __( 'Add account', 'wpify-woo' ),
						),
						'items'   => [
							[
								'id'           => 'source',
								'type'         => 'select',
								'label'        => __( 'Account data source', 'wpify-woo' ),
								'options'      => function ( $args ) {
									return $this->get_bacs_accounts_options();
								},
								'async'        => true,
								'async_params' => array(
									'tab'       => 'wpify-woo-settings',
									'section'   => $this->id(),
									'module_id' => $this->id(),
								),
								'default'      => '',
							],
							[
								'id'         => 'iban',
								'type'       => 'text',
								'label'      => __( 'IBAN', 'wpify-woo' ),
								'conditions' => array(
									array(
										'field'     => '#.source',
										'condition' => 'empty'
									),
								),
							],
							[
								'id'         => 'number',
								'type'       => 'text',
								'label'      => __( 'Account number (CZ only)', 'wpify-woo' ),
								'conditions' => array(
									array(
										'field'     => '#.source',
										'condition' => 'empty'
									),
								),
							],
							[
								'id'         => 'bank_code',
								'type'       => 'text',
								'label'      => __( 'Bank Code (CZ only)', 'wpify-woo' ),
								'conditions' => array(
									array(
										'field'     => '#.source',
										'condition' => 'empty'
									),
								),
							],
							[
								'id'         => 'bic',
								'type'       => 'text',
								'label'      => __( 'BIC (SWIFT)', 'wpify-woo' ),
								'conditions' => array(
									array(
										'field'     => '#.source',
										'condition' => 'empty'
									),
								),
							],
							[
								'id'          => 'recipient_name',
								'type'        => 'text',
								'label'       => __( 'Recipient name', 'wpify-woo' ),
								'description' => __( 'Full name of the account owner or company business name.', 'wpify-woo' ),
							],
							[
								'id'       => 'type',
								'type'     => 'select',
								'label'    => __( 'QR Type', 'wpify-woo' ),
								'required' => true,
								'default'  => 'auto',
								'options'  => [
									[
										'label' => __( 'Auto detect by order', 'wpify-woo' ),
										'value' => 'auto',
									],
									[
										'label' => 'QR Platba – CZ + CZK',
										'value' => 'cz',
									],
									[
										'label' => 'Pay BY Square – SK + EUR',
										'value' => 'sk',
									],
									[
										'label' => 'Hungary standard – HU + HUF',
										'value' => 'hu',
									],
									[
										'label' => 'EPC standard (SEPA) – DE, NL, AT, BE, FI + EUR',
										'value' => 'epc',
									],
								],
							],
							[
								'id'         => 'enabled_currencies',
								'type'       => 'multi_select',
								'label'      => __( 'Enabled currencies', 'wpify-woo' ),
								'options'    => [
									[ 'label' => 'CZK', 'value' => 'CZK' ],
									[ 'label' => 'EUR', 'value' => 'EUR' ],
									[ 'label' => 'HUF', 'value' => 'HUF' ],
								],
								'conditions' => array(
									array(
										'field' => '#.type',
										'value' => 'auto'
									),
								),
							],
							[
								'id'           => 'enabled_countries',
								'type'         => 'multi_select',
								'label'        => __( 'Enabled countries', 'wpify-woo' ),
								'options'      => function ( $args ) {
									return $this->woocommerce_integration->get_countries_select( $args );
								},
								'async'        => true,
								'async_params' => array(
									'tab'       => 'wpify-woo-settings',
									'section'   => $this->id(),
									'module_id' => $this->id(),
									'qr_type'   => '{{#.type}}'
								),
							],
							[
								'id'    => 'label',
								'type'  => 'text',
								'label' => __( 'Info label', 'wpify-woo' ),
							],
						],
					],
				],
			),
			[
				'id'    => 'note',
				'label' => __( 'Message to recipient', 'wpify-woo' ),
				'desc'  => __( 'Enter the message to recipient if you want it. You can use codes <code>{order}</code> to insert the order number and <code>{shop_name}</code> to insert the name of the shop. So the message might look like, for example, "QR payment order {order} from {shop_name}".',
					'wpify-woo' ),
				'type'  => 'text',
			],
			[
				'id'    => 'title_before',
				'label' => __( 'Title before', 'wpify-woo' ),
				'desc'  => __( 'You can use codes <code>{order}</code> to insert the order number and <code>{total}</code> to insert the value of order.', 'wpify-woo' ),
				'type'  => 'wysiwyg',
			],
			[
				'id'    => 'title_after',
				'label' => __( 'Title after', 'wpify-woo' ),
				'desc'  => __( 'You can use codes <code>{order}</code> to insert the order number and <code>{total}</code> to insert the value of order.', 'wpify-woo' ),
				'type'  => 'wysiwyg',
			],
			array(
				'id'      => 'thankyou_position',
				'label'   => __( 'QR position on thank you page', 'wpify-woo' ),
				'desc'    => __( 'Select where the QR code should be placed on the thank you page.', 'wpify-woo' ),
				'type'    => 'select',
				'options' => [
					[
						'label' => __( 'Dont show', 'wpify-woo' ),
						'value' => 'dont_show',
					],
					[
						'label' => __( 'Before page content', 'wpify-woo' ),
						'value' => 'before_thankyou',
					],
					[
						'label' => __( 'Before Order details', 'wpify-woo' ),
						'value' => 'before_order',
					],
					[
						'label' => __( 'After page content', 'wpify-woo' ),
						'value' => 'after_thankyou',
					],
				],
			),
			array(
				'id'      => 'email_position',
				'label'   => __( 'QR position in emails', 'wpify-woo' ),
				'desc'    => __( 'Select where the QR code should be placed in the emails.', 'wpify-woo' ),
				'type'    => 'select',
				'options' => [
					[
						'label' => __( 'Before order table', 'wpify-woo' ),
						'value' => 'woocommerce_email_before_order_table',
					],
					[
						'label' => __( 'After order table', 'wpify-woo' ),
						'value' => 'woocommerce_email_after_order_table',
					],
					[
						'label' => __( 'In order meta', 'wpify-woo' ),
						'value' => 'woocommerce_email_order_meta',
					],
				],
				'default' => 'woocommerce_email_before_order_table',
			),
			[
				'id'    => 'compatibility_mode',
				'title' => __( 'Compatibility mode', 'wpify-woo' ),
				'desc'  => __( 'The SK version requires XZ utils (https://tukaani.org/xz/). If your serevr does not support this, you can enable the compatibility mode, in which the QR code will be generated using the external API QR-Platba.cz and QRGenerator.sk. This is not recommended for performance reasons, as an unnecessary API call is done on thankyou page.',
						'wpify-woo' ) . __( 'Only for CZ and SK QR standards.', 'wpify-woo' ),
				'type'  => 'toggle',
			],
			[
				'id'    => 'save_img',
				'title' => __( 'Save as image', 'wpify-woo' ),
				'desc'  => __( 'Some email clients have a problem with displaying images in base64. If you enable this, the QR code will be saved as a file and then linked to.', 'wpify-woo' ),
				'type'  => 'toggle',
			],

		);

		if ( function_exists( 'wcpdf_get_document' ) ) {
			$settings[] = [
				'id'    => 'in_wcpdf',
				'title' => __( 'Insert into WCPDF invoice', 'wpify-woo' ),
				'desc'  => __( 'Insert QR payment into PDF Invoices from PDF Invoices & Packing Slips for WooCommerce plugin.', 'wpify-woo' ),
				'type'  => 'toggle',
			];
		}

		return $settings;
	}

	/**
	 * Render QR code
	 *
	 * @param int|WC_Order $order
	 *
	 * @return mixed
	 * @throws Exception
	 */
	public function render_qr_code( $order, $account ) {
		$note      = $this->get_setting( 'note' );
		$note_text = '';
		$qrCode    = '';

		if ( ! empty( $note ) ) {
			$replaces  = [
				'{order}'     => $order->get_order_number(),
				'{shop_name}' => get_bloginfo( 'name' ),
			];
			$note_text = str_replace( array_keys( $replaces ), array_values( $replaces ), $note );
		} else {
			$note_text = $this->name();
		}

		$payment_details = [
			'order'          => $order->get_order_number(),
			'total'          => $order->get_total(),
			'vs'             => preg_replace( '/[^0-9]/', '', $order->get_order_number() ),
			'currency'       => $order->get_currency(),
			'due_date'       => current_time( 'Y-m-d' ),
			'account_number' => $account['number'] ?? '',
			'bank_code'      => $account['bank_code'] ?? '',
			'iban'           => isset( $account['iban'] ) ? str_replace( ' ', '', $account['iban'] ) : '',
			'bic'            => isset( $account['bic'] ) ? str_replace( ' ', '', $account['bic'] ) : '',
			'note'           => $note_text,
			'recipient_name' => $account['recipient_name'] ?? '',
		];

		/**
		 * Filter to edit payment details in QR
		 *
		 * @param array    $payment_details payment details
		 * @param WC_Order $order           Order object
		 */
		$payment_details = apply_filters( 'wpify_woo_qr_payment_details', $payment_details, $order );

		/**
		 * Filter to provide custom QR code image data before default generation.
		 *
		 * @param string   $qrCode          QR code image data URI
		 * @param array    $payment_details payment details
		 * @param array    $account         bank account data
		 * @param WC_Order $order           Order object
		 */
		$qrCode = apply_filters( 'wpify_woo_qr_payment_qr_code', $qrCode, $payment_details, $account, $order );

		if ( ! empty( $qrCode ) ) {
			return $qrCode;
		}

		if ( $this->get_setting( 'compatibility_mode' ) && in_array( $account['type'], [ 'cz', 'sk' ], true ) ) {
			if ( 'cz' === $account['type'] ) {
				$account_prefix = '';
				$account_number = $payment_details['account_number'];
				if ( str_contains( $account_number, '-' ) ) {
					$ex             = explode( '-', $account_number );
					$account_prefix = $ex[0];
					$account_number = $ex[1];
				}
				$url    = add_query_arg( [
					'currency'      => (string) $payment_details['currency'],
					'accountPrefix' => (int) $account_prefix,
					'accountNumber' => (int) $account_number,
					'bankCode'      => str_pad( (int) $payment_details['bank_code'], 4, '0', STR_PAD_LEFT ),
					'amount'        => floatval( $payment_details['total'] ),
					'vs'            => (int) $payment_details['vs'],
					'message'       => (string) $payment_details['note'],
				], 'https://api.paylibo.com/paylibo/generator/czech/image' );
				$qrCode = base64_encode( wp_remote_retrieve_body( wp_remote_get( $url ) ) );
				$qrCode = "data:image/png;base64,{$qrCode}";
			} elseif ( 'sk' === $account['type'] ) {
				$url    = add_query_arg( [
					'currency'         => (string) $payment_details['currency'],
					'iban'             => (string) $payment_details['iban'],
					'bankCode'         => str_pad( (int) $payment_details['bank_code'], 4, '0', STR_PAD_LEFT ),
					'amount'           => floatval( $payment_details['total'] ),
					'vs'               => (int) $payment_details['vs'],
					'payment_note'     => (string) $payment_details['note'],
					'beneficiary_name' => (string) $payment_details['recipient_name'],
					'format'           => 'png',
					'size'             => 256,
				], 'https://api.qrgenerator.sk/by-square/pay/base64' );
				$qrCode = json_decode( wp_remote_retrieve_body( wp_remote_get( $url ) ) );
				$qrCode = "data:{$qrCode->mime};base64,{$qrCode->data}";
			}
		} else {
			if ( 'cz' === $account['type'] ) {
				try {
					$iban    = $payment_details['iban'] ? new IBAN( $payment_details['iban'] ) : new CzechIbanAdapter( $payment_details['account_number'], $payment_details['bank_code'] );
					$payment = new QrPayment( $iban, [
						QrPaymentOptions::VARIABLE_SYMBOL => $payment_details['vs'],
						QrPaymentOptions::AMOUNT          => $payment_details['total'],
						QrPaymentOptions::CURRENCY        => $payment_details['currency'],
						QrPaymentOptions::DUE_DATE        => new DateTime( $payment_details['due_date'] ),
						QrPaymentOptions::COMMENT         => $payment_details['note'],
						QrPaymentOptions::PAYEE_NAME      => $payment_details['recipient_name'],
					] );
					$qrCode  = $payment->getQrCode()->getDataUri();
				} catch ( Exception $e ) {
					$this->log->error( sprintf( 'QR payment: error create QR code.' ),
						array(
							'data' => array(
								'order_id'        => $order->get_id(),
								'message'         => $e->getMessage(),
								'payment_details' => $payment_details,
							),
						)
					);

					return new WP_Error( 'error', 'QR ERROR: ' . $e->getMessage() );
				}
			} elseif ( 'sk' === $account['type'] ) {
				try {
					$payment = new \WpifyWooDeps\rikudou\SkQrPayment\QrPayment();
					$options = [
						QrPaymentOptions::AMOUNT                                          => $payment_details['total'],
						QrPaymentOptions::CURRENCY                                        => $payment_details['currency'],
						QrPaymentOptions::DUE_DATE                                        => new DateTime( $payment_details['due_date'] ),
						QrPaymentOptions::VARIABLE_SYMBOL                                 => $payment_details['vs'],
						QrPaymentOptions::COMMENT                                         => $payment_details['note'],
						QrPaymentOptions::PAYEE_NAME                                      => $payment_details['recipient_name'],
						\WpifyWooDeps\rikudou\SkQrPayment\Payment\QrPaymentOptions::IBANS => [
							new IBAN( $payment_details['iban'] ),
						],
					];

					/**
					 * Filter options passed to the Slovak QR payment generator.
					 *
					 * @param array    $options         Slovak QR payment options
					 * @param array    $payment_details payment details
					 * @param array    $account         bank account data
					 * @param WC_Order $order           Order object
					 */
					$options = apply_filters( 'wpify_woo_qr_payment_sk_options', $options, $payment_details, $account, $order );

					$payment->setOptions( $options );
					$qrCode = $payment->getQrCode()->getDataUri();
				} catch ( Exception $e ) {
					$this->log->error( sprintf( 'QR payment: error create QR code.' ),
						array(
							'data' => array(
								'order_id'        => $order->get_id(),
								'message'         => $e->getMessage(),
								'payment_details' => $payment_details,
							),
						)
					);

					return new WP_Error( 'error', 'QR ERROR: ' . $e->getMessage() );
				}
			} elseif ( 'hu' === $account['type'] ) {
				try {
					$iban    = new IBAN( $payment_details['iban'] );
					$payment = new \WpifyWooDeps\hubipe\HuQrPayment\QrPayment( $iban );

					$payment
						->setIdCode( HuIdCode::TRANSFER_ORDER )
						->setCharacterSet( HuCharacterSet::UTF_8 )
						->setName( $payment_details['recipient_name'] )
						->setBic( $payment_details['bic'] )
						->setAmount( floatval( $payment_details['total'] ) )
						->setCurrency( $payment_details['currency'] )
						->setDueDate( new DateTime( $payment_details['due_date'] ) )
						->setPaymentSituationIdentifier( HuPurpose::PURCHASE_SALE_OF_GOODS )
						->setPayeeInternalId( $payment_details['vs'] )
						->setRemittance( $payment_details['note'] );


					$qrCode = $payment->getQrCode()->getDataUri();
				} catch ( Exception $e ) {
					$this->log->error( sprintf( 'QR payment: error create QR code.' ),
						array(
							'data' => array(
								'order_id'        => $order->get_id(),
								'message'         => $e->getMessage(),
								'payment_details' => $payment_details,
							),
						)
					);

					return new WP_Error( 'error', 'QR ERROR: ' . $e->getMessage() );
				}
			} elseif ( 'epc' === $account['type'] ) {
				try {
					$payment = new \WpifyWooDeps\rikudou\EuQrPayment\QrPayment( $payment_details['iban'] );

					$payment
						->setCharacterSet( EuCharacterSet::UTF_8 )
						->setBic( $payment_details['bic'] )
						->setBeneficiaryName( $payment_details['recipient_name'] )
						->setAmount( $payment_details['total'] )
						->setPurpose( EuPurpose::ACCOUNT_MANAGEMENT )
						->setCreditorReference( $payment_details['vs'] )
						->setInformation( $payment_details['note'] )
						->setCurrency( $payment_details['currency'] );

					$qrCode = $payment->getQrCode()->getDataUri();
				} catch ( Exception $e ) {
					$this->log->error( sprintf( 'QR payment: error create QR code.' ),
						array(
							'data' => array(
								'order_id'        => $order->get_id(),
								'message'         => $e->getMessage(),
								'payment_details' => $payment_details,
							),
						)
					);

					return new WP_Error( 'error', 'QR ERROR: ' . $e->getMessage() );
				}
			}
		}

		return $qrCode;
	}

	/**
	 * Save QR code as image file
	 *
	 * @param $base64_string
	 * @param $output_file
	 *
	 * @return false|int
	 */
	public function save_as_file( $base64_string, $output_file ) {
		$img  = str_replace( 'data:image/png;base64,', '', $base64_string );
		$img  = str_replace( ' ', '+', $img );
		$data = base64_decode( $img );
		$file = $output_file;

		return file_put_contents( $file, $data );
	}

	/**
	 * Display QR code
	 *
	 * @param int|WC_Order $order
	 * @param array        $qr_method
	 *
	 * @return void|WP_Error|null
	 * @throws Exception
	 */
	public function display_qr_code( $order, $qr_method = [] ) {
		if ( is_numeric( $order ) ) {
			$order = wc_get_order( $order );
		}

		if ( $qr_method ) {
			$payment_methods = [ $qr_method ];
		} else {
			$payment_methods = $this->get_setting( 'payment_methods' );
		}

		if ( ! is_array( $payment_methods ) || empty( $payment_methods ) ) {
			return null;
		}

		$payment_method = $order->get_payment_method();
		$currency       = $order->get_currency();
		$country        = $order->get_billing_country();
		$accounts       = [];

		foreach ( $payment_methods as $item ) {
			if ( empty( $item['payment_method'] ) || $payment_method !== $item['payment_method'] ) {
				continue;
			}

			foreach ( $item['accounts'] as $account ) {
				if ( 'auto' === $account['type'] && ! empty( $account['enabled_currencies'] ) && ! in_array( $currency, $account['enabled_currencies'] ) ) {
					continue;
				}
				$enabled_countries = ! empty( $account['enabled_countries'] ) ? $account['enabled_countries'] : array_keys( WC()->countries->get_allowed_countries() );
				if ( ! in_array( $country, $enabled_countries ) ) {
					continue;
				}
				$accounts[] = $account;
			}
		}
		if ( empty( $accounts ) ) {
			return null;
		}

		$qrCodes = [];
		$qrInfo  = [];

		foreach ( $accounts as $key => $account ) {
			/**
			 * Filter to skip rendering QR
			 *
			 * @param bool     $skip    skip render
			 * @param WC_Order $order   WC order object
			 * @param array    $account bank account data
			 */
			if ( apply_filters( 'wpify_woo_skip_qr_payment', false, $order, $account ) ) {
				continue;
			}

			$account = $this->validate_account_data( $account, $order );

			if ( is_wp_error( $account ) ) {
				continue;
			}

			$base64 = $this->render_qr_code( $order, $account );

			if ( is_wp_error( $base64 ) ) {
				echo esc_html( $base64->get_error_message() );
				continue;
			}

			if ( $this->get_setting( 'save_img' ) ) {
				$qr_path  = wp_upload_dir()['basedir'] . '/qr-payment/';
				$qr_url   = wp_upload_dir()['baseurl'] . '/qr-payment/';
				$hash     = ! empty( $account['number'] ) ? hash( 'sha1', $order->get_id() . $account['number'] ) : hash( 'sha1', $order->get_id() . $account['iban'] );
				$compa    = $this->get_setting( 'compatibility_mode' ) ? '1' : '0';
				$filename = 'qr-' . $account['type'] . $compa . $hash . '.png';

				if ( ! file_exists( $qr_path ) ) {
					mkdir( $qr_path, 0755, true ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- Direct file I/O required to cache generated QR images in the uploads dir.
				}

				if ( ! file_exists( $qr_path . $filename ) ) {
					$save_img = $this->save_as_file( $base64, $qr_path . $filename );

					if ( ! $save_img ) {
						return new WP_Error( 'error', __( 'The creation of the file for the QR code failed.', 'wpify-woo' ) );
					}
				}

				$qrCodes[ $key ] = $qr_url . $filename;
			} else {
				$qrCodes[ $key ] = $base64;
			}

			$qrInfo[ $key ] = $account['label'] ?? '';
		}

		if ( $qrCodes ) {
			$replaces = [
				'{order}' => $order->get_order_number(),
				'{total}' => wc_price( $order->get_total() ),
			];

			$title_before = str_replace( array_keys( $replaces ), array_values( $replaces ), $this->get_setting( 'title_before' ) );
			$title_after  = str_replace( array_keys( $replaces ), array_values( $replaces ), $this->get_setting( 'title_after' ) );

			echo '<style>.wpify-woo-qr-payment_code {max-width: 120px;}</style>';
			echo '<div class="wpify-woo-qr-payment">';
			echo wp_kses_post( sprintf( '<div class="wpify-woo-qr-payment_title-before">%s</div>', $title_before ) );
			foreach ( $qrCodes as $qrKey => $qrCode ) {
				if ( is_wp_error( $qrCode ) ) {
					echo esc_html( $qrCode->get_error_message() );
				} else {
					$altText = __( 'QR Payment', 'wpify-woo' );
					if ( isset( $qrInfo[ $qrKey ] ) && ! empty( $qrInfo[ $qrKey ] ) ) {
						echo '<div class="wpify-woo-qr-payment_code">';
						echo '<p>' . esc_html( $qrInfo[ $qrKey ] ) . '</p>';
						echo "<img src='" . esc_attr( $qrCode ) . "' alt='" . esc_attr( $altText ) . "' style='display: inline-block'>";
						echo '</div>';
					} else {
						echo "<img class='wpify-woo-qr-payment_code' src='" . esc_attr( $qrCode ) . "' alt='" . esc_attr( $altText ) . "' style='display: inline-block'>";
					}
				}
			}
			echo wp_kses_post( sprintf( '<div class="wpify-woo-qr-payment_title-after">%s</div>', $title_after ) );
			echo '</div>';
		}
	}

	/**
	 * Display QR code in emails
	 *
	 * @param int|WC_Order         $order
	 * @param WC_Email|string|null $email
	 *
	 * @throws Exception
	 */
	public function display_qr_code_in_email( $order = null, $sent_to_admin = null, $plain_text = null, $email = null ) {
		$payment_methods = $this->get_setting( 'payment_methods' );

		if ( ! is_array( $payment_methods ) || empty( $payment_methods ) ) {
			return null;
		}

		if ( is_numeric( $order ) ) {
			$order = wc_get_order( $order );
		}

		foreach ( $payment_methods as $item ) {
			if (
				empty( $order )
				|| ! is_a( $order, 'WC_Order' )
				|| $order->get_payment_method() != $item["payment_method"]
				|| empty( $email )
				|| ! is_a( $email, 'WC_Email' )
				|| empty( $item['enabled_emails'] )
				|| ! in_array( $email->id, $item['enabled_emails'] )
				|| $plain_text
			) {
				continue;
			}

			$this->display_qr_code( $order, $item );
		}
	}

	/**
	 * Render the [wpify_woo_render_qr_code] or [wpify_woo_render_qr_code order_id="123"] shortcode.
	 *
	 * @return string
	 * @throws Exception
	 */
	public function display_qr_code_shortcode( $atts = [] ) {
		$atts = shortcode_atts( [
			'order_id' => null,
		], $atts );

		$order_id = null;

		// 1. If order_id is in the shortcode
		if ( ! empty( $atts['order_id'] ) ) {
			$order_id = absint( $atts['order_id'] );

			// 2. If there is a key in the URL
		} elseif ( isset( $_GET['key'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only lookup of an order by its WooCommerce order key for display.
			$order_id = wc_get_order_id_by_order_key( sanitize_text_field( wp_unslash( $_GET['key'] ) ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only lookup of an order by its WooCommerce order key for display.

			// 3. If we run in an email context
		} elseif ( did_action( 'woocommerce_email_header' ) ) {
			global $email;
			if ( isset( $email ) && is_object( $email ) && method_exists( $email, 'get_order' ) ) {
				$order = $email->get_order();
				if ( $order instanceof WC_Order ) {
					$order_id = $order->get_id();
				}
			}

			// 4. If global $order is available
		} elseif ( isset( $GLOBALS['order'] ) && $GLOBALS['order'] instanceof WC_Order ) {
			$order_id = $GLOBALS['order']->get_id();

			// 5. If the current order page is in "My Account"
		} elseif ( function_exists( 'get_query_var' ) ) {
			$order_id = absint( get_query_var( 'order-pay' ) ); // thankyou/order-pay
			if ( ! $order_id ) {
				$order_id = absint( get_query_var( 'view-order' ) ); // my-account/view-order
			}
		}

		if ( empty( $order_id ) ) {
			return '';
		}

		ob_start();
		$this->display_qr_code( $order_id );

		return ob_get_clean();
	}

	/**
	 * Validate and prepare account data for QR code generation
	 *
	 * @param array    $account Account configuration data
	 * @param WC_Order $order   WooCommerce order object
	 *
	 * @return array|WP_Error Validated account data or WP_Error on failure
	 */
	public function validate_account_data( $account, $order ) {
		$country  = $order->get_billing_country();
		$currency = $order->get_currency();

		if ( 'auto' === $account['type'] ) {
			if ( 'CZ' === $country ) {
				$account['type'] = 'cz';
			} elseif ( 'SK' === $country ) {
				$account['type'] = 'sk';
			} elseif ( 'HU' === $country ) {
				$account['type'] = 'hu';
			} else {
				$account['type'] = 'epc';
			}
		}

		if (
			( 'cz' === $account['type'] && 'CZK' !== $currency ) ||
			( 'sk' === $account['type'] && 'EUR' !== $currency ) ||
			( 'hu' === $account['type'] && 'HUF' !== $currency ) ||
			( 'epc' === $account['type'] && 'EUR' !== $currency )
		) {
			$message = __( 'QR payment: Unsupported currency for QR standard.', 'wpify-woo' );
			$this->log->error( sprintf( $message ),
				array(
					'data' => array(
						'order_id' => $order->get_id(),
						'country'  => $country,
						'standard' => $account['type'],
						'currency' => $currency,
					),
				)
			);

			return new WP_Error( 'error', $message );
		}

		$source = $account['source'] ?? '';
		if ( ! empty( $source ) || '0' == $source ) {
			$bacs_data = $this->get_bacs_account_data( $source );

			if ( ! empty( $bacs_data ) ) {

				if ( ! empty( $bacs_data['account_number'] ) ) {
					$bacs_data['account_number'] = preg_replace( '/[\s\x{00a0}]+/u', '', $bacs_data['account_number'] );
					$numbers              = explode( '/', $bacs_data['account_number'] );
					$account['number']    = $numbers[0] ?? '';
					$account['bank_code'] = $numbers[1] ?? '';
				}

				if ( ! empty( $bacs_data['iban'] ) ) {
					$account['iban'] = $bacs_data['iban'];
				}

				if ( ! empty( $bacs_data['bic'] ) ) {
					$account['bic'] = $bacs_data['bic'];
				}

				if ( ! empty( $bacs_data['account_name'] ) ) {
					$account['recipient_name'] = $account['recipient_name'] ?: $bacs_data['account_name'];
				}

			}
		}

		foreach ( array( 'number', 'bank_code', 'iban', 'bic' ) as $key ) {
			if ( ! empty( $account[ $key ] ) ) {
				$account[ $key ] = preg_replace( '/[\s\x{00a0}]+/u', '', $account[ $key ] );
			}
		}

		return apply_filters( 'wpify_woo_qr_account_data', $account, $order );
	}

	/**
	 * Display QR code in WCPDF invoices
	 *
	 * @param string   $invoice_type Type of WCPDF document
	 * @param WC_Order $order        WooCommerce order object
	 *
	 * @return void
	 * @throws Exception
	 */
	public function display_qr_code_in_wcpdf( $invoice_type, $order ) {
		$render = $this->get_setting( 'in_wcpdf' ) ?: false;

		if ( 'invoice' !== $invoice_type || ! $render ) {
			return;
		}

		$this->display_qr_code( $order );
	}

	/**
	 * Get BACS account data by key
	 *
	 * @param int|string $key Account index from BACS settings
	 *
	 * @return array|null Account data or null if not found
	 */
	public function get_bacs_account_data( $key ) {
		$bacs_accounts_info = get_option( 'woocommerce_bacs_accounts' );

		return $bacs_accounts_info[ $key ] ?: null;
	}

	/**
	 * Get BACS accounts as select options for settings
	 *
	 * @return array[] Array of options with value and label keys
	 */
	public function get_bacs_accounts_options() {
		$bacs_accounts_info = get_option( 'woocommerce_bacs_accounts' );
		$options            = [
			[
				'value' => '',
				'label' => __( 'Manual', 'wpify-woo' ),
			]
		];
		foreach ( $bacs_accounts_info as $key => $value ) {
			$options[] = [
				'value' => $key,
				'label' => $value['account_name']
			];
		}

		return $options;

	}
}
