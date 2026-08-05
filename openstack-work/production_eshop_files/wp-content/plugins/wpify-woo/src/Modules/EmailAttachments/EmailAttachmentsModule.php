<?php

namespace WpifyWoo\Modules\EmailAttachments;

defined( 'ABSPATH' ) || exit;

use WC_Order;
use WC_Order_Item_Product;
use WC_Product;
use WpifyWoo\Plugin;
use WpifyWoo\WooCommerceIntegration;
use WpifyWooDeps\Wpify\WooCore\Abstracts\AbstractModule;
use WpifyWooDeps\Wpify\CustomFields\CustomFields;
use WpifyWooDeps\Wpify\Log\RotatingFileLog;

class EmailAttachmentsModule extends AbstractModule {

	public function __construct(
		private CustomFields $custom_fields,
		private WooCommerceIntegration $woocommerce_integration,
		public RotatingFileLog $log,
	) {
		parent::__construct();
		$this->setup();
	}

	/**
	 * @return void
	 */
	public function setup() {
		add_filter( 'woocommerce_email_attachments', array( $this, 'add_attachments_to_emails' ), 10, 3 );
		add_action( 'init', [ $this, 'product_attachments_metabox' ] );
	}

	function id() {
		return 'email_attachments';
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
		return 'wpify-woo/modules/email-attachments';
	}

	public function product_attachments_metabox() {
		$this->custom_fields->create_product_options(
			[
				'tab'           => array(
					'id'       => 'email_attachments',
					'label'    => __( 'Attachments', 'wpify-woo' ),
					'priority' => 100,
				),
				'init_priority' => 10,
				'items'         => $this->settings(),
			]
		);
	}

	/**
	 * @return array[]
	 */
	public function settings(): array {
		return array(
			array(
				'id'    => 'email_attachments',
				'type'  => 'multi_group',
				'title' => __( 'Email attachments', 'wpify-woo' ),
				'label' => __( 'Email attachments', 'wpify-woo' ),
				'items' => [
					[
						'id'           => 'email',
						'label'        => __( 'Attach to emails', 'wpify-woo' ),
						'type'         => 'multi_select',
						'options'      => function ($args) {
							return $this->woocommerce_integration->get_emails_select($args);
						},
						'async'        => true,
						'async_params' => array(
							'tab'       => 'wpify-woo-settings',
							'section'   => $this->id(),
							'module_id' => $this->id(),
						),
					],
					[
						'id'           => 'enabled_countries',
						'label'        => __( 'Enabled countries', 'wpify-woo' ),
						'desc'         => __( 'Select the countries for which the attachment should be added. Leave empty for all.', 'wpify-woo' ),
						'type'         => 'multi_select',
						'options'      => function ($args) {
							return $this->woocommerce_integration->get_countries_select($args);
						},
						'async'        => true,
						'async_params' => array(
							'tab'       => 'wpify-woo-settings',
							'section'   => $this->id(),
							'module_id' => $this->id(),
						),
					],
					[
						'id'    => 'attachments',
						'label' => __( 'Attachments', 'wpify-woo' ),
						'type'  => 'multi_attachment',
					],
					[
						'id'    => 'custom_fields',
						'label' => __( 'Custom fields', 'wpify-woo' ),
						'type'  => 'multi_group',
						'items' => [
							[
								'id'    => 'custom_field',
								'label' => __( 'Custom field', 'wpify-woo' ),
								'desc'  => __( 'Enter order custom field, where the path the file is stored.', 'wpify-woo' ),
								'type'  => 'text',
							],
						],
					],
				],
			)
		);
	}


	public function add_attachments_to_emails( $attachments, $email_id, $data ) {
		if ( ! is_a( $data, WC_Order::class ) ) {
			$this->log->error( 'NO WC_Order class', array('id' => $email_id) );
			return $attachments;
		}

		// Global emails
		$country     = $data->get_shipping_country() ?: $data->get_billing_country();
		$items       = $this->get_setting( 'email_attachments' ) ?: [];
		$attachments = array_merge( $attachments, $this->add_attachments( $items, $email_id, $country, $data ) );

		// Product emails.
		foreach ( $data->get_items() as $item ) {
			/**  @var $item WC_Order_Item_Product */
			if ( ! is_a( $item, WC_Order_Item_Product::class ) || ! is_a( $item->get_product(), WC_Product::class ) ) {
				continue;
			}

			$items = $item->get_product()->get_meta( 'email_attachments' );

			if ( empty( $items ) ) {
				continue;
			}

			$attachments = array_merge( $attachments, $this->add_attachments( $items, $email_id, $country, $data ) );
		}

		$this->log->info( 'attachments', array('id' => $email_id, 'att' => $attachments) );
		return array_unique( $attachments );
	}

	public function add_attachments( $items, $email_id, $country, WC_Order $order ) {
		$attachments = [];
		foreach ( $items as $item ) {
			if ( ! in_array( $email_id, $item['email'] ) ) {
				continue;
			}

			$enabled_countries = ! empty( $item['enabled_countries'] ) ? $item['enabled_countries'] : array_keys( WC()->countries->get_allowed_countries() );
			if ( ! in_array( $country, $enabled_countries ) ) {
				continue;
			}

			if ( ! empty( $item['attachments'] ) ) {
				foreach ( $item['attachments'] as $attachment_id ) {
					$file = get_attached_file( $attachment_id );
					if ( $file ) {
						$attachments[] = $file;
					}
				}
			}

			if ( ! empty( $item['custom_fields'] ) ) {
				foreach ( $item['custom_fields'] as $field ) {
					$file_path = $order->get_meta( $field['custom_field'] );
					if ( $file_path && file_exists( $file_path ) ) {
						$attachments[] = $file_path;
					}
				}
			}
		}
		return $attachments;
	}

	public function name() {
		return __( 'Email attachments', 'wpify-woo' );
	}
}
