<?php

namespace WpifyWoo\Managers;

defined( 'ABSPATH' ) || exit;

use WpifyWoo\Modules\AsyncEmails\AsyncEmailsModule;
use WpifyWoo\Modules\Comments\CommentsModule;
use WpifyWoo\Modules\DeliveryDates\DeliveryDatesModule;
use WpifyWoo\Modules\EmailAttachments\EmailAttachmentsModule;
use WpifyWoo\Modules\FreeShippingNotice\FreeShippingNoticeModule;
use WpifyWoo\Modules\HeurekaMereniKonverzi\HeurekaMereniKonverziModule;
use WpifyWoo\Modules\HeurekaOverenoZakazniky\HeurekaOverenoZakaznikyModule;
use WpifyWoo\Modules\IcDic\IcDicModule;
use WpifyWoo\Modules\Prices\PricesModule;
use WpifyWoo\Modules\PricesLog\PricesLogModule;
use WpifyWoo\Modules\QRPayment\QRPaymentModule;
use WpifyWoo\Modules\SklikRetargeting\SklikRetargetingModule;
use WpifyWoo\Modules\Template\TemplateModule;
use WpifyWoo\Modules\ZboziConversions\ZboziConversionsModule;
use WpifyWoo\Modules\Vocative\VocativeModule;
use WpifyWoo\Modules\WithdrawalClaims\WithdrawalClaimsModule;
use WpifyWoo\Modules\XmlFeedHeureka\XmlFeedHeurekaModule;
use WpifyWoo\Plugin;
use WpifyWoo\WooCommerceIntegration;
use WpifyWooDeps\Wpify\WooCore\WpifyWooCore;
use WpifyWooDeps\Wpify\WooCore\Abstracts\AbstractModule;

/**
 * Class ApiManager
 *
 * @package WpifyWoo\Managers
 * @property Plugin $plugin
 */
class ModulesManager {
	const OPTION_NAME = 'wpify-woo-settings';

	public function __construct(
		private WpifyWooCore $wpify_woo_core,
	) {

		$this->load_components();
	}

	protected $modules = array();
	private $async_emails = AsyncEmailsModule::class;
	private $ic_dic = IcDicModule::class;
	private $heureka_overeno_zakazniky = HeurekaOverenoZakaznikyModule::class;
	private $heureka_mereni_konverzi = HeurekaMereniKonverziModule::class;
	private $free_shipping_notice = FreeShippingNoticeModule::class;
	private $vocative = VocativeModule::class;
	private $qr_payment = QRPaymentModule::class;
	private $xml_feed_heureka = XmlFeedHeurekaModule::class;
	private $sklik_retargeting = SklikRetargetingModule::class;
	private $zbozi_conversions_lite = ZboziConversionsModule::class;
	private $template = TemplateModule::class;
	private $email_attachments = EmailAttachmentsModule::class;
	private $prices = PricesModule::class;
	private $prices_log = PricesLogModule::class;
	private $comments = CommentsModule::class;
	private $delivery_dates = DeliveryDatesModule::class;
	private $withdrawal_claims = WithdrawalClaimsModule::class;


	private array $modules_ids = [
		'async_emails',
		'ic_dic',
		'heureka_overeno_zakazniky',
		'heureka_mereni_konverzi',
		'xml_feed_heureka',
		'free_shipping_notice',
		'vocative',
		'qr_payment',
		'sklik_retargeting',
		'zbozi_conversions_lite',
		'template',
		'email_attachments',
		'prices',
		'prices_log',
		'comments',
		'delivery_dates',
		'withdrawal_claims',
	];

	public function get_module_by_id( $module ) {
		if ( ! property_exists( $this, $module ) ) {
			return null;
		}

		return wpify_woo_container()->get( $this->{$module} );
	}


	public function load_components() {
		foreach ( $this->modules_ids as $module ) {
			if ( $this->is_module_enabled( $module ) && property_exists( $this, $module ) ) {
				$module = $this->get_module_by_id( $module );
				$this->wpify_woo_core->get_modules_manager()->add_module( $module->id(), $module );
			}
		}
	}

	/**
	 * Get documentation URL for a module
	 *
	 * @param string $module_id Module ID.
	 *
	 * @return string
	 */
	private function get_module_documentation_url( string $module_id ): string {
		// Map module ID to documentation path slug
		$path_map = array(
			'async_emails'             => 'async-emails',
			'ic_dic'                   => 'ic-dic',
			'heureka_overeno_zakazniky' => 'heureka-verified',
			'heureka_mereni_konverzi'  => 'heureka-conversions',
			'xml_feed_heureka'         => 'xml-feed-heureka',
			'free_shipping_notice'     => 'free-shipping-notice',
			'vocative'                 => 'vocative',
			'qr_payment'               => 'qr-payment',
			'sklik_retargeting'        => 'sklik-retargeting',
			'zbozi_conversions_lite'   => 'zbozi-conversions',
			'template'                 => 'template',
			'email_attachments'        => 'email-attachments',
			'prices'                   => 'prices',
			'prices_log'               => 'prices-log',
			'comments'                 => 'comments',
			'delivery_dates'           => 'delivery-dates',
			'withdrawal_claims'        => 'withdrawal-claims',
		);

		$slug   = $path_map[ $module_id ] ?? str_replace( '_', '-', $module_id );
		$path   = 'wpify-woo/modules/' . $slug;
		$domain = 'https://docs.wpify.cz/';

		if ( in_array( get_locale(), array( 'cs_CZ', 'sk_SK' ), true ) ) {
			$domain = 'https://docs.wpify.cz/cs/';
		}

		return esc_url( $domain . $path );
	}

	public function get_modules(): array {
		$modules_data = array(
			array(
				'title' => __( 'Async emails', 'wpify-woo' ),
				'value' => 'async_emails',
			),
			array(
				'title' => __( 'Checkout IČ and DIČ', 'wpify-woo' ),
				'value' => 'ic_dic',
			),
			array(
				'title' => __( 'Heureka ověřeno zákazníky', 'wpify-woo' ),
				'value' => 'heureka_overeno_zakazniky',
			),
			array(
				'title' => __( 'Heureka měření konverzí', 'wpify-woo' ),
				'value' => 'heureka_mereni_konverzi',
			),
			array(
				'title' => __( 'XML Feed Heureka', 'wpify-woo' ),
				'value' => 'xml_feed_heureka',
			),
			array(
				'title' => __( 'Free shipping notice', 'wpify-woo' ),
				'value' => 'free_shipping_notice',
			),
			array(
				'title' => __( 'Emails Vocative', 'wpify-woo' ),
				'value' => 'vocative',
			),
			array(
				'title' => __( 'QR Payment', 'wpify-woo' ),
				'value' => 'qr_payment',
			),
			array(
				'title' => __( 'Sklik retargeting', 'wpify-woo' ),
				'value' => 'sklik_retargeting',
			),
			array(
				'title' => __( 'Zbozi.cz/Sklik Conversions Limited', 'wpify-woo' ),
				'value' => 'zbozi_conversions_lite',
			),
			array(
				'title' => __( 'Template', 'wpify-woo' ),
				'value' => 'template',
			),
			array(
				'title' => __( 'Email attachments', 'wpify-woo' ),
				'value' => 'email_attachments',
			),
			array(
				'title' => __( 'Prices', 'wpify-woo' ),
				'value' => 'prices',
			),
			array(
				'title' => __( 'Prices log', 'wpify-woo' ),
				'value' => 'prices_log',
			),
			array(
				'title' => __( 'Comments', 'wpify-woo' ),
				'value' => 'comments',
			),
			array(
				'title' => __( 'Delivery dates', 'wpify-woo' ),
				'value' => 'delivery_dates',
			),
			array(
				'title' => __( 'Withdrawal & Claim', 'wpify-woo' ),
				'value' => 'withdrawal_claims',
			),
		);

		$modules = array();
		foreach ( $modules_data as $module_data ) {
			$doc_url = $this->get_module_documentation_url( $module_data['value'] );
			$label   = sprintf(
				'<h3>%1$s</h3> <a href="%2$s" target="_blank">%3$s</a>',
				$module_data['title'],
				$doc_url,
				__( 'Documentation', 'wpify-woo' )
			);

			if ( $this->is_module_enabled( $module_data['value'] ) && property_exists( $this, $module_data['value'] ) ) {
				/** @var AbstractModule $module_obj */
				$module_obj = $this->get_module_by_id( $module_data['value'] );
				$label      = sprintf(
					'%1$s <a href="%2$s" class="button">%3$s</a>',
					$label,
					$module_obj->get_settings_url(),
					__( 'Settings', 'wpify-woo' )
				);
			}

			$modules[] = array(
				'label' => $label,
				'title' => $module_data['title'],
				'value' => $module_data['value'],
			);
		}

		return $modules;
	}

	/**
	 * Check if a module is enabled
	 *
	 * @param string $module Module name.
	 *
	 * @return bool
	 */
	public function is_module_enabled( string $module ): bool {
		return in_array( $module, $this->get_enabled_modules(), true );
	}

	/**
	 * Get an array of enabled modules
	 *
	 * @return array
	 */
	public function get_enabled_modules(): array {
		return $this->get_settings( 'general' )['enabled_modules'] ?? array();
	}

	/**
	 * Get settings for a specific module
	 *
	 * @param string $module Module name.
	 *
	 * @return array
	 */
	public function get_settings( string $module ): array {
		return get_option( $this->get_settings_name( $module ), array() );
	}

	public function get_settings_name( string $module ): string {
		return sprintf( '%s-%s', $this::OPTION_NAME, $module );
	}
}
