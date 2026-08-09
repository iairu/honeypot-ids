<?php

namespace WpifyWoo\Modules\XmlFeedHeureka;

defined( 'ABSPATH' ) || exit;

use WpifyWoo\Plugin;
use WpifyWooDeps\Wpify\WooCore\Abstracts\AbstractModule;
use WpifyWoo\Managers\ApiManager;

class XmlFeedHeurekaModule extends AbstractModule {
	/**
	 * @var Feed
	 */
	private $feed;

	private $temp_categories = [];

	public function __construct(
		Feed $feed,
		private ApiManager $api_manager,
	) {
		parent::__construct();
		$this->feed = $feed;
		$this->setup();
	}

	public function setup() {
		add_action( 'admin_init', [ $this, 'handle_actions' ] );
		add_filter( 'woocommerce_product_data_tabs', [ $this, 'add_product_tabs' ] );
		add_action( 'woocommerce_product_data_panels', [ $this, 'add_product_tabs_content' ] );
		add_action( 'woocommerce_process_product_meta', [ $this, 'save_custom_fields' ] );
		add_action( 'woocommerce_product_after_variable_attributes', [ $this, 'add_custom_variations_fields' ], 10, 3 );
		add_action( 'woocommerce_save_product_variation', [ $this, 'save_custom_variation_fields' ], 10, 2 );
	}

	/**
	 * Set the module ID.
	 * @return string
	 */
	public function id(): string {
		return 'xml_feed_heureka';
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
		return 'wpify-woo/modules/xml-feed-heureka';
	}

	function add_product_tabs( $tabs ) {
		$tabs['additional_info'] = [
			'label'    => __( 'Heureka XML', 'wpify-woo' ),
			'target'   => 'wpify_woo_heureka_xml',
			'priority' => 200,
		];

		return $tabs;
	}

	public function add_product_tabs_content() { ?>
		<div id="wpify_woo_heureka_xml" class="panel woocommerce_options_panel hidden"><?php

		woocommerce_wp_text_input( [
			'id'    => '_wpify_woo_heureka_product_name',
			'label' => __( 'Heureka Product name', 'wpify-woo' ),
		] );
		woocommerce_wp_text_input( [
			'id'    => '_wpify_woo_heureka_product',
			'label' => __( 'Heureka Product', 'wpify-woo' ),
		] );
		woocommerce_wp_text_input( [
			'id'    => '_wpify_woo_heureka_category',
			'label' => __( 'Heureka Category', 'wpify-woo' ),
		] );

		?></div><?php
	}

	public function add_custom_variations_fields( $loop, $variation_data, $variation ) {
		echo '<div class="options_group form-row form-row-full">';

		woocommerce_wp_text_input(
			array(
				'id'    => '_wpify_woo_heureka_product_name[' . $variation->ID . ']',
				'label' => __( 'Heureka Product name', 'wpify-woo' ),
				'value' => get_post_meta( $variation->ID, '_wpify_woo_heureka_product_name', true ),
			)
		);
		woocommerce_wp_text_input(
			array(
				'id'    => '_wpify_woo_heureka_product[' . $variation->ID . ']',
				'label' => __( 'Heureka Product', 'wpify-woo' ),
				'value' => get_post_meta( $variation->ID, '_wpify_woo_heureka_product', true ),
			)
		);
		woocommerce_wp_text_input(
			array(
				'id'    => '_wpify_woo_heureka_category[' . $variation->ID . ']',
				'label' => __( 'Heureka Category', 'wpify-woo' ),
				'value' => get_post_meta( $variation->ID, '_wpify_woo_heureka_category', true ),
			)
		);
		echo '</div>';
	}

	function save_custom_variation_fields( $post_id ) {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Nonce verified by WooCommerce core before this product-meta hook.
		foreach ( array( '_wpify_woo_heureka_product_name', '_wpify_woo_heureka_product', '_wpify_woo_heureka_category' ) as $key ) {
			if ( isset( $_POST[ $key ][ $post_id ] ) ) {
				update_post_meta( $post_id, $key, sanitize_text_field( wp_unslash( $_POST[ $key ][ $post_id ] ) ) );
			}
		}
		// phpcs:enable WordPress.Security.NonceVerification.Missing
	}

	public function save_custom_fields( $post_id ) {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Nonce verified by WooCommerce core before this product-meta hook.
		$product = wc_get_product( $post_id );
		$product->update_meta_data( '_wpify_woo_heureka_product_name', isset( $_POST['_wpify_woo_heureka_product_name'] ) ? sanitize_text_field( wp_unslash( $_POST['_wpify_woo_heureka_product_name'] ) ) : '' );
		$product->update_meta_data( '_wpify_woo_heureka_product', isset( $_POST['_wpify_woo_heureka_product'] ) ? sanitize_text_field( wp_unslash( $_POST['_wpify_woo_heureka_product'] ) ) : '' );
		$product->update_meta_data( '_wpify_woo_heureka_category', isset( $_POST['_wpify_woo_heureka_category'] ) ? sanitize_text_field( wp_unslash( $_POST['_wpify_woo_heureka_category'] ) ) : '' );
		$product->save();
		// phpcs:enable WordPress.Security.NonceVerification.Missing
	}

	/**
	 * Set the module ID.
	 * @return string
	 */
	public function name() {
		return __( 'XML Feed Heureka', 'wpify-woo' );
	}

	public function settings_tabs(): array {
		return array(
			'general'    => __( 'General', 'wpify-woo' ),
			'shipping'   => __( 'Delivery methods', 'wpify-woo' ),
			'categories' => __( 'Map categories', 'wpify-woo' ),
		);
	}

	/**
	 * Add settings
	 * @return array[] Settings.
	 */
	public function settings(): array {
		$settings = array(
			array(
				'id'      => 'delivery',
				'type'    => 'text',
				'label'   => __( 'Delivery time', 'wpify-woo' ),
				'desc'    => __( 'Enter 0 for instock, 1-3 for 3 days, 4-7 for one week, 8-14 for two weeks, 15-30 for one month, 31 and more for month and more.', 'wpify-woo' ),
				'default' => '0',
				'tab'     => 'general',
			),
			array(
				'id'      => 'delivery_out_of_stock',
				'type'    => 'text',
				'label'   => __( 'Delivery time for out of stock items', 'wpify-woo' ),
				'desc'    => __( 'Enter 0 for instock, 1-3 for 3 days, 4-7 for one week, 8-14 for two weeks, 15-30 for one month, 31 and more for month and more.', 'wpify-woo' ),
				'default' => '0',
				'tab'     => 'general',
			),
			array(
				'id'    => 'exclude_outofstock',
				'type'  => 'toggle',
				'title' => __( 'Exclude out of stock items', 'wpify-woo' ),
				'desc'  => __( 'Check to exclude out of stock items.', 'wpify-woo' ),
				'tab'   => 'general',
			),
			array(
				'id'    => 'item_id_custom_field',
				'type'  => 'text',
				'label' => __( 'ITEM_ID custom field', 'wpify-woo' ),
				'desc'  => __( 'Product ID is used as default value for ITEM_ID. Enter custom field key if you want to use custom field value instead.', 'wpify-woo' ),
				'tab'   => 'general',
			),
			array(
				'id'    => 'ean_custom_field',
				'type'  => 'text',
				'label' => __( 'EAN custom field', 'wpify-woo' ),
				'desc'  => __( 'SKU is used as default value for EAN. Enter custom field key if you want to use custom field value instead.', 'wpify-woo' ),
				'tab'   => 'general',
			),
		);

		$settings[] = array(
			'id'    => 'delivery_methods_title',
			'type'  => 'title',
			'title' => __( 'Delivery methods', 'wpify-woo' ),
			'desc'  => __( 'Select the delivery methods and prices', 'wpify-woo' ),
			'tab'   => 'shipping',
		);

		$settings[] = array(
			'id'      => 'delivery_methods',
			'type'    => 'multi_group',
			'label'   => __( 'Delivery methods', 'wpify-woo' ),
			'min'     => 0,
			'buttons' => array(
				'add' => __( 'Add method', 'wpify-woo' ),
			),
			'tab'     => 'shipping',
			'items'   => array(
				array(
					'id'           => 'method',
					'type'         => 'select',
					'label'        => __( 'Delivery method', 'wpify-woo' ),
					'desc'         => __( 'Select delivery method', 'wpify-woo' ),
					'options'      => array( $this, 'get_heureka_delivery_methods_select' ),
					'async'        => true,
					'async_params' => array(
						'tab'       => 'wpify-woo-settings',
						'section'   => $this->id(),
						'module_id' => $this->id(),
					),
				),
				array(
					'id'    => 'price',
					'type'  => 'text',
					'label' => __( 'Price', 'wpify-woo' ),
					'desc'  => __( 'Enter price for delivery.', 'wpify-woo' ),
				),
				array(
					'id'    => 'price_cod',
					'type'  => 'text',
					'label' => __( 'Price COD', 'wpify-woo' ),
					'desc'  => __( 'Enter price for delivery with COD.', 'wpify-woo' ),
				),
				array(
					'id'      => 'product_type',
					'type'    => 'select',
					'label'   => __( 'Only for product type', 'wpify-woo' ),
					'desc'    => __( 'Select the product types to which this shipping option should be restricted.', 'wpify-woo' ),
					'options' => array(
						array(
							'label' => __( 'Only virtual', 'wpify-woo' ),
							'value' => 'virtual'
						),
						array(
							'label' => __( 'Only non-virtual', 'wpify-woo' ),
							'value' => 'non-virtual'
						),
					),
				),
			),
		);

		$settings[] = array(
			'id'    => 'map_categories_title',
			'type'  => 'title',
			'title' => __( 'Map categories', 'wpify-woo' ),
			'desc'  => __( 'Map WooCommerce categories to Heureka categories', 'wpify-woo' ),
			'tab'   => 'categories',
		);

		$settings[] = array(
			'id'      => 'categories_languages',
			'type'    => 'multi_select',
			'multi'   => true,
			'desc'    => __( 'Select languages to show in the select bellow. Please make sure to save settings to show all the selected languages.', 'wpify-woo' ),
			'label'   => __( 'Categories languages', 'wpify-woo' ),
			'options' => array(
				array(
					'label' => 'CZ',
					'value' => 'cz',
				),
				array(
					'label' => 'SK',
					'value' => 'sk',
				),
			),
			'default' => array(),
			'tab'     => 'categories',
		);


		$settings[] = array(
			'id'     => 'update_categories_button',
			'type'   => 'button',
			'desc'   => __( 'Click to update the Heureka categories.', 'wpify-woo' ),
			'label'  => __( 'Update Heureka categories', 'wpify-woo' ),
			'title'  => __( 'Update categories', 'wpify-woo' ),
			'url'    => add_query_arg(
				array(
					'wpify-woo-action' => 'update-heureka-categories',
					'_wpnonce'         => wp_create_nonce( 'wpify-woo-update-heureka-categories' ),
				),
				$this->get_settings_url()
			),
			'tab'    => 'categories',
			'target' => '_self'
		);

		$categories = get_terms( apply_filters( 'wpify_heureka_categories_assignment', array(
			'taxonomy'   => 'product_cat',
			'hide_empty' => false
		) ) );

		if ( ! is_wp_error( $categories ) ) {
			foreach ( $categories as $category ) {
				$settings[] = array(
					'id'           => 'heureka_category_' . $category->term_id,
					/* translators: %s: category name */
					'label'        => sprintf( __( 'Heureka category for %s', 'wpify-woo' ), $category->name ),
					'type'         => 'select',
					'options'      => array( $this, 'get_heureka_categories_list' ),
					'list_id'      => 'wpify_woo_heureka_category',
					'tab'          => 'categories',
					'async'        => true,
					'async_params' => array(
						'tab'       => 'wpify-woo-settings',
						'section'   => $this->id(),
						'module_id' => $this->id(),
					),
				);
			}
		}

		$settings[] = array(
			'id'             => 'generate_button',
			'type'           => 'generate_feed',
			'desc'           => sprintf(
				/* translators: %1$s: feed URL, %2$s: REST API endpoint for cron job */
				__( 'Click to regenerate feed. Make sure to save the settings before generating the feed.<br/>The feed will be available at <a href="%1$s" target="_blank"><code style="-webkit-user-select: all;user-select: all;">%1$s</code></a>.<br/>You can also setup cron job to <code style="-webkit-user-select: all;user-select: all;">%2$s</code> to regenerate the feed automatically.', 'wpify-woo' ),
				$this->feed->get_xml_url(),
				$this->api_manager->get_rest_url() . '/feed/generate/heureka'
			),
			'label'          => __( 'Generate feed', 'wpify-woo' ),
			'title'          => __( 'Generate feed', 'wpify-woo' ),
			'feed_chunk_url' => $this->api_manager->get_rest_url() . '/feed/chunk-generate/heureka',
			'tab'            => 'general',
		);

		$writable_check = $this->can_write_feed_file();
		if ( $writable_check ) {
			$settings[] = array(
				'id'   => 'error_title',
				'type' => 'title',
				'desc' => sprintf( '<p style="color:red"><strong>%s</strong>: %s</p>', __( 'Error saving files', 'wpify-woo' ), $writable_check ),
				'tab'  => 'general',
			);
		}

		return $settings;
	}

	public function can_write_feed_file(): string {
		$dir       = $this->feed->get_dir_path();
		$file      = $this->feed->get_xml_path();
		$temp_dir  = $this->feed->get_tmp_dir_path();
		$temp_file = $this->feed->get_tmp_file_path();

		if ( ! file_exists( $dir ) ) {
			$parent_dir = dirname( $dir );
			if ( ! is_writable( $parent_dir ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Direct file I/O required for streamed feed generation to uploads dir.
				return sprintf(
					/* translators: %s: parent directory path */
					__( 'Nelze vytvořit složku – nadřazená složka není zapisovatelná: %s', 'wpify-woo' ),
					$parent_dir
				);
			}
			if ( ! mkdir( $dir, 0777, true ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- Direct file I/O required for streamed feed generation to uploads dir.
				return sprintf(
					/* translators: %s: directory path */
					__( 'Nepodařilo se vytvořit složku: %s', 'wpify-woo' ),
					$dir
				);
			}
		} elseif ( ! is_writable( $dir ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Direct file I/O required for streamed feed generation to uploads dir.
			return sprintf(
				/* translators: %s: directory path */
				__( 'Složka existuje, ale není zapisovatelná: %s', 'wpify-woo' ),
				$dir
			);
		}

		if ( file_exists( $file ) && ! is_writable( $file ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Direct file I/O required for streamed feed generation to uploads dir.
			return sprintf(
				/* translators: %s: file path */
				__( 'Soubor existuje, ale není zapisovatelný: %s', 'wpify-woo' ),
				$file
			);
		}

		if ( ! file_exists( $temp_dir ) ) {
			$parent_dir = dirname( $temp_dir );
			if ( ! is_writable( $parent_dir ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Direct file I/O required for streamed feed generation to uploads dir.
				return sprintf(
					/* translators: %s: parent directory path */
					__( 'Nelze vytvořit temp složku – nadřazená složka není zapisovatelná: %s', 'wpify-woo' ),
					$parent_dir
				);
			}
			if ( ! mkdir( $temp_dir, 0777, true ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- Direct file I/O required for streamed feed generation to uploads dir.
				return sprintf(
					/* translators: %s: temporary directory path */
					__( 'Nepodařilo se vytvořit temp složku: %s', 'wpify-woo' ),
					$temp_dir
				);
			}
		} elseif ( ! is_writable( $temp_dir ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Direct file I/O required for streamed feed generation to uploads dir.
			return sprintf(
				/* translators: %s: temporary directory path */
				__( 'Složka temp existuje, ale není zapisovatelná: %s', 'wpify-woo' ),
				$temp_dir
			);
		}

		if ( file_exists( $temp_file ) && ! is_writable( $temp_file ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Direct file I/O required for streamed feed generation to uploads dir.
			return sprintf(
				/* translators: %s: temporary file path */
				__( 'Soubor temp existuje, ale není zapisovatelný: %s', 'wpify-woo' ),
				$temp_file
			);
		}

		return '';
	}

	public function get_heureka_delivery_methods_select() {
		$select = [];

		foreach ( $this->get_heureka_delivery_methods() as $id => $label ) {
			$select[] = [
				'value' => $id,
				'label' => $label,
			];
		}

		return $select;
	}

	public function get_heureka_delivery_methods() {
		return [
			'CESKA_POSTA'                      => 'Česká pošta - Balík Do ruky',
			'CESKA_POSTA_NAPOSTU_DEPOTAPI'     => 'Česká pošta - Balík Na poštu',
			'CESKA_POSTA_DOPORUCENA_ZASILKA'   => 'Česká pošta - Doporučená zásilka',
			'CSAD_LOGISTIK_OSTRAVA'            => 'ČSAD Logistik Ostrava',
			'DPD'                              => 'DPD (nejedná se o DPD ParcelShop)',
			'DPD_PICKUP'                       => 'DPD Pickup',
			'DPD_BOX'                          => 'DPD Box',
			'DHL'                              => 'DHL',
			'DSV'                              => 'DSV',
			'FOFR'                             => 'FOFR',
			'GEBRUDER_WEISS'                   => 'Gebrüder Weiss',
			'GEIS'                             => 'Geis (nejedná se o Geis Point)',
			'GLS'                              => 'GLS',
			'GLS_PARCELSHOP'                   => 'GLS parcel shop',
			'HDS'                              => 'HDS',
			'PPL'                              => 'PPL',
			'PPL_PARCELSHOP'                   => 'PPL parcel shop',
			'PPL_PARCELBOX'                    => 'PPL Parcelbox',
			'SEEGMULLER'                       => 'Seegmuller',
			'TNT'                              => 'TNT',
			'UPS'                              => 'UPS',
			'FEDEX'                            => 'FEDEX',
			'RABEN_LOGISTICS'                  => 'Raben Logistics',
			'ZASILKOVNA'                       => 'Zásilkovna',
			'ZASILKOVNA_NA_ADRESU'             => 'Zásilkovna na adresu (CZ)',
			'ZASIELKOVNA_NA_ADRESU'            => 'Zásielkovňa na adresu (SK)',
			'Z_BOX'                            => 'Z-BOX',
			'BALIKOVNA_DEPOTAPI'               => 'Balíkovna',
			'BALIKOVNA_BOX'                    => 'Balíkovna-BOX',
			'WEDO_HOME'                        => 'WE|DO HOME',
			'WEDO_POINT'                       => 'WE|DO POINT',
			'WEDO_BOX'                         => 'WE|DO BOX',
			'ULOZENKA'                         => 'Uloženka by WeDo',
			'SLOVENSKA_POSTA'                  => 'Slovenská pošta - Balík na adresu',
			'SLOVENSKA_POSTA_NAPOSTU_DEPOTAPI' => 'Slovenská pošta - Balík na poštu',
			'EXPRES_KURIER'                    => 'Expres Kuriér',
			'INTIME'                           => 'InTime',
			'REMAX'                            => 'ReMax Courier Service',
			'TOPTRANS'                         => 'TOPTRANS',
			'SDS'                              => 'SDS',
			'SPS'                              => 'SPS',
			'SPS_PARCELSHOP'                   => 'SPS parcel shop',
			'123KURIER'                        => '123KURIER',
			'PALETEXPRESS'                     => 'PaletExpress',
			'RHENUS_LOGISTICS'                 => 'Rhenus Logistics',
			'MESSENGER'                        => 'MESSENGER',
			'ALZABOX'                          => 'AlzaBox',
			'VLASTNI_PREPRAVA'                 => 'Vlastní přeprava (CZ)',
			'VLASTNA_PREPRAVA'                 => 'Vlastná preprava (SK)',
		];
	}

	public function get_heureka_categories( $lang = '' ) {
		$categories_languages = $this->get_setting( 'categories_languages', true );

		if ( empty( $categories_languages ) || $lang === 'cz' || $lang === 'cs' ||
			 ( count( $categories_languages ) === 1 && $categories_languages[0] === 'cz' )
		) {
			return get_option( 'wpify_woo_heureka_xml_categories', [] );
		}

		if ( $lang ) {
			return get_option( 'wpify_woo_heureka_xml_categories_' . $lang, [] );
		}

		$categories = [];

		foreach ( $categories_languages as $language ) {
			if ( $language === 'cz' ) {
				$categories = array_merge( $categories, get_option( 'wpify_woo_heureka_xml_categories', [] ) );
			} else {
				$categories = array_merge( $categories, get_option( 'wpify_woo_heureka_xml_categories_' . $language, [] ) );
			}
		}

		return $categories;
	}

	private function categories_to_select( $categories = array() ) {
		$select = array();

		foreach ( $categories as $id => $category ) {
			$select[] = array(
				'label' => $category['category_fullname'] ?: $category['category_name'],
				'value' => strval( $category['category_id'] ),
			);
		}

		return $select;
	}

	public function handle_actions() {
		if ( isset( $_GET['wpify-woo-action'] )
			&& 'update-heureka-categories' === $_GET['wpify-woo-action']
			&& current_user_can( 'manage_woocommerce' )
			&& wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['_wpnonce'] ?? '' ) ), 'wpify-woo-update-heureka-categories' ) ) {
			$this->update_heureka_categories();
		}
	}

	public function update_heureka_categories() {
		$xmls = array(
			array(
				'lang'        => 'cz',
				'url'         => 'https://www.heureka.cz/direct/xml-export/shops/heureka-sekce.xml',
				'option_name' => 'wpify_woo_heureka_xml_categories',
			),
			array(
				'lang'        => 'sk',
				'url'         => 'https://www.heureka.sk/direct/xml-export/shops/heureka-sekce.xml',
				'option_name' => 'wpify_woo_heureka_xml_categories_sk',
			),
		);

		foreach ( $xmls as $xml ) {
			$this->temp_categories = [];
			$response_xml_data     = file_get_contents( $xml['url'] );
			if ( $response_xml_data === false ) {
				// Try CURL
				$response_xml_data = $this->file_get_contents_curl( $xml['url'] );
			}
			if ( ! $response_xml_data ) {
				wp_die( esc_html__( 'Downloading of the categories XML failed, please contact your hosting provider.', 'wpify-woo' ) );
			}

			$feed = simplexml_load_string( $response_xml_data );
			foreach ( $feed->CATEGORY as $first_level ) {
				$id                                                = (string) $first_level->CATEGORY_ID;
				$name                                              = (string) $first_level->CATEGORY_NAME;
				$this->temp_categories[ $id ]['category_id']       = $id;
				$this->temp_categories[ $id ]['category_name']     = $name;
				$this->temp_categories[ $id ]['category_fullname'] = '';
				$this->build_categories( $first_level->CATEGORY, $id );
			}
			update_option( $xml['option_name'], $this->temp_categories, false );
		}
	}

	/**
	 * Helper to get file with CURL instead of file_get_contents
	 *
	 * @param $url
	 *
	 * @return bool|string
	 */
	public function file_get_contents_curl( $url ) {
		$response = wp_remote_get(
			$url,
			array(
				'timeout'     => 30,
				'redirection' => 5,
			)
		);

		if ( is_wp_error( $response ) ) {
			return false;
		}

		return wp_remote_retrieve_body( $response );
	}

	public function build_categories( $data, $category_id ) {
		if ( ! empty( $data ) ) {
			foreach ( $data as $item ) {
				$item_id       = (string) $item->CATEGORY_ID;
				$item_name     = (string) $item->CATEGORY_NAME;
				$item_fullname = (string) $item->CATEGORY_FULLNAME;

				if ( ! empty( $item_fullname ) ) {
					$this->temp_categories[ $item_id ]['category_id']       = $item_id;
					$this->temp_categories[ $item_id ]['category_name']     = $item_name;
					$this->temp_categories[ $item_id ]['category_fullname'] = $item_fullname;
				}

				$this->build_categories( $item->CATEGORY, $category_id );
			}
		}
	}

	/**
	 * @return Feed
	 */
	public function get_feed(): Feed {
		return $this->feed;
	}

	/**
	 * @param array $list
	 * @param array $params
	 */
	public function get_heureka_categories_list( $params ) {
		$categories = $this->get_heureka_categories();
		$search     = sanitize_title( $params['search'] );
		$search_ids = array();
		$list       = array();

		if ( ! empty( $params['value'] ) ) {
			$search_ids = is_array( $params['value'] )
				? array_map( 'strval', $params['value'] )
				: array( strval( $params['value'] ) );
		}

		if ( ! empty( $search_ids ) ) {
			foreach ( $categories as $category ) {
				if ( in_array( strval( $category['category_id'] ), $search_ids ) ) {
					$list[] = $category;
				}
			}
		}

		if ( ! empty( $search ) ) {
			foreach ( $categories as $category ) {
				if (
					( strpos( sanitize_title( $category['category_name'] ), $search ) !== false
					  || strpos( sanitize_title( $category['category_fullname'] ), $search ) !== false
					)
					&& ! in_array( strval( $category['category_id'] ), $search_ids )
				) {
					$list[] = $category;
				}
			}
		}

		if ( empty( $search ) && empty( $search_ids ) ) {
			$list = $categories;
		}

		return array_values(
			$this->categories_to_select(
				array_slice( $list, 0, 50 )
			)
		);
	}
}
