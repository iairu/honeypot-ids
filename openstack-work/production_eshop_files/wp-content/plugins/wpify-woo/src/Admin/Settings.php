<?php

namespace WpifyWoo\Admin;

defined( 'ABSPATH' ) || exit;

use WC_Admin_Settings;
use WpifyWoo\Managers\ApiManager;
use WpifyWoo\Managers\ModulesManager;
use WpifyWoo\Plugin;

use WpifyWooDeps\Wpify\Asset\AssetFactory;
use WpifyWooDeps\Wpify\CustomFields\CustomFields;
use WpifyWooDeps\Wpify\PluginUtils\PluginUtils;

/**
 * Class Settings
 *
 * @package WpifyWoo\Admin
 * @property Plugin $plugin
 */
class Settings {
	public const MAIN_SETTINGS_ID = 'wpify-woo';
	public const GENERAL_SECTION_ID = 'general';
	private $id;
	private $label;
	private $pages;

	public function __construct(
		private ModulesManager $modules_manager,
		private AssetFactory $asset_factory,
		private PluginUtils $plugin_utils,
		private ApiManager $api_manager,
	) {
		add_action( 'woocommerce_init', array( $this, 'setup' ) );
	}

	public function setup() {
		$this->id    = 'wpify-woo-settings';
		$this->label = __( 'Wpify Woo', 'wpify-woo' );

		add_filter( 'wpify_get_sections_' . $this::MAIN_SETTINGS_ID, array( $this, 'add_settings_section' ) );

		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_scripts' ) );
		add_filter( 'wpify_admin_menu_bar_data', array( $this, 'add_admin_menu_bar_data' ) );
		add_action( 'wpify_dashboard_before_news_posts', array( $this, 'render_newsletter_block' ) );
		add_action( 'all_admin_notices', array( $this, 'render_newsletter_notice' ), 30 );
		add_action( 'admin_init', array( $this, 'maybe_hyde_newsletter_notice' ) );
	}

	public function option_name() {
		return sprintf( '%s-%s', $this->id, $this::GENERAL_SECTION_ID );
	}

	public function add_settings_section( $sections ) {
		$add_section[ $this::MAIN_SETTINGS_ID ] = array(
			'option_id'   => $this::GENERAL_SECTION_ID,
			'option_name' => $this->option_name(),
			'title'       => __( 'Modules', 'wpify-woo' ),
			'parent'      => $this::MAIN_SETTINGS_ID,
			'menu_slug'   => sprintf( 'wpify/%s', $this::MAIN_SETTINGS_ID ),
			'url'         => add_query_arg( array( 'page' => sprintf( 'wpify/%s', $this::MAIN_SETTINGS_ID ) ), admin_url( 'admin.php' ) ),
			'tabs'        => array(),
			'settings'    => array(
				array(
					'type'      => 'multi_toggle',
					'id'        => 'enabled_modules',
					'label'     => __( 'Enabled modules', 'wpify-woo' ),
					'options'   => $this->modules_manager->get_modules(),
					'desc'      => __( 'Select the modules you want to enable', 'wpify-woo' ),
					'className' => 'wpify__modules-toggle',
					'render_options' => ['noFieldWrapper' => true],
				),
			)
		);

		return array_merge( $add_section, $sections );
	}

	public function enqueue_admin_scripts() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Reading the page slug to gate admin asset loading; no state change.
		$page = isset( $_GET['page'] ) ? sanitize_text_field( wp_unslash( $_GET['page'] ) ) : '';
		if ( ! $page || ! str_contains( $page, 'wpify/' ) ) {
			return;
		}

		$rest_url = $this->api_manager->get_rest_url();

		//$this->asset_factory->admin_wp_script( $this->plugin_utils->get_plugin_path( 'build/settings.css' ) );
		$this->asset_factory->admin_wp_script( $this->plugin_utils->get_plugin_path( 'build/settings.js' ), array(
			'handle'           => 'wpify-settings',
			'variables'        => array(
				'wpifyWooSettings' => array(
					'publicPath'    => $this->plugin_utils->get_plugin_url( 'build/' ),
					'restUrl'       => $this->api_manager->get_rest_url(),
					'nonce'         => wp_create_nonce( $this->api_manager->get_nonce_action() ),
					'activateUrl'   => $rest_url . '/license/activate',
					'deactivateUrl' => $rest_url . '/license/deactivate',
				),
			),
			'translation_path' => $this->plugin_utils->get_plugin_path( 'languages' ),
		) );
	}

	public function is_settings_page() {
		// phpcs:disable WordPress.Security.NonceVerification -- Read-only settings-page detection from query vars; no state change.
		$page = isset( $_GET['page'] ) ? sanitize_text_field( wp_unslash( $_GET['page'] ) ) : '';
		if ( str_contains( $page, 'wpify/' ) ) {
			$subpage = explode( '/', $page )[1] ?? '';
			if ( $subpage === $this::MAIN_SETTINGS_ID ) {
				return \true;
			}
		}
		if ( isset( $_POST[ $this->option_name() ] ) ) {
			return \true;
		}

		// Load items only in admin (for settings pages) or rest (for async lists)
		$section = isset( $_GET['section'] ) ? sanitize_text_field( wp_unslash( $_GET['section'] ) ) : '';
		// phpcs:enable WordPress.Security.NonceVerification
		return ( wp_is_json_request() || is_admin() ) && '' !== $section && $section === $this::GENERAL_SECTION_ID;
	}

	public function add_admin_menu_bar_data( $data ) {
		if ( ! $this->is_settings_page() ) {
			return $data;
		}
		$data['title']    = $this->label;
		$data['icon']     = '';
		$data['parent']   = $this::MAIN_SETTINGS_ID;
		$data['plugin']   = $this->plugin_utils->get_plugin_slug();
		$data['menu'][]   = array(
			'icon'  => '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="1" d="M21 5h-3m-4.25-2v4M13 5H3m4 7H3m7.75-2v4M21 12H11m10 7h-3m-4.25-2v4M13 19H3"/></svg>',
			'label' => __( 'Settings', 'wpify-woo' ),
			'link'  => add_query_arg( array( 'page' => sprintf( 'wpify/%s', $this::MAIN_SETTINGS_ID ) ), admin_url( 'admin.php' ) )
		);
		$data['doc_link'] = $this->get_documentation_url();

		return $data;
	}

	/**
	 * Get documentation URL with locale awareness
	 *
	 * @return string
	 */
	private function get_documentation_url(): string {
		$domain = 'https://docs.wpify.cz/';

		if ( in_array( get_locale(), array( 'cs_CZ', 'sk_SK' ), true ) ) {
			$domain = 'https://docs.wpify.cz/cs/';
		}

		return esc_url( $domain . 'wpify-woo' );
	}

	public function maybe_hyde_newsletter_notice() {
		if ( ! isset( $_POST['submit_wpify_subscription_hide'] ) || ! check_admin_referer( 'wpify_subscription_form', 'wpify_subscription_nonce' ) ) {
			return;
		}

		$display_notice = get_option( 'wpify-woo-display-subscription', '' );
		if ( 'none' === $display_notice ) {
			return;
		}

		$count = (int) get_option( 'wpify-woo-display-subscription-count', 0 ) + 1;

		if ( $count <= 1 ) {
			$new_date = strtotime( '+1 month' );
		} elseif ( 2 === $count ) {
			$new_date = strtotime( '+3 months' );
		} else {
			$new_date = strtotime( '+6 months' );
		}

		update_option( 'wpify-woo-display-subscription', $new_date );
		update_option( 'wpify-woo-display-subscription-count', $count );
	}

	public function render_newsletter_notice() {
		$screen       = get_current_screen();
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Display-only notice gating; no state change.
		$current_page = isset( $_GET['page'] ) ? sanitize_text_field( wp_unslash( $_GET['page'] ) ) : '';

		if ( ! $screen || ! str_contains( $current_page, 'wpify' ) ) {
			return;
		}

		$display_notice = get_option( 'wpify-woo-display-subscription', '' );
		if ( 'none' === $display_notice || ( is_numeric( $display_notice ) && time() < (int) $display_notice ) ) {
			return;
		}

		$icon = '';
		if ( file_exists( $this->plugin_utils->get_plugin_path( 'icon.svg' ) ) ) {
			$icon = $this->plugin_utils->get_plugin_url( 'icon.svg' );
		}
		?>
		<style>
			.wpify__card-full .wpify_subscription_form {
				display: flex;
				flex-wrap: wrap;
			}

			.wpify__card-full .wpify_subscription__email {
				min-width: 25%;
			}

			.wpify__card-full .wpify_subscription__email input[type=email] {
				width: 100%;
			}
		</style>
		<div style="margin: 5px 20px 20px 0;">
			<div class="wpify__card wpify__card-full" style="max-width:100%">
				<div class="wpify__card-body" style="display: flex;flex-wrap: wrap;gap: 20px">
					<?php if ( $icon ) {
						?>
						<div style="margin-top: 20px">
							<img src="<?php echo esc_url( $icon ); ?>" alt="ICO" width="100" height="100">
						</div>
						<?php
					} ?>
					<div style="flex: 1">
						<?php $this->newsletter_content(); ?>
					</div>
					<form method="post" class="wpify_subscription_hide_notice_form" style="margin-top: 20px">
						<?php wp_nonce_field( 'wpify_subscription_form', 'wpify_subscription_nonce' ); ?>
						<button type="submit" name="submit_wpify_subscription_hide" class="button">
							<span class="dashicons dashicons-dismiss" style="line-height: 1.3"></span>
						</button>
					</form>
				</div>
			</div>
		</div>
		<?php
	}

	public function render_newsletter_block() {
		?>
		<style>
			.wpify__card-side .wpify_subscription_form input {
				width: 100%;
			}
		</style>
		<div class="wpify__cards">
			<div class="wpify__card wpify__card-side" style="max-width:100%">
				<div class="wpify__card-body">
					<?php $this->newsletter_content(); ?>
				</div>
			</div>
		</div>
		<?php
	}

	public function newsletter_content() {
		$admin_email = get_option( 'admin_email' );

		?>
		<h3>🚀 <?php esc_html_e( 'Increase sales + 10% discount on your first purchase!', 'wpify-woo' ); ?></h3>
		<p><?php esc_html_e( 'Do you want a faster e-shop, more customers and higher conversions? Sign up for our newsletter and get:', 'wpify-woo' ); ?></p>
		<ul style="list-style: disc;padding-left: 20px">
			<li><?php esc_html_e( 'Tips to speed up your e-shop and improve performance', 'wpify-woo' ); ?></li>
			<li><?php esc_html_e( 'Strategies for more orders and higher profits', 'wpify-woo' ); ?></li>
			<li><?php esc_html_e( '10% discount on your first purchase of premium plugins', 'wpify-woo' ); ?></li>
		</ul>
		<p><?php esc_html_e( 'Sign up now and get exclusive advice + discount code in your email.', 'wpify-woo' ); ?></p>
		<p>
		<form method="post" class="wpify_subscription_form">
			<?php wp_nonce_field( 'wpify_subscription_form', 'wpify_subscription_nonce' ); ?>
			<p class="wpify_subscription__email" style="position: relative;">
				<label for="email" style="position: absolute; top: 50%; left: 10px; transform: translateY(-50%);">
					<span class="dashicons dashicons-email-alt"></span>
				</label>
				<input type="email" name="email" style="padding: 7px 10px 7px 40px;"
					   value="<?php echo esc_attr( $admin_email ); ?>" required/>
			</p>
			<p><input type="submit" name="submit_wpify_subscription" class="button button-primary"
					  value="<?php esc_attr_e( 'I want a better e-shop + discount', 'wpify-woo' ); ?>"/></p>
		</form>
		</p>
		<?php
		if ( isset( $_POST['submit_wpify_subscription'] ) && check_admin_referer( 'wpify_subscription_form', 'wpify_subscription_nonce' ) ) {
			$this->process_fluentcrm_submission();
		} ?>

		<?php
	}

	// Zpracování formuláře a odeslání dat do FluentCRM
	public function process_fluentcrm_submission() {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified via check_admin_referer() in newsletter_content() before this runs.
		$email = isset( $_POST['email'] ) ? sanitize_email( wp_unslash( $_POST['email'] ) ) : '';
		if ( ! is_email( $email ) ) {
			echo wp_kses_post( sprintf( '<div class="wpify-notice wpify-notice-error"><p>%s</p></div>', esc_html__( 'Incorrect email.', 'wpify-woo' ) ) );

			return;
		}

		$api_url  = 'https://wpify.cz/wp-json/fluent-crm/v2/subscribers';
		$api_user = 'managercrm';
		$api_key  = 'XahE M54R 5B00 rFLf Tsje vNLP';

		$args = array(
			'body'    => json_encode( array(
				'email'  => $email,
				'lists'  => array( 5 ),
				'status' => 'subscribed'
			) ),
			'headers' => array(
				'Authorization' => 'Basic ' . base64_encode( $api_user . ':' . $api_key ),
				'Content-Type'  => 'application/json'
			),
			'method'  => 'POST'
		);

		$response      = wp_remote_post( $api_url, $args );
		$response_code = wp_remote_retrieve_response_code( $response );

		if ( $response_code == 200 ) {
			echo wp_kses_post( sprintf( '<div class="wpify-notice wpify-notice-success"><p>%s</p></div>', esc_html__( 'The email address has been successfully added.', 'wpify-woo' ) ) );
			update_option( 'wpify-woo-display-subscription', 'none' );
		} elseif ( $response_code == 422 ) {
			echo wp_kses_post( sprintf( '<div class="wpify-notice wpify-notice-info"><p>%s</p></div>', esc_html__( 'The email address is already on the subscription list.', 'wpify-woo' ) ) );
		} else {
			$response_body = wp_remote_retrieve_body( $response );
			echo sprintf( '<div class="wpify-notice wpify-notice-error"><p>%s</p><code>%s</code></div>', esc_html__( 'Error while sending.', 'wpify-woo' ), esc_html( $response_body ) );
		}
	}
}
