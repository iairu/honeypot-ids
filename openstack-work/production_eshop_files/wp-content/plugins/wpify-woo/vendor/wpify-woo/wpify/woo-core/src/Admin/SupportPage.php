<?php

namespace WpifyWooDeps\Wpify\WooCore\Admin;

/**
 * Class SupportPage
 *
 * Handles rendering and registration of the WPify Support page.
 *
 * @package Wpify\WooCore\Admin
 */
class SupportPage
{
    const SLUG = 'wpify/support';
    private DashboardPage $dashboard_page;
    private ?array $log_files_cache = null;
    public function __construct(DashboardPage $dashboard_page)
    {
        $this->dashboard_page = $dashboard_page;
        add_action('admin_menu', [$this, 'register']);
        add_action('admin_post_wpify_support_request', [$this, 'handle_support_request']);
    }
    /**
     * Register support submenu page
     *
     * @return void
     */
    public function register(): void
    {
        add_submenu_page(DashboardPage::SLUG, __('WPify Plugins Support', 'wpify-core'), __('Support', 'wpify-core'), 'manage_options', self::SLUG, [$this, 'render'], 99);
    }
    /**
     * Render Support page html
     *
     * @return void
     */
    public function render(): void
    {
        $doc_base = $this->get_docs_base_url();
        $doc_link = add_query_arg(array('utm_source' => 'plugin-support', 'utm_medium' => 'plugin-link', 'utm_campaign' => 'documentation-link'), $doc_base);
        $debug_link = add_query_arg(array('utm_source' => 'plugin-support', 'utm_medium' => 'plugin-link', 'utm_campaign' => 'troubleshooting-link'), $doc_base . 'general/');
        $faqs = apply_filters('wpify_dashboard_support_faqs', array(array('title' => __('How do the pricing plans work?', 'wpify-core'), 'content' => __('When you purchase the plugin, you receive support and updates for one year. After this period, the license will automatically renew.', 'wpify-core')), array('title' => __('Will the plugin work if I do not renew my license?', 'wpify-core'), 'content' => __('Yes, the plugin will continue to work, but you will no longer have access to updates and support.', 'wpify-core')), array('title' => __('I need a feature that the plugin does not currently support.', 'wpify-core'), 'content' => __('Let us know, and we will consider adding the requested functionality.', 'wpify-core'))));
        $active_plugins = $this->get_active_wpify_plugins();
        $log_files = $this->get_log_files();
        $logs_url = $this->get_logs_page_url();
        ?>
		<div class="wpify-dashboard__wrap wrap">
			<div class="wpify-dashboard__content">
				<h1><?php 
        _e('Support page', 'wpify-core');
        ?></h1>

				<?php 
        $sent_status = isset($_GET['wpify_support_sent']) ? sanitize_text_field(wp_unslash($_GET['wpify_support_sent'])) : null;
        if ($sent_status !== null) {
            ?>
					<div class="notice notice-<?php 
            echo $sent_status === '1' ? 'success' : 'error';
            ?> is-dismissible">
						<p>
							<?php 
            echo $sent_status === '1' ? esc_html__('Your support request has been sent. We will get back to you shortly.', 'wpify-core') : esc_html__('Your support request could not be sent. Please try again.', 'wpify-core');
            ?>
						</p>
					</div>
				<?php 
        }
        ?>

				<?php 
        do_action('wpify_dashboard_before_support_content');
        ?>

				<div class="wpify__cards grid-layout-2">
					<div class="wpify__card">
						<div class="wpify__card-body">
							<h2><?php 
        _e('Quick debugging checklist', 'wpify-core');
        ?></h2>
							<ol>
								<li>
									<h3><?php 
        _e('Check order notes', 'wpify-core');
        ?></h3>
                                    <p><?php 
        _e('In the WooCommerce order detail, you’ll find notes that plugins automatically add. Look for messages about errors or failed operations.', 'wpify-core');
        ?></p>
								</li>
								<li>
									<h3><?php 
        _e('Review logs', 'wpify-core');
        ?></h3>
									<p><?php 
        _e('Most plugins log communication in WPify → WPify Logs. Select the relevant plugin and date, look for records marked as ERROR.', 'wpify-core');
        ?></p>
									<?php 
        if (!empty($log_files)) {
            ?>
                                        <p>
											<?php 
            if ($logs_url) {
                ?>
                                                <a class="button" href="<?php 
                echo esc_url($logs_url);
                ?>">
													<?php 
                _e('Open WPify Logs', 'wpify-core');
                ?>
												</a>
											<?php 
            }
            ?>
                                        </p>
									<?php 
        }
        ?>
                                </li>
								<li>
									<h3><?php 
        _e('Check plugin documentation', 'wpify-core');
        ?></h3>
                                    <p><?php 
        _e('Each plugin has its own troubleshooting section with descriptions of common errors and their solutions.', 'wpify-core');
        ?></p>
                                    <ul>
										<?php 
        foreach ($active_plugins as $slug => $plugin) {
            if (empty($plugin['doc_link'])) {
                continue;
            }
            ?>
                                            <li>
                                                <a href="<?php 
            echo esc_url($plugin['doc_link']);
            ?>" target="_blank">
													<?php 
            echo esc_html($plugin['title'] ?? $slug);
            ?>
                                                </a>
                                            </li>
										<?php 
        }
        ?>
                                    </ul>
                                </li>
								<li>
									<h3><?php 
        _e('Contact support', 'wpify-core');
        ?></h3>
                                    <p><?php 
        _e('If the problem persists, email us at support@wpify.io with a description of the problem, steps to reproduce, and relevant log content.', 'wpify-core');
        ?></p>
								</li>
							</ol>
							<p>
								<a href="<?php 
        echo esc_url($debug_link);
        ?>" target="_blank">
									<?php 
        _e('Full debugging guide', 'wpify-core');
        ?>
								</a>
							</p>
						</div>
					</div>
					<div class="wpify__card">
						<div class="wpify__card-body">
							<h2><?php 
        _e('Frequently Asked Questions', 'wpify-core');
        ?></h2>

							<?php 
        foreach ($faqs as $faq) {
            ?>
								<div class="faq">
									<h3><?php 
            echo wp_kses_post($faq['title'] ?? '');
            ?></h3>
									<p><?php 
            echo wp_kses_post($faq['content'] ?? '');
            ?></p>
								</div>
							<?php 
        }
        ?>

                            <h3><?php 
        _e('Do you have any other questions?', 'wpify-core');
        ?></h3>
                            <p><?php 
        _e('Check out the plugin documentation to see if your question is already answered.', 'wpify-core');
        ?></p>
                            <p><a href="<?php 
        echo esc_url($doc_link);
        ?>" target="_blank"
                                  class="button button-primary"><?php 
        _e('Documentation', 'wpify-core');
        ?></a></p>

						</div>
					</div>

					<div class="wpify__card wpify__card--100">
						<div class="wpify__card-body">
							<h2><?php 
        _e('Send a support request', 'wpify-core');
        ?></h2>
							<form method="post" action="<?php 
        echo esc_url(admin_url('admin-post.php'));
        ?>" enctype="multipart/form-data">
								<?php 
        wp_nonce_field('wpify_support_request');
        ?>
								<input type="hidden" name="action" value="wpify_support_request">

								<p>
									<label for="wpify-support-plugin"><strong><?php 
        _e('Plugin', 'wpify-core');
        ?></strong></label><br>
									<select id="wpify-support-plugin" name="plugin" class="regular-text">
										<option value="general"><?php 
        _e('General', 'wpify-core');
        ?></option>
										<?php 
        foreach ($active_plugins as $slug => $plugin) {
            ?>
											<option value="<?php 
            echo esc_attr($slug);
            ?>"><?php 
            echo esc_html($plugin['title'] ?? $slug);
            ?></option>
										<?php 
        }
        ?>
									</select>
								</p>
								<p>
									<label for="wpify-support-subject"><strong><?php 
        _e('Subject (optional)', 'wpify-core');
        ?></strong></label><br>
									<input id="wpify-support-subject" class="regular-text" type="text" name="subject" placeholder="<?php 
        esc_attr_e('Short summary of the issue', 'wpify-core');
        ?>">
								</p>
								<p>
									<label for="wpify-support-email"><strong><?php 
        _e('Contact email', 'wpify-core');
        ?></strong></label><br>
									<input id="wpify-support-email" class="regular-text" type="email" name="email" value="<?php 
        echo esc_attr(wp_get_current_user()->user_email ?? '');
        ?>" required>
								</p>
								<p>
									<label for="wpify-support-message"><strong><?php 
        _e('Message', 'wpify-core');
        ?></strong></label><br>
									<textarea id="wpify-support-message" class="large-text" rows="6" name="message" required></textarea>
								</p>
								<?php 
        if (!empty($log_files)) {
            ?>
									<p>
										<label for="wpify-support-log"><strong><?php 
            _e('Attach log (optional)', 'wpify-core');
            ?></strong></label><br>
										<span style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
											<select id="wpify-support-log" name="log_files[]" class="regular-text" multiple size="4">
												<?php 
            foreach ($log_files as $log) {
                ?>
													<option
														value="<?php 
                echo esc_attr($log['file']);
                ?>"
														data-channel="<?php 
                echo esc_attr($log['channel']);
                ?>"
													>
														<?php 
                echo esc_html($log['label']);
                ?>
													</option>
												<?php 
            }
            ?>
											</select>
										</span>
										<span class="description"><?php 
            _e('Hold Ctrl (Windows) or Cmd (Mac) to select multiple logs.', 'wpify-core');
            ?></span>
									</p>
								<?php 
        }
        ?>
								<p>
									<label for="wpify-support-files"><strong><?php 
        _e('Attach files (optional)', 'wpify-core');
        ?></strong></label><br>
									<input id="wpify-support-files" type="file" name="support_files[]" multiple>
									<span class="description"><?php 
        _e('Screenshots or documents that help explain the issue.', 'wpify-core');
        ?></span>
								</p>
								<p>
									<?php 
        submit_button(__('Send request', 'wpify-core'), 'primary', 'submit', \false);
        ?>
								</p>
							</form>
							<p class="description"><?php 
        _e('Basic diagnostics (site, environment, active WPify plugins) are included automatically.', 'wpify-core');
        ?></p>
						</div>
					</div>

					<?php 
        do_action('wpify_dashboard_support_cards');
        ?>

				</div>

				<?php 
        do_action('wpify_dashboard_after_support_content');
        ?>

			</div>
			<div class="wpify-dashboard__sidebar">
				<?php 
        do_action('wpify_dashboard_before_news_posts');
        $this->dashboard_page->render_news_posts();
        do_action('wpify_dashboard_after_news_posts');
        ?>
			</div>
		</div>
		<?php 
        if (!empty($log_files)) {
            ?>
			<script>
				(function () {
					const pluginSelect = document.getElementById('wpify-support-plugin');
					const logSelect = document.getElementById('wpify-support-log');
					if (!pluginSelect || !logSelect) {
						return;
					}

					const options = Array.from(logSelect.options);
					const normalizeChannel = (value) => (value || '').replace(/-/g, '_');
					const syncOptions = () => {
						const plugin = pluginSelect.value || 'general';
						const channel = plugin === 'general' ? '' : normalizeChannel(plugin);

						options.forEach(option => {
							const optionChannel = normalizeChannel(option.getAttribute('data-channel') || '');
							option.hidden = channel && optionChannel !== channel;
							if (option.hidden) {
								option.selected = false;
							}
						});
					};

					pluginSelect.addEventListener('change', syncOptions);
					syncOptions();
				})();
			</script>
		<?php 
        }
        ?>
		<?php 
    }
    private function get_docs_base_url(): string
    {
        $domain = 'https://docs.wpify.cz/';
        if (in_array(get_locale(), array('cs_CZ', 'sk_SK'), \true)) {
            $domain = 'https://docs.wpify.cz/cs/';
        }
        return $domain;
    }
    private function get_active_wpify_plugins(): array
    {
        $plugins = apply_filters('wpify_installed_plugins', []);
        if (!is_array($plugins)) {
            return [];
        }
        foreach ($plugins as $slug => $plugin) {
            if (isset($plugin['doc_link']) && $plugin['doc_link']) {
                $plugins[$slug]['doc_link'] = add_query_arg(array('utm_source' => 'plugin-support', 'utm_medium' => 'plugin-link', 'utm_campaign' => 'documentation-link'), $plugin['doc_link']);
            }
        }
        return $plugins;
    }
    public function handle_support_request(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to submit support requests.', 'wpify-core'));
        }
        check_admin_referer('wpify_support_request');
        $plugin_slug = isset($_POST['plugin']) ? sanitize_key(wp_unslash($_POST['plugin'])) : 'general';
        $subject_input = isset($_POST['subject']) ? sanitize_text_field(wp_unslash($_POST['subject'])) : '';
        $message_input = isset($_POST['message']) ? sanitize_textarea_field(wp_unslash($_POST['message'])) : '';
        $email_input = isset($_POST['email']) ? sanitize_email(wp_unslash($_POST['email'])) : '';
        $log_files = isset($_POST['log_files']) ? (array) wp_unslash($_POST['log_files']) : [];
        $upload_files = isset($_FILES['support_files']) ? $_FILES['support_files'] : null;
        if (empty($message_input) || empty($email_input)) {
            wp_safe_redirect(add_query_arg(array('page' => self::SLUG, 'wpify_support_sent' => '0'), admin_url('admin.php')));
            exit;
        }
        $active_plugins = $this->get_active_wpify_plugins();
        $plugin_title = $active_plugins[$plugin_slug]['title'] ?? __('General', 'wpify-core');
        $license_data = $this->get_license_details($plugin_slug);
        $site_host = wp_parse_url(home_url(), \PHP_URL_HOST);
        $subject = $subject_input ? $subject_input : $plugin_title;
        $subject = sprintf('WPify Support | %s | %s', $subject, $site_host ?: home_url());
        $woo_version = '';
        if (defined('WpifyWooDeps\WC_VERSION')) {
            $woo_version = WC_VERSION;
        } else {
            if (!function_exists('is_plugin_active')) {
                require_once \ABSPATH . 'wp-admin/includes/plugin.php';
            }
            $woo_active = function_exists('is_plugin_active') && is_plugin_active('woocommerce/woocommerce.php');
            if ($woo_active) {
                $woo_version = (string) get_option('woocommerce_version', '');
                if ($woo_version === '') {
                    $woo_version = 'active';
                }
            }
        }
        if ($woo_version === '') {
            $woo_version = 'not active';
        }
        $theme = wp_get_theme();
        $theme_name = $theme ? $theme->get('Name') . ' ' . $theme->get('Version') : '';
        $diagnostics = apply_filters('wpify_dashboard_support_email_diagnostics', array('Site URL' => site_url(), 'Home URL' => home_url(), 'WP Version' => get_bloginfo('version'), 'PHP Version' => \PHP_VERSION, 'Locale' => get_locale(), 'WooCommerce' => $woo_version, 'Active Theme' => $theme_name, 'WPify Plugins (active)' => $this->format_plugin_list($active_plugins), 'License status' => $license_data['status'], 'License key' => $license_data['key']), $plugin_slug);
        $body_lines = array('Plugin: ' . $plugin_title, 'From: ' . wp_get_current_user()->display_name, 'Contact email: ' . $email_input, '', 'Message:', $message_input, '', 'Diagnostics:');
        foreach ($diagnostics as $label => $value) {
            $body_lines[] = $label . ': ' . ($value !== '' ? $value : '-');
        }
        $attachments = [];
        $temp_paths = [];
        $log_paths = $this->get_log_attachment_paths($log_files);
        if ($log_paths) {
            $attachments = array_merge($attachments, $log_paths);
            $body_lines[] = '';
            $body_lines[] = 'Log attachments: ' . implode(', ', array_map('basename', $log_paths));
        }
        $upload_result = $this->handle_support_uploads($upload_files);
        if (!empty($upload_result['paths'])) {
            $attachments = array_merge($attachments, $upload_result['paths']);
            $body_lines[] = '';
            $body_lines[] = 'File attachments: ' . implode(', ', array_map('basename', $upload_result['paths']));
        }
        $generated = apply_filters('wpify_dashboard_support_email_generated_attachments', [], $plugin_slug);
        if (is_array($generated) && $generated) {
            $generated_paths = $this->create_generated_attachments($generated);
            if (!empty($generated_paths['paths'])) {
                $attachments = array_merge($attachments, $generated_paths['paths']);
                $temp_paths = array_merge($temp_paths, $generated_paths['paths']);
                $body_lines[] = '';
                $body_lines[] = 'Generated attachments: ' . implode(', ', array_map('basename', $generated_paths['paths']));
            }
        }
        $attachments = apply_filters('wpify_dashboard_support_email_attachments', $attachments, $plugin_slug);
        $headers = array('Reply-To: ' . $email_input);
        $sent = wp_mail('support@wpify.io', $subject, implode("\n", $body_lines), $headers, $attachments);
        if (!empty($upload_result['paths'])) {
            foreach ($upload_result['paths'] as $path) {
                if (is_string($path) && $path !== '') {
                    @unlink($path);
                }
            }
        }
        if ($temp_paths) {
            foreach ($temp_paths as $path) {
                if (is_string($path) && $path !== '') {
                    @unlink($path);
                }
            }
        }
        wp_safe_redirect(add_query_arg(array('page' => self::SLUG, 'wpify_support_sent' => $sent ? '1' : '0'), admin_url('admin.php')));
        exit;
    }
    private function format_plugin_list(array $plugins): string
    {
        if (empty($plugins)) {
            return '-';
        }
        $items = [];
        foreach ($plugins as $slug => $plugin) {
            $title = $plugin['title'] ?? $slug;
            $version = $plugin['version'] ?? '';
            $items[] = $version ? sprintf('%s (%s)', $title, $version) : $title;
        }
        return implode(', ', $items);
    }
    private function get_log_files(): array
    {
        if ($this->log_files_cache !== null) {
            return $this->log_files_cache;
        }
        $logs = apply_filters('wpify_logs', []);
        $files = [];
        foreach ($logs as $log) {
            if (!is_object($log) || !method_exists($log, 'getHandlers')) {
                continue;
            }
            $channel = method_exists($log, 'get_channel') ? $log->get_channel() : '';
            foreach ($log->getHandlers() as $handler) {
                if (!method_exists($handler, 'get_glob_pattern')) {
                    continue;
                }
                $log_files = glob($handler->get_glob_pattern());
                if (!is_array($log_files)) {
                    continue;
                }
                foreach ($log_files as $file) {
                    $files[] = array('file' => $file, 'channel' => $channel, 'label' => $this->format_log_label($file, $channel));
                }
            }
        }
        usort($files, static function ($left, $right) {
            return strcmp($right['label'], $left['label']);
        });
        $this->log_files_cache = $files;
        return $this->log_files_cache;
    }
    private function format_log_label(string $file, string $channel): string
    {
        $file_name = basename($file);
        $date = '';
        if (preg_match('/-(\d{4}-\d{2}-\d{2})\.log$/', $file_name, $matches)) {
            $date = ' ' . $matches[1];
            $file_name = preg_replace('/-\d{4}-\d{2}-\d{2}\.log$/', '', $file_name);
        } else {
            $file_name = str_replace('.log', '', $file_name);
        }
        $cleared_name = str_replace('wpify_log_', '', $file_name);
        $cleared_name = preg_replace('/_[a-f0-9]{32}$/', '', $cleared_name);
        $label = $cleared_name ?: $channel;
        $label = str_replace('_', ' ', $label);
        $label = ucwords($label);
        return trim($label . ' –' . $date);
    }
    private function get_log_attachment_paths(array $selected_files): array
    {
        $selected_files = array_filter(array_map('strval', $selected_files));
        if (empty($selected_files)) {
            return [];
        }
        $available = [];
        foreach ($this->get_log_files() as $log) {
            $available[$log['file']] = \true;
        }
        $paths = [];
        foreach ($selected_files as $file) {
            if (empty($available[$file])) {
                continue;
            }
            if (is_readable($file)) {
                $paths[] = $file;
            }
        }
        return $paths;
    }
    private function create_generated_attachments(array $generated): array
    {
        if (!function_exists('wp_tempnam')) {
            require_once \ABSPATH . 'wp-admin/includes/file.php';
        }
        $paths = [];
        foreach ($generated as $item) {
            if (!is_array($item) || empty($item['content'])) {
                continue;
            }
            $name = isset($item['name']) ? sanitize_file_name((string) $item['name']) : 'attachment.txt';
            $content = (string) $item['content'];
            $tmp = wp_tempnam($name);
            if (!$tmp) {
                continue;
            }
            $written = file_put_contents($tmp, $content);
            if ($written === \false) {
                @unlink($tmp);
                continue;
            }
            $paths[] = $tmp;
        }
        return array('paths' => $paths);
    }
    private function handle_support_uploads(?array $files): array
    {
        if (empty($files) || empty($files['name']) || !is_array($files['name'])) {
            return array('paths' => [], 'errors' => []);
        }
        $max_size = (int) apply_filters('wpify_dashboard_support_upload_max_size', 10 * 1024 * 1024);
        $mimes = apply_filters('wpify_dashboard_support_upload_mimes', array('jpg|jpeg' => 'image/jpeg', 'png' => 'image/png', 'gif' => 'image/gif', 'pdf' => 'application/pdf', 'txt' => 'text/plain', 'log' => 'text/plain', 'json' => 'application/json', 'csv' => 'text/csv'));
        $paths = [];
        $errors = [];
        foreach ($files['name'] as $index => $name) {
            if (empty($name)) {
                continue;
            }
            if (!empty($files['error'][$index])) {
                $errors[] = $name;
                continue;
            }
            if (isset($files['size'][$index]) && $files['size'][$index] > $max_size) {
                $errors[] = $name;
                continue;
            }
            $tmp_name = $files['tmp_name'][$index] ?? '';
            if (empty($tmp_name) || !is_uploaded_file($tmp_name)) {
                $errors[] = $name;
                continue;
            }
            $check = wp_check_filetype_and_ext($tmp_name, $name, $mimes);
            if (empty($check['type'])) {
                $errors[] = $name;
                continue;
            }
            $paths[] = $tmp_name;
        }
        return array('paths' => $paths, 'errors' => $errors);
    }
    private function get_logs_page_url(): ?string
    {
        global $submenu;
        if (!is_array($submenu)) {
            return null;
        }
        $parents = array('wpify', 'tools.php');
        foreach ($parents as $parent) {
            if (empty($submenu[$parent]) || !is_array($submenu[$parent])) {
                continue;
            }
            foreach ($submenu[$parent] as $item) {
                if (isset($item[2]) && $item[2] === 'wpify-logs') {
                    return admin_url('admin.php?page=wpify-logs');
                }
            }
        }
        return null;
    }
    private function get_license_details(string $plugin_slug): array
    {
        if (empty($plugin_slug) || $plugin_slug === 'general') {
            return array('status' => 'n/a', 'key' => '-');
        }
        $option_key = $plugin_slug . '_license';
        if (is_multisite()) {
            $data = get_network_option(get_current_network_id(), $option_key);
        } else {
            $data = get_option($option_key);
        }
        if (!is_array($data) || empty($data['license'])) {
            return array('status' => 'inactive', 'key' => '-');
        }
        if (array_key_exists('valid', $data)) {
            $status = $data['valid'] ? 'valid' : 'invalid';
        } else {
            $status = 'active';
        }
        return array('status' => $status, 'key' => $data['license']);
    }
}
