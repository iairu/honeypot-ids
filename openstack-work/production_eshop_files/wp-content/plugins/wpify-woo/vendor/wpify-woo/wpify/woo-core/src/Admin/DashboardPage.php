<?php

namespace WpifyWooDeps\Wpify\WooCore\Admin;

/**
 * Class DashboardPage
 *
 * Handles rendering and registration of the WPify Dashboard page with plugins overview.
 *
 * @package Wpify\WooCore\Admin
 */
class DashboardPage
{
    const SLUG = 'wpify';
    const MENU_ICON = 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNTUwIiBoZWlnaHQ9IjU1MCIgdmlld0JveD0iMCAwIDU1MCA1NTAiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CjxyZWN0IG9wYWNpdHk9IjAuMyIgd2lkdGg9IjUzMiIgaGVpZ2h0PSI3OCIgcng9IjM5IiB0cmFuc2Zvcm09Im1hdHJpeCgtNC4zNzExNGUtMDggMSAxIDQuMzcxMTRlLTA4IDM2Ny43NSA5LjAwMDEyKSIgZmlsbD0id2hpdGUiLz4KPHJlY3Qgb3BhY2l0eT0iMC4zIiB3aWR0aD0iNTMwIiBoZWlnaHQ9Ijc4IiByeD0iMzkiIHRyYW5zZm9ybT0ibWF0cml4KC00LjM3MTE0ZS0wOCAxIDEgNC4zNzExNGUtMDggMjA0Ljc1IDkuMDAwMTIpIiBmaWxsPSJ3aGl0ZSIvPgo8cmVjdCBvcGFjaXR5PSIwLjgiIHdpZHRoPSI1NTcuODgyIiBoZWlnaHQ9Ijc4LjE1ODUiIHJ4PSIzOS4wNzkyIiB0cmFuc2Zvcm09Im1hdHJpeCgwLjMzODc4MSAwLjk0MDg2NSAwLjk0MDg2NSAtMC4zMzg3ODEgMzEuNzUgMjQuNDc4OCkiIGZpbGw9IndoaXRlIi8+CjxyZWN0IG9wYWNpdHk9IjAuOCIgd2lkdGg9IjU2MC42NzYiIGhlaWdodD0iNzguMTU4NSIgcng9IjM5LjA3OTIiIHRyYW5zZm9ybT0ibWF0cml4KDAuMzM4NzgxIDAuOTQwODY1IDAuOTQwODY1IC0wLjMzODc4MSAxOTMuMjQ5IDI0LjQ3ODgpIiBmaWxsPSJ3aGl0ZSIvPgo8cmVjdCBvcGFjaXR5PSIwLjgiIHdpZHRoPSIyNTkuNjQ2IiBoZWlnaHQ9Ijc4LjE1ODUiIHJ4PSIzOS4wNzkyIiB0cmFuc2Zvcm09Im1hdHJpeCgwLjMzODc4MSAwLjk0MDg2NSAwLjk0MDg2NSAtMC4zMzg3ODEgMzU2Ljc1IDI0LjQ3ODYpIiBmaWxsPSJ3aGl0ZSIvPgo8L3N2Zz4=';
    const REMOTE_TIMEOUT = 3;
    private Settings $settings;
    public function __construct(Settings $settings)
    {
        $this->settings = $settings;
        add_action('admin_menu', [$this, 'register']);
    }
    /**
     * Register dashboard menu page
     *
     * @return void
     */
    public function register(): void
    {
        add_menu_page(__('WPify Plugins', 'wpify-core'), __('WPify', 'wpify-core'), 'manage_options', self::SLUG, [$this, 'render'], self::MENU_ICON, 59);
        add_submenu_page(self::SLUG, __('WPify Plugins Dashboard', 'wpify-core'), __('Dashboard', 'wpify-core'), 'manage_options', self::SLUG, [$this, 'render']);
        do_action('wpify_woo_settings_menu_page_registered');
    }
    /**
     * Render Dashboard page html
     *
     * @return void
     */
    public function render(): void
    {
        ?>
		<div class="wpify-dashboard__wrap wrap">
			<div class="wpify-dashboard__content">
				<?php 
        echo $this->get_plugins_overview();
        ?>
			</div>
			<div class="wpify-dashboard__sidebar">
				<?php 
        do_action('wpify_dashboard_before_news_posts');
        $this->render_news_posts();
        do_action('wpify_dashboard_after_news_posts');
        ?>
			</div>
		</div>
		<?php 
    }
    /**
     * Get html of plugins overview for dashboard
     *
     * @return string
     */
    public function get_plugins_overview(): string
    {
        $installed_plugins = $this->settings->get_plugins();
        $extensions = $this->get_cached_remote_data('wpify_core_all_plugins', 'https://wpify.cz/wp-json/wpify/v1/plugins-list', 2 * HOUR_IN_SECONDS, 15 * MINUTE_IN_SECONDS, 'plugins');
        $extensions_map = array();
        if (is_array($extensions)) {
            foreach ($extensions as $extension) {
                if (empty($extension['slug'])) {
                    continue;
                }
                $extensions_map[$extension['slug']] = $extension;
            }
            foreach ($installed_plugins as $slug => $plugin) {
                if (isset($extensions_map[$slug])) {
                    $installed_plugins[$slug] = $extensions_map[$slug];
                    foreach ($plugin as $key => $value) {
                        if (!isset($installed_plugins[$slug][$key]) || !empty($value)) {
                            $installed_plugins[$slug][$key] = $value;
                        }
                    }
                    unset($extensions_map[$slug]);
                } else {
                    $check_url = add_query_arg(['update_action' => 'get_metadata', 'update_slug' => $slug, 'installed_version' => $plugin['version'], 'locale' => get_locale(), 'checking_for_updates' => '1'], 'https://wpify.cz');
                    $data = $this->get_cached_remote_data('wpify_core_plugin_update_data_' . $slug, $check_url, 6 * HOUR_IN_SECONDS, 15 * MINUTE_IN_SECONDS);
                    $update_data = ['name' => $data['name'] ?? '', 'version' => $data['version'] ?? '', 'requires_php' => $data['requires_php'] ?? '', 'requires_wp' => $data['requires'] ?? '', 'changelog' => $data['sections']['changelog'] ?? ''];
                    if ($update_data) {
                        $installed_plugins[$slug]['plugin_info'] = $update_data;
                    }
                }
            }
        }
        do_action('wpify_dashboard_before_installed_plugins');
        $html = sprintf('<h2>%s</h2>', __('Installed plugins', 'wpify-core'));
        $html .= $this->get_plugins_blocks($installed_plugins, \true);
        do_action('wpify_dashboard_after_installed_plugins');
        if ($extensions_map) {
            $html .= sprintf('<h2>%s</h2>', __('Our other plugins', 'wpify-core'));
            $html .= $this->get_plugins_blocks($extensions_map);
        }
        do_action('wpify_dashboard_after_other_plugins');
        return $html;
    }
    /**
     * Get plugins blocks html for overview
     *
     * @param array $plugins   plugins data
     * @param bool  $installed is installed
     *
     * @return bool|string
     */
    public function get_plugins_blocks(array $plugins, bool $installed = \false): bool|string
    {
        if ($installed) {
            wp_add_inline_script('thickbox', '
        document.addEventListener("DOMContentLoaded", function() {
            document.querySelectorAll(".open-plugin-details-modal").forEach(function(link) {
                link.addEventListener("click", function() {
                    const width = Math.min(window.innerWidth - 100, 800);
                    const height = Math.min(window.innerHeight - 100, 600);

                    let href = this.href.replace(/&width=\d+/, "").replace(/&height=\d+/, "");
                    this.href = href + "&width=" + width + "&height=" + height;
                });
            });
        });
    ');
        }
        ob_start();
        ?>
		<div class="wpify__cards">

			<?php 
        foreach ($plugins as $slug => $plugin) {
            if (isset($plugin['link']) && $plugin['link']) {
                $plugin['link'] = add_query_arg(array('utm_source' => 'plugin-dashboard', 'utm_medium' => 'plugin-link', 'utm_campaign' => 'upsell-link'), $plugin['link']);
            }
            if (isset($plugin['doc_link']) && $plugin['doc_link']) {
                $plugin['doc_link'] = add_query_arg(array('utm_source' => 'plugin-dashboard', 'utm_medium' => 'plugin-link', 'utm_campaign' => 'documentation-link'), $plugin['doc_link']);
            }
            $is_active = $installed && (!empty($plugin['plugin_file']) ? is_plugin_active($plugin['plugin_file']) : !empty($plugin['settings_url']));
            $license = $plugin['license'] ?? \true;
            ?>
				<div class="wpify__card <?php 
            echo $installed ? $is_active ? 'active' : 'inactive' : 'buy';
            echo $installed && !$license ? ' no-licence' : '';
            ?>">
					<div class="wpify__card-head">
						<?php 
            if (isset($plugin['icon']) && $plugin['icon']) {
                ?>
							<img src="<?php 
                echo $plugin['icon'];
                ?>" alt="<?php 
                echo $plugin['title'];
                ?>" width="50" height="50">
							<?php 
            }
            ?>
						<div>
							<h3>
								<?php 
            echo $plugin['title'];
            ?>
							</h3>
							<?php 
            $metas = [];
            $notices = [];
            if ($installed && isset($plugin['license']) && !$plugin['license']) {
                $notices[] = array('type' => 'error', 'content' => sprintf('<a href="%s">❗ %s</a>', $plugin['settings_url'] ?? '#', __('Please, activate the license.', 'wpify-core')));
            }
            if ($installed && isset($plugin['version'])) {
                $version = $plugin['version'];
                if (isset($plugin['plugin_info'])) {
                    $available_v = $plugin['plugin_info']['version'] ?? 0;
                    if ($available_v && version_compare($available_v, $version, '>')) {
                        /* translators: %s: Available version number. */
                        $update_notice = '⚠️ ' . sprintf(__('New version %s available.', 'wpify-core'), $available_v);
                        if ($is_active && !empty($plugin['license'])) {
                            $can_update = current_user_can('update_plugins');
                            if (is_multisite()) {
                                $can_update = $can_update && current_user_can('manage_network_plugins');
                            }
                            if ($can_update) {
                                $path = 'plugin-install.php?tab=plugin-information&plugin=' . urlencode($slug) . '&section=changelog&TB_iframe=true&width=772&height=800';
                                $details_url = is_multisite() ? network_admin_url($path) : admin_url($path);
                                $update_notice = sprintf('<a href="%s" class="thickbox open-plugin-details-modal" title="Plugin Details">%s</a>', esc_url($details_url), $update_notice);
                            }
                        }
                        $notices[] = array('type' => 'warning', 'content' => $update_notice);
                    }
                }
                $metas[] = $version;
            } elseif (isset($plugin['plugin_info']) && isset($plugin['plugin_info']['version'])) {
                $metas[] = $plugin['plugin_info']['version'];
            }
            if (isset($plugin['rating']) && $plugin['rating']) {
                $metas[] = sprintf('⭐ %s/5', $plugin['rating']);
            }
            if (!$installed && isset($plugin['doc_link']) && $plugin['doc_link']) {
                $metas[] = sprintf('<a href="%s" target="_blank">%s</a>', esc_url($plugin['doc_link']), __('Documentation', 'wpify-core'));
            }
            echo join(' | ', $metas);
            ?>
						</div>
					</div>
					<div class="wpify__card-body">
						<?php 
            if ($notices) {
                foreach ($notices as $notice) {
                    echo sprintf('<div class="wpify-notice-%s wpify-notice">%s</div>', $notice['type'], $notice['content']);
                }
            }
            if (!$installed) {
                echo $plugin['desc'] ?? '';
            }
            ?>
					</div>
					<div class="wpify__card-footer">
						<?php 
            if (!$installed && isset($plugin['price'])) {
                echo '<strong>' . $plugin['price'] . '</strong>';
            }
            if ($installed && isset($plugin['doc_link']) && $plugin['doc_link']) {
                ?>
							<a href="<?php 
                echo esc_url($plugin['doc_link']);
                ?>"
							   target="_blank"><?php 
                _e('Documentation', 'wpify-core');
                ?></a>
							<?php 
            }
            ?>
						<div style="flex: 1"></div>
						<?php 
            if ($installed && $is_active) {
                if (!empty($plugin['plugin_file'])) {
                    $redirect_url = admin_url('admin.php?page=wpify');
                    $deactivate_url = wp_nonce_url(admin_url('plugins.php?action=deactivate&plugin=' . urlencode($plugin['plugin_file']) . '&wpify_redirect=' . urlencode($redirect_url)), 'deactivate-plugin_' . $plugin['plugin_file']);
                    ?>
								<a class="toggle-button active" href="<?php 
                    echo esc_url($deactivate_url);
                    ?>"
								   role="button"><span class="toggle-button__label"><?php 
                    _e('Deactivate', 'wpify-core');
                    ?>
                                    </span>
									<span class="toggle-button__thumb"></span>
								</a>
								<?php 
                }
                if (!empty($plugin['settings_url'])) {
                    ?>
								<a class="button button-primary" href="<?php 
                    echo esc_url($plugin['settings_url']);
                    ?>"
								   role="button"><?php 
                    _e('Settings', 'wpify-core');
                    ?></a>
								<?php 
                }
            } elseif ($installed && $plugin['plugin_file']) {
                $redirect_url = admin_url('admin.php?page=wpify');
                $activate_url = wp_nonce_url(admin_url('plugins.php?action=activate&plugin=' . urlencode($plugin['plugin_file']) . '&wpify_redirect=' . urlencode($redirect_url)), 'activate-plugin_' . $plugin['plugin_file']);
                ?>
							<a class="toggle-button inactive" href="<?php 
                echo esc_url($activate_url);
                ?>"
							   role="button"><span class="toggle-button__label"><?php 
                _e('Activate', 'wpify-core');
                ?>
                                    </span>
								<span class="toggle-button__thumb"></span>
							</a>
							<?php 
            } elseif (isset($plugin['link']) && $plugin['link']) {
                ?>
							<span><a class="install-now button button-primary" href="<?php 
                echo esc_url($plugin['link']);
                ?>"
							         role="button" target="_blank"><?php 
                _e('Get plugin', 'wpify-core');
                ?></a></span>
							<?php 
            }
            ?>
					</div>
				</div>
				<?php 
        }
        ?>
		</div>
		<?php 
        return ob_get_clean();
    }
    /**
     * Render WPify news posts
     *
     * @return void
     */
    public function render_news_posts(): void
    {
        $posts = $this->get_cached_remote_data('wpify_core_news', 'https://wpify.cz/wp-json/wp/v2/posts?per_page=4&_embed', DAY_IN_SECONDS, 15 * MINUTE_IN_SECONDS, null, \false);
        if (empty($posts)) {
            return;
        }
        ?>
		<h2><?php 
        _e('WPify News', 'wpify-core');
        ?></h2>
		<div class="wpify__cards">

			<?php 
        foreach ($posts as $post) {
            $link = add_query_arg(array('utm_source' => 'plugin-dashboard', 'utm_medium' => 'plugin-link', 'utm_campaign' => 'news-link'), $post->link);
            ?>
				<div class="wpify__card" style="max-width:100%">
					<?php 
            $embedded = (array) $post->_embedded;
            $thumbnail = $embedded['wp:featuredmedia'][0]->source_url ?? '';
            if ($thumbnail) {
                ?>
						<a href="<?php 
                echo esc_url($link);
                ?>" target="_blank">
							<img src="<?php 
                echo esc_url($thumbnail);
                ?>" loading="lazy"
							     alt="<?php 
                echo esc_attr($post->title->rendered);
                ?>"
							     style="width: 100%; height: auto">
						</a>
					<?php 
            }
            ?>
					<div class="wpify__card-body">
						<h3><a href="<?php 
            echo esc_url($link);
            ?>" target="_blank">
								<?php 
            echo esc_html($post->title->rendered);
            ?>
							</a></h3>
						<?php 
            echo $post->excerpt->rendered;
            ?>
					</div>
				</div>
				<?php 
        }
        ?>
		</div>
		<?php 
    }
    private function get_cached_remote_data(string $cache_key, string $url, int $ttl, int $failure_ttl, ?string $root_key = null, bool $assoc = \true)
    {
        $data = get_transient($cache_key);
        if ($data !== \false) {
            return $data;
        }
        $fallback_key = 'wpify_core_fallback_' . md5($cache_key);
        $failure_key = $cache_key . '_failed';
        if (get_transient($failure_key)) {
            return get_option($fallback_key, []);
        }
        $response = wp_remote_get($url, ['timeout' => self::REMOTE_TIMEOUT]);
        if (is_wp_error($response)) {
            set_transient($failure_key, 1, $failure_ttl);
            return get_option($fallback_key, []);
        }
        $body = wp_remote_retrieve_body($response);
        if ($body === '') {
            set_transient($failure_key, 1, $failure_ttl);
            return get_option($fallback_key, []);
        }
        $decoded = json_decode($body, $assoc);
        if ($decoded === null) {
            $decoded = json_decode($body);
        }
        if ($root_key !== null && is_array($decoded)) {
            $decoded = $decoded[$root_key] ?? [];
        }
        if (empty($decoded)) {
            set_transient($failure_key, 1, $failure_ttl);
            return get_option($fallback_key, []);
        }
        set_transient($cache_key, $decoded, $ttl);
        update_option($fallback_key, $decoded, \false);
        delete_transient($failure_key);
        return $decoded;
    }
}
