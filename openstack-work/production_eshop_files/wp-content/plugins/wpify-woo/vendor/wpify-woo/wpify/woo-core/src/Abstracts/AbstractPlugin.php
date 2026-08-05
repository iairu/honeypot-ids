<?php

namespace WpifyWooDeps\Wpify\WooCore\Abstracts;

use WpifyWooDeps\Wpify\License\License;
use WpifyWooDeps\Wpify\PluginUtils\PluginUtils;
use WpifyWooDeps\Wpify\WooCore\WpifyWooCore;
/**
 * Class AbstractModule
 * @package WpifyWoo\Abstracts
 */
abstract class AbstractPlugin
{
    protected bool $requires_activation = \true;
    private WpifyWooCore $wpify_woo_core;
    private PluginUtils $plugin_utils;
    private License $license;
    private ?array $plugin_data_cache = null;
    private ?string $icon_file_cache = null;
    public function __construct(WpifyWooCore $wpify_woo_core, PluginUtils $plugin_utils)
    {
        $this->wpify_woo_core = $wpify_woo_core;
        $this->plugin_utils = $plugin_utils;
        add_filter('wpify_installed_plugins', array($this, 'add_plugin'));
        add_filter('plugin_action_links_' . $this->id() . '/' . $this->id() . '.php', array($this, 'add_action_links'));
        add_filter('plugin_row_meta', array($this, 'add_row_meta_links'), 10, 2);
        // Registrace filteru pro moduly - fallback na plugin dokumentaci
        add_filter('wpify_woo_plugin_documentation_url_' . $this->id(), array($this, 'documentation_url'));
        if ($this->requires_activation) {
            $this->license = new License($this->id(), \false, is_multisite() ? get_current_network_id() : 0);
            if (!$this->license->is_activated()) {
                //				add_action( 'admin_notices', array( $this, 'activation_notice' ) );
                add_action('after_plugin_row_' . $this->plugin_utils->get_plugin_basename(), array($this, 'activation_update_notice'), 10, 3);
            }
        }
    }
    /**
     * Plugin data
     *
     * @return array
     */
    public function plugin_data(): array
    {
        if ($this->plugin_data_cache === null) {
            $this->plugin_data_cache = get_plugin_data($this->plugin_utils->get_plugin_file());
        }
        return $this->plugin_data_cache;
    }
    /**
     * Plugin id
     *
     * @return string
     */
    public function id(): string
    {
        return $this->plugin_utils->get_plugin_slug();
    }
    /**
     * Plugin name
     *
     * @return string|null
     */
    public function name(): ?string
    {
        return $this->plugin_data()['Name'] ?? $this->plugin_utils->get_plugin_name();
    }
    /**
     * Plugin base option id
     *
     * @return string|null
     */
    public function base_option_id(): ?string
    {
        return $this->id();
    }
    /**
     * Menu slug for settings page url
     * @return string
     */
    public function get_menu_slug(): string
    {
        return sprintf('wpify/%s', $this->base_option_id());
    }
    /**
     * Plugin settings url
     *
     * @return string
     */
    public function settings_url(): string
    {
        return add_query_arg(['page' => $this->get_menu_slug()], admin_url('admin.php'));
    }
    /**
     * Plugin documentation path
     *
     * @return string
     */
    public function get_documentation_path(): string
    {
        return '';
    }
    /**
     * Plugin documentation url
     *
     * @return string
     */
    public function documentation_url(): string
    {
        $domain = 'https://docs.wpify.cz/';
        if (in_array(get_locale(), array('cs_CZ', 'sk_SK'), \true)) {
            $domain = 'https://docs.wpify.cz/cs/';
        }
        $path = $this->get_documentation_path();
        return esc_url($domain . $path);
    }
    /**
     * Plugin support url
     *
     * @return string
     */
    public function support_url(): string
    {
        return '';
    }
    /**
     * Plugin icon url
     *
     * @return string
     */
    public function icon_file(): string
    {
        if ($this->icon_file_cache !== null) {
            return $this->icon_file_cache;
        }
        if (file_exists($this->plugin_utils->get_plugin_path('icon.svg'))) {
            $this->icon_file_cache = $this->plugin_utils->get_plugin_url('icon.svg');
            return $this->icon_file_cache;
        }
        $this->icon_file_cache = '';
        return $this->icon_file_cache;
    }
    /**
     * Plugin general Settings tabs
     * @return array Settings tabs.
     */
    public function settings_tabs(): array
    {
        return array();
    }
    /**
     * Plugin general Settings
     * @return array Settings.
     */
    public function settings(): array
    {
        return array();
    }
    /**
     * Register plugin into WPify dashboard
     *
     * @param $plugins
     *
     * @return mixed
     */
    public function add_plugin($plugins)
    {
        $plugins[$this->id()] = array('title' => $this->name(), 'desc' => $this->plugin_data()['Description'], 'icon' => $this->icon_file(), 'version' => $this->plugin_utils->get_plugin_version(), 'doc_link' => $this->documentation_url(), 'support_url' => $this->support_url(), 'menu_slug' => $this->get_menu_slug(), 'option_id' => $this->base_option_id(), 'settings_url' => $this->settings_url(), 'tabs' => $this->settings_tabs(), 'settings' => $this->settings(), 'license' => $this->requires_activation ? $this->license->is_activated() : \true);
        return $plugins;
    }
    /**
     * Add action links to WP plugin list
     *
     * @param $links
     *
     * @return array
     */
    public function add_action_links($links): array
    {
        $web_link = add_query_arg(array('utm_source' => $this->id() ?: 'plugin-dashboard', 'utm_medium' => 'plugin-link', 'utm_campaign' => 'company-link'), 'https://wpify.io/');
        $before = array('settings' => sprintf('<a href="%s">%s</a>', $this->settings_url(), __('Settings', 'wpify-core')));
        $after = array('wpify' => sprintf('<a href="%s" target="_blank">%s</a>', $web_link, __('Get more plugins and support', 'wpify-core')));
        return array_merge($before, $links, $after);
    }
    /**
     * Add action links on WP plugin list into meta
     *
     * @param $plugin_meta
     * @param $plugin_file
     *
     * @return array
     */
    public function add_row_meta_links($plugin_meta, $plugin_file): array
    {
        $new_links = array();
        if ($this->documentation_url() && strpos($this->plugin_utils->get_plugin_file(), $plugin_file)) {
            $doc_link = add_query_arg(array('utm_source' => $this->id() ?: 'plugin-dashboard', 'utm_medium' => 'plugin-link', 'utm_campaign' => 'documentation-link'), $this->documentation_url());
            $new_links = array('wpify-doc' => sprintf('<a href="%s" target="_blank">%s</a>', $doc_link, __('Documentation', 'wpify-core')));
        }
        return array_merge($plugin_meta, $new_links);
    }
    public function requires_activation()
    {
        return $this->requires_activation;
    }
    public function get_license()
    {
        return $this->license;
    }
    /**
     * Add activation notice if the license s not active yet.
     */
    public function activation_notice($notice = \false)
    {
        $class = !$notice ? 'error notice' : 'update-message notice inline notice-error notice-alt';
        ?>
        <div class="<?php 
        echo $class;
        ?>">
            <p><?php 
        /* translators: 1: Plugin name, 2: Settings URL. */
        printf(__('Your %1$s plugin licence is not activated yet. Please <a href="%2$s">activate the domain</a> by connecting it with your WPify account!', 'wpify-core'), $this->name(), $this->settings_url());
        ?></p>
        </div>
		<?php 
    }
    /**
     * Add activation notice if the license s not active yet.
     */
    public function activation_update_notice($plugin_file, $plugin_data, $status)
    {
        ?>
        <tr class="plugin-update-tr active">
            <td colspan="4" class="plugin-update colspanchange">
				<?php 
        $this->activation_notice(\true);
        ?>
            </td>
        </tr>
		<?php 
    }
}
