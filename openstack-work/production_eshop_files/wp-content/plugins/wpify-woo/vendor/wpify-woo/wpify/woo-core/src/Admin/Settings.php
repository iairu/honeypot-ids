<?php

namespace WpifyWooDeps\Wpify\WooCore\Admin;

use WpifyWooDeps\Wpify\Asset\AssetFactory;
use WpifyWooDeps\Wpify\CustomFields\CustomFields;
use WpifyWooDeps\Wpify\WooCore\Managers\ModulesManager;
/**
 * Class Settings
 *
 * Core settings class handling plugin/module settings registration.
 *
 * @package WpifyWooCore\Admin
 */
if (class_exists(__NAMESPACE__ . '\Settings', \false)) {
    return;
}
class Settings
{
    const OPTION_NAME = 'wpify-woo-settings';
    private array $pages = [];
    private ?array $plugins_cache = null;
    private array $sections_cache = [];
    private CustomFields $custom_fields;
    private ModulesManager $modules_manager;
    private AssetFactory $asset_factory;
    private ?DashboardPage $dashboard_page = null;
    private ?SupportPage $support_page = null;
    private ?MenuBar $menu_bar = null;
    public function __construct(CustomFields $custom_fields, ModulesManager $modules_manager, AssetFactory $asset_factory)
    {
        $this->custom_fields = $custom_fields;
        $this->modules_manager = $modules_manager;
        $this->asset_factory = $asset_factory;
        $allow_initialization = apply_filters('wpify_core_allow_initialization', \true, static::class);
        if (!$allow_initialization) {
            return;
        }
        // Block old core (filter-based) from initializing.
        // Use own callback (not __return_true) so we can detect old core in initialize_core().
        add_filter('wpify_core_settings_initialized', [$this, 'is_initialized']);
        // Version-aware initialization: highest woo-core version wins
        $my_version = $this->get_core_version();
        global $wpify_woo_core_active_version, $wpify_woo_core_active_instance;
        if (!isset($wpify_woo_core_active_version) || version_compare($my_version, $wpify_woo_core_active_version, '>')) {
            $wpify_woo_core_active_version = $my_version;
            $wpify_woo_core_active_instance = $this;
        }
        // Register deferred init once — runs after all plugins have loaded (priority 99)
        // so we know which version is the highest
        global $wpify_woo_core_init_registered;
        if (!$wpify_woo_core_init_registered) {
            $wpify_woo_core_init_registered = \true;
            add_action('plugins_loaded', function () {
                global $wpify_woo_core_active_instance;
                $wpify_woo_core_active_instance->initialize_core();
            }, 99);
        }
    }
    /**
     * Initialize core hooks and page components.
     * Called once from deferred plugins_loaded (priority 99) on the highest-version instance.
     *
     * @return void
     */
    public function initialize_core(): void
    {
        // If old core already initialized (it uses __return_true on this filter), skip
        if (has_filter('wpify_core_settings_initialized', '__return_true')) {
            return;
        }
        add_action('init', [$this, 'load_textdomain']);
        add_action('init', [$this, 'register_settings']);
        add_action('admin_init', [$this, 'hide_admin_notices']);
        add_filter('admin_body_class', [static::class, 'add_admin_body_class'], 9999);
        add_action('activated_plugin', [$this, 'maybe_set_redirect']);
        add_action('deactivated_plugin', [$this, 'maybe_set_redirect']);
        add_action('admin_init', [$this, 'maybe_redirect']);
        // Initialize page components (they register themselves)
        $this->get_dashboard_page();
        $this->get_support_page();
        $this->get_menu_bar();
    }
    /**
     * Get dashboard page instance (lazy loaded)
     *
     * @return DashboardPage
     */
    public function get_dashboard_page(): DashboardPage
    {
        if ($this->dashboard_page === null) {
            $this->dashboard_page = new DashboardPage($this);
        }
        return $this->dashboard_page;
    }
    /**
     * Get support page instance (lazy loaded)
     *
     * @return SupportPage
     */
    public function get_support_page(): SupportPage
    {
        if ($this->support_page === null) {
            $this->support_page = new SupportPage($this->get_dashboard_page());
        }
        return $this->support_page;
    }
    /**
     * Get menu bar instance (lazy loaded)
     *
     * @return MenuBar
     */
    public function get_menu_bar(): MenuBar
    {
        if ($this->menu_bar === null) {
            $this->menu_bar = new MenuBar($this);
        }
        return $this->menu_bar;
    }
    /**
     * Filter callback to signal that new core is present.
     * Used instead of __return_true so we can detect old core separately.
     *
     * @return bool
     */
    public function is_initialized(): bool
    {
        return \true;
    }
    /**
     * Maybe set redirect transient after plugin activation/deactivation
     *
     * @return void
     */
    public function maybe_set_redirect(): void
    {
        if (!empty($_GET['wpify_redirect'])) {
            set_transient('wpify_redirect', esc_url_raw(wp_unslash($_GET['wpify_redirect'])), 3);
        }
    }
    /**
     * Maybe redirect after plugin activation/deactivation
     *
     * @return void
     */
    public function maybe_redirect(): void
    {
        $redirect = get_transient('wpify_redirect');
        if ($redirect) {
            delete_transient('wpify_redirect');
            wp_safe_redirect($redirect);
            exit;
        }
    }
    /**
     * Register core textdomain
     *
     * @return void
     */
    public function load_textdomain(): void
    {
        $mo_file = dirname(__DIR__, 2) . '/languages/wpify-core-' . get_locale() . '.mo';
        if (file_exists($mo_file)) {
            load_textdomain('wpify-core', $mo_file);
        }
    }
    /**
     * Hide all admin notices on dashboard or hide non wpify notices on wpify settings pages
     *
     * @return void
     */
    public function hide_admin_notices(): void
    {
        global $wp_filter;
        if (!isset($wp_filter['admin_notices'])) {
            return;
        }
        $current_page = isset($_GET['page']) ? sanitize_text_field(wp_unslash($_GET['page'])) : '';
        if ($current_page === DashboardPage::SLUG) {
            unset($wp_filter['admin_notices']);
            return;
        }
        if (!str_contains($current_page, 'wpify/')) {
            return;
        }
        foreach ($wp_filter['admin_notices']->callbacks as $priority => $callbacks) {
            foreach ($callbacks as $key => $callback) {
                $function = $callback['function'];
                if (is_array($function) && isset($function[0])) {
                    $class_name = is_object($function[0]) ? get_class($function[0]) : $function[0];
                    if (!str_contains($class_name, 'Wpify')) {
                        unset($wp_filter['admin_notices']->callbacks[$priority][$key]);
                    }
                }
            }
        }
    }
    /**
     * Check if current request is a wpifycf REST API request
     *
     * @return bool
     */
    private function is_wpifycf_rest_request(): bool
    {
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Only used for string matching
        $request_uri = $_SERVER['REQUEST_URI'] ?? '';
        return str_contains($request_uri, '/wpifycf/');
    }
    /**
     * Register admin pages and settings for plugins and modules
     *
     * @return void
     */
    public function register_settings(): void
    {
        if (!$this->should_register_settings()) {
            return;
        }
        $plugins = $this->get_plugins();
        if (empty($plugins)) {
            return;
        }
        $this->pages = [];
        foreach ($plugins as $plugin_id => $plugin) {
            if (empty($plugin['menu_slug'])) {
                continue;
            }
            $this->pages[$plugin_id] = ['page_title' => $plugin['title'], 'menu_title' => $plugin['title'], 'menu_slug' => $plugin['menu_slug'], 'id' => $plugin_id, 'parent_slug' => DashboardPage::SLUG, 'class' => 'wpify-woo-settings', 'option_name' => $this->get_settings_name($plugin['option_id']), 'tabs' => $this->is_current('', $plugin_id) ? $plugin['tabs'] : [], 'items' => $this->is_current('', $plugin_id) ? $plugin['settings'] : []];
            $sections = $this->get_sections($plugin_id);
            foreach ($sections as $section_id => $section) {
                if (empty($section_id)) {
                    continue;
                }
                if (isset($this->pages[$section_id]) || $plugin['option_id'] === $section['option_id']) {
                    $this->pages[$plugin_id]['page_title'] = $section['title'];
                    $this->pages[$plugin_id]['id'] = $section_id;
                    $this->pages[$plugin_id]['option_name'] = $section['option_name'] ?? $this->get_settings_name($section['option_id']);
                    $this->pages[$plugin_id]['tabs'] = $this->is_current('', $section_id) ? $section['tabs'] : [];
                    $this->pages[$plugin_id]['items'] = $this->is_current('', $section_id) ? $section['settings'] : [];
                    continue;
                }
                $this->pages[$section_id] = ['page_title' => $section['title'], 'menu_title' => $section['title'], 'menu_slug' => $section['menu_slug'], 'id' => $section_id, 'parent_slug' => $section['parent'], 'class' => 'wpify-woo-settings', 'option_name' => $section['option_name'] ?? $this->get_settings_name($section['option_id']), 'tabs' => $this->is_current('', $section_id) ? $section['tabs'] : [], 'items' => $this->is_current('', $section_id) ? $section['settings'] : []];
            }
        }
        foreach ($this->pages as $page) {
            $page['position'] = 1;
            $this->custom_fields->create_options_page($page);
        }
    }
    /**
     * Get plugins
     *
     * @return array
     */
    public function get_plugins(): array
    {
        if ($this->plugins_cache !== null) {
            return $this->plugins_cache;
        }
        $all_plugins = get_plugins();
        $active = apply_filters('wpify_installed_plugins', []);
        $wpify_plugins = [];
        foreach ($all_plugins as $plugin_file => $plugin_data) {
            $slug = $this->get_plugin_slug($plugin_file);
            if (isset($active[$slug])) {
                $wpify_plugins[$slug] = $active[$slug];
                $wpify_plugins[$slug]['plugin_file'] = $plugin_file;
                continue;
            }
            if (isset($plugin_data['Author']) && str_contains(strtolower($plugin_data['Author']), 'wpify')) {
                $wpify_plugins[$slug] = ['title' => $plugin_data['Name'], 'desc' => $plugin_data['Description'], 'icon' => '', 'version' => $plugin_data['Version'], 'doc_link' => '', 'support_url' => '', 'menu_slug' => '', 'option_id' => '', 'settings_url' => '', 'plugin_file' => $plugin_file, 'tabs' => [], 'settings' => []];
            }
        }
        $this->plugins_cache = $wpify_plugins;
        return $this->plugins_cache;
    }
    /**
     * Get plugin slug from file path
     *
     * @param string $plugin_file Plugin file path
     *
     * @return string
     */
    public function get_plugin_slug(string $plugin_file): string
    {
        return basename($plugin_file, '.php');
    }
    /**
     * Get sections
     *
     * @param string|null $subpage subpage slug
     *
     * @return array
     */
    public function get_sections(?string $subpage = null): array
    {
        if (!$subpage) {
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- This is a read-only page detection
            $current_page = isset($_REQUEST['page']) ? sanitize_text_field(wp_unslash($_REQUEST['page'])) : '';
            if (!str_contains($current_page, 'wpify/')) {
                return [];
            }
            $subpage = explode('/', $current_page)[1] ?? '';
        }
        $subpage = sanitize_key($subpage);
        if (isset($this->sections_cache[$subpage])) {
            return $this->sections_cache[$subpage];
        }
        $this->sections_cache[$subpage] = apply_filters('wpify_get_sections_' . $subpage, []);
        return $this->sections_cache[$subpage];
    }
    /**
     * Get an array of enabled modules
     *
     * @return array
     */
    public function get_enabled_modules(): array
    {
        return $this->get_settings('general')['enabled_modules'] ?? [];
    }
    /**
     * Set module as active
     *
     * @param string $module Module slug
     *
     * @return void
     */
    public function enable_module(string $module): void
    {
        $general_settings = $this->get_settings('general');
        $enabled_modules = $general_settings['enabled_modules'] ?? [];
        if (!in_array($module, $enabled_modules, \true)) {
            $enabled_modules[] = $module;
            $general_settings['enabled_modules'] = $enabled_modules;
            update_option($this->get_settings_name('general'), $general_settings);
        }
    }
    /**
     * Get settings for a specific module
     *
     * @param string $module Module slug.
     *
     * @return array
     */
    public function get_settings(string $module): array
    {
        return get_option($this->get_settings_name($module), []);
    }
    /**
     * Get settings name
     *
     * @param string $module Module slug
     *
     * @return string
     */
    public function get_settings_name(string $module): string
    {
        $key = sprintf('%s-%s', self::OPTION_NAME, $module);
        if ('general' !== $module && defined('ICL_LANGUAGE_CODE')) {
            $default_lang = apply_filters('wpml_default_language', null);
            if ($default_lang !== ICL_LANGUAGE_CODE) {
                $key = sprintf('%s_%s', $key, ICL_LANGUAGE_CODE);
            }
        }
        return $key;
    }
    /**
     * Check if is a current settings page
     *
     * @param string $tab     tab id
     * @param string $section section id
     *
     * @return bool
     */
    public function is_current(string $tab = '', string $section = ''): bool
    {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- This is a read-only page detection
        $current_tab = isset($_REQUEST['tab']) ? sanitize_text_field(wp_unslash($_REQUEST['tab'])) : '';
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- This is a read-only page detection
        $current_section = isset($_REQUEST['section']) ? sanitize_text_field(wp_unslash($_REQUEST['section'])) : '';
        if ($tab === $current_tab && $section === $current_section) {
            return \true;
        }
        $current_module = $this->get_current_module();
        if ($current_module === $section) {
            return \true;
        }
        foreach ($this->modules_manager->get_modules() as $module) {
            $option_name = $this->get_settings_name($module->get_id());
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- This is a simple presence check
            if (isset($_REQUEST[$option_name])) {
                return \true;
            }
        }
        $module_id = isset($_GET['module_id']) ? sanitize_text_field(wp_unslash($_GET['module_id'])) : '';
        if (wp_is_json_request() && $module_id === $section) {
            return \true;
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- This is a read-only page detection
        $option_page = isset($_POST['option_page']) ? sanitize_text_field(wp_unslash($_POST['option_page'])) : '';
        if ($option_page === $this->get_settings_name($section)) {
            return \true;
        }
        if ($option_page && str_contains($option_page, $section)) {
            return \true;
        }
        return \false;
    }
    /**
     * Get current module slug
     *
     * @return false|string
     */
    public function get_current_module(): false|string
    {
        foreach ($this->modules_manager->get_modules() as $module) {
            $module_id = $module->get_id();
            $option_name = $this->get_settings_name($module_id);
            // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- This is a simple presence check
            if (isset($_REQUEST[$option_name])) {
                return $module_id;
            }
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- This is a read-only page detection
        $current_page = isset($_REQUEST['page']) ? sanitize_text_field(wp_unslash($_REQUEST['page'])) : '';
        if (!str_contains($current_page, 'wpify/')) {
            return \false;
        }
        $page_attributes = explode('/', $current_page);
        return end($page_attributes);
    }
    /**
     * Get woo-core version from composer installed.php
     *
     * @return string
     */
    private function get_core_version(): string
    {
        // From src/Admin/ go up to the composer dir: woo-core -> wpify -> deps|vendor -> composer
        $installed_php = dirname(__DIR__, 4) . '/composer/installed.php';
        if (file_exists($installed_php)) {
            $data = @include $installed_php;
            if (is_array($data) && isset($data['versions']['wpify/woo-core']['pretty_version'])) {
                return $data['versions']['wpify/woo-core']['pretty_version'];
            }
        }
        return '0';
    }
    private function should_register_settings(): bool
    {
        if ($this->is_wpifycf_rest_request()) {
            return \true;
        }
        /*
         * Settings pages must be registered on every admin request.
         * Restricting this to WPify pages breaks menu/submenu registration and makes
         * settings pages disappear until a WPify page initializes the tree first.
         */
        return is_admin();
    }
    /**
     * Add custom class to admin body on wpify pages
     *
     * @param string $admin_body_class Existing body classes
     *
     * @return string
     */
    public static function add_admin_body_class(string $admin_body_class = ''): string
    {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- This is a read-only page detection
        $current_page = isset($_REQUEST['page']) ? sanitize_text_field(wp_unslash($_REQUEST['page'])) : '';
        if (!str_contains($current_page, 'wpify')) {
            return $admin_body_class;
        }
        $classes = explode(' ', trim($admin_body_class));
        $classes[] = 'wpify-admin-page';
        $admin_body_class = implode(' ', array_unique($classes));
        return " {$admin_body_class} ";
    }
}
