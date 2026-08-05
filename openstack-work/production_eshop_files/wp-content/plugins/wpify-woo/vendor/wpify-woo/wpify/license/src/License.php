<?php

namespace WpifyWooDeps\Wpify\License;

use WpifyWooDeps\Wpify\Asset\AssetFactory;
use WpifyWooDeps\Wpify\License\Api\LicenseApi;
/**
 * Class License
 *
 * @package WpifyWoo
 */
class License
{
    const PATH = __DIR__;
    private string $option_key;
    /**
     * @param string $plugin
     * @param bool   $enqueue_script
     * @param int    $network_id
     */
    public function __construct(private string $plugin, private $enqueue_script = \false, private $network_id = 0, bool $api_check = \false)
    {
        $this->option_key = sprintf('%s_license', $plugin);
        add_action('admin_init', array($this, 'save_activation_token'));
        add_action('admin_init', array($this, 'delete_activation_token'));
        add_action('init', array($this, 'load_textdomain'));
        if ($this->enqueue_script) {
            add_action('admin_enqueue_scripts', array($this, 'enqueue_scripts'), 1000);
        }
        if ($api_check) {
            add_action('init', [$this, 'schedule_licence_check']);
            add_action($this->get_api_check_hook(), [$this, 'license_check']);
        }
    }
    /**
     * Register license textdomain
     * @return void
     */
    function load_textdomain()
    {
        $mo_file = dirname(__DIR__, 2) . '/languages/wpify-license-' . get_locale() . '.mo';
        if (file_exists($mo_file)) {
            load_textdomain('wpify-license', $mo_file);
        }
    }
    public function get_full_url()
    {
        $query_string = $_SERVER['QUERY_STRING'];
        parse_str($query_string, $query_params);
        $url = (empty($_SERVER['HTTPS']) ? 'http' : 'https') . "://{$_SERVER['HTTP_HOST']}{$_SERVER['REQUEST_URI']}";
        return add_query_arg($query_params, $url);
    }
    public function enqueue_scripts()
    {
        wp_dequeue_script('wpify-settings');
        $asset_factory = new AssetFactory();
        $asset_factory->wp_script(dirname(__DIR__) . '/build/settings.css', array('is_admin' => \true));
        $asset_factory->wp_script(dirname(__DIR__) . '/build/settings.js', array('handle' => 'wpify-woo-settings', 'is_admin' => \true, 'variables' => array('wpifyWooLicenseSettings' => array('publicPath' => dirname($this::PATH) . '/build/', 'activateUrl' => add_query_arg(array('license-action' => 'add', 'slug' => $this->plugin, 'domain' => get_site_url(), 'return_url' => urlencode(urlencode($this->get_full_url()))), $this->get_base_url()), 'deactivateUrl' => add_query_arg(array('license-action' => 'deactivate', 'slug' => $this->plugin, 'domain' => get_site_url(), 'uuid' => $this->get_license(), 'return_url' => urlencode(urlencode($this->get_full_url()))), $this->get_base_url()), 'activated' => $this->is_activated(), 'license' => $this->is_activated() && isset($this->is_activated()['license']) ? $this->is_activated()['license'] : '', 'license_details_url' => sprintf($this->get_base_url() . 'wp-json/wpify/v1/license/%s', $this->get_license()))), 'dependencies' => array('react', 'wp-components', 'wp-element', 'wp-hooks', 'wp-date', 'wp-i18n', 'wp-polyfill')));
        wp_set_script_translations('wpify-woo-settings', 'wpify-license', dirname(__DIR__) . '/languages');
    }
    public function get_option_key()
    {
        return $this->option_key;
    }
    public function save_option_license($args)
    {
        $data = array('license' => $args['license'], 'slug' => $this->plugin);
        if (isset($args['valid'])) {
            $data['valid'] = $args['valid'];
        }
        if ($this->network_id) {
            update_network_option($this->network_id, $this->get_option_key(), $data);
        } else {
            update_option($this->get_option_key(), $data);
        }
    }
    /**
     * Get Base URL
     *
     * @return string
     */
    public function get_base_url(): string
    {
        return 'https://wpify.io/';
    }
    public function save_activation_token()
    {
        if (empty($_GET['slug']) || empty($_GET['activation-token'] || empty($_GET['wpify-license-action']))) {
            return;
        }
        if ($_GET['slug'] !== $this->plugin) {
            return;
        }
        if ($_GET['wpify-license-action'] !== 'add') {
            return;
        }
        $data = ['license' => sanitize_text_field(wp_unslash($_GET['activation-token'])), 'valid' => \true];
        $this->save_option_license($data);
        wp_redirect(remove_query_arg(array('slug', 'activation-token', 'license-action'), $this->get_full_url()));
        exit;
    }
    public function delete_activation_token()
    {
        if (empty($_GET['slug']) || empty($_GET['activation-token'] || empty($_GET['license-action']))) {
            return;
        }
        if ($_GET['slug'] !== $this->plugin) {
            return;
        }
        if ($_GET['wpify-license-action'] !== 'deactivate') {
            return;
        }
        $this->delete_option_license();
        wp_redirect(remove_query_arg(array('slug', 'activation-token', 'license-action'), $this->get_full_url()));
        exit;
    }
    public function delete_option_license()
    {
        if ($this->network_id) {
            delete_network_option($this->network_id, $this->get_option_key());
        } else {
            delete_option($this->get_option_key());
        }
    }
    public function is_activated()
    {
        if ($this->network_id) {
            return get_network_option($this->network_id, $this->get_option_key());
        } else {
            return get_option($this->get_option_key());
        }
    }
    public function get_api_check_hook()
    {
        return sprintf('%s_license_check', $this->plugin);
    }
    public function schedule_licence_check()
    {
        if (function_exists('as_schedule_recurring_action')) {
            if (!as_has_scheduled_action($this->get_api_check_hook())) {
                as_schedule_recurring_action(time(), 12 * HOUR_IN_SECONDS, $this->get_api_check_hook());
            }
        }
    }
    public function unschedule_licence_check()
    {
        if (function_exists('as_unschedule_all_actions')) {
            as_unschedule_all_actions($this->get_api_check_hook());
        }
    }
    public function license_check()
    {
        // Do nothing if the license is not activated.
        if (!$this->is_activated()) {
            return;
        }
        $details = $this->get_api_license_details();
        if (is_wp_error($details)) {
            if ($details->get_error_code() === 'not-found') {
                $this->delete_option_license();
            }
            return;
        }
        if (!$details || !isset($details['valid'])) {
            return;
        }
        $this->save_option_license($details);
    }
    public function get_license()
    {
        return isset($this->is_activated()['license']) ? $this->is_activated()['license'] : null;
    }
    public function get_api_license_details()
    {
        $license = $this->is_activated()['license'];
        $url = $this->get_base_url() . 'wp-json/wpify/v1/license/' . $license;
        $result = wp_remote_get($url, ['timeout' => 15]);
        if (!$result || is_wp_error($result)) {
            return null;
        }
        $data = json_decode(wp_remote_retrieve_body($result), \true);
        if (is_wp_error($data) && $data->get_error_code() === 'license-not-found') {
            return $data;
        }
        if (!$data || is_wp_error($data)) {
            return null;
        }
        if (isset($data['code']) && $data['code'] === 'license-not-found') {
            return new \WP_Error('license-not-found', __('License not found', 'wpify-license'), array('status' => 404));
        }
        return $data['item'];
    }
    public function is_valid()
    {
        return $this->is_activated()['valid'] ?? \false;
    }
}
