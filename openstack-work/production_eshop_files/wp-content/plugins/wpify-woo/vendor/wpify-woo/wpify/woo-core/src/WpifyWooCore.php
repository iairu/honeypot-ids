<?php

namespace WpifyWooDeps\Wpify\WooCore;

use WpifyWooDeps\Wpify\WooCore\Admin\Settings;
use WpifyWooDeps\Wpify\WooCore\Managers\ModulesManager;
class WpifyWooCore
{
    const PATH = __DIR__;
    /**
     * @var Settings
     */
    private $settings;
    /**
     * @var ModulesManager
     */
    private $modules_manager;
    public function __construct(Settings $settings, ModulesManager $modules_manager)
    {
        $this->settings = $settings;
        $this->modules_manager = $modules_manager;
    }
    /**
     * @return ModulesManager
     */
    public function get_modules_manager(): ModulesManager
    {
        return $this->modules_manager;
    }
    /**
     * @return Settings
     */
    public function get_settings(): Settings
    {
        return $this->settings;
    }
}
