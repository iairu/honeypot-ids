<?php

namespace WpifyWooDeps\Wpify\WooCore\Managers;

class ModulesManager
{
    private $modules = [];
    /**
     * Add module
     *
     * @param $id
     * @param $module
     *
     * @return void
     */
    public function add_module($id, $module): void
    {
        $this->modules[$id] = $module;
    }
    /**
     * Check if a module is enabled
     *
     * @param string $id Module id.
     *
     * @return bool
     */
    public function is_module_enabled(string $id): bool
    {
        return isset($this->modules[$id]);
    }
    /**
     * Get available modules
     *
     * @return array
     */
    public function get_modules(): array
    {
        return $this->modules;
    }
    /**
     * Get module by id
     *
     * @param $id
     *
     * @return mixed|null
     */
    public function get_module_by_id($id)
    {
        return $this->modules[$id] ?? null;
    }
}
