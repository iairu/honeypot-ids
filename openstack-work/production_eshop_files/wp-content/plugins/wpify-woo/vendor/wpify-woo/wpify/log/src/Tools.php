<?php

namespace WpifyWooDeps\Wpify\Log;

class Tools
{
    private $menu_args;
    public function __construct(array $menu_args = [])
    {
        $this->menu_args = $menu_args;
        add_action('admin_menu', [$this, 'add_menu_page'], 99);
        add_action('admin_init', [$this, 'register_settings']);
        add_action('admin_post_wpify_logs_save_settings', [$this, 'save_settings']);
    }
    public function add_menu_page()
    {
        add_submenu_page($this->menu_args['parent_slug'] ?? 'tools.php', $this->menu_args['page_title'] ?? __('WPify Logs', 'wpify-log'), $this->menu_args['menu_title'] ?? __('WPify Logs', 'wpify-log'), $this->menu_args['capability'] ?? 'read', $this->menu_args['menu_slug'] ?? 'wpify-logs', [$this, 'logs_screen'], 109);
    }
    public function logs_screen()
    {
        $logs = apply_filters('wpify_logs', []);
        $files = [];
        foreach ($logs as $log) {
            foreach ($log->getHandlers() as $handler) {
                if (!method_exists($handler, 'get_glob_pattern')) {
                    continue;
                }
                $log_files = \glob($handler->get_glob_pattern());
                $files = array_merge($files, $log_files);
            }
        }
        ?>
        <style>
            .wpify-logs-settings-form {
                display: flex;
                justify-content: center;
                align-items: center;
                width: 100%;
                gap: 10px;
                flex-wrap: wrap;
                border-top: 1px solid var(--wpify-core-light);
                padding-top: 20px;
                margin-top: 20px;

                p.submit {
                    width: auto;
                    margin-top: 0;
                    margin-bottom: 0;
                    padding-top: 0;
                    padding-bottom: 0;
                }
            }
        </style>
        <div class="wrap">
            <h2><?php 
        echo $this->menu_args['page_title'] ?? __('WPify Logs', 'wpify-log');
        ?></h2>

            <form action="" style="display:flex; flex-wrap:wrap; justify-content: start; margin-bottom: 20px;gap: 10px">
                <div class="wpifycf-select">
                    <select class="wpifycf-select__control" name="log-file" id="log-file"
                            style="max-width: 500px; padding-right: 30px">
                        <option value=""></option>
						<?php 
        foreach ($files as $file) {
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
            $parts = explode('_', $cleared_name);
            $parts = array_map('ucfirst', $parts);
            $formated_name = implode(' ', $parts) . ' – ' . $date;
            ?>
                            <option value="<?php 
            echo $file;
            ?>" <?php 
            echo selected($file, !empty($_GET['log-file']) ? esc_html($_GET['log-file']) : '');
            ?>><?php 
            echo $formated_name;
            ?></option>
							<?php 
        }
        ?>
                    </select>
                </div>
                <input type="hidden" name="page" value="<?php 
        echo $this->menu_args['menu_slug'] ?? 'wpify-logs';
        ?>"/>
                <input class="button" type="submit" value="Display log"/>
            </form>
        </div>

        <div class="wrap">
			<?php 
        if (!empty($_GET['log-file'])) {
            $file = str_replace('\\\\', '\\', $_GET['log-file']);
            if (!\in_array($file, $files)) {
                ?>
                    <p><?php 
                _e('File not found, cheating, huh?', 'wpify-log');
                ?></p>
					<?php 
            } else {
                $logs = array_map(function ($item) {
                    return json_decode($item, \ARRAY_A);
                }, file($_GET['log-file']));
                if (!empty($logs)) {
                    $header = [];
                    foreach ($logs[0] as $key => $item) {
                        $header[] = $key;
                    }
                    ?>

                        <table class="wp-list-table widefat fixed striped table-view-list posts">
                            <thead>
                            <tr>
								<?php 
                    foreach ($header as $item) {
                        if (in_array($item, ['channel', 'extra'])) {
                            continue;
                        }
                        ?>
                                    <th style="width: <?php 
                        echo $this->column_width($item);
                        ?>"><?php 
                        echo $item;
                        ?></th>
									<?php 
                    }
                    ?>
                            </tr>
                            </thead>
                            <tbody>
							<?php 
                    foreach ($logs as $log) {
                        ?>
                                <tr>
									<?php 
                        foreach ($log as $key => $item) {
                            if (in_array($key, ['channel', 'extra'])) {
                                continue;
                            }
                            ?>
                                        <td style="width: <?php 
                            echo $this->column_width($key);
                            ?>"><?php 
                            $this->pretty_print_log_item($item, $key);
                            ?></td>
										<?php 
                        }
                        ?>
                                </tr>
								<?php 
                    }
                    ?>
                            </tbody>
                        </table>
						<?php 
                }
            }
        }
        ?>
        </div>

        <div class="wrap">
            <form method="post" action="<?php 
        echo admin_url('admin-post.php');
        ?>" style="margin-bottom: 20px">
				<?php 
        wp_nonce_field('wpify_logs_settings', 'wpify_logs_nonce');
        ?>
                <input type="hidden" name="action" value="wpify_logs_save_settings">

                <div class="wpify-logs-settings-form">
                    <div style="flex: 1;min-width: 250px;">
                        <label for="wpify_logs_max_files"><?php 
        _e('Maximum log files to keep per plugin', 'wpify-log');
        ?></label>

                        <input type="number" id="wpify_logs_max_files" name="wpify_logs_max_files"
                               value="<?php 
        echo esc_attr(get_option('wpify_logs_max_files', 5));
        ?>"
                               min="1" max="100"/>
                    </div>
					<?php 
        submit_button(__('Save Settings', 'wpify-log'));
        ?>
                </div>
            </form>
        </div>
		<?php 
    }
    public function column_width($key)
    {
        switch ($key) {
            case 'context':
                $width = '44%';
                break;
            case 'level':
            case 'level_name':
            case 'extra':
                $width = '7%';
                break;
            default:
                $width = '15%';
                break;
        }
        return $width;
    }
    public function pretty_print_log_item($item, $key)
    {
        if ('level_name' === $key) {
            $level_name = esc_html($item);
            switch ($level_name) {
                case 'DEBUG':
                    $style = 'default';
                    break;
                case 'INFO':
                    $style = 'success';
                    break;
                case 'NOTICE':
                    $style = 'primary';
                    break;
                case 'WARNING':
                    $style = 'warning';
                    break;
                default:
                    $style = 'error';
                    break;
            }
            printf('<span class="log-level log-level-%s wpify-badge wpify-badge-%s">%s</span>', esc_attr($level_name), $style, $level_name);
            return;
        }
        if (is_string($item) && ($item[0] === '{' && str_ends_with($item, '}') || $item[0] === '[' && str_ends_with($item, ']'))) {
            $decoded = json_decode($item, \true);
            if (json_last_error() === \JSON_ERROR_NONE) {
                $item = $decoded;
            }
        }
        if (is_array($item)) {
            $json = json_encode($item, \JSON_UNESCAPED_UNICODE | \JSON_PRETTY_PRINT);
            $body = trim($json);
            if ($body[0] === '{' && substr($body, -1) === '}') {
                $body = substr($body, 1, -1);
            }
            echo '<pre style="white-space: pre-wrap; word-break: break-all; font-size:13px; margin:0;">' . $body . '</pre>';
        } else {
            echo esc_html($item);
        }
    }
    public function register_settings()
    {
        register_setting('wpify_logs_settings', 'wpify_logs_max_files', ['type' => 'integer', 'default' => 5, 'sanitize_callback' => [$this, 'sanitize_max_files']]);
    }
    public function sanitize_max_files($value)
    {
        $value = absint($value);
        if ($value < 1) {
            $value = 1;
        } elseif ($value > 100) {
            $value = 100;
        }
        return $value;
    }
    public function save_settings()
    {
        if (!isset($_POST['wpify_logs_nonce']) || !wp_verify_nonce($_POST['wpify_logs_nonce'], 'wpify_logs_settings')) {
            wp_die(__('Security check failed', 'wpify-log'));
        }
        if (!current_user_can('manage_options')) {
            wp_die(__('You do not have permission to perform this action', 'wpify-log'));
        }
        $max_files = isset($_POST['wpify_logs_max_files']) ? $this->sanitize_max_files($_POST['wpify_logs_max_files']) : 5;
        update_option('wpify_logs_max_files', $max_files);
        $parent_slug = $this->menu_args['parent_slug'] ?? 'tools.php';
        if (strpos($parent_slug, '.php') === \false) {
            $admin_page = 'admin.php';
        } else {
            $admin_page = $parent_slug;
        }
        $redirect_url = add_query_arg(['page' => $this->menu_args['menu_slug'] ?? 'wpify-logs'], admin_url($admin_page));
        wp_safe_redirect($redirect_url);
        exit;
    }
}
