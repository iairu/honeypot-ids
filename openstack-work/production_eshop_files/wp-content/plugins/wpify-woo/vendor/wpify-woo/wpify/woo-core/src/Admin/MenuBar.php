<?php

namespace WpifyWooDeps\Wpify\WooCore\Admin;

/**
 * Class MenuBar
 *
 * Handles rendering of the WPify admin menu bar.
 *
 * @package Wpify\WooCore\Admin
 */
class MenuBar
{
    private Settings $settings;
    public function __construct(Settings $settings)
    {
        $this->settings = $settings;
        add_action('in_admin_header', [$this, 'render']);
    }
    /**
     * Render menu bar
     *
     * @return void
     */
    public function render(): void
    {
        /** @var \WP_Screen $screen */
        $screen = get_current_screen();
        $current_page = isset($_GET['page']) ? sanitize_text_field(wp_unslash($_GET['page'])) : '';
        if (!$screen || !str_contains($current_page, 'wpify')) {
            return;
        }
        $this->enqueue_styles();
        wp_enqueue_script('thickbox');
        wp_enqueue_style('thickbox');
        global $title;
        $data = array('title' => $title, 'icon' => '', 'parent' => '', 'plugin' => '', 'menu' => array(array('icon' => $this->get_dashboard_icon(), 'label' => __('Dashboard', 'wpify-core'), 'link' => add_query_arg(['page' => DashboardPage::SLUG], admin_url('admin.php')))), 'support_url' => add_query_arg(['page' => SupportPage::SLUG], admin_url('admin.php')), 'doc_link' => $this->get_docs_base_url());
        $data = apply_filters('wpify_admin_menu_bar_data', $data);
        $sections = $this->settings->get_sections($data['plugin']);
        foreach ($sections as $section_id => $section) {
            if (isset($section['in_menubar']) && !$section['in_menubar']) {
                unset($sections[$section_id]);
            }
        }
        $data['sections'] = $sections;
        $plugins = $this->settings->get_plugins();
        if (isset($plugins[$data['plugin']])) {
            $data['title'] = $plugins[$data['plugin']]['title'];
            $data['icon'] = $plugins[$data['plugin']]['icon'];
            $data['support_url'] = $plugins[$data['plugin']]['support_url'] ?: $data['support_url'];
            $data['doc_link'] = $data['doc_link'] ?: $plugins[$data['plugin']]['doc_link'];
        }
        if (isset($data['doc_link']) && $data['doc_link']) {
            $data['doc_link'] = add_query_arg(array('utm_source' => $data['plugin'] ?: 'plugin-dashboard', 'utm_medium' => 'plugin-link', 'utm_campaign' => 'documentation-link'), $data['doc_link']);
        }
        $this->render_main_bar($data, $current_page, $title);
        $this->render_sections_bar($data, $current_page);
    }
    /**
     * Render main menu bar
     *
     * @param array  $data         Menu bar data
     * @param string $current_page Current page slug
     * @param string $title        Page title
     *
     * @return void
     */
    private function render_main_bar(array $data, string $current_page, string $title): void
    {
        ?>
		<div class="wpify__menu-bar">
			<div class="wpify__menu-bar-column title-column">
				<?php 
        if ($data['icon']) {
            ?>
					<div class="wpify__plugin-icon">
						<img src="<?php 
            echo esc_url($data['icon']);
            ?>" alt="ICO" width="40" height="40">
					</div>
					<?php 
        }
        ?>
				<div class="wpify__menu-bar-name">
					<?php 
        echo esc_html($data['title'] ?: $title);
        ?>
				</div>
			</div>
			<div class="wpify__menu-bar-column menu-column">
				<?php 
        foreach ($data['menu'] as $item) {
            $url_components = wp_parse_url($item['link']);
            parse_str($url_components['query'] ?? '', $query_params);
            $menu_page = $query_params['page'] ?? '';
            $active_class = $current_page === $menu_page ? ' current' : '';
            printf('<a class="wpify__menu-bar-item%s" href="%s">%s<span>%s</span></a>', esc_attr($active_class), esc_url($item['link']), $item['icon'], esc_html($item['label']));
        }
        if ($data['doc_link']) {
            printf('<a class="wpify__menu-bar-item" href="%s" target="_blank">%s<span>%s</span></a>', esc_url($data['doc_link']), $this->get_documentation_icon(), esc_html__('Documentation', 'wpify-core'));
        }
        printf('<a class="wpify__menu-bar-item%s" href="%s">%s<span>%s</span></a>', $current_page === SupportPage::SLUG ? ' current' : '', esc_url($data['support_url']), $this->get_support_icon(), esc_html__('Support', 'wpify-core'));
        ?>
			</div>
			<div class="wpify__menu-bar-column">
				<?php 
        $this->render_logo();
        ?>
			</div>
		</div>
		<?php 
    }
    /**
     * Render sections bar
     *
     * @param array  $data         Menu bar data
     * @param string $current_page Current page slug
     *
     * @return void
     */
    private function render_sections_bar(array $data, string $current_page): void
    {
        if (empty($data['sections']) || !is_array($data['sections'])) {
            return;
        }
        ?>
		<div class="wpify__menu-section-bar">
			<?php 
        foreach ($data['sections'] as $section) {
            ?>
				<a class="wpify__menu-section-bar-item <?php 
            echo $current_page === $section['menu_slug'] ? 'current' : '';
            ?>"
				   href="<?php 
            echo esc_url($section['url']);
            ?>"
				   title="<?php 
            echo esc_attr($section['title']);
            ?>"><?php 
            echo esc_html($section['title']);
            ?></a>
			<?php 
        }
        ?>
		</div>
		<?php 
    }
    /**
     * Render WPify logo
     *
     * @return void
     */
    private function render_logo(): void
    {
        $web_link = add_query_arg(array('utm_source' => 'plugin-dashboard', 'utm_medium' => 'plugin-link', 'utm_campaign' => 'company-link'), 'https://wpify.io/');
        ?>
		<a class="wpify__logo" href="<?php 
        echo esc_url($web_link);
        ?>" target="_blank" title="WPify Web">
			<svg width="77" height="30" viewBox="0 0 1430 554" fill="none" xmlns="http://www.w3.org/2000/svg">
				<rect opacity="0.3" width="534.768" height="78.1585" rx="39.0792"
				      transform="matrix(-4.37114e-08 1 1 4.37114e-08 336.915 10.0248)"
				      fill="url(#paint0_linear_1101_8228)"></rect>
				<rect opacity="0.3" width="530.655" height="78.1585" rx="39.0792"
				      transform="matrix(-4.37114e-08 1 1 4.37114e-08 172.382 10.0248)"
				      fill="url(#paint1_linear_1101_8228)"></rect>
				<rect opacity="0.8" width="557.882" height="78.1585" rx="39.0792"
				      transform="matrix(0.338781 0.940865 0.940865 -0.338781 0 26.4789)"
				      fill="url(#paint2_linear_1101_8228)"></rect>
				<rect opacity="0.8" width="560.676" height="78.1585" rx="39.0792"
				      transform="matrix(0.338781 0.940865 0.940865 -0.338781 161.499 26.4789)"
				      fill="url(#paint3_linear_1101_8228)"></rect>
				<path opacity="0.8"
				      d="M361.939 13.402C341.81 20.6499 331.252 42.7365 338.252 62.9529L396.856 232.208C403.978 252.779 426.538 263.563 447.019 256.188C467.148 248.94 477.706 226.854 470.707 206.637L412.103 37.3822C404.98 16.8113 382.42 6.02707 361.939 13.402Z"
				      fill="url(#paint4_linear_1101_8228)"></path>
				<path
					d="M661.12 342.274L703.483 174.421H732.858L727.063 225.776L684.899 390.632H658.922L661.12 342.274ZM643.336 174.421L675.707 342.874L675.907 390.632H646.733L598.175 174.421H643.336ZM767.028 340.876L798.001 174.421H843.361L794.803 390.632H765.629L767.028 340.876ZM737.853 174.421L779.617 340.076L782.614 390.632H756.637L713.674 225.776L708.079 174.421H737.853ZM913.708 215.985V473.76H867.348V174.421H909.911L913.708 215.985ZM1030.01 273.934V291.119C1030.01 308.038 1028.47 322.958 1025.41 335.88C1022.35 348.802 1017.82 359.659 1011.82 368.452C1005.96 377.111 998.7 383.638 990.041 388.034C981.382 392.431 971.257 394.629 959.667 394.629C948.744 394.629 939.219 392.231 931.092 387.435C923.099 382.639 916.372 375.912 910.91 367.253C905.448 358.594 901.052 348.336 897.722 336.479C894.524 324.49 892.193 311.435 890.728 297.314V270.937C892.193 256.016 894.458 242.428 897.522 230.172C900.719 217.783 905.048 207.126 910.51 198.2C916.106 189.275 922.9 182.414 930.893 177.618C938.886 172.822 948.411 170.425 959.468 170.425C971.058 170.425 981.249 172.489 990.041 176.619C998.833 180.749 1006.16 187.077 1012.02 195.603C1018.02 204.128 1022.48 214.919 1025.41 227.974C1028.47 240.896 1030.01 256.216 1030.01 273.934ZM983.447 291.119V273.934C983.447 262.877 982.714 253.352 981.249 245.359C979.916 237.233 977.652 230.572 974.455 225.377C971.391 220.181 967.461 216.318 962.665 213.787C958.002 211.256 952.207 209.99 945.28 209.99C939.152 209.99 933.757 211.256 929.094 213.787C924.432 216.318 920.502 219.848 917.304 224.377C914.107 228.774 911.576 234.036 909.711 240.164C907.846 246.158 906.647 252.686 906.114 259.747V308.704C907.313 317.23 909.311 325.089 912.109 332.283C914.907 339.344 918.97 345.005 924.298 349.268C929.76 353.531 936.887 355.663 945.68 355.663C952.474 355.663 958.269 354.331 963.064 351.666C967.86 349.002 971.724 345.005 974.654 339.677C977.718 334.348 979.916 327.687 981.249 319.694C982.714 311.568 983.447 302.043 983.447 291.119ZM1110.54 174.421V390.632H1063.98V174.421H1110.54ZM1061.59 117.87C1061.59 110.41 1063.85 104.216 1068.38 99.2866C1072.91 94.2244 1079.24 91.6933 1087.36 91.6933C1095.49 91.6933 1101.82 94.2244 1106.35 99.2866C1110.88 104.216 1113.14 110.41 1113.14 117.87C1113.14 125.064 1110.88 131.125 1106.35 136.055C1101.82 140.984 1095.49 143.448 1087.36 143.448C1079.24 143.448 1072.91 140.984 1068.38 136.055C1063.85 131.125 1061.59 125.064 1061.59 117.87ZM1213.06 390.632H1166.5V153.839C1166.5 137.72 1169.17 124.198 1174.5 113.274C1179.96 102.217 1187.62 93.8247 1197.48 88.0964C1207.47 82.3681 1219.26 79.5039 1232.84 79.5039C1236.97 79.5039 1241.04 79.8369 1245.03 80.503C1249.03 81.0359 1252.83 81.9018 1256.42 83.1008L1255.43 121.068C1253.56 120.535 1251.23 120.135 1248.43 119.869C1245.77 119.602 1243.17 119.469 1240.64 119.469C1234.78 119.469 1229.78 120.801 1225.65 123.466C1221.52 126.13 1218.39 129.993 1216.26 135.055C1214.13 140.118 1213.06 146.379 1213.06 153.839V390.632ZM1248.23 174.421V210.39H1139.33V174.421H1248.23ZM1328.37 366.853L1374.73 174.421H1423.69L1352.35 423.404C1350.75 428.865 1348.49 434.727 1345.55 440.988C1342.76 447.249 1339.09 453.178 1334.56 458.773C1330.17 464.501 1324.64 469.097 1317.98 472.561C1311.45 476.158 1303.66 477.956 1294.6 477.956C1290.87 477.956 1287.27 477.623 1283.81 476.957C1280.34 476.291 1277.01 475.491 1273.82 474.559V436.992C1274.88 437.125 1276.08 437.258 1277.41 437.391C1278.75 437.525 1279.95 437.591 1281.01 437.591C1287.54 437.591 1292.93 436.592 1297.2 434.594C1301.46 432.729 1304.99 429.665 1307.79 425.402C1310.59 421.272 1313.05 415.744 1315.18 408.816L1328.37 366.853ZM1307.79 174.421L1345.75 335.281L1353.95 387.435L1321.98 395.628L1257.63 174.421H1307.79Z"
					fill="#191E23" fill-opacity="0.9"></path>
				<defs>
					<linearGradient id="paint0_linear_1101_8228" x1="8.79553" y1="7.08742" x2="168.854"
					                y2="274.752" gradientUnits="userSpaceOnUse">
						<stop stop-color="#00A0D2"></stop>
						<stop offset="1" stop-color="#826EB4"></stop>
					</linearGradient>
					<linearGradient id="paint1_linear_1101_8228" x1="8.72787" y1="7.08742" x2="169.369"
					                y2="273.659" gradientUnits="userSpaceOnUse">
						<stop stop-color="#00A0D2"></stop>
						<stop offset="1" stop-color="#826EB4"></stop>
					</linearGradient>
					<linearGradient id="paint2_linear_1101_8228" x1="9.17569" y1="7.08742" x2="153.168"
					                y2="338.084" gradientUnits="userSpaceOnUse">
						<stop stop-color="#03C5FF"></stop>
						<stop offset="1" stop-color="#7F54B3"></stop>
					</linearGradient>
					<linearGradient id="paint3_linear_1101_8228" x1="-31.232" y1="-62.453" x2="98.4039"
					                y2="269.464" gradientUnits="userSpaceOnUse">
						<stop stop-color="#03C5FF"></stop>
						<stop offset="1" stop-color="#7F54B3"></stop>
					</linearGradient>
					<linearGradient id="paint4_linear_1101_8228" x1="233.88" y1="-46.7434" x2="549.504"
					                y2="65.3096" gradientUnits="userSpaceOnUse">
						<stop stop-color="#03C5FF"></stop>
						<stop offset="1" stop-color="#7F54B3"></stop>
					</linearGradient>
				</defs>
			</svg>
		</a>
		<?php 
    }
    /**
     * Enqueue admin styles
     *
     * @return void
     */
    private function enqueue_styles(): void
    {
        $base_dir = dirname(__DIR__, 2);
        $asset_path = $base_dir . '/assets/admin.css';
        $reflection = new \ReflectionClass(static::class);
        $package_root = dirname($reflection->getFileName(), 3);
        $relative_path = str_replace($package_root, '', $asset_path);
        $package_url = str_replace(wp_normalize_path(\WP_CONTENT_DIR), content_url(), wp_normalize_path($package_root));
        $url = $package_url . $relative_path;
        $ver = file_exists($asset_path) ? filemtime($asset_path) : null;
        wp_enqueue_style('wpify-core-admin', $url, [], $ver);
    }
    private function get_docs_base_url(): string
    {
        $domain = 'https://docs.wpify.cz/';
        if (in_array(get_locale(), array('cs_CZ', 'sk_SK'), \true)) {
            $domain = 'https://docs.wpify.cz/cs/';
        }
        return $domain;
    }
    /**
     * Get dashboard icon SVG
     *
     * @return string
     */
    private function get_dashboard_icon(): string
    {
        return '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><path fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="1" d="M3 6.75c0-1.768 0-2.652.55-3.2C4.097 3 4.981 3 6.75 3s2.652 0 3.2.55c.55.548.55 1.432.55 3.2s0 2.652-.55 3.2c-.548.55-1.432.55-3.2.55s-2.652 0-3.2-.55C3 9.403 3 8.519 3 6.75m0 10.507c0-1.768 0-2.652.55-3.2c.548-.55 1.432-.55 3.2-.55s2.652 0 3.2.55c.55.548.55 1.432.55 3.2s0 2.652-.55 3.2c-.548.55-1.432.55-3.2.55s-2.652 0-3.2-.55C3 19.91 3 19.026 3 17.258M13.5 6.75c0-1.768 0-2.652.55-3.2c.548-.55 1.432-.55 3.2-.55s2.652 0 3.2.55c.55.548.55 1.432.55 3.2s0 2.652-.55 3.2c-.548.55-1.432.55-3.2.55s-2.652 0-3.2-.55c-.55-.548-.55-1.432-.55-3.2m0 10.507c0-1.768 0-2.652.55-3.2c.548-.55 1.432-.55 3.2-.55s2.652 0 3.2.55c.55.548.55 1.432.55 3.2s0 2.652-.55 3.2c-.548.55-1.432.55-3.2.55s-2.652 0-3.2-.55c-.55-.548-.55-1.432-.55-3.2"/></svg>';
    }
    /**
     * Get documentation icon SVG
     *
     * @return string
     */
    private function get_documentation_icon(): string
    {
        return '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><g fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="1"><path d="M5 20.25c0 .414.336.75.75.75h10.652C17.565 21 18 20.635 18 19.4v-1.445M5 20.25A2.25 2.25 0 0 1 7.25 18h10.152q.339 0 .598-.045M5 20.25V6.2c0-1.136-.072-2.389 1.092-2.982C6.52 3 7.08 3 8.2 3h9.2c1.236 0 1.6.437 1.6 1.6v11.8c0 .995-.282 1.425-1 1.555"/><path d="m9.6 10.323l1.379 1.575a.3.3 0 0 0 .466-.022L14.245 8"/></g></svg>';
    }
    /**
     * Get support icon SVG
     *
     * @return string
     */
    private function get_support_icon(): string
    {
        return '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><g fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="1"><path d="M21 12a9 9 0 1 1-18 0a9 9 0 0 1 18 0"/><path d="M12 13.496c0-2.003 2-1.503 2-3.506c0-2.659-4-2.659-4 0m2 6.007v-.5"/></g></svg>';
    }
}
