<?php
$omega_storefront_layout = omega_storefront_get_final_sidebar_layout();
$omega_storefront_sidebar_class = 'column-order-1';

if ( $omega_storefront_layout === 'left-sidebar' ) {
    $omega_storefront_sidebar_class = 'column-order-1';
} elseif ( $omega_storefront_layout === 'right-sidebar' ) {
    $omega_storefront_sidebar_class = 'column-order-2';
}

if ( $omega_storefront_layout !== 'no-sidebar' ) : ?>
    <aside id="secondary" class="widget-area <?php echo esc_attr( $omega_storefront_sidebar_class ); ?>">
        <div class="widget-area-wrapper">
            <?php if ( is_active_sidebar('sidebar-1') ) : ?>
                <?php dynamic_sidebar( 'sidebar-1' ); ?>
            <?php else : ?>
                <!-- Default widgets -->
                <div class="widget widget_block widget_search">
                    <h3 class="widget-title"><?php esc_html_e('Search', 'omega-storefront'); ?></h3>
                    <?php get_search_form(); ?>
                </div>

                <div class="widget widget_pages">
                    <h3 class="widget-title"><?php esc_html_e('Pages', 'omega-storefront'); ?></h3>
                    <ul>
                        <?php
                        wp_list_pages(array(
                            'title_li' => '',
                        ));
                        ?>
                    </ul>
                </div>

                <div class="widget widget_archive">
                    <h3 class="widget-title"><?php esc_html_e('Archives', 'omega-storefront'); ?></h3>
                    <ul>
                        <?php wp_get_archives(['type' => 'monthly', 'show_post_count' => true]); ?>
                    </ul>
                </div>

                <div class="widget widget_categories">
                    <h3 class="widget-title"><?php esc_html_e('Categories', 'omega-storefront'); ?></h3>
                    <ul class="wp-block-categories-list wp-block-categories">
                        <?php wp_list_categories(['orderby' => 'name', 'title_li' => '', 'show_count' => true]); ?>
                    </ul>
                </div>

                <div class="widget widget_tag_cloud">
                    <h3 class="widget-title"><?php esc_html_e('Tags', 'omega-storefront'); ?></h3>
                    <?php
                    $omega_storefront_tags = get_tags();
                    if ( $omega_storefront_tags ) {
                        echo '<div class="tagcloud">';
                        foreach ( $omega_storefront_tags as $omega_storefront_tag ) {
                            $omega_storefront_link = get_tag_link($omega_storefront_tag->term_id);
                            echo '<a href="' . esc_url($omega_storefront_link) . '" class="tag-cloud-link">' . esc_html($omega_storefront_tag->name) . '</a> ';
                        }
                        echo '</div>';
                    } else {
                        echo '<p>' . esc_html__('No tags found.', 'omega-storefront') . '</p>';
                    }
                    ?>
                </div>

            <?php endif; ?>
        </div>
    </aside>
<?php endif; ?>
