<?php
/**
 * The template for displaying single posts and pages.
 * @package Omega Storefront
 * @since 1.0.0
 */

get_header();

$omega_storefront_default = omega_storefront_get_default_theme_options();
$omega_storefront_global_layout = get_theme_mod('omega_storefront_global_sidebar_layout', $omega_storefront_default['omega_storefront_global_sidebar_layout']);
$omega_storefront_page_layout = get_theme_mod('omega_storefront_page_sidebar_layout', $omega_storefront_global_layout);
$omega_storefront_post_layout = get_theme_mod('omega_storefront_post_sidebar_layout', $omega_storefront_global_layout);
$omega_storefront_post_meta = get_post_meta(get_the_ID(), 'omega_storefront_post_sidebar_option', true);

$omega_storefront_final_layout = $omega_storefront_global_layout;
if (!empty($omega_storefront_post_meta) && $omega_storefront_post_meta !== 'default') {
    $omega_storefront_final_layout = $omega_storefront_post_meta;
} elseif (is_page() || (function_exists('is_shop') && is_shop())) {
    $omega_storefront_final_layout = $omega_storefront_page_layout;
} elseif (is_single()) {
    $omega_storefront_final_layout = $omega_storefront_post_layout;
}

// Set content column order based on sidebar layout
$omega_storefront_sidebar_column_class = 'column-order-1';
if ($omega_storefront_final_layout === 'left-sidebar') {
    $omega_storefront_sidebar_column_class = 'column-order-2';
}

?>

<div id="single-page" class="singular-main-block">
    <div class="wrapper">
        <div class="column-row <?php echo esc_attr($omega_storefront_final_layout === 'no-sidebar' ? 'no-sidebar-layout' : ''); ?>">

            <?php if ($omega_storefront_final_layout === 'left-sidebar') : ?>
                <?php get_sidebar(); ?>
            <?php endif; ?>

            <div id="primary" class="content-area <?php echo esc_attr($omega_storefront_final_layout === 'no-sidebar' ? 'full-width-content' : $omega_storefront_sidebar_column_class); ?>">
                <main id="site-content" role="main">

                    <?php
                    omega_storefront_breadcrumb(); // Display breadcrumb

                    if (have_posts()) : ?>

                        <div class="article-wraper">
                            <?php while (have_posts()) : the_post(); ?>

                                <?php get_template_part('template-parts/content', 'single'); ?>

                                <?php if ((is_single() || is_page()) && (comments_open() || get_comments_number()) && !post_password_required()) : ?>
                                    <div class="comments-wrapper">
                                        <?php comments_template(); ?>
                                    </div>
                                <?php endif; ?>

                            <?php endwhile; ?>
                        </div>

                    <?php else : ?>

                        <?php get_template_part('template-parts/content', 'none'); ?>

                    <?php endif;

                    do_action('omega_storefront_navigation_action');
                    ?>

                </main>
            </div>

            <?php if ($omega_storefront_final_layout === 'right-sidebar') : ?>
                <?php get_sidebar(); ?>
            <?php endif; ?>

        </div>
    </div>
</div>

<?php get_footer(); ?>