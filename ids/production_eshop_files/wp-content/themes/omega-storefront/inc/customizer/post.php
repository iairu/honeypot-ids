<?php
/**
* Posts Settings.
*
* @package Omega Storefront
*/

$omega_storefront_default = omega_storefront_get_default_theme_options();

// Single Post Section.
$wp_customize->add_section( 'omega_storefront_single_posts_settings',
    array(
    'title'      => esc_html__( 'Single Meta Information Settings', 'omega-storefront' ),
    'priority'   => 35,
    'capability' => 'edit_theme_options',
    'panel'      => 'omega_storefront_theme_option_panel',
    )
);

$wp_customize->add_setting('omega_storefront_display_single_post_image',
    array(
        'default' => $omega_storefront_default['omega_storefront_display_single_post_image'],
        'capability' => 'edit_theme_options',
        'sanitize_callback' => 'omega_storefront_sanitize_checkbox',
    )
);
$wp_customize->add_control('omega_storefront_display_single_post_image',
    array(
        'label' => esc_html__('Enable Single Posts Image', 'omega-storefront'),
        'section' => 'omega_storefront_single_posts_settings',
        'type' => 'checkbox',
    )
);

$wp_customize->add_setting('omega_storefront_post_author',
    array(
        'default' => $omega_storefront_default['omega_storefront_post_author'],
        'capability' => 'edit_theme_options',
        'sanitize_callback' => 'omega_storefront_sanitize_checkbox',
    )
);
$wp_customize->add_control('omega_storefront_post_author',
    array(
        'label' => esc_html__('Enable Posts Author', 'omega-storefront'),
        'section' => 'omega_storefront_single_posts_settings',
        'type' => 'checkbox',
    )
);

$wp_customize->add_setting('omega_storefront_post_date',
    array(
        'default' => $omega_storefront_default['omega_storefront_post_date'],
        'capability' => 'edit_theme_options',
        'sanitize_callback' => 'omega_storefront_sanitize_checkbox',
    )
);
$wp_customize->add_control('omega_storefront_post_date',
    array(
        'label' => esc_html__('Enable Posts Date', 'omega-storefront'),
        'section' => 'omega_storefront_single_posts_settings',
        'type' => 'checkbox',
    )
);

$wp_customize->add_setting('omega_storefront_post_category',
    array(
        'default' => $omega_storefront_default['omega_storefront_post_category'],
        'capability' => 'edit_theme_options',
        'sanitize_callback' => 'omega_storefront_sanitize_checkbox',
    )
);
$wp_customize->add_control('omega_storefront_post_category',
    array(
        'label' => esc_html__('Enable Posts Category', 'omega-storefront'),
        'section' => 'omega_storefront_single_posts_settings',
        'type' => 'checkbox',
    )
);

$wp_customize->add_setting('omega_storefront_post_tags',
    array(
        'default' => $omega_storefront_default['omega_storefront_post_tags'],
        'capability' => 'edit_theme_options',
        'sanitize_callback' => 'omega_storefront_sanitize_checkbox',
    )
);
$wp_customize->add_control('omega_storefront_post_tags',
    array(
        'label' => esc_html__('Enable Posts Tags', 'omega-storefront'),
        'section' => 'omega_storefront_single_posts_settings',
        'type' => 'checkbox',
    )
);

$wp_customize->add_setting( 'omega_storefront_single_page_content_alignment',
    array(
    'default'           => $omega_storefront_default['omega_storefront_single_page_content_alignment'],
    'capability'        => 'edit_theme_options',
    'sanitize_callback' => 'omega_storefront_sanitize_page_content_alignment',
    )
);
$wp_customize->add_control( 'omega_storefront_single_page_content_alignment',
    array(
    'label'       => esc_html__( 'Single Page Content Alignment', 'omega-storefront' ),
    'section'     => 'omega_storefront_single_posts_settings',
    'type'        => 'select',
    'choices'     => array(
        'left' => esc_html__( 'Left', 'omega-storefront' ),
        'center'  => esc_html__( 'Center', 'omega-storefront' ),
        'right'    => esc_html__( 'Right', 'omega-storefront' ),
        ),
    )
);

$wp_customize->add_setting( 'omega_storefront_single_post_content_alignment',
    array(
    'default'           => $omega_storefront_default['omega_storefront_single_post_content_alignment'],
    'capability'        => 'edit_theme_options',
    'sanitize_callback' => 'omega_storefront_sanitize_page_content_alignment',
    )
);
$wp_customize->add_control( 'omega_storefront_single_post_content_alignment',
    array(
    'label'       => esc_html__( 'Single Post Content Alignment', 'omega-storefront' ),
    'section'     => 'omega_storefront_single_posts_settings',
    'type'        => 'select',
    'choices'     => array(
        'left' => esc_html__( 'Left', 'omega-storefront' ),
        'center'  => esc_html__( 'Center', 'omega-storefront' ),
        'right'    => esc_html__( 'Right', 'omega-storefront' ),
        ),
    )
);

// Archive Post Section.
$wp_customize->add_section( 'omega_storefront_posts_settings',
    array(
    'title'      => esc_html__( 'Archive Meta Information Settings', 'omega-storefront' ),
    'priority'   => 36,
    'capability' => 'edit_theme_options',
    'panel'      => 'omega_storefront_theme_option_panel',
    )
);

$wp_customize->add_setting('omega_storefront_display_archive_post_format_icon',
    array(
        'default' => $omega_storefront_default['omega_storefront_display_archive_post_format_icon'],
        'capability' => 'edit_theme_options',
        'sanitize_callback' => 'omega_storefront_sanitize_checkbox',
    )
);
$wp_customize->add_control('omega_storefront_display_archive_post_format_icon',
    array(
        'label' => esc_html__('Enable Posts Format Icon', 'omega-storefront'),
        'section' => 'omega_storefront_posts_settings',
        'type' => 'checkbox',
    )
);

$wp_customize->add_setting('omega_storefront_display_archive_post_image',
    array(
        'default' => $omega_storefront_default['omega_storefront_display_archive_post_image'],
        'capability' => 'edit_theme_options',
        'sanitize_callback' => 'omega_storefront_sanitize_checkbox',
    )
);
$wp_customize->add_control('omega_storefront_display_archive_post_image',
    array(
        'label' => esc_html__('Enable Posts Image', 'omega-storefront'),
        'section' => 'omega_storefront_posts_settings',
        'type' => 'checkbox',
    )
);

$wp_customize->add_setting('omega_storefront_display_archive_post_category',
    array(
        'default' => $omega_storefront_default['omega_storefront_display_archive_post_category'],
        'capability' => 'edit_theme_options',
        'sanitize_callback' => 'omega_storefront_sanitize_checkbox',
    )
);
$wp_customize->add_control('omega_storefront_display_archive_post_category',
    array(
        'label' => esc_html__('Enable Posts Category', 'omega-storefront'),
        'section' => 'omega_storefront_posts_settings',
        'type' => 'checkbox',
    )
);

$wp_customize->add_setting('omega_storefront_display_archive_post_title',
    array(
        'default' => $omega_storefront_default['omega_storefront_display_archive_post_title'],
        'capability' => 'edit_theme_options',
        'sanitize_callback' => 'omega_storefront_sanitize_checkbox',
    )
);
$wp_customize->add_control('omega_storefront_display_archive_post_title',
    array(
        'label' => esc_html__('Enable Posts Title', 'omega-storefront'),
        'section' => 'omega_storefront_posts_settings',
        'type' => 'checkbox',
    )
);

$wp_customize->add_setting('omega_storefront_display_archive_post_content',
    array(
        'default' => $omega_storefront_default['omega_storefront_display_archive_post_content'],
        'capability' => 'edit_theme_options',
        'sanitize_callback' => 'omega_storefront_sanitize_checkbox',
    )
);
$wp_customize->add_control('omega_storefront_display_archive_post_content',
    array(
        'label' => esc_html__('Enable Posts Content', 'omega-storefront'),
        'section' => 'omega_storefront_posts_settings',
        'type' => 'checkbox',
    )
);

$wp_customize->add_setting('omega_storefront_display_archive_post_button',
    array(
        'default' => $omega_storefront_default['omega_storefront_display_archive_post_button'],
        'capability' => 'edit_theme_options',
        'sanitize_callback' => 'omega_storefront_sanitize_checkbox',
    )
);
$wp_customize->add_control('omega_storefront_display_archive_post_button',
    array(
        'label' => esc_html__('Enable Posts Button', 'omega-storefront'),
        'section' => 'omega_storefront_posts_settings',
        'type' => 'checkbox',
    )
);

$wp_customize->add_setting('omega_storefront_excerpt_limit',
    array(
        'default'           => $omega_storefront_default['omega_storefront_excerpt_limit'],
        'capability'        => 'edit_theme_options',
        'sanitize_callback' => 'omega_storefront_sanitize_number_range',
    )
);
$wp_customize->add_control('omega_storefront_excerpt_limit',
    array(
        'label'       => esc_html__('Blog Posts Excerpt limit', 'omega-storefront'),
        'section'     => 'omega_storefront_posts_settings',
        'type'        => 'number',
        'input_attrs' => array(
           'min'   => 1,
           'max'   => 100,
           'step'   => 1,
        ),
    )
);

$wp_customize->add_setting( 'omega_storefront_archive_image_size',
	array(
	'default'           => 'medium',
	'capability'        => 'edit_theme_options',
	'sanitize_callback' => 'omega_storefront_sanitize_select',
	)
);
$wp_customize->add_control( 'omega_storefront_archive_image_size',
	array(
	'label'       => esc_html__( 'Blog Posts Image Size', 'omega-storefront' ),
	'section'     => 'omega_storefront_posts_settings',
	'type'        => 'select',
	'choices'               => array(
		'full' => esc_html__( 'Large Size Image', 'omega-storefront' ),
		'large' => esc_html__( 'Big Size Image', 'omega-storefront' ),
		'medium' => esc_html__( 'Medium Size Image', 'omega-storefront' ),
		'small' => esc_html__( 'Small Size Image', 'omega-storefront' ),
		'xsmall' => esc_html__( 'Extra Small Size Image', 'omega-storefront' ),
		'thumbnail' => esc_html__( 'Thumbnail Size Image', 'omega-storefront' ),
	    ),
	)
);

$wp_customize->add_setting('omega_storefront_posts_per_columns',
    array(
    'default'           => '3',
    'capability'        => 'edit_theme_options',
    'sanitize_callback' => 'omega_storefront_sanitize_number_range',
    )
);
$wp_customize->add_control('omega_storefront_posts_per_columns',
    array(
    'label'       => esc_html__('Blog Posts Per Column', 'omega-storefront'),
    'section'     => 'omega_storefront_posts_settings',
    'type'        => 'number',
    'input_attrs' => array(
    'min'   => 1,
    'max'   => 5,
    'step'   => 1,
    ),
    )
);