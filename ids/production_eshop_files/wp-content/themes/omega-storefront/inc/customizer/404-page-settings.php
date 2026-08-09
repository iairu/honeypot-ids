<?php
/**
* 404 Page Settings.
*
* @package Omega Storefront
*/

$omega_storefront_default = omega_storefront_get_default_theme_options();

$wp_customize->add_section( 'omega_storefront_404_page_settings',
    array(
        'title'      => esc_html__( '404 Page Settings', 'omega-storefront' ),
        'priority'   => 200,
        'capability' => 'edit_theme_options',
        'panel'      => 'omega_storefront_theme_addons_panel',
    )
);

$wp_customize->add_setting( 'omega_storefront_404_main_title',
    array(
        'default'           => $omega_storefront_default['omega_storefront_404_main_title'],
        'capability'        => 'edit_theme_options',
        'sanitize_callback' => 'sanitize_text_field',
    )
);
$wp_customize->add_control( 'omega_storefront_404_main_title',
    array(
        'label'    => esc_html__( '404 Main Title', 'omega-storefront' ),
        'section'  => 'omega_storefront_404_page_settings',
        'type'     => 'text',
    )
);

$wp_customize->add_setting( 'omega_storefront_404_subtitle_one',
    array(
        'default'           => $omega_storefront_default['omega_storefront_404_subtitle_one'],
        'capability'        => 'edit_theme_options',
        'sanitize_callback' => 'sanitize_text_field',
    )
);
$wp_customize->add_control( 'omega_storefront_404_subtitle_one',
    array(
        'label'    => esc_html__( '404 Sub Title One', 'omega-storefront' ),
        'section'  => 'omega_storefront_404_page_settings',
        'type'     => 'text',
    )
);

$wp_customize->add_setting( 'omega_storefront_404_para_one',
    array(
        'default'           => $omega_storefront_default['omega_storefront_404_para_one'],
        'capability'        => 'edit_theme_options',
        'sanitize_callback' => 'sanitize_text_field',
    )
);
$wp_customize->add_control( 'omega_storefront_404_para_one',
    array(
        'label'    => esc_html__( '404 Para Text One', 'omega-storefront' ),
        'section'  => 'omega_storefront_404_page_settings',
        'type'     => 'text',
    )
);

$wp_customize->add_setting( 'omega_storefront_404_subtitle_two',
    array(
        'default'           => $omega_storefront_default['omega_storefront_404_subtitle_two'],
        'capability'        => 'edit_theme_options',
        'sanitize_callback' => 'sanitize_text_field',
    )
);
$wp_customize->add_control( 'omega_storefront_404_subtitle_two',
    array(
        'label'    => esc_html__( '404 Sub Title Two', 'omega-storefront' ),
        'section'  => 'omega_storefront_404_page_settings',
        'type'     => 'text',
    )
);

$wp_customize->add_setting( 'omega_storefront_404_para_two',
    array(
        'default'           => $omega_storefront_default['omega_storefront_404_para_two'],
        'capability'        => 'edit_theme_options',
        'sanitize_callback' => 'sanitize_text_field',
    )
);
$wp_customize->add_control( 'omega_storefront_404_para_two',
    array(
        'label'    => esc_html__( '404 Para Text Two', 'omega-storefront' ),
        'section'  => 'omega_storefront_404_page_settings',
        'type'     => 'text',
    )
);