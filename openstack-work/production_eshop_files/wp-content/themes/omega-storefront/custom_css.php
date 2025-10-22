<?php

$omega_storefront_custom_css = "";

		$omega_storefront_theme_pagination_options_alignment = get_theme_mod('omega_storefront_theme_pagination_options_alignment', 'Center');
		if ($omega_storefront_theme_pagination_options_alignment == 'Center') {
			$omega_storefront_custom_css .= '.navigation.pagination,.navigation.posts-navigation .nav-links{';
			$omega_storefront_custom_css .= 'justify-content: center;margin: 0 auto;';
			$omega_storefront_custom_css .= '}';
		} else if ($omega_storefront_theme_pagination_options_alignment == 'Right') {
			$omega_storefront_custom_css .= '.navigation.pagination,.navigation.posts-navigation .nav-links{';
			$omega_storefront_custom_css .= 'justify-content: right;margin: 0 0 0 auto;';
			$omega_storefront_custom_css .= '}';
		} else if ($omega_storefront_theme_pagination_options_alignment == 'Left') {
			$omega_storefront_custom_css .= '.navigation.pagination,.navigation.posts-navigation .nav-links{';
			$omega_storefront_custom_css .= 'justify-content: left;margin: 0 auto 0 0;';
			$omega_storefront_custom_css .= '}';
		}

		$omega_storefront_theme_breadcrumb_enable = get_theme_mod('omega_storefront_theme_breadcrumb_enable',true);
		if($omega_storefront_theme_breadcrumb_enable != true){
			$omega_storefront_custom_css .='nav.breadcrumb-trail.breadcrumbs,nav.woocommerce-breadcrumb{';
				$omega_storefront_custom_css .='display: none;';
			$omega_storefront_custom_css .='}';
		}

		$omega_storefront_theme_breadcrumb_options_alignment = get_theme_mod('omega_storefront_theme_breadcrumb_options_alignment', 'Left');
		if ($omega_storefront_theme_breadcrumb_options_alignment == 'Center') {
			$omega_storefront_custom_css .= '.breadcrumbs ul,nav.woocommerce-breadcrumb{';
			$omega_storefront_custom_css .= 'text-align: center !important;';
			$omega_storefront_custom_css .= '}';
		} else if ($omega_storefront_theme_breadcrumb_options_alignment == 'Right') {
			$omega_storefront_custom_css .= '.breadcrumbs ul,nav.woocommerce-breadcrumb{';
			$omega_storefront_custom_css .= 'text-align: Right !important;';
			$omega_storefront_custom_css .= '}';
		} else if ($omega_storefront_theme_breadcrumb_options_alignment == 'Left') {
			$omega_storefront_custom_css .= '.breadcrumbs ul,nav.woocommerce-breadcrumb{';
			$omega_storefront_custom_css .= 'text-align: Left !important;';
			$omega_storefront_custom_css .= '}';
		}

		$omega_storefront_single_page_content_alignment = get_theme_mod('omega_storefront_single_page_content_alignment', 'left');
		if ($omega_storefront_single_page_content_alignment == 'left') {
			$omega_storefront_custom_css .= '#single-page .type-page,section.theme-custom-block.theme-error-sectiontheme-error-section.error-block-middle,section.theme-custom-block.theme-error-section.error-block-heading .theme-area-header{';
			$omega_storefront_custom_css .= 'text-align: left !important;';
			$omega_storefront_custom_css .= '}';
		} else if ($omega_storefront_single_page_content_alignment == 'center') {
			$omega_storefront_custom_css .= '#single-page .type-page,section.theme-custom-block.theme-error-sectiontheme-error-section.error-block-middle,section.theme-custom-block.theme-error-section.error-block-heading .theme-area-header{';
			$omega_storefront_custom_css .= 'text-align: center !important;';
			$omega_storefront_custom_css .= '}';
		} else if ($omega_storefront_single_page_content_alignment == 'right') {
			$omega_storefront_custom_css .= '#single-page .type-page,section.theme-custom-block.theme-error-sectiontheme-error-section.error-block-middle,section.theme-custom-block.theme-error-section.error-block-heading .theme-area-header{';
			$omega_storefront_custom_css .= 'text-align: right !important;';
			$omega_storefront_custom_css .= '}';
		}

		$omega_storefront_single_post_content_alignment = get_theme_mod('omega_storefront_single_post_content_alignment', 'left');
		if ($omega_storefront_single_post_content_alignment == 'left') {
			$omega_storefront_custom_css .= '#single-page .type-post,#single-page .type-post .entry-meta,#single-page .type-post .is-layout-flex{';
			$omega_storefront_custom_css .= 'text-align: left !important;justify-content: left;';
			$omega_storefront_custom_css .= '}';
		} else if ($omega_storefront_single_post_content_alignment == 'center') {
			$omega_storefront_custom_css .= '#single-page .type-post,#single-page .type-post .entry-meta,#single-page .type-post .is-layout-flex{';
			$omega_storefront_custom_css .= 'text-align: center !important;justify-content: center;';
			$omega_storefront_custom_css .= '}';
		} else if ($omega_storefront_single_post_content_alignment == 'right') {
			$omega_storefront_custom_css .= '#single-page .type-post,#single-page .type-post .entry-meta,#single-page .type-post .is-layout-flex{';
			$omega_storefront_custom_css .= 'text-align: right !important;justify-content: right;';
			$omega_storefront_custom_css .= '}';
		}

		$omega_storefront_menu_text_transform = get_theme_mod('omega_storefront_menu_text_transform', 'Capitalize');
		if ($omega_storefront_menu_text_transform == 'Capitalize') {
		    $omega_storefront_custom_css .= '.site-navigation .primary-menu > li a{';
		    $omega_storefront_custom_css .= 'text-transform: Capitalize !important;';
		    $omega_storefront_custom_css .= '}';
		} else if ($omega_storefront_menu_text_transform == 'uppercase') {
		    $omega_storefront_custom_css .= '.site-navigation .primary-menu > li a{';
		    $omega_storefront_custom_css .= 'text-transform: uppercase !important;';
		    $omega_storefront_custom_css .= '}';
		} else if ($omega_storefront_menu_text_transform == 'lowercase') {
		    $omega_storefront_custom_css .= '.site-navigation .primary-menu > li a{';
		    $omega_storefront_custom_css .= 'text-transform: lowercase !important;';
		    $omega_storefront_custom_css .= '}';
		}

		$omega_storefront_footer_widget_title_alignment = get_theme_mod('omega_storefront_footer_widget_title_alignment', 'left');
		if ($omega_storefront_footer_widget_title_alignment == 'left') {
			$omega_storefront_custom_css .= 'h2.widget-title{';
			$omega_storefront_custom_css .= 'text-align: left !important;';
			$omega_storefront_custom_css .= '}';
		} else if ($omega_storefront_footer_widget_title_alignment == 'center') {
			$omega_storefront_custom_css .= 'h2.widget-title{';
			$omega_storefront_custom_css .= 'text-align: center !important;';
			$omega_storefront_custom_css .= '}';
		} else if ($omega_storefront_footer_widget_title_alignment == 'right') {
			$omega_storefront_custom_css .= 'h2.widget-title{';
			$omega_storefront_custom_css .= 'text-align: right !important;';
			$omega_storefront_custom_css .= '}';
		}
	
		$omega_storefront_show_hide_related_product = get_theme_mod('omega_storefront_show_hide_related_product',true);
		if($omega_storefront_show_hide_related_product != true){
			$omega_storefront_custom_css .='.related.products{';
				$omega_storefront_custom_css .='display: none;';
			$omega_storefront_custom_css .='}';
		}
	
		/*-------------------- Global First Color -------------------*/
	
		$omega_storefront_global_color = get_theme_mod('omega_storefront_global_color', '#5482F7'); // Add a fallback if the color isn't set
	
		if ($omega_storefront_global_color) {
			$omega_storefront_custom_css .= ':root {';
			$omega_storefront_custom_css .= '--global-color: ' . esc_attr($omega_storefront_global_color) . ';';
			$omega_storefront_custom_css .= '}';
		}

		/*-------------------- Content Font -------------------*/

		$omega_storefront_content_typography_font = get_theme_mod('omega_storefront_content_typography_font', 'Roboto", sans-serif'); // Add a fallback if the color isn't set

		if ($omega_storefront_content_typography_font) {
			$omega_storefront_custom_css .= ':root {';
			$omega_storefront_custom_css .= '--font-main: ' . esc_attr($omega_storefront_content_typography_font) . ';';
			$omega_storefront_custom_css .= '}';
		}

		/*-------------------- Heading Font -------------------*/

		$omega_storefront_heading_typography_font = get_theme_mod('omega_storefront_heading_typography_font', 'Outfit", sans-serif'); // Add a fallback if the color isn't set

		if ($omega_storefront_heading_typography_font) {
			$omega_storefront_custom_css .= ':root {';
			$omega_storefront_custom_css .= '--font-head: ' . esc_attr($omega_storefront_heading_typography_font) . ';';
			$omega_storefront_custom_css .= '}';
		}

		$omega_storefront_columns = get_theme_mod('omega_storefront_posts_per_columns', 3);
		$omega_storefront_columns = absint($omega_storefront_columns);
		if ( $omega_storefront_columns < 1 || $omega_storefront_columns > 6 ) {
			$omega_storefront_columns = 3;
		}
		$omega_storefront_custom_css .= "
			.site-content .article-wraper-archive {
				grid-template-columns: repeat({$omega_storefront_columns}, 1fr);
			}
		";

		$omega_storefront_copyright_alignment = get_theme_mod( 'omega_storefront_copyright_alignment', 'Default' );
		if ( $omega_storefront_copyright_alignment === 'Reverse' ) {
			$omega_storefront_custom_css .= '.site-info .column-row { flex-direction: row-reverse; }';
			$omega_storefront_custom_css .= '.footer-credits { justify-content: flex-end; }';
			$omega_storefront_custom_css .= '.footer-copyright { text-align: right; }';
			$omega_storefront_custom_css .= '.site-info .column.column-3 { text-align: left; }';
		} elseif ( $omega_storefront_copyright_alignment === 'Center' ) {
			$omega_storefront_custom_css .= '.site-info .column-row { flex-direction: column; align-items: center; gap: 15px; }';
			$omega_storefront_custom_css .= '.footer-credits { justify-content: center; }';
			$omega_storefront_custom_css .= '.footer-copyright { text-align: center; }';
			$omega_storefront_custom_css .= '.site-info .column.column-3 { text-align: center; }';
		}

		// FOOTER

		$omega_storefront_footer_widget_background_color = get_theme_mod('omega_storefront_footer_widget_background_color');
		if ($omega_storefront_footer_widget_background_color) {

			$omega_storefront_custom_css .= "
				.footer-widgetarea {
					background-color: ". esc_attr($omega_storefront_footer_widget_background_color) .";
				}
			";
		}

		$omega_storefront_footer_widget_background_image = get_theme_mod('omega_storefront_footer_widget_background_image');
		if ($omega_storefront_footer_widget_background_image) {
			$omega_storefront_custom_css .= "
				.footer-widgetarea {
					background-image: url(" . esc_url($omega_storefront_footer_widget_background_image) . ");
				}
			";
		}

		$omega_storefront_copyright_font_size = get_theme_mod('omega_storefront_copyright_font_size');
		if ($omega_storefront_copyright_font_size) {

			$omega_storefront_custom_css .= "
				.footer-copyright {
					font-size: ". esc_attr($omega_storefront_copyright_font_size) ."px;
				}
			";
		}