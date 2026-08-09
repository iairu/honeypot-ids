<?php

namespace WpifyWoo\Abstracts;

defined( 'ABSPATH' ) || exit;

use WpifyWoo\Plugin;
use WpifyWooDeps\Spatie\ArrayToXml\ArrayToXml;
use WpifyWooDeps\Wpify\Core\Abstracts\AbstractComponent;

/**
 * Class AbstractModule
 * @package WpifyWoo\Abstracts
 * @property Plugin $plugin
 */
abstract class AbstractFeed {

	public function generate_feed() {
		$this->save_feed( $this->get_feed_xml() );
	}

	public function save_feed( $data ) {
		if ( ! file_exists( $this->get_dir_path() ) ) {
			mkdir( $this->get_dir_path(), 0777, true ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- Direct file I/O required for streamed feed generation to uploads dir.
		}

		return file_put_contents( $this->get_xml_path(), $data );
	}

	public function get_dir_path() {
		return trailingslashit( wp_upload_dir()['basedir'] ) . trailingslashit( $this->get_directory_name() );
	}

	public function get_directory_name() {
		return 'xml';
	}

	public function get_xml_path() {
		return $this->get_dir_path() . $this->get_file_name();
	}

	public function get_file_name() {
		return apply_filters( 'wpify_woo_feed_filename', sprintf( '%s_%s.xml', $this->feed_name(), get_current_blog_id() ), $this->feed_name(), $this );
	}

	abstract public function feed_name();

	public function get_feed_xml() {
		for ( $i = 1; $i < 1000000; $i ++ ) {
			$data = $this->get_data_for_page( $i );
			if ( ! $data ) {
				break;
			}

			$this->add_tmp_data( $data['data'] );
		}

		return $this->get_xml_from_array( $this->get_tmp_data(), $this->get_root_name() );
	}

	public function get_data_for_page( $page ) {
		$args = [
			'limit'      => apply_filters( 'wpify_woo_feed_products_per_page', 100, $this->feed_name() ),
			'page'       => $page,
			'status'     => 'publish',
			'visibility' => 'visible',
		];

		$products = wc_get_products( $args );
		if ( empty( $products ) ) {
			return null;
		}

		return [
			'data'  => $this->data( $products ),
			'count' => count( $products ),
		];
	}

	public function get_tmp_data() {
		if ( ! file_exists( $this->get_tmp_file_path() ) ) {
			return [];
		}

		$data = json_decode( file_get_contents( $this->get_tmp_file_path() ) ) ?: array();

		return $data ? json_decode( json_encode( $data ), true ) : array();
	}

	public function get_tmp_file_path() {
		return $this->get_tmp_dir_path() . $this->get_tmp_file_name();
	}

	public function get_tmp_dir_path() {
		return trailingslashit( wp_upload_dir()['basedir'] ) . trailingslashit( $this->get_directory_name() ) . 'tmp/';
	}

	public function get_tmp_file_name() {
		return sprintf( '%s_%s_tmp.json', $this->feed_name(), get_current_blog_id() );
	}

	/**
	 * @param array $products
	 *
	 * @return array
	 */
	abstract public function data( array $product ): array;

	public function add_tmp_data( array $data ) {
		$data   = array_merge( $this->get_tmp_data(), $data );
		$result = $this->save_tmp_data( $data );

		if ( is_wp_error( $result ) ) {
			return $result;
		}

		return $data;
	}

	public function save_tmp_data( array $data ) {
		if ( ! file_exists( $this->get_tmp_dir_path() ) ) {
			mkdir( $this->get_tmp_dir_path(), 0777, true ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- Direct file I/O required for streamed feed generation to uploads dir.
		}

		$tmp_file = $this->get_tmp_file_path();
		if ( $this->has_non_utf8( $data ) ) {
			$data = $this->ensure_utf8( $data );
		}
		$json_data = json_encode( $data );

		if ( $json_data === false ) {
			return new \WP_Error( 'feed_save_error', json_last_error_msg() );
		}

		if ( file_exists( $tmp_file ) && ! is_writable( $tmp_file ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Direct file I/O required for streamed feed generation to uploads dir.
			return new \WP_Error( 'feed_save_error', 'TMP soubor existuje, ale není zapisovatelný: ' . $tmp_file );
		}

		$result = file_put_contents( $tmp_file, $json_data );
		if ( $result === false ) {
			return new \WP_Error( 'feed_save_error', 'error file_put_contents: ' . $tmp_file );
		}

		return $result;
	}

	function has_non_utf8( $data ) {
		if ( is_array( $data ) ) {
			foreach ( $data as $value ) {
				if ( $this->has_non_utf8( $value ) ) {
					return true;
				}
			}
		} elseif ( is_string( $data ) ) {
			if ( ! mb_check_encoding( $data, 'UTF-8' ) ) {
				return true;
			}
		}
		return false;
	}

	function ensure_utf8( $data ) {
		if ( is_array( $data ) ) {
			return array_map( [ $this, 'ensure_utf8' ], $data );
		} elseif ( is_string( $data ) ) {
			if ( ! mb_check_encoding( $data, 'UTF-8' ) ) {
				return mb_convert_encoding( $data, 'UTF-8', 'auto' );
			}
		}

		return $data;
	}

	public function get_xml_from_array( $data, $root_name = 'root', $encoding = 'UTF-8' ) {
		$data = apply_filters( 'wpify_woo_feed_data', $data, $this->feed_name() );
		$xml  = new ArrayToXml( $data, $root_name, true, $encoding );

		return $xml->prettify()->toXml();
	}

	public function get_root_name() {
		return 'root';
	}

	public function delete_tmp_file() {
		if ( file_exists( $this->get_tmp_file_path() ) ) {
			unlink( $this->get_tmp_file_path() ); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Direct file I/O required for streamed feed generation to uploads dir.
		}
	}

	public function get_xml_url() {
		return $this->get_dir_url() . $this->get_file_name();
	}

	public function get_dir_url() {
		return trailingslashit( wp_upload_dir()['baseurl'] ) . trailingslashit( $this->get_directory_name() );
	}
}
