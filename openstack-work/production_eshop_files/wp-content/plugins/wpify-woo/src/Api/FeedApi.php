<?php

namespace WpifyWoo\Api;

defined( 'ABSPATH' ) || exit;

use WP_REST_Response;
use WP_REST_Server;
use WpifyWoo\Managers\ApiManager;
use WpifyWoo\Modules\XmlFeedHeureka\XmlFeedHeurekaModule;
use WpifyWoo\Plugin;
use WpifyWooDeps\Wpify\Core\Abstracts\AbstractRest;

/**
 * @property Plugin $plugin
 */
class FeedApi extends \WP_REST_Controller {

	/**
	 * ExampleApi constructor.
	 */
	public function __construct() {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	/**
	 * Register the routes for the objects of the controller.
	 */
	public function register_routes() {
		register_rest_route(
			ApiManager::REST_NAMESPACE,
			'feed/generate/(?P<id>[\w].+)',
			array(
				array(
					'methods'             => WP_REST_Server::READABLE,
					'callback'            => array( $this, 'generate_feed' ),
					'permission_callback' => '__return_true',
				),
			)
		);
		register_rest_route(
			ApiManager::REST_NAMESPACE,
			'feed/chunk-generate/(?P<id>[\w].+)',
			array(
				array(
					'methods'             => WP_REST_Server::READABLE,
					'callback'            => array( $this, 'chunk_generate_feed' ),
					'permission_callback' => '__return_true',
				),
			)
		);
	}

	public function get_module( $id ) {
		if ( 'heureka' === $id ) {
			/** @var XmlFeedHeurekaModule $module */
			$module = wpify_woo_container()->get( XmlFeedHeurekaModule::class );
		} else {
			$module = apply_filters( 'wpify_woo_feeds_api_module', null, $id );
		}

		return $module;
	}

	/**
	 * @param \WP_REST_Request $request Full data about the request.
	 *
	 * @return \WP_Error|\WP_REST_Request|\WP_REST_Response | bool
	 * @throws \ComposePress\Core\Exception\Plugin
	 */
	public function generate_feed( $request ) {
		if ( $this->is_rate_limited( 'generate', 30 ) ) {
			return new \WP_Error( 'rate-limited', __( 'Too many requests. Please try again later.', 'wpify-woo' ), array( 'status' => 429 ) );
		}

		$id     = $request->get_param( 'id' );
		$module = $this->get_module( $id );
		if ( ! $module ) {
			return new \WP_Error( 'module-not-found', __( 'Module not found', 'wpify-woo' ) );
		}

		$module->get_feed()->delete_tmp_file();
		$module->get_feed()->generate_feed();

		return new WP_REST_Response( array( 'result' => 'done' ), 200 );
	}

	/**
	 * @param \WP_REST_Request $request Full data about the request.
	 *
	 * @return \WP_Error|\WP_REST_Request|\WP_REST_Response | bool
	 * @throws \ComposePress\Core\Exception\Plugin
	 */
	public function chunk_generate_feed( $request ) {
		if ( $this->is_rate_limited( 'chunk', 600 ) ) {
			return new \WP_Error( 'rate-limited', __( 'Too many requests. Please try again later.', 'wpify-woo' ), array( 'status' => 429 ) );
		}

		$id     = $request->get_param( 'id' );
		$module = $this->get_module( $id );
		if ( ! $module ) {
			return new \WP_Error( 'module-not-found', __( 'Module not found', 'wpify-woo' ) );
		}

		$feed = $module->get_feed();
		$page = $request->get_param( 'page' ) ?: 1;
		if ( (int) $page === 1 ) {
			$feed->delete_tmp_file();
		}
		$new_data = $feed->get_data_for_page( $page );
		if ( ! $new_data ) {
			// We are done, save the feed.
			$result = $feed->save_feed( $feed->get_xml_from_array( $feed->get_tmp_data(), $feed->get_root_name() ) );

			if ( $result === false ) {
				return new \WP_Error( 'feed_save_error', 'Error write to file.', $feed->get_tmp_data() );
			}

			return new WP_REST_Response( array( 'status' => 'done' ), 201 );
		}

		$feed->add_tmp_data( $new_data['data'] );
		$total = wp_count_posts( 'product' );

		return new WP_REST_Response( array(
			'total_count'     => (int) $total->publish,
			'processed_count' => $new_data['count'],
			'next_page'       => $page + 1,
			'status'          => 'pending',
		), 201 );
	}


	/**
	 * Per-IP throttle for the public feed endpoints. They stay public because
	 * they are documented as a cron target, so this only caps abusive floods
	 * of full-catalog rebuilds without breaking cron or admin generation.
	 *
	 * @param string $bucket Identifies the endpoint (separate counters).
	 * @param int    $max    Allowed requests per 10 minutes for this bucket.
	 *
	 * @return bool True when the current client has exceeded the limit.
	 */
	private function is_rate_limited( string $bucket, int $max ): bool {
		$ip    = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '0.0.0.0';
		$key   = 'wpify_woo_feed_rl_' . $bucket . '_' . md5( $ip );
		$count = (int) get_transient( $key );

		if ( $count >= $max ) {
			return true;
		}

		set_transient( $key, $count + 1, 10 * MINUTE_IN_SECONDS );

		return false;
	}

	/**
	 * Check if a given request has access to create items
	 *
	 * @param \WP_REST_Request $request Full data about the request.
	 *
	 * @return \WP_Error|bool
	 */
	public function create_item_permissions_check( $request ) {
		return true;
	}

	/**
	 * Prepare the item for the REST response
	 *
	 * @param mixed            $item    WordPress representation of the item.
	 * @param \WP_REST_Request $request Request object.
	 *
	 * @return mixed
	 */
	public function prepare_item_for_response( $item, $request ) {
		return array();
	}
}
