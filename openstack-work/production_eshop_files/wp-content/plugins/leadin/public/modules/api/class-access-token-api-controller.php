<?php

namespace Leadin\api;

use Leadin\api\Base_Api_Controller;
use Leadin\auth\OAuth;
use Leadin\auth\OAuthCrypto;
use Leadin\data\Filters;
use Leadin\data\Portal_Options;

class Access_Token_Api_Controller extends Base_Api_Controller {

	const CACHE_KEY = 'leadin_access_token';

	public function __construct() {
		// Uses register_leadin_route → edit_posts capability
		// Safe because only short-lived access token is returned,
		// NOT the long-lived refresh token
		self::register_leadin_route(
			'/access-token',
			\WP_REST_Server::READABLE,
			array( $this, 'get_access_token' )
		);
	}

	public function get_access_token() {
		$cached = get_transient( self::CACHE_KEY );
		if ( ! empty( $cached ) ) {
			$cached_data = json_decode( $cached, true );
			if ( ! empty( $cached_data['accessToken'] )
				&& ! empty( $cached_data['expiresAt'] )
				&& $cached_data['expiresAt'] > ( time() + 300 ) ) {
				return new \WP_REST_Response(
					array(
						'accessToken' => $cached_data['accessToken'],
						'expiresIn'   => $cached_data['expiresAt'] - time(),
					),
					200
				);
			}
		}

		$refresh_token = OAuth::get_refresh_token();

		if ( false === $refresh_token ) {
			return new \WP_REST_Response(
				array( 'error' => 'decrypt_failed' ),
				500
			);
		}

		if ( empty( $refresh_token ) ) {
			return new \WP_REST_Response(
				array( 'error' => 'not_connected' ),
				403
			);
		}

		// Server-side exchange — refresh token never leaves PHP.
		// The /wordpress/v2/oauth/refresh endpoint takes the token in the POST
		// body so it does not appear in server access logs.
		$api_url  = Filters::apply_base_api_url_filters() . '/wordpress/v2/oauth/refresh';
		$response = wp_remote_post(
			$api_url,
			array(
				'headers' => array( 'Content-Type' => 'application/json' ),
				'body'    => json_encode( array( 'refreshToken' => $refresh_token ) ),
				'timeout' => 15,
			)
		);

		if ( is_wp_error( $response ) ) {
			return new \WP_REST_Response(
				array( 'error' => 'refresh_failed' ),
				500
			);
		}

		$response_code = wp_remote_retrieve_response_code( $response );
		if ( 200 !== $response_code ) {
			return new \WP_REST_Response(
				array(
					'error' => 'refresh_failed',
					'code'  => $response_code,
				),
				500
			);
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( empty( $body ) || empty( $body['access_token'] ) ) {
			return new \WP_REST_Response(
				array( 'error' => 'invalid_response' ),
				500
			);
		}

		$expires_in = isset( $body['expires_in'] ) ? (int) $body['expires_in'] : 0;

		if ( ! empty( $body['refresh_token'] ) ) {
			$encrypted_new_token = OAuthCrypto::encrypt( $body['refresh_token'] );
			Portal_Options::set_refresh_token( $encrypted_new_token );
		}

		if ( $expires_in > 300 ) {
			$cache_data = json_encode(
				array(
					'accessToken' => $body['access_token'],
					'expiresAt'   => time() + $expires_in,
			)
			);
			set_transient( self::CACHE_KEY, $cache_data, $expires_in - 300 );
		}

		// Return ONLY the access token — refresh token stays server-side
		return new \WP_REST_Response(
			array(
				'accessToken' => $body['access_token'],
				'expiresIn'   => $expires_in,
			),
			200
		);
	}
}
