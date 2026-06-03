<?php
/**
 * REST API endpoint: login slug check.
 *
 * Exposes a single lightweight endpoint that Nginx can query via the
 * auth_request directive to determine whether an incoming request URI
 * matches the currently configured custom login slug.
 *
 * Endpoint
 * --------
 * GET /wp-json/penalis-login/v1/is-login-slug
 *
 * Nginx passes the original request URI in the X-Original-URI header and
 * the shared secret in the X-Penalis-Auth-Token header. After the token is
 * verified, the endpoint strips the path down to its first segment and
 * compares it against the stored slug.
 *
 * Response codes
 * --------------
 * 200  The shared secret is valid and the URI matches the custom login slug.
 * 403  The shared secret is missing/invalid, or the URI does not match.
 *
 * Security considerations
 * -----------------------
 * - The endpoint requires a shared secret in the X-Penalis-Auth-Token
 *   header. Nginx sends this header from its internal auth_request
 *   subrequest; public clients should not know it.
 * - The slug itself is never included in the response body, only the HTTP
 *   status code is meaningful after the shared secret has been verified.
 * - Rate limiting on this endpoint can be handled by Nginx itself.
 *
 * @package PenalisLogin\Api
 */

declare(strict_types=1);

namespace PenalisLogin\Api;

use PenalisLogin\Helpers;
use WP_REST_Request;
use WP_REST_Response;

/**
 * Class LoginSlugEndpoint
 *
 * Registers and handles the REST endpoint used by Nginx auth_request.
 */
final class LoginSlugEndpoint {

	/** REST API namespace. */
	private const NAMESPACE = 'penalis-login/v1';

	/** REST API route. */
	private const ROUTE = '/is-login-slug';

	/**
	 * @param Helpers $helpers Shared helper utilities.
	 */
	public function __construct( private readonly Helpers $helpers ) {}

	// -------------------------------------------------------------------------
	// Registration
	// -------------------------------------------------------------------------

	/**
	 * Registers the REST route.
	 *
	 * @return void
	 */
	public function register(): void {
		add_action( 'rest_api_init', [ $this, 'registerRoute' ] );
	}

	/**
	 * Registers the REST route with WordPress.
	 *
	 * @return void
	 */
	public function registerRoute(): void {
		register_rest_route(
			self::NAMESPACE,
			self::ROUTE,
			[
				'methods'             => 'GET',
				'callback'            => [ $this, 'handle' ],
				// WordPress user authentication is not required because Nginx
				// calls this as an internal subrequest. The handler enforces a
				// shared secret before doing any slug comparison.
				'permission_callback' => '__return_true',
			]
		);
	}

	// -------------------------------------------------------------------------
	// Handler
	// -------------------------------------------------------------------------

	/**
	 * Handles the auth_request check from Nginx.
	 *
	 * Validates the shared secret from X-Penalis-Auth-Token, then reads the
	 * original request URI from the X-Original-URI header that Nginx sets on
	 * the subrequest, extracts the first path segment, and compares it against
	 * the configured login slug.
	 *
	 * Returns HTTP 200 if the shared secret is valid and the URI matches the
	 * login slug, or HTTP 403 if the secret is missing/invalid or the URI does
	 * not match.
	 *
	 * @param  WP_REST_Request $request The REST request object.
	 * @return WP_REST_Response
	 */
	public function handle( WP_REST_Request $request ): WP_REST_Response {
		$provided_token = trim( (string) $request->get_header( 'x_penalis_auth_token' ) );
		$expected_token = $this->helpers->getNginxAuthToken();

		if ( '' === $provided_token || ! hash_equals( $expected_token, $provided_token ) ) {
			return new WP_REST_Response( null, 403 );
		}

		$original_uri = $request->get_header( 'x_original_uri' );

		// If Nginx did not send the header, deny by default (safe fallback).
		if ( empty( $original_uri ) ) {
			return new WP_REST_Response( null, 403 );
		}

		// Strip query string and normalise slashes.
		$path = explode( '?', (string) $original_uri, 2 )[0];
		$path = '/' . trim( (string) $path, '/' );

		// Extract the first path segment.
		// e.g. "/my-login/foo" → "my-login"
		$segments  = explode( '/', ltrim( $path, '/' ) );
		$first_seg = $segments[0] ?? '';

		if ( '' === $first_seg ) {
			return new WP_REST_Response( null, 403 );
		}

		$slug = $this->helpers->getLoginSlug();

		if ( $first_seg === $slug ) {
			// Match.
			return new WP_REST_Response( null, 200 );
		}

		// No match.
		return new WP_REST_Response( null, 403 );
	}
}
