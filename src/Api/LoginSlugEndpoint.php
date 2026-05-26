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
 * Nginx passes the original request URI in the X-Original-URI header.
 * The endpoint strips the path down to its first segment and compares it
 * against the stored slug.
 *
 * Response codes
 * --------------
 * 200  The URI matches the custom login slug → Nginx should apply
 *      basic auth and rate limiting.
 * 403  The URI does not match → Nginx should let the request through
 *      without any extra protection.
 *
 * Security considerations
 * -----------------------
 * - The endpoint is intentionally unauthenticated so Nginx can call it
 *   without credentials. It reveals nothing sensitive — only a boolean
 *   yes/no about whether a given path is the login slug.
 * - The slug itself is never included in the response body, only the
 *   HTTP status code is meaningful.
 * - Rate limiting on this endpoint is handled by Nginx itself (the
 *   subrequest is internal and never reaches the public internet).
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
				// No authentication required — Nginx calls this as an internal
				// subrequest. The endpoint is safe to expose publicly because
				// it returns no sensitive data, only an HTTP status code.
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
	 * Reads the original request URI from the X-Original-URI header that
	 * Nginx sets on the subrequest, extracts the first path segment, and
	 * compares it against the configured login slug.
	 *
	 * Returns HTTP 200 if the URI matches the login slug (Nginx should
	 * apply protection), or HTTP 403 if it does not (Nginx should pass
	 * the request through unchanged).
	 *
	 * @param  WP_REST_Request $request The REST request object.
	 * @return WP_REST_Response
	 */
	public function handle( WP_REST_Request $request ): WP_REST_Response {
		$original_uri = $request->get_header( 'x_original_uri' );

		// If Nginx did not send the header, deny by default (safe fallback).
		if ( empty( $original_uri ) ) {
			return new WP_REST_Response( null, 403 );
		}

		// Strip query string and normalise slashes.
		$path = strtok( (string) $original_uri, '?' );
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
			// Match — tell Nginx to apply basic auth + rate limiting.
			return new WP_REST_Response( null, 200 );
		}

		// No match — tell Nginx to leave this request alone.
		return new WP_REST_Response( null, 403 );
	}
}
