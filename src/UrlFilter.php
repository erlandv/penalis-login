<?php
/**
 * URL filter manager.
 *
 * Replaces all WordPress-generated wp-login.php URLs with the custom
 * login slug URL so the native login URL is never exposed in HTML output,
 * emails, or API responses.
 *
 * Filters applied
 * ---------------
 * - login_url          → custom login URL
 * - logout_url         → custom login URL with action=logout
 * - lostpassword_url   → custom login URL with action=lostpassword
 * - register_url       → custom login URL with action=register
 * - network_site_url   → strips wp-login.php from network URLs (multisite)
 * - site_url           → strips wp-login.php from site URLs
 * - wp_redirect        → prevents redirect loops to wp-login.php
 *
 * @package PenalisLogin
 */

declare(strict_types=1);

namespace PenalisLogin;

/**
 * Class UrlFilter
 *
 * Hooks into WordPress URL generation filters to replace all references to
 * wp-login.php with the custom login slug URL.
 */
final class UrlFilter {

	/**
	 * @param Helpers $helpers Shared helper utilities.
	 */
	public function __construct( private readonly Helpers $helpers ) {}

	// -------------------------------------------------------------------------
	// Registration
	// -------------------------------------------------------------------------

	/**
	 * Registers all WordPress URL filters.
	 *
	 * @return void
	 */
	public function register(): void {
		// Core login URL filters.
		add_filter( 'login_url', [ $this, 'filterLoginUrl' ], 10, 3 );
		add_filter( 'logout_url', [ $this, 'filterLogoutUrl' ], 10, 2 );
		add_filter( 'lostpassword_url', [ $this, 'filterLostPasswordUrl' ], 10, 2 );
		add_filter( 'register_url', [ $this, 'filterRegisterUrl' ] );

		// site_url() and network_site_url() are used internally by WordPress
		// to build login-related URLs. We intercept them to prevent wp-login.php
		// from leaking into generated output.
		add_filter( 'site_url', [ $this, 'filterSiteUrl' ], 10, 4 );
		add_filter( 'network_site_url', [ $this, 'filterNetworkSiteUrl' ], 10, 3 );

		// Intercept redirects to prevent redirect loops and wp-login.php exposure.
		add_filter( 'wp_redirect', [ $this, 'filterRedirect' ], 10, 2 );

		// Intercept auth_redirect so plugins that call it get the custom URL.
		add_filter( 'auth_redirect_scheme', [ $this, 'filterAuthRedirectScheme' ] );
	}

	// -------------------------------------------------------------------------
	// Filter callbacks
	// -------------------------------------------------------------------------

	/**
	 * Replaces the WordPress login URL with the custom slug URL.
	 *
	 * @param  string $login_url    The original login URL.
	 * @param  string $redirect     The redirect URL after login.
	 * @param  bool   $force_reauth Whether to force re-authentication.
	 * @return string
	 */
	public function filterLoginUrl( string $login_url, string $redirect, bool $force_reauth ): string {
		$slug = $this->helpers->getLoginSlug();
		$url  = home_url( '/' . $slug . '/' );

		if ( '' !== $redirect ) {
			$url = add_query_arg( 'redirect_to', rawurlencode( $redirect ), $url );
		}

		if ( $force_reauth ) {
			$url = add_query_arg( 'reauth', '1', $url );
		}

		return $url;
	}

	/**
	 * Replaces the WordPress logout URL with the custom slug URL.
	 *
	 * @param  string $logout_url The original logout URL.
	 * @param  string $redirect   The redirect URL after logout.
	 * @return string
	 */
	public function filterLogoutUrl( string $logout_url, string $redirect ): string {
		$slug  = $this->helpers->getLoginSlug();
		$nonce = wp_create_nonce( 'log-out' );
		$url   = add_query_arg(
			[
				'action'   => 'logout',
				'_wpnonce' => $nonce,
			],
			home_url( '/' . $slug . '/' )
		);

		if ( '' !== $redirect ) {
			$url = add_query_arg( 'redirect_to', rawurlencode( $redirect ), $url );
		}

		return $url;
	}

	/**
	 * Replaces the lost password URL with the custom slug URL.
	 *
	 * @param  string $lostpassword_url The original lost password URL.
	 * @param  string $redirect         The redirect URL.
	 * @return string
	 */
	public function filterLostPasswordUrl( string $lostpassword_url, string $redirect ): string {
		$slug = $this->helpers->getLoginSlug();
		$url  = add_query_arg(
			'action',
			'lostpassword',
			home_url( '/' . $slug . '/' )
		);

		if ( '' !== $redirect ) {
			$url = add_query_arg( 'redirect_to', rawurlencode( $redirect ), $url );
		}

		return $url;
	}

	/**
	 * Replaces the registration URL with the custom slug URL.
	 *
	 * @param  string $register_url The original registration URL.
	 * @return string
	 */
	public function filterRegisterUrl( string $register_url ): string {
		$slug = $this->helpers->getLoginSlug();

		return add_query_arg(
			'action',
			'register',
			home_url( '/' . $slug . '/' )
		);
	}

	/**
	 * Intercepts site_url() calls that reference wp-login.php.
	 *
	 * WordPress core uses site_url('wp-login.php') in several places.
	 * We replace those references with the custom login URL so wp-login.php
	 * is never exposed in generated output.
	 *
	 * Important: We must NOT touch URLs for:
	 * - admin-ajax.php
	 * - wp-cron.php
	 * - xmlrpc.php
	 * - REST API endpoints
	 * - Application passwords
	 *
	 * @param  string      $url    The generated URL.
	 * @param  string      $path   The path passed to site_url().
	 * @param  string|null $scheme The URL scheme.
	 * @param  int|null    $blog_id Blog ID (multisite).
	 * @return string
	 */
	public function filterSiteUrl( string $url, string $path, ?string $scheme, ?int $blog_id ): string {
		if ( $this->pathIsWpLogin( $path ) ) {
			return $this->replaceWpLoginInUrl( $url );
		}

		return $url;
	}

	/**
	 * Intercepts network_site_url() calls that reference wp-login.php.
	 *
	 * @param  string      $url    The generated URL.
	 * @param  string      $path   The path passed to network_site_url().
	 * @param  string|null $scheme The URL scheme.
	 * @return string
	 */
	public function filterNetworkSiteUrl( string $url, string $path, ?string $scheme ): string {
		if ( $this->pathIsWpLogin( $path ) ) {
			return $this->replaceWpLoginInUrl( $url );
		}

		return $url;
	}

	/**
	 * Intercepts wp_redirect() calls to prevent redirect loops and slug exposure.
	 *
	 * If WordPress tries to redirect to wp-login.php (e.g. after a failed
	 * auth check), we redirect to the custom login URL instead.
	 *
	 * Important: We must NOT rewrite redirects that originate from a direct
	 * request to wp-login.php itself. When an attacker hits wp-login.php
	 * directly (e.g. with an invalid ?key=), WordPress issues an internal
	 * redirect back to wp-login.php with an error query string. Rewriting
	 * that redirect would expose the custom login slug in the Location header.
	 *
	 * We only rewrite redirects that originate from within the custom login
	 * slug flow (i.e. the current request is NOT a direct wp-login.php hit).
	 *
	 * @param  string $location The redirect URL.
	 * @param  int    $status   HTTP status code.
	 * @return string
	 */
	public function filterRedirect( string $location, int $status ): string {
		if ( ! str_contains( $location, 'wp-login.php' ) ) {
			return $location;
		}

		// If the current request is a direct wp-login.php hit, do not rewrite
		// the redirect — the SecurityHandler will have already blocked or is
		// about to block the request. Rewriting here would leak the slug.
		if ( $this->helpers->isWpLoginRequest() ) {
			return $location;
		}

		return $this->replaceWpLoginInUrl( $location );
	}

	/**
	 * Ensures auth_redirect() uses the custom login URL.
	 *
	 * auth_redirect() calls wp_login_url() internally, which goes through
	 * our filterLoginUrl() filter. This filter is a no-op but ensures the
	 * scheme is preserved.
	 *
	 * @param  string $scheme The auth redirect scheme.
	 * @return string
	 */
	public function filterAuthRedirectScheme( string $scheme ): string {
		return $scheme;
	}

	// -------------------------------------------------------------------------
	// Private helpers
	// -------------------------------------------------------------------------

	/**
	 * Returns whether a given path references wp-login.php.
	 *
	 * @param  string $path URL path to check.
	 * @return bool
	 */
	private function pathIsWpLogin( string $path ): bool {
		return str_contains( $path, 'wp-login.php' );
	}

	/**
	 * Replaces the wp-login.php portion of a URL with the custom login URL.
	 *
	 * Preserves query string parameters (action, redirect_to, etc.) so
	 * WordPress login flows continue to work correctly.
	 *
	 * @param  string $url URL containing wp-login.php.
	 * @return string      URL with wp-login.php replaced by the custom slug.
	 */
	private function replaceWpLoginInUrl( string $url ): string {
		$slug     = $this->helpers->getLoginSlug();
		$base_url = home_url( '/' . $slug . '/' );

		// Parse the original URL to extract query string parameters.
		$parsed = wp_parse_url( $url );
		$query  = $parsed['query'] ?? '';

		if ( '' !== $query ) {
			return $base_url . '?' . $query;
		}

		return $base_url;
	}
}
