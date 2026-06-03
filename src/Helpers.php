<?php
/**
 * Shared helper utilities.
 *
 * Centralises option retrieval and common logic so other classes
 * don't duplicate database calls or slug-validation code.
 *
 * @package PenalisLogin
 */

declare(strict_types=1);

namespace PenalisLogin;

/**
 * Class Helpers
 *
 * Provides read-only access to plugin settings and shared utility methods.
 * All option reads are cached in-memory for the duration of the request.
 */
final class Helpers {

	// -------------------------------------------------------------------------
	// Option keys
	// -------------------------------------------------------------------------

	/** WordPress option name that stores all plugin settings. */
	public const OPTION_KEY = 'penalis_login_settings';

	/** WordPress option name for the "delete data on uninstall" flag. */
	public const DELETE_ON_UNINSTALL_KEY = 'penalis_login_delete_on_uninstall';

	/** Default custom login slug. */
	public const DEFAULT_SLUG = 'login';

	/** Length of the shared secret used by the Nginx auth_request endpoint. */
	private const NGINX_AUTH_TOKEN_LENGTH = 64;

	// -------------------------------------------------------------------------
	// In-memory cache
	// -------------------------------------------------------------------------

	/** @var array<string,mixed>|null Cached settings array. */
	private ?array $settings = null;

	// -------------------------------------------------------------------------
	// Settings retrieval
	// -------------------------------------------------------------------------

	/**
	 * Returns the default settings array.
	 *
	 * Single source of truth for defaults — used by Activator on first
	 * activation and by SettingsPage when resetting to defaults.
	 *
	 * @return array<string,mixed>
	 */
	public static function getDefaultSettings(): array {
		return [
			'enabled'                 => true,
			'login_slug'              => self::DEFAULT_SLUG,
			'nginx_auth_token'        => self::generateNginxAuthToken(),
			'block_behavior'          => '404',
			'wp_admin_guest_behavior' => 'redirect_login',
			'protection'              => self::getDefaultProtectionSettings(),
			'log_retention_days'      => 30,
		];
	}

	/**
	 * Returns the default settings for the Protection tab.
	 *
	 * All protection features are OFF by default — the admin must explicitly
	 * enable them. This prevents unexpected behavior changes on existing sites.
	 *
	 * @return array<string,mixed>
	 */
	public static function getDefaultProtectionSettings(): array {
		return [
			// Login Attempt Limiter
			'attempt_limiter_enabled' => false,
			'max_attempts'            => 5,
			'window_minutes'          => 10,
			'lockout_minutes'         => 15,

			// Login Notification
			'notify_enabled'          => false,
			'notify_email'            => '',
			'notify_threshold'        => 5,

			// IP Access Control
			'ip_access_enabled'       => false,
			'ip_mode'                 => 'blocklist',

			// Trusted Proxies
			'trusted_proxies_enabled' => false,
			'trusted_proxies'         => '',
		];
	}

	/**
	 * Returns the full settings array, loading from the database once per request.
	 *
	 * @return array<string,mixed>
	 */
	public function getSettings(): array {
		if ( null === $this->settings ) {
			$raw = get_option( self::OPTION_KEY, [] );
			$this->settings = is_array( $raw ) ? $raw : [];
		}

		return $this->settings;
	}

	/**
	 * Invalidates the in-memory settings cache.
	 *
	 * Call this after saving new settings so subsequent reads pick up the
	 * updated values within the same request.
	 *
	 * @return void
	 */
	public function invalidateCache(): void {
		$this->settings = null;
	}

	/**
	 * Returns the number of days to retain activity log records.
	 * Returns 0 when retention is disabled (keep forever).
	 *
	 * @return int
	 */
	public function getLogRetentionDays(): int {
		$settings = $this->getSettings();
		return max( 0, (int) ( $settings['log_retention_days'] ?? 30 ) );
	}

	/**
	 * Returns the merged protection settings (defaults + saved values).
	 *
	 * Single source of truth used by all protection feature classes.
	 * Eliminates the repeated array_merge(defaults, protection) pattern.
	 *
	 * @return array<string,mixed>
	 */
	public function getProtectionSettings(): array {		$settings = $this->getSettings();

		return array_merge(
			self::getDefaultProtectionSettings(),
			$settings['protection'] ?? []
		);
	}

	/**
	 * Returns whether the plugin is enabled.
	 *
	 * Defaults to true so the plugin works out-of-the-box after activation.
	 *
	 * @return bool
	 */
	public function isPluginEnabled(): bool {
		$settings = $this->getSettings();

		// If the key doesn't exist yet (fresh install), treat as enabled.
		if ( ! array_key_exists( 'enabled', $settings ) ) {
			return true;
		}

		return (bool) $settings['enabled'];
	}

	/**
	 * Returns the sanitized custom login slug.
	 *
	 * Falls back to the default slug if the stored value is empty or invalid.
	 * This is the primary failsafe against administrator lockout.
	 *
	 * @return string A non-empty, URL-safe slug.
	 */
	public function getLoginSlug(): string {
		$settings = $this->getSettings();
		$slug     = $settings['login_slug'] ?? self::DEFAULT_SLUG;

		return $this->sanitizeSlug( (string) $slug );
	}

	/**
	 * Returns the shared secret required by the Nginx auth_request endpoint.
	 *
	 * The token is generated lazily for upgraded installs that predate this
	 * setting. It is intentionally not user-editable; admins copy it into their
	 * Nginx config and can rotate it by resetting plugin settings.
	 *
	 * @return string
	 */
	public function getNginxAuthToken(): string {
		$settings = $this->getSettings();
		$token    = isset( $settings['nginx_auth_token'] )
			? trim( (string) $settings['nginx_auth_token'] )
			: '';

		if ( '' !== $token ) {
			return $token;
		}

		$token                         = self::generateNginxAuthToken();
		$settings['nginx_auth_token'] = $token;

		update_option( self::OPTION_KEY, $settings, false );
		$this->settings = $settings;

		return $token;
	}

	/**
	 * Generates a URL/header-safe shared secret for the Nginx auth endpoint.
	 *
	 * @return string
	 */
	public static function generateNginxAuthToken(): string {
		if ( function_exists( 'wp_generate_password' ) ) {
			return wp_generate_password( self::NGINX_AUTH_TOKEN_LENGTH, false, false );
		}

		return bin2hex( random_bytes( intdiv( self::NGINX_AUTH_TOKEN_LENGTH, 2 ) ) );
	}

	/**
	 * Returns the behavior when wp-login.php is accessed directly.
	 *
	 * Possible values: '404' | '403' | 'redirect_home'
	 * Defaults to '404'.
	 *
	 * @return string
	 */
	public function getBlockBehavior(): string {
		$settings = $this->getSettings();
		$behavior = $settings['block_behavior'] ?? '404';

		$allowed = [ '404', '403', 'redirect_home' ];

		return in_array( $behavior, $allowed, true ) ? $behavior : '404';
	}

	/**
	 * Returns the behavior when a guest (non-logged-in user) accesses /wp-admin/.
	 *
	 * Possible values:
	 *  - 'redirect_login' : Redirect to the custom login URL (WordPress default
	 *                        behavior, but exposes the login slug).
	 *  - 'redirect_home'  : Redirect to the site homepage silently.
	 *  - '404'            : Return a 404 Not Found response (stealth mode).
	 *  - '403'            : Return a 403 Forbidden response.
	 *
	 * Defaults to 'redirect_login' for safe out-of-the-box compatibility.
	 *
	 * @return string
	 */
	public function getWpAdminGuestBehavior(): string {
		$settings = $this->getSettings();
		$behavior = $settings['wp_admin_guest_behavior'] ?? 'redirect_login';

		$allowed = [ 'redirect_login', 'redirect_home', '404', '403' ];

		return in_array( $behavior, $allowed, true ) ? $behavior : 'redirect_login';
	}

	/**
	 * Returns a request path relative to the WordPress home URL path.
	 *
	 * Examples:
	 *  - home /      + request /login/          => /login
	 *  - home /blog/ + request /blog/login/     => /login
	 *  - home /blog/ + request /blog/wp-admin/  => /wp-admin
	 *
	 * @param  string $uri Request URI or URL.
	 * @return string      Normalized path beginning with /, without a trailing slash.
	 */
	public function getPathRelativeToHome( string $uri ): string {
		$path = parse_url( $uri, PHP_URL_PATH );

		if ( ! is_string( $path ) || '' === $path ) {
			$path = '/';
		}

		$path      = $this->normalizePath( $path );
		$home_path = $this->normalizePath( (string) parse_url( home_url( '/' ), PHP_URL_PATH ) );

		if ( '/' !== $home_path && ( $path === $home_path || str_starts_with( $path, $home_path . '/' ) ) ) {
			$path = substr( $path, strlen( $home_path ) );
			$path = $this->normalizePath( $path );
		}

		return $path;
	}

	/**
	 * Returns the current request path relative to the WordPress home URL path.
	 *
	 * @return string
	 */
	public function getCurrentPathRelativeToHome(): string {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		$uri = isset( $_SERVER['REQUEST_URI'] )
			? wp_unslash( $_SERVER['REQUEST_URI'] )
			: '';

		return $this->getPathRelativeToHome( (string) $uri );
	}

	/**
	 * Determines whether the current request is for the /wp-admin/ directory
	 * relative to the WordPress home path (but NOT admin-ajax.php, admin-post.php,
	 * or REST API).
	 *
	 * @return bool
	 */
	public function isWpAdminRequest(): bool {
		$path = $this->getCurrentPathRelativeToHome();

		// Must start with /wp-admin/ (or be exactly /wp-admin).
		if ( ! preg_match( '#^/wp-admin(/|$)#i', $path ) ) {
			return false;
		}

		// Exclude front-end entry points that live under wp-admin but must remain
		// reachable to unauthenticated visitors.
		if ( preg_match( '#^/wp-admin/(admin-ajax|admin-post)\.php$#i', $path ) ) {
			return false;
		}

		return true;
	}

	/**
	 * Normalizes a URL path to a leading slash and no trailing slash.
	 *
	 * @param  string $path Raw path.
	 * @return string
	 */
	private function normalizePath( string $path ): string {
		$path = preg_replace( '#/+#', '/', '/' . trim( $path, '/' ) );

		if ( ! is_string( $path ) || '' === $path ) {
			return '/';
		}

		return '/' === $path ? '/' : rtrim( $path, '/' );
	}

	// -------------------------------------------------------------------------
	// Slug utilities
	// -------------------------------------------------------------------------

	/**
	 * Sanitizes a login slug.
	 *
	 * - Strips leading/trailing slashes.
	 * - Converts to lowercase.
	 * - Removes characters that are not alphanumeric, hyphens, or underscores.
	 * - Falls back to DEFAULT_SLUG if the result is empty or reserved.
	 *
	 * Note: this method silently falls back. For user-facing validation that
	 * needs to distinguish *why* a slug was rejected, use normalizeSlug()
	 * combined with isReservedSlug().
	 *
	 * @param  string $slug Raw slug input.
	 * @return string       Sanitized slug.
	 */
	public function sanitizeSlug( string $slug ): string {
		$normalized = $this->normalizeSlug( $slug );

		if ( '' === $normalized || $this->isReservedSlug( $normalized ) ) {
			return self::DEFAULT_SLUG;
		}

		return $normalized;
	}

	/**
	 * Normalizes a slug without applying reserved-slug or empty-string guards.
	 *
	 * Use this when you need the cleaned value before deciding what to do with
	 * it (e.g. to show a specific validation error to the user).
	 *
	 * @param  string $slug Raw slug input.
	 * @return string       Normalized slug (may be empty string).
	 */
	public function normalizeSlug( string $slug ): string {
		$slug = trim( $slug, '/' );

		return sanitize_title( $slug );
	}

	/**
	 * Returns whether a (already normalized) slug is in the reserved list.
	 *
	 * @param  string $slug Normalized slug to check.
	 * @return bool
	 */
	public function isReservedSlug( string $slug ): bool {
		return in_array( $slug, $this->getReservedSlugs(), true );
	}

	/**
	 * Returns a list of slugs that must not be used as the custom login slug
	 * because they conflict with WordPress core routing.
	 *
	 * @return string[]
	 */
	public function getReservedSlugs(): array {
		return [
			'wp-login',
			'wp-admin',
			'wp-content',
			'wp-includes',
			'admin',
			'dashboard',
			'feed',
			'rss',
			'rss2',
			'atom',
			'rdf',
			'sitemap',
			'wp-json',
			'xmlrpc',
			'wp-cron',
		];
	}

	/**
	 * Returns the full custom login URL.
	 *
	 * @param  string $redirect Optional redirect URL appended as a query arg.
	 * @return string
	 */
	public function getCustomLoginUrl( string $redirect = '' ): string {
		$url = home_url( '/' . $this->getLoginSlug() . '/' );

		if ( '' !== $redirect ) {
			$url = add_query_arg( 'redirect_to', rawurlencode( $redirect ), $url );
		}

		return $url;
	}

	/**
	 * Determines whether the current request is for the native wp-login.php.
	 *
	 * Checks both the PHP_SELF server variable and the parsed request URI to
	 * handle edge cases where the server rewrites the path.
	 *
	 * @return bool
	 */
	public function isWpLoginRequest(): bool {
		// phpcs:disable WordPress.Security.ValidatedSanitizedInput
		$self = isset( $_SERVER['PHP_SELF'] )
			? wp_unslash( $_SERVER['PHP_SELF'] )
			: '';

		$uri = isset( $_SERVER['REQUEST_URI'] )
			? wp_unslash( $_SERVER['REQUEST_URI'] )
			: '';
		// phpcs:enable

		// Normalise to path only (strip query string).
		$path = explode( '?', (string) $uri, 2 )[0];

		return str_contains( (string) $self, 'wp-login.php' )
			|| str_contains( (string) $path, 'wp-login.php' );
	}

	/**
	 * Returns whether the current visitor is a logged-in administrator.
	 *
	 * Used by the anti-lockout mechanism.
	 *
	 * @return bool
	 */
	public function isLoggedInAdmin(): bool {
		return is_user_logged_in() && current_user_can( 'manage_options' );
	}
}
