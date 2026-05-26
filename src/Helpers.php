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

	// -------------------------------------------------------------------------
	// In-memory cache
	// -------------------------------------------------------------------------

	/** @var array<string,mixed>|null Cached settings array. */
	private ?array $settings = null;

	// -------------------------------------------------------------------------
	// Settings retrieval
	// -------------------------------------------------------------------------

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
