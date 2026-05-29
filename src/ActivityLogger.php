<?php
/**
 * Login activity logger.
 *
 * Hooks into WordPress authentication events and writes a record to the
 * activity log table for every login attempt (success or failure).
 *
 * This class is always active when the plugin is enabled — the Activity Log
 * tab is read-only and does not have an on/off toggle.
 *
 * @package PenalisLogin
 */

declare(strict_types=1);

namespace PenalisLogin;

use PenalisLogin\Database\ActivityRepository;

/**
 * Class ActivityLogger
 *
 * Listens to WordPress login hooks and persists activity records.
 */
final class ActivityLogger {

	/**
	 * @param ActivityRepository $repository Activity log repository.
	 */
	public function __construct( private readonly ActivityRepository $repository ) {}

	// -------------------------------------------------------------------------
	// Registration
	// -------------------------------------------------------------------------

	/**
	 * Registers all WordPress hooks managed by this class.
	 *
	 * @return void
	 */
	public function register(): void {
		// Fires after a user successfully logs in.
		add_action( 'wp_login', [ $this, 'onLoginSuccess' ], 10, 2 );

		// Fires when authentication fails (wrong password, unknown user, etc.).
		add_action( 'wp_login_failed', [ $this, 'onLoginFailed' ], 10, 2 );
	}

	// -------------------------------------------------------------------------
	// Hook callbacks
	// -------------------------------------------------------------------------

	/**
	 * Records a successful login.
	 *
	 * @param  string   $user_login The username that logged in.
	 * @param  \WP_User $user       The WP_User object.
	 * @return void
	 */
	public function onLoginSuccess( string $user_login, \WP_User $user ): void {
		$this->repository->insert(
			ActivityRepository::EVENT_LOGIN_SUCCESS,
			$user_login,
			$this->getClientIp(),
			$this->getUserAgent()
		);
	}

	/**
	 * Records a failed login attempt.
	 *
	 * WordPress fires wp_login_failed with ($username, $error) since WP 5.4.
	 * The $error parameter is accepted but not used — we only need the username.
	 *
	 * @param  string    $username The username that was attempted.
	 * @param  \WP_Error $error    The authentication error (unused).
	 * @return void
	 */
	public function onLoginFailed( string $username, \WP_Error $error ): void {
		$this->repository->insert(
			ActivityRepository::EVENT_LOGIN_FAILED,
			$username,
			$this->getClientIp(),
			$this->getUserAgent()
		);
	}

	// -------------------------------------------------------------------------
	// Public helpers (used by other classes to log non-hook events)
	// -------------------------------------------------------------------------

	/**
	 * Records a login attempt that was blocked by the rate limiter.
	 *
	 * @param  string $username   The username that was attempted.
	 * @param  string $ip_address The IP address that was blocked.
	 * @return void
	 */
	public function logBlocked( string $username, string $ip_address ): void {
		$this->repository->insert(
			ActivityRepository::EVENT_LOGIN_BLOCKED,
			$username,
			$ip_address,
			$this->getUserAgent()
		);
	}

	/**
	 * Records a login attempt that was blocked by the IP blocklist.
	 *
	 * @param  string $ip_address The IP address that was blocked.
	 * @return void
	 */
	public function logIpBlocked( string $ip_address ): void {
		$this->repository->insert(
			ActivityRepository::EVENT_IP_BLOCKED,
			'',
			$ip_address,
			$this->getUserAgent()
		);
	}

	// -------------------------------------------------------------------------
	// Private helpers
	// -------------------------------------------------------------------------

	/**
	 * Returns the best-guess client IP address.
	 *
	 * Checks common proxy headers first, then falls back to REMOTE_ADDR.
	 * Note: headers like X-Forwarded-For can be spoofed — this is acceptable
	 * for logging purposes but should not be used for security decisions alone.
	 *
	 * @return string
	 */
	private function getClientIp(): string {
		// phpcs:disable WordPress.Security.ValidatedSanitizedInput
		$candidates = [
			$_SERVER['HTTP_CF_CONNECTING_IP'] ?? '',   // Cloudflare
			$_SERVER['HTTP_X_REAL_IP']         ?? '',   // Nginx proxy
			$_SERVER['HTTP_X_FORWARDED_FOR']   ?? '',   // Generic proxy (may be comma-list)
			$_SERVER['REMOTE_ADDR']            ?? '',
		];
		// phpcs:enable

		foreach ( $candidates as $candidate ) {
			// X-Forwarded-For may contain a comma-separated list; take the first.
			$ip = trim( explode( ',', $candidate )[0] );

			if ( '' !== $ip && filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				return $ip;
			}
		}

		return '';
	}

	/**
	 * Returns the sanitized User-Agent string.
	 *
	 * @return string
	 */
	private function getUserAgent(): string {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] )
			? wp_unslash( $_SERVER['HTTP_USER_AGENT'] )
			: '';

		return sanitize_text_field( (string) $ua );
	}
}
