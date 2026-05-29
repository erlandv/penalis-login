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
 */
final class ActivityLogger {

	public function __construct(
		private readonly ActivityRepository $repository,
		private readonly ClientIpResolver $ipResolver
	) {}

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
			$this->ipResolver->resolveForLogging(),
			$this->getUserAgent()
		);
	}

	public function onLoginFailed( string $username, \WP_Error $error ): void {
		$this->repository->insert(
			ActivityRepository::EVENT_LOGIN_FAILED,
			$username,
			$this->ipResolver->resolveForLogging(),
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

	private function getUserAgent(): string {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] )
			? wp_unslash( $_SERVER['HTTP_USER_AGENT'] )
			: '';

		return sanitize_text_field( (string) $ua );
	}
}
