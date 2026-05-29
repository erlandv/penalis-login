<?php
/**
 * Login attempt rate limiter.
 *
 * Tracks failed login attempts per IP address and per username.
 * When the configured threshold is exceeded within the time window,
 * the request is blocked and a lockout transient is set.
 *
 * This class is only active when the "Login Attempt Limiter" feature
 * is enabled in the Protection settings tab.
 *
 * @package PenalisLogin
 */

declare(strict_types=1);

namespace PenalisLogin;

use PenalisLogin\Database\ActivityRepository;

/**
 * Class LoginAttemptLimiter
 *
 * Hooks into the WordPress authentication pipeline to enforce rate limits.
 */
final class LoginAttemptLimiter {

	// -------------------------------------------------------------------------
	// Option / transient key prefixes
	// -------------------------------------------------------------------------

	/** Transient key prefix for IP-based lockouts. */
	private const LOCKOUT_IP_PREFIX = 'penalis_lockout_ip_';

	/** Transient key prefix for username-based lockouts. */
	private const LOCKOUT_USER_PREFIX = 'penalis_lockout_user_';

	/**
	 * @param Helpers            $helpers    Shared helper utilities.
	 * @param ActivityRepository $repository Activity log repository.
	 * @param ActivityLogger     $logger     Activity logger (for blocked events).
	 */
	public function __construct(
		private readonly Helpers $helpers,
		private readonly ActivityRepository $repository,
		private readonly ActivityLogger $logger
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
		// Check lockout status before WordPress processes the login form.
		// Priority 1 so we run before other auth filters.
		add_filter( 'authenticate', [ $this, 'checkLockout' ], 1, 3 );

		// Record failures and set lockout transients after WP processes auth.
		add_action( 'wp_login_failed', [ $this, 'onLoginFailed' ], 20, 1 );
	}

	// -------------------------------------------------------------------------
	// Hook callbacks
	// -------------------------------------------------------------------------

	/**
	 * Checks whether the current IP or username is locked out.
	 *
	 * Hooked to 'authenticate' at priority 1. If a lockout is active,
	 * returns a WP_Error to short-circuit the authentication pipeline.
	 *
	 * @param  \WP_User|\WP_Error|null $user     Current auth result.
	 * @param  string                  $username Submitted username.
	 * @param  string                  $password Submitted password (unused).
	 * @return \WP_User|\WP_Error|null
	 */
	public function checkLockout(
		\WP_User|\WP_Error|null $user,
		string $username,
		string $password
	): \WP_User|\WP_Error|null {
		$ip = $this->getClientIp();

		// Check IP lockout.
		if ( $this->isIpLockedOut( $ip ) ) {
			$this->logger->logBlocked( $username, $ip );

			return new \WP_Error(
				'penalis_ip_locked',
				$this->getLockoutMessage()
			);
		}

		// Check username lockout.
		if ( '' !== $username && $this->isUserLockedOut( $username ) ) {
			$this->logger->logBlocked( $username, $ip );

			return new \WP_Error(
				'penalis_user_locked',
				$this->getLockoutMessage()
			);
		}

		return $user;
	}

	/**
	 * Fires after a failed login attempt.
	 *
	 * Counts recent failures and sets a lockout transient if the threshold
	 * has been reached.
	 *
	 * @param  string $username The username that failed.
	 * @return void
	 */
	public function onLoginFailed( string $username ): void {
		$ip          = $this->getClientIp();
		$settings    = $this->getSettings();
		$max         = (int) $settings['max_attempts'];
		$window      = (int) $settings['window_minutes'] * 60;
		$lockout_dur = (int) $settings['lockout_minutes'] * 60;

		// Count failures in the window from the activity log.
		$ip_failures   = $this->repository->countRecentFailures( $ip, $window );
		$user_failures = '' !== $username
			? $this->repository->countRecentFailuresByUsername( $username, $window )
			: 0;

		// Set IP lockout if threshold reached.
		if ( $ip_failures >= $max ) {
			set_transient(
				self::LOCKOUT_IP_PREFIX . md5( $ip ),
				time(),
				$lockout_dur
			);
		}

		// Set username lockout if threshold reached.
		if ( '' !== $username && $user_failures >= $max ) {
			set_transient(
				self::LOCKOUT_USER_PREFIX . md5( $username ),
				time(),
				$lockout_dur
			);
		}
	}

	// -------------------------------------------------------------------------
	// Lockout checks
	// -------------------------------------------------------------------------

	/**
	 * Returns whether the given IP address is currently locked out.
	 *
	 * @param  string $ip The IP address to check.
	 * @return bool
	 */
	public function isIpLockedOut( string $ip ): bool {
		return false !== get_transient( self::LOCKOUT_IP_PREFIX . md5( $ip ) );
	}

	/**
	 * Returns whether the given username is currently locked out.
	 *
	 * @param  string $username The username to check.
	 * @return bool
	 */
	public function isUserLockedOut( string $username ): bool {
		return false !== get_transient( self::LOCKOUT_USER_PREFIX . md5( $username ) );
	}

	/**
	 * Manually releases the lockout for a given IP address.
	 *
	 * @param  string $ip The IP address to unlock.
	 * @return void
	 */
	public function releaseIpLockout( string $ip ): void {
		delete_transient( self::LOCKOUT_IP_PREFIX . md5( $ip ) );
	}

	// -------------------------------------------------------------------------
	// Private helpers
	// -------------------------------------------------------------------------

	/**
	 * Returns the Protection tab settings for the rate limiter.
	 *
	 * @return array<string, mixed>
	 */
	private function getSettings(): array {
		$all      = $this->helpers->getSettings();
		$defaults = Helpers::getDefaultProtectionSettings();

		return array_merge( $defaults, $all['protection'] ?? [] );
	}

	/**
	 * Returns the lockout error message shown to the user.
	 *
	 * @return string
	 */
	private function getLockoutMessage(): string {
		$settings = $this->getSettings();
		$minutes  = (int) $settings['lockout_minutes'];

		return sprintf(
			/* translators: %d: lockout duration in minutes */
			esc_html__( 'Too many failed login attempts. Please try again in %d minute(s).', 'penalis-login' ),
			$minutes
		);
	}

	/**
	 * Returns the best-guess client IP address.
	 *
	 * @return string
	 */
	private function getClientIp(): string {
		// phpcs:disable WordPress.Security.ValidatedSanitizedInput
		$candidates = [
			$_SERVER['HTTP_CF_CONNECTING_IP'] ?? '',
			$_SERVER['HTTP_X_REAL_IP']         ?? '',
			$_SERVER['HTTP_X_FORWARDED_FOR']   ?? '',
			$_SERVER['REMOTE_ADDR']            ?? '',
		];
		// phpcs:enable

		foreach ( $candidates as $candidate ) {
			$ip = trim( explode( ',', $candidate )[0] );

			if ( '' !== $ip && filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				return $ip;
			}
		}

		return '';
	}
}
