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
		private readonly ActivityLogger $logger,
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
		// Block locked-out IPs at the page level — before the login form
		// is rendered. This prevents the form from appearing at all when
		// an IP is locked out, rather than just showing an error on submit.
		add_action( 'init', [ $this, 'blockLockedOutRequest' ], 5 );

		// Also hook into the authenticate filter as a second layer of defence
		// (catches programmatic auth calls that bypass the login page).
		add_filter( 'authenticate', [ $this, 'checkLockout' ], 1, 3 );

		// Record failures and set lockout transients after WP processes auth.
		add_action( 'wp_login_failed', [ $this, 'onLoginFailed' ], 20, 1 );
	}

	// -------------------------------------------------------------------------
	// Hook callbacks
	// -------------------------------------------------------------------------

	/**
	 * Blocks the login page entirely for locked-out IPs.
	 *
	 * Runs on 'init' at priority 5 — before the login form is rendered.
	 * Detects the login page by matching the REQUEST_URI against the
	 * configured slug directly, without relying on query vars (which are
	 * not yet populated at init time).
	 *
	 * @return void
	 */
	public function blockLockedOutRequest(): void {
		if ( ! $this->isLoginPageUri() ) {
			return;
		}

		// Anti-lockout: never block logged-in administrators.
		if ( $this->helpers->isLoggedInAdmin() ) {
			return;
		}

		$ip = $this->ipResolver->resolveForSecurity();

		if ( ! $this->isIpLockedOut( $ip ) ) {
			return;
		}

		status_header( 429 );
		nocache_headers();

		wp_die(
			esc_html( $this->getLockoutMessage() ),
			esc_html__( 'Too Many Requests', 'penalis-login' ),
			[ 'response' => 429 ]
		);
	}

	/**
	 * Returns whether the current REQUEST_URI matches the login page.
	 *
	 * Checks both the custom slug (from settings) and the native wp-login.php.
	 * Does NOT use get_query_var() because query vars are not populated yet
	 * at init time.
	 *
	 * @return bool
	 */
	private function isLoginPageUri(): bool {
		// Native wp-login.php — already handled by Helpers.
		if ( $this->helpers->isWpLoginRequest() ) {
			return true;
		}

		// Custom slug — match the first path segment of REQUEST_URI.
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
		$path = explode( '?', (string) $uri, 2 )[0];
		$path = trim( $path, '/' );

		// Take only the first segment (e.g. "login" from "login/foo").
		$first_segment = explode( '/', $path, 2 )[0];

		return $first_segment === $this->helpers->getLoginSlug();
	}

	/**
	 * Checks whether the current IP or username is locked out.
	 *
	 * Hooked to 'authenticate' at priority 1. Acts as a second layer of
	 * defence for programmatic auth calls that bypass the login page.
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
		$ip       = $this->ipResolver->resolveForSecurity();
		$settings = $this->helpers->getProtectionSettings();
		$max      = (int) $settings['max_attempts'];
		$window   = (int) $settings['window_minutes'] * 60;

		// Check transient lockout first (fast path — set after threshold is hit).
		$ip_locked   = $this->isIpLockedOut( $ip );
		$user_locked = '' !== $username && $this->isUserLockedOut( $username );

		// Fallback: if no transient yet, count directly from DB.
		// This handles the case where the threshold is hit on this exact
		// request — the transient won't exist yet but the DB count will.
		if ( ! $ip_locked ) {
			$ip_locked = $this->repository->countRecentFailures( $ip, $window ) >= $max;
		}

		if ( ! $user_locked && '' !== $username ) {
			$user_locked = $this->repository->countRecentFailuresByUsername( $username, $window ) >= $max;
		}

		if ( $ip_locked ) {
			$this->logger->logBlocked( $username, $ip );
			return new \WP_Error( 'penalis_ip_locked', $this->getLockoutMessage() );
		}

		if ( $user_locked ) {
			$this->logger->logBlocked( $username, $ip );
			return new \WP_Error( 'penalis_user_locked', $this->getLockoutMessage() );
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
		$ip       = $this->ipResolver->resolveForSecurity();
		$settings = $this->helpers->getProtectionSettings();
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

	private function getLockoutMessage(): string {
		$minutes = (int) $this->helpers->getProtectionSettings()['lockout_minutes'];

		return sprintf(
			/* translators: %d: lockout duration in minutes */
			esc_html__( 'Too many failed login attempts. Please try again in %d minute(s).', 'penalis-login' ),
			$minutes
		);
	}
}
