<?php
/**
 * Login notification mailer.
 *
 * Sends an email to the site administrator when suspicious login activity
 * is detected — specifically when the number of failed attempts from a
 * single IP exceeds the configured threshold within the time window.
 *
 * This class is only active when the "Login Notification" feature is
 * enabled in the Protection settings tab.
 *
 * @package PenalisLogin
 */

declare(strict_types=1);

namespace PenalisLogin;

use PenalisLogin\Database\ActivityRepository;

/**
 * Class LoginNotifier
 *
 * Hooks into the failed login event and dispatches email alerts.
 */
final class LoginNotifier {

	/** Transient key prefix — prevents duplicate emails per IP per window. */
	private const NOTIFIED_PREFIX = 'penalis_notified_ip_';

	/**
	 * @param Helpers            $helpers    Shared helper utilities.
	 * @param ActivityRepository $repository Activity log repository.
	 */
	public function __construct(
		private readonly Helpers $helpers,
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
		// Run after ActivityLogger (priority 10) and LoginAttemptLimiter (priority 20)
		// so the failure is already recorded before we count it.
		add_action( 'wp_login_failed', [ $this, 'onLoginFailed' ], 30, 1 );
	}

	// -------------------------------------------------------------------------
	// Hook callbacks
	// -------------------------------------------------------------------------

	/**
	 * Checks whether a notification should be sent after a failed login.
	 *
	 * @param  string $username The username that failed.
	 * @return void
	 */
	public function onLoginFailed( string $username ): void {
		$ip       = $this->ipResolver->resolveForSecurity();
		$settings = $this->helpers->getProtectionSettings();

		$threshold = (int) $settings['notify_threshold'];
		$window    = (int) $settings['window_minutes'] * 60;

		// Count recent failures from this IP.
		$failures = $this->repository->countRecentFailures( $ip, $window );

		// Use >= instead of === to be resilient against race conditions.
		// If two requests arrive simultaneously, $failures could jump past
		// $threshold before the transient is set, causing === to never match
		// and the notification to never fire.
		if ( $failures < $threshold ) {
			return;
		}

		// Prevent duplicate notifications for the same IP within the window.
		// This guard also handles the case where $failures > $threshold —
		// the transient is already set from the first time threshold was hit.
		$transient_key = self::NOTIFIED_PREFIX . md5( $ip );
		if ( false !== get_transient( $transient_key ) ) {
			return;
		}

		// Set the "already notified" transient for the duration of the window.
		set_transient( $transient_key, true, $window );

		$this->sendAlert( $ip, $username, $failures, $settings );
	}

	// -------------------------------------------------------------------------
	// Email
	// -------------------------------------------------------------------------

	private function sendAlert(
		string $ip,
		string $username,
		int $count,
		array $settings
	): void {
		$recipient = '' !== (string) $settings['notify_email']
			? (string) $settings['notify_email']
			: get_option( 'admin_email' );

		$site_name = get_bloginfo( 'name' );
		$site_url  = home_url();

		$subject = sprintf(
			/* translators: 1: site name, 2: IP address */
			__( '[%1$s] Suspicious login activity detected from %2$s', 'penalis-login' ),
			$site_name,
			$ip
		);

		$body = sprintf(
			/* translators: 1: site name, 2: count, 3: window minutes, 4: IP, 5: username, 6: site URL, 7: activity log URL */
			__(
				"Hello,\n\n" .
				"%2\$d failed login attempts have been detected on %1\$s within the last %3\$d minute(s).\n\n" .
				"IP Address : %4\$s\n" .
				"Last username tried : %5\$s\n" .
				"Site : %6\$s\n\n" .
				"You can review the full activity log here:\n%7\$s\n\n" .
				"If this was you, no action is needed.\n" .
				"If this looks suspicious, consider adding this IP to your blocklist.\n\n" .
				"— Penalis Login",
				'penalis-login'
			),
			$site_name,
			$count,
			(int) $settings['window_minutes'],
			$ip,
			'' !== $username ? $username : __( '(unknown)', 'penalis-login' ),
			$site_url,
			admin_url( 'options-general.php?page=penalis-login-settings&tab=activity' )
		);

		wp_mail(
			$recipient,
			$subject,
			$body
		);
	}

}
