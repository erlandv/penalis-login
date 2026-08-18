<?php
/**
 * IP access control (blocklist / allowlist).
 *
 * Intercepts login page requests and enforces IP-based access rules:
 *
 * - Blocklist mode: specific IPs are denied access to the login page.
 * - Allowlist mode: only listed IPs may access the login page; all others
 *   are denied. Allowlist mode is only active when at least one allowlist
 *   entry exists (to prevent accidental self-lockout on an empty list).
 *
 * This class is only active when the "IP Access Control" feature is
 * enabled in the Protection settings tab.
 *
 * @package PenalisLogin
 */

declare(strict_types=1);

namespace PenalisLogin;

use PenalisLogin\Database\IpRulesRepository;

/**
 * Class IpAccessControl
 *
 * Hooks into the login page request and enforces IP rules.
 */
final class IpAccessControl {

	/**
	 * @param Helpers             $helpers    Shared helper utilities.
	 * @param IpRulesRepository   $repository IP rules repository.
	 * @param ActivityLogger      $logger     Activity logger.
	 */
	public function __construct(
		private readonly Helpers $helpers,
		private readonly IpRulesRepository $repository,
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
		// Run on 'init' at priority 2 — after SecurityHandler (priority 1)
		// but before most other plugins.
		add_action( 'init', [ $this, 'enforceIpRules' ], 2 );
	}

	// -------------------------------------------------------------------------
	// Enforcement
	// -------------------------------------------------------------------------

	/**
	 * Checks the current request against IP rules and blocks if necessary.
	 *
	 * Only runs on requests that target the custom login slug or wp-login.php.
	 *
	 * @return void
	 */
	public function enforceIpRules(): void {
		// Only act on login page requests.
		if ( ! $this->isLoginPageRequest() ) {
			return;
		}

		// Anti-lockout: logged-in administrators are never blocked.
		if ( $this->helpers->isLoggedInAdmin() ) {
			return;
		}

		$ip       = $this->ipResolver->resolveForSecurity();
		$settings = $this->helpers->getProtectionSettings();
		$mode     = (string) $settings['ip_mode'];

		if ( 'allowlist' === $mode ) {
			$this->enforceAllowlist( $ip );
		} else {
			$this->enforceBlocklist( $ip );
		}
	}

	// -------------------------------------------------------------------------
	// Mode enforcement
	// -------------------------------------------------------------------------

	/**
	 * Blocks the request if the IP is on the blocklist.
	 *
	 * @param  string $ip The client IP address.
	 * @return void
	 */
	private function enforceBlocklist( string $ip ): void {
		if ( ! $this->repository->exists( IpRulesRepository::TYPE_BLOCK, $ip ) ) {
			return;
		}

		$this->logger->logIpBlocked( $ip );
		$this->denyAccess();
	}

	/**
	 * Blocks the request if the IP is NOT on the allowlist.
	 *
	 * If the allowlist is empty, this method does nothing (fail-open) to
	 * prevent accidental lockout when the admin enables allowlist mode
	 * before adding any entries.
	 *
	 * @param  string $ip The client IP address.
	 * @return void
	 */
	private function enforceAllowlist( string $ip ): void {
		// Safety: if no allowlist entries exist, do not block anyone.
		if ( ! $this->repository->hasAllowlistEntries() ) {
			return;
		}

		if ( $this->repository->exists( IpRulesRepository::TYPE_ALLOW, $ip ) ) {
			return; // IP is allowed.
		}

		$this->logger->logIpBlocked( $ip );
		$this->denyAccess();
	}

	// -------------------------------------------------------------------------
	// Request detection
	// -------------------------------------------------------------------------

	/**
	 * Returns whether the current request is for the login page.
	 *
	 * Checks both the custom slug and the native wp-login.php. This runs on
	 * init, before rewrite query vars are populated, so custom slug detection
	 * must use the request path rather than get_query_var().
	 *
	 * @return bool
	 */
	private function isLoginPageRequest(): bool {
		if ( $this->helpers->isWpLoginRequest() ) {
			return true;
		}

		$path          = trim( $this->helpers->getCurrentPathRelativeToHome(), '/' );
		$first_segment = explode( '/', $path, 2 )[0];

		return $first_segment === $this->helpers->getLoginSlug();
	}

	// -------------------------------------------------------------------------
	// Response
	// -------------------------------------------------------------------------

	/**
	 * Sends a 403 Forbidden response and terminates the request.
	 *
	 * @return never
	 */
	private function denyAccess(): never {
		status_header( 403 );
		nocache_headers();

		wp_die(
			esc_html__( 'Sorry, you are not allowed to access this page.', 'penalis-login' ),
			esc_html__( 'Forbidden', 'penalis-login' ),
			[ 'response' => 403 ]
		);
	}

}
