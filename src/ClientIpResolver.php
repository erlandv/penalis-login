<?php
/**
 * Client IP resolver.
 *
 * Resolves the real client IP address for security-critical operations.
 *
 * Security model
 * --------------
 * REMOTE_ADDR is the only value that cannot be spoofed — it is set by the
 * OS/kernel based on the actual TCP connection. HTTP headers like
 * X-Forwarded-For, X-Real-IP, and CF-Connecting-IP are trivially forgeable
 * by any client.
 *
 * Proxy headers are therefore only trusted when:
 *  1. The admin has explicitly enabled trusted proxy support in settings.
 *  2. The actual REMOTE_ADDR is in the configured trusted proxy list.
 *
 * When neither condition is met, REMOTE_ADDR is returned directly.
 *
 * Usage contexts
 * --------------
 * - SECURITY (LoginAttemptLimiter, IpAccessControl): use resolveForSecurity().
 *   Returns the most accurate IP possible while resisting spoofing.
 *
 * - LOGGING (ActivityLogger): use resolveForLogging().
 *   Includes proxy headers for informational value, clearly noting they
 *   may be spoofed. Acceptable because logs are not used for enforcement.
 *
 * @package PenalisLogin
 */

declare(strict_types=1);

namespace PenalisLogin;

/**
 * Class ClientIpResolver
 */
final class ClientIpResolver {

	/**
	 * @param Helpers $helpers Shared helper utilities.
	 */
	public function __construct( private readonly Helpers $helpers ) {}

	// -------------------------------------------------------------------------
	// Public API
	// -------------------------------------------------------------------------

	/**
	 * Resolves the client IP for security-critical operations.
	 *
	 * Only reads proxy headers when REMOTE_ADDR is a configured trusted proxy.
	 * Falls back to REMOTE_ADDR when no trusted proxy configuration exists or
	 * when the connecting address is not a trusted proxy.
	 *
	 * @return string IPv4 or IPv6 address string, or empty string if unresolvable.
	 */
	public function resolveForSecurity(): string {
		$remote_addr = $this->getRemoteAddr();

		// If trusted proxy support is disabled or no proxies are configured,
		// always use REMOTE_ADDR — it cannot be spoofed.
		$trusted_proxies = $this->getTrustedProxies();

		if ( empty( $trusted_proxies ) ) {
			return $remote_addr;
		}

		// Only trust proxy headers when the actual connecting IP is a
		// known trusted proxy (e.g. Cloudflare, Nginx reverse proxy).
		if ( ! $this->isTrustedProxy( $remote_addr, $trusted_proxies ) ) {
			return $remote_addr;
		}

		// REMOTE_ADDR is a trusted proxy — read the forwarded IP from headers.
		return $this->readForwardedIp() ?: $remote_addr;
	}

	/**
	 * Resolves the client IP for logging purposes.
	 *
	 * Attempts to read proxy headers for informational value. The result
	 * may be spoofed and MUST NOT be used for security enforcement.
	 *
	 * @return string
	 */
	public function resolveForLogging(): string {
		// For logging, try proxy headers first for better visibility,
		// then fall back to REMOTE_ADDR.
		return $this->readForwardedIp() ?: $this->getRemoteAddr();
	}

	// -------------------------------------------------------------------------
	// Private helpers
	// -------------------------------------------------------------------------

	/**
	 * Returns the REMOTE_ADDR value — the actual TCP connection address.
	 *
	 * @return string
	 */
	private function getRemoteAddr(): string {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		$addr = $_SERVER['REMOTE_ADDR'] ?? '';

		return filter_var( trim( (string) $addr ), FILTER_VALIDATE_IP ) ? trim( (string) $addr ) : '';
	}

	/**
	 * Reads the forwarded client IP from proxy headers.
	 *
	 * Checks headers in order of specificity:
	 *  1. CF-Connecting-IP  (Cloudflare — single IP, most reliable)
	 *  2. X-Real-IP         (Nginx — single IP)
	 *  3. X-Forwarded-For   (Generic — comma-separated list, leftmost = client)
	 *
	 * @return string Valid IP address, or empty string if none found.
	 */
	private function readForwardedIp(): string {
		// phpcs:disable WordPress.Security.ValidatedSanitizedInput
		$candidates = [
			$_SERVER['HTTP_CF_CONNECTING_IP'] ?? '',
			$_SERVER['HTTP_X_REAL_IP']         ?? '',
			$_SERVER['HTTP_X_FORWARDED_FOR']   ?? '',
		];
		// phpcs:enable

		foreach ( $candidates as $candidate ) {
			// X-Forwarded-For may be a comma-separated list; the leftmost
			// entry is the original client IP (rightmost is the last proxy).
			$ip = trim( explode( ',', (string) $candidate )[0] );

			if ( '' !== $ip && filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				return $ip;
			}
		}

		return '';
	}

	/**
	 * Returns the list of trusted proxy IP addresses from settings.
	 *
	 * @return string[]
	 */
	private function getTrustedProxies(): array {
		$prot = $this->helpers->getProtectionSettings();

		if ( empty( $prot['trusted_proxies_enabled'] ) ) {
			return [];
		}

		return $this->parseProxyList( (string) ( $prot['trusted_proxies'] ?? '' ) );
	}

	/**
	 * Parses a newline-separated list of proxy IP addresses.
	 *
	 * @param  string $raw Raw textarea content.
	 * @return string[]
	 */
	private function parseProxyList( string $raw ): array {
		$lines  = preg_split( '/\r\n|\r|\n/', $raw ) ?: [];
		$result = [];

		foreach ( $lines as $line ) {
			$line = trim( $line );

			if ( '' === $line || str_starts_with( $line, '#' ) ) {
				continue;
			}

			// Strip inline comments.
			if ( str_contains( $line, '#' ) ) {
				$line = trim( explode( '#', $line, 2 )[0] );
			}

			if ( filter_var( $line, FILTER_VALIDATE_IP ) ) {
				$result[] = $line;
			}
		}

		return $result;
	}

	/**
	 * Returns whether a given IP address is in the trusted proxy list.
	 *
	 * @param  string   $ip      The IP to check.
	 * @param  string[] $proxies List of trusted proxy IPs.
	 * @return bool
	 */
	private function isTrustedProxy( string $ip, array $proxies ): bool {
		return in_array( $ip, $proxies, true );
	}
}
