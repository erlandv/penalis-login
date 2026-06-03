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
 *  2. The actual REMOTE_ADDR is in the configured trusted proxy list
 *     (exact IP or CIDR range).
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
	 * Returns the list of trusted proxy IP addresses or CIDR ranges from settings.
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
	 * Parses a newline-separated list of proxy IP addresses or CIDR ranges.
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

			if ( $this->isValidProxyEntry( $line ) ) {
				$result[] = $line;
			}
		}

		return $result;
	}

	/**
	 * Returns whether a given IP address is in the trusted proxy list.
	 *
	 * @param  string   $ip      The IP to check.
	 * @param  string[] $proxies List of trusted proxy IPs or CIDR ranges.
	 * @return bool
	 */
	private function isTrustedProxy( string $ip, array $proxies ): bool {
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}

		foreach ( $proxies as $proxy ) {
			if ( str_contains( $proxy, '/' ) ) {
				if ( $this->ipMatchesCidr( $ip, $proxy ) ) {
					return true;
				}

				continue;
			}

			if ( inet_pton( $ip ) === inet_pton( $proxy ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Returns whether a proxy list entry is a valid exact IP or CIDR range.
	 *
	 * @param  string $entry Proxy list entry.
	 * @return bool
	 */
	private function isValidProxyEntry( string $entry ): bool {
		if ( filter_var( $entry, FILTER_VALIDATE_IP ) ) {
			return true;
		}

		if ( ! str_contains( $entry, '/' ) ) {
			return false;
		}

		$parts = explode( '/', $entry, 2 );

		if ( 2 !== count( $parts ) ) {
			return false;
		}

		$network = trim( $parts[0] );
		$prefix  = trim( $parts[1] );

		if ( ! filter_var( $network, FILTER_VALIDATE_IP ) || ! ctype_digit( $prefix ) ) {
			return false;
		}

		$prefix_length = (int) $prefix;
		$max_prefix    = filter_var( $network, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ? 32 : 128;

		return $prefix_length >= 0 && $prefix_length <= $max_prefix;
	}

	/**
	 * Returns whether an IP address belongs to a CIDR range.
	 *
	 * @param  string $ip   IP address to check.
	 * @param  string $cidr CIDR range.
	 * @return bool
	 */
	private function ipMatchesCidr( string $ip, string $cidr ): bool {
		[ $network, $prefix ] = explode( '/', $cidr, 2 );

		$ip_bin      = inet_pton( $ip );
		$network_bin = inet_pton( $network );

		if ( false === $ip_bin || false === $network_bin || strlen( $ip_bin ) !== strlen( $network_bin ) ) {
			return false;
		}

		$prefix = trim( $prefix );

		if ( ! ctype_digit( $prefix ) ) {
			return false;
		}

		$prefix_length = (int) $prefix;

		if ( $prefix_length < 0 || $prefix_length > strlen( $ip_bin ) * 8 ) {
			return false;
		}

		$full_bytes    = intdiv( $prefix_length, 8 );
		$remaining     = $prefix_length % 8;

		if ( $full_bytes > 0 && substr( $ip_bin, 0, $full_bytes ) !== substr( $network_bin, 0, $full_bytes ) ) {
			return false;
		}

		if ( 0 === $remaining ) {
			return true;
		}

		$mask = ( 0xff << ( 8 - $remaining ) ) & 0xff;

		return ( ord( $ip_bin[ $full_bytes ] ) & $mask ) === ( ord( $network_bin[ $full_bytes ] ) & $mask );
	}
}
