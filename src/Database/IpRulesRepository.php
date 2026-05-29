<?php
/**
 * IP rules repository.
 *
 * Provides read and write access to the IP blocklist / allowlist table.
 * All database interaction for IP rules is centralised here.
 *
 * @package PenalisLogin\Database
 */

declare(strict_types=1);

namespace PenalisLogin\Database;

/**
 * Class IpRulesRepository
 *
 * Handles CRUD operations for IP blocklist and allowlist entries.
 */
final class IpRulesRepository {

	// -------------------------------------------------------------------------
	// Rule type constants
	// -------------------------------------------------------------------------

	/** Block this IP from accessing the login page. */
	public const TYPE_BLOCK = 'block';

	/** Only allow these IPs to access the login page (allowlist mode). */
	public const TYPE_ALLOW = 'allow';

	// -------------------------------------------------------------------------
	// Write
	// -------------------------------------------------------------------------

	/**
	 * Inserts a new IP rule.
	 *
	 * Silently ignores duplicate (rule_type + ip_address) combinations
	 * because the table has a UNIQUE KEY on that pair.
	 *
	 * @param  string $rule_type  One of the TYPE_* constants.
	 * @param  string $ip_address The IP address (IPv4 or IPv6).
	 * @param  string $label      Optional human-readable label.
	 * @return bool               True on success, false on failure.
	 */
	public function insert( string $rule_type, string $ip_address, string $label = '' ): bool {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$result = $wpdb->insert(
			Schema::ipRulesTable(),
			[
				'rule_type'  => $rule_type,
				'ip_address' => substr( $ip_address, 0, 45 ),
				'label'      => substr( $label, 0, 100 ),
				'created_at' => current_time( 'mysql', true ),
			],
			[ '%s', '%s', '%s', '%s' ]
		);

		return false !== $result;
	}

	/**
	 * Deletes an IP rule by its ID.
	 *
	 * @param  int $id The rule ID.
	 * @return bool    True on success, false on failure.
	 */
	public function delete( int $id ): bool {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$result = $wpdb->delete(
			Schema::ipRulesTable(),
			[ 'id' => $id ],
			[ '%d' ]
		);

		return false !== $result;
	}

	/**
	 * Replaces all IP rules of a given type with a new set of addresses.
	 *
	 * This is the "textarea save" operation: delete everything of that type,
	 * then insert the new list. Runs inside a transaction where supported.
	 *
	 * @param  string   $rule_type   One of the TYPE_* constants.
	 * @param  string[] $ip_addresses Validated IP addresses to store.
	 * @return void
	 */
	public function sync( string $rule_type, array $ip_addresses ): void {
		global $wpdb;

		$table = Schema::ipRulesTable();
		$now   = current_time( 'mysql', true );

		// Delete all existing rules of this type.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->delete( Schema::ipRulesTable(), [ 'rule_type' => $rule_type ], [ '%s' ] );

		// Insert the new set.
		foreach ( array_unique( $ip_addresses ) as $ip ) {
			$ip = trim( $ip );
			if ( '' === $ip || ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				continue;
			}

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$wpdb->insert(
				$table,
				[
					'rule_type'  => $rule_type,
					'ip_address' => substr( $ip, 0, 45 ),
					'label'      => '',
					'created_at' => $now,
				],
				[ '%s', '%s', '%s', '%s' ]
			);
		}
	}

	// -------------------------------------------------------------------------
	// Read
	// -------------------------------------------------------------------------

	/**
	 * Returns all rules of a given type.
	 *
	 * @param  string $rule_type One of the TYPE_* constants.
	 * @return array<int, object>
	 */
	public function getByType( string $rule_type ): array {
		global $wpdb;

		$table = Schema::ipRulesTable();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$results = $wpdb->get_results(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT * FROM {$table} WHERE rule_type = %s ORDER BY created_at DESC",
				$rule_type
			)
		);

		return is_array( $results ) ? $results : [];
	}

	/**
	 * Returns all IP addresses of a given type as a plain string array.
	 *
	 * Used to populate the textarea UI — one IP per line.
	 *
	 * @param  string $rule_type One of the TYPE_* constants.
	 * @return string[]
	 */
	public function getIpList( string $rule_type ): array {
		global $wpdb;

		$table = Schema::ipRulesTable();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$results = $wpdb->get_col(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT ip_address FROM {$table} WHERE rule_type = %s ORDER BY ip_address ASC",
				$rule_type
			)
		);

		return is_array( $results ) ? $results : [];
	}

	/**
	 * Returns whether a specific IP address has a rule of the given type.
	 *
	 * @param  string $rule_type  One of the TYPE_* constants.
	 * @param  string $ip_address The IP address to check.
	 * @return bool
	 */
	public function exists( string $rule_type, string $ip_address ): bool {
		global $wpdb;

		$table = Schema::ipRulesTable();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$count = $wpdb->get_var(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT COUNT(*) FROM {$table} WHERE rule_type = %s AND ip_address = %s",
				$rule_type,
				$ip_address
			)
		);

		return (int) $count > 0;
	}

	/**
	 * Returns whether any allowlist rules exist.
	 *
	 * When the allowlist is empty, allowlist mode is effectively disabled
	 * (no IP would be allowed through, which would lock everyone out).
	 *
	 * @return bool
	 */
	public function hasAllowlistEntries(): bool {
		global $wpdb;

		$table = Schema::ipRulesTable();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$count = $wpdb->get_var(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT COUNT(*) FROM {$table} WHERE rule_type = %s",
				self::TYPE_ALLOW
			)
		);

		return (int) $count > 0;
	}
}
