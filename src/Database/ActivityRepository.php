<?php
/**
 * Activity log repository.
 *
 * Provides read and write access to the login activity log table.
 * All database interaction for activity records is centralised here.
 *
 * @package PenalisLogin\Database
 */

declare(strict_types=1);

namespace PenalisLogin\Database;

/**
 * Class ActivityRepository
 *
 * Handles inserting and querying login activity records.
 */
final class ActivityRepository {

	// -------------------------------------------------------------------------
	// Event type constants
	// -------------------------------------------------------------------------

	/** A successful login. */
	public const EVENT_LOGIN_SUCCESS = 'login_success';

	/** A failed login attempt. */
	public const EVENT_LOGIN_FAILED = 'login_failed';

	/** A login blocked by the rate limiter. */
	public const EVENT_LOGIN_BLOCKED = 'login_blocked';

	/** A login blocked by the IP blocklist. */
	public const EVENT_IP_BLOCKED = 'ip_blocked';

	// -------------------------------------------------------------------------
	// Write
	// -------------------------------------------------------------------------

	/**
	 * Inserts a new activity record.
	 *
	 * @param  string $event_type One of the EVENT_* constants.
	 * @param  string $username   The username that was used (may be empty).
	 * @param  string $ip_address The visitor's IP address.
	 * @param  string $user_agent The visitor's User-Agent string.
	 * @return void
	 */
	public function insert(
		string $event_type,
		string $username,
		string $ip_address,
		string $user_agent
	): void {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->insert(
			Schema::activityTable(),
			[
				'event_type'  => substr( $event_type, 0, 20 ),
				'username'    => substr( $username, 0, 60 ),
				'ip_address'  => substr( $ip_address, 0, 45 ),
				'user_agent'  => substr( $user_agent, 0, 255 ),
				'occurred_at' => current_time( 'mysql', true ), // UTC
			],
			[ '%s', '%s', '%s', '%s', '%s' ]
		);
	}

	// -------------------------------------------------------------------------
	// Read
	// -------------------------------------------------------------------------

	/**
	 * Returns a paginated list of activity records, newest first.
	 *
	 * @param  int $per_page Number of records per page.
	 * @param  int $page     1-based page number.
	 * @return array<int, object> Array of row objects.
	 */
	public function getPaginated( int $per_page = 50, int $page = 1 ): array {
		global $wpdb;

		$offset = ( max( 1, $page ) - 1 ) * $per_page;
		$table  = Schema::activityTable();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$results = $wpdb->get_results(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT * FROM {$table} ORDER BY occurred_at DESC LIMIT %d OFFSET %d",
				$per_page,
				$offset
			)
		);

		return is_array( $results ) ? $results : [];
	}

	/**
	 * Returns the total number of activity records.
	 *
	 * @return int
	 */
	public function getTotal(): int {
		global $wpdb;

		$table = Schema::activityTable();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$count = $wpdb->get_var(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			"SELECT COUNT(*) FROM {$table}"
		);

		return (int) $count;
	}

	/**
	 * Returns the number of failed login attempts from a given IP address
	 * within the last N seconds.
	 *
	 * Used by the rate limiter to decide whether to block a request.
	 *
	 * @param  string $ip_address  The IP address to check.
	 * @param  int    $window_secs Look-back window in seconds.
	 * @return int
	 */
	public function countRecentFailures( string $ip_address, int $window_secs ): int {
		global $wpdb;

		$table = Schema::activityTable();
		$since = gmdate( 'Y-m-d H:i:s', time() - $window_secs );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$count = $wpdb->get_var(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT COUNT(*) FROM {$table}
				 WHERE ip_address = %s
				   AND event_type = %s
				   AND occurred_at >= %s",
				$ip_address,
				self::EVENT_LOGIN_FAILED,
				$since
			)
		);

		return (int) $count;
	}

	/**
	 * Returns the number of failed login attempts for a given username
	 * within the last N seconds.
	 *
	 * @param  string $username    The username to check.
	 * @param  int    $window_secs Look-back window in seconds.
	 * @return int
	 */
	public function countRecentFailuresByUsername( string $username, int $window_secs ): int {
		global $wpdb;

		$table = Schema::activityTable();
		$since = gmdate( 'Y-m-d H:i:s', time() - $window_secs );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$count = $wpdb->get_var(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT COUNT(*) FROM {$table}
				 WHERE username = %s
				   AND event_type = %s
				   AND occurred_at >= %s",
				$username,
				self::EVENT_LOGIN_FAILED,
				$since
			)
		);

		return (int) $count;
	}

	// -------------------------------------------------------------------------
	// Maintenance
	// -------------------------------------------------------------------------

	/**
	 * Deletes activity records older than the given number of days.
	 *
	 * @param  int $days Records older than this many days will be deleted.
	 * @return int       Number of rows deleted.
	 */
	public function pruneOlderThan( int $days ): int {
		global $wpdb;

		$table  = Schema::activityTable();
		$cutoff = gmdate( 'Y-m-d H:i:s', strtotime( "-{$days} days" ) );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$deleted = $wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"DELETE FROM {$table} WHERE occurred_at < %s",
				$cutoff
			)
		);

		return (int) $deleted;
	}

	/**
	 * Deletes all activity records.
	 *
	 * @return void
	 */
	public function truncate(): void {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query( 'TRUNCATE TABLE ' . esc_sql( Schema::activityTable() ) );
	}
}
