<?php
/**
 * Database schema manager.
 *
 * Creates and removes the custom database tables used by Penalis Login.
 * All DDL is centralised here so Activator and uninstall.php have a single
 * source of truth for table names and structure.
 *
 * Tables
 * ------
 * {prefix}penalis_login_activity
 *   Stores every login attempt (success or failure) with metadata.
 *
 * {prefix}penalis_login_ip_rules
 *   Stores IP blocklist / allowlist entries.
 *
 * @package PenalisLogin\Database
 */

declare(strict_types=1);

namespace PenalisLogin\Database;

/**
 * Class Schema
 *
 * Handles creation and removal of plugin-specific database tables.
 */
final class Schema {

	// -------------------------------------------------------------------------
	// Table name constants (without prefix)
	// -------------------------------------------------------------------------

	/** Unprefixed name of the login activity log table. */
	public const ACTIVITY_TABLE = 'penalis_login_activity';

	/** Unprefixed name of the IP rules table. */
	public const IP_RULES_TABLE = 'penalis_login_ip_rules';

	// -------------------------------------------------------------------------
	// Table name helpers
	// -------------------------------------------------------------------------

	/**
	 * Returns the full (prefixed) name of the activity log table.
	 *
	 * @return string
	 */
	public static function activityTable(): string {
		global $wpdb;
		return $wpdb->prefix . self::ACTIVITY_TABLE;
	}

	/**
	 * Returns the full (prefixed) name of the IP rules table.
	 *
	 * @return string
	 */
	public static function ipRulesTable(): string {
		global $wpdb;
		return $wpdb->prefix . self::IP_RULES_TABLE;
	}

	// -------------------------------------------------------------------------
	// Create
	// -------------------------------------------------------------------------

	/**
	 * Creates all plugin tables if they do not already exist.
	 *
	 * Uses dbDelta() so it is safe to call on every activation — it only
	 * creates or alters, never drops data.
	 *
	 * @return void
	 */
	public static function createTables(): void {
		global $wpdb;

		$charset_collate = $wpdb->get_charset_collate();

		$activity = self::activityTable();
		$ip_rules = self::ipRulesTable();

		$sql = "
CREATE TABLE {$activity} (
  id          BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  event_type  VARCHAR(20)  NOT NULL DEFAULT 'login_failed',
  username    VARCHAR(60)  NOT NULL DEFAULT '',
  ip_address  VARCHAR(45)  NOT NULL DEFAULT '',
  user_agent  VARCHAR(255) NOT NULL DEFAULT '',
  occurred_at DATETIME     NOT NULL,
  PRIMARY KEY (id),
  KEY idx_event_type  (event_type),
  KEY idx_ip_address  (ip_address),
  KEY idx_occurred_at (occurred_at)
) {$charset_collate};

CREATE TABLE {$ip_rules} (
  id         BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  rule_type  VARCHAR(10)  NOT NULL DEFAULT 'block',
  ip_address VARCHAR(45)  NOT NULL DEFAULT '',
  label      VARCHAR(100) NOT NULL DEFAULT '',
  created_at DATETIME     NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY idx_rule_ip (rule_type, ip_address),
  KEY idx_rule_type (rule_type)
) {$charset_collate};
";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}

	// -------------------------------------------------------------------------
	// Drop
	// -------------------------------------------------------------------------

	/**
	 * Drops all plugin tables.
	 *
	 * Called only from uninstall.php when the user has opted in to data deletion.
	 *
	 * @return void
	 */
	public static function dropTables(): void {
		global $wpdb;

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.SchemaChange
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query( 'DROP TABLE IF EXISTS ' . esc_sql( self::activityTable() ) );
		$wpdb->query( 'DROP TABLE IF EXISTS ' . esc_sql( self::ipRulesTable() ) );
		// phpcs:enable
	}
}
