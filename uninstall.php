<?php
/**
 * Uninstall handler.
 *
 * Runs when the plugin is deleted from the WordPress admin (Plugins → Delete).
 * Only removes plugin data from the database if the user has opted in via the
 * "Delete Plugin Data on Uninstall" setting.
 *
 * This file is executed by WordPress directly — it does NOT go through the
 * normal plugin bootstrap, so we cannot rely on autoloading or constants
 * defined in penalis-login.php. All option keys and table names are therefore
 * hardcoded here rather than referenced via class constants.
 *
 * @package PenalisLogin
 */

declare(strict_types=1);

// WordPress sets this constant before calling uninstall.php.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

// Only delete data if the user explicitly opted in.
$delete_on_uninstall = (bool) get_option( 'penalis_login_delete_on_uninstall', false );

if ( ! $delete_on_uninstall ) {
	return;
}

global $wpdb;

// Remove the plugin settings option.
delete_option( 'penalis_login_settings' );

// Remove the uninstall preference option itself.
delete_option( 'penalis_login_delete_on_uninstall' );

// Remove the DB schema version option.
delete_option( 'penalis_login_db_version' );

// Remove any transients created by the plugin.
delete_transient( 'penalis_login_flush_rules' );
delete_transient( 'penalis_login_pending_delete_flag' );

// Drop custom database tables.
// phpcs:disable WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.DirectDatabaseQuery.NoCaching
$wpdb->query( 'DROP TABLE IF EXISTS ' . esc_sql( $wpdb->prefix . 'penalis_login_activity' ) );
$wpdb->query( 'DROP TABLE IF EXISTS ' . esc_sql( $wpdb->prefix . 'penalis_login_ip_rules' ) );
// phpcs:enable

// Flush rewrite rules to remove the custom login rule from the database.
flush_rewrite_rules( true );
