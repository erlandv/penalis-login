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
 * defined in penalis-login.php. All option keys are therefore hardcoded here
 * rather than referenced via class constants.
 *
 * @package PenalisLogin
 */

declare(strict_types=1);

// WordPress sets this constant before calling uninstall.php.
// If it's not set, someone is trying to run this file directly — bail out.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

// Only delete data if the user explicitly opted in.
// The flag is stored as a separate option (not inside the main settings array)
// so we can read it here without loading the plugin's autoloader.
$delete_on_uninstall = (bool) get_option( 'penalis_login_delete_on_uninstall', false );

if ( ! $delete_on_uninstall ) {
	return;
}

// Remove the plugin settings option.
delete_option( 'penalis_login_settings' );

// Remove the uninstall preference option itself.
delete_option( 'penalis_login_delete_on_uninstall' );

// Remove any transients created by the plugin.
delete_transient( 'penalis_login_flush_rules' );

// Flush rewrite rules to remove the custom login rule from the database.
flush_rewrite_rules( true );
