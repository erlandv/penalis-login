<?php
/**
 * Activation and deactivation routines.
 *
 * Rewrite rules are flushed ONLY here — never on every request — to keep
 * the plugin lightweight and avoid unnecessary database writes.
 *
 * @package PenalisLogin
 */

declare(strict_types=1);

namespace PenalisLogin;

/**
 * Class Activator
 *
 * Handles plugin activation and deactivation lifecycle events.
 * All methods are static so they can be referenced directly in
 * register_activation_hook() / register_deactivation_hook() without
 * requiring the Plugin singleton to be fully booted.
 */
final class Activator {

	/**
	 * Runs on plugin activation.
	 *
	 * - Seeds default settings if none exist yet.
	 * - Registers the custom login rewrite rule.
	 * - Flushes rewrite rules so the new rule takes effect immediately.
	 *
	 * @return void
	 */
	public static function activate(): void {
		// Seed default settings on first activation only.
		if ( false === get_option( Helpers::OPTION_KEY ) ) {
			$defaults = [
				'enabled'                 => true,
				'login_slug'              => Helpers::DEFAULT_SLUG,
				'block_behavior'          => '404',
				'wp_admin_guest_behavior' => 'redirect_login',
			];

			add_option( Helpers::OPTION_KEY, $defaults, '', false );
		}

		// Register the rewrite rule so it exists before flushing.
		$helpers = new Helpers();
		RewriteHandler::addRewriteRule( $helpers->getLoginSlug() );

		// Flush rewrite rules (hard flush writes to .htaccess on Apache).
		flush_rewrite_rules( true );
	}

	/**
	 * Runs on plugin deactivation.
	 *
	 * - Removes the custom rewrite rule.
	 * - Flushes rewrite rules to restore default WordPress routing.
	 *
	 * Note: Plugin settings are intentionally preserved on deactivation so
	 * they survive a deactivate → reactivate cycle. Settings are only removed
	 * on full uninstall (see uninstall.php).
	 *
	 * @return void
	 */
	public static function deactivate(): void {
		// Flush rewrite rules to remove the custom login rule.
		flush_rewrite_rules( true );
	}
}
