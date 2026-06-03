<?php
/**
 * Plugin Name:       Penalis Login
 * Plugin URI:        https://github.com/erlandv/penalis-login
 * Description:       Hides the default WordPress login URL and adds optional security features to protect against brute force attacks.
 * Version:           2.1.2
 * Requires at least: 6.4
 * Requires PHP:      8.1
 * Author:            Penalis
 * Author URI:        https://penalis.com
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       penalis-login
 * Domain Path:       /languages
 *
 * @package PenalisLogin
 */

declare(strict_types=1);

// Prevent direct file access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Minimum PHP version guard — fail gracefully without fatal errors.
if ( version_compare( PHP_VERSION, '8.1', '<' ) ) {
	add_action(
		'admin_notices',
		static function (): void {
			echo '<div class="notice notice-error"><p>'
				. esc_html__( 'Penalis Login requires PHP 8.1 or higher. Please upgrade PHP.', 'penalis-login' )
				. '</p></div>';
		}
	);
	return;
}

// -------------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------------

define( 'PENALIS_LOGIN_VERSION', '2.1.2' );
define( 'PENALIS_LOGIN_FILE', __FILE__ );
define( 'PENALIS_LOGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'PENALIS_LOGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'PENALIS_LOGIN_BASENAME', plugin_basename( __FILE__ ) );

// -------------------------------------------------------------------------
// Autoloader — simple PSR-4-style loader for the src/ directory.
// -------------------------------------------------------------------------

spl_autoload_register(
	static function ( string $class ): void {
		$prefix = 'PenalisLogin\\';
		$len    = strlen( $prefix );

		if ( strncmp( $prefix, $class, $len ) !== 0 ) {
			return;
		}

		$relative = substr( $class, $len );
		$file     = PENALIS_LOGIN_DIR . 'src/' . str_replace( '\\', '/', $relative ) . '.php';

		if ( file_exists( $file ) ) {
			require_once $file;
		}
	}
);

// -------------------------------------------------------------------------
// Activation / Deactivation hooks — registered before Plugin::boot() so
// they fire even if the plugin is not yet fully initialised.
// -------------------------------------------------------------------------

register_activation_hook(
	PENALIS_LOGIN_FILE,
	[ \PenalisLogin\Activator::class, 'activate' ]
);

register_deactivation_hook(
	PENALIS_LOGIN_FILE,
	[ \PenalisLogin\Activator::class, 'deactivate' ]
);

// -------------------------------------------------------------------------
// Boot the plugin.
// -------------------------------------------------------------------------

add_action(
	'plugins_loaded',
	static function (): void {
		\PenalisLogin\Plugin::getInstance()->boot();
	},
	// Priority 1 — run early so URL filters are in place before other plugins
	// generate login/logout links.
	1
);
