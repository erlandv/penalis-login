<?php
/**
 * Plugin orchestrator / service container.
 *
 * Bootstraps all plugin components and wires them together.
 * Uses the singleton pattern so the same instance is reused across the
 * request lifecycle without polluting global scope.
 *
 * @package PenalisLogin
 */

declare(strict_types=1);

namespace PenalisLogin;

use PenalisLogin\Admin\SettingsPage;
use PenalisLogin\Api\LoginSlugEndpoint;

/**
 * Class Plugin
 *
 * Central service container. Instantiates and registers all plugin
 * components. Call Plugin::getInstance()->boot() once on plugins_loaded.
 */
final class Plugin {

	// -------------------------------------------------------------------------
	// Singleton
	// -------------------------------------------------------------------------

	/** @var Plugin|null Singleton instance. */
	private static ?Plugin $instance = null;

	/** @var bool Whether boot() has already run. */
	private bool $booted = false;

	/**
	 * Private constructor — use getInstance().
	 */
	private function __construct() {}

	/**
	 * Returns the singleton instance.
	 *
	 * @return Plugin
	 */
	public static function getInstance(): Plugin {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	// -------------------------------------------------------------------------
	// Services
	// -------------------------------------------------------------------------

	/** @var Helpers|null Shared helper utilities. */
	private ?Helpers $helpers = null;

	/** @var RewriteHandler Rewrite rule manager. */
	private RewriteHandler $rewriteHandler;

	/** @var UrlFilter URL filter manager. */
	private UrlFilter $urlFilter;

	/** @var SecurityHandler Security / blocking handler. */
	private SecurityHandler $securityHandler;

	/** @var SettingsPage|null Admin settings page (admin-only). */
	private ?SettingsPage $settingsPage = null;

	/** @var LoginSlugEndpoint REST endpoint for Nginx auth_request integration. */
	private LoginSlugEndpoint $loginSlugEndpoint;

	// -------------------------------------------------------------------------
	// Boot
	// -------------------------------------------------------------------------

	/**
	 * Initialises all plugin components.
	 *
	 * Safe to call multiple times — subsequent calls are no-ops.
	 *
	 * @return void
	 */
	public function boot(): void {
		if ( $this->booted ) {
			return;
		}

		$this->booted = true;

		// Load text domain for i18n.
		load_plugin_textdomain(
			'penalis-login',
			false,
			dirname( PENALIS_LOGIN_BASENAME ) . '/languages'
		);

		// Instantiate shared helpers first — other classes depend on it.
		$this->helpers = new Helpers();

		// If the plugin is disabled via settings, bail out early.
		// We still load the settings page so the admin can re-enable it.
		if ( is_admin() ) {
			$this->settingsPage = new SettingsPage( $this->helpers );
			$this->settingsPage->register();
		}

		// REST endpoint — answers Nginx auth_request subrequests so Nginx
		// always knows the current login slug without manual config updates.
		// Registered unconditionally (even when the plugin is disabled) so
		// Nginx auth_request configs don't silently break when the plugin is
		// toggled off. The endpoint is passive and only responds when called.
		$this->loginSlugEndpoint = new LoginSlugEndpoint( $this->helpers );
		$this->loginSlugEndpoint->register();

		if ( ! $this->helpers->isPluginEnabled() ) {
			return;
		}

		// Rewrite handler — manages custom login slug rewrite rules.
		$this->rewriteHandler = new RewriteHandler( $this->helpers );
		$this->rewriteHandler->register();

		// URL filter — replaces all wp-login.php references in generated URLs.
		$this->urlFilter = new UrlFilter( $this->helpers );
		$this->urlFilter->register();

		// Security handler — blocks direct access to wp-login.php.
		$this->securityHandler = new SecurityHandler( $this->helpers );
		$this->securityHandler->register();
	}

	// -------------------------------------------------------------------------
	// Accessors (used by other classes / tests)
	// -------------------------------------------------------------------------

	/**
	 * Returns the Helpers instance.
	 *
	 * @return Helpers
	 * @throws \LogicException If called before boot() has been run.
	 */
	public function getHelpers(): Helpers {
		if ( null === $this->helpers ) {
			throw new \LogicException( 'Plugin::getHelpers() called before boot(). Call Plugin::getInstance()->boot() first.' );
		}

		return $this->helpers;
	}
}
