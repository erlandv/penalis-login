<?php
/**
 * Plugin orchestrator / service container.
 *
 * Bootstraps all plugin components and wires them together.
 *
 * @package PenalisLogin
 */

declare(strict_types=1);

namespace PenalisLogin;

use PenalisLogin\Admin\SettingsPage;
use PenalisLogin\Admin\ActivityLogActions;
use PenalisLogin\Api\LoginSlugEndpoint;
use PenalisLogin\Database\ActivityRepository;
use PenalisLogin\Database\IpRulesRepository;

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

	/** @var Plugin|null */
	private static ?Plugin $instance = null;

	/** @var bool */
	private bool $booted = false;

	private function __construct() {}

	public static function getInstance(): Plugin {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	// -------------------------------------------------------------------------
	// Services
	// -------------------------------------------------------------------------

	private ?Helpers $helpers = null;
	private ActivityRepository $activityRepo;
	private IpRulesRepository $ipRepo;
	private ClientIpResolver $ipResolver;
	private RewriteHandler $rewriteHandler;
	private UrlFilter $urlFilter;
	private SecurityHandler $securityHandler;
	private ActivityLogger $activityLogger;
	private ?LoginAttemptLimiter $attemptLimiter = null;
	private ?LoginNotifier $loginNotifier = null;
	private ?IpAccessControl $ipAccessControl = null;
	private ?SettingsPage $settingsPage = null;
	private LoginSlugEndpoint $loginSlugEndpoint;

	// -------------------------------------------------------------------------
	// Boot
	// -------------------------------------------------------------------------

	/**
	 * Initialises all plugin components.
	 *
	 * @return void
	 */
	public function boot(): void {
		if ( $this->booted ) {
			return;
		}

		$this->booted = true;

		load_plugin_textdomain(
			'penalis-login',
			false,
			dirname( PENALIS_LOGIN_BASENAME ) . '/languages'
		);

		// Shared services — always instantiated.
		$this->helpers      = new Helpers();
		$this->activityRepo = new ActivityRepository();
		$this->ipRepo       = new IpRulesRepository();
		$this->ipResolver   = new ClientIpResolver( $this->helpers );

		// Ensure custom tables exist.
		$this->maybeCreateTables();

		// Activity logger — uses resolveForLogging() (proxy headers acceptable).
		$this->activityLogger = new ActivityLogger( $this->activityRepo, $this->ipResolver );
		$this->activityLogger->register();

		// Admin UI — always loaded so the admin can manage settings even when
		// the plugin's main functionality is disabled.
		if ( is_admin() ) {
			$this->settingsPage = new SettingsPage(
				$this->helpers,
				$this->ipRepo,
				$this->activityRepo
			);
			$this->settingsPage->register();

			// Activity log POST action handler.
			$activityLogActions = new ActivityLogActions( $this->activityRepo );
			$activityLogActions->register();
		}

		// REST endpoint — always registered so Nginx auth_request configs
		// don't break when the plugin is toggled off.
		$this->loginSlugEndpoint = new LoginSlugEndpoint( $this->helpers );
		$this->loginSlugEndpoint->register();

		// Bail out here if the plugin is disabled.
		if ( ! $this->helpers->isPluginEnabled() ) {
			return;
		}

		// Core login URL rewriting.
		$this->rewriteHandler = new RewriteHandler( $this->helpers );
		$this->rewriteHandler->register();

		$this->urlFilter = new UrlFilter( $this->helpers );
		$this->urlFilter->register();

		$this->securityHandler = new SecurityHandler( $this->helpers );
		$this->securityHandler->register();

		// Protection features — only active when individually enabled.
		$this->bootProtectionFeatures();
	}

	/**
	 * Boots the optional protection features based on their individual settings.
	 *
	 * @return void
	 */
	private function bootProtectionFeatures(): void {
		$settings = $this->helpers->getSettings();
		$prot     = array_merge(
			Helpers::getDefaultProtectionSettings(),
			$settings['protection'] ?? []
		);

		// Login Attempt Limiter — uses resolveForSecurity() (REMOTE_ADDR only unless trusted proxy configured).
		if ( ! empty( $prot['attempt_limiter_enabled'] ) ) {
			$this->attemptLimiter = new LoginAttemptLimiter(
				$this->helpers,
				$this->activityRepo,
				$this->activityLogger,
				$this->ipResolver
			);
			$this->attemptLimiter->register();
		}

		// Login Notification.
		if ( ! empty( $prot['notify_enabled'] ) ) {
			$this->loginNotifier = new LoginNotifier( $this->helpers, $this->activityRepo, $this->ipResolver );
			$this->loginNotifier->register();
		}

		// IP Access Control — uses resolveForSecurity().
		if ( ! empty( $prot['ip_access_enabled'] ) ) {
			$this->ipAccessControl = new IpAccessControl(
				$this->helpers,
				$this->ipRepo,
				$this->activityLogger,
				$this->ipResolver
			);
			$this->ipAccessControl->register();
		}
	}

	// -------------------------------------------------------------------------
	// Accessors
	// -------------------------------------------------------------------------

	/**
	 * @return Helpers
	 * @throws \LogicException If called before boot().
	 */
	public function getHelpers(): Helpers {
		if ( null === $this->helpers ) {
			throw new \LogicException( 'Plugin::getHelpers() called before boot().' );
		}

		return $this->helpers;
	}

	// -------------------------------------------------------------------------
	// Table creation guard
	// -------------------------------------------------------------------------

	/** Option key that stores the installed DB schema version. */
	private const DB_VERSION_OPTION = 'penalis_login_db_version';

	/** Current schema version — bump this when table structure changes. */
	private const DB_VERSION = '1.0';

	/**
	 * Creates the custom tables if they are missing or the schema version
	 * option is absent (e.g. after a plugin update that added new tables).
	 *
	 * Uses a lightweight option check so dbDelta() is NOT called on every
	 * request — only when the version is missing or outdated.
	 *
	 * @return void
	 */
	private function maybeCreateTables(): void {
		if ( get_option( self::DB_VERSION_OPTION ) === self::DB_VERSION ) {
			return;
		}

		\PenalisLogin\Database\Schema::createTables();
		update_option( self::DB_VERSION_OPTION, self::DB_VERSION, false );
	}
}
