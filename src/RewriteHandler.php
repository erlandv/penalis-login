<?php
/**
 * Rewrite rule manager.
 *
 * Registers a custom rewrite rule that maps the chosen login slug to the
 * native wp-login.php handler. WordPress core continues to process the
 * login form — we only change the public-facing URL.
 *
 * Architectural note
 * ------------------
 * We use a rewrite rule + query var approach rather than intercepting the
 * request in template_redirect. This keeps us inside WordPress's normal
 * routing pipeline and avoids output-buffering hacks.
 *
 * @package PenalisLogin
 */

declare(strict_types=1);

namespace PenalisLogin;

/**
 * Class RewriteHandler
 *
 * Manages the custom login slug rewrite rule and the query var that signals
 * WordPress to serve the login page.
 */
final class RewriteHandler {

	/** Query var name used to identify a custom login request. */
	public const QUERY_VAR = 'penalis_login';

	/**
	 * @param Helpers $helpers Shared helper utilities.
	 */
	public function __construct( private readonly Helpers $helpers ) {}

	// -------------------------------------------------------------------------
	// Registration
	// -------------------------------------------------------------------------

	/**
	 * Registers all WordPress hooks managed by this class.
	 *
	 * @return void
	 */
	public function register(): void {
		// Add the rewrite rule on init so it is available for every request.
		add_action( 'init', [ $this, 'addRule' ] );

		// Flush rewrite rules if the slug changed (runs after addRule so the
		// new rule is already registered before flushing).
		add_action( 'init', [ $this, 'maybeFlushRules' ], 20 );

		// Register our custom query var so WP_Query doesn't strip it.
		add_filter( 'query_vars', [ $this, 'addQueryVar' ] );

		// Intercept the request when our query var is present.
		add_action( 'template_redirect', [ $this, 'handleLoginRequest' ], 1 );

		// When the slug changes in settings, re-register the rule and schedule
		// a rewrite flush for the next request (avoids flushing mid-request).
		add_action( 'update_option_' . Helpers::OPTION_KEY, [ $this, 'onSettingsUpdate' ], 10, 2 );
	}

	// -------------------------------------------------------------------------
	// Rewrite rule
	// -------------------------------------------------------------------------

	/**
	 * Adds the custom login rewrite rule.
	 *
	 * Called on the 'init' hook so the rule is registered for every request.
	 * Actual flushing only happens on activation/deactivation or when the
	 * slug changes.
	 *
	 * @return void
	 */
	public function addRule(): void {
		self::addRewriteRule( $this->helpers->getLoginSlug() );
	}

	/**
	 * Static helper that adds the rewrite rule for a given slug.
	 *
	 * Extracted as a static method so Activator can call it without
	 * instantiating the full class.
	 *
	 * @param  string $slug The custom login slug (already sanitized).
	 * @return void
	 */
	public static function addRewriteRule( string $slug ): void {
		if ( '' === $slug ) {
			return;
		}

		// Match both trailing-slash and non-trailing-slash variants.
		add_rewrite_rule(
			'^' . preg_quote( $slug, '#' ) . '/?$',
			'index.php?' . self::QUERY_VAR . '=1',
			'top' // Must be 'top' so it takes priority over page/post rules.
		);
	}

	/**
	 * Registers the custom query var with WordPress.
	 *
	 * @param  string[] $vars Existing public query vars.
	 * @return string[]
	 */
	public function addQueryVar( array $vars ): array {
		$vars[] = self::QUERY_VAR;

		return $vars;
	}

	// -------------------------------------------------------------------------
	// Request handling
	// -------------------------------------------------------------------------

	/**
	 * Handles a request that matched the custom login rewrite rule.
	 *
	 * Passes the request through to wp-login.php by including it directly.
	 * This keeps all WordPress authentication logic intact without any
	 * output-buffering tricks.
	 *
	 * @return void
	 */
	public function handleLoginRequest(): void {
		if ( ! get_query_var( self::QUERY_VAR ) ) {
			return;
		}

		// Prevent WordPress from serving a 404 for this virtual URL.
		global $wp_query;
		$wp_query->is_404 = false;

		// Include wp-login.php directly. WordPress will handle the rest.
		// We set WPINC so the include works from any directory context.
		$login_file = ABSPATH . 'wp-login.php';

		if ( file_exists( $login_file ) ) {
			// phpcs:ignore WordPressVIPMinimum.Files.IncludingFile.UsingVariable
			require_once $login_file;
			exit;
		}
	}

	// -------------------------------------------------------------------------
	// Settings change handler
	// -------------------------------------------------------------------------

	/**
	 * Fires when the plugin settings option is updated.
	 *
	 * Schedules a rewrite flush for the next request by setting a transient.
	 * The actual flush happens in addRule() on the following init.
	 *
	 * @param  mixed $old_value Previous option value.
	 * @param  mixed $new_value New option value.
	 * @return void
	 */
	public function onSettingsUpdate( mixed $old_value, mixed $new_value ): void {
		$old_slug = is_array( $old_value ) ? ( $old_value['login_slug'] ?? '' ) : '';
		$new_slug = is_array( $new_value ) ? ( $new_value['login_slug'] ?? '' ) : '';

		if ( $old_slug !== $new_slug ) {
			// Flag that rewrite rules need flushing on the next request.
			set_transient( 'penalis_login_flush_rules', true, 60 );
		}
	}

	/**
	 * Flushes rewrite rules if the transient flag is set.
	 *
	 * Hooked to 'init' at a later priority than addRule() so the new rule
	 * is already registered before flushing.
	 *
	 * @return void
	 */
	public function maybeFlushRules(): void {
		if ( get_transient( 'penalis_login_flush_rules' ) ) {
			delete_transient( 'penalis_login_flush_rules' );
			flush_rewrite_rules( false );
		}
	}
}
