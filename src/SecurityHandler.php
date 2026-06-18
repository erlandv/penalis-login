<?php
/**
 * Security handler.
 *
 * Blocks direct access to wp-login.php and implements the anti-lockout
 * mechanism that keeps logged-in administrators accessible even if the
 * plugin configuration breaks.
 *
 * What we protect
 * ---------------
 * - Direct GET/POST requests to /wp-login.php
 * - Requests with ?action=... appended to wp-login.php
 *
 * What we deliberately do NOT touch
 * ----------------------------------
 * - admin-ajax.php          (AJAX handlers)
 * - admin-post.php          (front-end form/action handlers)
 * - wp-cron.php             (scheduled tasks)
 * - xmlrpc.php              (XML-RPC API)
 * - wp-json/*               (REST API)
 * - Application passwords   (handled by REST API)
 * - WooCommerce auth flows  (use their own endpoints)
 *
 * Anti-lockout mechanism
 * ----------------------
 * If a logged-in administrator visits wp-login.php directly, we allow
 * access rather than blocking them. This prevents a misconfigured slug
 * from permanently locking out the site owner.
 *
 * @package PenalisLogin
 */

declare(strict_types=1);

namespace PenalisLogin;

/**
 * Class SecurityHandler
 *
 * Intercepts requests to wp-login.php and enforces the configured
 * blocking behavior (404, 403, or redirect to homepage).
 */
final class SecurityHandler {

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
	 * We hook into 'init' at priority 1 (very early) so we can intercept
	 * wp-login.php requests before any other plugin processes them.
	 *
	 * @return void
	 */
	public function register(): void {
		add_action( 'init', [ $this, 'blockWpLogin' ], 1 );
		add_action( 'init', [ $this, 'blockWpAdminForGuests' ], 1 );
		add_action( 'template_redirect', [ $this, 'blockCoreLoginShortcut' ], 0 );
	}

	// -------------------------------------------------------------------------
	// Blocking logic
	// -------------------------------------------------------------------------

	/**
	 * Blocks direct access to wp-login.php.
	 *
	 * Runs on 'init' at priority 1. Exits early for all requests that are
	 * not targeting wp-login.php so there is zero overhead on normal pages.
	 *
	 * @return void
	 */
	public function blockWpLogin(): void {
		if ( ! $this->helpers->isWpLoginRequest() ) {
			return;
		}

		// Anti-lockout: allow logged-in administrators through unconditionally.
		// This is the last line of defence against a broken configuration.
		if ( $this->helpers->isLoggedInAdmin() ) {
			return;
		}

		// Allow legitimate WordPress internal requests that use wp-login.php
		// as a pass-through (e.g. WooCommerce, application passwords).
		if ( $this->isAllowedWpLoginAction() ) {
			return;
		}

		// Enforce the configured blocking behavior.
		$this->enforceBlockBehavior();
	}

	/**
	 * Blocks WordPress core's /login/ shortcut when it is not the active slug.
	 *
	 * Core redirects /login/ to wp-login.php via wp_redirect_admin_locations().
	 * Our URL filter then rewrites that destination to the active custom slug,
	 * exposing it when a site previously used "login" and later changed slug.
	 *
	 * @return void
	 */
	public function blockCoreLoginShortcut(): void {
		if ( 'login' === $this->helpers->getLoginSlug() ) {
			return;
		}

		if ( '/login' !== $this->helpers->getCurrentPathRelativeToHome() ) {
			return;
		}

		$this->enforceBlockBehavior();
	}

	/**
	 * Blocks or redirects guest access to /wp-admin/ based on the configured
	 * wp_admin_guest_behavior setting.
	 *
	 * WordPress's default behavior is to redirect unauthenticated /wp-admin/
	 * requests to wp-login.php (via auth_redirect). Our UrlFilter then rewrites
	 * that to the custom login URL — which exposes the slug to anyone watching
	 * the network tab or Location header.
	 *
	 * This method intercepts the request before WordPress's own redirect fires,
	 * giving the admin full control over what guests see.
	 *
	 * Anti-lockout: logged-in administrators are always allowed through,
	 * identical to the wp-login.php protection above.
	 *
	 * @return void
	 */
	public function blockWpAdminForGuests(): void {
		if ( ! $this->helpers->isWpAdminRequest() ) {
			return;
		}

		// Already logged in — let WordPress handle it normally.
		if ( is_user_logged_in() ) {
			return;
		}

		// Anti-lockout: administrators can always get through even if their
		// session just expired and they need to re-authenticate.
		// (is_user_logged_in() already covers this, but kept explicit for clarity.)

		$this->enforceWpAdminGuestBehavior();
	}

	/**
	 * Enforces the configured wp-admin guest behavior and terminates the request.
	 *
	 * @return never
	 */
	private function enforceWpAdminGuestBehavior(): never {
		$behavior = $this->helpers->getWpAdminGuestBehavior();

		switch ( $behavior ) {
			case '403':
				$this->send403();
				break;

			case '404':
				$this->send404();
				break;

			case 'redirect_home':
				$this->redirectHome();
				break;

			case 'redirect_login':
			default:
				// Redirect to the custom login URL, preserving the original
				// destination so the user lands back here after logging in.
				// phpcs:ignore WordPress.Security.ValidatedSanitizedInput
				$requested_url = isset( $_SERVER['REQUEST_URI'] )
					? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) )
					: admin_url();

				nocache_headers();
				wp_safe_redirect(
					$this->helpers->getCustomLoginUrl( $requested_url ),
					302
				);
				exit;
		}
	}

	// -------------------------------------------------------------------------
	// Allowed actions
	// -------------------------------------------------------------------------

	/**
	 * Returns whether the current wp-login.php request uses an action that
	 * must be allowed through for compatibility with core features and
	 * common plugins.
	 *
	 * @return bool
	 */
	private function isAllowedWpLoginAction(): bool {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$action = isset( $_GET['action'] ) ? sanitize_key( $_GET['action'] ) : '';

		/**
		 * Actions that must pass through to wp-login.php for compatibility.
		 *
		 * - postpass       : Password-protected post access.
		 * - logout         : Logout nonce verification (handled by WP core).
		 * - confirm_admin_email : Admin email confirmation prompt.
		 * - confirmaction  : GDPR personal data export/erasure confirmation.
		 *
		 * Note: 'rp' and 'resetpass' are intentionally NOT listed here.
		 * Password reset links carry a ?key= parameter that we validate
		 * against the database in the block below. Allowing them here
		 * (without key validation) would let an attacker pass ?action=rp
		 * without a valid key and still reach wp-login.php.
		 *
		 * Note: We do NOT allow 'login' here because that is the default
		 * action and would defeat the purpose of the plugin.
		 */
		$allowed_actions = [
			'postpass',
			'logout',
			'confirm_admin_email',
			'confirmaction',
		];

		/**
		 * Filters the list of wp-login.php actions that are allowed through
		 * even when the plugin is blocking direct access.
		 *
		 * @param string[] $allowed_actions List of allowed action strings.
		 */
		$allowed_actions = apply_filters( 'penalis_login_allowed_actions', $allowed_actions );

		if ( in_array( $action, $allowed_actions, true ) ) {
			return true;
		}

		// Allow password reset requests that carry a reset key in the URL.
		// These are sent via email and must work regardless of the login slug.
		//
		// Security note: We validate that the key + login pair actually exists
		// in the database before allowing the request through. An invalid or
		// fabricated key must NOT be allowed to pass — doing so would let an
		// attacker probe wp-login.php and trigger WP's own error redirects,
		// which would expose the custom login slug via the wp_redirect filter.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['key'] ) && '' !== $_GET['key'] ) {
			return $this->isValidPasswordResetKey();
		}

		return false;
	}

	// -------------------------------------------------------------------------
	// Password reset key validation
	// -------------------------------------------------------------------------

	/**
	 * Returns whether the current request carries a valid password reset key.
	 *
	 * WordPress password reset links have the form:
	 *   /wp-login.php?action=rp&key=<key>&login=<login>
	 *
	 * We validate the key + login pair against the database before allowing
	 * the request through. This prevents an attacker from passing an arbitrary
	 * ?key= value to bypass the block and then triggering WP's own error
	 * redirect, which would expose the custom login slug.
	 *
	 * Note: check_password_reset_key() is available after 'init' fires, which
	 * is exactly when blockWpLogin() runs, so the call is safe here.
	 *
	 * @return bool True only when the key + login pair is valid in the DB.
	 */
	private function isValidPasswordResetKey(): bool {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		$key   = isset( $_GET['key'] )   ? sanitize_text_field( wp_unslash( $_GET['key'] ) )   : '';
		$login = isset( $_GET['login'] ) ? sanitize_user( wp_unslash( $_GET['login'] ) )        : '';
		// phpcs:enable

		if ( '' === $key || '' === $login ) {
			return false;
		}

		$user = check_password_reset_key( $key, $login );

		return ( $user instanceof \WP_User );
	}

	// -------------------------------------------------------------------------
	// Block behavior enforcement
	// -------------------------------------------------------------------------

	/**
	 * Enforces the configured blocking behavior and terminates the request.
	 *
	 * @return never
	 */
	private function enforceBlockBehavior(): never {
		$behavior = $this->helpers->getBlockBehavior();

		switch ( $behavior ) {
			case '403':
				$this->send403();
				break;

			case 'redirect_home':
				$this->redirectHome();
				break;

			case '404':
			default:
				$this->send404();
				break;
		}
	}

	/**
	 * Sends a proper 404 response and loads the theme's 404 template.
	 *
	 * Using the theme template rather than a plain wp_die() gives a more
	 * natural-looking response that doesn't hint at the existence of a
	 * login page.
	 *
	 * @return never
	 */
	private function send404(): never {
		global $wp_query;

		// Mark the query as a 404 so get_header() and the theme behave correctly.
		if ( isset( $wp_query ) ) {
			$wp_query->set_404();
		}

		status_header( 404 );
		nocache_headers();

		// Attempt to load the theme's 404 template.
		$template = get_404_template();

		if ( $template && file_exists( $template ) ) {
			// phpcs:ignore WordPressVIPMinimum.Files.IncludingFile.UsingVariable
			include $template;
			exit;
		}

		// Fallback: plain 404 response with no body content.
		wp_die(
			'',
			'',
			[ 'response' => 404 ]
		);
	}

	/**
	 * Sends a 403 Forbidden response.
	 *
	 * @return never
	 */
	private function send403(): never {
		status_header( 403 );
		nocache_headers();

		wp_die(
			esc_html__( 'Sorry, you are not allowed to access this page.', 'penalis-login' ),
			esc_html__( 'Forbidden', 'penalis-login' ),
			[ 'response' => 403 ]
		);
	}

	/**
	 * Redirects the visitor to the site homepage.
	 *
	 * @return never
	 */
	private function redirectHome(): never {
		nocache_headers();
		wp_safe_redirect( home_url( '/' ), 302 );
		exit;
	}
}
