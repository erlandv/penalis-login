<?php
/**
 * Admin POST action handlers for the activity log.
 *
 * The IP add/delete handlers have been removed — IP lists are now managed
 * via textarea fields that save together with the Protection tab settings.
 *
 * @package PenalisLogin\Admin
 */

declare(strict_types=1);

namespace PenalisLogin\Admin;

use PenalisLogin\Database\ActivityRepository;

/**
 * Class IpRuleActions
 *
 * Registers admin-post.php action handlers for activity log management.
 */
final class IpRuleActions {

	/**
	 * @param ActivityRepository $activityRepo Activity log repository.
	 */
	public function __construct(
		private readonly ActivityRepository $activityRepo
	) {}

	// -------------------------------------------------------------------------
	// Registration
	// -------------------------------------------------------------------------

	/**
	 * Registers all admin-post.php action hooks.
	 *
	 * @return void
	 */
	public function register(): void {
		add_action( 'admin_post_penalis_clear_activity_log', [ $this, 'handleClearActivityLog' ] );
	}

	// -------------------------------------------------------------------------
	// Handlers
	// -------------------------------------------------------------------------

	/**
	 * Handles the "Clear activity log" form submission.
	 *
	 * @return void
	 */
	public function handleClearActivityLog(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to do this.', 'penalis-login' ) );
		}

		check_admin_referer( 'penalis_clear_activity_log', 'penalis_activity_nonce' );

		$this->activityRepo->truncate();

		$this->redirectBack(
			'success',
			__( 'Activity log cleared successfully.', 'penalis-login' ),
			'activity'
		);
	}

	// -------------------------------------------------------------------------
	// Private helpers
	// -------------------------------------------------------------------------

	/**
	 * Redirects back to the settings page with a status message.
	 *
	 * @param  string $status  'success' or 'error'.
	 * @param  string $message The message to display.
	 * @param  string $tab     The tab to return to.
	 * @return never
	 */
	private function redirectBack( string $status, string $message, string $tab = 'protection' ): never {
		$url = add_query_arg(
			[
				'page'            => 'penalis-login-settings',
				'tab'             => $tab,
				'penalis_status'  => $status,
				'penalis_message' => rawurlencode( $message ),
			],
			admin_url( 'options-general.php' )
		);

		wp_safe_redirect( $url );
		exit;
	}
}
