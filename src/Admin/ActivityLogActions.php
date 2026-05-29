<?php
/**
 * Admin POST action handler for the activity log.
 *
 * @package PenalisLogin\Admin
 */

declare(strict_types=1);

namespace PenalisLogin\Admin;

use PenalisLogin\Database\ActivityRepository;

/**
 * Class ActivityLogActions
 *
 * Handles the "Clear activity log" admin-post.php action.
 */
final class ActivityLogActions {

	public function __construct(
		private readonly ActivityRepository $activityRepo
	) {}

	public function register(): void {
		add_action( 'admin_post_penalis_clear_activity_log', [ $this, 'handleClearActivityLog' ] );
	}

	public function handleClearActivityLog(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to do this.', 'penalis-login' ) );
		}

		check_admin_referer( 'penalis_clear_activity_log', 'penalis_activity_nonce' );

		$this->activityRepo->truncate();

		wp_safe_redirect( add_query_arg(
			[
				'page'            => \PenalisLogin\Admin\SettingsPage::PAGE_SLUG,
				'tab'             => 'activity',
				'penalis_status'  => 'success',
				'penalis_message' => rawurlencode( __( 'Activity log cleared successfully.', 'penalis-login' ) ),
			],
			admin_url( 'options-general.php' )
		) );
		exit;
	}
}
