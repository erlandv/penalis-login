<?php
/**
 * Activity Log tab.
 *
 * Read-only view of all login activity records. No settings to save here —
 * this tab only displays data from the activity log table.
 *
 * @package PenalisLogin\Admin\Tabs
 */

declare(strict_types=1);

namespace PenalisLogin\Admin\Tabs;

use PenalisLogin\Database\ActivityRepository;
use PenalisLogin\Helpers;

/**
 * Class ActivityTab
 *
 * Renders the Activity Log tab content.
 */
final class ActivityTab {

	/** Number of records to show per page. */
	private const PER_PAGE = 50;

	/**
	 * @param ActivityRepository $repository Activity log repository.
	 * @param Helpers            $helpers    Shared helper utilities (for retention setting).
	 */
	public function __construct(
		private readonly ActivityRepository $repository,
		private readonly Helpers $helpers
	) {}

	// -------------------------------------------------------------------------
	// Render
	// -------------------------------------------------------------------------

	/**
	 * Renders the full activity log tab content.
	 *
	 * @return void
	 */
	public function render(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$current_page    = isset( $_GET['paged'] ) ? max( 1, (int) $_GET['paged'] ) : 1;
		$retention_days  = $this->helpers->getLogRetentionDays();

		$total       = $this->repository->getTotal();
		$records     = $this->repository->getPaginated( self::PER_PAGE, $current_page );
		$total_pages = (int) ceil( $total / self::PER_PAGE );
		?>

		<!-- Activity Records — displayed first, above settings -->
		<h2><?php esc_html_e( 'Activity Records', 'penalis-login' ); ?></h2>
		
		<div class="penalis-activity-header">
			<p class="description">
				<?php
				printf(
					/* translators: %d: total number of records */
					esc_html__( 'Showing login activity. %d total records.', 'penalis-login' ),
					$total
				);
				?>
			</p>

			<?php if ( $total > 0 ) : ?>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline;">
					<?php wp_nonce_field( 'penalis_clear_activity_log', 'penalis_activity_nonce' ); ?>
					<input type="hidden" name="action" value="penalis_clear_activity_log" />
					<button
						type="submit"
						class="button button-secondary penalis-btn-danger"
						onclick="return confirm('<?php echo esc_js( __( 'Clear all activity log records? This cannot be undone.', 'penalis-login' ) ); ?>')"
					>
						<?php esc_html_e( 'Clear Log', 'penalis-login' ); ?>
					</button>
				</form>
			<?php endif; ?>
		</div>

		<?php if ( empty( $records ) ) : ?>
			<div class="penalis-activity-empty">
				<p><?php esc_html_e( 'No login activity recorded yet. Activity will appear here once users start logging in.', 'penalis-login' ); ?></p>
			</div>
		<?php else : ?>
			<table class="widefat striped penalis-activity-table">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Date / Time', 'penalis-login' ); ?></th>
						<th><?php esc_html_e( 'Event', 'penalis-login' ); ?></th>
						<th><?php esc_html_e( 'Username', 'penalis-login' ); ?></th>
						<th><?php esc_html_e( 'IP Address', 'penalis-login' ); ?></th>
						<th><?php esc_html_e( 'User Agent', 'penalis-login' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $records as $record ) : ?>
						<tr class="penalis-activity-row penalis-event-<?php echo esc_attr( $record->event_type ); ?>">
							<td class="penalis-activity-date">
								<?php echo esc_html( $this->formatDate( $record->occurred_at ) ); ?>
							</td>
							<td>
								<span class="penalis-event-badge penalis-event-badge-<?php echo esc_attr( $record->event_type ); ?>">
									<?php echo esc_html( $this->getEventLabel( $record->event_type ) ); ?>
								</span>
							</td>
							<td>
								<?php echo '' !== $record->username ? esc_html( $record->username ) : '<span class="penalis-muted">—</span>'; ?>
							</td>
							<td><code><?php echo esc_html( $record->ip_address ); ?></code></td>
							<td class="penalis-activity-ua">
								<span title="<?php echo esc_attr( $record->user_agent ); ?>">
									<?php echo esc_html( $this->truncateUa( $record->user_agent ) ); ?>
								</span>
							</td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>

			<?php if ( $total_pages > 1 ) : ?>
				<div class="penalis-pagination tablenav">
					<div class="tablenav-pages">
						<?php
						$base_url = add_query_arg(
							[
								'page' => 'penalis-login-settings',
								'tab'  => 'activity',
							],
							admin_url( 'options-general.php' )
						);

						echo wp_kses_post(
							paginate_links(
								[
									'base'      => $base_url . '%_%',
									'format'    => '&paged=%#%',
									'current'   => $current_page,
									'total'     => $total_pages,
									'prev_text' => '&laquo;',
									'next_text' => '&raquo;',
								]
							)
						);
						?>
					</div>
				</div>
			<?php endif; ?>
		<?php endif; ?>
		<?php
	}

	// -------------------------------------------------------------------------
	// Retention settings (rendered below the log table)
	// -------------------------------------------------------------------------

	/**
	 * Renders the Log Settings section with the retention field.
	 *
	 * Called by SettingsPage inside the settings <form>, after render().
	 * Keeping it separate from render() makes the form boundary explicit.
	 *
	 * @return void
	 */
	public function renderRetentionSettings(): void {
		$retention_days = $this->helpers->getLogRetentionDays();
		?>
		<hr class="penalis-section-divider" />
		<h2><?php esc_html_e( 'Log Settings', 'penalis-login' ); ?></h2>
		<table class="form-table" role="presentation"><tbody>
			<tr>
				<th scope="row">
					<label for="penalis_log_retention_days"><?php esc_html_e( 'Log Retention', 'penalis-login' ); ?></label>
				</th>
				<td>
					<input
						type="number"
						id="penalis_log_retention_days"
						name="<?php echo esc_attr( Helpers::OPTION_KEY ); ?>[log_retention_days]"
						value="<?php echo esc_attr( (string) $retention_days ); ?>"
						min="0"
						max="3650"
						class="small-text"
					/>
					<span class="description"><?php esc_html_e( 'days', 'penalis-login' ); ?></span>
					<p class="description">
						<?php esc_html_e( 'Automatically delete activity log records older than this many days. Set to 0 to keep records forever.', 'penalis-login' ); ?>
					</p>
					<p class="description" style="color:#646970;">
						<?php
						if ( 0 === $retention_days ) {
							esc_html_e( 'Auto-pruning is disabled. Records will be kept indefinitely.', 'penalis-login' );
						} else {
							printf(
								/* translators: %d: number of days */
								esc_html__( 'Records older than %d day(s) will be deleted automatically once per day.', 'penalis-login' ),
								$retention_days
							);
						}
						?>
					</p>
				</td>
			</tr>
		</tbody></table>
		<?php
	}

	// -------------------------------------------------------------------------
	// Private helpers
	// -------------------------------------------------------------------------
	/**
	 * Formats a UTC datetime string for display in the site's local timezone.
	 *
	 * @param  string $utc_datetime UTC datetime string (Y-m-d H:i:s).
	 * @return string
	 */
	private function formatDate( string $utc_datetime ): string {
		$timestamp = strtotime( $utc_datetime );

		if ( false === $timestamp ) {
			return $utc_datetime;
		}

		return wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $timestamp );
	}

	/**
	 * Returns a human-readable label for an event type.
	 *
	 * @param  string $event_type The event_type value from the database.
	 * @return string
	 */
	private function getEventLabel( string $event_type ): string {
		return match ( $event_type ) {
			ActivityRepository::EVENT_LOGIN_SUCCESS => __( 'Login Success', 'penalis-login' ),
			ActivityRepository::EVENT_LOGIN_FAILED  => __( 'Login Failed', 'penalis-login' ),
			ActivityRepository::EVENT_LOGIN_BLOCKED => __( 'Blocked (Rate Limit)', 'penalis-login' ),
			ActivityRepository::EVENT_IP_BLOCKED    => __( 'Blocked (IP Rule)', 'penalis-login' ),
			default                                 => ucwords( str_replace( '_', ' ', $event_type ) ),
		};
	}

	/**
	 * Truncates a User-Agent string for display.
	 *
	 * @param  string $ua Full User-Agent string.
	 * @return string
	 */
	private function truncateUa( string $ua ): string {
		if ( mb_strlen( $ua ) <= 60 ) {
			return $ua;
		}

		return mb_substr( $ua, 0, 57 ) . '…';
	}
}
