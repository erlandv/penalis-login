<?php
/**
 * Activity log pruner.
 *
 * Schedules and runs a daily WordPress cron job that deletes activity log
 * records older than the configured retention period.
 *
 * When retention is set to 0, pruning is disabled and all records are kept.
 *
 * @package PenalisLogin
 */

declare(strict_types=1);

namespace PenalisLogin;

use PenalisLogin\Database\ActivityRepository;

/**
 * Class ActivityPruner
 */
final class ActivityPruner {

	/** WordPress cron hook name. */
	public const CRON_HOOK = 'penalis_login_prune_activity_log';

	/**
	 * @param Helpers            $helpers    Shared helper utilities.
	 * @param ActivityRepository $repository Activity log repository.
	 */
	public function __construct(
		private readonly Helpers $helpers,
		private readonly ActivityRepository $repository
	) {}

	// -------------------------------------------------------------------------
	// Registration
	// -------------------------------------------------------------------------

	/**
	 * Registers the cron hook callback.
	 *
	 * @return void
	 */
	public function register(): void {
		add_action( self::CRON_HOOK, [ $this, 'prune' ] );
	}

	// -------------------------------------------------------------------------
	// Scheduling
	// -------------------------------------------------------------------------

	/**
	 * Schedules the daily pruning cron job if not already scheduled.
	 *
	 * Safe to call on every activation — wp_next_scheduled() prevents
	 * duplicate scheduling.
	 *
	 * @return void
	 */
	public static function schedule(): void {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time(), 'daily', self::CRON_HOOK );
		}
	}

	/**
	 * Unschedules the pruning cron job.
	 *
	 * Called on plugin deactivation.
	 *
	 * @return void
	 */
	public static function unschedule(): void {
		$timestamp = wp_next_scheduled( self::CRON_HOOK );

		if ( false !== $timestamp ) {
			wp_unschedule_event( $timestamp, self::CRON_HOOK );
		}
	}

	// -------------------------------------------------------------------------
	// Pruning
	// -------------------------------------------------------------------------

	/**
	 * Deletes activity log records older than the configured retention period.
	 *
	 * Called by the WordPress cron scheduler once per day.
	 * Does nothing when retention is set to 0 (keep forever).
	 *
	 * @return void
	 */
	public function prune(): void {
		$days = $this->helpers->getLogRetentionDays();

		if ( 0 === $days ) {
			return;
		}

		$this->repository->pruneOlderThan( $days );
	}
}
