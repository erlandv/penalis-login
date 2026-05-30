<?php
/**
 * Admin settings page — tab orchestrator.
 *
 * Uses admin-post.php for form submission instead of options.php to avoid
 * WordPress Settings API multi-tab redirect issues.
 *
 * @package PenalisLogin\Admin
 */

declare(strict_types=1);

namespace PenalisLogin\Admin;

use PenalisLogin\Helpers;
use PenalisLogin\Database\IpRulesRepository;
use PenalisLogin\Database\ActivityRepository;
use PenalisLogin\Admin\Tabs\GeneralTab;
use PenalisLogin\Admin\Tabs\ProtectionTab;
use PenalisLogin\Admin\Tabs\ActivityTab;

/**
 * Class SettingsPage
 */
final class SettingsPage {

	public const PAGE_SLUG = 'penalis-login-settings';

	private const NONCE_ACTION = 'penalis_login_save_settings';
	private const NONCE_FIELD  = 'penalis_login_nonce';
	private const TABS         = [ 'general', 'protection', 'activity' ];

	private GeneralTab $generalTab;
	private ProtectionTab $protectionTab;
	private ActivityTab $activityTab;

	public function __construct(
		private readonly Helpers $helpers,
		private readonly IpRulesRepository $ipRepo,
		private readonly ActivityRepository $activityRepo
	) {
		$this->generalTab    = new GeneralTab( $this->helpers );
		$this->protectionTab = new ProtectionTab( $this->helpers, $this->ipRepo );
		$this->activityTab   = new ActivityTab( $this->activityRepo, $this->helpers );
	}

	public function register(): void {
		add_action( 'admin_menu',            [ $this, 'addMenuPage' ] );
		add_action( 'admin_enqueue_scripts', [ $this, 'enqueueAssets' ] );
		add_action( 'admin_post_penalis_login_save', [ $this, 'handleSave' ] );
		add_filter( 'plugin_action_links_' . PENALIS_LOGIN_BASENAME, [ $this, 'addPluginActionLinks' ] );
	}

	public function addMenuPage(): void {
		add_options_page(
			__( 'Penalis Login Settings', 'penalis-login' ),
			__( 'Penalis Login', 'penalis-login' ),
			'manage_options',
			self::PAGE_SLUG,
			[ $this, 'renderPage' ]
		);
	}

	// -------------------------------------------------------------------------
	// Form save handler (replaces options.php)
	// -------------------------------------------------------------------------

	/**
	 * Handles the settings form POST via admin-post.php.
	 *
	 * @return never
	 */
	public function handleSave(): never {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to do this.', 'penalis-login' ) );
		}

		check_admin_referer( self::NONCE_ACTION, self::NONCE_FIELD );

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$input = isset( $_POST[ Helpers::OPTION_KEY ] ) && is_array( $_POST[ Helpers::OPTION_KEY ] )
			? wp_unslash( $_POST[ Helpers::OPTION_KEY ] )
			: [];

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$tab = isset( $_POST['_tab'] ) ? sanitize_key( $_POST['_tab'] ) : 'general';
		$tab = in_array( $tab, self::TABS, true ) ? $tab : 'general';

		[ $sanitized, $errors ] = $this->sanitizeSettings( $input, $tab );

		// Merge with existing settings so saving one tab doesn't wipe the other.
		$existing = get_option( Helpers::OPTION_KEY, [] );
		if ( ! is_array( $existing ) ) {
			$existing = [];
		}

		if ( 'general' === $tab ) {
			$merged = array_merge( $existing, $sanitized );
			$merged['protection']         = $existing['protection'] ?? Helpers::getDefaultProtectionSettings();
			$merged['log_retention_days'] = $existing['log_retention_days'] ?? 30;
		} elseif ( 'activity' === $tab ) {
			$merged                       = $existing;
			$merged['log_retention_days'] = $sanitized['log_retention_days'];
		} else {
			// Protection tab.
			$merged               = $existing;
			$merged['protection'] = $sanitized['protection'];

			if ( ! isset( $input['_reset'] ) || '1' !== (string) $input['_reset'] ) {
				$this->syncIpListsFromPost();
			}
		}

		update_option( Helpers::OPTION_KEY, $merged, false );
		$this->helpers->invalidateCache();
		set_transient( 'penalis_login_flush_rules', true, 60 );

		// Store result in a transient so it survives the redirect.
		set_transient( 'penalis_login_save_result', [ 'errors' => $errors ], 60 );

		wp_safe_redirect( $this->tabUrl( $tab ) );
		exit;
	}


	// -------------------------------------------------------------------------
	// Sanitization
	// -------------------------------------------------------------------------

	/**
	 * Parses the IP textarea fields from $_POST and syncs them to the DB.
	 *
	 * Each textarea contains one IP address per line. Lines that are empty
	 * or contain invalid IPs are silently skipped.
	 *
	 * @return void
	 */
	private function syncIpListsFromPost(): void {
		// phpcs:disable WordPress.Security.NonceVerification.Missing
		$raw_blocklist = isset( $_POST['penalis_ip_blocklist'] )
			? sanitize_textarea_field( wp_unslash( $_POST['penalis_ip_blocklist'] ) )
			: '';

		$raw_allowlist = isset( $_POST['penalis_ip_allowlist'] )
			? sanitize_textarea_field( wp_unslash( $_POST['penalis_ip_allowlist'] ) )
			: '';
		// phpcs:enable

		$this->ipRepo->sync(
			\PenalisLogin\Database\IpRulesRepository::TYPE_BLOCK,
			$this->parseIpTextarea( $raw_blocklist )
		);

		$this->ipRepo->sync(
			\PenalisLogin\Database\IpRulesRepository::TYPE_ALLOW,
			$this->parseIpTextarea( $raw_allowlist )
		);	}

	/**
	 * Parses a textarea value into an array of [ip => comment] pairs.
	 *
	 * - Splits on newlines.
	 * - Trims whitespace from each line.
	 * - Skips empty lines and lines starting with '#'.
	 * - Extracts inline comment after '#' as the label.
	 * - Skips lines whose IP portion is not a valid IPv4/IPv6 address.
	 *
	 * Returns an associative array: [ 'ip_address' => 'comment' ]
	 *
	 * @param  string $raw Raw textarea content.
	 * @return array<string, string>
	 */
	private function parseIpTextarea( string $raw ): array {
		$lines  = preg_split( '/\r\n|\r|\n/', $raw ) ?: [];
		$result = [];

		foreach ( $lines as $line ) {
			$line = trim( $line );

			// Skip empty lines and full-line comments.
			if ( '' === $line || str_starts_with( $line, '#' ) ) {
				continue;
			}

			$comment = '';

			// Split on '#' to separate IP from inline comment.
			if ( str_contains( $line, '#' ) ) {
				[ $ip_part, $comment_part ] = explode( '#', $line, 2 );
				$line    = trim( $ip_part );
				$comment = trim( $comment_part );
			}

			if ( '' !== $line && filter_var( $line, FILTER_VALIDATE_IP ) ) {
				$result[ $line ] = $comment;
			}
		}

		return $result;
	}

	/**
	 * Sanitizes the submitted settings for the given tab.
	 *
	 * Returns [sanitized_array, errors_array].
	 *
	 * @param  array<string,mixed> $input Raw POST input.
	 * @param  string              $tab   Active tab.
	 * @return array{0: array<string,mixed>, 1: string[]}
	 */
	private function sanitizeSettings( array $input, string $tab ): array {
		$errors = [];

		// ---- Reset to defaults ---------------------------------------------
		if ( isset( $input['_reset'] ) && '1' === (string) $input['_reset'] ) {
			if ( 'general' === $tab ) {
				update_option( Helpers::DELETE_ON_UNINSTALL_KEY, false, false );
				return [ Helpers::getDefaultSettings(), [] ];
			}

			// Protection tab reset: also wipe IP lists from DB.
			$this->ipRepo->sync( \PenalisLogin\Database\IpRulesRepository::TYPE_BLOCK, [] );
			$this->ipRepo->sync( \PenalisLogin\Database\IpRulesRepository::TYPE_ALLOW, [] );

			return [ [ 'protection' => Helpers::getDefaultProtectionSettings() ], [] ];
		}

		if ( 'general' === $tab ) {
			return $this->sanitizeGeneralTab( $input );
		}

		if ( 'activity' === $tab ) {
			return $this->sanitizeActivityTab( $input );
		}
		return $this->sanitizeProtectionTab( $input );
	}

	/**
	 * @param  array<string,mixed> $input
	 * @return array{0: array<string,mixed>, 1: string[]}
	 */
	private function sanitizeGeneralTab( array $input ): array {
		$errors = [];
		$output = [];

		$output['enabled'] = $this->checkboxValue( $input, 'enabled' );

		// Slug.
		$raw_slug   = isset( $input['login_slug'] ) ? (string) $input['login_slug'] : '';
		$slug_error = $this->validateSlug( $raw_slug );
		if ( null !== $slug_error ) {
			$errors[]             = $slug_error;
			$output['login_slug'] = $this->helpers->getLoginSlug();
		} else {
			$output['login_slug'] = $this->helpers->normalizeSlug( $raw_slug );
		}

		// Block behavior.
		$allowed                  = [ '404', '403', 'redirect_home' ];
		$raw                      = isset( $input['block_behavior'] ) ? (string) $input['block_behavior'] : '404';
		$output['block_behavior'] = in_array( $raw, $allowed, true ) ? $raw : '404';

		// wp-admin guest behavior.
		$allowed_wp               = [ 'redirect_login', 'redirect_home', '404', '403' ];
		$raw_wp                   = isset( $input['wp_admin_guest_behavior'] ) ? (string) $input['wp_admin_guest_behavior'] : 'redirect_login';
		$output['wp_admin_guest_behavior'] = in_array( $raw_wp, $allowed_wp, true ) ? $raw_wp : 'redirect_login';

		// Delete on uninstall.
		$delete = $this->checkboxValue( $input, 'delete_on_uninstall' );
		update_option( Helpers::DELETE_ON_UNINSTALL_KEY, $delete, false );

		return [ $output, $errors ];
	}

	/**
	 * @param  array<string,mixed> $input
	 * @return array{0: array<string,mixed>, 1: string[]}
	 */
	private function sanitizeProtectionTab( array $input ): array {
		$defaults = Helpers::getDefaultProtectionSettings();
		$raw      = is_array( $input['protection'] ?? null ) ? $input['protection'] : [];

		$protection = [
			'attempt_limiter_enabled' => $this->checkboxValue( $raw, 'attempt_limiter_enabled' ),
			'max_attempts'            => min( 100, max( 1, (int) ( $raw['max_attempts']    ?? $defaults['max_attempts'] ) ) ),
			'window_minutes'          => min( 1440, max( 1, (int) ( $raw['window_minutes'] ?? $defaults['window_minutes'] ) ) ),
			'lockout_minutes'         => min( 10080, max( 1, (int) ( $raw['lockout_minutes'] ?? $defaults['lockout_minutes'] ) ) ),
			'notify_enabled'          => $this->checkboxValue( $raw, 'notify_enabled' ),
			'notify_email'            => sanitize_email( (string) ( $raw['notify_email'] ?? '' ) ),
			'notify_threshold'        => min( 100, max( 1, (int) ( $raw['notify_threshold'] ?? $defaults['notify_threshold'] ) ) ),
			'ip_access_enabled'       => $this->checkboxValue( $raw, 'ip_access_enabled' ),
			'ip_mode'                 => in_array( $raw['ip_mode'] ?? '', [ 'blocklist', 'allowlist' ], true )
				? (string) $raw['ip_mode']
				: 'blocklist',
			'trusted_proxies_enabled' => $this->checkboxValue( $raw, 'trusted_proxies_enabled' ),
			'trusted_proxies'         => sanitize_textarea_field( (string) ( $raw['trusted_proxies'] ?? '' ) ),
		];

		return [ [ 'protection' => $protection ], [] ];
	}


	// -------------------------------------------------------------------------
	// Slug validation
	// -------------------------------------------------------------------------

	/**
	 * @param  array<string,mixed> $input
	 * @return array{0: array<string,mixed>, 1: string[]}
	 */
	private function sanitizeActivityTab( array $input ): array {
		$days = isset( $input['log_retention_days'] )
			? min( 3650, max( 0, (int) $input['log_retention_days'] ) )
			: 30;

		return [ [ 'log_retention_days' => $days ], [] ];
	}
	private function validateSlug( string $raw_slug ): ?string {
		$slug = $this->helpers->normalizeSlug( $raw_slug );

		if ( '' === $slug ) {
			return sprintf(
				esc_html__( 'The login slug cannot be empty. The previous slug has been kept.', 'penalis-login' )
			);
		}

		if ( $this->helpers->isReservedSlug( $slug ) ) {
			return sprintf(
				esc_html__( '"%s" is a reserved WordPress slug and cannot be used. The previous slug has been kept.', 'penalis-login' ),
				esc_html( $slug )
			);
		}

		$conflict = $this->findSlugConflict( $slug );
		if ( null !== $conflict ) {
			return sprintf(
				esc_html__( '"%1$s" is already used by the %2$s "%3$s". The previous slug has been kept.', 'penalis-login' ),
				esc_html( $slug ),
				esc_html( $conflict['type_label'] ),
				esc_html( $conflict['post_title'] )
			);
		}

		return null;
	}

	/** @return array{post_title: string, type_label: string}|null */
	private function findSlugConflict( string $slug ): ?array {
		foreach ( get_post_types( [ 'public' => true ], 'objects' ) as $post_type_obj ) {
			$post = get_page_by_path( $slug, OBJECT, $post_type_obj->name );
			if ( $post && 'publish' === $post->post_status ) {
				return [
					'post_title' => $post->post_title,
					'type_label' => $post_type_obj->labels->singular_name,
				];
			}
		}
		return null;
	}


	// -------------------------------------------------------------------------
	// Page renderer
	// -------------------------------------------------------------------------

	public function renderPage(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have sufficient permissions to access this page.', 'penalis-login' ) );
		}

		$active_tab = $this->getActiveTab();
		?>
		<div class="wrap penalis-login-settings">
			<h1 class="penalis-login-title"><?php esc_html_e( 'Penalis Login', 'penalis-login' ); ?></h1>
			<div id="penalis-login-notices">
				<?php $this->renderNotices(); ?>
			</div>
			<?php $this->renderTabNav( $active_tab ); ?>
			<div class="penalis-tab-content">
				<?php $this->renderTabContent( $active_tab ); ?>
			</div>
		</div>
		<?php
	}

	/**
	 * Renders save result and IP action notices.
	 */
	private function renderNotices(): void {
		$save_result = get_transient( 'penalis_login_save_result' );
		if ( false !== $save_result ) {
			delete_transient( 'penalis_login_save_result' );
			$this->renderSaveNotices( $save_result );
		}

		$this->renderIpActionNotice();
	}

	/**
	 * Renders the tab navigation bar.
	 */
	private function renderTabNav( string $active_tab ): void {
		$tabs = [
			'general'    => __( 'General', 'penalis-login' ),
			'protection' => __( 'Protection', 'penalis-login' ),
			'activity'   => __( 'Activity Log', 'penalis-login' ),
		];
		?>
		<nav class="nav-tab-wrapper penalis-tab-nav" aria-label="<?php esc_attr_e( 'Settings tabs', 'penalis-login' ); ?>">
			<?php foreach ( $tabs as $slug => $label ) : ?>
				<a href="<?php echo esc_url( $this->tabUrl( $slug ) ); ?>" class="nav-tab <?php echo $slug === $active_tab ? 'nav-tab-active' : ''; ?>">
					<?php echo esc_html( $label ); ?>
				</a>
			<?php endforeach; ?>
		</nav>
		<?php
	}

	/**
	 * Renders the content area for the active tab.
	 */
	private function renderTabContent( string $active_tab ): void {
		if ( 'activity' === $active_tab ) {
			?>
			<div class="penalis-login-body penalis-activity-body">
				<div class="penalis-login-main">

					<?php
					// The activity header (record count + Clear Log button) and the
					// log table are rendered OUTSIDE the settings form because
					// renderClearLogForm() contains its own <form> for the clear action.
					// HTML forbids nested forms — the Clear Log form must be standalone.
					$this->activityTab->renderHeader();
					$this->activityTab->render();

					// Settings form — only contains the retention field and Save button.
					?>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
						<input type="hidden" name="action" value="penalis_login_save" />
						<input type="hidden" name="_tab" value="activity" />
						<?php wp_nonce_field( self::NONCE_ACTION, self::NONCE_FIELD ); ?>
						<?php $this->activityTab->renderRetentionSettings(); ?>
						<div class="penalis-form-actions">
							<?php submit_button( __( 'Save Settings', 'penalis-login' ), 'primary', 'submit', false ); ?>
						</div>
					</form>

				</div>
			</div>
			<?php
			return;
		}

		$reset_confirm = 'general' === $active_tab
			? __( 'Reset all settings to their defaults? This cannot be undone.', 'penalis-login' )
			: __( 'Reset all Protection settings to their defaults and clear all IP lists? This cannot be undone.', 'penalis-login' );
		?>
		<div class="penalis-login-body">
			<div class="penalis-login-main">
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
					<input type="hidden" name="action" value="penalis_login_save" />
					<input type="hidden" name="_tab" value="<?php echo esc_attr( $active_tab ); ?>" />
					<?php wp_nonce_field( self::NONCE_ACTION, self::NONCE_FIELD ); ?>

					<?php if ( 'general' === $active_tab ) : ?>
						<?php $this->generalTab->renderFields(); ?>
					<?php else : ?>
						<?php $this->protectionTab->renderFields(); ?>
						<?php $this->protectionTab->renderIpSection(); ?>
					<?php endif; ?>

					<div class="penalis-form-actions">
						<?php submit_button( __( 'Save Settings', 'penalis-login' ), 'primary', 'submit', false ); ?>
						<button
							type="submit"
							name="<?php echo esc_attr( Helpers::OPTION_KEY ); ?>[_reset]"
							value="1"
							class="button button-secondary penalis-reset-button"
							onclick="return confirm('<?php echo esc_js( $reset_confirm ); ?>')"
						><?php esc_html_e( 'Reset to Defaults', 'penalis-login' ); ?></button>
					</div>
				</form>
			</div>
			<div class="penalis-login-sidebar">
				<?php $this->renderSidebar( $active_tab ); ?>
			</div>
		</div>
		<?php
	}	// -------------------------------------------------------------------------
	// Notices
	// -------------------------------------------------------------------------

	/** @param array<string,mixed>|false $save_result */
	private function renderSaveNotices( $save_result ): void {
		if ( false === $save_result ) {
			return;
		}

		$errors = $save_result['errors'] ?? [];

		if ( ! empty( $errors ) ) {
			foreach ( $errors as $error ) {
				printf(
					'<div class="notice notice-error is-dismissible"><p>%s</p></div>',
					esc_html( $error )
				);
			}
			return;
		}

		printf(
			'<div class="notice notice-success is-dismissible"><p>%s</p></div>',
			esc_html__( 'Settings saved.', 'penalis-login' )
		);
	}

	public function renderIpActionNotice(): void {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! isset( $_GET['page'] ) || self::PAGE_SLUG !== $_GET['page'] ) {
			return;
		}

		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		$status  = isset( $_GET['penalis_status'] )  ? sanitize_key( $_GET['penalis_status'] ) : '';
		$message = isset( $_GET['penalis_message'] ) ? sanitize_text_field( wp_unslash( rawurldecode( $_GET['penalis_message'] ) ) ) : '';
		// phpcs:enable

		if ( '' === $status || '' === $message ) {
			return;
		}

		$class = 'success' === $status ? 'notice-success' : 'notice-error';
		printf(
			'<div class="notice %s is-dismissible"><p>%s</p></div>',
			esc_attr( $class ),
			esc_html( $message )
		);
	}


	// -------------------------------------------------------------------------
	// Sidebar
	// -------------------------------------------------------------------------

	private function renderSidebar( string $tab ): void {
		$prot = $this->helpers->getProtectionSettings();
		?>
		<div class="penalis-login-info-box">
			<h3><?php esc_html_e( 'Current Status', 'penalis-login' ); ?></h3>
			<table class="widefat striped">
				<tbody>
					<tr>
						<td><strong><?php esc_html_e( 'Plugin Status', 'penalis-login' ); ?></strong></td>
						<td>
							<?php if ( $this->helpers->isPluginEnabled() ) : ?>
								<span class="penalis-status-active">&#10003; <?php esc_html_e( 'Active', 'penalis-login' ); ?></span>
							<?php else : ?>
								<span class="penalis-status-inactive">&#10007; <?php esc_html_e( 'Disabled', 'penalis-login' ); ?></span>
							<?php endif; ?>
						</td>
					</tr>
					<tr>
						<td><strong><?php esc_html_e( 'Login URL', 'penalis-login' ); ?></strong></td>
						<td>
							<a href="<?php echo esc_url( home_url( '/' . $this->helpers->getLoginSlug() . '/' ) ); ?>" target="_blank">
								<?php echo esc_html( home_url( '/' . $this->helpers->getLoginSlug() . '/' ) ); ?>
							</a>
						</td>
					</tr>
					<?php if ( 'protection' === $tab ) : ?>
						<tr>
							<td><strong><?php esc_html_e( 'Rate Limiting', 'penalis-login' ); ?></strong></td>
							<td><?php echo $prot['attempt_limiter_enabled'] ? '<span class="penalis-status-active">&#10003; ' . esc_html__( 'Enabled', 'penalis-login' ) . '</span>' : '<span class="penalis-status-inactive">&#10007; ' . esc_html__( 'Disabled', 'penalis-login' ) . '</span>'; ?></td>
						</tr>
						<tr>
							<td><strong><?php esc_html_e( 'Notifications', 'penalis-login' ); ?></strong></td>
							<td><?php echo $prot['notify_enabled'] ? '<span class="penalis-status-active">&#10003; ' . esc_html__( 'Enabled', 'penalis-login' ) . '</span>' : '<span class="penalis-status-inactive">&#10007; ' . esc_html__( 'Disabled', 'penalis-login' ) . '</span>'; ?></td>
						</tr>
						<tr>
							<td><strong><?php esc_html_e( 'IP Access Control', 'penalis-login' ); ?></strong></td>
							<td><?php echo $prot['ip_access_enabled'] ? '<span class="penalis-status-active">&#10003; ' . esc_html__( 'Enabled', 'penalis-login' ) . '</span>' : '<span class="penalis-status-inactive">&#10007; ' . esc_html__( 'Disabled', 'penalis-login' ) . '</span>'; ?></td>
						</tr>
					<?php else : ?>
						<tr>
							<td><strong><?php esc_html_e( 'Block Behavior', 'penalis-login' ); ?></strong></td>
							<td><?php echo esc_html( $this->getBlockBehaviorLabel() ); ?></td>
						</tr>
						<tr>
							<td><strong><?php esc_html_e( 'Guest /wp-admin/', 'penalis-login' ); ?></strong></td>
							<td><?php echo esc_html( $this->getWpAdminGuestBehaviorLabel() ); ?></td>
						</tr>
					<?php endif; ?>
					<tr>
						<td><strong><?php esc_html_e( 'Version', 'penalis-login' ); ?></strong></td>
						<td><?php echo esc_html( PENALIS_LOGIN_VERSION ); ?></td>
					</tr>
				</tbody>
			</table>
		</div>
		<?php
	}


	// -------------------------------------------------------------------------
	// Assets & links
	// -------------------------------------------------------------------------

	public function enqueueAssets( string $hook_suffix ): void {
		if ( 'settings_page_' . self::PAGE_SLUG !== $hook_suffix ) {
			return;
		}

		wp_enqueue_style(
			'penalis-login-admin',
			PENALIS_LOGIN_URL . 'assets/admin.css',
			[],
			PENALIS_LOGIN_VERSION
		);
	}

	/** @param string[] $links */
	public function addPluginActionLinks( array $links ): array {
		array_unshift( $links, sprintf(
			'<a href="%s">%s</a>',
			esc_url( admin_url( 'options-general.php?page=' . self::PAGE_SLUG ) ),
			esc_html__( 'Settings', 'penalis-login' )
		) );

		return $links;
	}

	// -------------------------------------------------------------------------
	// Delete-on-uninstall sync
	// -------------------------------------------------------------------------

	// Removed: syncDeleteOnUninstallOption() and syncDeleteOnUninstallOptionOnAdd()
	// were dead code. The delete_on_uninstall flag is written directly via
	// update_option() inside sanitizeGeneralTab(), so no hook-based sync is needed.

	// -------------------------------------------------------------------------
	// Helpers
	// -------------------------------------------------------------------------

	/**
	 * Returns the boolean value of a checkbox field from a POST input array.
	 *
	 * HTML checkboxes submit '1' when checked and nothing when unchecked.
	 * This helper centralises that pattern instead of repeating it inline.
	 *
	 * @param  array<string,mixed> $input The input array to read from.
	 * @param  string              $key   The field key to check.
	 * @return bool
	 */
	private function checkboxValue( array $input, string $key ): bool {
		return isset( $input[ $key ] ) && '1' === (string) $input[ $key ];
	}

	private function getBlockBehaviorLabel(): string {
		return match ( $this->helpers->getBlockBehavior() ) {
			'403'           => __( '403 Forbidden', 'penalis-login' ),
			'redirect_home' => __( 'Redirect to homepage', 'penalis-login' ),
			default         => __( '404 Not Found', 'penalis-login' ),
		};
	}

	private function getWpAdminGuestBehaviorLabel(): string {
		return match ( $this->helpers->getWpAdminGuestBehavior() ) {
			'redirect_home' => __( 'Redirect to homepage', 'penalis-login' ),
			'404'           => __( '404 Not Found', 'penalis-login' ),
			'403'           => __( '403 Forbidden', 'penalis-login' ),
			default         => __( 'Redirect to login', 'penalis-login' ),
		};
	}

	private function getActiveTab(): string {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$tab = isset( $_GET['tab'] ) ? sanitize_key( $_GET['tab'] ) : 'general';
		return in_array( $tab, self::TABS, true ) ? $tab : 'general';
	}

	private function tabUrl( string $tab ): string {
		return add_query_arg(
			[ 'page' => self::PAGE_SLUG, 'tab' => $tab ],
			admin_url( 'options-general.php' )
		);
	}
}
