<?php
/**
 * Admin settings page.
 *
 * Registers the "Settings → Penalis Login" page and handles all settings
 * using the WordPress Settings API for proper sanitization, nonce handling,
 * and capability checks.
 *
 * @package PenalisLogin\Admin
 */

declare(strict_types=1);

namespace PenalisLogin\Admin;

use PenalisLogin\Helpers;
use PenalisLogin\RewriteHandler;

/**
 * Class SettingsPage
 *
 * Renders and processes the Penalis Login settings page in wp-admin.
 */
final class SettingsPage {

	/** Settings page slug used in the admin menu. */
	private const PAGE_SLUG = 'penalis-login-settings';

	/** Settings group name used by settings_fields(). */
	private const SETTINGS_GROUP = 'penalis_login_group';

	/**
	 * @param Helpers $helpers Shared helper utilities.
	 */
	public function __construct( private readonly Helpers $helpers ) {}

	// -------------------------------------------------------------------------
	// Registration
	// -------------------------------------------------------------------------

	/**
	 * Registers all WordPress hooks for the admin settings page.
	 *
	 * @return void
	 */
	public function register(): void {
		add_action( 'admin_menu', [ $this, 'addMenuPage' ] );
		add_action( 'admin_init', [ $this, 'registerSettings' ] );
		add_action( 'admin_enqueue_scripts', [ $this, 'enqueueAssets' ] );

		// Persist the "delete on uninstall" flag as a separate option whenever
		// the main settings are saved. This is done outside the sanitize
		// callback to avoid side effects from WordPress calling sanitize
		// more than once per request.
		add_action( 'update_option_' . Helpers::OPTION_KEY, [ $this, 'syncDeleteOnUninstallOption' ], 10, 2 );
		add_action( 'add_option_' . Helpers::OPTION_KEY, [ $this, 'syncDeleteOnUninstallOptionOnAdd' ], 10, 2 );

		// Add a "Settings" link on the Plugins list page for quick access.
		add_filter(
			'plugin_action_links_' . PENALIS_LOGIN_BASENAME,
			[ $this, 'addPluginActionLinks' ]
		);
	}

	// -------------------------------------------------------------------------
	// Menu
	// -------------------------------------------------------------------------

	/**
	 * Adds the settings page under Settings → Penalis Login.
	 *
	 * @return void
	 */
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
	// Settings API registration
	// -------------------------------------------------------------------------

	/**
	 * Registers the settings, sections, and fields using the WordPress
	 * Settings API.
	 *
	 * @return void
	 */
	public function registerSettings(): void {
		register_setting(
			self::SETTINGS_GROUP,
			Helpers::OPTION_KEY,
			[
				'type'              => 'array',
				'sanitize_callback' => [ $this, 'sanitizeSettings' ],
				'default'           => [
					'enabled'        => true,
					'login_slug'     => Helpers::DEFAULT_SLUG,
					'block_behavior' => '404',
				],
			]
		);

		// ---- General section ------------------------------------------------

		add_settings_section(
			'penalis_login_general',
			__( 'General Settings', 'penalis-login' ),
			[ $this, 'renderGeneralSectionDescription' ],
			self::PAGE_SLUG
		);

		add_settings_field(
			'penalis_login_enabled',
			__( 'Enable Plugin', 'penalis-login' ),
			[ $this, 'renderEnabledField' ],
			self::PAGE_SLUG,
			'penalis_login_general'
		);

		add_settings_field(
			'penalis_login_slug',
			__( 'Custom Login Slug', 'penalis-login' ),
			[ $this, 'renderSlugField' ],
			self::PAGE_SLUG,
			'penalis_login_general'
		);

		// ---- Security section -----------------------------------------------

		add_settings_section(
			'penalis_login_security',
			__( 'Security Settings', 'penalis-login' ),
			[ $this, 'renderSecuritySectionDescription' ],
			self::PAGE_SLUG
		);

		add_settings_field(
			'penalis_login_block_behavior',
			__( 'When /wp-login.php is accessed', 'penalis-login' ),
			[ $this, 'renderBlockBehaviorField' ],
			self::PAGE_SLUG,
			'penalis_login_security',
			[ 'label_for' => '' ] // Prevent WP from wrapping the th content in a <label>.
		);

		add_settings_field(
			'penalis_login_wp_admin_guest_behavior',
			__( 'When /wp-admin/ is accessed while logged out', 'penalis-login' ),
			[ $this, 'renderWpAdminGuestBehaviorField' ],
			self::PAGE_SLUG,
			'penalis_login_security',
			[ 'label_for' => '' ] // Prevent WP from wrapping the th content in a <label>.
		);

		// ---- Uninstall section ----------------------------------------------

		add_settings_section(
			'penalis_login_uninstall',
			__( 'Uninstall Settings', 'penalis-login' ),
			[ $this, 'renderUninstallSectionDescription' ],
			self::PAGE_SLUG
		);

		add_settings_field(
			'penalis_login_delete_on_uninstall',
			__( 'Delete Plugin Data', 'penalis-login' ),
			[ $this, 'renderDeleteOnUninstallField' ],
			self::PAGE_SLUG,
			'penalis_login_uninstall'
		);
	}

	// -------------------------------------------------------------------------
	// Sanitization
	// -------------------------------------------------------------------------

	/**
	 * Sanitizes and validates the settings array before saving.
	 *
	 * This is the single point of truth for input validation. All values
	 * are explicitly cast and validated — we never trust raw user input.
	 *
	 * If the hidden field '_reset' is present and set to '1', all settings
	 * are reset to their defaults instead of reading the submitted values.
	 *
	 * Slug validation order:
	 *  1. Normalize (sanitize_title).
	 *  2. Reject if empty → fall back to current saved slug.
	 *  3. Reject if reserved WP core slug → show error, fall back.
	 *  4. Reject if already used by a published post/page/CPT → show error, fall back.
	 *  5. Accept.
	 *
	 * @param  mixed $input Raw input from the settings form.
	 * @return array<string,mixed> Sanitized settings array.
	 */
	public function sanitizeSettings( mixed $input ): array {

		// ---- Reset to defaults ---------------------------------------------
		// The "Reset to Defaults" button submits the form with _reset=1.
		// We return the defaults immediately, bypassing all other validation.
		if ( isset( $input['_reset'] ) && '1' === (string) $input['_reset'] ) {
			// Also reset the separate delete-on-uninstall option.
			update_option( Helpers::DELETE_ON_UNINSTALL_KEY, false, false );

			$this->helpers->invalidateCache();
			set_transient( 'penalis_login_flush_rules', true, 60 );

			$existing_reset = wp_list_filter( get_settings_errors(), [ 'code' => 'settings-reset' ] );
			if ( empty( $existing_reset ) ) {
				add_settings_error(
					Helpers::OPTION_KEY,
					'settings-reset',
					sprintf(
						'<span class="penalis-notice-icon">&#10003;</span> <strong>%s</strong> %s',
						esc_html__( 'Settings reset.', 'penalis-login' ),
						esc_html__( 'All settings have been restored to their defaults.', 'penalis-login' )
					),
					'success'
				);
			}

			return Helpers::getDefaultSettings();
		}

		$output = [];

		// Enabled flag.
		$output['enabled'] = isset( $input['enabled'] ) && '1' === (string) $input['enabled'];

		// ---- Login slug validation ------------------------------------------

		$raw_slug      = isset( $input['login_slug'] ) ? (string) $input['login_slug'] : '';
		$slug_error    = $this->validateSlug( $raw_slug );

		if ( null !== $slug_error ) {
			// Validation failed: show an error notice and keep the previously
			// saved slug so the site does not break.
			add_settings_error(
				Helpers::OPTION_KEY,
				'penalis-slug-invalid',
				$slug_error,
				'error'
			);

			// Fall back to the currently stored slug (before this save attempt).
			$output['login_slug'] = $this->helpers->getLoginSlug();
		} else {
			$output['login_slug'] = $this->helpers->normalizeSlug( $raw_slug );
		}

		// ---- Block behavior ------------------------------------------------

		$allowed_behaviors    = [ '404', '403', 'redirect_home' ];
		$raw_behavior         = isset( $input['block_behavior'] ) ? (string) $input['block_behavior'] : '404';
		$output['block_behavior'] = in_array( $raw_behavior, $allowed_behaviors, true )
			? $raw_behavior
			: '404';

		// ---- wp-admin guest behavior ---------------------------------------

		$allowed_wp_admin_behaviors      = [ 'redirect_login', 'redirect_home', '404', '403' ];
		$raw_wp_admin_behavior           = isset( $input['wp_admin_guest_behavior'] ) ? (string) $input['wp_admin_guest_behavior'] : 'redirect_login';
		$output['wp_admin_guest_behavior'] = in_array( $raw_wp_admin_behavior, $allowed_wp_admin_behaviors, true )
			? $raw_wp_admin_behavior
			: 'redirect_login';

		// ---- Delete on uninstall -------------------------------------------
		// The actual update_option() call is handled by syncDeleteOnUninstallOption()
		// via the update_option_ hook, to avoid side effects from WordPress
		// calling this sanitize callback more than once per request.
		// We still read the submitted value here so it can be passed along
		// via a transient for the hook to pick up.
		$delete_on_uninstall = isset( $input['delete_on_uninstall'] ) && '1' === (string) $input['delete_on_uninstall'];
		set_transient( 'penalis_login_pending_delete_flag', $delete_on_uninstall ? '1' : '0', 60 );

		// Invalidate the in-memory settings cache so the new values are used
		// immediately within this request.
		$this->helpers->invalidateCache();

		// Schedule a rewrite flush for the next request.
		set_transient( 'penalis_login_flush_rules', true, 60 );

		// Replace the default "Settings saved." notice with a custom one.
		// Using the same code ('settings-updated') as WordPress's built-in
		// notice ensures ours replaces it instead of stacking on top.
		// The duplicate guard prevents double-firing when WordPress calls
		// the sanitize callback more than once per request.
		// We only show the success notice when there are no slug errors.
		$has_slug_error = ! empty( wp_list_filter( get_settings_errors(), [ 'code' => 'penalis-slug-invalid' ] ) );
		$existing       = wp_list_filter( get_settings_errors(), [ 'code' => 'settings-updated' ] );

		if ( ! $has_slug_error && empty( $existing ) ) {
			add_settings_error(
				Helpers::OPTION_KEY,
				'settings-updated',
				sprintf(
					'<span class="penalis-notice-icon">&#10003;</span> <strong>%s</strong> %s',
					esc_html__( 'Settings saved.', 'penalis-login' ),
					esc_html__( 'Your settings have been updated.', 'penalis-login' )
				),
				'success'
			);
		}

		return $output;
	}

	// -------------------------------------------------------------------------
	// Slug validation
	// -------------------------------------------------------------------------

	/**
	 * Validates a raw login slug candidate.
	 *
	 * Returns a translated error message string when the slug is invalid, or
	 * null when the slug is acceptable.
	 *
	 * Checks performed (in order):
	 *  1. Empty after normalization.
	 *  2. Conflicts with a reserved WordPress core path.
	 *  3. Conflicts with an existing published post, page, or custom post type.
	 *
	 * @param  string $raw_slug Raw slug value from the form input.
	 * @return string|null      Error message, or null if the slug is valid.
	 */
	private function validateSlug( string $raw_slug ): ?string {
		$slug = $this->helpers->normalizeSlug( $raw_slug );

		// 1. Empty slug after normalization.
		if ( '' === $slug ) {
			return sprintf(
				/* translators: %s: the default fallback slug */
				esc_html__( 'The login slug cannot be empty. Falling back to the default slug "%s". The previous slug has been kept.', 'penalis-login' ),
				esc_html( Helpers::DEFAULT_SLUG )
			);
		}

		// 2. Reserved WordPress core slug.
		if ( $this->helpers->isReservedSlug( $slug ) ) {
			return sprintf(
				/* translators: %s: the slug the user tried to use */
				esc_html__( '"%s" is a reserved WordPress slug and cannot be used as the login slug. The previous slug has been kept.', 'penalis-login' ),
				esc_html( $slug )
			);
		}

		// 3. Conflict with an existing published post, page, or CPT.
		$conflict = $this->findSlugConflict( $slug );
		if ( null !== $conflict ) {
			return sprintf(
				/* translators: 1: the slug the user tried to use, 2: post type label, 3: post title */
				esc_html__( '"%1$s" is already used by the %2$s "%3$s". Choose a different slug to avoid routing conflicts. The previous slug has been kept.', 'penalis-login' ),
				esc_html( $slug ),
				esc_html( $conflict['type_label'] ),
				esc_html( $conflict['post_title'] )
			);
		}

		return null;
	}

	/**
	 * Checks whether a slug is already used by any published post, page, or
	 * custom post type entry.
	 *
	 * Returns an associative array with 'post_title' and 'type_label' keys
	 * when a conflict is found, or null when the slug is free.
	 *
	 * @param  string $slug Normalized slug to check.
	 * @return array{post_title: string, type_label: string}|null
	 */
	private function findSlugConflict( string $slug ): ?array {
		// get_page_by_path() is the canonical WP function for slug lookups.
		// We query all public post types to catch pages, posts, and CPTs.
		$public_post_types = get_post_types( [ 'public' => true ], 'objects' );

		foreach ( $public_post_types as $post_type => $post_type_obj ) {
			$post = get_page_by_path( $slug, OBJECT, $post_type );

			if ( null === $post ) {
				continue;
			}

			// Only flag published content — drafts and trashed posts do not
			// occupy a public URL and should not block slug selection.
			if ( 'publish' !== $post->post_status ) {
				continue;
			}

			return [
				'post_title' => $post->post_title,
				'type_label' => $post_type_obj->labels->singular_name,
			];
		}

		return null;
	}

	// -------------------------------------------------------------------------
	// Section descriptions
	// -------------------------------------------------------------------------

	/**
	 * Renders the description for the General Settings section.
	 *
	 * @return void
	 */
	public function renderGeneralSectionDescription(): void {
		echo '<p>'
			. esc_html__( 'Configure the custom login URL and enable or disable the plugin.', 'penalis-login' )
			. '</p>';
	}

	/**
	 * Renders the description for the Security Settings section.
	 *
	 * @return void
	 */
	public function renderSecuritySectionDescription(): void {
		echo '<p>'
			. esc_html__( 'Control what happens when someone tries to access the default WordPress login or admin URLs directly. These settings help prevent bots and attackers from finding your login page.', 'penalis-login' )
			. '</p>';
	}

	/**
	 * Renders the description for the Uninstall Settings section.
	 *
	 * @return void
	 */
	public function renderUninstallSectionDescription(): void {
		echo '<p>'
			. esc_html__( 'Controls what happens to plugin data when the plugin is deleted from WordPress.', 'penalis-login' )
			. '</p>';
	}

	// -------------------------------------------------------------------------
	// Field renderers
	// -------------------------------------------------------------------------

	/**
	 * Renders the "Enable Plugin" checkbox field.
	 *
	 * @return void
	 */
	public function renderEnabledField(): void {
		$enabled = $this->helpers->isPluginEnabled();
		?>
		<label for="penalis_login_enabled">
			<input
				type="checkbox"
				id="penalis_login_enabled"
				name="<?php echo esc_attr( Helpers::OPTION_KEY ); ?>[enabled]"
				value="1"
				<?php checked( $enabled ); ?>
			/>
			<?php esc_html_e( 'Enable custom login URL', 'penalis-login' ); ?>
		</label>
		<p class="description">
			<?php esc_html_e( 'When disabled, the default WordPress login URL (/wp-login.php) will be used.', 'penalis-login' ); ?>
		</p>
		<?php
	}

	/**
	 * Renders the "Custom Login Slug" text field.
	 *
	 * @return void
	 */
	public function renderSlugField(): void {
		$slug         = $this->helpers->getLoginSlug();
		$preview_url  = home_url( '/' . $slug . '/' );
		$reserved     = implode( ', ', $this->helpers->getReservedSlugs() );
		?>
		<input
			type="text"
			id="penalis_login_slug"
			name="<?php echo esc_attr( Helpers::OPTION_KEY ); ?>[login_slug]"
			value="<?php echo esc_attr( $slug ); ?>"
			class="regular-text"
			placeholder="<?php echo esc_attr( Helpers::DEFAULT_SLUG ); ?>"
		/>
		<p class="description">
			<?php
			printf(
				/* translators: %s: preview URL */
				esc_html__( 'Your custom login URL will be: %s', 'penalis-login' ),
				'<code>' . esc_url( $preview_url ) . '</code>'
			);
			?>
		</p>
		<p class="description">
			<?php
			printf(
				/* translators: %s: comma-separated list of reserved slugs */
				esc_html__( 'Reserved slugs (cannot be used): %s', 'penalis-login' ),
				'<code>' . esc_html( $reserved ) . '</code>'
			);
			?>
		</p>
		<?php
	}

	/**
	 * Renders the "When /wp-login.php is accessed" horizontal behavior cards.
	 *
	 * Three cards side by side — compact layout because there are only 3 options
	 * and descriptions are short enough to fit inside a card.
	 *
	 * @return void
	 */
	public function renderBlockBehaviorField(): void {
		$current = $this->helpers->getBlockBehavior();

		$options = [
			'404' => [
				'label' => __( 'Return 404 Not Found', 'penalis-login' ),
				'badge' => null,
				'desc'  => __( 'Recommended. Does not reveal that a login page exists. Best for security and preventing bots from discovering your site.', 'penalis-login' ),
			],
			'403' => [
				'label' => __( 'Return 403 Forbidden', 'penalis-login' ),
				'badge' => null,
				'desc'  => __( 'Explicitly denies access. Signals that a protected area exists, but does not reveal the login URL.', 'penalis-login' ),
			],
			'redirect_home' => [
				'label' => __( 'Redirect to homepage', 'penalis-login' ),
				'badge' => null,
				'desc'  => __( 'Redirects visitors to your homepage. May reveal that your site is protected, but not the login URL.', 'penalis-login' ),
			],
		];
		?>
		<div class="penalis-behavior-cards" role="group" aria-label="<?php esc_attr_e( 'Block behavior for wp-login.php', 'penalis-login' ); ?>">
			<?php foreach ( $options as $value => $option ) : ?>
				<?php
				$value = (string) $value;
				$id    = 'penalis_block_' . $value;
				?>
				<input
					type="radio"
					id="<?php echo esc_attr( $id ); ?>"
					name="<?php echo esc_attr( Helpers::OPTION_KEY ); ?>[block_behavior]"
					value="<?php echo esc_attr( $value ); ?>"
					<?php checked( $current, $value ); ?>
				/>
				<label for="<?php echo esc_attr( $id ); ?>" class="penalis-behavior-card">
					<span class="penalis-behavior-card-radio">
						<span class="penalis-behavior-card-dot" aria-hidden="true"></span>
					</span>
					<span class="penalis-behavior-card-title">
						<?php echo esc_html( $option['label'] ); ?>
						<?php if ( 'recommended' === $option['badge'] ) : ?>
							<span class="penalis-badge penalis-badge-recommended"><?php esc_html_e( 'Recommended', 'penalis-login' ); ?></span>
						<?php endif; ?>
					</span>
					<span class="penalis-behavior-card-desc">
						<?php echo esc_html( $option['desc'] ); ?>
					</span>
				</label>
			<?php endforeach; ?>
		</div>

		<div class="penalis-field-note" style="margin-top:10px; max-width:680px;">
			<span><?php esc_html_e( 'Your own access is never affected — logged-in administrators can always reach /wp-login.php normally.', 'penalis-login' ); ?></span>
		</div>
		<?php
	}

	/**
	 * Renders the "When /wp-admin/ is accessed while logged out" vertical behavior list.
	 *
	 * Each row shows a radio dot, title with optional badge, and a description.
	 * The warning row gets an amber tint when selected.
	 *
	 * @return void
	 */
	public function renderWpAdminGuestBehaviorField(): void {
		$current = $this->helpers->getWpAdminGuestBehavior();

		$options = [
			'redirect_login' => [
				'label'   => __( 'Redirect to custom login URL', 'penalis-login' ),
				'badge'   => null,
				'desc'    => null,
				'warn'    => __( 'This will expose your login URL to anyone who visits /wp-admin/ while logged out.', 'penalis-login' ),
				'warning' => true,
			],
			'redirect_home' => [
				'label'   => __( 'Redirect to homepage', 'penalis-login' ),
				'badge'   => null,
				'desc'    => __( 'Silently redirects visitors to the homepage. Does not reveal the login URL.', 'penalis-login' ),
				'warn'    => null,
				'warning' => false,
			],
			'404' => [
				'label'   => __( 'Show 404 Not Found', 'penalis-login' ),
				'badge'   => null,
				'desc'    => __( 'Stealth mode. Makes /wp-admin/ completely invisible to bots and scanners.', 'penalis-login' ),
				'warn'    => null,
				'warning' => false,
			],
			'403' => [
				'label'   => __( 'Show 403 Forbidden', 'penalis-login' ),
				'badge'   => null,
				'desc'    => __( 'Explicitly denies access. Signals that a protected area exists, but does not reveal the login URL.', 'penalis-login' ),
				'warn'    => null,
				'warning' => false,
			],
		];
		?>
		<div class="penalis-behavior-list" role="group" aria-label="<?php esc_attr_e( 'Guest behavior for wp-admin', 'penalis-login' ); ?>">
			<?php foreach ( $options as $value => $option ) : ?>
				<?php
				$value      = (string) $value;
				$id         = 'penalis_wp_admin_' . $value;
				$row_class  = 'penalis-behavior-row' . ( $option['warning'] ? ' is-warning' : '' );
				?>
				<input
					type="radio"
					id="<?php echo esc_attr( $id ); ?>"
					name="<?php echo esc_attr( Helpers::OPTION_KEY ); ?>[wp_admin_guest_behavior]"
					value="<?php echo esc_attr( $value ); ?>"
					<?php checked( $current, $value ); ?>
				/>
				<label for="<?php echo esc_attr( $id ); ?>" class="<?php echo esc_attr( $row_class ); ?>">
					<span class="penalis-behavior-row-dot" aria-hidden="true"></span>

					<span class="penalis-behavior-row-title">
						<?php echo esc_html( $option['label'] ); ?>
						<?php if ( 'default' === $option['badge'] ) : ?>
							<span class="penalis-badge penalis-badge-default"><?php esc_html_e( 'Default', 'penalis-login' ); ?></span>
						<?php elseif ( 'stealth' === $option['badge'] ) : ?>
							<span class="penalis-badge penalis-badge-stealth"><?php esc_html_e( 'Stealth Mode', 'penalis-login' ); ?></span>
						<?php endif; ?>
					</span>

					<?php if ( ! empty( $option['desc'] ) ) : ?>
						<span class="penalis-behavior-row-desc">
							<?php echo esc_html( $option['desc'] ); ?>
						</span>
					<?php endif; ?>

					<?php if ( ! empty( $option['warn'] ) ) : ?>
						<span class="penalis-behavior-row-warn">
							<span aria-hidden="true">&#9888;</span>
							<?php echo esc_html( $option['warn'] ); ?>
						</span>
					<?php endif; ?>
				</label>
			<?php endforeach; ?>
		</div>

		<div class="penalis-field-note" style="margin-top:10px; max-width:680px;">
			<span><?php esc_html_e( 'Your own access is never affected — logged-in users always reach /wp-admin/ normally regardless of this setting.', 'penalis-login' ); ?></span>
		</div>
		<?php
	}

	/**
	 * Renders the "Delete Plugin Data on Uninstall" checkbox field.
	 *
	 * @return void
	 */
	public function renderDeleteOnUninstallField(): void {
		$checked = (bool) get_option( Helpers::DELETE_ON_UNINSTALL_KEY, false );
		?>
		<label for="penalis_login_delete_on_uninstall">
			<input
				type="checkbox"
				id="penalis_login_delete_on_uninstall"
				name="<?php echo esc_attr( Helpers::OPTION_KEY ); ?>[delete_on_uninstall]"
				value="1"
				<?php checked( $checked ); ?>
			/>
			<?php esc_html_e( 'Delete all plugin data when the plugin is uninstalled', 'penalis-login' ); ?>
		</label>
		<p class="description">
			<?php esc_html_e( 'When enabled, all plugin settings will be permanently removed from the database when you delete this plugin. Disable this option if you want to preserve your settings across reinstalls.', 'penalis-login' ); ?>
		</p>
		<?php
	}

	// -------------------------------------------------------------------------
	// Page renderer
	// -------------------------------------------------------------------------

	/**
	 * Renders the full settings page HTML.
	 *
	 * @return void
	 */
	public function renderPage(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have sufficient permissions to access this page.', 'penalis-login' ) );
		}
		?>
		<div class="wrap penalis-login-settings">

			<!--
				<h1> is intentionally outside the flex header row.
				WordPress injects a hidden .wp-header-end sentinel immediately
				after the first <h1> in .wrap, then appends all admin notices
				after that sentinel. Keeping <h1> inside a flex container would
				pull those notices into the flex row, placing them beside the
				heading. By putting <h1> before the flex row, the sentinel lands
				outside the flex context and our manual notice container below
				takes over cleanly.
			-->
			<h1 class="penalis-login-title"><?php esc_html_e( 'Penalis Login', 'penalis-login' ); ?></h1>

			<!--
				Render our notices here manually. We pass $sanitize = false so
				WordPress does not re-run the sanitize callback, and we clear
				the global errors store afterwards so the notices WordPress would
				normally auto-render after .wp-header-end are suppressed.
			-->
			<div id="penalis-login-notices">
				<?php
				settings_errors( Helpers::OPTION_KEY, false, true );
				// Clear the global errors so WordPress does not render them
				// a second time via its own admin_notices / .wp-header-end flow.
				global $wp_settings_errors;
				$wp_settings_errors = []; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
				?>
			</div>

			<div class="penalis-login-body">

				<!-- Main column: settings form -->
				<div class="penalis-login-main">
					<form method="post" action="options.php">
						<?php
						settings_fields( self::SETTINGS_GROUP );
						do_settings_sections( self::PAGE_SLUG );
						?>
						<div class="penalis-form-actions">
							<?php submit_button( __( 'Save Settings', 'penalis-login' ), 'primary', 'submit', false ); ?>
							<button
								type="submit"
								name="<?php echo esc_attr( Helpers::OPTION_KEY ); ?>[_reset]"
								value="1"
								class="button button-secondary penalis-reset-button"
								onclick="return confirm('<?php echo esc_js( __( 'Reset all settings to their defaults? This cannot be undone.', 'penalis-login' ) ); ?>')"
							>
								<?php esc_html_e( 'Reset to Defaults', 'penalis-login' ); ?>
							</button>
						</div>
					</form>
				</div>

				<!-- Sidebar column: current status -->
				<div class="penalis-login-sidebar">
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
								<tr>
									<td><strong><?php esc_html_e( 'Block Behavior', 'penalis-login' ); ?></strong></td>
									<td><?php echo esc_html( $this->getBlockBehaviorLabel() ); ?></td>
								</tr>
								<tr>
									<td><strong><?php esc_html_e( 'Guest /wp-admin/', 'penalis-login' ); ?></strong></td>
									<td><?php echo esc_html( $this->getWpAdminGuestBehaviorLabel() ); ?></td>
								</tr>
								<tr>
									<td><strong><?php esc_html_e( 'Version', 'penalis-login' ); ?></strong></td>
									<td><?php echo esc_html( PENALIS_LOGIN_VERSION ); ?></td>
								</tr>
							</tbody>
						</table>
					</div>
				</div>

			</div><!-- /.penalis-login-body -->

		</div>
		<?php
	}

	// -------------------------------------------------------------------------
	// Assets
	// -------------------------------------------------------------------------

	/**
	 * Enqueues admin CSS on the Penalis Login settings page only.
	 *
	 * @param  string $hook_suffix The current admin page hook suffix.
	 * @return void
	 */
	public function enqueueAssets( string $hook_suffix ): void {
		// Only load on our settings page.
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

	// -------------------------------------------------------------------------
	// Plugin action links
	// -------------------------------------------------------------------------

	/**
	 * Adds a "Settings" link to the plugin row on the Plugins list page.
	 *
	 * @param  string[] $links Existing plugin action links.
	 * @return string[]
	 */
	public function addPluginActionLinks( array $links ): array {
		$settings_link = sprintf(
			'<a href="%s">%s</a>',
			esc_url( admin_url( 'options-general.php?page=' . self::PAGE_SLUG ) ),
			esc_html__( 'Settings', 'penalis-login' )
		);

		array_unshift( $links, $settings_link );

		return $links;
	}

	// -------------------------------------------------------------------------
	// Delete-on-uninstall sync
	// -------------------------------------------------------------------------

	/**
	 * Syncs the "delete on uninstall" flag to its own option after the main
	 * settings option is updated.
	 *
	 * Hooked to update_option_{option_name} so it runs exactly once per save,
	 * avoiding the double-execution risk of doing it inside sanitizeSettings().
	 *
	 * @param  mixed $old_value Previous option value (unused).
	 * @param  mixed $new_value New option value (unused — we read the transient).
	 * @return void
	 */
	public function syncDeleteOnUninstallOption( mixed $old_value, mixed $new_value ): void {
		$pending = get_transient( 'penalis_login_pending_delete_flag' );

		if ( false !== $pending ) {
			delete_transient( 'penalis_login_pending_delete_flag' );
			update_option( Helpers::DELETE_ON_UNINSTALL_KEY, '1' === $pending, false );
		}
	}

	/**
	 * Same as syncDeleteOnUninstallOption() but fires on add_option_ for the
	 * very first save (when the option doesn't exist yet).
	 *
	 * @param  string $option Option name (unused).
	 * @param  mixed  $value  Option value (unused).
	 * @return void
	 */
	public function syncDeleteOnUninstallOptionOnAdd( string $option, mixed $value ): void {
		$this->syncDeleteOnUninstallOption( null, null );
	}

	// -------------------------------------------------------------------------
	// Private helpers
	// -------------------------------------------------------------------------

	/**
	 * Returns a human-readable label for the current block behavior setting.
	 *
	 * @return string
	 */
	private function getBlockBehaviorLabel(): string {
		$labels = [
			'404'           => __( '404 Not Found', 'penalis-login' ),
			'403'           => __( '403 Forbidden', 'penalis-login' ),
			'redirect_home' => __( 'Redirect to homepage', 'penalis-login' ),
		];

		return $labels[ $this->helpers->getBlockBehavior() ] ?? __( '404 Not Found', 'penalis-login' );
	}

	/**
	 * Returns a human-readable label for the current wp-admin guest behavior setting.
	 *
	 * @return string
	 */
	private function getWpAdminGuestBehaviorLabel(): string {
		$labels = [
			'redirect_login' => __( 'Redirect to login', 'penalis-login' ),
			'redirect_home'  => __( 'Redirect to homepage', 'penalis-login' ),
			'404'            => __( '404 Not Found (Stealth)', 'penalis-login' ),
			'403'            => __( '403 Forbidden', 'penalis-login' ),
		];

		return $labels[ $this->helpers->getWpAdminGuestBehavior() ] ?? __( 'Redirect to login', 'penalis-login' );
	}
}
