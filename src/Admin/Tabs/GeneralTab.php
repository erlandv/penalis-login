<?php
/**
 * General settings tab.
 *
 * Contains all fields that were previously in SettingsPage directly:
 * enable/disable toggle, custom login slug, block behavior, and
 * wp-admin guest behavior.
 *
 * @package PenalisLogin\Admin\Tabs
 */

declare(strict_types=1);

namespace PenalisLogin\Admin\Tabs;

use PenalisLogin\Helpers;

/**
 * Class GeneralTab
 *
 * Registers and renders the General settings tab fields.
 */
final class GeneralTab {

	/**
	 * @param Helpers $helpers Shared helper utilities.
	 */
	public function __construct( private readonly Helpers $helpers ) {}

	// -------------------------------------------------------------------------
	// Render all fields (called directly by SettingsPage, no Settings API)
	// -------------------------------------------------------------------------

	/**
	 * Renders all General tab fields as a standard WP form-table.
	 *
	 * @return void
	 */
	public function renderFields(): void {
		?>
		<h2><?php esc_html_e( 'General Settings', 'penalis-login' ); ?></h2>
		<p><?php esc_html_e( 'Configure the custom login URL and enable or disable the plugin.', 'penalis-login' ); ?></p>
		<table class="form-table" role="presentation">
			<tbody>
				<tr>
					<th scope="row"><?php esc_html_e( 'Enable Plugin', 'penalis-login' ); ?></th>
					<td><?php $this->renderEnabledField(); ?></td>
				</tr>
				<tr>
					<th scope="row"><label for="penalis_login_slug"><?php esc_html_e( 'Custom Login Slug', 'penalis-login' ); ?></label></th>
					<td><?php $this->renderSlugField(); ?></td>
				</tr>
			</tbody>
		</table>

		<h2><?php esc_html_e( 'Security Settings', 'penalis-login' ); ?></h2>
		<p><?php esc_html_e( 'Control what happens when someone tries to access the default WordPress login or admin URLs directly.', 'penalis-login' ); ?></p>
		<table class="form-table" role="presentation">
			<tbody>
				<tr>
					<th scope="row"><?php esc_html_e( 'When /wp-login.php is accessed', 'penalis-login' ); ?></th>
					<td><?php $this->renderBlockBehaviorField(); ?></td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'When /wp-admin/ is accessed while logged out', 'penalis-login' ); ?></th>
					<td><?php $this->renderWpAdminGuestBehaviorField(); ?></td>
				</tr>
			</tbody>
		</table>

		<h2><?php esc_html_e( 'Uninstall Settings', 'penalis-login' ); ?></h2>
		<p><?php esc_html_e( 'Controls what happens to plugin data when the plugin is deleted from WordPress.', 'penalis-login' ); ?></p>
		<table class="form-table" role="presentation">
			<tbody>
				<tr>
					<th scope="row"><?php esc_html_e( 'Delete Plugin Data', 'penalis-login' ); ?></th>
					<td><?php $this->renderDeleteOnUninstallField(); ?></td>
				</tr>
			</tbody>
		</table>
		<?php
	}

	// -------------------------------------------------------------------------
	// Field renderers
	// -------------------------------------------------------------------------

	/** @return void */
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

	/** @return void */
	public function renderSlugField(): void {
		$slug        = $this->helpers->getLoginSlug();
		$preview_url = home_url( '/' . $slug . '/' );
		$reserved    = implode( ', ', $this->helpers->getReservedSlugs() );
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

	/** @return void */
	public function renderBlockBehaviorField(): void {
		$current = $this->helpers->getBlockBehavior();

		$options = [
			'404' => [
				'label' => __( 'Return 404 Not Found', 'penalis-login' ),
				'desc'  => __( 'Recommended. Does not reveal that a login page exists. Best for security and preventing bots from discovering your site.', 'penalis-login' ),
			],
			'403' => [
				'label' => __( 'Return 403 Forbidden', 'penalis-login' ),
				'desc'  => __( 'Explicitly denies access. Signals that a protected area exists, but does not reveal the login URL.', 'penalis-login' ),
			],
			'redirect_home' => [
				'label' => __( 'Redirect to homepage', 'penalis-login' ),
				'desc'  => __( 'Redirects visitors to your homepage. May reveal that your site is protected, but not the login URL.', 'penalis-login' ),
			],
		];
		?>
		<div class="penalis-behavior-cards" role="group" aria-label="<?php esc_attr_e( 'Block behavior for wp-login.php', 'penalis-login' ); ?>">
			<?php foreach ( $options as $value => $option ) : ?>
				<?php $id = 'penalis_block_' . $value; ?>
				<input
					type="radio"
					id="<?php echo esc_attr( $id ); ?>"
					name="<?php echo esc_attr( Helpers::OPTION_KEY ); ?>[block_behavior]"
					value="<?php echo esc_attr( (string) $value ); ?>"
					<?php checked( $current, $value ); ?>
				/>
				<label for="<?php echo esc_attr( $id ); ?>" class="penalis-behavior-card">
					<span class="penalis-behavior-card-radio">
						<span class="penalis-behavior-card-dot" aria-hidden="true"></span>
					</span>
					<span class="penalis-behavior-card-title"><?php echo esc_html( $option['label'] ); ?></span>
					<span class="penalis-behavior-card-desc"><?php echo esc_html( $option['desc'] ); ?></span>
				</label>
			<?php endforeach; ?>
		</div>
		<div class="penalis-field-note" style="margin-top:10px; max-width:680px;">
			<span><?php esc_html_e( 'Your own access is never affected — logged-in administrators can always reach /wp-login.php normally.', 'penalis-login' ); ?></span>
		</div>
		<?php
	}

	/** @return void */
	public function renderWpAdminGuestBehaviorField(): void {
		$current = $this->helpers->getWpAdminGuestBehavior();

		$options = [
			'redirect_login' => [
				'label'   => __( 'Redirect to custom login URL', 'penalis-login' ),
				'desc'    => null,
				'warn'    => __( 'This will expose your login URL to anyone who visits /wp-admin/ while logged out.', 'penalis-login' ),
				'warning' => true,
			],
			'redirect_home' => [
				'label'   => __( 'Redirect to homepage', 'penalis-login' ),
				'desc'    => __( 'Silently redirects visitors to the homepage. Does not reveal the login URL.', 'penalis-login' ),
				'warn'    => null,
				'warning' => false,
			],
			'404' => [
				'label'   => __( 'Show 404 Not Found', 'penalis-login' ),
				'desc'    => __( 'Stealth mode. Makes /wp-admin/ completely invisible to bots and scanners.', 'penalis-login' ),
				'warn'    => null,
				'warning' => false,
			],
			'403' => [
				'label'   => __( 'Show 403 Forbidden', 'penalis-login' ),
				'desc'    => __( 'Explicitly denies access. Signals that a protected area exists, but does not reveal the login URL.', 'penalis-login' ),
				'warn'    => null,
				'warning' => false,
			],
		];
		?>
		<div class="penalis-behavior-list" role="group" aria-label="<?php esc_attr_e( 'Guest behavior for wp-admin', 'penalis-login' ); ?>">
			<?php foreach ( $options as $value => $option ) : ?>
				<?php
				$id        = 'penalis_wp_admin_' . $value;
				$row_class = 'penalis-behavior-row' . ( $option['warning'] ? ' is-warning' : '' );
				?>
				<input
					type="radio"
					id="<?php echo esc_attr( $id ); ?>"
					name="<?php echo esc_attr( Helpers::OPTION_KEY ); ?>[wp_admin_guest_behavior]"
					value="<?php echo esc_attr( (string) $value ); ?>"
					<?php checked( $current, $value ); ?>
				/>
				<label for="<?php echo esc_attr( $id ); ?>" class="<?php echo esc_attr( $row_class ); ?>">
					<span class="penalis-behavior-row-dot" aria-hidden="true"></span>
					<span class="penalis-behavior-row-title"><?php echo esc_html( $option['label'] ); ?></span>
					<?php if ( ! empty( $option['desc'] ) ) : ?>
						<span class="penalis-behavior-row-desc"><?php echo esc_html( $option['desc'] ); ?></span>
					<?php endif; ?>
					<?php if ( ! empty( $option['warn'] ) ) : ?>
						<span class="penalis-behavior-row-warn">
							<span class="dashicons dashicons-warning" aria-hidden="true"></span>
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

	/** @return void */
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
			<?php esc_html_e( 'When enabled, all plugin settings and logs will be permanently removed from the database when you delete this plugin.', 'penalis-login' ); ?>
		</p>
		<?php
	}
}
