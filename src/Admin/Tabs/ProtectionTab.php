<?php
/**
 * Protection settings tab.
 *
 * @package PenalisLogin\Admin\Tabs
 */

declare(strict_types=1);

namespace PenalisLogin\Admin\Tabs;

use PenalisLogin\Helpers;
use PenalisLogin\Database\IpRulesRepository;

final class ProtectionTab {

	public function __construct(
		private readonly Helpers $helpers,
		private readonly IpRulesRepository $ipRepo
	) {}

	// -------------------------------------------------------------------------
	// Main render — called inside the settings <form>
	// -------------------------------------------------------------------------

	public function renderFields(): void {
		?>
		<h2><?php esc_html_e( 'Login Attempt Limiter', 'penalis-login' ); ?></h2>
		<p><?php esc_html_e( 'Limit the number of failed login attempts per IP address and username. After the threshold is reached, the IP is temporarily locked out.', 'penalis-login' ); ?></p>
		<table class="form-table" role="presentation"><tbody>
			<tr>
				<th scope="row"><?php esc_html_e( 'Enable Rate Limiting', 'penalis-login' ); ?></th>
				<td><?php $this->renderAttemptLimiterEnabledField(); ?></td>
			</tr>
			<tr>
				<th scope="row"><label for="penalis_max_attempts"><?php esc_html_e( 'Max Failed Attempts', 'penalis-login' ); ?></label></th>
				<td><?php $this->renderMaxAttemptsField(); ?></td>
			</tr>
			<tr>
				<th scope="row"><label for="penalis_window_minutes"><?php esc_html_e( 'Time Window', 'penalis-login' ); ?></label></th>
				<td><?php $this->renderWindowMinutesField(); ?></td>
			</tr>
			<tr>
				<th scope="row"><label for="penalis_lockout_minutes"><?php esc_html_e( 'Lockout Duration', 'penalis-login' ); ?></label></th>
				<td><?php $this->renderLockoutMinutesField(); ?></td>
			</tr>
		</tbody></table>

		<h2><?php esc_html_e( 'Login Notification', 'penalis-login' ); ?></h2>
		<p><?php esc_html_e( 'Receive an email alert when suspicious login activity is detected from a single IP address.', 'penalis-login' ); ?></p>
		<table class="form-table" role="presentation"><tbody>
			<tr>
				<th scope="row"><?php esc_html_e( 'Enable Email Alerts', 'penalis-login' ); ?></th>
				<td><?php $this->renderNotifyEnabledField(); ?></td>
			</tr>
			<tr>
				<th scope="row"><label for="penalis_notify_email"><?php esc_html_e( 'Alert Email Address', 'penalis-login' ); ?></label></th>
				<td><?php $this->renderNotifyEmailField(); ?></td>
			</tr>
			<tr>
				<th scope="row"><label for="penalis_notify_threshold"><?php esc_html_e( 'Alert Threshold', 'penalis-login' ); ?></label></th>
				<td><?php $this->renderNotifyThresholdField(); ?></td>
			</tr>
		</tbody></table>

		<h2><?php esc_html_e( 'IP Access Control', 'penalis-login' ); ?></h2>
		<p><?php esc_html_e( 'Control which IP addresses can access the login page. Use blocklist mode to deny specific IPs, or allowlist mode to restrict access to trusted IPs only.', 'penalis-login' ); ?></p>
		<table class="form-table" role="presentation"><tbody>
			<tr>
				<th scope="row"><?php esc_html_e( 'Enable IP Access Control', 'penalis-login' ); ?></th>
				<td><?php $this->renderIpAccessEnabledField(); ?></td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Mode', 'penalis-login' ); ?></th>
				<td><?php $this->renderIpModeField(); ?></td>
			</tr>
		</tbody></table>
		<?php
	}

	/**
	 * Renders the IP blocklist and allowlist as textareas (one IP per line).
	 * Called inside the main settings <form> — no nested form issue.
	 */
	public function renderIpSection(): void {
		$blocklist = $this->ipRepo->getIpList( IpRulesRepository::TYPE_BLOCK );
		$allowlist = $this->ipRepo->getIpList( IpRulesRepository::TYPE_ALLOW );
		?>
		<table class="form-table" role="presentation"><tbody>
			<tr>
				<th scope="row">
					<label for="penalis_ip_blocklist"><?php esc_html_e( 'Blocked IPs', 'penalis-login' ); ?></label>
				</th>
				<td>
					<textarea
						id="penalis_ip_blocklist"
						name="penalis_ip_blocklist"
						rows="6"
						class="large-text code penalis-ip-textarea"
						placeholder="192.168.1.1&#10;10.0.0.1&#10;203.0.113.0"
						spellcheck="false"
					><?php echo esc_textarea( implode( "\n", $blocklist ) ); ?></textarea>
					<p class="description">
						<?php esc_html_e( 'One IP address per line. Inline comments are supported: 192.168.1.1 # office router. These IPs will be denied access to the login page.', 'penalis-login' ); ?>
					</p>
				</td>
			</tr>
			<tr>
				<th scope="row">
					<label for="penalis_ip_allowlist"><?php esc_html_e( 'Allowed IPs', 'penalis-login' ); ?></label>
				</th>
				<td>
					<textarea
						id="penalis_ip_allowlist"
						name="penalis_ip_allowlist"
						rows="6"
						class="large-text code penalis-ip-textarea"
						placeholder="192.168.1.100&#10;10.0.0.50"
						spellcheck="false"
					><?php echo esc_textarea( implode( "\n", $allowlist ) ); ?></textarea>
					<p class="description">
						<?php esc_html_e( 'One IP address per line. Inline comments are supported: 192.168.1.100 # my office. Only these IPs will be allowed when Allowlist mode is active.', 'penalis-login' ); ?>
					</p>
					<?php if ( empty( $allowlist ) && 'allowlist' === (string) $this->getProtectionSetting( 'ip_mode' ) ) : ?>
						<div class="penalis-field-note penalis-field-note-warning" style="margin-top:8px; max-width:680px;">
							<span><span class="dashicons dashicons-warning" aria-hidden="true"></span> <?php esc_html_e( 'Allowlist mode is active but the list is empty — no one will be blocked. Add at least one IP before relying on this mode.', 'penalis-login' ); ?></span>
						</div>
					<?php endif; ?>
				</td>
			</tr>
		</tbody></table>

		<h2><?php esc_html_e( 'Trusted Proxies', 'penalis-login' ); ?></h2>
		<p><?php esc_html_e( 'If your site is behind a reverse proxy or Cloudflare, configure trusted proxy IPs here so rate limiting and IP access control use the real visitor IP instead of the proxy IP.', 'penalis-login' ); ?></p>
		<table class="form-table" role="presentation"><tbody>
			<tr>
				<th scope="row"><?php esc_html_e( 'Enable Trusted Proxies', 'penalis-login' ); ?></th>
				<td><?php $this->renderTrustedProxiesEnabledField(); ?></td>
			</tr>
			<tr>
				<th scope="row"><label for="penalis_trusted_proxies"><?php esc_html_e( 'Proxy IP Addresses', 'penalis-login' ); ?></label></th>
				<td><?php $this->renderTrustedProxiesField(); ?></td>
			</tr>
		</tbody></table>
		<?php
	}

	// -------------------------------------------------------------------------
	// Attempt Limiter fields
	// -------------------------------------------------------------------------

	private function renderAttemptLimiterEnabledField(): void {
		$val = $this->getProtectionSetting( 'attempt_limiter_enabled' );
		?>
		<label for="penalis_attempt_limiter_enabled">
			<input type="checkbox" id="penalis_attempt_limiter_enabled"
				name="<?php echo esc_attr( Helpers::OPTION_KEY ); ?>[protection][attempt_limiter_enabled]"
				value="1" <?php checked( (bool) $val ); ?> />
			<?php esc_html_e( 'Block IPs that exceed the failed attempt threshold', 'penalis-login' ); ?>
		</label>
		<?php
	}

	private function renderMaxAttemptsField(): void {
		$val = (int) $this->getProtectionSetting( 'max_attempts' );
		?>
		<input type="number" id="penalis_max_attempts"
			name="<?php echo esc_attr( Helpers::OPTION_KEY ); ?>[protection][max_attempts]"
			value="<?php echo esc_attr( (string) $val ); ?>" min="1" max="100" class="small-text" />
		<p class="description"><?php esc_html_e( 'Number of failed attempts before a lockout is triggered.', 'penalis-login' ); ?></p>
		<?php
	}

	private function renderWindowMinutesField(): void {
		$val = (int) $this->getProtectionSetting( 'window_minutes' );
		?>
		<input type="number" id="penalis_window_minutes"
			name="<?php echo esc_attr( Helpers::OPTION_KEY ); ?>[protection][window_minutes]"
			value="<?php echo esc_attr( (string) $val ); ?>" min="1" max="1440" class="small-text" />
		<span class="description"><?php esc_html_e( 'minutes', 'penalis-login' ); ?></span>
		<p class="description"><?php esc_html_e( 'Failed attempts are counted within this rolling time window.', 'penalis-login' ); ?></p>
		<?php
	}

	private function renderLockoutMinutesField(): void {
		$val = (int) $this->getProtectionSetting( 'lockout_minutes' );
		?>
		<input type="number" id="penalis_lockout_minutes"
			name="<?php echo esc_attr( Helpers::OPTION_KEY ); ?>[protection][lockout_minutes]"
			value="<?php echo esc_attr( (string) $val ); ?>" min="1" max="10080" class="small-text" />
		<span class="description"><?php esc_html_e( 'minutes', 'penalis-login' ); ?></span>
		<p class="description"><?php esc_html_e( 'How long a locked-out IP must wait before trying again.', 'penalis-login' ); ?></p>
		<?php
	}

	// -------------------------------------------------------------------------
	// Notification fields
	// -------------------------------------------------------------------------

	private function renderNotifyEnabledField(): void {
		$val = $this->getProtectionSetting( 'notify_enabled' );
		?>
		<label for="penalis_notify_enabled">
			<input type="checkbox" id="penalis_notify_enabled"
				name="<?php echo esc_attr( Helpers::OPTION_KEY ); ?>[protection][notify_enabled]"
				value="1" <?php checked( (bool) $val ); ?> />
			<?php esc_html_e( 'Send an email alert when the threshold is reached', 'penalis-login' ); ?>
		</label>
		<?php
	}

	private function renderNotifyEmailField(): void {
		$val         = (string) $this->getProtectionSetting( 'notify_email' );
		$admin_email = get_option( 'admin_email' );
		?>
		<input type="email" id="penalis_notify_email"
			name="<?php echo esc_attr( Helpers::OPTION_KEY ); ?>[protection][notify_email]"
			value="<?php echo esc_attr( $val ); ?>" class="regular-text"
			placeholder="<?php echo esc_attr( $admin_email ); ?>" />
		<p class="description">
			<?php printf(
				esc_html__( 'Leave blank to use the site admin email (%s).', 'penalis-login' ),
				'<code>' . esc_html( $admin_email ) . '</code>'
			); ?>
		</p>
		<?php
	}

	private function renderNotifyThresholdField(): void {
		$val = (int) $this->getProtectionSetting( 'notify_threshold' );
		?>
		<input type="number" id="penalis_notify_threshold"
			name="<?php echo esc_attr( Helpers::OPTION_KEY ); ?>[protection][notify_threshold]"
			value="<?php echo esc_attr( (string) $val ); ?>" min="1" max="100" class="small-text" />
		<p class="description"><?php esc_html_e( 'Send an alert when this many failed attempts are detected from a single IP within the time window.', 'penalis-login' ); ?></p>
		<?php
	}

	// -------------------------------------------------------------------------
	// IP Access Control fields
	// -------------------------------------------------------------------------

	private function renderIpAccessEnabledField(): void {
		$val = $this->getProtectionSetting( 'ip_access_enabled' );
		?>
		<label for="penalis_ip_access_enabled">
			<input type="checkbox" id="penalis_ip_access_enabled"
				name="<?php echo esc_attr( Helpers::OPTION_KEY ); ?>[protection][ip_access_enabled]"
				value="1" <?php checked( (bool) $val ); ?> />
			<?php esc_html_e( 'Enable IP-based access control for the login page', 'penalis-login' ); ?>
		</label>
		<?php
	}

	private function renderIpModeField(): void {
		$val = (string) $this->getProtectionSetting( 'ip_mode' );
		?>
		<fieldset>
			<label>
				<input type="radio"
					name="<?php echo esc_attr( Helpers::OPTION_KEY ); ?>[protection][ip_mode]"
					value="blocklist" <?php checked( $val, 'blocklist' ); ?> />
				<?php esc_html_e( 'Blocklist — deny specific IPs', 'penalis-login' ); ?>
			</label>
			<br />
			<label>
				<input type="radio"
					name="<?php echo esc_attr( Helpers::OPTION_KEY ); ?>[protection][ip_mode]"
					value="allowlist" <?php checked( $val, 'allowlist' ); ?> />
				<?php esc_html_e( 'Allowlist — only allow specific IPs', 'penalis-login' ); ?>
			</label>
		</fieldset>
		<div class="penalis-field-note penalis-field-note-warning" style="margin-top:8px; max-width:680px;">
			<span><span class="dashicons dashicons-warning" aria-hidden="true"></span> <?php esc_html_e( 'Allowlist mode will deny everyone not on the list, including you. Make sure your own IP is added before enabling this mode.', 'penalis-login' ); ?></span>
		</div>
		<?php
	}

	// -------------------------------------------------------------------------
	// Trusted Proxies fields
	// -------------------------------------------------------------------------

	private function renderTrustedProxiesEnabledField(): void {
		$val = $this->getProtectionSetting( 'trusted_proxies_enabled' );
		?>
		<label for="penalis_trusted_proxies_enabled">
			<input type="checkbox" id="penalis_trusted_proxies_enabled"
				name="<?php echo esc_attr( Helpers::OPTION_KEY ); ?>[protection][trusted_proxies_enabled]"
				value="1" <?php checked( (bool) $val ); ?> />
			<?php esc_html_e( 'Trust proxy headers (X-Forwarded-For, CF-Connecting-IP, X-Real-IP) from the IPs listed below', 'penalis-login' ); ?>
		</label>
		<div class="penalis-field-note penalis-field-note-warning" style="margin-top:8px; max-width:680px;">
			<span><span class="dashicons dashicons-warning" aria-hidden="true"></span> <?php esc_html_e( 'Only enable this if your site is behind a reverse proxy. Enabling it without adding the correct proxy IPs below will make IP-based security features unreliable.', 'penalis-login' ); ?></span>
		</div>
		<?php
	}

	private function renderTrustedProxiesField(): void {
		$val = (string) $this->getProtectionSetting( 'trusted_proxies' );
		?>
		<textarea
			id="penalis_trusted_proxies"
			name="<?php echo esc_attr( Helpers::OPTION_KEY ); ?>[protection][trusted_proxies]"
			rows="4"
			class="large-text code penalis-ip-textarea"
			placeholder="103.21.244.0 # Cloudflare&#10;103.22.200.0 # Cloudflare&#10;127.0.0.1 # local Nginx"
			spellcheck="false"
		><?php echo esc_textarea( $val ); ?></textarea>
		<p class="description">
			<?php esc_html_e( 'One IP address per line. Inline comments supported. Only requests arriving from these IPs will have their proxy headers trusted.', 'penalis-login' ); ?>
		</p>
		<?php
	}

	// -------------------------------------------------------------------------
	// Helper
	// -------------------------------------------------------------------------

	private function getProtectionSetting( string $key ): mixed {
		return $this->helpers->getProtectionSettings()[ $key ] ?? null;
	}
}
