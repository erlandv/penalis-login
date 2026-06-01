=== Penalis Login ===
Contributors: penalis
Tags: login, security, custom login url, hide login, brute force
Requires at least: 6.4
Tested up to: 6.7
Requires PHP: 8.1
Stable tag: 2.1.1
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Hides the default WordPress login URL and adds optional security features to protect against brute force attacks.

== Description ==

Penalis Login replaces the default WordPress login URL (`/wp-login.php`) with a custom slug of your choice. Direct access to `/wp-login.php` is blocked with a configurable response (404, 403, or redirect). Guest access to `/wp-admin/` is also configurable.

The plugin is organized into three tabs:

**General** — always active:

* Custom login slug (default: `/login/`)
* Blocks direct access to `/wp-login.php` (404, 403, or redirect to homepage)
* Configurable guest access behavior for `/wp-admin/` (redirect to login, redirect to homepage, 404, or 403)
* Filters all WordPress-generated login/logout/lost-password/register URLs
* Anti-lockout: logged-in administrators can always access `/wp-login.php` and `/wp-admin/` directly
* Compatible with WooCommerce, REST API, XML-RPC, admin-ajax, and application passwords

**Protection** — optional, all features disabled by default:

* Login Attempt Limiter — rate limits failed login attempts per IP and username; locks out offending IPs temporarily (HTTP 429)
* Login Notification — sends an email alert when suspicious activity is detected from a single IP
* IP Access Control — blocklist specific IPs, or restrict access to an allowlist of trusted IPs only
* Trusted Proxies — configure trusted reverse proxy IPs (Cloudflare, Nginx) so security features use the real visitor IP

**Activity Log** — always active:

* Records every login attempt (success, failure, blocked by rate limit, blocked by IP rule)
* Stores IP address, username, HTTP method, referrer, user agent, and timestamp
* Viewable in the Activity Log tab with pagination and one-click log clearing
* Configurable log retention — automatically prune records older than N days via daily cron (0 = keep forever)

== Installation ==

1. Upload the `penalis-login` folder to `/wp-content/plugins/`
2. Activate the plugin through Plugins → Installed Plugins
3. Go to Settings → Penalis Login to configure

== Frequently Asked Questions ==

= Will this break my site? =

No. The plugin uses WordPress's native rewrite rules and includes `wp-login.php` directly, so all authentication logic remains intact.

= What if I forget my custom login slug? =

Logged-in administrators can always access `/wp-login.php` and `/wp-admin/` directly regardless of plugin settings. If you are locked out, deactivate the plugin via FTP by renaming the plugin folder.

= Is this compatible with WooCommerce? =

Yes. The plugin does not interfere with WooCommerce's My Account login form or its authentication flows.

= Can an attacker bypass rate limiting by forging IP headers? =

Not by default. The plugin only reads `REMOTE_ADDR` (which cannot be spoofed) unless you explicitly configure trusted proxy IPs in the Protection tab. Proxy headers are only trusted when the actual connecting IP matches a listed trusted proxy.

= Does the plugin create database tables? =

Yes. Two custom tables are created on activation: one for the login activity log and one for IP rules. They are removed when the plugin is deleted if the "Delete Plugin Data" setting is enabled.

== Changelog ==

= 2.1.1 =
* Fix: Replaced unicode symbol characters (✓ ✗ ⚠) with Dashicons in admin status indicators and warning messages for better accessibility and screen reader compatibility.

= 2.1.0 =
* New: Activity log now records HTTP method (GET/POST) and referrer for each login event, making it easier to distinguish browser logins from bot probes.
* New: Log Retention setting in the Activity Log tab — automatically delete records older than a configurable number of days via daily WordPress cron. Set to 0 to keep records forever (default: 30 days).
* Fix: Blocked login attempts are now correctly logged to the activity log when an IP is locked out at the page level (HTTP 429), including the username from the submitted form if available.
* Fix: Save Settings button in the Activity Log tab was unresponsive due to a nested HTML form conflict with the Clear Log button. Both forms are now properly separated.

= 2.0.0 =
* New: Login Attempt Limiter — rate limits failed login attempts per IP and username with configurable thresholds and lockout duration. Locked-out IPs receive HTTP 429 and cannot access the login page until the lockout expires.
* New: Login Notification — sends an email alert to the admin when a configurable number of failed attempts is detected from a single IP within the time window.
* New: IP Access Control — blocklist specific IPs from the login page, or switch to allowlist mode to restrict access to trusted IPs only. IP lists support inline comments (`192.168.1.1 # office`).
* New: Trusted Proxies — configure trusted reverse proxy IPs so rate limiting and IP access control use the real visitor IP instead of the proxy IP. Proxy headers are only trusted when `REMOTE_ADDR` matches a listed proxy, preventing IP spoofing attacks.
* New: Activity Log — records every login event (success, failure, blocked by rate limit, blocked by IP rule) with IP address, username, user agent, and timestamp. Viewable in a dedicated tab with pagination and log clearing.
* New: Settings page redesigned with three tabs — General, Protection, and Activity Log.
* New: Reset to Defaults button on both General and Protection tabs.
* New: Custom database tables for activity log and IP rules, created automatically on activation.
* Fix: Locked-out IPs now see HTTP 429 immediately when accessing the login page, not just on form submission.
* Fix: IP spoofing prevention — proxy headers are only trusted when explicitly configured via Trusted Proxies settings.
* Fix: All plugin transients (including lockout entries) are now cleaned up on uninstall.

= 1.1.0 =
* New: Added configurable guest access behavior for `/wp-admin/` — choose between redirect to custom login URL, redirect to homepage, 404 Not Found (stealth mode), or 403 Forbidden.
* New: Added "Reset to Defaults" button on the settings page.
* New: Settings page UI redesigned with option cards and behavior lists.
* Fix: REST endpoint is now registered even when the plugin is disabled, preventing silent failures in Nginx `auth_request` configurations.
* Fix: Password reset keys are now validated against the database before allowing access to `/wp-login.php`.

= 1.0.0 =
* Initial release.
