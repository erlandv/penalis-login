=== Penalis Login ===
Contributors: penalis
Tags: login, security, custom login url, hide login, wp-login
Requires at least: 6.4
Tested up to: 6.7
Requires PHP: 8.1
Stable tag: 1.0.0
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Hides and customizes the default WordPress login URL for enhanced security.

== Description ==

Penalis Login replaces the default WordPress login URL (`/wp-login.php`) with a custom slug of your choice. Direct access to `/wp-login.php` is blocked with a configurable response (404, 403, or redirect).

**Features:**

* Custom login slug (default: `/login/`)
* Blocks direct access to `/wp-login.php`
* Filters all WordPress-generated login/logout/lost-password/register URLs
* Anti-lockout: logged-in administrators can always access `/wp-login.php`
* Compatible with WooCommerce, REST API, XML-RPC, and admin-ajax
* Settings page under Settings → Penalis Login

== Installation ==

1. Upload the `penalis-login` folder to `/wp-content/plugins/`
2. Activate the plugin through Plugins → Installed Plugins
3. Go to Settings → Penalis Login to configure

== Frequently Asked Questions ==

= Will this break my site? =

No. The plugin uses WordPress's native rewrite rules and includes `wp-login.php` directly, so all authentication logic remains intact.

= What if I forget my custom login slug? =

Logged-in administrators can always access `/wp-login.php` directly. If you are locked out, deactivate the plugin via FTP by renaming the plugin folder.

= Is this compatible with WooCommerce? =

Yes. The plugin does not interfere with WooCommerce's My Account login form or its authentication flows.

== Changelog ==

= 1.0.0 =
* Initial release.
