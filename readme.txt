=== Simple IP Blocker ===
Contributors: maybebernd
Tags: ip-blocking, ip-blocklists
Requires at least: 6.1
Tested up to: 6.2
Requires PHP: 7.0
License: GPL3
License URI: https://www.gnu.org/licenses/gpl-3.0
A small plugin for creating IP blocklists. IPs can be blocked via REMOTE_ADDR or if the application runs behind a proxy via X-Forwarded-For.

== Description ==

The plugin stores all blocked ips inside two differend WordPress options. Those are the block list.
The first list ist used to block the REMOTE_ADDR IPs the second one is used to block X-Forwarded-For IPs.
The plugin adds a subpage to the main menu of the settings page.
The client IP check is done over the 'plugin_loaded' hook.
