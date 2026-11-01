# Changelog

## v3.3.5 (2026-11-01)

- Stop the low-rate other-port sample by default. The watch now logs only ports on the configured list, and they remain Blocked unless an allow or forward applies.
- Make other-port sampling opt-in with **Settings → WAN watch settings → Also sample other ports**. Existing configurations default to off.
- Default the table, chips, and insights to **Known ports only**, so old other-port samples do not flood the page. Choose **All verdict types** to inspect them.
- Add migration-safe defaults for existing `/etc/config/infra-port-watch` files and preserve the sample setting when adding a port or importing settings.

## v3.3.4 (2026-11-01)

- Click a source IP to open a detail drawer with all events in view, ports, first/last seen, reverse DNS, copy IP/log line, and one-click port-watch actions.
- Sort the table by time, source, country, or destination port, and filter with quick chips for verdict, country, ASN, and port.
- Add **Browse router history**, a server-side query dialog with filtering, sorting, and pagination, plus an opt-in persistent history store on disk or USB.
- Replace the 15-second full `logread -l 1500` rescan with a `logread -f` stream, incremental ring updates, and optional batched daily history files.
- Show GeoIP download, validation, and apply progress in a dialog and refresh the database age when it completes.
- Reinstall same-version packages with `apk add --force-reinstall` when supported, avoiding `apk del` removing auto-installed dependencies.

## v3.3.3 (2026-11-01)

- Fix the **Details**, settings-import, and port-forward review dialogs opening on LuCI 25.12. They now use `ui.showModal(title, content, ...classes)` and keep their action buttons inside the content.
- Redesign the **WAN watch settings** dialog with a status summary, labelled two-column layout, inline validation, sticky actions, and no more `undefined` fields.
- Treat an empty or malformed WAN status response as unavailable instead of reporting a disabled watch with zero ports.
- Keep the event-details lookup stable across live refreshes.

## v3.3.2 (2026-11-01)

- Fix the online installer failing with `has no package version` on OpenWrt 25.12. APK v3 packages are ADB archives, not gzipped tarballs, so the installer now reads `info.version` through `apk adbdump` and keeps the tarred `.PKGINFO` fallback for APK v2.
- Initialize the `/lib/functions.sh` config globals before loading the firewall config, so package post-install starts the WAN watch instead of aborting with `CONFIG_LIST_STATE: parameter not set`.
- Rename the README and GitHub release title to `luci-app-log`; the package remains `luci-app-log-viewer`.

## v3.3.1 (2026-10-31)

- Running the installer again upgrades an older `luci-app-log-viewer` and replaces the same release. A newer installed copy is left alone. The saved `/etc/config/infra-port-watch` stays.

## v3.3.0 (2026-10-31)

- Depend on `iptables-mod-hashlimit` so each source address gets its own WAN log budget. If the match still cannot be loaded, the watch falls back to one shared limit and the status line says so.
- Add **Add missing default ports** in the WAN editor. It appends shipped defaults that are not already in the list and leaves saved ports in place. Save settings to apply the change.
- Add **Update GeoIP databases** under Settings → Files. It runs `/usr/bin/flint4-geoip-update` on the router and refreshes the database age.

## v3.2.1 (2026-10-31)

- Drop the Firewall Log type one step: table and fields are 13px, buttons are 13px, and the summary numbers are 22px. Column titles stay pinned while the log scrolls.
- Add **Log this port at the full budget** to the details of an Other event. It appends that destination port to the known list and restarts the watch. A port already on the list is left as it is, and a 257th port is refused.

## v3.2.0 (2026-10-31)

- Give each source address its own WAN log budget: 30 per minute after a burst of 15 on a known port, 4 per minute after a burst of 4 when that port is also an enabled firewall forward, and 2 per minute after a burst of 5 for every other port. Listed ports use iptables goto so they are not logged again by the other-port chain. If hashlimit is missing, the same rates fall back to one shared limit. The watch still only logs IPv4 TCP SYN and UDP, then returns the packet.
- Classify a known-port probe with no allow and no forward as **Blocked**, subtitle **Default deny**. Classify a port outside the list as **Other**, subtitle **Not on the watch list**. Add TR-069 (7547), MikroTik (8291), MQTT TLS (8883), kubelet (10250), and WireGuard (51820) to the default list. An upgrade keeps the saved UCI port list; those five ports apply to a new install or an empty list. The other-port sample runs either way.
- Look up GeoIP in one `flint4-geoip --batch` call per chunk. Remember positive hits in the browser for 7 days. Reload WAN watch status about once a minute instead of on every 15-second log tick.
- Keep up to 500 firewall lines, including `INFRA_PORT_OTHER`, in `/tmp/log-viewer/events.ring`. `log-viewer-history` updates that ring every 15 seconds and is enabled with the package. The ring is cleared on reboot. Browser history is unchanged.
- Group Settings into WAN watch, exposed labels, history, and files. Saved filters stay on the toolbar. An insight filter names what its clear button removes. The page does not offer LuCI Save & Apply.

## v3.1.3 (2026-10-30)

- Grant LuCI exec access to `/usr/sbin/infra-port-watch-config` itself. An ACL entry of `infra-port-watch-config set` does not match the real command line, which also carries the interface and port list, and rpcd rejects argument strings longer than 1024 bytes before the pattern is tested. Saving WAN watch settings from the page failed with access denied.
- Read log lines from ubus `log.read`, then fall back to `logread` including `/usr/libexec/logread-ubox`. OpenWrt 25.12 installs logread at that path, and LuCI `file.exec` keeps only about 256 KiB, so a 1,500-line `logread` tail could drop the newest events.
- Re-apply the WAN watch when interface `wan` comes up, so a boot before PPPoE or DHCP has a device still installs the log rule.
- Keep `infra-port-watch get` working when `/etc/config/firewall` is missing, instead of exiting before it prints status JSON.
- Restart `rpcd` and clear the LuCI menu cache from the package postinst. Copy country flags, the policy example, and the WAN hotplug hook from `install.sh`.
- Download CSV and settings exports by clicking a link attached to the document, so browsers that ignore detached anchors still save the file.
- Depend on `luci-base` and `logd`.

## v3.1.1

- Fixes WAN watcher startup on OpenWrt 25.12 when `IPKG_INSTROOT` is unset during package post-upgrade.

## v3.1.0

- Classifies configured `INFRA_PORT_HIT` WAN watchlist entries as Blocked and clarifies default-deny behavior.
- Adds clickable source, burst and destination-port insights, expandable repeated-probe groups, and a collapsible Insights panel.
- Adds a router-configurable WAN interface and browser-local exposed-service labels to distinguish hits matching configured forwards.
- Packages and enables a rate-limited, log-only WAN port watch with the existing Flint4 defaults; its interface and up to 256 ports are configurable from the Firewall Log UI.
- Adds router-timezone-aware event filtering, a selectable activity timeline, and IPv4-only watcher status.
- Adds browser-local optional history with retention and a 10,000-event cap, plus reviewed firewall-forward label imports and portable settings files.
- Bounds log-group and expanded-row rendering pages and caches local history in memory between refreshes.
- Improves filter and file-import accessibility, reports the 1,500-source-line limit, and retains the theme unchanged.

## v3.0.0

- Makes Firewall Log the only page and renames the Status menu entry to Firewall Log.
- Removes the System Log and Kernel Log views and their unused RPC access.

## v2.1.0

- Verifies both APK downloads against the published SHA-256 file before package installation.
- Documents OpenWrt 25.12 and supported MediaTek Filogic snapshot installation.
- Adds browser-local filter presets, event details, filtered/all-loaded CSV export, formula-safe CSV cells, and opt-in external reputation links.
- Reports the loaded log window and GeoIP database age, and supports loading more matching rows.
- Avoids repeat parsing of unchanged logs and duplicate Firewall Log style injection; GeoIP lookups run after the log table is rendered and unavailable results are briefly cached.
- Removes the unreferenced root screenshot assets while retaining the documented developer examples and required upstream license notices.

## v2.0.0

- Establishes REFFIX's own v2 release line.
- Reduces Firewall Log typography by one step across the event table, toolbar, statistics and insight panels.
- Prevents destination IP addresses from wrapping inside table cells.
- Makes the online installer fall back to GitHub release assets when the raw-content package index cannot be fetched.
- Keeps the existing `luci-app-log-viewer` package identity for in-place upgrades.

- Restricts package builds and online installation to OpenWrt 25.12 / APK only.
- Release pipeline removes legacy releases, tags and old package-mirror directories after publishing v2.0.0.
