# luci-app-log v3.3.5

OpenWrt 25.12 release. The package name remains `luci-app-log-viewer`. IPv4 only.

## This release

The WAN watch now logs **only the configured port list** by default. The low-rate sample of every other WAN port is off unless you enable **Settings → WAN watch settings → Also sample other ports**. Existing routers default to off.

The page opens with **Known ports only** selected, so previous other-port samples no longer flood the table, chips, or insights. Choose **All verdict types** when you want to inspect them. Ports on the watch list are classified **Blocked** unless a label or allow rule applies.

The v3.3.4 features remain: source detail drawer, sorting and filter chips, router-side history browsing and pagination, opt-in persistent history, visible GeoIP update progress, streamed `logread -f` collection, and dependency-safe same-version reinstalls.

The package depends on `iptables-mod-hashlimit`, so each source address keeps its own log budget. If the match cannot be loaded, the watch falls back to one shared limit and the status line says so.

**Settings → WAN watch settings → Add missing default ports** appends shipped defaults that are missing from the saved list, including TR-069 (7547), MikroTik (8291), MQTT TLS (8883), kubelet (10250), and WireGuard (51820). Saved ports stay. Choose **Save settings** to apply them. The list still stops at 256 ports.

**Settings → Files → Update GeoIP databases** downloads fresh Country and ASN databases on the router.

## WAN watch

Each source address has its own log budget:

- Known ports: 30 per minute after a burst of 15.
- A known port that is also an enabled firewall forward: 4 per minute after a burst of 4.
- Any other port: 2 per minute after a burst of 5.

Listed ports jump to their log chain with goto. Both chains only log, then return the packet.

**Blocked** is a known-port probe with no allow and no forward. **Other** is the low-rate sample of a port that is not on the list. **Details** on an Other row can add that port to the known list.

GeoLite2 databases are not in the APK. See the README before sharing them.
