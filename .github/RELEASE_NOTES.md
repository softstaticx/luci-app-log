# luci-app-log v3.3.4

OpenWrt 25.12 release. The package name remains `luci-app-log-viewer`. IPv4 only.

## This release

Click any **source IP** to open a detail drawer: all events in view, ports, first/last seen, reverse DNS, copy actions, and one-click “watch this port.” The toolbar now sorts by time, source, country, or port, and quick chips filter by verdict, country, ASN, or port.

**Browse router history** reads the router ring and opt-in disk history in pages. Filtering, sorting, and pagination happen on the router, so large histories no longer have to fit in the browser. Enable **Persistent history settings** to write daily files to a mounted disk or USB path with a retention period and size cap; it is off by default.

The background collector now streams `logread -f` and appends only new firewall lines. It no longer rescans the last 1,500 log lines every 15 seconds; the page reads the cheap status and ring instead of triggering another scan.

**Update GeoIP databases** now shows download, validation, and apply phases, including the downloaded sizes, and refreshes the database age when it finishes.

The installer reinstalls the same release with `apk add --force-reinstall` where available, so auto-installed dependencies such as the hashlimit modules are not removed first.

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
