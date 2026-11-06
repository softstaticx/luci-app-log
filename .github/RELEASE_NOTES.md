# luci-app-log v4.0.5

OpenWrt 25.12 patch release. The package name remains `luci-app-log-viewer`.

## What changed

Destination IP addresses no longer break across lines. The 4.0.0 theme rewrite
dropped the `nowrap` rules for the destination column, so `overflow-wrap`
split `5.103.97.94` into `5.103.97.9` and a lonely `4`.

- Destination addresses, source addresses, ports and timestamps stay on one
  line.
- The mobile card layout no longer re-enables wrapping for the destination.
- A regression test covers the rules; the table was rendered and checked before
  this release.

## Upgrading

```sh
uclient-fetch -qO- https://raw.githubusercontent.com/softstaticx/luci-app-log/main/install-online.sh | sh
```

Then **hard-refresh the page** (Ctrl+F5 / Cmd+Shift+R) so the browser picks up
the new `firewall.css`.

No configuration changes. Settings, ports, WAN zone and history are preserved.

GeoLite2 databases are not in the APK. See the README for the MaxMind EULA.
