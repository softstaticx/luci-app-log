# luci-app-log v4.0.2

OpenWrt 25.12 patch release. The package name remains `luci-app-log-viewer`.

## Why this release exists

After 4.0.1 the updater works, but the page could still show **GeoIP unavailable**
on every row while one old row kept its country. That happens when the native
lookup helper produces no output: the wrapper used to `exec` it, so a broken or
missing helper turned every address into a silent miss, and the page could not
tell "no data" from "GeoIP is not set up".

## What changed

- The wrapper now captures the helper's output and falls back to `mmdblookup(1)`
  for the batch when it is empty. A broken helper costs speed, not data.
- No databases installed? The page says **GeoIP off** and shows a banner with an
  **Update GeoIP databases** button, instead of leaving every row blank.
- Failing lookups are reported once with the real reason instead of being cached
  as empty.
- A successful update clears the empty cache and fills the table immediately.

## If you still see GeoIP off

1. Upgrade to 4.0.2.
2. **Settings → Files → Update GeoIP databases** (or the banner button).
3. If it reports a failure, the dialog now shows the reason, and the same text is
   in `/tmp/log-viewer/geoip-update.status`.

Quick check from a shell:

```sh
/usr/bin/flint4-geoip --status
/usr/bin/flint4-geoip --batch 8.8.8.8
ls -l /usr/share/GeoIP
```

`--status` must report `"available":true` and the batch must return a line with
a `country_code`. If the batch is empty, `mmdblookup` is missing
(`apk add libmaxminddb`) or the databases are absent (run the update).

## Upgrading

```sh
uclient-fetch -qO- https://raw.githubusercontent.com/softstaticx/luci-app-log/main/install-online.sh | sh
```

No configuration changes. Settings, ports, WAN zone and history are preserved.

GeoLite2 databases are not in the APK. See the README for the MaxMind EULA.
