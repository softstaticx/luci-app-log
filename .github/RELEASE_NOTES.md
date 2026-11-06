# luci-app-log v4.0.4

OpenWrt 25.12 patch release. The package name remains `luci-app-log-viewer`.

## The bug

If the page showed

> GeoIP lookups are failing: Unexpected non-whitespace character after JSON at position 129 (line 2 column 1)

then every GeoIP lookup was being thrown away by the browser, even with valid
databases installed. The view tried to parse a whole newline-delimited batch as
a single JSON document; the check that was meant to recognise the old 3.x format
(`text.startsWith('{')`) matched every batch, and `JSON.parse` failed on the
second line. The failure was caught, cached as "no data", and every row fell
back to **GeoIP unavailable**.

This affected 4.0.0–4.0.3. It only became visible once the databases existed,
which is why the earlier fixes (updater, fallback, reasons) did not make the
columns populate.

## The fix

- The batch is parsed one line at a time and accepts both shapes: the current
  one-object-per-address output and the 3.x single object keyed by address.
- Error records are preserved so the page can explain them.
- Unit tests cover NDJSON, the 3.x payload, error records, garbage input, and an
  explicit regression test for the whole-batch case.

## Upgrading and verifying

```sh
uclient-fetch -qO- https://raw.githubusercontent.com/softstaticx/luci-app-log/main/install-online.sh | sh
```

Then **hard-refresh the page** (Ctrl+F5 / Cmd+Shift+R) so the browser drops the
cached `firewall.js`.

The GeoIP column should populate within a refresh, and the banner disappears.
From a shell:

```sh
/usr/bin/flint4-geoip --batch 8.8.8.8
```

should print one JSON line with a `country_code`. If the page still shows
GeoIP off, the status reason names the cause (`no database`,
`mmdblookup missing`, `database unreadable`) — see v4.0.3 notes.

No configuration changes. Settings, ports, WAN zone and history are preserved.

GeoLite2 databases are not in the APK. See the README for the MaxMind EULA.
