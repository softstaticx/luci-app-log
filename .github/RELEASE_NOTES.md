# luci-app-log v4.0.3

OpenWrt 25.12 patch release. The package name remains `luci-app-log-viewer`.

## What this release is for

4.0.2 made a broken lookup helper fall back to `mmdblookup` and added a GeoIP
banner. 4.0.3 makes the remaining failures say what is wrong, instead of showing
blank rows.

- `flint4-geoip --status` now checks the country database with a real lookup and
  returns a `reason`: `no database`, `mmdblookup missing` or
  `database unreadable`. A truncated `.mmdb` is no longer reported as ready.
- Lookups without a database return an explicit error record, so the page shows
  **GeoIP off · no database** (or the matching reason) and the banner explains
  what to do.
- The test suite covers missing, corrupt and unreadable database states.

## If GeoIP is still off

Run these on the router and compare:

```sh
/usr/bin/flint4-geoip --status
/usr/bin/flint4-geoip --batch 8.8.8.8
ls -l /usr/share/GeoIP
```

| Output | Meaning | Fix |
| --- | --- | --- |
| `"available":false,"reason":"no database"` | No `.mmdb` files | Update the databases |
| `"reason":"mmdblookup missing"` | `libmaxminddb` is not installed | `apk add libmaxminddb` |
| `"reason":"database unreadable"` | A file is truncated or corrupt | Update the databases again |
| `"available":true` but the batch line has `"error"` | The helper could not read the files | Update the databases; the wrapper falls back to `mmdblookup` |
| Batch prints `country_code` | Lookups work; reload the page | — |

The last update message is always in `/tmp/log-viewer/geoip-update.status`.

## Upgrading

```sh
uclient-fetch -qO- https://raw.githubusercontent.com/softstaticx/luci-app-log/main/install-online.sh | sh
```

No configuration changes. Settings, ports, WAN zone and history are preserved.

GeoLite2 databases are not in the APK. See the README for the MaxMind EULA.
