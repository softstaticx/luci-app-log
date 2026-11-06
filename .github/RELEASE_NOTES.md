# luci-app-log v4.0.1

OpenWrt 25.12 patch release. The package name remains `luci-app-log-viewer`.

## Why this release exists

On a default 4.0.0 install the GeoIP update did not work: the updater exited
before downloading anything, and the page still said "Applied. Databases are
ready." There were two causes and one misleading symptom.

- The updater's UCI loader ended with `[ -n "$v" ] && VAR="$v"`. The shipped
  `sha256_country` and `sha256_asn` options are empty, so the function returned
  1 and `set -e` ended the script silently.
- The lock line used `exec 9>"$LOCK" 2>/dev/null`. A redirection-only `exec`
  applies its redirections to the whole shell, so every later error message was
  written to `/dev/null`.
- cgi-io always answers `200 OK` for `cgi-exec`, even when the command fails.
  The page trusted the resolved promise, so failures looked like success.

## What changed

- GeoIP update works again on a fresh install, with the empty checksum options
  that ship by default.
- Failed updates now say why: the modal shows the updater's message and output,
  and the installer prints it too.
- Settings saves, history changes, clearing history and **Re-apply rules** now
  verify what the router actually returned instead of assuming success.
- `flint4-geoip` and the 3.x history migration no longer abort when an optional
  UCI value is missing.
- The shell test suite executes the updater for real: empty options, failed
  download, checksum mismatch, and a router without a `geoip` section.

## Upgrading

```sh
uclient-fetch -qO- https://raw.githubusercontent.com/softstaticx/luci-app-log/main/install-online.sh | sh
```

or:

```sh
apk add --upgrade ./reffix-luci-app-log-viewer-openwrt-25.12.apk
```

No configuration changes. Settings, ports, WAN zone and history are preserved.

## After upgrading

Open **Status → Firewall Log → Settings → Files → Update GeoIP databases**.
It should now complete and show the database sizes. If it still fails, the
dialog shows the updater's own error instead of a false success; the same text
is in `/tmp/log-viewer/geoip-update.status`.

If `mmdblookup` is missing, install it first:

```sh
apk add libmaxminddb
```

GeoLite2 databases are not in the APK. See the README for the MaxMind EULA.
