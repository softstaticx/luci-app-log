#!/bin/sh
# Installs this source overlay to an existing LuCI/OpenWrt router.
#
# This path copies files instead of using APK. The packaged GeoIP helper
# (/usr/libexec/log-viewer-geoip) is a compiled binary and is not included
# here; /usr/bin/flint4-geoip falls back to mmdblookup(1) when it is missing.
set -eu

# The CDPATH= prefix is deliberate: it keeps `cd` from printing a path.
# shellcheck disable=SC1007
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
BACKUP="/root/reffix-log-viewer-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP"

backup() {
  src="$1"
  if [ -e "$src" ]; then
    dest="$BACKUP$src"
    mkdir -p "$(dirname "$dest")"
    cp -a "$src" "$dest"
  fi
}

for path in \
  /www/luci-static/resources/view/log-viewer/firewall.js \
  /www/luci-static/resources/log-viewer/firewall.css \
  /www/luci-static/resources/log-viewer/logo.svg \
  /usr/bin/flint4-geoip \
  /usr/bin/flint4-geoip-update \
  /usr/sbin/infra-port-watch \
  /usr/sbin/infra-port-watch-config \
  /usr/sbin/log-viewer-history \
  /usr/sbin/log-viewer-query \
  /usr/sbin/log-viewer-ip \
  /usr/sbin/log-viewer-migrate \
  /etc/infra-port-watch.sh \
  /etc/init.d/infra-port-watch \
  /etc/init.d/log-viewer-history \
  /etc/config/log-viewer \
  /etc/config/infra-port-watch \
  /etc/log-viewer/policies.json \
  /usr/share/luci/menu.d/luci-app-log-viewer.json \
  /usr/share/rpcd/acl.d/luci-app-log-viewer.json \
  /etc/hotplug.d/iface/99-infra-port-watch; do
  backup "$path"
done

mkdir -p /www/luci-static/resources/view/log-viewer /www/luci-static/resources/log-viewer
mkdir -p /usr/bin /usr/sbin /etc/config /etc/init.d /etc/hotplug.d/iface
mkdir -p /usr/share/luci/menu.d /usr/share/rpcd/acl.d /usr/share/log-viewer /etc/log-viewer

cp "$ROOT/htdocs/luci-static/resources/view/log-viewer/firewall.js" /www/luci-static/resources/view/log-viewer/firewall.js
cp "$ROOT/htdocs/luci-static/resources/log-viewer/firewall.css" /www/luci-static/resources/log-viewer/firewall.css
cp "$ROOT/htdocs/luci-static/resources/log-viewer/logo.svg" /www/luci-static/resources/log-viewer/logo.svg
rm -rf /www/luci-static/resources/log-viewer/flags
cp -a "$ROOT/htdocs/luci-static/resources/log-viewer/flags" /www/luci-static/resources/log-viewer/

for file in flint4-geoip flint4-geoip-update; do
  cp "$ROOT/root/usr/bin/$file" "/usr/bin/$file"
done
for file in infra-port-watch infra-port-watch-config log-viewer-history log-viewer-query log-viewer-ip log-viewer-migrate; do
  cp "$ROOT/root/usr/sbin/$file" "/usr/sbin/$file"
done

cp "$ROOT/root/etc/infra-port-watch.sh" /etc/infra-port-watch.sh
cp "$ROOT/root/etc/init.d/infra-port-watch" /etc/init.d/infra-port-watch
cp "$ROOT/root/etc/init.d/log-viewer-history" /etc/init.d/log-viewer-history
cp "$ROOT/root/etc/hotplug.d/iface/99-infra-port-watch" /etc/hotplug.d/iface/99-infra-port-watch
cp "$ROOT/root/usr/share/log-viewer/policies.example.json" /usr/share/log-viewer/policies.example.json
cp "$ROOT/root/usr/share/luci/menu.d/luci-app-log-viewer.json" /usr/share/luci/menu.d/luci-app-log-viewer.json
cp "$ROOT/root/usr/share/rpcd/acl.d/luci-app-log-viewer.json" /usr/share/rpcd/acl.d/luci-app-log-viewer.json

# Never overwrite saved settings or a policy file the user edited.
[ -f /etc/config/infra-port-watch ] || cp "$ROOT/root/etc/config/infra-port-watch" /etc/config/infra-port-watch
[ -f /etc/config/log-viewer ] || cp "$ROOT/root/etc/config/log-viewer" /etc/config/log-viewer
[ -f /etc/log-viewer/policies.json ] || cp "$ROOT/root/etc/log-viewer/policies.json" /etc/log-viewer/policies.json

chmod 755 /usr/bin/flint4-geoip /usr/bin/flint4-geoip-update
chmod 755 /usr/sbin/infra-port-watch /usr/sbin/infra-port-watch-config /usr/sbin/log-viewer-history
chmod 755 /usr/sbin/log-viewer-query /usr/sbin/log-viewer-ip /usr/sbin/log-viewer-migrate
chmod 755 /etc/infra-port-watch.sh /etc/init.d/infra-port-watch /etc/init.d/log-viewer-history
chmod 755 /etc/hotplug.d/iface/99-infra-port-watch

# Move 3.x configuration to the 4.0 layout before starting the services.
/usr/sbin/log-viewer-migrate 2>/dev/null || true

/etc/init.d/log-viewer-history enable
/etc/init.d/log-viewer-history restart || echo "WARNING: firewall history collector did not start." >&2
/etc/init.d/infra-port-watch enable
if ! /etc/init.d/infra-port-watch restart; then
  echo "WARNING: WAN watch did not start. Set the WAN zone in WAN watch settings and press Re-apply rules." >&2
fi

rm -rf /tmp/luci-indexcache /tmp/luci-modulecache
if [ -x /etc/init.d/rpcd ]; then
  /etc/init.d/rpcd restart >/dev/null 2>&1 || true
fi

echo "Installed Firewall Log. Existing files were backed up under: $BACKUP"
echo "GeoIP: install libmaxminddb (apk add libmaxminddb), then run /usr/bin/flint4-geoip-update."
echo "Log in again if Status -> Firewall Log is missing; rpcd was restarted so the new ACL applies."
