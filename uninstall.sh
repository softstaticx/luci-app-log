#!/bin/sh
# Removes the source overlay installed by install.sh.
# Package installs should use: apk del luci-app-log-viewer
set -eu

/etc/init.d/infra-port-watch disable 2>/dev/null || true
/usr/sbin/infra-port-watch remove 2>/dev/null || true
/etc/init.d/infra-port-watch stop 2>/dev/null || true
/etc/init.d/log-viewer-history disable 2>/dev/null || true
/etc/init.d/log-viewer-history stop 2>/dev/null || true

rm -f /usr/sbin/infra-port-watch /usr/sbin/infra-port-watch-config
rm -f /usr/sbin/log-viewer-history /usr/sbin/log-viewer-query /usr/sbin/log-viewer-ip /usr/sbin/log-viewer-migrate
rm -f /etc/infra-port-watch.sh /etc/init.d/infra-port-watch /etc/init.d/log-viewer-history
rm -f /etc/hotplug.d/iface/99-infra-port-watch
rm -f /usr/libexec/log-viewer-geoip
rm -rf /tmp/log-viewer

rm -f /www/luci-static/resources/view/log-viewer/firewall.js
rm -f /www/luci-static/resources/log-viewer/firewall.css
rm -f /www/luci-static/resources/log-viewer/logo.svg
rm -rf /www/luci-static/resources/log-viewer/flags
rm -f /usr/bin/flint4-geoip /usr/bin/flint4-geoip-update
rm -f /usr/share/log-viewer/policies.example.json
rm -f /usr/share/luci/menu.d/luci-app-log-viewer.json
rm -f /usr/share/rpcd/acl.d/luci-app-log-viewer.json

# Generated nftables includes and the watch table.
rm -f /usr/share/nftables.d/table-pre/10-log-viewer.nft 2>/dev/null || true
rm -f /usr/share/nftables.d/chain-post/input_*/10-log-viewer.nft 2>/dev/null || true
rm -f /usr/share/nftables.d/chain-post/forward_*/10-log-viewer.nft 2>/dev/null || true

rm -rf /tmp/luci-indexcache /tmp/luci-modulecache
if [ -x /etc/init.d/firewall ]; then
  /etc/init.d/firewall reload >/dev/null 2>&1 || true
fi
if [ -x /etc/init.d/rpcd ]; then
  /etc/init.d/rpcd restart >/dev/null 2>&1 || true
fi

echo "Removed Firewall Log, its WAN watch rules, and the country flags."
echo "Settings remain in /etc/config/log-viewer and /etc/config/infra-port-watch."
echo "GeoIP databases in /usr/share/GeoIP and /etc/log-viewer/policies.json were left in place."
echo "Backups from install.sh, if any, are under /root/reffix-log-viewer-backup-*."
