#
# luci-app-log-viewer - firewall log dashboard for OpenWrt 25.12
#
# REFFIX-maintained fork of gSpotx2f/luci-app-log.
# The original application is distributed under the MIT License.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-log-viewer
PKG_VERSION:=$(shell cat $(CURDIR)/VERSION 2>/dev/null || echo 4.0.0)
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE
PKG_MAINTAINER:=REFFIX

PKG_BUILD_DEPENDS:=libmaxminddb

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-log-viewer
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=Firewall Log
  URL:=https://github.com/softstaticx/luci-app-log
  DEPENDS:=+luci-base +logd +ucode +ucode-mod-fs +jsonfilter +libmaxminddb +firewall4
endef

define Package/luci-app-log-viewer/conffiles
/etc/config/infra-port-watch
/etc/config/log-viewer
/etc/log-viewer/policies.json
endef

define Package/luci-app-log-viewer/description
 Firewall log dashboard for OpenWrt. Shows blocked WAN traffic with the real
 firewall verdict, optional probe visibility, local GeoLite2 country and ASN
 enrichment, and an opt-in on-disk history. IPv4 and IPv6.
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_CPPFLAGS) -I$(STAGING_DIR)/usr/include \
		-o $(PKG_BUILD_DIR)/log-viewer-geoip \
		$(CURDIR)/src/log-viewer-geoip.c \
		$(TARGET_LDFLAGS) -L$(STAGING_DIR)/usr/lib -lmaxminddb
endef

define Package/luci-app-log-viewer/install
	$(INSTALL_DIR) $(1)/www
	$(CP) ./htdocs/* $(1)/www/
	$(CP) ./root/* $(1)/
	$(INSTALL_DIR) $(1)/usr/libexec
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/log-viewer-geoip $(1)/usr/libexec/log-viewer-geoip
	$(INSTALL_DIR) $(1)/usr/share/nftables.d
	chmod 755 $(1)/usr/bin/flint4-geoip $(1)/usr/bin/flint4-geoip-update \
		$(1)/usr/sbin/infra-port-watch $(1)/usr/sbin/infra-port-watch-config \
		$(1)/usr/sbin/log-viewer-history $(1)/usr/sbin/log-viewer-query \
		$(1)/usr/sbin/log-viewer-ip $(1)/usr/sbin/log-viewer-migrate \
		$(1)/etc/init.d/infra-port-watch $(1)/etc/init.d/log-viewer-history \
		$(1)/etc/infra-port-watch.sh $(1)/etc/hotplug.d/iface/99-infra-port-watch
endef

define Package/luci-app-log-viewer/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
/usr/sbin/log-viewer-migrate 2>/dev/null || true
/etc/init.d/infra-port-watch enable
/etc/init.d/infra-port-watch restart || echo "WARNING: the WAN watch could not start; set the WAN zone or device in WAN watch settings."
/etc/init.d/log-viewer-history enable
/etc/init.d/log-viewer-history restart || echo "WARNING: the firewall history collector did not start."
rm -rf /tmp/luci-indexcache /tmp/luci-modulecache
/etc/init.d/rpcd restart >/dev/null 2>&1 || true
exit 0
endef

define Package/luci-app-log-viewer/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
/etc/init.d/infra-port-watch stop 2>/dev/null || true
/etc/init.d/infra-port-watch disable 2>/dev/null || true
/etc/init.d/log-viewer-history stop 2>/dev/null || true
/etc/init.d/log-viewer-history disable 2>/dev/null || true
exit 0
endef

define Package/luci-app-log-viewer/postrm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
rm -f /usr/share/nftables.d/table-pre/10-log-viewer.nft 2>/dev/null || true
rm -f /usr/share/nftables.d/chain-post/input_*/10-log-viewer.nft 2>/dev/null || true
rm -f /usr/share/nftables.d/chain-post/forward_*/10-log-viewer.nft 2>/dev/null || true
rm -rf /tmp/log-viewer 2>/dev/null || true
rm -rf /tmp/luci-indexcache /tmp/luci-modulecache
exit 0
endef

$(eval $(call BuildPackage,luci-app-log-viewer))
