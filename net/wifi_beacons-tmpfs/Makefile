#
# Copyright (C) 2006-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=wifi_beacons-tmpfs
PKG_VERSION:=2.0
PKG_RELEASE:=2

GIT_URL:=git://github.com/abnarain/wifi_beacons.git
#GIT_URL:=src/

include $(INCLUDE_DIR)/package.mk

define Package/wifi_beacons-tmpfs
	SECTION:=net
	CATEGORY:=Network
	TITLE:=The tool aggregates beacons of neighboring access points
	URL:=http://doesnotexist.com
	DEPENDS:=+libpcap +zlib +bismark-data-transmit 
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	git clone -- $(GIT_URL) $(PKG_BUILD_DIR)
	git --git-dir=$(PKG_BUILD_DIR)/.git rev-parse HEAD
endef

define Package/wifi_beacons-tmpfs/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/wifi_beacons $(1)/usr/bin/wifi_beacons.bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/scripts/setup $(1)/etc/init.d/wifi_beacons
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/scripts/keep-alive $(1)/usr/bin/wifi_beacons

endef

 
define Package/wifi_beacons-tmpfs/postinst
#!/bin/sh
/tmp/etc/init.d/wifi_beacons restart
endef

define Package/wifi_beacons-tmpfs/prerm
#!/bin/sh
/tmp/etc/init.d/wifi_beacons stop

endef

$(eval $(call BuildPackage,wifi_beacons-tmpfs))
