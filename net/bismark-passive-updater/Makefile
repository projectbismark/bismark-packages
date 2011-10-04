#
# Copyright (C) 2006-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=bismark-passive-updater
PKG_VERSION:=1
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/bismark-passive-updater
	SECTION:=net
	CATEGORY:=Network
	TITLE:=PCAP-based passive traffic observer
	URL:=http://www.projectbismark.net
	DEPENDS:=+libopenssl +libpcap +libpthread +zlib
endef

define Package/bismark-passive-updater/description
	A periodic updater for bismark-passive. This handles periodically
	downloading and installing new versions of bismark-passive binaries.
endef

define Package/bismark-passive-updater/config
	source "$(SOURCE)/Config.in"
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	cp -r files/* $(PKG_BUILD_DIR)
endef

define Build/Compile
endef

define Package/bismark-passive-updater/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/usr/bin/bismark-passive-updater $(1)/usr/bin/bismark-passive-updater
	$(INSTALL_DIR) $(1)/etc/bismark
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/etc/bismark/bismark-passive-updater.conf $(1)/etc/bismark/bismark-passive-updater.conf
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/etc/init.d/bismark-passive-updater $(1)/etc/init.d/bismark-passive-updater
endef

define Package/bismark-passive-updater/postinst
#!/bin/sh

CT_TEMP=`mktemp`
crontab -l | grep -v bismark-passive-updater > $$CT_TEMP
echo \*/$(CONFIG_BISMARK_PASSIVE_UPDATE_INTERVAL) \* \* \* \* /usr/bin/bismark-passive-updater >> $$CT_TEMP
crontab $$CT_TEMP
rm $$CT_TEMP

/etc/init.d/bismark-passive-updater enable
true

endef

define Package/bismark-passive-updater/prerm
#!/bin/sh

CT_TEMP=`mktemp`
crontab -l | grep -v bismark-passive-updater > $$CT_TEMP
crontab $$CT_TEMP
rm $$CT_TEMP

/etc/init.d/bismark-passive-updater stop
/etc/init.d/bismark-passive-updater disable

endef

$(eval $(call BuildPackage,bismark-passive-updater))
