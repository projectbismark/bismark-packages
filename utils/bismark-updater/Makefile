#
# Copyright (C) 2006-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=bismark-updater
PKG_VERSION:=1
PKG_RELEASE:=17

include $(INCLUDE_DIR)/package.mk

define Package/bismark-updater
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=tmpfs-aware OpenWRT package updater
	URL:=http://www.projectbismark.net
	DEPENDS:=+bismark-data-transmit
endef

define Package/bismark-updater/description
	A periodic package updater for bismark. This will automatically download and
	update new packages from all repositories listed in opkg.conf.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	cp -r files/* $(PKG_BUILD_DIR)
endef

define Build/Compile
endef

define Package/bismark-updater/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/usr/bin/bismark-updater $(1)/usr/bin/bismark-updater
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/usr/bin/bismark-updater.lua $(1)/usr/bin/bismark-updater.lua
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/etc/init.d/bismark-updater $(1)/etc/init.d/bismark-updater
endef

define Package/bismark-updater/postinst
#!/bin/sh

(crontab -l | grep -v bismark-updater; echo 0 \* \* \* \* /usr/bin/bismark-updater) | crontab -
[ -z "$${IPKG_INSTROOT}" ] && /etc/init.d/bismark-updater enable
true

endef

define Package/bismark-updater/prerm
#!/bin/sh

crontab -l | grep -v bismark-updater | crontab -
[ -z "$${IPKG_INSTROOT}" ] && /etc/init.d/bismark-updater disable
true

endef

$(eval $(call BuildPackage,bismark-updater))
