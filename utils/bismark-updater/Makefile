#
# Copyright (C) 2006-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=bismark-updater
PKG_VERSION:=1
PKG_RELEASE:=25

include $(INCLUDE_DIR)/package.mk

define Package/bismark-updater
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=tmpfs-aware OpenWRT package updater
	URL:=http://www.projectbismark.net
	DEPENDS:=+bismark-data-transmit +bismark-lua +bismark-mgmt
endef

define Package/bismark-updater/description
	A periodic package updater for bismark. This will automatically download and
	update new packages from all repositories listed in opkg.conf.
endef

define Build/Compile
endef

define Package/bismark-updater/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/usr/bin/bismark-updater $(1)/usr/bin/bismark-updater
	$(INSTALL_BIN) ./files/usr/bin/bismark-updater.lua $(1)/usr/bin/bismark-updater.lua
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_DATA) ./files/etc/crontabs.d/bismark-updater $(1)/etc/crontabs.d/bismark-updater
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/bismark-updater $(1)/etc/init.d/bismark-updater
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/etc/uci-defaults/bismark-updater $(1)/etc/uci-defaults/bismark-updater
endef

define Package/bismark-updater/postinst
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	/etc/uci-defaults/bismark-updater
	rm /etc/uci-defaults/bismark-updater
fi
endef

define Package/bismark-updater/prerm
#!/bin/sh
crontab -l | grep -sFv -f /etc/crontabs.d/bismark-updater | sort -u | crontab -
/etc/init.d/bismark-updater disable
endef

$(eval $(call BuildPackage,bismark-updater))
