#
# Copyright (C) 2006-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=bismark-experiments-manager
PKG_VERSION:=1
PKG_RELEASE:=62

include $(INCLUDE_DIR)/package.mk

define Package/bismark-experiments-manager
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=Track and intstall experiments for the Bismark platform
	URL:=http://www.projectbismark.net
	DEPENDS:=+bismark-data-transmit +bismark-lua +bismark-mgmt +libuci-lua
endef

define Package/bismark-experiments-manager/description
	This package tracks the list of the latest experiments available for the
	Bismark platform, and lets users install and remove experiments.
endef

define Build/Compile
endef

define Package/bismark-experiments-manager/conffiles
/etc/config/bismark-experiments
endef

define Package/bismark-experiments-manager/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/usr/bin/setup-and-teardown-experiments $(1)/usr/bin/setup-and-teardown-experiments
	$(INSTALL_BIN) ./files/usr/bin/merge-experiments $(1)/usr/bin/merge-experiments
	$(INSTALL_BIN) ./files/usr/bin/bismark-experiments-manager $(1)/usr/bin/bismark-experiments-manager
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/bismark-experiments-manager $(1)/etc/init.d/bismark-experiments-manager
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/bismark-experiments $(1)/etc/config/bismark-experiments
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/etc/uci-defaults/bismark-experiments-manager $(1)/etc/uci-defaults/bismark-experiments-manager
endef

define Package/bismark-experiments-manager/postinst
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	/etc/uci-defaults/bismark-experiments-manager
	rm /etc/uci-defaults/bismark-experiments-manager
fi
endef

define Package/bismark-experiments-manager/prerm
#!/bin/sh
/etc/init.d/bismark-experiment-manager disable
crontab -l | grep -v bismark-experiments-manager | crontab -
endef

$(eval $(call BuildPackage,bismark-experiments-manager))
