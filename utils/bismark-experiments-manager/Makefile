#
# Copyright (C) 2006-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=bismark-experiments-manager
PKG_VERSION:=1
PKG_RELEASE:=17

include $(INCLUDE_DIR)/package.mk

define Package/bismark-experiments-manager
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=Track and intstall experiments for the Bismark platform
	URL:=http://www.projectbismark.net
	DEPENDS:=+bismark-lua +libuci-lua
endef

define Package/bismark-experiments-manager/description
	This package tracks the list of the latest experiments available for the
	Bismark platform, and lets users install and remove experiments.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	cp -r files/* $(PKG_BUILD_DIR)
endef

define Build/Compile
endef

define Package/bismark-experiments-manager/conffiles
/etc/config/bismark-experiments
endef

define Package/bismark-experiments-manager/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/usr/bin/setup-and-teardown-experiments $(1)/usr/bin/setup-and-teardown-experiments
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/usr/bin/merge-experiments $(1)/usr/bin/merge-experiments
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/etc/init.d/bismark-experiments-manager $(1)/etc/init.d/bismark-experiments-manager
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/etc/config/bismark-experiments $(1)/etc/config/bismark-experiments
endef

define Package/bismark-experiments-manager/postinst
#!/bin/sh
[ -z "$${IPKG_INSTROOT}" ] && /etc/init.d/bismark-experiments-manager enable
(crontab -l | grep -v merge-experiments; echo 0 \* \* \* \* /usr/bin/merge-experiments) | crontab -
true
endef

define Package/bismark-experiments-manager/prerm
#!/bin/sh
[ -z "$${IPKG_INSTROOT}" ] && /etc/init.d/bismark-experiment-manager disable
crontab -l | grep -v merge-experiments | crontab -
true
endef

$(eval $(call BuildPackage,bismark-experiments-manager))
