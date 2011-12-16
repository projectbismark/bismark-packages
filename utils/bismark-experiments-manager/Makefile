#
# Copyright (C) 2006-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=bismark-experiments-manager
PKG_VERSION:=1
PKG_RELEASE:=7

include $(INCLUDE_DIR)/package.mk

define Package/bismark-experiments-manager
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=Track and intstall experiments for the Bismark platform
	URL:=http://www.projectbismark.net
	DEPENDS:=+bismark-experiments-list-tmpfs
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
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/etc/init.d/bismark-experiments-manager $(1)/etc/init.d/bismark-experiments-manager
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/etc/config/bismark-experiments $(1)/etc/config/bismark-experiments
endef

#define Package/bismark-experiments-manager/postinst
##!/bin/sh
#(crontab -l | grep -v bismark-experiment-manager; echo 0 \* \* \* \* /usr/bin/setup-and-teardown-experiments) | crontab -
#[ -z "$${IPKG_INSTROOT}" ] && /etc/init.d/bismark-experiments-manager enable
#true
#endef
#
#define Package/bismark-experiments-manager/prerm
##!/bin/sh
#crontab -l | grep -v bismark-experiment-manager | crontab -
#[ -z "$${IPKG_INSTROOT}" ] && /etc/init.d/bismark-experiment-manager disable
#true
#endef

$(eval $(call BuildPackage,bismark-experiments-manager))
