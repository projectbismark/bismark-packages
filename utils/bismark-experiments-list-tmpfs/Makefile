#
# Copyright (C) 2006-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=bismark-experiments-list-tmpfs
PKG_VERSION:=1
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/bismark-experiments-list-tmpfs
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=Track and intstall experiments for the Bismark platform
	URL:=http://www.projectbismark.net
endef

define Package/bismark-experiments-list-tmpfs/description
	This package contains the list of experiments for Bismark.
	It is meant to be used by bismark-experiments-manager.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	cp -r files/* $(PKG_BUILD_DIR)
endef

define Build/Compile
endef

define Package/bismark-experiments-list-tmpfs/install
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/bismark-experiments-list $(1)/bismark-experiments-list
endef

$(eval $(call BuildPackage,bismark-experiments-list-tmpfs))
