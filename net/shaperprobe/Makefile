#
# Copyright (C) 2006-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=shaperprobe
PKG_VERSION:=1.0
PKG_RELEASE:=4

# XXX - what are the depends?
# PKG_BUILD_DEPENDS:=libncurses

include $(INCLUDE_DIR)/package.mk

# DEPENDS:=+libpthread
define Package/shaperprobe
	SECTION:=net
	CATEGORY:=Network
	TITLE:=DiffProbe Shaper Module used to detect traffic shaping
	URL:=http://www.cc.gatech.edu/~partha/diffprobe/shaperprobe.html
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)
endef

define Package/shaperprobe/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/prober $(1)/usr/bin/prober
endef

$(eval $(call BuildPackage,shaperprobe))
