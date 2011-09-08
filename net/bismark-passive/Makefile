#
# Copyright (C) 2006-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=bismark-passive
PKG_VERSION:=0.1
PKG_RELEASE:=1

PKG_BUILD_DEPENDS:=libpcap zlib libopenssl

include $(INCLUDE_DIR)/package.mk

# DEPENDS:=+libpthread
define Package/bismark-passive
	SECTION:=net
	CATEGORY:=Network
	TITLE:=PCAP-based passive observer for bismark-passive
	URL:=http://www.projectbismark.net
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)
endef

define Package/bismark-passive/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bismark-passive $(1)/usr/bin/bismark-passive
endef

$(eval $(call BuildPackage,bismark-passive))
