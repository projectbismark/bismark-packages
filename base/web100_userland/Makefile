#
# Copyright (C) 2006-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=web100_userland
PKG_VERSION:=1.8
PKG_RELEASE:=1
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=http://www.web100.org/download/userland/version1.8
PKG_MD5SUM:=4dd53dfe4df3946ed606b22a73ec1bf3
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

# XXX - what are the depends?
# PKG_BUILD_DEPENDS:=libncurses

include $(INCLUDE_DIR)/package.mk

# DEPENDS:=+libpthread
define Package/web100_userland
	SECTION:=net
	CATEGORY:=Network
	TITLE:=web100_userland
endef

#define Build/Prepare
#	mkdir -p $(PKG_BUILD_DIR)
#	$(CP) ./src/$(PKG_NAME)-$(PKG_VERSION)/* $(PKG_BUILD_DIR)
#endef

define Build/Configure
	$(call Build/Configure/Default, \
		--disable-python\
		--disable-gtk2\
		--disable-gtktest\
	)
endef


define Package/web100_userland/install
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lib/.libs/libweb100.so* $(1)/usr/lib/
endef

$(eval $(call BuildPackage,web100_userland))
