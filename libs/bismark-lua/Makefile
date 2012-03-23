#
# Copyright (C) 2006-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=bismark-lua
PKG_RELEASE:=4
PKG_VERSION:=HEAD

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=git://github.com/projectbismark/bmlua.git
PKG_SOURCE_VERSION:=$(PKG_VERSION)
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_PROTO:=git

include $(INCLUDE_DIR)/package.mk

define Package/bismark-lua
	SECTION:=net
	CATEGORY:=Libraries
	TITLE:=Lua libraries for Bismark
	URL:=http://www.projectbismark.net
	DEPENDS:=+lua
endef

define Package/bismark-lua/description
	A set of lua libraries used by Bismark.
endef

define Build/Compile
endef

define Package/bismark-lua/install
	$(INSTALL_DIR) $(1)/usr/lib/lua/bmlua
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/bmlua/graphs.lua $(1)/usr/lib/lua/bmlua/graphs.lua
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/bmlua/opkg.lua $(1)/usr/lib/lua/bmlua/opkg.lua
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/bmlua/path.lua $(1)/usr/lib/lua/bmlua/path.lua
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/bmlua/set.lua $(1)/usr/lib/lua/bmlua/set.lua
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/bmlua/str.lua $(1)/usr/lib/lua/bmlua/str.lua
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/bmlua/tbl.lua $(1)/usr/lib/lua/bmlua/tbl.lua
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/bmlua/uci.lua $(1)/usr/lib/lua/bmlua/uci.lua
endef

$(eval $(call BuildPackage,bismark-lua))
