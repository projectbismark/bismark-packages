#
# Copyright (C) 2006-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=bismark-lua
PKG_VERSION:=head
PKG_RELEASE:=7

GIT_URL:=git://github.com/projectbismark.net/bmlua.git

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

define Package/bismark-lua/config
	source "$(SOURCE)/Config.in"
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	git clone -- $(GIT_URL) $(PKG_BUILD_DIR)
	git --git-dir=$(PKG_BUILD_DIR)/.git rev-parse HEAD
#	cp -r ./files $(PKG_BUILD_DIR)
endef

define Build/Compile
endef

define Package/bismark-lua/install
	$(INSTALL_DIR) $(1)/usr/lib/lua/bmlua
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/bmlua/opkg.lua $(1)/usr/lib/lua/bmlua/opkg.lua
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/bmlua/path.lua $(1)/usr/lib/lua/bmlua/path.lua
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/bmlua/set.lua $(1)/usr/lib/lua/bmlua/set.lua
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/bmlua/str.lua $(1)/usr/lib/lua/bmlua/str.lua
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/bmlua/tbl.lua $(1)/usr/lib/lua/bmlua/tbl.lua
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/bmlua/uci.lua $(1)/usr/lib/lua/bmlua/uci.lua
endef

$(eval $(call BuildPackage,bismark-lua))
