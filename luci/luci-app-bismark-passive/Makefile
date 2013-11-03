#
# Copyright (C) 2006-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-bismark-passive
PKG_VERSION:=1.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-bismark-passive
  SECTION:=luci
  CATEGORY:=LuCI
  DEFAULT:=y
  TITLE:=BISmark passive
  URL:=http://github.com/shahifaqeer/luci-app-bismark
  SUBMENU:=1. Applications
  DEPENDS:=+lua +libuci-lua +libubus-lua
endef

define Package/luci-app-bismark-passive/description
  Bismark passive interdace on luci.

  Allows installation of experiments manager separate from
  luci version dependency.
endef

define Build/Prepare
endef

define Build/Compile
endef

define Package/luci-app-bismark-passive/install
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller/bismark
	$(CP) ./files/usr/lib/lua/luci/controller/bismark/passive.lua $(1)/usr/lib/lua/luci/controller/bismark/passive.lua
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/model/cbi/bismark-passive
	$(CP) ./files/usr/lib/lua/luci/model/cbi/bismark-passive/general.lua $(1)/usr/lib/lua/luci/model/cbi/bismark-passive/general.lua
endef

define Package/luci-app-bismark-passive/postinst
#!/bin/sh
rm -rf /tmp/luci-indexcache /tmp/luci-modulecache
endef
define Package/luci-app-bismark-passive/prerm 
#!/bin/sh
rm -rf /tmp/luci-indexcache /tmp/luci-modulecache
endef

$(eval $(call BuildPackage,luci-app-bismark-passive))
