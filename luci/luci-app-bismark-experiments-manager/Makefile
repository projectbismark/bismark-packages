#
# Copyright (C) 2006-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-bismark-experiments-manager
PKG_VERSION:=1.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-bismark-experiments-manager
  SECTION:=luci
  CATEGORY:=LuCI
  DEFAULT:=y
  TITLE:=BISmark experiments manager
  URL:=http://github.com/shahifaqeer/luci-app-bismark
  SUBMENU:=1. Applications
  DEPENDS:=+lua +libuci-lua +libubus-lua
endef

define Package/luci-app-bismark-experiments-manager/description
  Experiments manager for all bismark experiments installable
  on luci.

  Allows installation of experiments manager separate from
  luci version dependency.
endef

define Build/Prepare
endef

define Build/Compile
endef

define Package/luci-app-bismark-experiments-manager/install
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller/bismark
	$(CP) ./files/usr/lib/lua/luci/controller/bismark/experiments.lua $(1)/usr/lib/lua/luci/controller/bismark/experiments.lua
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/model/cbi/bismark-experiments-manager
	$(CP) ./files/usr/lib/lua/luci/model/cbi/bismark-experiments-manager/general.lua $(1)/usr/lib/lua/luci/model/cbi/bismark-experiments-manager/general.lua
endef

define Package/luci-app-bismark-experiments-manager/postinst
#!/bin/sh
rm -f /tmp/luci-indexcache 
endef
define Package/luci-app-bismark-experiments-manager/prerm 
#!/bin/sh
rm -f /tmp/luci-indexcache
endef

$(eval $(call BuildPackage,luci-app-bismark-experiments-manager))
