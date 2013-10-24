#
# Copyright (C) 2007-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=bismark-chrome
PKG_VERSION:=2.0.0
PKG_RELEASE:=7

include $(INCLUDE_DIR)/package.mk

define Package/bismark-chrome
   SECTION:=utils
   CATEGORY:=Utilities
   TITLE:=On-router HTML interface/information files.
   URL:=http://www.projectbismark.net/
   MAINTAINER:=Bismark Development List <bismark-devel@lists.bufferbloat.net>
   DEPENDS:=+uhttpd
endef

define Package/bismark-chrome/description
	The bismark-chrome package provides the default web interface/information
	files on the bismark router.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) -pr ./files/* $(PKG_BUILD_DIR)
endef

define Build/Compile
	
endef

define Package/bismark-chrome/install
	$(INSTALL_DIR) $(1)/www
	$(CP) -p $(PKG_BUILD_DIR)/www/* $(1)/www/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/etc/init.d/bismark-chrome $(1)/etc/init.d/bismark-chrome
endef

define Package/bismark-chrome/postinst
#!/bin/sh
# Bismark management post-install script
if [[ -e /www/index.html ]] && [[ -e /www/index.htm ]]; then
    rm -f /www/index.html
fi
endef

$(eval $(call BuildPackage,bismark-chrome))
