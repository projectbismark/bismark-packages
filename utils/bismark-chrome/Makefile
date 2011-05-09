#
# Copyright (C) 2007-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=bismark-chrome
PKG_VERSION:=0.1
PKG_RELEASE:=16

include $(INCLUDE_DIR)/package.mk

define Package/bismark-chrome
   SECTION:=utils
   CATEGORY:=Utilities
   TITLE:=Web server files for bismark
   URL:=http://www.gtnoise.net/
   MAINTAINER:=Bismark Development List <bismark-devel@lists.bufferbloat.net>
   DEPENDS:=+lighttpd
endef

define Package/bismark-chrome/description
	The bismark-chrome package provides a reference local web page
	for network resources.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) -pr ./files/* $(PKG_BUILD_DIR)
endef

define Build/Compile
	
endef

define Package/bismark-chrome/install
	$(INSTALL_DIR) $(1)/etc/web $(1)/etc/cgi-bin
	$(CP) -p $(PKG_BUILD_DIR)/etc/{web,cgi-bin} $(1)/etc/
endef

$(eval $(call BuildPackage,bismark-chrome))
