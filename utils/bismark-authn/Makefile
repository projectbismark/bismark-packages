#
# Copyright (C) 2006-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=bismark-authn
PKG_VERSION:=1
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/bismark-authn
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=BISmark registration utility
	URL:=http://www.projectbismark.net
	DEPENDS:=+bismark-lua +nodogsplash +libcurl
endef

define Package/bismark-authn/description
	A set of tools to manage user registration and authorization of BISmark 	routers.
endef

define Build/Compile
endef

define Package/bismark-authn/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/usr/bin/bismark-authn-check $(1)/usr/bin/bismark-authn-check
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/bismark-authn-check $(1)/etc/init.d/bismark-authn-check
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller/bismark-oauth
	$(INSTALL_BIN) ./files/usr/lib/lua/luci/controller/bismark-oauth/genkey.lua $(1)/usr/lib/lua/luci/controller/bismark-oauth/genkey.lua
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/view/bismark
	$(INSTALL_BIN) ./files/usr/lib/lua/luci/view/bismark/genkey.htm $(1)/usr/lib/lua/luci/view/bismark/genkey.htm
	$(INSTALL_DIR) $(1)/etc/nodogsplash/htdocs/images
	$(INSTALL_DATA) ./files/etc/nodogsplash/htdocs/images/splash.html $(1)/etc/nodogsplash/htdocs/images/splash.html
	$(INSTALL_DIR) $(1)/etc/nodogsplash/htdocs/images
	$(INSTALL_DATA) ./files/etc/nodogsplash/htdocs/images/index.css $(1)/etc/nodogsplash/htdocs/images/index.css
	$(INSTALL_DIR) $(1)/etc/nodogsplash/htdocs/images
	$(INSTALL_DATA) ./files/etc/nodogsplash/htdocs/images/bismark.gif $(1)/etc/nodogsplash/htdocs/images/bismark.gif
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/etc/uci-defaults/bismark-authn $(1)/etc/uci-defaults/bismark-authn
endef

define Package/bismark-authn/postinst
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	/etc/uci-defaults/bismark-authn
	rm /etc/uci-defaults/bismark-authn
fi
endef

define Package/bismark-authn/prerm
#!/bin/sh
/etc/init.d/bismark-authn-check disable
crontab -l | grep -v bismark-authn-check | crontab -
endef

$(eval $(call BuildPackage,bismark-authn))

