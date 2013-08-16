#
# Copyright (C) 2006-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=bismark-registration
PKG_VERSION:=1
PKG_RELEASE:=3

include $(INCLUDE_DIR)/package.mk

define Package/bismark-registration
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=BISmark registration utility
	URL:=http://www.projectbismark.net
	DEPENDS:=+bismark-chrome +bismark-lua +nodogsplash +libcurl
endef

define Package/bismark-registration/description
	A set of tools to manage user registration and authorization of BISmark routers.
endef

define Build/Compile
endef

define Package/bismark-registration/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/usr/bin/bismark-authn-check $(1)/usr/bin/bismark-authn-check
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/bismark-authn-check $(1)/etc/init.d/bismark-authn-check
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/controller/bismark
	$(INSTALL_BIN) ./files/usr/lib/lua/luci/controller/bismark/genkey.lua $(1)/usr/lib/lua/luci/controller/bismark/genkey.lua
	$(INSTALL_DIR) $(1)/usr/lib/lua/luci/view/bismark
	$(INSTALL_BIN) ./files/usr/lib/lua/luci/view/bismark/genkey.htm $(1)/usr/lib/lua/luci/view/bismark/genkey.htm
	$(INSTALL_DIR) $(1)/etc/nodogsplash
	$(INSTALL_DATA) ./files/etc/nodogsplash/nodogsplash.conf $(1)/etc/nodogsplash/nodogsplash.conf.will-rename-in-uci-defaults
	$(INSTALL_DIR) $(1)/etc/nodogsplash/htdocs
	$(INSTALL_DATA) ./files/etc/nodogsplash/htdocs/splash.html $(1)/etc/nodogsplash/htdocs/splash.html.will-rename-in-uci-defaults
	$(INSTALL_DIR) $(1)/etc/nodogsplash/htdocs/images
	$(INSTALL_DATA) ./files/etc/nodogsplash/htdocs/images/index.css $(1)/etc/nodogsplash/htdocs/images/index.css
	$(INSTALL_DATA) ./files/etc/nodogsplash/htdocs/images/bismark.gif $(1)/etc/nodogsplash/htdocs/images/bismark.gif
	$(INSTALL_DIR) $(1)/www/cgi-bin
	$(INSTALL_BIN) ./files/www/cgi-bin/register-verify $(1)/www/cgi-bin/register-verify
	$(INSTALL_BIN) ./files/www/cgi-bin/register-macaddress $(1)/www/cgi-bin/register-macaddress
endef

define Package/bismark-registration/postinst
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	/etc/uci-defaults/bismark-authn
	rm /etc/uci-defaults/bismark-authn
fi
endef

define Package/bismark-registration/prerm
#!/bin/sh
/etc/init.d/bismark-authn-check disable
crontab -l | grep -v bismark-authn-check | crontab -
endef

$(eval $(call BuildPackage,bismark-registration))

