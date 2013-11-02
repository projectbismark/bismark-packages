#
# Copyright (C) 2006-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=bismark-health
PKG_VERSION:=1
PKG_RELEASE:=6

include $(INCLUDE_DIR)/package.mk

define Package/bismark-health
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=Generate periodic health reports for BISmark routers.
	URL:=http://www.projectbismark.net
	DEPENDS:=+bismark-data-transmit
endef

define Package/bismark-health/description
	Periodically generate some health information about a router and upload it
	to the data collection server.
endef

define Build/Compile
endef

define Package/bismark-health/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/usr/bin/bismark-health $(1)/usr/bin/bismark-health
	$(INSTALL_DIR) $(1)/etc/crontabs.d
	$(INSTALL_DATA) ./files/etc/crontabs.d/bismark-health $(1)/etc/crontabs.d/bismark-health
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/etc/uci-defaults/bismark-health $(1)/etc/uci-defaults/bismark-health
endef

define Package/bismark-health/postinst
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	/etc/uci-defaults/bismark-health
	rm /etc/uci-defaults/bismark-health
fi
endef

define Package/bismark-health/prerm
#!/bin/sh
crontab -l | grep -sFv -f /etc/crontabs.d/bismark-health | sort -u | crontab -
endef

$(eval $(call BuildPackage,bismark-health))
