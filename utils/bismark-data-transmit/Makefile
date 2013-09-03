#
# Copyright (C) 2006-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=bismark-data-transmit
PKG_RELEASE:=13
PKG_VERSION:=HEAD

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=git://github.com/projectbismark/bismark-data-transmit.git
PKG_SOURCE_VERSION:=$(PKG_VERSION)
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_PROTO:=git

include $(INCLUDE_DIR)/package.mk

MAKE_FLAGS += BUILD_ID=$(BISMARK_DATA_TRANSMIT_BUILDID)
MAKE_FLAGS += DEFAULT_UPLOADS_URL="https://uploads.projectbismark.net:8081/upload/"
MAKE_FLAGS += RETRY_INTERVAL_MINUTES=3

define Package/bismark-data-transmit
	SECTION:=util
	CATEGORY:=Utilities
	TITLE:=cURL-based data transfer tool for BISmark
	URL:=https://github.com/sburnett/bismark-data-transmit
	DEPENDS:=+bismark-mgmt +libcurl
endef

define Package/bismark-data-transmit/description
	cURL-based data transfer tool for BISmark. Monitors directories for
	new data files and sends them over a persistent connect when found.
endef

define Package/bismark-data-transmit/config
	source "$(SOURCE)/Config.in"
endef

define Package/bismark-data-transmit/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bismark-data-transmit $(1)/usr/bin/bismark-data-transmit.bin
	$(INSTALL_BIN) ./files/usr/bin/bismark-data-transmit $(1)/usr/bin/bismark-data-transmit
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/bismark-data-transmit $(1)/etc/init.d/bismark-data-transmit
endef

define Package/bismark-data-transmit/postinst
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	/etc/init.d/bismark-data-transmit enable
	/etc/init.d/bismark-data-transmit restart
fi
true
endef

define Package/bismark-data-transmit/prerm
#!/bin/sh
/etc/init.d/bismark-data-transmit stop
/etc/init.d/bismark-data-transmit disable
endef

$(eval $(call BuildPackage,bismark-data-transmit))
