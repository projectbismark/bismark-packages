#
# Copyright (C) 2006-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=bismark-data-transmit
PKG_VERSION:=head
PKG_RELEASE:=20

GIT_URL:=git://github.com/projectbismark/bismark-data-transmit.git

include $(INCLUDE_DIR)/package.mk

MAKE_FLAGS += BUILD_ID=$(BISMARK_DATA_TRANSMIT_BUILDID)
MAKE_FLAGS += UPLOADS_URL="https://projectbismark.net:8081/upload/"
MAKE_FLAGS += RETRY_INTERVAL_MINUTES=3

define Package/bismark-data-transmit
	SECTION:=util
	CATEGORY:=Utilities
	TITLE:=cURL-based data transfer tool for BISmark
	URL:=https://github.com/sburnett/bismark-data-transmit
	DEPENDS:=+libcurl
endef

define Package/bismark-data-transmit/description
	cURL-based data transfer tool for BISmark. Monitors directories for
	new data files and sends them over a persistent connect when found.
endef

define Package/bismark-data-transmit/config
	source "$(SOURCE)/Config.in"
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	git clone -- $(GIT_URL) $(PKG_BUILD_DIR)
	git --git-dir=$(PKG_BUILD_DIR)/.git rev-parse HEAD
	cp -r ./files $(PKG_BUILD_DIR)
endef

define Package/bismark-data-transmit/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bismark-data-transmit $(1)/usr/bin/bismark-data-transmit.bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bismark-data-transmit-collect $(1)/usr/bin/bismark-data-transmit-collect
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/usr/bin/bismark-data-transmit $(1)/usr/bin/bismark-data-transmit
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/etc/init.d/bismark-data-transmit $(1)/etc/init.d/bismark-data-transmit
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/files/etc/init.d/bismark-data-transmit-collect $(1)/etc/init.d/bismark-data-transmit-collect
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) $(PKG_BUILD_DIR)/files/etc/config/bismark-data-transmit $(1)/etc/config/bismark-data-transmit
endef

define Package/bismark-data-transmit/postinst
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	/etc/init.d/bismark-data-transmit enable
	/etc/init.d/bismark-data-transmit-collect enable
	/etc/init.d/bismark-data-transmit restart
	/etc/init.d/bismark-data-transmit-collect restart
fi
true
endef

define Pakcage/bismark-data-transmit/prerm
#!/bin/sh
/etc/init.d/bismark-data-transmit stop
/etc/init.d/bismark-data-transmit-collect stop
/etc/init.d/bismark-data-transmit disable
/etc/init.d/bismark-data-transmit-collect disable
endef

$(eval $(call BuildPackage,bismark-data-transmit))
