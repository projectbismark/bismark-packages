#
# Copyright (C) 2007-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=bismark
PKG_VERSION:=0.9.3
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=http://www.infinalink.com/bismark/
PKG_MD5SUM:=59a6da92b7b36f4133aeb393a4b57692

PKG_INSTALL:=1

include $(INCLUDE_DIR)/package.mk

define Package/bismark
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Broadband Internet Service benchMARK
  URL:=http://www.gtnoise.net/
  MAINTAINER:=Not It <spam@someoneelse.com>
endef

define Package/bismark/description
  Insert description of bismark here
endef

# Specify where and how to install the program. Since we only have one file,
# the helloworld executable, install it by copying it to the /bin directory on
# the router. The $(1) variable represents the root directory on the router running
# OpenWrt. The $(INSTALL_DIR) variable contains a command to prepare the install
# directory if it does not already exist.  Likewise $(INSTALL_BIN) contains the
# command to copy the binary file from its current location (in our case the build
# directory) to the install directory.
define Package/bismark/install
	$(INSTALL_DIR) $(1)/root/.ssh
	$(INSTALL_DIR) $(1)/root/bin
	$(INSTALL_DIR) $(1)/root/etc
	$(INSTALL_DIR) $(1)/root/scripts
	$(INSTALL_DIR) $(1)/etc
	$(CP) -p $(PKG_BUILD_DIR)/bin/etc/* $(1)/root/etc/
	$(CP) -p $(PKG_BUILD_DIR)/bin/keys/* $(1)/root/.ssh/
	$(CP) -p $(PKG_BUILD_DIR)/bin/scripts/* $(1)/root/scripts/
	$(CP) -p $(PKG_BUILD_DIR)/bin/rc.local $(1)/etc/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bin/ITGDec $(1)/root/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bin/ITGRecv $(1)/root/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bin/ITGSend $(1)/root/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bin/prober $(1)/root/bin
endef

$(eval $(call BuildPackage,bismark))
