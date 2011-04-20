#
# Copyright (C) 2007-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=bismark-mgmt
PKG_VERSION:=0.1
PKG_RELEASE:=14

include $(INCLUDE_DIR)/package.mk

define Package/bismark-mgmt
   SECTION:=utils
   CATEGORY:=Utilities
   TITLE:=Broadband Internet Service benchMARK
   URL:=http://www.gtnoise.net/
   MAINTAINER:=Bismark Development List <bismark-devel@lists.bufferbloat.net>
   DEPENDS:=netcat
endef

define Package/bismark-mgmt/description
  XXX Insert description of bismark here XXX
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) -pr ./files/* $(PKG_BUILD_DIR)
endef

define Build/Compile
	
endef

# Specify where and how to install the program. Since we only have one file,
# the helloworld executable, install it by copying it to the /bin directory on
# the router. The $(1) variable represents the root directory on the router running
# OpenWrt. The $(INSTALL_DIR) variable contains a command to prepare the install
# directory if it does not already exist.  Likewise $(INSTALL_BIN) contains the
# command to copy the binary file from its current location (in our case the build
# directory) to the install directory.
define Package/bismark-mgmt/install
	$(INSTALL_DIR) $(1)/root/.ssh $(1)/usr/bin $(1)/etc/init.d $(1)/etc/bismark $(1)/usr/lib/bismark $(1)/root/.ssh $(1)/etc/dropbear
	$(CP) -p $(PKG_BUILD_DIR)/etc/* $(1)/etc/bismark
	$(CP) -p $(PKG_BUILD_DIR)/keys/* $(1)/etc/bismark
	$(CP) -p $(PKG_BUILD_DIR)/scripts/* $(1)/usr/bin/
	$(CP) -p $(PKG_BUILD_DIR)/lib/* $(1)/usr/lib/bismark/
	$(CP) $(PKG_BUILD_DIR)/etc/bismark.initd $(1)/etc/init.d/bismark
endef

define Package/bismark-mgmt/postinst
#!/bin/sh
# Bismark management post-install script

cat $${IPKG_INSTROOT}/etc/bismark/authorized_keys >> $${IPKG_INSTROOT}/etc/dropbear/authorized_keys
cat $${IPKG_INSTROOT}/etc/bismark/known_hosts >> $${IPKG_INSTROOT}/root/.ssh/known_hosts

endef

$(eval $(call BuildPackage,bismark-mgmt))
