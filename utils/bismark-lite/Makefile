#
# Copyright (C) 2007-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=bismark-lite
PKG_VERSION:=0.1
PKG_RELEASE:=3
GIT_COMMIT:=lite

include $(INCLUDE_DIR)/package.mk

define Package/bismark-lite
   SECTION:=utils
   CATEGORY:=Utilities
   TITLE:=Broadband Internet Service benchMARK - A light management tool
   URL:=http://projectbismark.net/
   MAINTAINER:=Bismark Development List <bismark-devel@lists.bufferbloat.net>
   DEPENDS:=+netcat
endef

define Package/bismark-lite/description
	The bismark-lite package is a light-weight package enables administering bismark
	routers remotely.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)/{scripts,etc,lib,keys}
	[ -d files ] && ( cd files ; git pull ; git checkout $(GIT_COMMIT)) \
		     || ( git clone git://github.com/bismark-devel/bismark.git files ; cd files ; git checkout $(GIT_COMMIT))

	$(CP) files/device/OpenWrt_common/scripts/bismark-{action-lite,bootstrap-lite,probe} $(PKG_BUILD_DIR)/scripts
	$(CP) files/device/OpenWrt_common/etc/{bismark.conf,bismark-lite.{conf,initd},crontab-lite} $(PKG_BUILD_DIR)/etc
	$(CP) files/device/OpenWrt_common/lib/functions.inc.sh $(PKG_BUILD_DIR)/lib
	$(CP) -L files/device/OpenWrt_common/keys/cert.pem $(PKG_BUILD_DIR)/keys

	VERSION=$(cd files ; git log --pretty=format:'' | wc -l)
	sed -i -e "/^VERSION=/ s/=.*/=$${VERSION}/" $(PKG_BUILD_DIR)/etc/bismark.conf
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
define Package/bismark-lite/install
	$(INSTALL_DIR) $(1)/root/.ssh $(1)/usr/bin $(1)/etc/init.d $(1)/etc/bismark $(1)/usr/lib/bismark $(1)/etc/dropbear $(1)/etc/ssl/certs
	$(CP) -p $(PKG_BUILD_DIR)/etc/{bismark.conf,bismark-lite.conf,crontab-lite} $(1)/etc/bismark
	$(CP) -p $(PKG_BUILD_DIR)/keys/cert.pem $(1)/etc/bismark
	###$(LN) $(1)/etc/bismark/cert.pem $(1)/etc/ssl/certs/381178f4.0
	$(CP) -p $(PKG_BUILD_DIR)/scripts/* $(1)/usr/bin/
	$(CP) -p $(PKG_BUILD_DIR)/lib/* $(1)/usr/lib/bismark/
	$(CP) $(PKG_BUILD_DIR)/etc/bismark-lite.initd $(1)/etc/init.d/bismark-lite
endef

define Package/bismark-lite/postinst
#!/bin/sh
# Bismark management post-install script

###cat $${IPKG_INSTROOT}/etc/bismark/authorized_keys >> $${IPKG_INSTROOT}/etc/dropbear/authorized_keys
###cat $${IPKG_INSTROOT}/etc/bismark/known_hosts >> $${IPKG_INSTROOT}/root/.ssh/known_hosts
ln -sf ${IPKG_INSTROOT}/etc/bismark/cert.pem $${IPKG_INSTROOT}/etc/ssl/certs/381178f4.0

endef

$(eval $(call BuildPackage,bismark-lite))

