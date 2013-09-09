#
# Copyright (C) 2007-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=bismark-mgmt
PKG_VERSION:=0.7
PKG_RELEASE:=24
#GIT_COMMIT:=1123704e593bddc4a9b4
#GIT_COMMIT:=lite

include $(INCLUDE_DIR)/package.mk

define Package/bismark-mgmt
   SECTION:=utils
   CATEGORY:=Utilities
   TITLE:=Broadband Internet Service benchMARK
   URL:=http://projectbismark.net/
   MAINTAINER:=Bismark Development List <bismark-devel@lists.bufferbloat.net>
   DEPENDS:=+netcat +curl +ntpclient
endef

define Package/bismark-mgmt/description
	The bismark-mgmt package makes it possible to administer a bismark
	router remotely.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)/{scripts,etc,lib,keys}
#	[ -d files ] && ( cd files ; git pull ) \#; git checkout $(GIT_COMMIT)) \
#		     || ( git clone git://github.com/projectbismark/bismark.git files ; cd files ) #; git checkout $(GIT_COMMIT))
	[ -d files ] && ( cd files ; git pull ) \
		     || ( git clone git://github.com/projectbismark/bismark.git files ; cd files ) 

	$(CP) files/device/OpenWrt_common/scripts/bismark-{action,bootstrap,probe,rshell,scp,sshd} $(PKG_BUILD_DIR)/scripts
	$(CP) files/device/OpenWrt_common/etc/{bismark.{conf,initd},crontab} $(PKG_BUILD_DIR)/etc
	$(CP) files/device/OpenWrt_common/lib/functions.inc.sh $(PKG_BUILD_DIR)/lib
	$(CP) -L files/device/OpenWrt_common/keys/{authorized_keys,bismark_key*,known_hosts} $(PKG_BUILD_DIR)/keys
	$(CP) -L files/device/OpenWrt_common/keys/gd_*.crt $(PKG_BUILD_DIR)/keys
	$(CP) -L files/device/OpenWrt_common/keys/projectbismark_*.crt $(PKG_BUILD_DIR)/keys

	#VERSION=$(cd files ; git log --pretty=format:'' | wc -l)
	sed -i -e "/^VERSION=/ s/=.*/=`cd files ; git log --pretty=format:'' | wc -l`/" $(PKG_BUILD_DIR)/etc/bismark.conf
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
	$(INSTALL_DIR) $(1)/root/.ssh $(1)/usr/bin $(1)/etc/init.d $(1)/etc/bismark $(1)/usr/lib/bismark $(1)/root/.ssh $(1)/etc/dropbear $(1)/etc/ssl/certs
	$(CP) -p $(PKG_BUILD_DIR)/etc/{bismark.conf,crontab} $(1)/etc/bismark
	$(CP) -p $(PKG_BUILD_DIR)/keys/* $(1)/etc/bismark
	$(CP) -p $(PKG_BUILD_DIR)/scripts/* $(1)/usr/bin/
	$(CP) -p $(PKG_BUILD_DIR)/lib/* $(1)/usr/lib/bismark/
	$(CP) $(PKG_BUILD_DIR)/etc/bismark.initd $(1)/etc/init.d/bismark
endef

define Package/bismark-mgmt/preinst
#!/bin/sh
# Bismark management pre-install script: clear crontab
if [ -z "$${IPKG_INSTROOT}" ]; then
	if [ -e /etc/bismark/crontab ]; then
		grep -sFvf /etc/bismark/crontab /etc/crontabs/root | sort -u | crontab -
	fi
fi
endef

define Package/bismark-mgmt/prerm
$(call Package/bismark-mgmt/preinst)
rm $${IPKG_INSTROOT}/etc/ssl/certs/219d9499.0
rm $${IPKG_INSTROOT}/etc/ssl/certs/97552d04.0
rm $${IPKG_INSTROOT}/etc/ssl/certs/1b3d9bdf.0
rm $${IPKG_INSTROOT}/etc/ssl/certs/34e84591.0
rm $${IPKG_INSTROOT}/etc/ssl/certs/f081611a.0
rm $${IPKG_INSTROOT}/etc/ssl/certs/598630ad.0
rm $${IPKG_INSTROOT}/etc/ssl/certs/275bb920.0
rm $${IPKG_INSTROOT}/etc/ssl/certs/c2ea5431.0
grep -sFvf $${IPKG_INSTROOT}/etc/bismark/known_hosts $${IPKG_INSTROOT}/root/.ssh/known_hosts | sort -u > $${IPKG_INSTROOT}/tmp/knownhosts.nonbismark
cp $${IPKG_INSTROOT}/tmp/knownhosts.nonbismark $${IPKG_INSTROOT}/root/.ssh/known_hosts
rm $${IPKG_INSTROOT}/tmp/knownhosts.nonbismark
endef

define Package/bismark-mgmt/postinst
#!/bin/sh
# Bismark management post-install script
# openssl < 1.0.0 (MD5-based subject hash)
ln -sf ${IPKG_INSTROOT}/etc/bismark/gd_root.crt $${IPKG_INSTROOT}/etc/ssl/certs/219d9499.0
ln -sf ${IPKG_INSTROOT}/etc/bismark/gd_int.crt $${IPKG_INSTROOT}/etc/ssl/certs/97552d04.0
ln -sf ${IPKG_INSTROOT}/etc/bismark/projectbismark_root.crt $${IPKG_INSTROOT}/etc/ssl/certs/1b3d9bdf.0
ln -sf ${IPKG_INSTROOT}/etc/bismark/projectbismark_int.crt $${IPKG_INSTROOT}/etc/ssl/certs/34e84591.0
# openssl >= 1.0.0 (SHA1-based subject hash)
ln -sf ${IPKG_INSTROOT}/etc/bismark/gd_root.crt $${IPKG_INSTROOT}/etc/ssl/certs/f081611a.0
ln -sf ${IPKG_INSTROOT}/etc/bismark/gd_int.crt $${IPKG_INSTROOT}/etc/ssl/certs/598630ad.0
ln -sf ${IPKG_INSTROOT}/etc/bismark/projectbismark_root.crt $${IPKG_INSTROOT}/etc/ssl/certs/275bb920.0
ln -sf ${IPKG_INSTROOT}/etc/bismark/projectbismark_int.crt $${IPKG_INSTROOT}/etc/ssl/certs/c2ea5431.0
cat $${IPKG_INSTROOT}/etc/bismark/known_hosts $${IPKG_INSTROOT}/root/.ssh/known_hosts | sort -u > $${IPKG_INSTROOT}/tmp/knownhosts.bismark
cp $${IPKG_INSTROOT}/tmp/knownhosts.bismark $${IPKG_INSTROOT}/root/.ssh/known_hosts 
rm $${IPKG_INSTROOT}/tmp/knownhosts.bismark
if [ -z "$${IPKG_INSTROOT}" ]; then
    	$${IPKG_INSTROOT}/usr/bin/bismark-bootstrap
	#$${IPKG_INSTROOT}/etc/init.d/cron stop
	#$${IPKG_INSTROOT}/etc/init.d/cron start
fi
endef

$(eval $(call BuildPackage,bismark-mgmt))

