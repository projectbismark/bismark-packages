#
# Copyright (C) 2007-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=bismark-active-tmpfs
PKG_VERSION:=0.2
PKG_RELEASE:=22

include $(INCLUDE_DIR)/package.mk

define Package/bismark-active-tmpfs
   SECTION:=utils
   CATEGORY:=Utilities
   TITLE:=Broadband Internet Service benchMARK - Active measurement tools
   URL:=http://www.networkdashboard.org/
   MAINTAINER:=Bismark Development List <bismark-devel@lists.bufferbloat.net>
   DEPENDS:=+bismark-mgmt +bismark-netexp
endef

define Package/bismark-active-tmpfs/description
	The bismark-active-tmpfs package includes tools meant for active network measurements
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)/{scripts,etc,lib}
	[ -d files ] && ( cd files ; git pull ) || git clone git://github.com/projectbismark/bismark.git files
	$(CP) files/device/OpenWrt_common/scripts/bismark-{measure-active,measure-wrapper,tr,rtr,ptr,rptr,ping,fping,netperf,dns,ditg,sp,mstats,sysctl} $(PKG_BUILD_DIR)/scripts
	$(CP) files/device/OpenWrt_common/etc/{bismark-active.conf,crontab-active-tmpfs,sysctl.conf} $(PKG_BUILD_DIR)/etc
	$(CP) files/device/OpenWrt_common/lib/*.list $(PKG_BUILD_DIR)/lib
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
define Package/bismark-active-tmpfs/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_DIR) $(1)/usr/lib/bismark
	$(INSTALL_DIR) $(1)/etc/bismark
	$(CP) -p $(PKG_BUILD_DIR)/scripts/* $(1)/usr/bin/
	$(CP) -p $(PKG_BUILD_DIR)/lib/* $(1)/usr/lib/bismark/
	$(CP) -p $(PKG_BUILD_DIR)/etc/* $(1)/etc/bismark/
endef

define Package/bismark-active-tmpfs/preinst
#!/bin/sh
# Bismark active-tmpfs pre-install script: clear crontab
if [ -z "$${IPKG_INSTROOT}" ]; then
	if [ -e /tmp/etc/bismark/crontab-active-tmpfs ]; then
		grep -sFvf /tmp/etc/bismark/crontab-active-tmpfs /etc/crontabs/root | sort -u | crontab -
	fi
fi
endef

define Package/bismark-active-tmpfs/prerm
$(call Package/bismark-active-tmpfs/preinst)
endef

define Package/bismark-active-tmpfs/postinst
#!/bin/sh
# Bismark active-tmpfs post-install script

if [ -z "$${IPKG_INSTROOT}" ]; then
    $${IPKG_INSTROOT}/usr/bin/bismark-bootstrap
fi
endef


$(eval $(call BuildPackage,bismark-active-tmpfs))
