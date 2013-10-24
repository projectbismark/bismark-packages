#
# Copyright (C) 2007-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=bismark-active-tmpfs
PKG_VERSION:=HEAD
PKG_RELEASE:=25

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=git://github.com/projectbismark/bismark-active.git
PKG_SOURCE_VERSION:=$(PKG_VERSION)
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_PROTO:=git

include $(INCLUDE_DIR)/package.mk

define Package/bismark-active-tmpfs
   SECTION:=utils
   CATEGORY:=Utilities
   TITLE:=Broadband Internet Service benchMARK - Active measurement tools
   URL:=http://www.networkdashboard.org/
   MAINTAINER:=Bismark Development List <bismark-devel@projectbismark.net>
   DEPENDS:=+bismark-mgmt +bismark-netexp
endef

define Package/bismark-active-tmpfs/description
	The bismark-active-tmpfs package runs active network measurements 
endef

define Build/Compile
endef

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
	crontab -l | grep -sv bismark-measure-wrapper | sort -u | crontab -
	/etc/init.d/cron restart
fi
endef

define Package/bismark-active-tmpfs/prerm
$(call Package/bismark-active-tmpfs/preinst)
endef

define Package/bismark-active-tmpfs/postinst
#!/bin/sh
# Bismark active-tmpfs post-install script

if [ -z "$${IPKG_INSTROOT}" ]; then
	(crontab -l; echo "*/1  * * * * /tmp/usr/bin/bismark-measure-wrapper  # remove on reboot") | sort -u > /tmp/bismark-crontab
	if ! cmp -s /etc/crontabs/root /tmp/bismark-crontab; then
		crontab /tmp/bismark-crontab
	fi
	rm /tmp/bismark-crontab
	/etc/init.d/cron restart
	bismark-action scriptupdate
	#$${IPKG_INSTROOT}/usr/bin/bismark-bootstrap
fi
endef


$(eval $(call BuildPackage,bismark-active-tmpfs))
