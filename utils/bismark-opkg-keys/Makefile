#
# Copyright (C) 2006-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=bismark-opkg-keys
PKG_VERSION:=1
PKG_RELEASE:=2

include $(INCLUDE_DIR)/package.mk

define Package/bismark-opkg-keys
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=Opkg package signing.
	URL:=http://www.projectbismark.net
	MAINTAINER:=Bismark Development List <bismark-devel@projectbismark.net>
	DEPENDS:=+opkg-bismark +opkg
endef

define Package/bismark-opkg-keys/description
	Opkg package signing enables secure installation of packages from certified bismark source list.
endef

define Build/Compile
endef

define Package/bismark-opkg-keys/install
	$(INSTALL_DIR) $(1)/etc/ssl
	$(INSTALL_DATA) ./files/etc/ssl/serverCA.pem $(1)/etc/ssl/serverCA.pem
endef

define Package/bismark-opkg-keys/postinst
#!/bin/sh                                                                                                                          

if [ -z "$${IPKG_INSTROOT}" ]; then                                                                                                                                   
    if  ! grep -Fs "signature" /etc/opkg.conf >/dev/null ; then
        sed -i '$$aoption check_signature 1'  /etc/opkg.conf
        sed -i '$$aoption signature_ca_file /etc/ssl/serverCA.pem'  /etc/opkg.conf
        sed -i '$$aoption signature_ca_path /etc/ssl/'  /etc/opkg.conf
    fi
fi
endef

define Package/bismark-opkg-keys/prerm
#!/bin/sh

sed -i '/signature/d' /etc/opkg.conf
endef

$(eval $(call BuildPackage,bismark-opkg-keys))
