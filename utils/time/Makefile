# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=time
PKG_VERSION:=1.7
PKG_RELEASE:=10

PKG_FIXUP:=libtool

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=@GNU/time
PKG_MD5SUM:=e38d2b8b34b1ca259cf7b053caac32b3

include $(INCLUDE_DIR)/package.mk

define Package/time/Default
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=The GNU time utility 
  URL:=http://www.gnu.org/software/time/
endef

define Package/time
  $(call Package/time/Default)
  TITLE:=The GNU time utility 
  MENU:=1
endef

define Package/time/description
	The GNU time utility
endef

define Build/Compile
        $(MAKE) -C $(PKG_BUILD_DIR)
endef

define Package/time/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/time $(1)/usr/bin/gtime
endef

define Package/time/postinst
#!/bin/sh
if [ -e $${IPKG_INSTROOT}/usr/bin/time ]; then
  rm -rf $${IPKG_INSTROOT}/usr/bin/time
fi
ln -sf ./gtime $${IPKG_INSTROOT}/usr/bin/time
endef

define Package/time/postrm
#!/bin/sh
rm $${IPKG_INSTROOT}/usr/bin/time
ln -s ../../bin/busybox $${IPKG_INSTROOT}/usr/bin/time
$${IPKG_INSTROOT}/usr/bin/time 2>&1 | grep 'applet not found' > /dev/null 2>&1 && rm $${IPKG_INSTROOT}/usr/bin/time
exit 0
endef

$(eval $(call BuildPackage,time))
