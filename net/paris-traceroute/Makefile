#
# Copyright (C) 2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=paris-traceroute
PKG_VERSION:=0.92
PKG_RELEASE:=dev

#PKG_BUILD_DIR:=$(BUILD_DIR)/D-ITG-${PKG_VERSION}-${PKG_RELEASE}

include $(INCLUDE_DIR)/package.mk

define Package/paris-traceroute
  TITLE:=Paris Traceroute 
  SECTION:=net
  CATEGORY:=Network
  URL:=http://www.paris-traceroute.net
  MAINTAINER:=LIP6
  DEPENDS:=+uclibcxx 
endef

define Package/paris-traceroute/Default/description
Paris traceroute is a new version of the well-known network diagnosis and measurement tool. It addresses problems caused by load balancers with the initial implementation of traceroute.
endef

define Package/paris-traceroute
  $(call Package/traceroute/Default)
endef

TARGET_CXX=g++-uc

define Build/Compile
	$(PKG_BUILD_DIR)/src/$(CONFIGURE_CMD)
	$(MAKE) \
		CXX="$(TARGET_CXX)" \
		CXXOPT="-DMULTIPORT -DARM $(TARGET_CFLAGS) $(TARGET_CPPFLAGS)" \
		-C $(PKG_BUILD_DIR)/src 
endef

define Package/paris-traceroute/install
	$(INSTALL_DIR) $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bin/paris-traceroute $(1)/usr/bin/paris-traceroute
endef

$(eval $(call BuildPackage,paris-traceroute))
