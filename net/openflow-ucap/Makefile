# 
# Copyright (C) 2009 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# $Id: Makefile $

include $(TOPDIR)/rules.mk

PKG_NAME_SHORT:=openflow-ucap
PKG_NAME:=kmod-$(PKG_NAME_SHORT)
PKG_RELEASE:=3
PKG_VERSION:=HEAD

PKG_SOURCE:=$(PKG_NAME_SHORT)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=git://github.com/projectbismark/openflow-ucap.git
PKG_SOURCE_VERSION:=$(PKG_VERSION)
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_PROTO:=git

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_FIXUP = libtool

define Package/openflow-ucap/Default
  SECTION:=net
  CATEGORY:=Network
  URL:=http://www.openflowswitch.org/
  MAINTAINER:=Yiannis Yiakoumis (yiannisy@stanford.edu) 
  PROVIDES:=openflow
endef

define Package/openflow-ucap/Default/description
 OpenFlow is an open standard that allows you to run experimental 
 protocols in production networks. It is in the process of being 
 implemented by major switch vendors and used today by universities 
 to deploy innovative networking technology in their campus network. 
 This is the version specifically for embedded low cost router.

 This is a modified version of OpenFlow that anonymizes the MAC addresses
 it sends to the controller using BISmark's anonymization key.
endef

define Package/openflow-ucap
  $(call Package/openflow-ucap/Default)
  TITLE:=Open Flow Switch Userspace Package
endef

define Package/openflow-ucap/description
 This package contains the OPENFLOW userspace implementation.
 OpenFlow is an architecture for Ethernet switches and 
 routers, which allows a researcher to experiment 
 with new functionality in their own network; for example, 
 to add a new routing protocol, a new management technique, a 
 novel packet processing algorithm, or even - eventually - 
 alternatives to IP.
endef

define Build/Prepare
	$(call Build/Prepare/Default)
	autoreconf --install --force $(PKG_BUILD_DIR)
endef 

define Build/Configure
	$(call Build/Configure/Default,$(CONFIGURE_ARGS))
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS) -std=c99" \
		LDFLAGS="$(TARGET_LDFLAGS)" \
		LDFLAGS_MODULES="$(TARGET_LDFLAGS)" \
		PRECOMPILED_FILTER=1 \
		STAGING_DIR="$(STAGING_DIR)" \
		DESTDIR="$(PKG_INSTALL_DIR)/usr" \
		CROSS_COMPILE="$(TARGET_CROSS)" \
		ARCH="$(LINUX_KARCH)" \
		PATH="$(TARGET_PATH)" \
		KCC="$(KERNEL_CC)"
endef

define Package/openflow-ucap/install
	$(INSTALL_DIR) $(1)/etc/init.d $(1)/etc/config $(1)/etc/hotplug.d/ofiface
	$(INSTALL_DATA) ./files/etc/config/openflow $(1)/etc/config
	$(INSTALL_BIN) ./files/etc/init.d/openflow $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/hotplug.d/ofiface/00-netstate $(1)/etc/hotplug.d/ofiface

	$(INSTALL_DIR) $(1)/lib/openflow
	$(INSTALL_BIN) ./files/lib/openflow/ofinterfaces.sh $(1)/lib/openflow
	$(INSTALL_BIN) ./files/lib/openflow/ofswitch.sh $(1)/lib/openflow
	$(INSTALL_BIN) ./files/lib/openflow/ofprotocol.sh $(1)/lib/openflow

	$(INSTALL_DIR) $(1)/sbin/
	$(INSTALL_BIN) ./files/sbin/ofup $(1)/sbin/
	$(INSTALL_BIN) ./files/sbin/ofdown $(1)/sbin/

	$(INSTALL_DIR) $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/secchan/ofprotocol $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/udatapath/ofdatapath $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/controller/controller $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/utilities/dpctl $(1)/usr/bin/
endef

$(eval $(call BuildPackage,openflow-ucap))
