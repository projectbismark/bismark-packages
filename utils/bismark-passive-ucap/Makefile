#
# Copyright (C) 2006-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=bismark-passive-ucap
PKG_RELEASE:=1
PKG_VERSION:=HEAD

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=git://github.com/projectbismark/bismark-passive.git
PKG_SOURCE_VERSION:=$(PKG_VERSION)
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_PROTO:=git

include $(INCLUDE_DIR)/package.mk

MAKE_FLAGS += UPDATE_INTERVAL=30
MAKE_FLAGS += BUILD_ID=$(BISMARK_PASSIVE_BUILDID)
MAKE_FLAGS += FREQUENT_UPDATES=yes
#MAKE_FLAGS += DISABLE_ANONYMIZATION=yes
#MAKE_FLAGS += ENABLE_HTTP_URL=yes
MAKE_FLAGS += debug

define Package/bismark-passive-ucap
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=PCAP-based passive observer for bismark-passive
	URL:=http://www.projectbismark.net
	DEPENDS:=+libpcap +libpthread +zlib +bismark-data-transmit
endef

define Package/bismark-passive-ucap/description
	A passive packet observer for Bismark. This examines packet sizes,
	timestamps and headers, but does not record packet contents aside from DNS
	responses. Unless explicitely disabled, all identifying information (e.g.,
	domain names, IP addresses) are anonymized using a secure hash function.
endef

define Package/bismark-passive-ucap/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bismark-passive.bin $(1)/usr/bin/bismark-passive.bin
	$(INSTALL_BIN) ./files/usr/bin/bismark-passive $(1)/usr/bin/bismark-passive
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/bismark-passive $(1)/etc/init.d/bismark-passive
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/bismark-passive $(1)/etc/config/bismark-passive
	$(INSTALL_DIR) $(1)/etc/bismark
endef

define Package/bismark-passive-ucap/postinst
#!/bin/sh
/etc/init.d/bismark-passive restart
endef

define Package/bismark-passive-ucap/prerm
#!/bin/sh
/etc/init.d/bismark-passive stop
endef

$(eval $(call BuildPackage,bismark-passive-ucap))
