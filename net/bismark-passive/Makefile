#
# Copyright (C) 2006-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=bismark-passive-git
PKG_VERSION:=head
PKG_RELEASE:=2

GIT_URL:=git://github.com/sburnett/bismark-passive.git
GIT_DIR:=bismark-passive

MAKE_FLAGS += DISABLE_ANONYMIZATION=$(DISABLE_ANONYMIZATION)
MAKE_FLAGS += $(BISMARK_PASSIVE_TARGET)

include $(INCLUDE_DIR)/package.mk

define Package/bismark-passive
	SECTION:=net
	CATEGORY:=Network
	TITLE:=PCAP-based passive observer for bismark-passive
	URL:=http://www.projectbismark.net
	DEPENDS:=+libopenssl +libpcap +libpthread +zlib
endef

define Package/bismark-passive/description
	A passive packet observer for Bismark. This examines packet sizes,
	timestamps and headers, but does not record packet contents aside from DNS
	responses. Unless explicitely disabled, all identifying information (e.g.,
	domain names, IP addresses) are anonymized using a secure hash function.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	git clone -- $(GIT_URL) $(PKG_BUILD_DIR)
endef

define Package/bismark-passive/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bismark-passive $(1)/usr/bin/bismark-passive
endef

$(eval $(call BuildPackage,bismark-passive))
