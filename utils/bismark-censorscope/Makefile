#
# Copyright (C) 2006-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=bismark-censorscope
PKG_VERSION:=v1
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=git://github.com/projectbismark/censorscope.git
PKG_SOURCE_VERSION:=$(PKG_VERSION)
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_PROTO:=git

include $(INCLUDE_DIR)/package.mk

define Package/bismark-censorscope
	SECTION:=util
	CATEGORY:=Utilities
	TITLE:=Sandboxed Lua environment for running network experiments
	URL:=https://github.com/projectbismark/censorscope
	DEPENDS:=+bismark-data-transmit +liblua +libldns +libevent2 +libcurl
endef

define Package/bismark-censorscope/description
	Censorscope is a sandboxed Lua environment for running networking
	experiments, particularly experiments for measuring network filtering
	and censorship.
endef

define Package/bismark-censorscope/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/censorscope $(1)/usr/bin/censorscope
endef

$(eval $(call BuildPackage,bismark-censorscope))
