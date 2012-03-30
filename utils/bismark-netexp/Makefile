#
# Copyright (C) 2007-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=bismark-netexp
PKG_VERSION:=0.1
PKG_RELEASE:=2

include $(INCLUDE_DIR)/package.mk

define Package/bismark-netexp
   SECTION:=utils
   CATEGORY:=Utilities
   TITLE:=Broadband Internet Service benchMARK
   URL:=http://projectbismark.net/
   MAINTAINER:=Bismark Development List <bismark-devel@lists.bufferbloat.net>
   DEPENDS:=+bing +bwping +tcptraceroute +paris-traceroute +httping +iperf-mt +tcpdump +hping3 +shaperprobe +bismark-ditg +time +netperf +curl +fping +tc
endef

define Package/bismark-netexp/description
	bismark-netexp is a meta package that includes useful networking tools.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
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
define Package/bismark-netexp/install
	$(INSTALL_DIR) $(1)/etc
endef

define Package/bismark-netexp/preinst
endef

define Package/bismark-netexp/prerm
endef

define Package/bismark-netexp/postinst
endef

$(eval $(call BuildPackage,bismark-netexp))

