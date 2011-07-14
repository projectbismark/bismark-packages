#
# Copyright (C) 2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=ditg
PKG_VERSION:=2.8.0
PKG_RELEASE:=rc1

PKG_SOURCE:=D-ITG-${PKG_VERSION}-${PKG_RELEASE}.tgz
#PKG_SOURCE_URL:=http://www.grid.unina.it/software/ITG/codice/
PKG_SOURCE_URL:=http://143.215.131.215:4096/
#PKG_MD5SUM:=55f79b1c49d291fe5fad293a785c3451

PKG_BUILD_DIR:=$(BUILD_DIR)/D-ITG-${PKG_VERSION}-${PKG_RELEASE}

include $(INCLUDE_DIR)/package.mk

define Package/ditg/Default
  TITLE:=D-ITG (Distributed Internet Traffic Generator)
  SECTION:=net
  CATEGORY:=Network
  URL:=http://www.grid.unina.it/software/ITG/
  MAINTAINER:=Giovanni Di Stasi <giovanni.distasi@unina.it>
  DEPENDS:= +libpcap 
endef

define Package/ditg/Default/description
  D-ITG (Distributed Internet Traffic Generator) is a platform capable
  to produce traffic at packet level accurately replicating appropriate
  stochastic processes for both IDT (Inter Departure Time) and PS
  (Packet Size) random variables (exponential, uniform, cauchy, normal,
  pareto, ...). D-ITG supports both IPv4 and IPv6 traffic generation and
  it is capable to generate traffic at network, transport, and
  application layer. We believe that D-ITG shows interesting properties
  when compared to other traffic generators.
endef

define Package/ditg
  $(call Package/ditg/Default)
endef

define Build/Compile
	$(MAKE) \
		CXX="$(TARGET_CXX)-uc" \
		CXXOPT="-DARM $(TARGET_CFLAGS) $(TARGET_CPPFLAGS)" \
		LDOPT="-luClibc++"
		-C $(PKG_BUILD_DIR)/src 
endef

define Package/ditg/install
	$(INSTALL_DIR) $(1)/usr/bin/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bin/{ITGSend,ITGRecv,ITGLog,ITGDec}  \
		$(1)/usr/bin
endef

$(eval $(call BuildPackage,ditg))
