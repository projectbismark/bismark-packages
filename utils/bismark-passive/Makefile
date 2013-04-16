#
# Copyright (C) 2006-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=bismark-passive
PKG_RELEASE:=20
PKG_VERSION:=HEAD

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_RELEASE).tar.gz
PKG_SOURCE_URL:=git://github.com/projectbismark/bismark-passive.git
PKG_SOURCE_VERSION:=$(PKG_VERSION)
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_PROTO:=git

include $(INCLUDE_DIR)/package.mk

define Build/Compile
	mkdir -p \
		$(PKG_BUILD_DIR)/bismark-passive-tmpfs \
		$(PKG_BUILD_DIR)/bismark-passive-http-url-tmpfs \
		$(PKG_BUILD_DIR)/bismark-passive-ucap \
		$(PKG_BUILD_DIR)/bismark-passive-hasher-tmpfs
	$(MAKE_VARS) $(MAKE) -C "$(PKG_BUILD_DIR)" \
		$(MAKE_FLAGS) \
		UPDATE_INTERVAL=30 \
		BUILD_ID=$(BISMARK_PASSIVE_BUILDID) \
		EXE=bismark-passive.bin \
		BUILD_DIR=$(PKG_BUILD_DIR)/bismark-passive-tmpfs \
		release
	$(MAKE_VARS) $(MAKE) -C "$(PKG_BUILD_DIR)" \
		$(MAKE_FLAGS) \
		UPDATE_INTERVAL=30 \
		BUILD_ID=$(BISMARK_PASSIVE_BUILDID) \
		ENABLE_HTTP_URL=yes \
		EXE=bismark-passive-http-url.bin \
		BUILD_DIR=$(PKG_BUILD_DIR)/bismark-passive-http-url-tmpfs \
		release
	$(MAKE_VARS) $(MAKE) -C "$(PKG_BUILD_DIR)" \
		$(MAKE_FLAGS) \
		UPDATE_INTERVAL=30 \
		BUILD_ID=$(BISMARK_PASSIVE_BUILDID) \
		FREQUENT_UPDATES=yes \
		EXE=bismark-passive-ucap.bin \
		BUILD_DIR=$(PKG_BUILD_DIR)/bismark-passive-ucap \
		release
	$(MAKE_VARS) $(MAKE) -C "$(PKG_BUILD_DIR)" \
		$(MAKE_FLAGS) \
		BUILD_ID=$(BISMARK_PASSIVE_BUILDID) \
		HASHER_EXE=bismark-passive-hasher.bin \
		BUILD_DIR=$(PKG_BUILD_DIR)/bismark-passive-hasher-tmpfs \
		hasher
endef

define InstallCommon
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/usr/bin/bismark-passive $(1)/usr/bin/bismark-passive
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/bismark-passive $(1)/etc/init.d/bismark-passive
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/bismark-passive $(1)/etc/config/bismark-passive
	$(INSTALL_DIR) $(1)/etc/bismark
endef


define Package/bismark-passive-tmpfs
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=PCAP-based passive observer for bismark-passive
	URL:=http://www.projectbismark.net
	DEPENDS:=+bismark-data-transmit +bismark-mgmt +libpcap +libpthread +zlib 
	PROVIDES:=bismark-passive
endef

define Package/bismark-passive-tmpfs/description
	A passive packet observer for Bismark. This examines packet sizes,
	timestamps and headers, but does not record packet contents aside from DNS
	responses. Unless explicitely disabled, all identifying information (e.g.,
	domain names, IP addresses) are anonymized using a secure hash function.
endef

define Package/bismark-passive-tmpfs/install
	$(call InstallCommon,$1)
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bismark-passive.bin $(1)/usr/bin/bismark-passive.bin
endef

define Package/bismark-passive-tmpfs/postinst
#!/bin/sh
/tmp/etc/init.d/bismark-passive restart
endef

define Package/bismark-passive-tmpfs/prerm
#!/bin/sh
/tmp/etc/init.d/bismark-passive stop
endef

$(eval $(call BuildPackage,bismark-passive-tmpfs))


define Package/bismark-passive-http-url-tmpfs
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=PCAP-based passive observer for bismark-passive
	URL:=http://www.projectbismark.net
	DEPENDS:=+libpcap +libpthread +zlib +bismark-data-transmit
	PROVIDES:=bismark-passive
endef

define Package/bismark-passive-http-url-tmpfs/description
	A passive packet observer for Bismark. This examines packet sizes,
	timestamps and headers, but does not record packet contents aside from DNS
	responses. Unless explicitely disabled, all identifying information (e.g.,
	domain names, IP addresses) are anonymized using a secure hash function.
	This package includes support for recording hashed URLs.
endef

define Package/bismark-passive-http-url-tmpfs/install
	$(call InstallCommon,$1)
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bismark-passive-http-url.bin $(1)/usr/bin/bismark-passive.bin
endef

define Package/bismark-passive-http-url-tmpfs/postinst
#!/bin/sh
/tmp/etc/init.d/bismark-passive restart
endef

define Package/bismark-passive-http-url-tmpfs/prerm
#!/bin/sh
/tmp/etc/init.d/bismark-passive stop
endef

$(eval $(call BuildPackage,bismark-passive-http-url-tmpfs))


define Package/bismark-passive-ucap
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=PCAP-based passive observer for bismark-passive
	URL:=http://www.projectbismark.net
	DEPENDS:=+libpcap +libpthread +zlib +bismark-data-transmit +ucap
	PROVIDES:=bismark-passive
endef

define Package/bismark-passive-ucap/description
	A passive packet observer for Bismark. This examines packet sizes,
	timestamps and headers, but does not record packet contents aside from DNS
	responses. Unless explicitely disabled, all identifying information (e.g.,
	domain names, IP addresses) are anonymized using a secure hash function.
	This package contains support for sending frequent usage updates to uCap.
endef

define Package/bismark-passive-ucap/install
	$(call InstallCommon,$1)
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bismark-passive-ucap.bin $(1)/usr/bin/bismark-passive.bin
endef

define Package/bismark-passive-ucap/postinst
#!/bin/sh
/etc/init.d/bismark-passive enable
/etc/init.d/bismark-passive restart
endef

define Package/bismark-passive-ucap/prerm
#!/bin/sh
/etc/init.d/bismark-passive stop
/etc/init.d/bismark-passive disable
endef

$(eval $(call BuildPackage,bismark-passive-ucap))


define Package/bismark-passive-hasher-tmpfs
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=Utility for manually hashing MAC addresses for BISmark Passive.
	URL:=http://www.projectbismark.net
	DEPENDS:=+libpcap +zlib
endef

define Package/bismark-passive-hasher-tmpfs/description
	This is a utility for manually hashing MAC addresses for BISmark Passive.
	You should not install it unless you know what you're doing.
endef

define Package/bismark-passive-hasher-tmpfs/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bismark-passive-hasher.bin $(1)/usr/bin/bismark-passive-hasher
endef

$(eval $(call BuildPackage,bismark-passive-hasher-tmpfs))
