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

include $(INCLUDE_DIR)/package.mk

ifneq ($(CONFIG_BISMARK_PASSIVE_ANONYMIZE),y)
	MAKE_FLAGS += DISABLE_ANONYMIZATION=yes
endif
MAKE_FLAGS += $(CONFIG_BISMARK_PASSIVE_TARGET)
MAKE_FLAGS += UPDATE_INTERVAL=$(CONFIG_BISMARK_PASSIVE_UPDATE_INTERVAL)

define Package/bismark-passive-git
	SECTION:=net
	CATEGORY:=Network
	TITLE:=PCAP-based passive observer for bismark-passive
	URL:=http://www.projectbismark.net
	DEPENDS:=+libopenssl +libpcap +libpthread +zlib
endef

define Package/bismark-passive-git/description
	A passive packet observer for Bismark. This examines packet sizes,
	timestamps and headers, but does not record packet contents aside from DNS
	responses. Unless explicitely disabled, all identifying information (e.g.,
	domain names, IP addresses) are anonymized using a secure hash function.
endef

define Package/bismark-passive-git/config
	source "$(SOURCE)/Config.in"
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	git clone -- $(GIT_URL) $(PKG_BUILD_DIR)
endef

define Package/bismark-passive-git/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/bismark-passive.bin $(1)/usr/bin/bismark-passive.bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/scripts/bismark-passive $(1)/usr/bin/bismark-passive
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/scripts/bismark-passive-submit $(1)/usr/bin/bismark-passive-submit
endef

define Package/bismark-passive-git/postinst
#!/bin/sh
CT_TEMP=`mktemp`
crontab -l | grep -v bismark-passive-submit > $$CT_TEMP
echo */$(CONFIG_BISMARK_PASSIVE_UPLOAD_INTERVAL) * * * * /usr/bin/bismark-passive-submit >> $$CT_TEMP
crontab $$CT_TEMP
rm $$CT_TEMP
endef

define Package/bismark-passive-git/prerm
#!/bin/sh
CT_TEMP=`mktemp`
crontab -l | grep -v bismark-passive-submit > $$CT_TEMP
crontab $$CT_TEMP
rm $$CT_TEMP
endef

$(eval $(call BuildPackage,bismark-passive-git))
