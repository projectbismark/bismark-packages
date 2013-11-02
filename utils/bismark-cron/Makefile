#
# Copyright (C) 2006-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=bismark-cron
PKG_VERSION:=2
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/bismark-cron
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=Manage crontab directories.
	URL:=http://www.projectbismark.net
	DEPENDS:=
endef

define Package/bismark-cron/description
	bismark-cron manages the crontab. It lets you put cron entries in separate
	files in /etc/cron.d and /var/cron.d and will generate a system-side crontab
	using those files, alleviating you from managing your own crontab.
endef

define Build/Compile
endef

define Package/bismark-cron/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/usr/bin/bismark-cron $(1)/usr/bin/bismark-cron
	$(INSTALL_DIR) $(1)/etc/crontabs.d
	$(INSTALL_DATA) ./files/etc/crontabs.d/bismark-cron $(1)/etc/crontabs.d/bismark-cron
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/bismark-cron $(1)/etc/init.d/bismark-cron
	$(INSTALL_DIR) $(1)/etc/uci-defaults
	$(INSTALL_BIN) ./files/etc/uci-defaults/bismark-cron $(1)/etc/uci-defaults/bismark-cron
endef

define Package/bismark-cron/postinst
#!/bin/sh
if [ -z "$${IPKG_INSTROOT}" ]; then
	/etc/uci-defaults/bismark-cron
	rm /etc/uci-defaults/bismark-cron
fi
endef

define Package/bismark-cron/prerm
#!/bin/sh
crontab -l | grep -sFv -f /etc/crontabs.d/bismark-cron | sort -u | crontab -
/etc/init.d/bismark-cron disable
endef

$(eval $(call BuildPackage,bismark-cron))
