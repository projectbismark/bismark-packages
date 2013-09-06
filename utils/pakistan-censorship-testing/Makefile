#
# Copyright (C) 2007-2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=pakistan-censorship-testing-tmpfs
PKG_VERSION:=0.1
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/pakistan-censorship-testing-tmpfs
   SECTION:=utils
   CATEGORY:=Utilities
   TITLE:=Censorship testing in Pakistan
   DEPENDS:=+bismark-mgmt +bismark-netexp
endef

define Package/pakistan-censorship-testing-tmpfs/description
	Censorship testing in Pakistan.
endef

define Build/Compile
endef

define Package/pakistan-censorship-testing-tmpfs/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/usr/bin/pakistan-censorship-testing $(1)/usr/bin/pakistan-censorship-testing
endef

define Package/pakistan-censorship-testing-tmpfs/postinst
#!/bin/sh
(crontab -l | grep -v pakistan-censorship-testing; echo '*/10 3,9,15,21 * * * /tmp/usr/bin/pakistan-censorship-testing') | crontab -
endef

define Package/pakistan-censorship-testing-tmpfs/prerm
#!/bin/sh
(crontab -l | grep -v pakistan-censorship-testing) | crontab -
endef

$(eval $(call BuildPackage,pakistan-censorship-testing-tmpfs))
