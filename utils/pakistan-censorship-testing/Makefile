include $(TOPDIR)/rules.mk

PKG_NAME:=pakistan-censorship-testing-tmpfs
PKG_VERSION:=0.1
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/pakistan-censorship-testing-tmpfs
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=Censorship testing in Pakistan
	URL:=http://www.projectbismark.net
	DEPENDS:=+bismark-netexp +bismark-mgmt
endef

define Package/pakistan-censorship-testing-tmpfs/description
	Censorship testing in Pakistan.
endef

define Build/Compile
endef

define Package/pakistan-censorship-testing-tmpfs/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/usr/bin/pakistan-censorship-testing $(1)/usr/bin/pakistan-censorship-testing
	$(INSTALL_DATA) ./files/etc/pakistan-censorship-testing.crontab $(1)/etc/pakistan-censorship-testing.crontab
endef

define Package/pakistan-censorship-testing-tmpfs/postinst
#!/bin/sh
crontab -l | cat - /tmp/etc/pakistan-censorship-testing.crontab | sort -u | crontab -
endef

define Package/pakistan-censorship-testing-tmpfs/prerm
#!/bin/sh
crontab -l | grep -sFv -f /tmp/etc/pakistan-censorship-testing.crontab | crontab -
endef

$(eval $(call BuildPackage,pakistan-censorship-testing-tmpfs))
