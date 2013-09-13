include $(TOPDIR)/rules.mk

PKG_NAME:=censorship-performance-measurements-tmpfs
PKG_VERSION:=0.1
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/censorship-performance-measurements-tmpfs
   SECTION:=utils
   CATEGORY:=Utilities
   TITLE:=Examine performance differences between countries to attempt to infer censorship
   DEPENDS:=+bismark-mgmt +bismark-netexp +netcat
endef

define Package/censorship-performance-measurements-tmpfs/description
	Look at the web performance of a few sites in several countries across the globe
endef

define Build/Compile
endef

define Package/censorship-performance-measurements-tmpfs/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/usr/bin/simple_webtest $(1)/usr/bin/censorship-performance-measurements-http
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_DATA) ./files/etc/censorship-performance-measurements.crontab $(1)/etc/censorship-performance-measurements.crontab
endef

define Package/censorship-performance-measurements-tmpfs/postinst
#!/bin/sh
crontab -l | cat - /tmp/etc/censorship-performance-measurements.crontab | sort -u | crontab -
mkdir /tmp/censorship-performance-measurements
endef

define Package/censorship-performance-measurements-tmpfs/prerm
#!/bin/sh
crontab -l | grep -sFv -f /tmp/etc/censorship-performance-measurements.crontab | crontab -
rm -rf /tmp/censorship-performance-measurements
endef

$(eval $(call BuildPackage,censorship-performance-measurements-tmpfs))
