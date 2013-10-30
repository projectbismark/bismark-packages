include $(TOPDIR)/rules.mk

PKG_NAME:=bismark-censorship-performance-measurements-tmpfs
PKG_VERSION:=0.3
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/bismark-censorship-performance-measurements-tmpfs
   SECTION:=utils
   CATEGORY:=Utilities
   TITLE:=Examine performance differences between countries to attempt to infer censorship
   DEPENDS:=+bismark-mgmt +bismark-netexp +netcat
endef

define Package/bismark-censorship-performance-measurements-tmpfs/description
   Look at the web performance of a few sites in several countries across the globe
endef

define Build/Compile
$(MAKE_VARS) $(MAKE) -C ./src
endef

define Package/bismark-censorship-performance-measurements-tmpfs/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/usr/bin/simple_webtest $(1)/usr/bin/censorship-performance-measurements-http
	$(INSTALL_BIN) ./src/measure-web-performance $(1)/usr/bin/measure-web-performance
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_DATA) ./files/etc/censorship-performance-measurements.crontab $(1)/etc/censorship-performance-measurements.crontab
	$(INSTALL_DIR) $(1)/etc/censorship-performance-measurements
	$(INSTALL_DATA) ./files/etc/censorship-performance-measurements/usRouters.txt $(1)/etc/censorship-performance-measurements/usRouters.txt
endef

define Package/bismark-censorship-performance-measurements-tmpfs/postinst
#!/bin/sh
crontab -l | cat - /tmp/etc/censorship-performance-measurements.crontab | sort -u | crontab -
mkdir /tmp/censorship-performance-measurements
endef

define Package/bismark-censorship-performance-measurements-tmpfs/prerm
#!/bin/sh
crontab -l | grep -sFv -f /tmp/etc/censorship-performance-measurements.crontab | crontab -
rm -rf /tmp/censorship-performance-measurements
endef

$(eval $(call BuildPackage,bismark-censorship-performance-measurements-tmpfs))
