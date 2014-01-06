include $(TOPDIR)/rules.mk

PKG_NAME:=bismark-censorship-performance-measurements-tmpfs
PKG_VERSION:=0.11
PKG_RELEASE:=2

include $(INCLUDE_DIR)/package.mk


define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)
endef

define Build/Compile
	$(MAKE_VARS) $(MAKE) -C "$(PKG_BUILD_DIR)" $(MAKE_FLAGS) web100 || true
	$(MAKE_VARS) $(MAKE) -C "$(PKG_BUILD_DIR)" $(MAKE_FLAGS) web10g || true
endef

define Package/bismark-censorship-performance-measurements-web100-tmpfs
   SECTION:=utils
   CATEGORY:=Utilities
   TITLE:=Examine performance differences between countries to attempt to infer censorship
   DEPENDS:=web100_userland +bismark-mgmt +bismark-netexp +netcat
   PROVIDES:=bismark-censorship-performance-measurements-tmpfs
endef

define Package/bismark-censorship-performance-measurements-web100-tmpfs/description
   Look at the web performance of a few sites in several countries across the globe
endef

define Package/bismark-censorship-performance-measurements-web100-tmpfs/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/usr/bin/simple_webtest $(1)/usr/bin/censorship-performance-measurements-http
	$(INSTALL_DIR) $(1)/etc/cron.d
	$(INSTALL_DATA) ./files/etc/cron.d/censorship-performance-measurements $(1)/etc/cron.d/censorship-performance-measurements
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/measure-web-performance $(1)/usr/bin/measure-web-performance
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/get-web100-stats $(1)/usr/bin/get-web100-stats

endef

define Package/bismark-censorship-performance-measurements-web100-tmpfs/postinst
#!/bin/sh
mkdir -p /tmp/censorship-performance-measurements
crontab -l | grep -v bismark-censorship-performance | crontab -
endef

define Package/bismark-censorship-performance-measurements-web100-tmpfs/prerm
#!/bin/sh
rm -rf /tmp/censorship-performance-measurements
endef

$(eval $(call BuildPackage,bismark-censorship-performance-measurements-web100-tmpfs))

define Package/bismark-censorship-performance-measurements-web10g-tmpfs
   SECTION:=utils
   CATEGORY:=Utilities
   TITLE:=Examine performance differences between countries to attempt to infer censorship
   DEPENDS:=kmod-tcp-estats-nl +bismark-mgmt +bismark-netexp +netcat +libmnl
   PROVIDES:=bismark-censorship-performance-measurements-tmpfs
endef

define Package/bismark-censorship-performance-measurements-web10g-tmpfs/description
   Look at the web performance of a few sites in several countries across the globe
endef

define Package/bismark-censorship-performance-measurements-web10g-tmpfs/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/usr/bin/simple_webtest $(1)/usr/bin/censorship-performance-measurements-http
	$(INSTALL_DIR) $(1)/etc/cron.d
	$(INSTALL_DATA) ./files/etc/cron.d/censorship-performance-measurements $(1)/etc/cron.d/censorship-performance-measurements
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/measure-web-performance $(1)/usr/bin/measure-web-performance
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/get-web10g-stats $(1)/usr/bin/get-web10g-stats
endef

define Package/bismark-censorship-performance-measurements-web10g-tmpfs/postinst
#!/bin/sh
mkdir -p /tmp/censorship-performance-measurements
crontab -l | grep -v bismark-censorship-performance | crontab -
endef

define Package/bismark-censorship-performance-measurements-web10g-tmpfs/prerm
#!/bin/sh
rm -rf /tmp/censorship-performance-measurements
endef

$(eval $(call BuildPackage,bismark-censorship-performance-measurements-web10g-tmpfs))
