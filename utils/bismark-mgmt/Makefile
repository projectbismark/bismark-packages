include $(TOPDIR)/rules.mk

PKG_NAME:=bismark-mgmt
PKG_RELEASE:=4
PKG_VERSION:=HEAD

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=git://github.com/projectbismark/bismark-management-client.git
PKG_SOURCE_VERSION:=$(PKG_VERSION)
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_PROTO:=git

include $(INCLUDE_DIR)/package.mk

define Package/bismark-mgmt
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=Broadband Internet Service benchMARK
	URL:=http://projectbismark.net/
	MAINTAINER:=Bismark Development List <bismark-devel@projectbismark.net>
	DEPENDS:=+netcat +curl +ntpclient
endef

define Package/bismark-mgmt/description
	The bismark-mgmt package makes it possible to administer a bismark
	router remotely.
endef

define Build/Compile
endef

define Package/bismark-mgmt/install
	$(INSTALL_DIR) $(1)/etc/bismark
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/etc/bismark/authorized_keys $(1)/etc/bismark/authorized_keys
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/etc/bismark/bismark.conf $(1)/etc/bismark/bismark.conf
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/etc/bismark/crontab $(1)/etc/bismark/crontab
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/etc/bismark/known_hosts $(1)/etc/bismark/known_hosts
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/etc/bismark/bismark_key $(1)/etc/bismark/bismark_key
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/etc/bismark/bismark_key.pub $(1)/etc/bismark/bismark_key.pub
	$(INSTALL_DIR) $(1)/etc/ssl/certs
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/etc/ssl/certs/gd_int.crt $(1)/etc/ssl/certs/gd_int.crt
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/etc/ssl/certs/gd_root.crt $(1)/etc/ssl/certs/gd_root.crt
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/etc/ssl/certs/projectbismark_int.crt $(1)/etc/ssl/certs/projectbismark_int.crt
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/etc/ssl/certs/projectbismark_root.crt $(1)/etc/ssl/certs/projectbismark_root.crt
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/etc/init.d/bismark $(1)/etc/init.d/bismark
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/usr/bin/bismark-action $(1)/usr/bin/bismark-action
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/usr/bin/bismark-bootstrap $(1)/usr/bin/bismark-bootstrap
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/usr/bin/bismark-probe $(1)/usr/bin/bismark-probe
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/usr/bin/bismark-rshell $(1)/usr/bin/bismark-rshell
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/usr/bin/bismark-scp $(1)/usr/bin/bismark-scp
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/usr/bin/bismark-sshd $(1)/usr/bin/bismark-sshd
	$(INSTALL_DIR) $(1)/usr/lib/bismark
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/usr/lib/bismark/functions.inc.sh $(1)/usr/lib/bismark/functions.inc.sh
	# openssl < 1.0.0 (MD5-based subject hash)
	ln -sf gd_root.crt $(1)/etc/ssl/certs/219d9499.0
	ln -sf gd_int.crt $(1)/etc/ssl/certs/97552d04.0
	ln -sf projectbismark_root.crt $(1)/etc/ssl/certs/1b3d9bdf.0
	ln -sf projectbismark_int.crt $(1)/etc/ssl/certs/34e84591.0
	# openssl >= 1.0.0 (SHA1-based subject hash)
	ln -sf gd_root.crt $(1)/etc/ssl/certs/f081611a.0
	ln -sf gd_int.crt $(1)/etc/ssl/certs/598630ad.0
	ln -sf projectbismark_root.crt $(1)/etc/ssl/certs/275bb920.0
	ln -sf projectbismark_int.crt $(1)/etc/ssl/certs/c2ea5431.0
	sed -i 's/VERSION=0/VERSION='`head -4 $(TOPDIR)/files/etc/issue | tail -1`'/' $(1)/etc/bismark/bismark.conf
endef

define Package/bismark-mgmt/postinst
#!/bin/sh
# Bismark management post-install script
cp $${IPKG_INSTROOT}/root/.ssh/known_hosts $${IPKG_INSTROOT}/tmp/known_hosts
sort -u $${IPKG_INSTROOT}/tmp/known_hosts $${IPKG_INSTROOT}/etc/bismark/known_hosts > $${IPKG_INSTROOT}/root/.ssh/known_hosts
if [ -z "$${IPKG_INSTROOT}" ]; then
	$${IPKG_INSTROOT}/usr/bin/bismark-bootstrap
fi
endef

define Package/bismark-mgmt/prerm
grep -sFv -f /etc/bismark/crontab /etc/crontabs/root | sort -u | crontab -
cp /root/.ssh/known_hosts /tmp/known_hosts
grep -sFv -f /etc/bismark/known_hosts /tmp/known_hosts | sort -u > /root/.ssh/known_hosts
endef

$(eval $(call BuildPackage,bismark-mgmt))
