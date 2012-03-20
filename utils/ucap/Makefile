#
# Copyright (C) 2006-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=ucap
PKG_VERSION:=1
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/ucap
	SECTION:=util
	CATEGORY:=Utilities
	TITLE:=uCap
	URL:=https://github.com/deepwater82/bismark_ucap_scripts
	DEPENDS:=+openflow-ucap +veth +kmod-tun
endef

define Package/ucap/description
	Router support for uCap.
endef

define Build/Compile
endef

define Package/ucap/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) ./files/usr/bin/ucap-monitor-veth $(1)/usr/bin/ucap-monitor-veth
	$(INSTALL_DIR) $(1)/etc
	$(INSTALL_BIN) ./files/etc/preopenflow.user $(1)/etc/preopenflow.user
	$(INSTALL_BIN) ./files/etc/postopenflow.user $(1)/etc/postopenflow.user
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/ucap $(1)/etc/init.d/ucap
endef

define Package/ucap/postinst
#!/bin/sh -x
if uci get wireless.@wifi-iface[0].network \
		|| uci get wireless.@wifi-iface[1].network \
		|| uci get network.lan.ifname; then
	uci set wireless.@wifi-iface[0].network=''
	uci set wireless.@wifi-iface[1].network=''
	uci set network.lan.ifname=''
	uci commit wireless
	uci commit network
	/etc/init.d/network restart
fi

uci set openflow.@ofswitch[0].dp=dp0
uci set openflow.@ofswitch[0].dpid=`cut -b 3- /etc/bismark/ID`
uci set openflow.@ofswitch[0].ofports=wlan0,wlan1,eth0.1,veth0
uci set openflow.@ofswitch[0].ofctl=tcp:143.215.131.178:6633
uci set openflow.@ofswitch[0].mode=outofband
uci commit openflow
/etc/init.d/openflow enable
/etc/init.d/openflow restart

/etc/init.d/ucap enable
/etc/init.d/ucap restart
endef

define Pakcage/ucap/prerm
#!/bin/sh
/etc/init.d/ucap stop
/etc/init.d/ucap disable

while ip rule del iif wlan0; do true; done
while ip rule del iif wlan1; do true; done
while ip rule del iif eth0.1; do true; done
while ip rule del blackhole default table ucap_rt; do true; done

uci set wireless.@wifi-iface[0].network='lan'
uci set wireless.@wifi-iface[1].network='lan'
uci set network.lan.ifname='eth0.1'
uci commit wireless
uci commit network
/etc/init.d/network restart
endef

$(eval $(call BuildPackage,ucap))
