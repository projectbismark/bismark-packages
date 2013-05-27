#
# Copyright (C) 2006-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=ucap
PKG_VERSION:=1
PKG_RELEASE:=10

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
#!/bin/sh
if ! uci get network.dum.ifname; then
	uci set network.dum=interface
	uci set network.dum.ifname=eth0.2
	uci set network.dum.proto=static
	uci commit network
	/etc/init.d/network restart
fi

sed -i /^.*ucap_rt$/d /etc/iproute2/rt_tables
echo 200 ucap_rt >> /etc/iproute2/rt_tables

if [ ! -f /etc/bismark/passive.key ]; then
	dd if=/dev/urandom of=/etc/bismark/passive.key bs=1 count=16 2>/dev/null
fi

uci set openflow.@ofswitch[0].dp=dp0
uci set openflow.@ofswitch[0].dpid=`cut -b 3- /etc/bismark/ID`
uci set openflow.@ofswitch[0].ofports=wlan0,wlan1,eth0.1,veth0
uci set openflow.@ofswitch[0].ofctl=tcp:130.207.97.60:6633
uci set openflow.@ofswitch[0].mode=outofband
uci commit openflow
/etc/init.d/openflow enable
/etc/init.d/openflow restart

/etc/init.d/ucap enable
/etc/init.d/ucap restart

if [ -f /etc/init.d/bismark-passive ]; then
	/etc/init.d/bismark-passive restart
fi
endef

define Package/ucap/prerm
#!/bin/sh
/etc/init.d/ucap stop
/etc/init.d/ucap disable

/etc/init.d/openflow stop

while ip rule del iif wlan0; do true; done
while ip rule del iif wlan1; do true; done
while ip rule del iif eth0.1; do true; done
while ip route del blackhole default table ucap_rt; do true; done
ip route flush cache

/etc/init.d/network restart
#ifconfig eth0.1 up
#brctl addif br-lan eth0.1
endef

$(eval $(call BuildPackage,ucap))
