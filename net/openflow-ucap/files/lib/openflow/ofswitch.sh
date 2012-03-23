#!/bin/sh
# Copyright (C) 2006 OpenWrt.org

#DEBUG="echo"

add_ofswitch_datapath() {
	local config="$1"
	local ofports
	local dpports
	local dp
	local mode
	local dpid

	config_get ofports "$config" ofports
	config_get dp "$config" dp
	config_get mode "$config" mode
	config_get dpid "$config" dpid


	dpports=`echo "$ofports" | tr ' ' ','`
	echo "$dpports"

	pidfile="/var/run/ofdatapath.pid"	

	[ -n "$dpports" ] && {
		if [[ "$mode" == "inband" ]]
		then
			echo "Configuring OpenFlow switch for inband control"
 			[ -n "$dpid" ] && {
				ofdatapath punix:/var/run/dp0.sock -i "$dpports" --local-port=tap:tap0 "--pidfile=$pidfile" -d "$dpid" &
			} || {
				ofdatapath punix:/var/run/dp0.sock -i "$dpports" --local-port=tap:tap0 "--pidfile=$pidfile" &
			}
		else
			echo "Configuring OpenFlow switch for out-of-band control"
			[ -n "$dpid" ] && {
				ofdatapath punix:/var/run/dp0.sock -i "$dpports" --no-slicing --no-local-port "--pidfile=$pidfile" -d "$dpid" &
			} || {
				ofdatapath punix:/var/run/dp0.sock -i "$dpports" --no-slicing --no-local-port "--pidfile=$pidfile" &
			}
		fi
	}
}

setup_ofswitch() {
	local config="$1"

	add_ofswitch_datapath "$config"
}
		
