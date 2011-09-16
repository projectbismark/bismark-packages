BISMark Passive
===============

This software passively monitors network traffic on OpenWRT routers and
periodically sends small anonymized updates to a central server for analysis.
Doing so will enable researchers to better understand how people use home
networks.

Installation instructions
-------------------------

1. Follow instruction at `dp4:/data/users/bismark/openwrt/src/instructions.txt` to
prepare a build tree.  When cloning the bismark-packages repository, be sure to
add the `-b passive` option to clone the passive branch of the
repository.
2. From the OpenWRT build directory:
    - `scripts/feeds install bismark-passive`
    - `make package/bismark-passive/compile`
3. Copy `bin/ar71xx/packages/bismark-passive_*.ipk` to an OpenWRT router.
4. `opkg install bismark-passive_*.ipk`

Build options
-------------

You can pass options when `make`'ing the package:

1. `DISABLE_ANONYMIZATION=1` disables anonymization
2. `BISMARK_PASSIVE_TARGET=release` disables debugging support
3. `BISMARK_PASSIVE_TARGET=debug` enables debugging messages and binary symbols
   (default)

Operation instructions
----------------------

Usage: `bismark-passive <network interface> [mac address 0] [mac address 1] ...`

Recommended: capture on `br-lan` with the MAC addresses of all interfaces on the
machine.

It dumps into `/tmp/bismark-passive-update.gz` every 30 seconds.

File format for differential updates
------------------------------------

Bismark-passive periodically generates differential updates about the traffic it
has observed since the last update. Updates are gzipped text files with the
following format:

    [bismark ID] [timestamp at process creation] [sequence number]
    [(optional) total packets received by pcap] [(optional) total packets dropped by pcap] [(optional) total packets dropped by interface]
    
    [hash of anonymization key, or "UNANONYMIZED" if not anonymized]
    
    [timestamp of first packet] [packets dropped]
    [microseconds offset from previous packet] [packet size bytes] [flow id]
    [microseconds offset from previous packet] [packet size bytes] [flow id]
    ...
    [microseconds offset from previous packet] [packet size bytes] [flow id]
    
    [baseline timestamp] [num elements in flow table] [total expired flows] [total dropped flows]
    [flow id] [hashed source IP address] [hashed destination IP address] [transport protocol] [source port] [destination port]
    [flow id] [hashed source IP address] [hashed destination IP address] [transport protocol] [source port] [destination port]
    ...
    [flow id] [hashed source IP address] [hashed destination IP address] [transport protocol] [source port] [destination port]
    
    [total dropped A records] [total dropped CNAME records]
    [MAC id] [hashed domain name for A record] [hashed ip address for A record]
    [MAC id] [hashed domain name for A record] [hashed ip address for A record]
    ...
    [MAC id] [hashed domain name for A record] [hashed ip address for A record]
    
    [MAC id] [hashed domain name for CNAME record] [hashed cname for CNAME record]
    [MAC id] [hashed domain name for CNAME record] [hashed cname for CNAME record]
    ...
    [MAC id] [hashed domain name for CNAME record] [hashed cname for CNAME record]
    
    [address id of first address in list] [total size of address table]
    [MAC address with lower 24 bits hashed] [hashed IP address]
    [MAC address with lower 24 bits hashed] [hashed IP address]
    ...
    [MAC address with lower 24 bits hashed] [hashed IP address]

Complexity of resource usage
----------------------------

Bismark Passive runs in a resource constrianed environment, so we care about
these performance metrics:

* **Per-packet computational complexity** is proportional to the number of hosts
  on the local network. For DNS packets, computation also depends on the length
  of the packet.
* **Per-update computational complexity** is proportional to the number of
  packets received since the last update, the number of new flows since the last
  update, the number of DNS responses since the last update, and the number of
  devices on the local network.
* **Memory utilization complexity** is proportional to the number of packets
  since the last update, the number of flows within a window (currently 9 hours,
  although inactive flows expire sooner), the number of DNS responses since the
  last update, and the number of hosts on the local network.
* **Network utilization complexity** per update is proportional to the number of
  packets since the last update, the number of new flows since the last update,
  the number of DNS responses since the last update, and the number of hosts on
  the local network.
