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
  a. `scripts/feeds install bismark-passive`
  b. `make package/bismark-passive/compile`
3. Copy `bin/ar71xx/packages/bismark-passive_\*.ipk` to an OpenWRT router.
4. `opkg install bismark-passive_\*.ipk`

Build options
-------------

You can pass options when `make`'ing the package:

1. `DISABLE\_ANONYMIZATION=1` disables anonymization
2. `BISMARK_PASSIVE_TARGET=release` disables debugging support
3. `BISMARK_PASSIVE_TARGET=debug` enables debugging messages and binary symbols
   (default)

Operation instructions
----------------------

Usage: `bismark-passive [network interface]`

It dumps anonymized updates into /tmp/bismark-passive-update.gz every 30
seconds. Pass DISABLE\_ANONYMIZATION=1 to `make` to disable anonymization for
your build.

File format for differential updates
------------------------------------

Bismark-passive periodically generates differential updates about the traffic it
has observed since the last update. Updates are gzipped text files with the
following format:

    [timestamp at process creation] [total packets received by pcap] [total packets dropped by pcap] [total packets dropped by interface]
    
    [hash of anonymization key]
    
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
    
    [MAC id] [hashed domain name for CNAME record] [hashed ip address for CNAME record]
    [MAC id] [hashed domain name for CNAME record] [hashed ip address for CNAME record]
    ...
    [MAC id] [hashed domain name for CNAME record] [hashed ip address for CNAME record]
    
    [MAC address with lower 24 bits hashed (represents MAC id 0)]
    [MAC address with lower 24 bits hashed (represents MAC id 1)]
    ...
    [MAC address with lower 24 bits hashed (represents MAC id N)]
