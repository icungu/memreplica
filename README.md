memreplica
==========

memcached packet replicator


Requirement
-----------
pcap library needed.

Build
-----
$ make
cc -g -O2 -Wall memreplica.c -o memreplica -lpcap

Usage
-----
$ ./memreplica
memreplica (memcached packet replicator)

usage:
   ./memreplica <interface> [options]

interface:
   -l ip address1     Capture packets from ip address1.
   -d ip address2     Destination ip address of forwarded packets.
options:
   -p port            Capture packets from port.
   -c                 Capture packets only.
example:
   sudo ./memreplica -l 192.168.0.1 -d 192.168.0.2 -p 11211
