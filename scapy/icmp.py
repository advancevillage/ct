#! /usr/bin/env python

# The following line will import all Scapy modules
from scapy.all import *

# L2
eth = Ether(src="9e:67:d5:d0:19:d2", dst="2e:77:a3:0f:b5:79")

# L3
ipv4 = IP(src="172.20.56.105",dst="172.20.56.106")

# icmp
s = 1
i = 27740
while s <= 20:
    icmp = ICMP(seq=s, id=i)
    packet = eth / ipv4 / icmp
    sendp(packet, iface="ns-link-1")
    s += 1
