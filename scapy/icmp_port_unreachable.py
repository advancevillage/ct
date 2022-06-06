#! /usr/bin/env python

# The following line will import all Scapy modules
from scapy.all import *

# L2
eth = Ether(src="9e:67:d5:d0:19:d2", dst="2e:77:a3:0f:b5:79")

# L3
ipv4 = IP(src="172.20.56.105",dst="172.20.56.106")

# L4 
udp = UDP(sport=35345,dport=38022)

packet = eth / ipv4 / udp
sendp(packet, iface="ns-link-1")

# icmp
icmp = ICMP(seq=1)
icmp.type = 3
icmp.code = 1

packet = eth / ipv4 / icmp / ipv4 / udp
sendp(packet, iface="ns-link-1")
