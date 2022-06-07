#! /usr/bin/env python

# The following line will import all Scapy modules
from scapy.all import *

# L2
eth = Ether()

# L3
ipv4 = IP(src="172.20.56.105",dst="172.30.56.105")

# L4 
udp = UDP(sport=35345,dport=38022)
xxx = "hello udp ct"

s = 1
while s <= 20:
    packet = eth / ipv4 / udp / xxx
    sendp(packet)
    s += 1
