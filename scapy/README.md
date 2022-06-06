## SCAPY
https://scapy.readthedocs.io/en/latest/installation.html


## 环境
```shell
ip netns del ns1
ip netns del ns2

ip netns add ns1    
ip netns add ns2

ip link add ns-link-1 type veth peer name ns-link-2
ip link set dev ns-link-1 up
ip link set dev ns-link-2 up

ip link set ns-link-1 netns ns1
ip link set ns-link-2 netns ns2

ip netns exec ns1 ip link set dev ns-link-1 up
ip netns exec ns2 ip link set dev ns-link-2 up

ip netns exec ns1 ip addr add 172.20.56.105/24 brd 172.20.56.255 dev ns-link-1
ip netns exec ns2 ip addr add 172.20.56.106/24 brd 172.20.56.255 dev ns-link-2


tcpdump -l -i ns-link-2 -ennn -tttt -v -c 10  host 172.20.56.105 
```

## UDP ICMP Port Unreachable

| sip | dip | sport | dport | nexthdr | dir| rel | state|
| ------ | ------ |------ | ------ | ------ | ------ | ------ |------ |
| 172.20.56.106 | 172.20.56.105 | 38022 | 35345 | udp | egress | main connection | new|
| 172.20.56.106 | 172.20.56.105 | 38022 | 35345 | udp | egress| related connection | rel|
| 172.20.56.105 | 172.20.56.106 | 35345 | 38022 | udp | ingress| main connection | new|
| 172.20.56.105 | 172.20.56.106 | 35345 | 38022 | udp | ingress| related connection | rel+new|


