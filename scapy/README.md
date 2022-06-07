## SCAPY
https://scapy.readthedocs.io/en/latest/installation.html


## UDP ICMP Port Unreachable

| sip | dip | sport | dport | nexthdr | dir| rel | state|
| ------ | ------ |------ | ------ | ------ | ------ | ------ |------ |
| 172.20.56.106 | 172.20.56.105 | 38022 | 35345 | udp | egress | main connection | new|
| 172.20.56.106 | 172.20.56.105 | 38022 | 35345 | udp | egress| related connection | rel|
| 172.20.56.105 | 172.20.56.106 | 35345 | 38022 | udp | ingress| main connection | new|
| 172.20.56.105 | 172.20.56.106 | 35345 | 38022 | udp | ingress| related connection | rel+new|

## UDP

| sip | dip | sport | dport | nexthdr | dir| rel | state|
| ------ | ------ |------ | ------ | ------ | ------ | ------ |------ |
| 172.20.56.106 | 172.20.56.105 | 38022 | 35345 | udp | egress | main connection | new|
| 172.20.56.106 | 172.20.56.105 | 38022 | 35345 | udp | egress| related connection | rel|
| 172.20.56.105 | 172.20.56.106 | 35345 | 38022 | udp | ingress| main connection | new|
| 172.20.56.105 | 172.20.56.106 | 35345 | 38022 | udp | ingress| related connection | rel+new|

## ICMP ECHO REPLY
| sip | dip | sport | dport(id) | nexthdr | dir| rel | state|
| ------ | ------ |------ | ------ | ------ | ------ | ------ |------ |
| 172.20.56.106 | 172.20.56.105 | 27740 | 0 | icmp | egress | main connection | new|
| 172.20.56.105 | 172.20.56.106 | 0 | 27740 | icmp | ingress| main connection | rly+new|

