## 环境配置
```shell
#创建namespace
ip netns del ns1
ip netns del ns2

ip netns add ns1    
ip netns add ns2

#创建veth 虚拟网络设备
ip link add ns1-wan type veth peer name ns1-lan
ip link add ns2-wan type veth peer name ns2-lan

ip link set ns1-lan up
ip link set ns1-wan up
ip link set ns2-lan up
ip link set ns2-wan up

ip link set ns1-wan netns ns1
ip link set ns2-wan netns ns2

ip netns exec ns1  ip link set dev ns1-wan up
ip netns exec ns2  ip link set dev ns2-wan up

ip addr add 172.20.56.1/24 brd 172.20.56.255 dev ns1-lan
ip addr add 172.30.56.1/24 brd 172.30.56.255 dev ns2-lan

sysctl -w net.ipv4.conf.all.forwarding=1
sysctl -w net.ipv6.conf.all.forwarding=1

ip netns exec ns1 ip addr add 172.20.56.105/24 brd 172.20.56.255 dev ns1-wan
ip netns exec ns1 ip route add default via 172.20.56.1 dev ns1-wan

ip netns exec ns2 ip addr add 172.30.56.105/24 brd 172.30.56.255 dev ns2-wan
ip netns exec ns2 ip route add default via 172.30.56.1 dev ns2-wan
```
https://www.spinics.net/lists/xdp-newbies/msg01811.html

## 清理数据
```shell
## 取消xdp模式
ip link set dev ns-link-2 xdp off

clean=(map prog)
for i in ${clean[@]}; do ls -h /sys/fs/bpf/$i/ | xargs -I {} sudo unlink /sys/fs/bpf/$i/{}; done

```

```shell
bpftool -j -p map dump pinned /sys/fs/bpf/map/ctt | grep key | awk -F '[' '{print $2}' | sed -e 's/"//g' -e 's/,/ /g' -e 's/^/bpftool map delete pinned \/sys\/fs\/bpf\/map\/ctt key hex /g'

```
