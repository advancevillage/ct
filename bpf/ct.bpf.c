#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

//存储表控制参数
#define     CT_MAP_TCP          ct_tcp
#define     CT_MAP_ANY4         ct_any4
#define     CT_MAP_SIZE_ANY     4096 
#define     CT_MAP_SIZE_TCP     4096 


//常量定义
#define CT_EGRESS           0x0
#define CT_INGRESS          0x1

//路由指令
#define CT_TX               0x0
#define CT_DROP             0x1
#define CT_PASS             0x2


//连接跟踪状态
#define     CT_NEW              (1 << 0)
#define     CT_ESTABLISHED      (1 << 1)
#define     CT_REPLY            (1 << 2)
#define     CT_RELATED          (1 << 3)

//////////////////////////////////////////////////////////////

//连接跟踪元组信息 从cilium移植 cilium-1.11.5/bpf/lib/common.h
struct ipv4_ct_tuple {
	/* Address fields are reversed, i.e.,
	 * these field names are correct for reply direction traffic.
	 */
	__be32		daddr;
	__be32		saddr;
	/* The order of dport+sport must not be changed!
	 * These field names are correct for original direction traffic.
	 */
	__be16		dport;
	__be16		sport;
	__u8		nexthdr;
	__u8		flags;
} __packed;

//连接跟踪元组数据
struct ct_entry {
	__u64 rx_packets;
	__u64 rx_bytes;
	__u64 tx_packets;
	__u64 tx_bytes;
	__u32 lifetime;
	/* In the kernel ifindex is u32, so we need to check in cilium-agent
	 * that ifindex of a NodePort device is <= MAX(u16).
	 */
	__u16 ifindex;

	/* *x_flags_seen represents the OR of all TCP flags seen for the
	 * transmit/receive direction of this entry.
	 */
	__u8  tx_flags_seen;
	__u8  rx_flags_seen;
};

//////////////////////////////////////////////////////////////

// 存储表
struct {
   __uint(type,         BPF_MAP_TYPE_HASH);
   __type(key,          sizeof(struct ipv4_ct_tuple));
   __type(value,        sizeof(struct ct_entry));
   __uint(max_entries,  CT_MAP_SIZE_TCP);
   __uint(map_flags,    BPF_F_NO_PREALLOC);
} CT_MAP_TCP SEC(".maps");

struct {
   __uint(type,         BPF_MAP_TYPE_HASH);
   __type(key,          sizeof(struct ipv4_ct_tuple));
   __type(value,        sizeof(struct ct_entry));
   __uint(max_entries,  CT_MAP_SIZE_ANY);
   __uint(map_flags,    BPF_F_NO_PREALLOC);
} CT_MAP_ANY4 SEC(".maps");


//函数连接跟踪逻辑 parser--> match action --> deparser
static __inline __u8 ct(struct xdp_md *ctx, __u8 dir) {
    // 定义返回路由指示
    __u8 r = CT_TX;

    // 解析报文
    void *data_end  = (void *)(long)ctx->data_end;
	void *data      = (void *)(long)ctx->data;

    // 解析以太网L2协议
	struct ethhdr   *eth = data;  

    __u64 nh_off;       //字节偏移

    nh_off = (char*)(eth + 1) - (char*)eth;
    if (data + nh_off > data_end) {
        r = CT_DROP;
        goto leave;
    }

    __u16 h_proto;      //L3 协议类型
    h_proto = eth->h_proto; 

    switch (h_proto) {
    case bpf_htons(ETH_P_IP):
        break;
    default:
        r = CT_PASS;
        goto leave;
    }

    // 解析IPv4 报文
	struct iphdr          *iph;         //L3

    iph = data + nh_off;
    nh_off += (char*)(iph + 1) - (char*)iph;

    if (data + nh_off > data_end) {
         r = CT_DROP;
        goto leave;
    }

    // 分片报文不支持
    if (iph->frag_off & 0xff3f) {
        r = CT_PASS;
        goto leave;
    }

    // 解析CT Flow数据
    switch (iph->protocol) { //TODO: flow状态分析 NEW RELATED 
    case 0x01: //icmp
        //r = handle_ping()
        break;
    case 0x06: //tcp
        //r = handle_tcp()
        break;
        //r = handle_udp()
    case 0x11: //udp
        break;
    }

leave:
    return r;
}

SEC("xdp_ct_ingress")
int ct_ingress_wan(struct xdp_md *ctx) {
    int  xdp_r = XDP_TX;
    __u8 r = ct(ctx, CT_INGRESS);

    switch (r) {
    case CT_DROP:
        xdp_r = XDP_DROP;
        break;

    case CT_PASS:
        xdp_r = XDP_PASS;
        break;

    case CT_TX:
        xdp_r = XDP_TX;
        break;

    default: 
        xdp_r = XDP_DROP;
    }

    return xdp_r;
}

SEC("xdp_ct_egress")
int ct_egress_lan(struct xdp_md *ctx) {
    int  xdp_r = XDP_TX;
    __u8 r = ct(ctx, CT_EGRESS);

    switch (r) {
    case CT_DROP:
        xdp_r = XDP_DROP;
        break;

    case CT_PASS:
        xdp_r = XDP_PASS;
        break;

    case CT_TX:
        xdp_r = XDP_TX;
        break;

    default: 
        xdp_r = XDP_DROP;
    }

    return xdp_r;
}

char _license []SEC("license") = "GPL";

//clang -g -Wall -O2 -c -target bpf -D__TARGET_ARCH_x86 ct.bpf.c -I/usr/include/x86_64-linux-gnu/ -o ct.bpf.o 
//bpftool prog loadall ct.bpf.o /sys/fs/bpf/global
