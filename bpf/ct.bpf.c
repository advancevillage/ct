#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


//常量定义
#define CT_EGRESS           0x0
#define CT_INGRESS          0x1

//路由指令
#define CT_TX               0x0
#define CT_DROP             0x1
#define CT_PASS             0x2


//////////////////////////////////////////////////////////////

//连接跟踪元组信息
struct ct_tuple {
     struct {
        __be32          addr;

        union {
            __be16      all;

            struct {
                __be16  port;
            } tcp;

            struct {
                __be16  port;
            } udp;

            struct {
                __u8    type;
                __u8    code;
            } icmp;
        } u;

	    __u8		    l4num;

     } src, dst;
};

//连接跟踪元组数据
struct ct_entry {
	__u64       rx_packets;  //入向包量
	__u64       rx_bytes;    //入向流量
	__u64       tx_packets;  //出向包量
	__u64       tx_bytes;    //出向流量
	__u32       lifetime;    //有效时间
	__u16       ifindex;     //网络设备标示
    __u16       state;       //流状态
    __u8        l4num;       //L4协议类型
};


//////////////////////////////////////////////////////////////

// 存储表


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
    switch (iph->protocol) {
    case 0x01: //icmp
        break;
    case 0x06: //tcp
        break;
    case 0x11: //udp
        break;
    }

leave:
    return r;
}

SEC("xdp_ct_ingress")
int xdp_ct_ingress_wan(struct xdp_md *ctx) {
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
int xdp_ct_egress_lan(struct xdp_md *ctx) {
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
